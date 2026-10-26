"""Standalone helpers for encrypting/decrypting env values and files."""

from __future__ import annotations

import base64
import os
import re
import secrets
import stat
import sys
import tempfile
import threading
from pathlib import Path
from typing import Final

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MASTER_KEY_BYTES: Final[int] = 32
NONCE_BYTES: Final[int] = 12
DEFAULT_KEY_FILENAME: Final[str] = "uag_envsec_key"
DEFAULT_SEC_SUFFIX: Final[str] = ".sec"
KEYRING_SERVICE: Final[str] = "uag-envsec"
KEYRING_USERNAME: Final[str] = "master-key"
KEYRING_TIMEOUT_SECONDS: Final[float] = 3.0
LEGACY_FORMAT_VERSION: Final[int] = 0
CURRENT_FORMAT_VERSION: Final[int] = 1
_VERSIONED_CIPHERTEXT_PREFIX: Final[str] = "uag-envsec:v"
_KEYRING_TIMED_OUT = False


class UnsupportedCiphertextVersionError(ValueError):
    """Raised when ciphertext uses a format version this library cannot read."""


def _ensure_cryptography() -> None:
    """Confirm the crypto dependency at explicit crypto call sites.

    This module imports the primitives eagerly, so reaching this helper means
    the dependency has already been imported successfully.
    """
    return None


def _home_dir() -> Path:
    return Path.home()


def default_key_path() -> Path:
    return _home_dir() / ".uag" / DEFAULT_KEY_FILENAME


def _keyring_module():
    """Return python-keyring when installed; never install dependencies implicitly."""
    try:
        import keyring
    except ImportError:
        return None
    return keyring


def _keyring_timeout() -> float:
    """Return the maximum time allowed for one blocking keyring operation."""
    raw = os.getenv("UAGENT_KEYRING_TIMEOUT", "")
    try:
        value = float(raw) if raw.strip() else KEYRING_TIMEOUT_SECONDS
    except ValueError:
        value = KEYRING_TIMEOUT_SECONDS
    return min(max(value, 0.1), 30.0)


def _call_keyring(method, *args):
    """Call a keyring method without allowing Secret Service to block startup.

    ``secretstorage`` may wait for a D-Bus prompt forever when no desktop
    secret-service agent is running (a common situation over SSH or on a
    headless Raspberry Pi). The keyring API is synchronous, so run the call
    in a daemon thread and abandon it after a short, configurable timeout.
    """
    global _KEYRING_TIMED_OUT
    if _KEYRING_TIMED_OUT:
        raise TimeoutError("OS keyring is unavailable after a previous timeout")
    result: dict[str, object] = {}
    completed = threading.Event()

    def invoke() -> None:
        try:
            result["value"] = method(*args)
        except BaseException as exc:
            result["error"] = exc
        finally:
            completed.set()

    worker = threading.Thread(target=invoke, name="uag-keyring", daemon=True)
    worker.start()
    if not completed.wait(_keyring_timeout()):
        _KEYRING_TIMED_OUT = True
        raise TimeoutError(
            "OS keyring operation timed out; using the file backend instead"
        )
    error = result.get("error")
    if error is not None:
        raise error  # type: ignore[misc]
    return result.get("value")


def _key_backend() -> str:
    # Secret Service commonly requires a desktop D-Bus agent, which is not
    # normally available on headless Linux/SSH/Raspberry Pi installations.
    # Keep keyring opt-in there for now; other platforms retain auto-detect.
    default_backend = "file" if sys.platform.startswith("linux") else "auto"
    backend = os.getenv("UAGENT_ENVSEC_KEY_BACKEND", default_backend) or default_backend
    backend = backend.strip().lower()
    if backend not in {"auto", "file", "keyring", "os"}:
        raise ValueError(
            "UAGENT_ENVSEC_KEY_BACKEND must be one of: auto, file, keyring"
        )
    return "keyring" if backend == "os" else backend


def _decode_key(raw: str) -> bytes:
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError("Invalid keyring key encoding") from exc
    if len(key) != MASTER_KEY_BYTES:
        raise ValueError(f"Invalid key length: {len(key)}")
    return key


def _is_no_keyring_backend_error(exc: Exception) -> bool:
    return type(exc).__name__ == "NoKeyringError"


def _load_keyring_key() -> bytes | None:
    keyring = _keyring_module()
    if keyring is None:
        return None
    try:
        raw = _call_keyring(keyring.get_password, KEYRING_SERVICE, KEYRING_USERNAME)
    except TimeoutError:
        raise
    except Exception as exc:
        if _is_no_keyring_backend_error(exc):
            return None
        raise RuntimeError("OS keyring read failed; refusing file-key fallback") from exc
    return _decode_key(raw) if raw else None


def _save_keyring_key(key: bytes) -> str:
    keyring = _keyring_module()
    if keyring is None:
        raise RuntimeError(
            "python-keyring is not installed; install it or use file backend"
        )
    if _KEYRING_TIMED_OUT:
        raise TimeoutError("OS keyring is unavailable after a previous timeout")
    _call_keyring(
        keyring.set_password,
        KEYRING_SERVICE,
        KEYRING_USERNAME,
        base64.b64encode(key).decode("ascii"),
    )
    return f"keyring://{KEYRING_SERVICE}/{KEYRING_USERNAME}"


def _migrate_file_key_to_keyring(path: Path) -> bool:
    keyring = _keyring_module()
    if keyring is None:
        return False
    try:
        original_stat = path.lstat()
        if stat.S_ISLNK(original_stat.st_mode) or not stat.S_ISREG(original_stat.st_mode):
            return False

        flags = os.O_RDONLY
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags)
        try:
            opened_stat = os.fstat(fd)
            if (
                not stat.S_ISREG(opened_stat.st_mode)
                or (opened_stat.st_dev, opened_stat.st_ino)
                != (original_stat.st_dev, original_stat.st_ino)
            ):
                return False
            if os.name == "posix" and opened_stat.st_mode & 0o077:
                os.fchmod(fd, 0o600)

            chunks = bytearray()
            while len(chunks) <= MASTER_KEY_BYTES:
                chunk = os.read(fd, MASTER_KEY_BYTES + 1 - len(chunks))
                if not chunk:
                    break
                chunks.extend(chunk)
            key = bytes(chunks)
        finally:
            os.close(fd)

        if len(key) != MASTER_KEY_BYTES:
            return False
        raw = _call_keyring(keyring.get_password, KEYRING_SERVICE, KEYRING_USERNAME)
        if raw:
            try:
                if _decode_key(raw) == key:
                    current_stat = path.lstat()
                    if (
                        stat.S_ISREG(current_stat.st_mode)
                        and (current_stat.st_dev, current_stat.st_ino)
                        == (original_stat.st_dev, original_stat.st_ino)
                    ):
                        path.unlink()
                        return True
                    return False
            except ValueError:
                # Replace an invalid keyring entry with the valid file key.
                pass
        # The file key is the key that protects the existing .env.sec data.
        # Make it authoritative during migration, then remove the duplicate.
        _call_keyring(
            keyring.set_password,
            KEYRING_SERVICE,
            KEYRING_USERNAME,
            base64.b64encode(key).decode("ascii"),
        )
        stored = _call_keyring(keyring.get_password, KEYRING_SERVICE, KEYRING_USERNAME)
        if _decode_key(stored or "") != key:
            return False
        current_stat = path.lstat()
        if (
            not stat.S_ISREG(current_stat.st_mode)
            or (current_stat.st_dev, current_stat.st_ino)
            != (original_stat.st_dev, original_stat.st_ino)
        ):
            return False
        path.unlink()
        return True

    except Exception:
        # Auto migration must never prevent startup; the file remains usable.
        return False


def migrate_key_file_to_keyring() -> bool:
    """Migrate the default envsec key file when the automatic backend allows it.

    This is intentionally a no-op when the user selected the file backend or
    when no legacy key file exists.
    """
    if _key_backend() != "auto":
        return False
    path = default_key_path()
    if not path.exists():
        return False
    return _migrate_file_key_to_keyring(path)


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def save_key(path: str | Path | None = None, *, overwrite: bool = False) -> str:
    """Ensure a master key exists and return its storage location.

    ``overwrite=True`` replaces the selected key; existing ciphertexts are not
    re-encrypted and will require their previous key for decryption.
    """
    backend = _key_backend() if path is None else "file"
    if backend == "keyring":
        existing = _load_keyring_key()
        if existing is not None and not overwrite:
            return f"keyring://{KEYRING_SERVICE}/{KEYRING_USERNAME}"
        return _save_keyring_key(os.urandom(MASTER_KEY_BYTES))

    p = Path(path) if path is not None else default_key_path()
    if path is None and backend == "auto" and not p.exists():
        if _load_keyring_key() is not None and not overwrite:
            return f"keyring://{KEYRING_SERVICE}/{KEYRING_USERNAME}"
        if _keyring_module() is not None:
            try:
                return _save_keyring_key(os.urandom(MASTER_KEY_BYTES))
            except TimeoutError:
                raise
            except Exception as exc:
                if not _is_no_keyring_backend_error(exc):
                    raise RuntimeError(
                        "OS keyring write failed; refusing file-key fallback"
                    ) from exc

    ensure_parent(p)
    if path is None and p.is_symlink():
        raise PermissionError(f"Default envsec key path must not be a symlink: {p}")
    if p.exists() and not overwrite:
        load_key() if path is None else load_key(p)
        return str(p)

    key = os.urandom(MASTER_KEY_BYTES)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{p.name}.",
        suffix=".tmp",
        dir=str(p.parent),
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            remaining = memoryview(key)
            while remaining:
                written = stream.write(remaining)
                if written is None or written <= 0:
                    raise OSError("Failed to write complete envsec key")
                remaining = remaining[written:]
            stream.flush()
            os.fsync(stream.fileno())

        if overwrite:
            os.replace(temporary_path, p)
        else:
            try:
                os.link(temporary_path, p)
            except FileExistsError:
                load_key() if path is None else load_key(p)
            else:
                temporary_path.unlink()
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass
    return str(p)


def _check_key_file_permissions(path: Path, *, reject_symlink: bool) -> None:
    """Validate a key file and restrict POSIX permissions to its owner."""
    if reject_symlink and path.is_symlink():
        raise PermissionError(f"Default envsec key path must not be a symlink: {path}")
    if not path.exists():
        raise FileNotFoundError(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Key path must be a regular file: {path}")
    if os.name == "posix" and info.st_mode & 0o077:
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise PermissionError(
                f"Could not restrict key file permissions: {path}"
            ) from exc


def load_key(path: str | Path | None = None) -> bytes:
    if path is None:
        backend = _key_backend()
        p = default_key_path()
        # In automatic mode the OS keyring is authoritative whenever it has
        # a key, even if a legacy file is still present.
        if backend in {"keyring", "auto"}:
            key = _load_keyring_key()
            if key is not None:
                return key
            if backend == "keyring":
                raise FileNotFoundError(
                    f"No envsec key in OS keyring ({KEYRING_SERVICE}/{KEYRING_USERNAME})"
                )
    else:
        p = Path(path)
    if path is None:
        _check_key_file_permissions(p, reject_symlink=True)
    else:
        _check_key_file_permissions(p, reject_symlink=False)
    key = p.read_bytes()
    if len(key) != MASTER_KEY_BYTES:
        raise ValueError(f"Invalid key length: {len(key)}")
    return key


def ensure_key_file(path: str | Path | None = None, *, overwrite: bool = False) -> str:
    if path is None and _key_backend() in {"auto", "keyring"}:
        if _key_backend() == "keyring":
            return save_key(None, overwrite=overwrite)
        p = default_key_path()
        if p.exists():
            if _migrate_file_key_to_keyring(p):
                print(
                    "[INFO] Migrated envsec key to OS keyring; legacy key file removed.",
                    file=sys.stderr,
                )
                return f"keyring://{KEYRING_SERVICE}/{KEYRING_USERNAME}"
            if _load_keyring_key() is not None:
                return f"keyring://{KEYRING_SERVICE}/{KEYRING_USERNAME}"
            if not overwrite:
                load_key()
                return str(p)
        if not p.exists() and _load_keyring_key() is not None:
            return f"keyring://{KEYRING_SERVICE}/{KEYRING_USERNAME}"
        if not p.exists() and _keyring_module() is not None:
            return save_key(None, overwrite=overwrite)
    p = Path(path) if path is not None else default_key_path()
    if p.exists() and not overwrite:
        load_key() if path is None else load_key(p)
        return str(p)
    return save_key(p, overwrite=overwrite)


def _derive_subkey(master_key: bytes, *, purpose: str, length: int) -> bytes:
    _ensure_cryptography()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=("uag_envsec." + purpose).encode("utf-8"),
    )
    return hkdf.derive(master_key)


def _version_aad(version: int) -> bytes | None:
    if version == LEGACY_FORMAT_VERSION:
        return None
    return f"{_VERSIONED_CIPHERTEXT_PREFIX}{version}:".encode("ascii")


def _validate_format_version(format_version: int) -> int:
    if type(format_version) is not int or format_version not in {
        LEGACY_FORMAT_VERSION,
        CURRENT_FORMAT_VERSION,
    }:
        raise UnsupportedCiphertextVersionError(
            f"Unsupported ciphertext version: {format_version!r}"
        )
    return format_version


def _encrypt_text_with_key(
    plaintext: str,
    master_key: bytes,
    format_version: int,
) -> str:
    enc_key = _derive_subkey(master_key, purpose="enc", length=32)
    aesgcm = AESGCM(enc_key)
    nonce = os.urandom(NONCE_BYTES)
    ct = aesgcm.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        _version_aad(format_version),
    )
    payload = base64.b64encode(nonce + ct).decode("ascii")
    if format_version == LEGACY_FORMAT_VERSION:
        return payload
    return f"{_VERSIONED_CIPHERTEXT_PREFIX}{format_version}:{payload}"


def encrypt_text(
    plaintext: str,
    *,
    key_path: str | Path | None = None,
    format_version: int = CURRENT_FORMAT_VERSION,
) -> str:
    """Encrypt text in a selected envelope format.

    Version 1 is the default and authenticates its explicit
    ``uag-envsec:v1:`` prefix as AES-GCM associated data. Specify version 0
    when writing ciphertext for older uag releases.
    """
    _validate_format_version(format_version)

    return _encrypt_text_with_key(plaintext, load_key(key_path), format_version)


def detect_format_version(ciphertext: str) -> int:
    """Return the envelope version; historical unversioned data is version 0."""
    if not ciphertext.startswith(_VERSIONED_CIPHERTEXT_PREFIX):
        return LEGACY_FORMAT_VERSION

    match = re.match(r"^uag-envsec:v([0-9]+):(.*)$", ciphertext, re.DOTALL)
    if match is None:
        raise ValueError("Malformed versioned envsec ciphertext")
    version = int(match.group(1))
    if version != CURRENT_FORMAT_VERSION:
        raise UnsupportedCiphertextVersionError(
            f"Unsupported ciphertext version: {version}"
        )
    if not match.group(2):
        raise ValueError("Empty versioned envsec ciphertext payload")
    return version


def _decrypt_text_with_key(enc_b64: str, master_key: bytes) -> str:
    version = detect_format_version(enc_b64)
    payload = enc_b64
    if version == CURRENT_FORMAT_VERSION:
        payload = enc_b64.split(":", 2)[2]

    enc_key = _derive_subkey(master_key, purpose="enc", length=32)
    aesgcm = AESGCM(enc_key)
    blob = base64.b64decode(payload)
    if len(blob) < NONCE_BYTES + 16:
        raise ValueError("Invalid ciphertext")
    nonce = blob[:NONCE_BYTES]
    ct = blob[NONCE_BYTES:]
    pt = aesgcm.decrypt(nonce, ct, _version_aad(version))
    return pt.decode("utf-8")


def decrypt_text(enc_b64: str, *, key_path: str | Path | None = None) -> str:
    return _decrypt_text_with_key(enc_b64, load_key(key_path))


def migrate_text(
    ciphertext: str,
    *,
    target_version: int = CURRENT_FORMAT_VERSION,
    key_path: str | Path | None = None,
) -> str:
    """Decrypt and re-encrypt ciphertext in another supported format.

    Unversioned legacy ciphertext is treated as version 0. If the input is
    already in the requested format, it is validated and returned unchanged.
    """
    _validate_format_version(target_version)
    source_version = detect_format_version(ciphertext)
    master_key = load_key(key_path)
    plaintext = _decrypt_text_with_key(ciphertext, master_key)
    if source_version == target_version:
        return ciphertext
    return _encrypt_text_with_key(plaintext, master_key, target_version)


def rekey_text(
    ciphertext: str,
    *,
    new_key_path: str | Path,
    old_key_path: str | Path | None = None,
    format_version: int = CURRENT_FORMAT_VERSION,
) -> str:
    """Re-encrypt ciphertext under a distinct key without writing plaintext.

    Version 1 is the default output. Specify version 0 only when the new
    ciphertext must remain readable by older uag releases. A new key file is
    not created by this function.
    """
    target_version = _validate_format_version(format_version)
    old_key = load_key(old_key_path)
    new_key = load_key(new_key_path)
    if secrets.compare_digest(old_key, new_key):
        raise ValueError("New key must differ from the source key")

    plaintext = _decrypt_text_with_key(ciphertext, old_key)
    return _encrypt_text_with_key(plaintext, new_key, target_version)


def migrate_file(
    source_path: str | Path,
    *,
    target_version: int = CURRENT_FORMAT_VERSION,
    key_path: str | Path | None = None,
    output_path: str | Path | None = None,
    overwrite: bool = False,
) -> Path:
    """Migrate an encrypted file, preserving the source and writing atomically.

    By default the output is ``<source>.v<target_version>``. The source file is
    never overwritten; an explicit output path resolving to the source is
    rejected. Existing destination files require ``overwrite=True``.
    """
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Encrypted input file not found: {source}")

    raw_text = source.read_bytes().decode("utf-8")
    if raw_text.endswith("\r\n"):
        trailing_newline = "\r\n"
    elif raw_text.endswith("\n"):
        trailing_newline = "\n"
    elif raw_text.endswith("\r"):
        trailing_newline = "\r"
    else:
        trailing_newline = ""
    ciphertext = raw_text.strip()
    migrated = migrate_text(
        ciphertext,
        target_version=target_version,
        key_path=key_path,
    )

    if output_path is None and detect_format_version(ciphertext) == target_version:
        return source
    destination = (
        Path(output_path)
        if output_path is not None
        else Path(f"{source}.v{target_version}")
    )
    if source.resolve() == destination.resolve():
        raise ValueError("Migration output must differ from the source file")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Migration output already exists: {destination}")

    _write_private_text_atomic(
        destination,
        migrated + trailing_newline,
        overwrite=overwrite,
    )
    return destination


def rekey_file(
    source_path: str | Path,
    *,
    new_key_path: str | Path,
    old_key_path: str | Path | None = None,
    output_path: str | Path | None = None,
    format_version: int = CURRENT_FORMAT_VERSION,
    overwrite: bool = False,
) -> Path:
    """Re-encrypt a file under a distinct key and keep the source untouched.

    The default destination is ``<source>.rekeyed``. The new key must already
    exist at ``new_key_path``; use ``ensure_key_file`` to create one safely.
    """
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Encrypted input file not found: {source}")

    destination = (
        Path(output_path) if output_path is not None else Path(f"{source}.rekeyed")
    )
    if source.resolve() == destination.resolve():
        raise ValueError("Rekey output must differ from the source file")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Rekey output already exists: {destination}")

    raw_text = source.read_bytes().decode("utf-8")
    if raw_text.endswith(chr(13) + chr(10)):
        trailing_newline = chr(13) + chr(10)
    elif raw_text.endswith(chr(10)):
        trailing_newline = chr(10)
    elif raw_text.endswith(chr(13)):
        trailing_newline = chr(13)
    else:
        trailing_newline = ""

    rekeyed = rekey_text(
        raw_text.strip(),
        new_key_path=new_key_path,
        old_key_path=old_key_path,
        format_version=format_version,
    )
    _write_private_text_atomic(
        destination,
        rekeyed + trailing_newline,
        overwrite=overwrite,
    )
    return destination


def _write_private_text_atomic(
    destination: Path,
    content: str,
    *,
    overwrite: bool,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary_path, destination)
        else:
            try:
                os.link(temporary_path, destination)
            except FileExistsError as exc:
                raise FileExistsError(
                    f"Output file already exists: {destination}"
                ) from exc
            else:
                temporary_path.unlink()
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def encrypt_file(
    source_path: str | Path,
    *,
    key_path: str | Path | None = None,
    output_path: str | Path | None = None,
    format_version: int = CURRENT_FORMAT_VERSION,
    overwrite: bool = False,
) -> Path:
    """Encrypt a UTF-8 text file, leaving its plaintext source untouched.

    By default the destination is ``<source>.sec``. Existing outputs are not
    overwritten unless requested; ciphertext is written atomically.
    """
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Plaintext input file not found: {source}")

    destination = (
        Path(output_path)
        if output_path is not None
        else Path(f"{source}{DEFAULT_SEC_SUFFIX}")
    )
    if source.resolve() == destination.resolve():
        raise ValueError("Encrypted output must differ from the plaintext source")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Encrypted output already exists: {destination}")

    plaintext = source.read_bytes().decode("utf-8")
    ciphertext = encrypt_text(
        plaintext,
        key_path=key_path,
        format_version=format_version,
    )
    _write_private_text_atomic(destination, ciphertext, overwrite=overwrite)
    return destination


def decrypt_file(
    source_path: str | Path,
    *,
    key_path: str | Path | None = None,
    output_path: str | Path | None = None,
    overwrite: bool = False,
) -> Path:
    """Decrypt an envsec file to a private output, preserving the source.

    By default the destination is ``<source>.decrypted``. Existing outputs
    are not overwritten unless requested. Plaintext is held in memory and
    written atomically to an owner-only temporary file on POSIX systems.
    """
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Encrypted input file not found: {source}")

    destination = (
        Path(output_path)
        if output_path is not None
        else Path(f"{source}.decrypted")
    )
    if source.resolve() == destination.resolve():
        raise ValueError("Decrypted output must differ from the encrypted source")
    if destination.exists() and not overwrite:
        raise FileExistsError(f"Decrypted output already exists: {destination}")

    ciphertext = source.read_bytes().decode("utf-8").strip()
    plaintext = decrypt_text(ciphertext, key_path=key_path)
    _write_private_text_atomic(destination, plaintext, overwrite=overwrite)
    return destination


def inspect_file(
    source_path: str | Path,
    *,
    key_path: str | Path | None = None,
) -> dict[str, int | bool]:
    """Check ciphertext format and authenticated decryptability without outputting plaintext."""
    source = Path(source_path)
    if not source.is_file():
        raise FileNotFoundError(f"Encrypted input file not found: {source}")

    raw = source.read_bytes()
    ciphertext = raw.decode("utf-8").strip()
    version = detect_format_version(ciphertext)
    master_key = load_key(key_path)
    plaintext = _decrypt_text_with_key(ciphertext, master_key)
    del plaintext
    return {
        "format_version": version,
        "ciphertext_bytes": len(raw),
        "authenticated": True,
        "decryptable": True,
    }


def sign_text(message: str, *, key_path: str | Path | None = None) -> str:
    master = load_key(key_path)
    sign_key = _derive_subkey(master, purpose="sign", length=32)
    h = hmac.HMAC(sign_key, hashes.SHA256())
    h.update(message.encode("utf-8"))
    return base64.b64encode(h.finalize()).decode("ascii")


def verify_text(
    message: str, sig_b64: str, *, key_path: str | Path | None = None
) -> bool:
    master = load_key(key_path)
    sign_key = _derive_subkey(master, purpose="sign", length=32)
    sig = base64.b64decode(sig_b64)
    h = hmac.HMAC(sign_key, hashes.SHA256())
    h.update(message.encode("utf-8"))
    try:
        h.verify(sig)
        return True
    except Exception:
        return False
