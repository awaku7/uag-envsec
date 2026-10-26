"""CLI for encrypting and updating .env.sec files."""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys
import tempfile
from pathlib import Path

from .secret_core import (
    CURRENT_FORMAT_VERSION,
    DEFAULT_SEC_SUFFIX,
    LEGACY_FORMAT_VERSION,
    decrypt_file,
    decrypt_text,
    detect_format_version,
    default_key_path,
    encrypt_text,
    encrypt_file,
    ensure_key_file,
    inspect_file,
    load_key,
    migrate_file,
    rekey_file,
)

_ENV_KEY_RE = re.compile(
    r"^\s*(?:export\s+)?(?P<key>[A-Za-z_][A-Za-z0-9_]*)\s*=", re.MULTILINE
)


def _build_encrypt_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uag_envsec",
        description="Encrypt a .env file into .env.sec.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        default=".env",
        help="Path to the input .env file (default: .env)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path for the encrypted file (default: input path + .sec)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="Key file path (default: ~/.uag/uag_envsec_key)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists",
    )
    parser.add_argument(
        "--format-version",
        type=int,
        choices=[LEGACY_FORMAT_VERSION, CURRENT_FORMAT_VERSION],
        default=CURRENT_FORMAT_VERSION,
        help=(
            "Ciphertext envelope version (default: 1; use 0 for older-uag compatibility)"
        ),
    )
    return parser


def _build_decrypt_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uag_envsec decrypt",
        description="Decrypt an encrypted env file to a private output file.",
    )
    parser.add_argument("--file", required=True, help="Encrypted input file")
    parser.add_argument(
        "--output",
        default=None,
        help="Plaintext output path (default: append .decrypted to the input filename)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="Key file path (default: configured key backend)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing output file (the encrypted source is never overwritten)",
    )
    return parser


def _build_inspect_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uag_envsec inspect",
        description="Inspect ciphertext version and verify that it can be decrypted.",
    )
    parser.add_argument("--file", required=True, help="Encrypted input file")
    parser.add_argument(
        "--key-file",
        default=None,
        help="Key file path (default: configured key backend)",
    )
    return parser


def _build_add_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uag_envsec add",
        description="Add or update a variable inside an encrypted .env.sec file.",
    )
    parser.add_argument(
        "--file",
        default=".env.sec",
        help="Path to the encrypted .env.sec file (default: .env.sec)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path (default: overwrite the input file)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="Key file path (default: ~/.uag/uag_envsec_key)",
    )
    parser.add_argument(
        "--key",
        default=None,
        help="Environment variable name",
    )
    parser.add_argument(
        "--value",
        default=None,
        help="Environment variable value",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists",
    )
    parser.add_argument(
        "--format-version",
        type=int,
        choices=[LEGACY_FORMAT_VERSION, CURRENT_FORMAT_VERSION],
        default=CURRENT_FORMAT_VERSION,
        help="Output ciphertext version (default: 1; use 0 for older uag)",
    )
    return parser


def _build_delete_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uag_envsec delete",
        description="Delete a variable from an encrypted .env.sec file.",
    )
    parser.add_argument(
        "--file",
        default=".env.sec",
        help="Path to the encrypted .env.sec file (default: .env.sec)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path (default: overwrite the input file)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="Key file path (default: ~/.uag/uag_envsec_key)",
    )
    parser.add_argument(
        "--key",
        required=True,
        help="Environment variable name to delete",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite the output file if it already exists",
    )
    parser.add_argument(
        "--format-version",
        type=int,
        choices=[LEGACY_FORMAT_VERSION, CURRENT_FORMAT_VERSION],
        default=CURRENT_FORMAT_VERSION,
        help="Output ciphertext version (default: 1; use 0 for older uag)",
    )
    return parser


def _build_migrate_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uag_envsec migrate",
        description="Migrate an encrypted env file to another format version.",
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Encrypted input file",
    )
    parser.add_argument(
        "--to",
        "--format-version",
        dest="target_version",
        type=int,
        choices=[LEGACY_FORMAT_VERSION, CURRENT_FORMAT_VERSION],
        default=CURRENT_FORMAT_VERSION,
        help="Target ciphertext format version (default: 1)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path (default: append .v<version> to the input filename)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        help="Key file path (default: configured key backend)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing output file (the source is never overwritten)",
    )
    return parser


def _build_rekey_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="uag_envsec rekey",
        description="Re-encrypt an encrypted file using a different key.",
    )
    parser.add_argument("--file", required=True, help="Encrypted input file")
    parser.add_argument(
        "--new-key-file",
        required=True,
        help="Key file to use for the new ciphertext; created if missing",
    )
    parser.add_argument(
        "--old-key-file",
        default=None,
        help="Current key file (default: configured key backend)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output path (default: append .rekeyed to the input filename)",
    )
    parser.add_argument(
        "--format-version",
        type=int,
        choices=[LEGACY_FORMAT_VERSION, CURRENT_FORMAT_VERSION],
        default=CURRENT_FORMAT_VERSION,
        help="Output envelope version (default: 1; use 0 for older uag)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite an existing output file (the source is never overwritten)",
    )
    return parser


def _format_env_value(value: str) -> str:
    if value == "":
        return '""'
    if "\n" in value or "\r" in value:
        escaped = (
            value.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
        )
        return f'"{escaped}"'
    if re.fullmatch(r"[A-Za-z0-9_./:@%+=,-]+", value):
        return value
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _upsert_env_text(text: str, key: str, value: str) -> str:
    line = f"{key}={_format_env_value(value)}"
    lines = text.splitlines()
    for idx, current in enumerate(lines):
        match = _ENV_KEY_RE.match(current)
        if match and match.group("key") == key:
            lines[idx] = line
            break
    else:
        lines.append(line)

    updated = "\n".join(lines)
    if text.endswith(("\n", "\r")):
        return updated + "\n"
    return updated


def _read_key_value_from_args(args: argparse.Namespace) -> tuple[str, str]:
    if args.key is not None and args.value is not None:
        key = args.key.strip()
        value = args.value
        return key, value

    if args.key is not None and args.value is None:
        key = args.key.strip()
        value = getpass.getpass("Value: ")
        return key, value

    if args.key is None and args.value is not None:
        raise SystemExit("--value requires --key")

    key = input("Key: ").strip()
    if not key:
        raise SystemExit("Key is required")
    value = getpass.getpass("Value: ")
    return key, value


def _resolve_key_file(raw: str | None) -> Path:
    return Path(raw) if raw else default_key_path()


def _write_text_atomic(
    path: Path,
    content: str,
    *,
    overwrite: bool = True,
) -> None:
    """Write encrypted text through a private, unique file in the target dir."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary_path, path)
        else:
            try:
                os.link(temporary_path, path)
            except FileExistsError as exc:
                raise FileExistsError(f"Output file already exists: {path}") from exc
            else:
                temporary_path.unlink()
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass


def _run_encrypt(args: argparse.Namespace) -> int:
    src_path = Path(args.path)
    if not src_path.is_file():
        print(f"Input file not found: {src_path}", file=sys.stderr)
        return 1

    out_path = (
        Path(args.output) if args.output else Path(str(src_path) + DEFAULT_SEC_SUFFIX)
    )
    if out_path.exists() and not args.force:
        print(f"Output file already exists: {out_path} (use --force)", file=sys.stderr)
        return 1

    key_file = _resolve_key_file(args.key_file) if args.key_file else None
    try:
        ensure_key_file(key_file)
        result_path = encrypt_file(
            src_path,
            key_path=key_file,
            output_path=out_path,
            format_version=args.format_version,
            overwrite=args.force,
        )
    except Exception as exc:
        print(f"Failed to encrypt {src_path}: {exc}", file=sys.stderr)
        return 1
    print(str(result_path))
    return 0


def _run_decrypt(args: argparse.Namespace) -> int:
    source_path = Path(args.file)
    if not source_path.is_file():
        print(f"Encrypted input file not found: {source_path}", file=sys.stderr)
        return 1

    destination = (
        Path(args.output)
        if args.output
        else Path(f"{source_path}.decrypted")
    )
    if source_path.resolve() == destination.resolve():
        print("Decrypted output must differ from the encrypted source", file=sys.stderr)
        return 1
    if destination.exists() and not args.force:
        print(f"Decrypted output already exists: {destination}", file=sys.stderr)
        return 1

    key_file = Path(args.key_file) if args.key_file else None
    try:
        result_path = decrypt_file(
            source_path,
            key_path=key_file,
            output_path=destination,
            overwrite=args.force,
        )
    except Exception as exc:
        print(f"Failed to decrypt {source_path}: {exc}", file=sys.stderr)
        return 1

    print(str(result_path))
    return 0


def _run_inspect(args: argparse.Namespace) -> int:
    source_path = Path(args.file)
    key_file = Path(args.key_file) if args.key_file else None
    try:
        result = inspect_file(source_path, key_path=key_file)
    except Exception as exc:
        print(f"Inspection failed: {exc}", file=sys.stderr)
        return 1

    print(f"format_version: {result['format_version']}")
    print(f"ciphertext_bytes: {result['ciphertext_bytes']}")
    print(f"authenticated: {'yes' if result['authenticated'] else 'no'}")
    print(f"decryptable: {'yes' if result['decryptable'] else 'no'}")
    return 0


def _run_add(args: argparse.Namespace) -> int:
    enc_path = Path(args.file)
    if not enc_path.exists():
        print(f"Encrypted file not found: {enc_path}", file=sys.stderr)
        return 1

    out_path = Path(args.output) if args.output else enc_path
    if (
        out_path.exists()
        and out_path.resolve() != enc_path.resolve()
        and not args.force
    ):
        print(f"Output file already exists: {out_path} (use --force)", file=sys.stderr)
        return 1

    key_file = _resolve_key_file(args.key_file) if args.key_file else None
    if key_file is not None and not key_file.exists():
        print(f"Key file not found: {key_file}", file=sys.stderr)
        return 1
    ensure_key_file(key_file)

    key, value = _read_key_value_from_args(args)
    if not key:
        print("Key is required", file=sys.stderr)
        return 1
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        print(f"Invalid environment variable name: {key}", file=sys.stderr)
        return 1

    try:
        encrypted_input = enc_path.read_text(encoding="utf-8").strip()
        detect_format_version(encrypted_input)
        plaintext = decrypt_text(encrypted_input, key_path=key_file)
    except Exception as exc:
        print(f"Failed to decrypt {enc_path}: {exc}", file=sys.stderr)
        return 1

    updated = _upsert_env_text(plaintext, key, value)
    _write_text_atomic(
        out_path,
        encrypt_text(updated, key_path=key_file, format_version=args.format_version),
        overwrite=args.force or out_path.resolve() == enc_path.resolve(),
    )
    print(str(out_path))
    return 0


def _run_delete(args: argparse.Namespace) -> int:
    enc_path = Path(args.file)
    if not enc_path.exists():
        print(f"Encrypted file not found: {enc_path}", file=sys.stderr)
        return 1

    out_path = Path(args.output) if args.output else enc_path
    if (
        out_path.exists()
        and out_path.resolve() != enc_path.resolve()
        and not args.force
    ):
        print(f"Output file already exists: {out_path} (use --force)", file=sys.stderr)
        return 1

    key = args.key.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        print(f"Invalid environment variable name: {key}", file=sys.stderr)
        return 1

    key_file = _resolve_key_file(args.key_file) if args.key_file else None
    if key_file is not None and not key_file.exists():
        print(f"Key file not found: {key_file}", file=sys.stderr)
        return 1
    ensure_key_file(key_file)

    try:
        encrypted_input = enc_path.read_text(encoding="utf-8").strip()
        detect_format_version(encrypted_input)
        plaintext = decrypt_text(encrypted_input, key_path=key_file)
    except Exception as exc:
        print(f"Failed to decrypt {enc_path}: {exc}", file=sys.stderr)
        return 1

    pattern = re.compile(
        rf"^[ \t]*(?:export[ \t]+)?{re.escape(key)}[ \t]*=[^\r\n]*(?:\r\n|\n|\r|$)",
        re.MULTILINE,
    )
    updated, count = pattern.subn("", plaintext)
    if count == 0:
        print(f"Environment variable not found: {key}", file=sys.stderr)
        return 1

    try:
        _write_text_atomic(
            out_path,
            encrypt_text(updated, key_path=key_file, format_version=args.format_version),
            overwrite=args.force or out_path.resolve() == enc_path.resolve(),
        )
    except Exception as exc:
        print(f"Failed to encrypt {out_path}: {exc}", file=sys.stderr)
        return 1

    print(str(out_path))
    return 0


def _run_migrate(args: argparse.Namespace) -> int:
    source_path = Path(args.file)
    if not source_path.is_file():
        print(f"Encrypted input file not found: {source_path}", file=sys.stderr)
        return 1

    key_file = Path(args.key_file) if args.key_file else None
    try:
        result_path = migrate_file(
            source_path,
            target_version=args.target_version,
            key_path=key_file,
            output_path=args.output,
            overwrite=args.force,
        )
    except Exception as exc:
        print(f"Failed to migrate {source_path}: {exc}", file=sys.stderr)
        return 1

    if result_path.resolve() == source_path.resolve() and args.output is None:
        print(
            f"{source_path} is already format version {args.target_version}; "
            "no migration needed."
        )
    else:
        print(str(result_path))
    return 0


def _run_rekey(args: argparse.Namespace) -> int:
    source_path = Path(args.file)
    if not source_path.is_file():
        print(f"Encrypted input file not found: {source_path}", file=sys.stderr)
        return 1

    destination = (
        Path(args.output) if args.output else Path(f"{source_path}.rekeyed")
    )
    if source_path.resolve() == destination.resolve():
        print("Rekey output must differ from the source file", file=sys.stderr)
        return 1
    if destination.exists() and not args.force:
        print(f"Rekey output already exists: {destination}", file=sys.stderr)
        return 1

    old_key_path = Path(args.old_key_file) if args.old_key_file else None
    new_key_path = Path(args.new_key_file)
    try:
        load_key(old_key_path)
        ensure_key_file(new_key_path)
        result_path = rekey_file(
            source_path,
            new_key_path=new_key_path,
            old_key_path=old_key_path,
            output_path=destination,
            format_version=args.format_version,
            overwrite=args.force,
        )
    except Exception as exc:
        print(f"Failed to rekey {source_path}: {exc}", file=sys.stderr)
        return 1

    print(str(result_path))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "inspect":
        parsed = _build_inspect_parser().parse_args(args[1:])
        return _run_inspect(parsed)
    if args and args[0] == "decrypt":
        parsed = _build_decrypt_parser().parse_args(args[1:])
        return _run_decrypt(parsed)
    if args and args[0] == "add":
        parsed = _build_add_parser().parse_args(args[1:])
        return _run_add(parsed)
    if args and args[0] == "delete":
        parsed = _build_delete_parser().parse_args(args[1:])
        return _run_delete(parsed)
    if args and args[0] == "migrate":
        parsed = _build_migrate_parser().parse_args(args[1:])
        return _run_migrate(parsed)
    if args and args[0] == "rekey":
        parsed = _build_rekey_parser().parse_args(args[1:])
        return _run_rekey(parsed)
    if args and args[0] == "encrypt":
        parsed = _build_encrypt_parser().parse_args(args[1:])
        return _run_encrypt(parsed)
    parsed = _build_encrypt_parser().parse_args(args)
    return _run_encrypt(parsed)


if __name__ == "__main__":
    raise SystemExit(main())
