from __future__ import annotations

import os
import stat
import time
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from uag_envsec import (
    UnsupportedCiphertextVersionError,
    decrypt_file,
    detect_format_version,
    decrypt_text,
    encrypt_file,
    encrypt_text,
    inspect_file,
    migrate_file,
    migrate_text,
    rekey_file,
    rekey_text,
)
import uag_envsec.cli as envsec_cli
import uag_envsec.secret_core as secret_core


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, username: str) -> str | None:
        return self.values.get((service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        self.values[(service, username)] = password


def test_linux_defaults_to_file_backend(monkeypatch) -> None:
    monkeypatch.delenv("UAGENT_ENVSEC_KEY_BACKEND", raising=False)
    monkeypatch.setattr(secret_core.sys, "platform", "linux")

    assert secret_core._key_backend() == "file"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits only")
def test_default_key_file_permissions_are_restricted(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "file")
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)

    key_path = Path(secret_core.ensure_key_file())
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    key_path.chmod(0o644)
    secret_core.load_key()
    assert stat.S_IMODE(key_path.stat().st_mode) == 0o600

    explicit_key_path = tmp_path / "explicit.key"
    secret_core.ensure_key_file(explicit_key_path)
    explicit_key_path.chmod(0o644)
    secret_core.load_key(explicit_key_path)
    assert stat.S_IMODE(explicit_key_path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits only")
def test_cli_atomic_writer_uses_private_file_and_no_clobber(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / ".env.sec"
    envsec_cli._write_text_atomic(output_path, "ciphertext", overwrite=False)
    assert stat.S_IMODE(output_path.stat().st_mode) == 0o600

    with pytest.raises(FileExistsError):
        envsec_cli._write_text_atomic(output_path, "replacement", overwrite=False)
    assert output_path.read_text(encoding="utf-8") == "ciphertext"


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink behavior only")
def test_keyring_migration_rejects_symlink_source(
    monkeypatch, tmp_path: Path
) -> None:
    fake = FakeKeyring()
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: fake)
    real_key = tmp_path / "real.key"
    real_key.write_bytes(b"k" * secret_core.MASTER_KEY_BYTES)
    link_path = tmp_path / "linked.key"
    link_path.symlink_to(real_key)

    assert not secret_core._migrate_file_key_to_keyring(link_path)
    assert link_path.is_symlink()
    assert real_key.exists()
    assert not fake.values


def test_unversioned_ciphertext_is_version_zero(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    secret_core.ensure_key_file(key_path)

    ciphertext = encrypt_text(
        "UAGENT_TEST=value", key_path=key_path, format_version=0
    )

    assert not ciphertext.startswith("uag-envsec:")
    assert detect_format_version(ciphertext) == 0
    assert decrypt_text(ciphertext, key_path=key_path) == "UAGENT_TEST=value"


def test_version_one_ciphertext_round_trip(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    secret_core.ensure_key_file(key_path)

    ciphertext = encrypt_text(
        "UAGENT_TEST=value", key_path=key_path, format_version=1
    )

    assert ciphertext.startswith("uag-envsec:v1:")
    assert detect_format_version(ciphertext) == 1
    assert decrypt_text(ciphertext, key_path=key_path) == "UAGENT_TEST=value"


def test_version_one_marker_cannot_be_removed(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    secret_core.ensure_key_file(key_path)
    ciphertext = encrypt_text("UAGENT_TEST=value", key_path=key_path, format_version=1)
    unmarked_payload = ciphertext.split(":", 2)[2]

    with pytest.raises(InvalidTag):
        decrypt_text(unmarked_payload, key_path=key_path)


def test_unknown_ciphertext_version_is_rejected() -> None:
    with pytest.raises(UnsupportedCiphertextVersionError, match="version: 9"):
        detect_format_version("uag-envsec:v9:payload")


def test_keyring_backend_round_trip(monkeypatch, tmp_path: Path) -> None:
    fake = FakeKeyring()
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: fake)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "keyring")
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)

    location = secret_core.ensure_key_file()
    assert location == "keyring://uag-envsec/master-key"
    assert not (tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME).exists()

    encrypted = secret_core.encrypt_text("UAGENT_TEST=value")
    assert secret_core.decrypt_text(encrypted) == "UAGENT_TEST=value"


def test_cli_encrypt_can_write_version_one(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env"
    encrypted_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    source_path.write_text("UAGENT_TEST=value\n", encoding="utf-8")
    expected_plaintext = source_path.read_bytes().decode("utf-8")

    assert (
        envsec_cli.main(
            [
                "encrypt",
                str(source_path),
                "--output",
                str(encrypted_path),
                "--key-file",
                str(key_path),
            ]
        )
        == 0
    )

    ciphertext = encrypted_path.read_text(encoding="utf-8")
    assert detect_format_version(ciphertext) == 1
    assert decrypt_text(ciphertext, key_path=key_path) == expected_plaintext


def test_migrate_text_upgrades_unversioned_data_to_version_one(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "envsec.key"
    secret_core.ensure_key_file(key_path)
    original = encrypt_text("UAGENT_TEST=value", key_path=key_path, format_version=0)

    upgraded = migrate_text(original, target_version=1, key_path=key_path)

    assert detect_format_version(original) == 0
    assert detect_format_version(upgraded) == 1
    assert decrypt_text(upgraded, key_path=key_path) == "UAGENT_TEST=value"


def test_migrate_file_preserves_source_and_writes_versioned_sibling(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    original = encrypt_text("UAGENT_TEST=value\n", key_path=key_path, format_version=0) + "\n"
    source_path.write_text(original, encoding="utf-8")

    destination = migrate_file(source_path, key_path=key_path)

    assert destination == tmp_path / ".env.sec.v1"
    assert source_path.read_text(encoding="utf-8") == original
    migrated = destination.read_text(encoding="utf-8")
    assert detect_format_version(migrated.strip()) == 1
    assert decrypt_text(migrated.strip(), key_path=key_path) == "UAGENT_TEST=value\n"
    assert sorted(path.name for path in tmp_path.glob(".env.sec*")) == [
        ".env.sec",
        ".env.sec.v1",
    ]


def test_encrypt_file_writes_ciphertext_sibling_and_keeps_source(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env"
    secret_core.ensure_key_file(key_path)
    plaintext = "UAGENT_TEST=value\nsecond-line\n"
    source_path.write_bytes(plaintext.encode("utf-8"))

    destination = encrypt_file(source_path, key_path=key_path, format_version=1)

    assert destination == tmp_path / ".env.sec"
    assert source_path.read_bytes() == plaintext.encode("utf-8")
    ciphertext = destination.read_text(encoding="utf-8")
    assert detect_format_version(ciphertext) == 1
    assert decrypt_text(ciphertext, key_path=key_path) == plaintext


def test_encrypt_file_refuses_existing_destination(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env"
    destination = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    source_path.write_text("UAGENT_TEST=value", encoding="utf-8")
    destination.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        encrypt_file(source_path, key_path=key_path, output_path=destination)
    assert destination.read_text(encoding="utf-8") == "keep"


def test_rekey_text_uses_distinct_key_and_preserves_envelope_version(
    tmp_path: Path,
) -> None:
    old_key_path = tmp_path / "old.key"
    new_key_path = tmp_path / "new.key"
    secret_core.ensure_key_file(old_key_path)
    secret_core.ensure_key_file(new_key_path)
    original = encrypt_text(
        "UAGENT_TEST=value", key_path=old_key_path, format_version=1
    )

    rotated = rekey_text(
        original,
        old_key_path=old_key_path,
        new_key_path=new_key_path,
    )

    assert detect_format_version(rotated) == 1
    assert decrypt_text(rotated, key_path=new_key_path) == "UAGENT_TEST=value"
    with pytest.raises(InvalidTag):
        decrypt_text(rotated, key_path=old_key_path)


def test_rekey_text_rejects_same_key(tmp_path: Path) -> None:
    key_path = tmp_path / "same.key"
    secret_core.ensure_key_file(key_path)
    ciphertext = encrypt_text("secret", key_path=key_path)

    with pytest.raises(ValueError, match="must differ"):
        rekey_text(ciphertext, old_key_path=key_path, new_key_path=key_path)


def test_rekey_file_keeps_source_and_writes_private_sibling(
    tmp_path: Path,
) -> None:
    old_key_path = tmp_path / "old.key"
    new_key_path = tmp_path / "new.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(old_key_path)
    secret_core.ensure_key_file(new_key_path)
    original = encrypt_text(
        "UAGENT_TEST=value\n", key_path=old_key_path, format_version=0
    ) + "\n"
    source_path.write_text(original, encoding="utf-8")

    destination = rekey_file(
        source_path,
        old_key_path=old_key_path,
        new_key_path=new_key_path,
    )

    assert destination == tmp_path / ".env.sec.rekeyed"
    assert source_path.read_text(encoding="utf-8") == original
    rotated = destination.read_text(encoding="utf-8").strip()
    assert detect_format_version(rotated) == 1
    assert decrypt_text(rotated, key_path=new_key_path) == (
        "UAGENT_TEST=value\n"
    )
    with pytest.raises(InvalidTag):
        decrypt_text(destination.read_text(encoding="utf-8").strip(), key_path=old_key_path)


def test_cli_rekey_generates_new_key_and_keeps_source(tmp_path: Path) -> None:
    old_key_path = tmp_path / "old.key"
    new_key_path = tmp_path / "new.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(old_key_path)
    original = encrypt_text("UAGENT_TEST=value", key_path=old_key_path)
    source_path.write_text(original, encoding="utf-8")

    assert (
        envsec_cli.main(
            [
                "rekey",
                "--file",
                str(source_path),
                "--old-key-file",
                str(old_key_path),
                "--new-key-file",
                str(new_key_path),
            ]
        )
        == 0
    )

    destination = tmp_path / ".env.sec.rekeyed"
    assert source_path.read_text(encoding="utf-8") == original
    assert new_key_path.exists()
    assert decrypt_text(destination.read_text(encoding="utf-8"), key_path=new_key_path) == (
        "UAGENT_TEST=value"
    )


def test_decrypt_file_writes_plaintext_sibling_and_keeps_source(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    plaintext = "UAGENT_TEST=value\nsecond-line\n"
    original = encrypt_text(plaintext, key_path=key_path, format_version=1) + "\n"
    source_path.write_text(original, encoding="utf-8")

    destination = decrypt_file(source_path, key_path=key_path)

    assert destination == tmp_path / ".env.sec.decrypted"
    assert source_path.read_text(encoding="utf-8") == original
    assert destination.read_text(encoding="utf-8") == plaintext


def test_decrypt_file_refuses_existing_destination(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env.sec"
    destination = tmp_path / "plain.env"
    secret_core.ensure_key_file(key_path)
    source_path.write_text(
        encrypt_text("secret", key_path=key_path),
        encoding="utf-8",
    )
    destination.write_text("keep", encoding="utf-8")

    with pytest.raises(FileExistsError):
        decrypt_file(
            source_path,
            key_path=key_path,
            output_path=destination,
        )
    assert destination.read_text(encoding="utf-8") == "keep"


def test_decrypt_file_wrong_key_leaves_no_plaintext_output(tmp_path: Path) -> None:
    actual_key_path = tmp_path / "actual.key"
    wrong_key_path = tmp_path / "wrong.key"
    source_path = tmp_path / ".env.sec"
    destination = tmp_path / "plain.env"
    secret_core.ensure_key_file(actual_key_path)
    secret_core.ensure_key_file(wrong_key_path)
    source_path.write_text(
        encrypt_text("sensitive=value", key_path=actual_key_path),
        encoding="utf-8",
    )

    with pytest.raises(InvalidTag):
        decrypt_file(
            source_path,
            key_path=wrong_key_path,
            output_path=destination,
        )

    assert not destination.exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_cli_decrypt_writes_plaintext_file(tmp_path: Path, capsys) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    source_path.write_text(
        encrypt_text("UAGENT_TEST=value", key_path=key_path),
        encoding="utf-8",
    )

    assert (
        envsec_cli.main(
            [
                "decrypt",
                "--file",
                str(source_path),
                "--key-file",
                str(key_path),
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    destination = tmp_path / ".env.sec.decrypted"
    assert output.strip() == str(destination)
    assert "UAGENT_TEST" not in output
    assert destination.read_text(encoding="utf-8") == "UAGENT_TEST=value"


@pytest.mark.parametrize("format_version", [0, 1])
def test_inspect_file_reports_version_and_authentication(
    tmp_path: Path,
    format_version: int,
) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    ciphertext = encrypt_text(
        "do-not-display-this=value",
        key_path=key_path,
        format_version=format_version,
    )
    source_path.write_text(ciphertext, encoding="utf-8")

    result = inspect_file(source_path, key_path=key_path)

    assert result == {
        "format_version": format_version,
        "ciphertext_bytes": len(ciphertext.encode("utf-8")),
        "authenticated": True,
        "decryptable": True,
    }
    assert "do-not-display-this" not in repr(result)


def test_inspect_file_rejects_wrong_key(tmp_path: Path) -> None:
    actual_key = tmp_path / "actual.key"
    wrong_key = tmp_path / "wrong.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(actual_key)
    secret_core.ensure_key_file(wrong_key)
    source_path.write_text(
        encrypt_text("sensitive=value", key_path=actual_key),
        encoding="utf-8",
    )

    with pytest.raises(InvalidTag):
        inspect_file(source_path, key_path=wrong_key)


def test_cli_inspect_reports_metadata_without_plaintext(
    tmp_path: Path,
    capsys,
) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    source_path.write_text(
        encrypt_text("sensitive=value", key_path=key_path, format_version=0),
        encoding="utf-8",
    )

    assert (
        envsec_cli.main(
            [
                "inspect",
                "--file",
                str(source_path),
                "--key-file",
                str(key_path),
            ]
        )
        == 0
    )

    output = capsys.readouterr().out
    assert "format_version: 0" in output
    assert "authenticated: yes" in output
    assert "decryptable: yes" in output
    assert "sensitive=value" not in output


def test_cli_migrate_creates_v1_output_without_replacing_source(
    tmp_path: Path,
) -> None:
    key_path = tmp_path / "envsec.key"
    source_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    original = encrypt_text("UAGENT_TEST=value", key_path=key_path, format_version=0)
    source_path.write_text(original, encoding="utf-8")

    assert (
        envsec_cli.main(
            [
                "migrate",
                "--file",
                str(source_path),
                "--to",
                "1",
                "--key-file",
                str(key_path),
            ]
        )
        == 0
    )

    destination = tmp_path / ".env.sec.v1"
    assert source_path.read_text(encoding="utf-8") == original
    assert detect_format_version(destination.read_text(encoding="utf-8")) == 1


def test_cli_delete_removes_variable(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    envsec_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    encrypted = secret_core.encrypt_text(
        "UAGENT_KEEP=ok\nUAGENT_REMOVE=gone\n",
        key_path=key_path,
    )
    envsec_path.write_text(encrypted, encoding="utf-8")

    assert (
        envsec_cli.main(
            [
                "delete",
                "--file",
                str(envsec_path),
                "--key-file",
                str(key_path),
                "--key",
                "UAGENT_REMOVE",
            ]
        )
        == 0
    )

    plaintext = secret_core.decrypt_text(
        envsec_path.read_text(encoding="utf-8"),
        key_path=key_path,
    )
    assert plaintext == "UAGENT_KEEP=ok\n"


def test_cli_delete_upgrades_v0_input_to_v1(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    envsec_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    envsec_path.write_text(
        encrypt_text(
            "UAGENT_KEEP=ok\nUAGENT_REMOVE=gone\n",
            key_path=key_path,
            format_version=0,
        ),
        encoding="utf-8",
    )

    assert (
        envsec_cli.main(
            [
                "delete",
                "--file",
                str(envsec_path),
                "--key-file",
                str(key_path),
                "--key",
                "UAGENT_REMOVE",
            ]
        )
        == 0
    )

    updated = envsec_path.read_text(encoding="utf-8")
    assert detect_format_version(updated) == 1
    assert decrypt_text(updated, key_path=key_path) == "UAGENT_KEEP=ok\n"


def test_cli_add_preserves_versioned_format(tmp_path: Path) -> None:
    key_path = tmp_path / "envsec.key"
    envsec_path = tmp_path / ".env.sec"
    secret_core.ensure_key_file(key_path)
    envsec_path.write_text(
        encrypt_text("UAGENT_EXISTING=yes\n", key_path=key_path, format_version=1),
        encoding="utf-8",
    )

    assert (
        envsec_cli.main(
            [
                "add",
                "--file",
                str(envsec_path),
                "--key-file",
                str(key_path),
                "--key",
                "UAGENT_ADDED",
                "--value",
                "new",
            ]
        )
        == 0
    )

    result = envsec_path.read_text(encoding="utf-8")
    assert detect_format_version(result) == 1
    assert decrypt_text(result, key_path=key_path) == (
        "UAGENT_EXISTING=yes\nUAGENT_ADDED=new\n"
    )


def test_auto_migrates_existing_file_key(monkeypatch, tmp_path: Path, capsys) -> None:
    fake = FakeKeyring()
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: fake)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "file")
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)

    secret_core.ensure_key_file()
    old_key = (tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME).read_bytes()
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "auto")

    secret_core.ensure_key_file()
    assert "Migrated envsec key to OS keyring" in capsys.readouterr().err
    stored = fake.get_password(
        secret_core.KEYRING_SERVICE, secret_core.KEYRING_USERNAME
    )
    assert stored is not None
    assert secret_core._decode_key(stored) == old_key
    assert not (tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME).exists()


def test_file_key_path_overrides_keyring(monkeypatch, tmp_path: Path) -> None:
    fake = FakeKeyring()
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: fake)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "keyring")
    key_path = tmp_path / "explicit.key"

    secret_core.ensure_key_file(key_path)
    assert key_path.exists()
    assert secret_core.load_key(key_path) == key_path.read_bytes()


def test_keyring_backend_requires_keyring(monkeypatch) -> None:
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: None)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "keyring")

    with pytest.raises(RuntimeError, match="python-keyring is not installed"):
        secret_core.ensure_key_file()


def test_auto_removes_duplicate_file_key_when_keyring_matches(
    monkeypatch, tmp_path: Path
) -> None:
    fake = FakeKeyring()
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: fake)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "file")
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)

    secret_core.ensure_key_file()
    key_path = tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME
    key = key_path.read_bytes()
    fake.set_password(
        secret_core.KEYRING_SERVICE,
        secret_core.KEYRING_USERNAME,
        secret_core.base64.b64encode(key).decode("ascii"),
    )
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "auto")

    assert secret_core.ensure_key_file() == "keyring://uag-envsec/master-key"
    assert not key_path.exists()


def test_auto_replaces_different_keyring_key_with_file_key(
    monkeypatch, tmp_path: Path
) -> None:
    fake = FakeKeyring()
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: fake)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "file")
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)

    secret_core.ensure_key_file()
    key_path = tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME
    file_key = key_path.read_bytes()
    fake.set_password(
        secret_core.KEYRING_SERVICE,
        secret_core.KEYRING_USERNAME,
        secret_core.base64.b64encode(b"x" * secret_core.MASTER_KEY_BYTES).decode(
            "ascii"
        ),
    )
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "auto")

    assert secret_core.ensure_key_file() == "keyring://uag-envsec/master-key"
    assert not key_path.exists()
    stored = fake.get_password(
        secret_core.KEYRING_SERVICE, secret_core.KEYRING_USERNAME
    )
    assert stored is not None
    assert secret_core._decode_key(stored) == file_key


def test_auto_uses_file_backend_when_keyring_is_absent(
    monkeypatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: None)
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "auto")

    location = secret_core.ensure_key_file()

    assert location == str(tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME)
    assert len(secret_core.load_key()) == secret_core.MASTER_KEY_BYTES


def test_auto_refuses_file_fallback_when_keyring_read_fails(
    monkeypatch, tmp_path: Path
) -> None:
    class BrokenKeyring:
        def get_password(self, service: str, username: str) -> None:
            raise RuntimeError("temporarily unavailable")

    monkeypatch.setattr(secret_core, "_keyring_module", lambda: BrokenKeyring())
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "auto")

    with pytest.raises(RuntimeError, match="refusing file-key fallback"):
        secret_core.ensure_key_file()
    assert not (tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME).exists()


def test_auto_fails_closed_when_keyring_read_times_out(
    monkeypatch, tmp_path: Path
) -> None:
    class HangingKeyring:
        def get_password(self, service: str, username: str) -> None:
            time.sleep(1)
            return None

        def set_password(self, service: str, username: str, password: str) -> None:
            raise AssertionError("set_password must not be called after timeout")

    monkeypatch.setattr(secret_core, "_keyring_module", lambda: HangingKeyring())
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)
    monkeypatch.setattr(secret_core, "_KEYRING_TIMED_OUT", False)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "auto")
    monkeypatch.setenv("UAGENT_KEYRING_TIMEOUT", "0.1")

    started = time.monotonic()
    with pytest.raises(TimeoutError):
        secret_core.ensure_key_file()

    assert time.monotonic() - started < 0.8
    assert not (tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME).exists()


def test_auto_fails_closed_when_keyring_write_times_out(
    monkeypatch, tmp_path: Path
) -> None:
    class SlowWriteKeyring:
        def __init__(self) -> None:
            self.write_started = False

        def get_password(self, service: str, username: str) -> None:
            return None

        def set_password(self, service: str, username: str, password: str) -> None:
            self.write_started = True
            time.sleep(1)

    keyring = SlowWriteKeyring()
    monkeypatch.setattr(secret_core, "_keyring_module", lambda: keyring)
    monkeypatch.setattr(secret_core, "_home_dir", lambda: tmp_path)
    monkeypatch.setattr(secret_core, "_KEYRING_TIMED_OUT", False)
    monkeypatch.setenv("UAGENT_ENVSEC_KEY_BACKEND", "auto")
    monkeypatch.setenv("UAGENT_KEYRING_TIMEOUT", "0.1")

    with pytest.raises(TimeoutError):
        secret_core.ensure_key_file()

    assert keyring.write_started
    assert not (tmp_path / ".uag" / secret_core.DEFAULT_KEY_FILENAME).exists()
