"""uag_envsec

Standalone helpers for encrypting/decrypting environment files and values.

This package is intentionally small and can be reused outside uagent.
"""

from .secret_core import (
    CURRENT_FORMAT_VERSION,
    DEFAULT_KEY_FILENAME,
    DEFAULT_SEC_SUFFIX,
    KEYRING_SERVICE,
    KEYRING_USERNAME,
    LEGACY_FORMAT_VERSION,
    UnsupportedCiphertextVersionError,
    decrypt_file,
    decrypt_text,
    detect_format_version,
    encrypt_file,
    encrypt_text,
    ensure_key_file,
    inspect_file,
    load_key,
    migrate_file,
    migrate_key_file_to_keyring,
    migrate_text,
    rekey_file,
    rekey_text,
    save_key,
)

__all__ = [
    "CURRENT_FORMAT_VERSION",
    "DEFAULT_KEY_FILENAME",
    "DEFAULT_SEC_SUFFIX",
    "KEYRING_SERVICE",
    "KEYRING_USERNAME",
    "LEGACY_FORMAT_VERSION",
    "UnsupportedCiphertextVersionError",
    "decrypt_file",
    "decrypt_text",
    "detect_format_version",
    "encrypt_file",
    "encrypt_text",
    "ensure_key_file",
    "inspect_file",
    "load_key",
    "migrate_file",
    "migrate_key_file_to_keyring",
    "migrate_text",
    "rekey_file",
    "rekey_text",
    "save_key",
]
