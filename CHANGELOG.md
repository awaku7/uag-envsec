# Changelog

All notable changes to `uag-envsec` are documented here.

## [Unreleased]

## [0.1.2] - 2026-11-24

### Added

- Values-only dotenv encryption by default in the CLI and file API, with
  automatic decryption and authenticated variable-name binding;
  `--whole-file` preserves the previous whole-file mode.
- `encrypt_env_values` / `decrypt_env_values` Python APIs.
- `decrypt_text` detects values-only input by its header and decrypts it
  automatically, so existing whole-file consumers can read values-only
  files without changes.

### Compatibility

- Existing v0 and v1 whole-file ciphertext remains readable.
- Values-only files require this release (or later) to decrypt; older
  releases cannot read them.

## [0.1.1]

### Added

- Standalone `uag-envsec` Python package and `uag_envsec` CLI.
- Version-1 ciphertext envelopes, with versionless legacy ciphertext read as v0.
- File encryption/decryption and ciphertext inspection APIs and CLI commands.
- File and text migration between supported envelope versions.
- Per-file rekeying with an explicit new key, preserving the source file.
- Keyring support, secure key-file handling, and atomic private output writes.
- API reference and automated test coverage for legacy compatibility and security
  behavior.

### Compatibility

- New encryption writes v1 by default. Specify v0 when interoperating with older
  `uag` releases.
- Existing v0 data remains readable by this library.
