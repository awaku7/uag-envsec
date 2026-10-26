# Changelog

All notable changes to `uag-envsec` are documented here.

## [Unreleased]

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
