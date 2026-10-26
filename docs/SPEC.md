# uag-envsec Specification

**Status:** Current behavior specification for `uag-envsec` 0.1.0\
**Normative source:** This document describes the released behavior. If behavior changes, update this document, the API reference, and tests in the same change.

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express requirements for conforming implementations of this version.

## 1. Scope and package

`uag-envsec` is a Python library and command-line application for encrypting and decrypting UTF-8 text (including dotenv files), managing the encryption key, and migrating ciphertext between supported envelope versions or keys. It does not require the `uagent` application.

- Distribution name: `uag-envsec`
- Python import package: `uag_envsec`
- CLI entry point: `uag_envsec`
- Python requirement: 3.11 or later
- Required runtime dependency: `cryptography>=44.0.2`
- Optional OS keyring dependency: `keyring>=25.0.0`
- Optional test dependency: `pytest>=8.0`

The public Python API is the set exported by `uag_envsec.__init__`. The CLI and Python API are both covered by this specification; exact call signatures and return values are also listed in [API.md](API.md).

## 2. Functional requirements

An implementation conforming to version 0.1.0:

1. MUST encrypt and authenticate text using AES-GCM and MUST reject ciphertext that cannot be authenticated with the selected key.
1. MUST read both supported ciphertext envelopes, v0 and v1. New encryption MUST default to v1. Callers MAY request v0 for compatibility with older `uag` releases.
1. MUST preserve input files during file encryption, decryption, migration, and rekeying. These operations write to a distinct output path; an explicit output resolving to the source MUST be rejected.
1. MUST refuse to replace an existing output by default. An explicit overwrite option MAY replace the destination, but MUST NOT replace the source file.
1. MUST NOT print or return plaintext from the inspect operation. The Python text decryption API returns plaintext to its caller; the file API writes it to the requested output.
1. MUST keep encryption keys separate from ciphertext and MUST NOT silently fall back to a file key after an ambiguous OS-keyring error or timeout.
1. MUST avoid creating a plaintext intermediate file for encryption, migration, or rekeying. The implementation processes text in memory; it does not promise secure erasure of process memory.

## 3. Ciphertext envelope

### 3.1 Common payload

The plaintext input is encoded as UTF-8. A 32-byte master key is expanded to a 32-byte encryption subkey using HKDF with SHA-256, `salt=None`, and UTF-8 `info` value `uag_envsec.enc`.

For every encryption, the implementation generates a 12-byte nonce with the operating system random source and encrypts using AES-256-GCM. The serialized binary payload is:

```text
nonce[12] || ciphertext || authentication_tag[16]
```

The implementation applies standard Base64 encoding to that binary payload and emits the resulting ASCII text without line wrapping. There is no password-based key derivation or embedded key identifier.

### 3.2 Version 0 (legacy)

- The envelope has no version prefix.
- The Base64 payload contains the common serialized payload above.
- AES-GCM associated data is absent (`None`).
- Text without the recognized `uag-envsec:v` version introducer is interpreted as v0 and then decoded/decrypted as legacy data.

Version 0 is retained for compatibility. It SHOULD be selected only when the ciphertext must be read by a legacy `uag` release.

### 3.3 Version 1 (current)

- The exact ASCII prefix is `uag-envsec:v1:`.
- The portion after the prefix is the Base64-encoded common payload.
- The exact prefix bytes are supplied as AES-GCM associated data.

Changing or removing the v1 prefix therefore causes authentication to fail. Unknown numeric versions MUST be rejected with `UnsupportedCiphertextVersionError`; malformed versioned envelopes and empty v1 payloads MUST be rejected rather than guessed as v0.

### 3.4 Detection and validation

`detect_format_version()` returns `0` for unversioned data and `1` for a recognized v1 envelope. Ciphertext with an unrecognized numeric version raises `UnsupportedCiphertextVersionError`; malformed version markers raise `ValueError`. Decryption also rejects decoded payloads shorter than the 12-byte nonce plus 16-byte authentication tag, Base64 decoding errors, invalid UTF-8 plaintext, or authentication failure.

## 4. Key management

### 4.1 Key material and file storage

A generated master key is 32 random bytes. A key accepted from storage MUST contain exactly 32 bytes; the library does not assess the randomness of a caller-supplied key file. File-backed keys are stored as those raw bytes, not as Base64 text. The default key file is:

```text
~/.uag/uag_envsec_key
```

The parent directory is created as needed. On POSIX systems, key files are restricted to owner-only permissions (`0600`) when created and permissions that are broader are restricted before use. The default key path MUST NOT be a symbolic link; explicit key paths are checked for regular-file type and key length but are not subject to the default-path symlink prohibition.

Key creation uses a temporary file in the destination directory and avoids clobbering a key created concurrently unless overwrite was explicitly requested. `save_key(overwrite=True)` replaces the selected key; it does not re-encrypt existing ciphertext. Users MUST retain the old key or migrate/rekey affected ciphertext before discarding it.

### 4.2 OS keyring

When available, the optional `keyring` package stores the Base64 representation of the 32-byte key under service `uag-envsec` and username `master-key`.

`UAGENT_ENVSEC_KEY_BACKEND` accepts `auto`, `file`, `keyring`, or `os` (`os` is an alias for `keyring`). The default is `file` on Linux and `auto` on other platforms. In `auto` mode, a missing keyring package or unavailable keyring backend may use file storage. Other keyring read/write failures and timeouts fail closed rather than silently switching key sources.

`UAGENT_KEYRING_TIMEOUT` controls the per-operation timeout in seconds. Its default is `3`; values are clamped to the range `0.1` through `30`. A keyring operation that times out makes subsequent keyring operations in that process fail closed.

Automatic migration of the default file key to the keyring MUST preserve the existing key used by ciphertext. The keyring value is verified before the legacy key file is removed. Migration is only attempted in `auto` mode; it is not a general-purpose key rotation operation.

## 5. File-operation behavior

All file APIs accept UTF-8 text files and keep the source unchanged. File contents are read into memory; this version defines no separate streaming or maximum-file-size contract.

| Operation | Default destination | Source modified? | Default overwrite behavior |
|---|---|---:|---|
| `encrypt_file` | `<source>.sec` | No | Refuse existing destination |
| `decrypt_file` | `<source>.decrypted` | No | Refuse existing destination |
| `migrate_file` | `<source>.v<target-version>` | No | Refuse existing destination |
| `rekey_file` | `<source>.rekeyed` | No | Refuse existing destination |

When migration is requested to the version already used by a valid input and no explicit output is given, the input is validated and its source path is returned without writing another file. File output is written through a unique temporary file in the destination directory and finalized atomically where the platform/filesystem supports the underlying operation. On POSIX, plaintext outputs are created owner-only. Applications should still protect output directories and handle decrypted files as secrets.

## 6. CLI contract

The executable is `uag_envsec`. A command-specific failure is reported on standard error and returns a nonzero status; successful file operations print the result path. Argparse usage errors use argparse's nonzero exit behavior. Plaintext values supplied on the command line may be visible in shell history or process listings; the interactive hidden prompt is preferred for secret values.

| Form | Purpose and defaults |
|---|---|
| `uag_envsec [PATH] [--output PATH] [--key-file PATH] [--force] [--format-version 0\|1]` | Encrypt a file. `PATH` defaults to `.env`; output defaults to `<PATH>.sec`; format defaults to v1. `uag_envsec encrypt ...` is an equivalent explicit form. |
| `uag_envsec decrypt --file PATH [--output PATH] [--key-file PATH] [--force]` | Decrypt to `<PATH>.decrypted` by default. |
| `uag_envsec inspect --file PATH [--key-file PATH]` | Report format version, ciphertext byte count, authentication, and decryptability; never print plaintext. |
| `uag_envsec add [--file PATH] [--output PATH] [--key-file PATH] [--key NAME] [--value VALUE] [--force] [--format-version 0\|1]` | Add or update a dotenv variable. Input defaults to `.env.sec`; output defaults to the input, so the encrypted file is updated in place. If `--value` is omitted, the value is requested with echo disabled. If both key and value are omitted, the command prompts for both. |
| `uag_envsec delete --key NAME [--file PATH] [--output PATH] [--key-file PATH] [--force] [--format-version 0\|1]` | Remove matching variable assignment lines. Input defaults to `.env.sec`; output defaults to the input. A missing variable is an error. |
| `uag_envsec migrate --file PATH [--to 0\|1] [--output PATH] [--key-file PATH] [--force]` | Migrate envelope version. `--to` also accepts `--format-version`; the target defaults to v1. The input is preserved. |
| `uag_envsec rekey --file PATH --new-key-file PATH [--old-key-file PATH] [--output PATH] [--format-version 0\|1] [--force]` | Re-encrypt under a different key. The CLI creates the new key file if necessary; the Python `rekey_*` APIs require it to exist. The input is preserved. |

Environment variable names handled by `add` and `delete` MUST match `[A-Za-z_][A-Za-z0-9_]*`. `add` replaces the first matching assignment or appends a new assignment. `delete` removes matching assignment lines and fails when none are found. Both operations write v1 by default and can be directed to v0 for legacy compatibility.

## 7. Public Python API

The exported API includes text and file encrypt/decrypt operations, format detection, inspection, migration, rekeying, and key management. Its canonical names are:

- `encrypt_text`, `decrypt_text`, `detect_format_version`
- `encrypt_file`, `decrypt_file`, `inspect_file`
- `migrate_text`, `migrate_file`, `rekey_text`, `rekey_file`
- `ensure_key_file`, `save_key`, `load_key`, `migrate_key_file_to_keyring`

The API MUST NOT log or print key bytes. `decrypt_text()` returns plaintext to its caller. `inspect_file()` decrypts in memory to verify authentication and discards the plaintext; its result contains version, ciphertext size, and successful authentication/decryptability flags. Exact parameters, exceptions, and edge cases are maintained in [API.md](API.md).

## 8. Security properties and limitations

- AES-GCM provides confidentiality and authentication when the master key remains secret and nonce generation is secure. Anyone holding the key can decrypt the data.
- The format does not provide password protection, key escrow, multi-key identifiers, rollback detection, or automatic rotation of all files.
- Encryption, decryption, inspection, add/delete, migration, and rekeying process content in memory. Python and the operating system do not guarantee secure erasure of those memory copies.
- Atomic output replacement reduces partial-file exposure but is not a substitute for backups, filesystem security, or safe handling of plaintext after decryption.
- Callers are responsible for protecting key backups, decrypted outputs, command-line arguments, and the host environment.

## 9. Compatibility and conformance

Version 0.1.0 MUST remain able to read supported v0 and v1 envelopes. Version 0 output is the compatibility format for older `uag` releases; version 1 is the default for newly written ciphertext. Any future incompatible envelope MUST use a new explicit version and MUST NOT be silently interpreted as v0.

A release conforms to this specification when its exported API and CLI behavior match this document and the automated tests cover the cryptographic formats, key-backend failure behavior, source preservation, overwrite protections, and supported migration paths. The package's CI additionally builds and validates wheel and source distributions.
