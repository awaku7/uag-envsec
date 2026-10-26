# API reference

The public Python API is imported from `uag_envsec`. All ciphertext and key
files are UTF-8 text/binary files as noted below. Unless a function says
otherwise, `key_path=None` uses the configured default backend.

## Ciphertext versions

- Version 0 is the historical unversioned Base64 AES-GCM format. An input with
  no version marker is read as version 0.
- Version 1 uses the `uag-envsec:v1:` prefix and authenticates that prefix as
  AES-GCM associated data.
- New encryption defaults to version 1. Pass `format_version=0` only when the
  resulting ciphertext must remain readable by older `uag` releases.
- Decryption detects and reads both versions. Unknown or malformed version
  markers raise an error instead of being treated as legacy data.

## Text API

### `encrypt_text(plaintext, *, key_path=None, format_version=1) -> str`

Encrypt a string and return its ciphertext.

- `plaintext`: UTF-8 text to encrypt.
- `key_path`: optional key file path. Omit to use the configured default
  backend.
- `format_version`: `1` by default; specify `0` for legacy compatibility.

Raises `FileNotFoundError`, `ValueError`, or a keyring-related exception when
no usable key is available or the format version is unsupported.

### `decrypt_text(ciphertext, *, key_path=None) -> str`

Detect the input format, authenticate and decrypt it, then return plaintext.
Versionless data is interpreted as version 0. Authentication failures from
AES-GCM are raised; plaintext is never printed or written by this function.

### `detect_format_version(ciphertext) -> int`

Return `0` for unversioned legacy data and `1` for a supported version-1
ciphertext. Malformed version markers raise `ValueError`; unsupported numeric
versions raise `UnsupportedCiphertextVersionError`.

## File API

### `encrypt_file(source_path, *, key_path=None, output_path=None, format_version=1, overwrite=False) -> pathlib.Path`

Encrypt a UTF-8 text file. The default output is `<source>.sec`. The plaintext
source is not modified. Output is written atomically through a private
same-directory temporary file; an existing output is refused unless
`overwrite=True`.

### `decrypt_file(source_path, *, key_path=None, output_path=None, overwrite=False) -> pathlib.Path`

Decrypt an encrypted file. The default output is `<source>.decrypted`. The
encrypted source is not modified. Plaintext is held in memory and written
atomically; on POSIX the output file is owner-only. Existing outputs require
`overwrite=True`.

### `inspect_file(source_path, *, key_path=None) -> dict[str, int | bool]`

Check format and authenticated decryptability without returning or printing
plaintext. The returned dictionary contains:

- `format_version`: `0` or `1`.
- `ciphertext_bytes`: size of the source file in bytes.
- `authenticated`: `True` when the AES-GCM authentication check succeeds.
- `decryptable`: `True` when the file can be decrypted with the selected key.

Invalid ciphertext, an unavailable key, or an unsupported format raises an
exception. The plaintext is decrypted in memory for verification and discarded.

## Migration and key changes

### `migrate_text(ciphertext, *, target_version=1, key_path=None) -> str`

Decrypt and re-encrypt ciphertext under the same key. The default target is
version 1. When the source is already in the target version, it is validated
and returned unchanged.

### `migrate_file(source_path, *, target_version=1, key_path=None, output_path=None, overwrite=False) -> pathlib.Path`

Migrate an encrypted file while preserving the source. By default the output
is `<source>.v<target_version>`. If the source is already in the target format
and no output path is supplied, it is validated and its path is returned
without creating another file.

### `rekey_text(ciphertext, *, new_key_path, old_key_path=None, format_version=1) -> str`

Re-encrypt text under a different existing key. The default output format is
version 1. `new_key_path` must identify an existing key file; this API does not
create a key. The old and new keys must differ. Plaintext is kept in memory.

### `rekey_file(source_path, *, new_key_path, old_key_path=None, output_path=None, format_version=1, overwrite=False) -> pathlib.Path`

Re-encrypt a file under a different existing key. The default output is
`<source>.rekeyed`; the source is never overwritten. The function does not
change the configured default key or other encrypted files. Existing output
files require `overwrite=True`.

Use `ensure_key_file(new_key_path)` to safely create a new file key before
calling `rekey_text` or `rekey_file`.

## Key management

### `ensure_key_file(path=None, *, overwrite=False) -> str`

Ensure that a usable key exists and return its path or `keyring://` location.
When `path` is omitted, the configured backend is used. Existing keys are
validated before being returned.

### `save_key(path=None, *, overwrite=False) -> str`

Create a key and return its storage location. `overwrite=True` replaces the
selected key but does not re-encrypt existing ciphertext; retain the old key
or migrate the data before replacing it.

### `load_key(path=None) -> bytes`

Load and return the 32-byte master key. Handle the returned key as secret
material and do not log or expose it.

### `migrate_key_file_to_keyring() -> bool`

Attempt the configured automatic migration of the default key file to the OS
keyring. Returns `True` only after the keyring value has been verified and the
legacy file removed.

## Key backend configuration

- `UAGENT_ENVSEC_KEY_BACKEND`: `auto`, `file`, `keyring`, or `os` (`os` is an
  alias for `keyring`). Linux defaults to `file`; other platforms default to
  `auto`.
- `UAGENT_KEYRING_TIMEOUT`: timeout in seconds, clamped to `0.1`–`30`.

Keyring timeouts and ambiguous access failures fail closed rather than silently
switching to a different key source. See the README for installation and CLI
examples.
