# uag-envsec

Standalone Python library and CLI for encrypting environment files, managing the
key used to protect them, and encrypting/decrypting text values.

The package imports as `uag_envsec`; its distribution name is `uag-envsec`.
It has no dependency on the `uagent` application. `cryptography` is required;
`python-keyring` is optional and only needed when using an OS keyring backend.

- [API reference](docs/API.md)
- [Changelog](CHANGELOG.md)

## Install

```bash
python -m pip install .
```

Install OS-keyring support when desired:

```bash
python -m pip install '.[keyring]'
```

For development and tests:

```bash
python -m pip install '.[test]'
python -m pytest
```

## Python API

```python
from uag_envsec import decrypt_text, encrypt_text

ciphertext = encrypt_text("API_TOKEN=example")
plaintext = decrypt_text(ciphertext)
```

The default key is stored under `~/.uag/uag_envsec_key`, or in the OS keyring
when the selected backend and platform allow it. An explicit `key_path` can be
passed to `encrypt_text`, `decrypt_text`, `encrypt_file`, `decrypt_file`, and
related functions. `encrypt_file()` writes `<source>.sec` by default; the
plaintext source is retained and existing outputs are not overwritten.

## CLI

Encrypt a dotenv file to `<path>.sec`:

```bash
uag_envsec .env
```

Add or update a variable (the value is requested without echo if omitted):

```bash
uag_envsec add --file .env.sec --key API_TOKEN
```

Delete a variable:

```bash
uag_envsec delete --file .env.sec --key API_TOKEN
```

Use `--key-file PATH` to select an explicit file key. Existing output files are
not overwritten unless `--force` is supplied. `add` and `delete` read either
version and write version 1 by default; use `--format-version 0` when the
result must remain readable by an older `uag` release.

## Decrypt an encrypted file

Decrypt to a file without printing plaintext to the terminal:

```bash
uag_envsec decrypt --file .env.sec
```

By default this creates `.env.sec.decrypted`; use `--output` to choose another
path. The encrypted source is never replaced. An existing output is refused
unless `--force` is given. On POSIX systems the plaintext output is created
with owner-only permissions and written atomically.

The library API provides the same operation:

```python
from uag_envsec import decrypt_file

plain_path = decrypt_file(".env.sec")
```

`decrypt_file()` returns the output `Path`, keeps plaintext in memory until
writing, and does not overwrite an existing destination by default.

## Inspect an encrypted file

Check the envelope version and verify that the ciphertext authenticates and can
be decrypted, without printing plaintext or key material:

```bash
uag_envsec inspect --file .env.sec
```

The command reports the format version, ciphertext size, authentication result,
and decryptability. The library API returns the same metadata as a dictionary:

```python
from uag_envsec import inspect_file

metadata = inspect_file(".env.sec")
```

## Ciphertext format versions

- **Version 0** is the historical unversioned Base64 ciphertext. Data with no
  version marker is interpreted as version 0.
- **Version 1** uses the `uag-envsec:v1:` prefix. The prefix is authenticated
  as AES-GCM associated data, so removing or changing it causes decryption to
  fail. This reserves an explicit envelope version for future format evolution.

New encryption writes version 1 by default. Use version 0 explicitly when
creating data for older `uag` releases, which only understand the historical
unversioned format:

```python
ciphertext = encrypt_text(value, format_version=0)
```

```bash
uag_envsec .env --format-version 0
```

This library reads both formats. Unknown or malformed version markers are
rejected rather than guessed as legacy data.

## Migrate an existing encrypted file

Use the `migrate` command to decrypt an existing ciphertext in memory and
re-encrypt it using another supported envelope version. By default it upgrades
the file to version 1 and writes a new sibling file such as `.env.sec.v1`; the
source is never overwritten:

```bash
uag_envsec migrate --file .env.sec --to 1
```

Choose another destination with `--output`. `--force` permits replacing that
destination, but never replaces the source file.

The same operation is available through the library API:

```python
from uag_envsec import migrate_file, migrate_text

versioned_text = migrate_text(ciphertext, target_version=1)
versioned_path = migrate_file(".env.sec", target_version=1)
```

`migrate_text()` returns encrypted text and does not write a plaintext
intermediate file. `migrate_file()` writes atomically, preserves the source,
and by default names the output `<source>.v<target-version>`. If a file is
already in the requested format and no output path is specified, it validates
the ciphertext and returns the source path without creating another file.

## Rekey an encrypted file

`rekey` decrypts a file in memory and encrypts it under a different key. The
new key file is explicit and is created if it does not exist. By default the
source remains untouched and the output is `<source>.rekeyed`:

```bash
uag_envsec rekey --file .env.sec --old-key-file ~/.uag/uag_envsec_key --new-key-file ~/.uag/envsec-next.key
```

If `--old-key-file` is omitted, the configured default key backend is used.
The output uses version 1 by default; pass `--format-version 0` for older `uag`
compatibility. `--force` only replaces the output; it never replaces the source.
Keep the new key file safe. Rekeying one file does not change the library's
configured default key or automatically rotate other `.env.sec` files.

The library provides both text and file APIs:

```python
from uag_envsec import rekey_file, rekey_text

rotated = rekey_text(
    ciphertext,
    old_key_path="old.key",
    new_key_path="new.key",
)
rotated_path = rekey_file(
    ".env.sec",
    old_key_path="old.key",
    new_key_path="new.key",
)
```

`rekey_text()` requires the new key to exist and never writes plaintext to
disk. `rekey_file()` also requires an existing new key; the CLI creates it
before calling the API.

## Key backend settings

- `UAGENT_ENVSEC_KEY_BACKEND`: `auto`, `file`, or `keyring` (`os` is accepted
  as an alias for `keyring`). Linux defaults to `file`; other platforms default
  to `auto`.
- `UAGENT_KEYRING_TIMEOUT`: maximum wait for an OS keyring operation in
  seconds (default `3`, clamped to `0.1`–`30`).

In `auto` mode, keyring support is used when available; if the optional package
or a keyring backend is absent, the library uses the key file. Keyring access
errors and timeouts fail closed rather than silently switching key sources
while a request may still complete. The library never installs optional
dependencies implicitly. Select `keyring` explicitly to require an installed,
functional `python-keyring` backend.

File-backed keys, including explicit key paths, are created with owner-only
permissions on POSIX systems; existing key files with broader permissions are
restricted before use. The default key path rejects symlinks.
Encrypted CLI outputs are written through unique, owner-only temporary files
and replaced atomically. `save_key(overwrite=True)` replaces the active master
key but does not re-encrypt existing `.env.sec` files; retain the old key or
migrate the encrypted data before replacing it.

## Compatibility

This extraction preserves the existing `uag_envsec` Python import name, CLI
command, default key filename, keyring service/account, key-derivation labels,
and version-0 AES-GCM ciphertext format used by the `uag` application. Existing
keys and `.env.sec` files remain usable with the same key source.

## License

Apache-2.0. See [LICENSE](LICENSE).
