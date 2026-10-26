# xila-package-reader

An archive integrity inspector based on `tar-no-std`. This library is
`no_std + alloc`, but its TAR parser requires the **complete archive**
in a borrowed byte slice, and manifest decoding allocates.

- `inspect_unsigned` validates TAR layout, file order, declared paths,
  payload sizes, and SHA-256 digests.
- `verify_signed` additionally checks the detached Ed25519 signature
  on the exact manifest bytes with an **externally trusted** public key.

## Example

```rust
use xila_package_reader::inspect_unsigned;

// Invalid archives are rejected; valid ones yield their parsed manifest.
assert!(inspect_unsigned(&[]).is_err());
```

## Security

The unsigned inspector is intended for format checks and development builds.
Successful verification of SHA-256 **does not prove who published a package**.
Only call the signed API with a trusted key selected by a separate policy.

The profile rejects special TAR records and undeclared entries, and does
not support symlinks, compression, or other extension records. This is
**not a bounded-memory network-streaming installer for an ESP32-S3**.
A proper streaming reader and installer remain future work.

See [the archive format design](https://github.com/xila-project/core/issues/402).
