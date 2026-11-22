# xila-package-reader

The archive reader has two APIs:

- **In-memory legacy API:** `inspect_unsigned(&[u8])` and
  `verify_signed(&[u8], &PublicKey)` use `TarArchiveRef` and require the
  entire archive in RAM. They remain for backwards compatibility.
- **Incremental API:** `inspect_streaming(read_block, trusted_key)` or the
  push-oriented `StreamingVerifier::push(&[u8; 512])` / `finish()` use
  `TarStreamParser` from [tar-no-std](https://crates.io/crates/tar-no-std).
  `extract_streaming(read_block, trusted_key, write)` and
  `StreamingVerifier::extract` also return each file's bytes in the same pass.

## Streaming an authenticated package

```rust,no_run
use core::convert::Infallible;
use xila_package_reader::inspect_streaming;
use xila_package_verification::PublicKey;

// This illustrates the block-source contract. A real source should read from
// flash, Xila VFS, or a network stream and propagate any I/O error.
fn verify_from_blocks(
    mut next: impl FnMut(&mut [u8; 512]) -> Result<bool, Infallible>,
    trusted: &PublicKey,
) {
    let manifest = inspect_streaming(&mut next, Some(trusted)).unwrap();
    assert!(!manifest.files.is_empty());
}
```

The reader verifies the detached ordinary Ed25519 signature **over the
exact raw runtime manifest** before hashing the first executable or resource.
It does **not** sign a SHA-256 digest in lieu of the manifest: that would
change the signature protocol and invalidate compatibility with old packages.

Every declared payload is then checked with
`xila-package-verification::ContentVerifier`: a single incremental SHA-256
state and an exact byte counter. Files do not have to fit in RAM, and content
bytes do not enter an aggregate `Vec`.

Memory is dominated by **at most 64 KiB of raw manifest / signing-message
bytes**, plus the allocated parsed manifest (max 128 entries), Ed25519 state
and the caller's 512-byte block. The archive itself is never buffered.

The caller **must** submit all TAR blocks and call `finish()` after EOF:
until then, even verified individual files cannot be considered an accepted
package. This catches missing double-zero terminators, truncated payloads and
extra entries. The package format permits regular-file entries only, in the
order `.xila/manifest.json`, optional `.xila/manifest.sig`, then each
declared executable or resource. Special entries (symlinks, directory headers,
PAX/GNU extensions) are rejected, despite the upstream parser's default of
skipping them. Trailing zero padding is allowed; trailing nonzero blocks are
rejected.

## Extracting while verifying

`StreamingVerifier::extract(&block)` returns `Some(FileChunk)` for blocks that
belong to a declared file: `index` in `Manifest::files`, `first` (create the
file; no bytes), the payload `bytes` borrowed from the block, and `last` (size
and SHA-256 now verified). Files and their chunks arrive in manifest order, and
nothing is returned before the header signature is verified.
`extract_streaming` wraps this with a block source and a `write(file, chunk)`
callback. Write chunks to non-executable staging only, and discard everything
if any call or `finish()` fails.

```rust,no_run
use core::convert::Infallible;
use xila_package_reader::extract_streaming;
use xila_package_verification::PublicKey;

fn install_from_blocks(
    mut next: impl FnMut(&mut [u8; 512]) -> Result<bool, Infallible>,
    trusted: &PublicKey,
) {
    let manifest = extract_streaming(&mut next, Some(trusted), |file, chunk| {
        // Create `file.path` in staging when `chunk.first`, append
        // `chunk.bytes`, close it when `chunk.last`.
        let _ = (file, chunk);
        Ok(())
    })
    .unwrap();
    assert!(!manifest.files.is_empty());
}
```

**Security boundary:** on-device extraction must write to a quarantined
temporary location (not an executable/live path), check every hash and
signature and reach EOF before atomically publishing the bundle. This crate
implements only the reader/verifier and no Xila VFS or installer integration.
The caller must separately enforce publisher trust, deployment policy and
atomic activation. Successful unsigned verification is only an integrity check.
