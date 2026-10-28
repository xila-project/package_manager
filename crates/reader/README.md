# xila-package-reader

The archive reader has two APIs:

- **In-memory legacy API:** `inspect_unsigned(&[u8])` and
  `verify_signed(&[u8], &PublicKey)` use `TarArchiveRef` and require the
  entire archive in RAM. They remain for backwards compatibility.
- **Incremental API:** `inspect_streaming(read_block, trusted_key)` or the
  push-oriented `StreamingVerifier::push(&[u8; 512])` / `finish()` use
  `TarStreamParser` from
  [tar-no-std PR #73](https://github.com/phip1611/tar-no-std/pull/73).

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

**Security boundary:** on-device extraction must write to a quarantined
temporary location (not an executable/live path), check every hash and
signature and reach EOF before atomically publishing the bundle. This PR
implements only the reader/verifier and no Xila VFS or installer integration.
The caller must separately enforce publisher trust, deployment policy and
atomic activation. Successful unsigned verification is only an integrity check.

The reader currently pins the head of the upstream
`tar-no-std` streaming PR by Git SHA; replace that with an upstream crate
release after the PR is merged.
