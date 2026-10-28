# xila-package-bundle

Portable `#![no_std]` + `alloc` support for Xila application bundles.

This crate reuses the **same primitives as Xila Core**:
- `xila-package-manifest` / `miniserde` for the editable developer JSON and
  the generated runtime manifest, with a single validated wire format;
- `xila-package-verification` for allocation-free incremental SHA-256,
  checked sizes, constant-time digest verification and strict Ed25519 verification.

`FileHasher` incrementally calculates each file's metadata without opening a
filesystem handle. `Inventory` validates and deterministically sorts all
files, producing one runtime `Manifest` from the developer's configuration.
`verify_bytes`, `decode_sha256`, `signing_message`, and
`verify_signature` use no host OS APIs.

The caller supplies I/O. The native host builder currently uses `std::fs`,
`getargs`/`getargs-derive` and the host `tar` writer; a future Xila
application can instead supply VFS reads/writes to this portable crate
without pulling in the native CLI or TAR writer.

Signatures authenticate the exact generated manifest bytes, which contain
the SHA-256 and length of **all** declared payload files, including resources
and the executable. Signing the manifest therefore covers every resource
without embedding signatures in the file inventory or signing TAR padding.

This crate does **not** install bundles, mutate Xila VFS, manage trust anchors,
or control the Shell.
