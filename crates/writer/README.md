# xila-package-writer

Deterministic **host-only** USTAR archive builder. It embeds the versioned
Miniserde JSON manifest first, an optional detached Ed25519 signature
second, and the declared regular-file payloads in manifest order.
File sizes and SHA-256 hashes are checked before writing.

## Example

```rust
use xila_package_manifest::{Manifest, ManifestFile, FORMAT_VERSION};
use xila_package_writer::{SourceFile, write_package};

let manifest = Manifest {
    schema: Some(xila_package_manifest::SCHEMA_URL.into()),
    format_version: FORMAT_VERSION,
    name: "community.example".into(),
    version: "1.0.0".into(),
    target: "wasm32-wasip1".into(),
    minimum_xila_abi: 1,
    capabilities: vec![],
    files: vec![ManifestFile {
        path: "bin/example.wasm".into(),
        size: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
    }],
    application: None,
};
let mut archive = Vec::new();
write_package(
    &mut archive,
    &manifest,
    &[SourceFile { path: "bin/example.wasm", bytes: b"abc" }],
    None,
).unwrap();
assert!(!archive.is_empty());
```

The writer deliberately emits no compression, links, directories,
GNU long-name extensions or PAX records. Filenames must be ASCII and fit
within the 99-byte USTAR profile supported by the paired reader.

A `None` signature produces an **unsigned, development-only archive**.
The writer does not handle private keys, publisher authorization or
repository policy. Signed publication requires a separate, reviewed
signing workflow and a production-ready signature protocol.
