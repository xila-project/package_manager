# xila-package-manifest

The shared archive manifest schema, portable to `no_std + alloc`. It contains
package identity, target/ABI requirements, declared capabilities and the
inventory of files embedded in a Xila archive.

The format is **versioned but still experimental**. It uses Miniserde JSON,
which allocates memory during decoding; it is not a zero-allocation MCU parser.
The input limit is `MAX_MANIFEST_BYTES`, with additional file-count and
content-size bounds. The signature domain separator covers the **exact encoded
manifest bytes**, not an arbitrary reserialization.

## Example

```rust
use xila_package_manifest::{Manifest, ManifestFile, FORMAT_VERSION, encode, decode};

let manifest = Manifest {
    format_version: FORMAT_VERSION,
    name: "community.weather".into(),
    version: "1.0.0".into(),
    target: "wasm32-wasip1".into(),
    minimum_xila_abi: 1,
    capabilities: vec![],
    files: vec![ManifestFile {
        path: "bin/weather.wasm".into(),
        size: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
    }],
};
let json = encode(&manifest).unwrap();
assert_eq!(decode(json.as_bytes()).unwrap(), manifest);
```

## Trust boundary

`decode` and `validate` perform structural validation only. They do **not**
authenticate the publisher, authorize capabilities, or establish any trust in
the manifest. Signed installations must validate an accepted trust key
and signature over the exact stored bytes. The signature protocol and
schema compatibility still require review before production use.

See [the format discussion](https://github.com/xila-project/core/issues/402).
