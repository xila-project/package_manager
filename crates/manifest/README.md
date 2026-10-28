# xila-package-manifest

The shared archive manifest schema, portable to `no_std + alloc`. It contains
package identity, target/ABI requirements, declared capabilities and the
inventory of files embedded in a Xila archive.

Format v2 adds an optional `application` descriptor, **without creating a
second identity, version, signature or capability manifest**. A package with
`application: null` carries standalone executables/resources; a package with an
application descriptor can be discovered by the launcher. `entrypoint` references
a bundle-relative, inventory-verified executable or a preinstalled system
executable. Its presence does not grant permissions or authorization. v1
archives remain readable and use the original v1 signature domain.

The format is **versioned but still experimental**. It uses Miniserde JSON,
which allocates memory during decoding; it is not a zero-allocation MCU parser.
The input limit is `MAX_MANIFEST_BYTES`, with additional file-count and
content-size bounds. The version-specific signature domain separator covers the **exact encoded
manifest bytes**, not an arbitrary reserialization.

## Example

```rust
use xila_package_manifest::{Manifest, ManifestFile, Application, FORMAT_VERSION, encode, decode};

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
    application: Some(Application {
        entrypoint: "bin/weather.wasm".into(),
        display_name: "Weather".into(),
        icon: "".into(),
        show_in_launcher: true,
    }),
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
