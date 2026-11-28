# xila-package-manifest

The shared archive manifest schema, portable to `no_std + alloc`. It contains
package identity, target and Xila version requirements, declared capabilities and the
inventory of files embedded in a Xila archive.

The manifest carries an optional `application` descriptor.
A package with `application: null` carries standalone executables/resources;
an application descriptor enables launcher discovery. Its `entrypoint`
references a bundle-relative, inventory-verified executable or a preinstalled
system executable. This metadata does not grant permissions or authorization.

Format version 2 requires `xila_version` as a `"major.minor"` string in the
developer manifest, runtime manifest and registry entry. Both components
are decimal integers from 0 through 65535 without leading zeros. Use
`compatible(declared, running)` to apply the Xila version rule. Before 1.0, the
major and minor versions must match. Starting at 1.0, the major versions must
match and the running minor must be at least the declared minor. Patch versions
are ignored. Regenerate format version 1 development artifacts and re-sign
any signed manifests after regeneration.

The JSON Schema is maintained in
[schemas/package-manifest.schema.json](../../schemas/package-manifest.schema.json).
For editor completion and validation, authored manifests can include
`"$schema": "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/package-manifest.schema.json"`.
`xila-package manifest generate` emits this hint by default. It is covered
by signed manifest bytes but **never fetched at runtime** and is not a trust
anchor. JSON Schema validation is advisory and cannot replace verifying the
file hashes, manifest/file reference consistency or publisher authorization.

The format is **versioned but still experimental**. It uses Miniserde JSON,
which allocates memory during decoding; it is not a zero-allocation MCU parser.
The input limit is `MAX_MANIFEST_BYTES`, with additional file-count and
content-size bounds. The v1 signature domain separator covers the **exact encoded
manifest bytes**, not an arbitrary reserialization.

`Manifest::file(path)` looks up the exact inventory entry for a bundle-relative
path, and `ManifestFile::digest()` (or `decode_sha256`) strictly decodes its
lowercase hexadecimal SHA-256. Together with
`xila-package-verification::ContentVerifier`, they let a loader check installed
bytes against the manifest while streaming them, without the signing
dependencies. An installed manifest is only as trustworthy as the
installation that verified its signature and the file system permissions
that protect it afterwards.

## Example

```rust
use xila_package_manifest::{Manifest, ManifestFile, Application, Metadata, FORMAT_VERSION, XilaVersion, encode, decode};

let manifest = Manifest {
    schema: Some(xila_package_manifest::SCHEMA_URL.into()),
    format_version: FORMAT_VERSION,
    name: "example.xila.weather".into(),
    version: "1.0.0".into(),
    target: "wasm32-wasip1".into(),
    xila_version: XilaVersion::new(0, 1),
    capabilities: vec![],
    files: vec![ManifestFile {
        path: "executables/weather.wasm".into(),
        size: 3,
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
    }],
    application: Some(Application {
        entrypoint: "executables/weather.wasm".into(),
        display_name: "Weather".into(),
        icon: "".into(),
        show_in_launcher: true,
    }),
    metadata: Some(Metadata {
        summary: "Shows the current weather".into(),
        license: "MIT".into(),
        source: "https://github.com/example/weather".into(),
        homepage: None,
        author: Some("Example Weather".into()),
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

Registry entries pin a package signing key and generation. Rotation records
bind the next generation and both keys to the package identifier. The
installed origin stores the verified generation for subsequent upgrades.
See the [registry trust model](../../docs/registry-trust.md).
