# xila-package

Native executable to generate, refresh and bundle application packages. This first version produces only *development* archives. It does not sign packages, select trusted publishers, perform installation, or download releases.

Usage:

```bash
cargo run -p xila-package-builder -- manifest generate ./app ./manifest.json xila.calculator 1.0.0 wasm32-wasip1 1
cargo run -p xila-package-builder -- manifest update ./app ./manifest.json
cargo run -p xila-package-builder -- pack ./app ./manifest.json ./calculator.xpk
```

An optional trailing path to a raw 64-byte signature is supported for externally signed manifests. The signed bytes must exactly match the shared xila-package-manifest signing statement. The builder only inserts the supplied signature: it does not prove the signer was authorized.

Application sources are scanned in sorted order, links and special files are refused, and manifest files are recomputed using SHA-256. The packager validates the final archive through xila-package-reader. The source and the output manifest should be distinct directories.

This implementation currently reads all application files into host memory and the archive again for verification. This is acceptable only on host tooling and must not be copied into the microcontroller installation path.
