# xila-package-writer

Host-only deterministic USTAR writer using Rust's `tar` crate. Produces regular files in manifest order, a first embedded Miniserde JSON manifest, and an optional raw 64-byte signature supplied by a signing system. It validates file hashes and sizes before writing.

It deliberately writes no compressed content, no links, no extension records, and no directories. Paths are currently limited to 99 ASCII bytes. Output is tested through the separate `xila-package-reader` crate.

A missing signature means **development-only, untrusted** output. Signing keys and repository authorization are external concerns. A separate production signing workflow must be designed and validated.
