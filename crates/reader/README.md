# xila-package-reader

Borrowed TAR archive inspection based on `tar-no-std` 0.5.0. It checks every archive header is an ordinary file, validates manifest-first layout, exact declared files and order, lengths, and SHA-256 digests. It supports inspecting unsigned development archives or verifying a signature with an **externally trusted** Ed25519 key.

Limitations: The underlying parser expects the entire TAR archive as a slice, and the manifest is decoded through Miniserde using `alloc`. Consequently this prototype is **not an appropriate installer network-streaming path for ESP32-S3**. Do not expose it as a safe installer until source streaming, signature policy, full memory accounting and hostile TAR tests have been completed.

Compression, special TAR extensions, links, undeclared entries, and symlinks are unsupported. The current format profile is explicitly experimental. See Xila Core issue #402.
