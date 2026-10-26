# xila-package-manifest

Versioned package metadata with Miniserde. Miniserde is JSON-only and uses an allocator even though the crate is compatible with no_std; this prototype does **not** claim zero allocations. Input length and file count are limited, and file hashes cover uncompressed logical bytes.

The signed message proposal includes a versioned domain marker and exact raw manifest bytes. Schema, key policy, canonical encoding and strict rejection of unknown fields must be finalized before treating this as a production signature protocol. See Xila Core issue #402.
