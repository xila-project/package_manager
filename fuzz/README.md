# Fuzzing the package and registry parsers

This directory holds the cargo-fuzz harnesses for every parser that reads
bytes or text from a package or registry file. See
<https://github.com/xila-project/package_manager/issues/91> for the design
decision and the list of targets.

The harnesses live in their own Cargo workspace on purpose: they are built
only with a nightly toolchain by the fuzzing jobs, so the crates keep their
MSRV of 1.97 and their default build on stable is unchanged.

## Run locally

```sh
mise run fuzz:setup   # nightly toolchain with rust-src, plus cargo-fuzz
mise run fuzz:run     # every target for 120 seconds each
FUZZ_SECONDS=600 mise run fuzz:run   # longer local run
```

Corpora, build artifacts and crash files stay in `fuzz/corpus`, `fuzz/target`
and `fuzz/artifacts` and are never committed. To keep them outside the
repository, run with `CARGO_TARGET_DIR` and `FUZZ_CORPUS` pointing elsewhere,
for example under `~/.cache/xila-scratch/fuzzing/`.

The JSON targets are seeded from `tests/fixtures` and
`crates/builder/tests/fixtures`; the archive targets are seeded by
`cargo run --release --example make_seeds -- <corpus-root>`, which writes a
signed and an unsigned package plus damaged variants. No target uses the
network.

## Targets

| Target | Parser under test |
| --- | --- |
| `manifest` | `xila_package_manifest::decode` / `encode` round-trip |
| `developer_manifest` | `decode_developer` / `encode_developer` round-trip |
| `archive` | in-memory and streaming TAR readers, signed and unsigned |
| `archive_roundtrip` | `write_package` then every reader returns the same manifest |
| `file_inventory` | `FileHasher`, `Inventory`, `verify_bytes`, digest decoding |
| `signature_key` | `PublicKey::from_slice` / `verify_slice`, `decode_sha256` |
| `registry_entry` | `decode_registry_entry` round-trip |
| `rotation` | `decode_rotation` round-trip and public key decoding |
| `namespace` | `decode_namespace` round-trip, `Namespace::matches_identifier` |
| `trust_root` | `decode_root` round-trip, named-key decoding |
| `trust_index` | `decode_index` round-trip, `Index::file`, index listings |
| `repository_origin` | `decode_repository` / `decode_origin` round-trips |
| `transaction` | `decode_transaction` round-trip, temporary names |
| `version` | `XilaVersion`, `SemanticVersion`, `VersionRequirement`, identifiers, targets |
| `trust_chain` | `TrustedRoot` bootstrap/verify chain on untrusted bytes |
