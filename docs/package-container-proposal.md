# Proposal: Xila package container, manifest and signatures

**Status: request for comments; NOT a frozen format, and NOT an implementation.**

This document records the recommended architecture for review. [Xila Core issue #402](https://github.com/xila-project/core/issues/402) remains the authority for the final format decision and required comparison with CPIO, SWUpdate, Alpine package formats and a minimal custom container.

## Core requirements

- Install from an offline file or a non-seekable network stream.
- Keep memory bounded independently of archive and payload size, especially for ESP32-S3.
- Authenticate metadata **before** treating payloads as installable or executable.
- Authenticate every installable file, its path, type, byte length, hash, compression choice and installation-relevant properties.
- Do not execute hooks or activate files until the entire package is validated and committed safely.
- Support a host-side writer and lightweight target-side reader without a full general-purpose archive dependency on target.
- Keep the authoring manifest distinct from the wire representation without creating two competing definitions of package semantics.

## Candidate TAR layout

If restricted USTAR is selected, the suggested order of entries is:

```text
calculator-1.0.0.xpk            (ordinary uncompressed TAR container)
  .xila/manifest.bin           (first regular file, canonical versioned metadata)
  .xila/manifest.sig           (second regular file, versioned signature envelope)
  bin/calculator.wasm          (regular file, raw or independently LZ4-block encoded)
  share/icon.png               (regular file, raw)
```

The extension `.xpk` refers to the Xila package **profile** of TAR, not a claim that any arbitrary TAR file is installable.

Production reader policy, to be defined and tested:
1. Require the first two entries to be the metadata and signature, bounded to declared maximum lengths.
2. Verify the signature with an already trusted key before proceeding to payload extraction or installation preflight.
3. Parse one versioned manifest with strict limits and check target/application binary interface, ownership, privileges, paths, file inventory, declared sizes and available storage.
4. For each subsequent regular entry, compare its path and stored length against the signed declaration in the required order. Decode optional bounded independent LZ4 blocks into caller-provided scratch buffers. Stream SHA-256 over the **logical, uncompressed bytes** into non-executable staging, and compare expanded lengths and digests.
5. Reject undeclared, duplicate, out-of-order, missing, special, linked or extension entries; reject trailing non-padding data, malformed headers or checksums, path traversal, decompression bombs, overflows and extra payloads.
6. Commit an authenticated staged installation transaction and publish authenticated installed-file metadata, with crash recovery. No execution or install hook before commit.

A package-level SHA-256 digest authenticated by a signed remote index can additionally bind the **exact TAR bytes** for download integrity and byte-for-byte publication identity. That digest is optional for *offline package authenticity*, where the signed manifest and strict entry verification must suffice.

## What exactly is signed?

**Preferred: sign a deterministic, versioned package manifest with Ed25519.** The signature is NOT confined to the Wasm executable and need not cover the raw TAR headers and padding. The manifest must cover the entire semantically installable package.

A signature envelope should identify the format version and trusted signer key identifier. The signature-covered message must be unambiguous, include a fixed domain/purpose marker and format version, and bind the exact manifest bytes. This signed-byte definition must be frozen and exercised with golden test vectors before implementation.

An example only, not a final protocol:

```text
signed_message = "XILA-PACKAGE-MANIFEST-V1\0" || manifest_length || canonical_manifest_bytes
signature = Ed25519.sign(publisher_private_key, signed_message)
```

The final encoding of `manifest_length`, signature envelope and message must be specified exactly (including endianness), not inferred from pseudocode. The existing `verification::PublicKey` in Core performs strict ordinary Ed25519 verification on byte slices; it does not define the message format or the trust policy.

Signing the manifest avoids signing TAR padding, timestamps and other incidental archive bytes while preserving verification of every logical payload file. It also enables immediate metadata authentication, followed by per-file streaming verification. It does **not** remove the need for strict TAR framing and inventory enforcement.

If keeping the full canonical manifest in RAM proves too expensive on constrained targets, consider a bounded streaming metadata representation or signing a **domain-separated digest** of streamed canonical bytes as an explicit, separately versioned protocol. Do not silently substitute a content digest for ordinary Ed25519 signed-message bytes: producer and verifier must agree exactly on what is signed.

## Manifest structure to discuss

Define one authoritative `PackageManifestV1` in the shared `package_format` library, likely using a compact `no_std` binary representation such as Postcard. A human-readable authoring manifest (for example TOML) is a host tool input mapped to the same semantic schema and validated by the shared library, **not** an independently trusted format.

Suggested minimal semantic fields (provisional):

```text
PackageManifestV1
  format_version
  package_identifier            # namespace.application
  package_version               # explicit version ordering policy
  package_kind                  # portable Wasm application, other kinds only when justified
  target                        # for instance wasm32-wasip1
  minimum_runtime_abi_version
  maximum_runtime_abi_version   # optional compatibility ceiling if justified
  required_features             # optional
  requested_capabilities        # authenticated requests, not automatic grants
  dependencies                  # optional, likely absent in first release
  total_expanded_size
  files[]
    archive_path                # normalized, relative, unique
    destination_path            # preferably derived or scoped, not arbitrary absolute paths
    file_kind                   # regular file initially
    stored_size                 # bytes as present in TAR
    expanded_size               # decompressed bytes
    compression                 # none or independent LZ4 blocks
    maximum_block_size          # only when compressed
    sha256                      # uncompressed logical bytes
    install_flags               # only necessary, explicitly enumerated semantics
```

Keep metadata small; define bounds for file count, path length, fields, metadata size, capability list, per-file expansion and cumulative expansion. Reject unknown or unsupported manifest versions rather than guessing their semantics.

Keep a separate *repository publication declaration* containing URLs, exact published artifact lengths and hashes. That declaration must not become a second canonical install-time metadata standard: the shared host publisher should cross-check it against the actual signed package.

An authenticated repository index must not silently grant an untrusted application privileged capabilities. Installation authorization and runtime enforcement are separate decisions.

## Producing compatible TAR files

The host tool can use Rust's ordinary `tar` crate, `tar::Builder` and `Header::new_ustar()`. For reproducible output, fix modification timestamps, user/group identifiers, modes and ordering; write normal files only. Do not allow automatic GNU long-name or PAX-only extensions in the Xila profile. Verify the output by reading it with the **actual target parser** and adversarial test cases, not merely a general TAR extractor.

`tar-no-std` version 0.5.0 is **reader-only**; its primary `TarArchiveRef::new(&[u8])` interface expects archive bytes already in memory. Therefore it is NOT sufficient by itself as the network-streaming reader for ESP32-class targets. Either adapt its header parser to a bounded forward-only source (subject to license and maintenance review), or use a separately evaluated streaming TAR parser with a deliberately restricted profile.

Also note that `tar-no-std` skips special and extension entries in ordinary iteration. The Xila installer must explicitly reject these rather than silently skipping them, otherwise unsigned archive semantics may be hidden from the verifier.

## Decisions still open

1. Final TAR-versus-CPIO-versus-ADB comparison, parser footprint and streaming-read design.
2. Canonical binary manifest encoding, exact versioned structure, path and size limits, and signature-covered byte definition.
3. Signature envelope shape, publisher key identifiers, key rotation and trust separation between community packages and the official repository.
4. Optional LZ4 block framing, block-size bound, decompressor buffer budget and whether uncompressed-only comes first.
5. Rules for installation paths, compatibility, requested capabilities and declarative shortcuts.
6. Target metadata preflight and crash-consistent activation on LittleFS and other filesystems.
7. Separate signed static index format for direct package lookup, with rollback and freshness protection (search is out of first-release scope).

## Supporting references

- `tar-no-std` reader: https://docs.rs/tar-no-std/0.5.0/tar_no_std/
- Rust TAR archive builder: https://docs.rs/tar/latest/tar/struct.Builder.html
- Rust USTAR header: https://docs.rs/tar/latest/tar/struct.Header.html
- SWUpdate descriptor and signature ordering: https://github.com/sbabic/swupdate/blob/master/doc/source/swupdate.rst
- Xila format and security tracking: https://github.com/xila-project/core/issues/402
- Xila cryptographic verification implementation: https://github.com/xila-project/core/tree/main/libraries/verification
