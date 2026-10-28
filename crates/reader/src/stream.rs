//! Bounded-memory verification of signed Xila packages from TAR blocks.
//!
//! The TAR and each executable/resource are never buffered in full. Only
//! bounded signed metadata and the parsed manifest are retained in memory.
//! File contents are authenticated incrementally with ContentVerifier.

use alloc::vec::Vec;
use tar_no_std::{StreamEvent, TarStreamParser};

// USTAR's fixed 512-byte block size; tar-no-std deliberately keeps its
// internal BLOCKSIZE constant private.
const BLOCKSIZE: usize = 512;
use xila_package_bundle::decode_sha256;
use xila_package_manifest::{
    MANIFEST_PATH, MAX_MANIFEST_BYTES, Manifest, SIGNATURE_PATH, SIGNED_DOMAIN,
};
use xila_package_verification::{ContentVerifier, PublicKey};

use crate::Error;

/// Reader/source errors are separate from invalid or untrusted packages.
#[derive(Debug, PartialEq, Eq)]
pub enum StreamError<E> {
    Source(E),
    Package(Error),
}

#[derive(Clone, Copy, Debug)]
enum State {
    ManifestHeader,
    Manifest { size: usize, received: usize },
    AfterManifest,
    Signature { received: usize },
    Files,
    Payload,
    End,
}

/// Consume a package, one exactly 512-byte TAR block at a time.
///
/// - A maximum of 64 KiB of raw manifest bytes (plus signing domain separator)
///   is buffered. The parsed manifest also allocates a bounded inventory.
/// - Each payload is hashed with a constant-size SHA-256 state, independently
///   of its size; the caller owns the 512-byte I/O buffer.
/// - When a trusted key is supplied, the detached *ordinary* Ed25519 signature
///   is verified before the first payload is processed.
/// - Every TAR entry must be a regular file. Because the upstream streaming
///   parser silently skips special entries, a skipped nonzero block is rejected
///   here (including directory, PAX, link, and extension headers).
///
/// This API is deliberately free of I/O, VFS and installation side effects.
/// The caller MUST call finish() after feeding every block, including TAR
/// terminators, before considering the package accepted. Never publish bytes
/// written into temporary staging until the complete package is verified.
pub struct StreamingVerifier<'a> {
    parser: TarStreamParser,
    trusted: Option<&'a PublicKey>,
    state: State,
    signed_message: Vec<u8>,
    manifest: Option<Manifest>,
    signature: [u8; 64],
    has_signature: bool,
    signature_verified: bool,
    file_index: usize,
    current_file: Option<ContentVerifier>,
    failed: bool,
}

impl<'a> StreamingVerifier<'a> {
    pub fn new(trusted: Option<&'a PublicKey>) -> Self {
        Self {
            parser: TarStreamParser::new(),
            trusted,
            state: State::ManifestHeader,
            signed_message: Vec::new(),
            manifest: None,
            signature: [0; 64],
            has_signature: false,
            signature_verified: false,
            file_index: 0,
            current_file: None,
            failed: false,
        }
    }

    /// Push one block. On any failure, the verifier is permanently poisoned.
    pub fn push(&mut self, block: &[u8; BLOCKSIZE]) -> Result<(), Error> {
        if self.failed {
            return Err(Error::InvalidArchive);
        }
        let result = self.consume(block);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn consume(&mut self, block: &[u8; BLOCKSIZE]) -> Result<(), Error> {
        let event = self
            .parser
            .parse_block(block)
            .map_err(|_| Error::InvalidArchive)?;

        match event {
            Some(StreamEvent::Entry(entry)) => {
                let filename = entry.filename();
                let path = filename.as_str().map_err(|_| Error::InvalidArchive)?;
                self.on_entry(path, entry.payload_size())
            }
            Some(StreamEvent::Data { bytes, remaining }) => self.on_data(bytes, remaining),
            Some(StreamEvent::End) => self.on_end(),
            None => {
                // None also denotes skipped special TAR headers in the
                // upstream parser. Those are *not* allowed in the Xila format.
                // The first TAR terminator is all zero; further zero padding
                // after End is permitted. A skipped special header cannot be
                // zero, as a zero header is the TAR terminator.
                if block.iter().any(|&byte| byte != 0) {
                    Err(Error::UnexpectedEntry)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn on_entry(&mut self, path: &str, size: usize) -> Result<(), Error> {
        match self.state {
            State::ManifestHeader => {
                if path != MANIFEST_PATH || size == 0 || size > MAX_MANIFEST_BYTES {
                    return Err(Error::InvalidManifest);
                }
                // Construct the exact signed message *while* reading the
                // manifest, avoiding a second allocation/copy for Ed25519.
                self.signed_message = Vec::with_capacity(SIGNED_DOMAIN.len() + 4 + size);
                self.signed_message.extend_from_slice(SIGNED_DOMAIN);
                self.signed_message
                    .extend_from_slice(&(size as u32).to_le_bytes());
                self.state = State::Manifest { size, received: 0 };
                Ok(())
            }
            State::AfterManifest if path == SIGNATURE_PATH => {
                if size != self.signature.len() {
                    return Err(Error::InvalidSignature);
                }
                self.has_signature = true;
                self.state = State::Signature { received: 0 };
                Ok(())
            }
            State::AfterManifest | State::Files => {
                self.authenticate_header()?;
                let manifest = self.manifest.as_ref().ok_or(Error::InvalidManifest)?;
                let declared = manifest
                    .files
                    .get(self.file_index)
                    .ok_or(Error::UnexpectedEntry)?;
                if declared.path != path || declared.size != size as u64 {
                    return Err(Error::UnexpectedEntry);
                }
                let digest = decode_sha256(&declared.sha256).map_err(|_| Error::InvalidDigest)?;
                self.current_file = Some(
                    ContentVerifier::new(declared.size, digest)
                        .map_err(|_| Error::InvalidDigest)?,
                );
                if size == 0 {
                    self.end_file()?;
                } else {
                    self.state = State::Payload;
                }
                Ok(())
            }
            _ => Err(Error::UnexpectedEntry),
        }
    }

    fn on_data(&mut self, bytes: &[u8], remaining: usize) -> Result<(), Error> {
        match self.state {
            State::Manifest { size, received } => {
                let next = received
                    .checked_add(bytes.len())
                    .filter(|&len| len <= size)
                    .ok_or(Error::InvalidManifest)?;
                self.signed_message.extend_from_slice(bytes);
                if next == size {
                    let start = SIGNED_DOMAIN.len() + 4;
                    let decoded = xila_package_manifest::decode(&self.signed_message[start..])
                        .map_err(|_| Error::InvalidManifest)?;
                    self.manifest = Some(decoded);
                    self.state = State::AfterManifest;
                } else {
                    self.state = State::Manifest {
                        size,
                        received: next,
                    };
                }
                if next != size && remaining == 0 {
                    return Err(Error::InvalidManifest);
                }
                Ok(())
            }
            State::Signature { received } => {
                let next = received
                    .checked_add(bytes.len())
                    .filter(|&len| len <= 64)
                    .ok_or(Error::InvalidSignature)?;
                self.signature[received..next].copy_from_slice(bytes);
                self.state = if next == 64 {
                    State::Files
                } else {
                    State::Signature { received: next }
                };
                Ok(())
            }
            State::Payload => {
                self.current_file
                    .as_mut()
                    .ok_or(Error::UnexpectedEntry)?
                    .update(bytes)
                    .map_err(|_| Error::InvalidDigest)?;
                if remaining == 0 {
                    self.end_file()?;
                }
                Ok(())
            }
            _ => Err(Error::UnexpectedEntry),
        }
    }

    fn end_file(&mut self) -> Result<(), Error> {
        self.current_file
            .take()
            .ok_or(Error::UnexpectedEntry)?
            .verify()
            .map_err(|_| Error::InvalidDigest)?;
        self.file_index += 1;
        self.state = State::Files;
        Ok(())
    }

    fn authenticate_header(&mut self) -> Result<(), Error> {
        if self.signature_verified {
            return Ok(());
        }
        if let Some(trusted) = self.trusted {
            if !self.has_signature {
                return Err(Error::MissingSignature);
            }
            trusted
                .verify(&self.signed_message, &self.signature)
                .map_err(|_| Error::InvalidSignature)?;
        }
        self.signature_verified = true;
        Ok(())
    }

    fn on_end(&mut self) -> Result<(), Error> {
        if !matches!(self.state, State::AfterManifest | State::Files) {
            return Err(Error::InvalidArchive);
        }
        self.authenticate_header()?;
        let manifest = self.manifest.as_ref().ok_or(Error::InvalidManifest)?;
        if self.file_index != manifest.files.len() {
            return Err(Error::UnexpectedEntry);
        }
        self.state = State::End;
        Ok(())
    }

    /// Complete verification after the input source reaches EOF.
    ///
    /// A missing TAR terminator, incomplete file, absent declared file or
    /// missing/wrong signature is a terminal error. Successful hashing without
    /// a trusted key establishes integrity only, not publisher identity.
    pub fn finish(self) -> Result<Manifest, Error> {
        if self.failed || !matches!(self.state, State::End) {
            return Err(Error::InvalidArchive);
        }
        self.parser.finish().map_err(|_| Error::InvalidArchive)?;
        self.manifest.ok_or(Error::InvalidManifest)
    }
}

/// Pull exactly 512-byte blocks from any caller-owned source (VFS/flash/network).
///
/// A closure returns Ok(false) only on EOF. I/O errors fail closed; a caller
/// must never translate an I/O failure into EOF. This function reads through
/// the TAR end and any trailing padding; it does not return a verified package
/// until EOF and StreamingVerifier::finish() have both succeeded.
pub fn inspect_streaming<S, E>(
    mut read_block: S,
    trusted: Option<&PublicKey>,
) -> Result<Manifest, StreamError<E>>
where
    S: FnMut(&mut [u8; BLOCKSIZE]) -> Result<bool, E>,
{
    let mut verifier = StreamingVerifier::new(trusted);
    let mut block = [0_u8; BLOCKSIZE];
    loop {
        if !read_block(&mut block).map_err(StreamError::Source)? {
            return verifier.finish().map_err(StreamError::Package);
        }
        verifier.push(&block).map_err(StreamError::Package)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString, vec};
    use ed25519_dalek::{Signer, SigningKey};
    use xila_package_bundle::{FileHasher, signing_message};
    use xila_package_manifest::{Application, FORMAT_VERSION, ManifestFile, SCHEMA_URL};
    use xila_package_writer::{SourceFile, write_package};

    fn hashed_file(path: &str, contents: &[u8]) -> ManifestFile {
        let mut hasher = FileHasher::new(path).unwrap();
        for chunk in contents.chunks(7) {
            hasher.update(chunk).unwrap();
        }
        hasher.finish().unwrap()
    }

    fn fixture(sign: bool) -> (Vec<u8>, PublicKey, Vec<u8>) {
        let wasm = vec![42_u8; 8 * 1024 + 17];
        let icon = b"distinct-icon-resource".to_vec();
        let manifest = Manifest {
            schema: Some(SCHEMA_URL.to_string()),
            format_version: FORMAT_VERSION,
            name: "community.example".into(),
            version: "1.0.0".into(),
            target: "wasm32-wasip1".into(),
            minimum_xila_abi: 1,
            capabilities: vec![],
            files: vec![
                hashed_file("bin/main.wasm", &wasm),
                hashed_file("resources/icon.png", &icon),
            ],
            application: Some(Application {
                entrypoint: "bin/main.wasm".into(),
                display_name: "Example".into(),
                icon: "resources/icon.png".into(),
                show_in_launcher: true,
            }),
        };
        let private = SigningKey::from_bytes(&[7_u8; 32]);
        let public = PublicKey::from_bytes(&private.verifying_key().to_bytes()).unwrap();
        let json = xila_package_manifest::encode(&manifest).unwrap();
        let signature = private
            .sign(&signing_message(json.as_bytes()).unwrap())
            .to_bytes();
        let mut archive = Vec::new();
        write_package(
            &mut archive,
            &manifest,
            &[
                SourceFile {
                    path: "bin/main.wasm",
                    bytes: &wasm,
                },
                SourceFile {
                    path: "resources/icon.png",
                    bytes: &icon,
                },
            ],
            sign.then_some(&signature),
        )
        .unwrap();
        (archive, public, icon)
    }

    fn from_bytes<E>(
        bytes: &[u8],
        trusted: Option<&PublicKey>,
    ) -> Result<Manifest, StreamError<E>> {
        assert_eq!(bytes.len() % 512, 0);
        let mut blocks = bytes.chunks_exact(512);
        inspect_streaming(
            |buf| {
                if let Some(chunk) = blocks.next() {
                    buf.copy_from_slice(chunk);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            trusted,
        )
    }

    #[test]
    fn verifies_complete_signed_archive_in_512_byte_chunks() {
        let (archive, public, _) = fixture(true);
        let actual = from_bytes::<core::convert::Infallible>(&archive, Some(&public)).unwrap();
        assert_eq!(actual.files.len(), 2);
        assert_eq!(actual.files[0].size, 8 * 1024 + 17);
        assert_eq!(crate::verify_signed(&archive, &public).unwrap(), actual);
    }

    #[test]
    fn unsigned_development_and_missing_signature_rejected_for_release() {
        let (archive, public, _) = fixture(false);
        let manifest = from_bytes::<core::convert::Infallible>(&archive, None).unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(
            from_bytes::<core::convert::Infallible>(&archive, Some(&public)),
            Err(StreamError::Package(Error::MissingSignature))
        );
    }

    #[test]
    fn rejects_modified_resource_and_truncated_archive() {
        let (mut archive, public, icon) = fixture(true);
        let location = archive
            .windows(icon.len())
            .position(|bytes| bytes == icon)
            .unwrap();
        archive[location] ^= 1;
        assert_eq!(
            from_bytes::<core::convert::Infallible>(&archive, Some(&public)),
            Err(StreamError::Package(Error::InvalidDigest))
        );

        let (archive, public, _) = fixture(true);
        // Remove the final two-block terminator *and* optional zero padding,
        // but keep the entire authenticated content.
        let end_of_payload = archive
            .chunks_exact(512)
            .rposition(|block| block.iter().any(|&value| value != 0))
            .unwrap()
            + 1;
        assert_eq!(
            from_bytes::<core::convert::Infallible>(
                &archive[..end_of_payload * 512],
                Some(&public)
            ),
            Err(StreamError::Package(Error::InvalidArchive))
        );
        assert_eq!(
            from_bytes::<core::convert::Infallible>(&archive[..512], Some(&public)),
            Err(StreamError::Package(Error::InvalidArchive))
        );
    }

    #[test]
    fn rejects_hidden_special_tar_entries_and_appended_nonzero_bytes() {
        let (mut archive, public, _) = fixture(false);
        // Convert the first payload header into a directory header, fixing
        // its checksum. TarStreamParser *skips* special entries: our package
        // verifier must reject that skipped header, not ignore it.
        let manifest_len =
            xila_package_manifest::encode(&crate::inspect_unsigned(&archive).unwrap())
                .unwrap()
                .len();
        let offset = 512 + manifest_len.div_ceil(512) * 512;
        let block = &mut archive[offset..offset + 512];
        block[156] = b'5';
        block[148..156].fill(b' ');
        let checksum: u32 = block.iter().map(|&byte| u32::from(byte)).sum();
        let octal = format!("{checksum:06o}\0 ");
        block[148..156].copy_from_slice(octal.as_bytes());
        assert_eq!(
            from_bytes::<core::convert::Infallible>(&archive, None),
            Err(StreamError::Package(Error::UnexpectedEntry))
        );

        let (mut archive, _, _) = fixture(false);
        archive.extend_from_slice(&[0xff; 512]);
        assert_eq!(
            from_bytes::<core::convert::Infallible>(&archive, None),
            Err(StreamError::Package(Error::UnexpectedEntry))
        );
        // The trusted-key requirement is checked before the first payload.
        let _ = public;
    }

    #[test]
    fn source_io_failure_does_not_become_truncated_success() {
        let (archive, _, _) = fixture(false);
        let mut blocks = archive.chunks_exact(512);
        let mut reads = 0;
        let result = inspect_streaming(
            |buf| {
                reads += 1;
                if reads == 4 {
                    return Err("I/O failure");
                }
                if let Some(chunk) = blocks.next() {
                    buf.copy_from_slice(chunk);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            None,
        );
        assert_eq!(result, Err(StreamError::Source("I/O failure")));
    }

    #[test]
    fn poisoned_verifier_rejects_any_more_input() {
        let mut verifier = StreamingVerifier::new(None);
        assert_eq!(verifier.push(&[0xff; 512]), Err(Error::InvalidArchive));
        assert_eq!(verifier.push(&[0; 512]), Err(Error::InvalidArchive));
        assert_eq!(verifier.finish(), Err(Error::InvalidArchive));
    }
}
