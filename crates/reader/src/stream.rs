//! Bounded-memory verification of signed Xila packages from TAR blocks.
//!
//! The TAR and each executable/resource are never buffered in full. Only
//! bounded signed metadata is buffered until header authentication succeeds,
//! after which only the parsed manifest is retained in memory.
//! File contents are authenticated incrementally with ContentVerifier.
//!
//! [`StreamingVerifier::extract`] also hands each payload's bytes to the
//! caller in the same pass, so an installer can write them to staging without
//! parsing the TAR again or reading the archive twice.

use alloc::vec::Vec;
use tar_no_std::{BLOCKSIZE, StreamEvent, TarStreamParser};
use xila_package_bundle::decode_sha256;
use xila_package_manifest::{
    MANIFEST_PATH, MAX_MANIFEST_BYTES, Manifest, ManifestFile, SIGNATURE_PATH, SIGNED_DOMAIN,
};
use xila_package_verification::{ContentVerifier, PublicKey};

use crate::{Error, require_ordinary_file};

/// Reader/source errors are separate from invalid or untrusted packages.
#[derive(Debug, PartialEq, Eq)]
pub enum StreamError<E> {
    Source(E),
    Package(Error),
}

/// Part of a declared file carried by one TAR block, returned by
/// [`StreamingVerifier::extract`].
///
/// Chunks of a file arrive in order and files arrive in manifest order. The
/// header signature has been verified (when a trusted key was supplied) before
/// the first chunk, but a file's contents are only proven once its `last`
/// chunk is returned, and the package only once
/// [`StreamingVerifier::finish`] succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileChunk<'b> {
    /// Index of the file in [`Manifest::files`].
    pub index: usize,
    /// The next payload bytes; empty for the chunk that starts the file.
    pub bytes: &'b [u8],
    /// The file starts here: create it in staging. Its `bytes` are empty.
    pub first: bool,
    /// The file is complete and its size and SHA-256 match the manifest.
    pub last: bool,
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
///   is buffered until header authentication succeeds (or until manifest
///   decoding succeeds when no trusted key is supplied), then released before
///   payload verification begins. The parsed manifest also allocates a bounded
///   inventory.
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
        self.extract(block).map(|_| ())
    }

    /// Push one block and return the part of a declared file it carries, if
    /// any. On any failure, the verifier is permanently poisoned.
    ///
    /// Write chunks only to non-executable staging, and discard everything
    /// written for this package if any call or [`finish`](Self::finish) fails.
    pub fn extract<'b>(
        &mut self,
        block: &'b [u8; BLOCKSIZE],
    ) -> Result<Option<FileChunk<'b>>, Error> {
        if self.failed {
            return Err(Error::InvalidArchive);
        }
        let result = self.consume(block);
        if result.is_err() {
            self.failed = true;
            self.signed_message = Vec::new();
        }
        result
    }

    /// The decoded manifest, once its TAR entry has been read. Its header
    /// signature is verified only when the first file chunk is returned.
    pub fn manifest(&self) -> Option<&Manifest> {
        self.manifest.as_ref()
    }

    fn consume<'b>(&mut self, block: &'b [u8; BLOCKSIZE]) -> Result<Option<FileChunk<'b>>, Error> {
        let event = self
            .parser
            .parse_block(block)
            .map_err(|_| Error::InvalidArchive)?;

        match event {
            Some(StreamEvent::Entry {
                filename,
                posix_header,
                size,
            }) => {
                require_ordinary_file(posix_header)?;
                let path = filename.as_str().map_err(|_| Error::InvalidArchive)?;
                self.on_entry(path, size)
            }
            Some(StreamEvent::Data { data, remaining }) => self.on_data(data, remaining),
            Some(StreamEvent::End) => self.on_end().map(|()| None),
            None => {
                // None also denotes skipped special TAR headers in the
                // upstream parser. Those are *not* allowed in the Xila format.
                // The first TAR terminator is all zero; further zero padding
                // after End is permitted. A skipped special header cannot be
                // zero, as a zero header is the TAR terminator.
                if block.iter().any(|&byte| byte != 0) {
                    Err(Error::UnexpectedEntry)
                } else {
                    Ok(None)
                }
            }
        }
    }

    fn on_entry(&mut self, path: &str, size: usize) -> Result<Option<FileChunk<'static>>, Error> {
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
                Ok(None)
            }
            State::AfterManifest if path == SIGNATURE_PATH => {
                if size != self.signature.len() {
                    return Err(Error::InvalidSignature);
                }
                self.has_signature = true;
                self.state = State::Signature { received: 0 };
                Ok(None)
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
                let index = self.file_index;
                if size == 0 {
                    self.end_file()?;
                } else {
                    self.state = State::Payload;
                }
                Ok(Some(FileChunk {
                    index,
                    bytes: &[],
                    first: true,
                    last: size == 0,
                }))
            }
            _ => Err(Error::UnexpectedEntry),
        }
    }

    fn on_data<'b>(
        &mut self,
        bytes: &'b [u8],
        remaining: usize,
    ) -> Result<Option<FileChunk<'b>>, Error> {
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
                        .map_err(Error::from_manifest)?;
                    self.manifest = Some(decoded);
                    if self.trusted.is_none() {
                        self.signed_message = Vec::new();
                    }
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
                Ok(None)
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
                Ok(None)
            }
            State::Payload => {
                self.current_file
                    .as_mut()
                    .ok_or(Error::UnexpectedEntry)?
                    .update(bytes)
                    .map_err(|_| Error::InvalidDigest)?;
                let index = self.file_index;
                if remaining == 0 {
                    self.end_file()?;
                }
                Ok(Some(FileChunk {
                    index,
                    bytes,
                    first: false,
                    last: remaining == 0,
                }))
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
        self.signed_message = Vec::new();
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

/// Verify a package and hand each declared file's bytes to `write` in the
/// same pass, one 512-byte block at a time.
///
/// `write` receives the manifest entry of the file and the chunk. Source and
/// write errors share `E` and fail closed. The returned manifest is the only
/// proof that the package is valid: on any error, discard everything `write`
/// produced.
pub fn extract_streaming<S, W, E>(
    mut read_block: S,
    trusted: Option<&PublicKey>,
    mut write: W,
) -> Result<Manifest, StreamError<E>>
where
    S: FnMut(&mut [u8; BLOCKSIZE]) -> Result<bool, E>,
    W: FnMut(&ManifestFile, FileChunk<'_>) -> Result<(), E>,
{
    let mut verifier = StreamingVerifier::new(trusted);
    let mut block = [0_u8; BLOCKSIZE];
    loop {
        if !read_block(&mut block).map_err(StreamError::Source)? {
            return verifier.finish().map_err(StreamError::Package);
        }
        if let Some(chunk) = verifier.extract(&block).map_err(StreamError::Package)? {
            let file = verifier
                .manifest()
                .and_then(|manifest| manifest.files.get(chunk.index))
                .ok_or(StreamError::Package(Error::InvalidManifest))?;
            write(file, chunk).map_err(StreamError::Source)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{
        format,
        string::{String, ToString},
        vec,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use xila_package_bundle::{FileHasher, signing_message};
    use xila_package_manifest::{
        Application, FORMAT_VERSION, ManifestFile, SCHEMA_URL, XilaVersion,
    };
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
            xila_version: XilaVersion::new(0, 1),
            capabilities: vec![],
            files: vec![
                hashed_file("executables/main.wasm", &wasm),
                hashed_file("resources/icon.png", &icon),
            ],
            application: Some(Application {
                entrypoint: "executables/main.wasm".into(),
                display_name: "Example".into(),
                icon: "resources/icon.png".into(),
                show_in_launcher: true,
            }),
            metadata: None,
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
                    path: "executables/main.wasm",
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
        let mut blocks = bytes.as_chunks::<512>().0.iter();
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

    /// Path, contents and completion of each extracted file.
    type Extracted = Vec<(String, Vec<u8>, bool)>;

    /// Extract `bytes` and return each file's path and contents, checking
    /// that chunks arrive in order with consistent `first`/`last` flags.
    fn extract_all(
        bytes: &[u8],
        trusted: Option<&PublicKey>,
    ) -> Result<(Manifest, Extracted), StreamError<()>> {
        let mut blocks = bytes.as_chunks::<512>().0.iter();
        let mut files: Extracted = Vec::new();
        let manifest = extract_streaming(
            |buf| {
                if let Some(chunk) = blocks.next() {
                    buf.copy_from_slice(chunk);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            trusted,
            |file, chunk| {
                if chunk.first {
                    assert_eq!(chunk.index, files.len());
                    assert!(chunk.bytes.is_empty());
                    files.push((file.path.clone(), Vec::new(), false));
                }
                let (path, contents, complete) = files.last_mut().unwrap();
                assert_eq!(*path, file.path);
                assert!(!*complete);
                contents.extend_from_slice(chunk.bytes);
                *complete = chunk.last;
                Ok(())
            },
        )?;
        Ok((manifest, files))
    }

    #[test]
    fn extracts_every_file_in_the_verification_pass() {
        let (archive, public, icon) = fixture(true);
        let (manifest, files) = extract_all(&archive, Some(&public)).unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert_eq!(
            files,
            vec![
                (
                    "executables/main.wasm".to_string(),
                    vec![42_u8; 8 * 1024 + 17],
                    true
                ),
                ("resources/icon.png".to_string(), icon, true),
            ]
        );
    }

    #[test]
    fn extracts_empty_files_as_one_complete_chunk() {
        let manifest = Manifest {
            schema: Some(SCHEMA_URL.to_string()),
            format_version: FORMAT_VERSION,
            name: "community.empty".into(),
            version: "1.0.0".into(),
            target: "wasm32-wasip1".into(),
            xila_version: XilaVersion::new(0, 1),
            capabilities: vec![],
            files: vec![
                hashed_file("resources/empty", b""),
                hashed_file("resources/one", b"1"),
            ],
            application: None,
            metadata: None,
        };
        let mut archive = Vec::new();
        write_package(
            &mut archive,
            &manifest,
            &[
                SourceFile {
                    path: "resources/empty",
                    bytes: b"",
                },
                SourceFile {
                    path: "resources/one",
                    bytes: b"1",
                },
            ],
            None,
        )
        .unwrap();
        let mut verifier = StreamingVerifier::new(None);
        let mut chunks = Vec::new();
        for block in archive.as_chunks::<512>().0 {
            if let Some(chunk) = verifier.extract(block).unwrap() {
                chunks.push((chunk.index, chunk.bytes.to_vec(), chunk.first, chunk.last));
            }
        }
        assert_eq!(verifier.finish().unwrap(), manifest);
        assert_eq!(
            chunks,
            vec![
                (0, vec![], true, true),
                (1, vec![], true, false),
                (1, b"1".to_vec(), false, true),
            ]
        );
    }

    #[test]
    fn extraction_delivers_nothing_before_the_signature_is_verified() {
        let (archive, _, _) = fixture(true);
        let other = SigningKey::from_bytes(&[8_u8; 32]);
        let other = PublicKey::from_bytes(&other.verifying_key().to_bytes()).unwrap();
        assert_eq!(
            extract_all(&archive, Some(&other)).err(),
            Some(StreamError::Package(Error::InvalidSignature))
        );
        let (unsigned, public, _) = fixture(false);
        let mut delivered = false;
        let mut verifier = StreamingVerifier::new(Some(&public));
        let mut result = Ok(None);
        for block in unsigned.as_chunks::<512>().0 {
            result = verifier.extract(block);
            match &result {
                Ok(Some(_)) => delivered = true,
                Ok(None) => {}
                Err(_) => break,
            }
        }
        assert_eq!(result, Err(Error::MissingSignature));
        assert!(!delivered);
    }

    #[test]
    fn extraction_never_completes_a_modified_file() {
        let (mut archive, public, icon) = fixture(true);
        let offset = archive
            .windows(icon.len())
            .position(|bytes| bytes == icon.as_slice())
            .unwrap();
        archive[offset] ^= 1;
        let mut verifier = StreamingVerifier::new(Some(&public));
        let mut completed = Vec::new();
        let mut result = Ok(None);
        for block in archive.as_chunks::<512>().0 {
            result = verifier.extract(block);
            match &result {
                Ok(Some(chunk)) if chunk.last => completed.push(chunk.index),
                Ok(_) => {}
                Err(_) => break,
            }
        }
        assert_eq!(result, Err(Error::InvalidDigest));
        assert_eq!(completed, vec![0]);
    }

    #[test]
    fn extraction_write_errors_stop_the_pass() {
        let (archive, public, _) = fixture(true);
        let mut blocks = archive.as_chunks::<512>().0.iter();
        let mut writes = 0;
        let result = extract_streaming(
            |buf| {
                if let Some(chunk) = blocks.next() {
                    buf.copy_from_slice(chunk);
                    Ok(true)
                } else {
                    Ok(false)
                }
            },
            Some(&public),
            |_, _| {
                writes += 1;
                if writes == 3 {
                    Err("disk full")
                } else {
                    Ok(())
                }
            },
        );
        assert_eq!(result, Err(StreamError::Source("disk full")));
        assert_eq!(writes, 3);
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
    fn rejects_unsupported_manifest_versions_in_both_readers() {
        let (mut archive, _, _) = fixture(false);
        let format = br#""format_version":2"#;
        let offset = archive
            .windows(format.len())
            .position(|bytes| bytes == format)
            .unwrap();
        archive[offset + format.len() - 1] = b'1';
        assert_eq!(
            crate::inspect_unsigned(&archive),
            Err(Error::UnsupportedManifestVersion)
        );
        assert_eq!(
            from_bytes::<core::convert::Infallible>(&archive, None),
            Err(StreamError::Package(Error::UnsupportedManifestVersion))
        );
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
            .as_chunks::<512>()
            .0
            .iter()
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
        update_checksum(block);
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
    fn signed_verifiers_reject_extension_and_nonordinary_type_flags() {
        let (archive, public, icon) = fixture(true);
        let header_offset = archive
            .windows(icon.len())
            .position(|bytes| bytes == icon)
            .unwrap()
            - BLOCKSIZE;

        // Contiguous, sparse and unknown flags, plus GNU long-name ('L', 'K') and global PAX
        // ('g') headers: both readers must reject each one with the same error.
        for (flag, expected) in [
            (b'7', Some(Error::UnexpectedEntry)),
            (b'S', Some(Error::InvalidArchive)),
            (b'?', Some(Error::InvalidArchive)),
            (b'L', None),
            (b'K', None),
            (b'g', None),
        ] {
            let mut modified = archive.clone();
            let header = &mut modified[header_offset..header_offset + BLOCKSIZE];
            header[156] = flag;
            update_checksum(header);
            let streaming = from_bytes::<core::convert::Infallible>(&modified, Some(&public));
            let in_memory = crate::verify_signed(&modified, &public);
            let Err(StreamError::Package(streaming_error)) = streaming else {
                panic!("streaming reader accepted type flag {:?}", flag as char);
            };
            if let Some(expected) = &expected {
                assert_eq!(&streaming_error, expected, "type flag {:?}", flag as char);
            }
            assert_eq!(
                in_memory.map(|_| ()),
                Err(streaming_error),
                "readers disagree on type flag {:?}",
                flag as char
            );
        }

        // Insert a local PAX path that resolves to the signed path. Even a
        // matching path override must not be accepted by either verifier.
        let mut pax = [0; 2 * BLOCKSIZE];
        pax[..BLOCKSIZE].copy_from_slice(&archive[header_offset..header_offset + BLOCKSIZE]);
        let records = b"27 path=resources/icon.png\n";
        pax[124..136].copy_from_slice(format!("{:011o}\0", records.len()).as_bytes());
        pax[156] = b'x';
        update_checksum(&mut pax[..BLOCKSIZE]);
        pax[BLOCKSIZE..BLOCKSIZE + records.len()].copy_from_slice(records);
        let mut modified = archive.clone();
        modified.splice(header_offset..header_offset, pax);
        assert_eq!(
            crate::verify_signed(&modified, &public),
            Err(Error::UnexpectedEntry)
        );
        assert_eq!(
            from_bytes::<core::convert::Infallible>(&modified, Some(&public)),
            Err(StreamError::Package(Error::UnexpectedEntry))
        );
    }

    #[test]
    fn in_memory_verifier_rejects_nonzero_padding() {
        let (mut archive, public, _) = fixture(true);
        archive.extend_from_slice(&[0xff; BLOCKSIZE]);
        assert_eq!(
            crate::verify_signed(&archive, &public),
            Err(Error::UnexpectedEntry)
        );
    }

    fn update_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum: u32 = header.iter().map(|&byte| u32::from(byte)).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    }

    #[test]
    fn source_io_failure_does_not_become_truncated_success() {
        let (archive, _, _) = fixture(false);
        let mut blocks = archive.as_chunks::<512>().0.iter();
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

    #[test]
    fn releases_signed_manifest_buffer_after_header_authentication() {
        let (archive, public, _) = fixture(true);
        let manifest_len =
            xila_package_manifest::encode(&crate::verify_signed(&archive, &public).unwrap())
                .unwrap()
                .len();
        let manifest_blocks = 1 + manifest_len.div_ceil(BLOCKSIZE);
        let first_payload_block = manifest_blocks + 2;

        let mut verifier = StreamingVerifier::new(Some(&public));
        for (index, chunk) in archive.as_chunks::<BLOCKSIZE>().0.iter().enumerate() {
            if index == first_payload_block {
                assert!(
                    verifier.signed_message.capacity() >= SIGNED_DOMAIN.len() + 4 + manifest_len
                );
                assert!(!verifier.signature_verified);
            }
            verifier.push(chunk).unwrap();
            if index >= first_payload_block {
                assert!(verifier.signature_verified);
                assert!(verifier.signed_message.is_empty());
                assert_eq!(verifier.signed_message.capacity(), 0);
            }
        }
        let manifest = verifier.finish().unwrap();
        assert_eq!(manifest.files.len(), 2);
    }

    #[test]
    fn releases_manifest_buffer_immediately_for_unsigned_inspection() {
        let (archive, _, _) = fixture(false);
        let manifest_len =
            xila_package_manifest::encode(&crate::inspect_unsigned(&archive).unwrap())
                .unwrap()
                .len();
        let manifest_end_block = manifest_len.div_ceil(BLOCKSIZE);

        let mut verifier = StreamingVerifier::new(None);
        for (index, chunk) in archive.as_chunks::<BLOCKSIZE>().0.iter().enumerate() {
            verifier.push(chunk).unwrap();
            if index >= manifest_end_block {
                assert!(verifier.signed_message.is_empty());
                assert_eq!(verifier.signed_message.capacity(), 0);
            }
        }
        assert_eq!(verifier.finish().unwrap().files.len(), 2);
    }

    #[test]
    fn releases_signed_manifest_buffer_on_zero_file_package_and_failure() {
        let manifest = Manifest {
            schema: Some(SCHEMA_URL.to_string()),
            format_version: FORMAT_VERSION,
            name: "community.native-reference".into(),
            version: "1.0.0".into(),
            target: "native".into(),
            xila_version: XilaVersion::new(0, 1),
            capabilities: vec![],
            files: vec![],
            application: Some(Application {
                entrypoint: "/system/executables/settings".into(),
                display_name: "Settings".into(),
                icon: alloc::string::String::new(),
                show_in_launcher: true,
            }),
            metadata: None,
        };
        let private = SigningKey::from_bytes(&[11_u8; 32]);
        let public = PublicKey::from_bytes(&private.verifying_key().to_bytes()).unwrap();
        let json = xila_package_manifest::encode(&manifest).unwrap();
        let signature = private
            .sign(&signing_message(json.as_bytes()).unwrap())
            .to_bytes();
        let mut archive = Vec::new();
        write_package(&mut archive, &manifest, &[], Some(&signature)).unwrap();

        let mut verifier = StreamingVerifier::new(Some(&public));
        for chunk in archive.as_chunks::<BLOCKSIZE>().0 {
            verifier.push(chunk).unwrap();
        }
        assert!(verifier.signature_verified);
        assert_eq!(verifier.signed_message.capacity(), 0);
        assert_eq!(verifier.finish().unwrap(), manifest);

        // Corrupt the signature and confirm the buffer is released on failure
        // and the verifier stays permanently poisoned.
        let signature_data_block = 1 + json.len().div_ceil(BLOCKSIZE) + 1;
        let mut bad_archive = archive.clone();
        bad_archive[signature_data_block * BLOCKSIZE] ^= 0xff;
        let mut failing = StreamingVerifier::new(Some(&public));
        let mut observed = None;
        for chunk in bad_archive.as_chunks::<BLOCKSIZE>().0 {
            if let Err(error) = failing.push(chunk) {
                observed = Some(error);
                break;
            }
        }
        assert_eq!(observed, Some(Error::InvalidSignature));
        assert_eq!(failing.signed_message.capacity(), 0);
        assert_eq!(failing.push(&[0; BLOCKSIZE]), Err(Error::InvalidArchive));
        assert_eq!(failing.finish(), Err(Error::InvalidArchive));
    }
}
