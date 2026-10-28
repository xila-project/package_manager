#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]

extern crate alloc;

use alloc::{string::String, vec, vec::Vec};
use xila_package_manifest::{
    self as manifest, DeveloperManifest, MAX_FILES, Manifest, ManifestFile, SIGNED_DOMAIN,
};
use xila_package_verification::{ContentVerifier, PublicKey, Sha256Verifier};

/// Invalid portable bundle metadata or failed cryptographic verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidPath,
    InvalidDigest,
    InvalidManifest,
    HashFailure,
    InvalidSignature,
    Mismatch,
    TooManyFiles,
}

/// Fixed-width lowercase hexadecimal SHA-256 encoding.
pub fn encode_sha256(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

/// Strict lower-case, fixed-width decoding shared by host writer and guest reader.
pub fn decode_sha256(hex: &str) -> Result<[u8; 32], Error> {
    if hex.len() != 64 {
        return Err(Error::InvalidDigest);
    }
    fn nibble(value: u8) -> Result<u8, Error> {
        match value {
            b'0'..=b'9' => Ok(value - b'0'),
            b'a'..=b'f' => Ok(value - b'a' + 10),
            _ => Err(Error::InvalidDigest),
        }
    }
    let mut output = [0_u8; 32];
    for (index, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

/// Portable, incremental file inventory calculation. The caller supplies
/// file content in chunks from any I/O backend (std::fs, Xila VFS, or memory).
///
/// The path belongs to the bundle; no host path or filesystem handle is stored.
pub struct FileHasher {
    path: String,
    total: u64,
    hasher: Sha256Verifier,
}

impl FileHasher {
    pub fn new(path: &str) -> Result<Self, Error> {
        manifest::validate_path(path).map_err(|_| Error::InvalidPath)?;
        Ok(Self {
            path: path.into(),
            total: 0,
            hasher: Sha256Verifier::new(),
        })
    }

    pub fn update(&mut self, chunk: &[u8]) -> Result<(), Error> {
        let next = self
            .total
            .checked_add(u64::try_from(chunk.len()).map_err(|_| Error::HashFailure)?)
            .ok_or(Error::HashFailure)?;
        self.hasher.update(chunk).map_err(|_| Error::HashFailure)?;
        self.total = next;
        Ok(())
    }

    pub fn finish(self) -> Result<ManifestFile, Error> {
        let digest = self.hasher.finalize().map_err(|_| Error::HashFailure)?;
        Ok(ManifestFile {
            path: self.path,
            size: self.total,
            sha256: encode_sha256(&digest),
        })
    }
}

/// Confirm that file bytes match the expected file inventory entry.
/// This is integrity verification, not publisher authentication.
pub fn verify_bytes(declared: &ManifestFile, bytes: &[u8]) -> Result<(), Error> {
    let digest = decode_sha256(&declared.sha256)?;
    let mut verifier =
        ContentVerifier::new(declared.size, digest).map_err(|_| Error::HashFailure)?;
    verifier.update(bytes).map_err(|_| Error::Mismatch)?;
    verifier.verify().map_err(|_| Error::Mismatch)
}

/// Pure inventory accumulator shared by native bundle tooling and Xila targets.
///
/// All file types (Wasm, icons, locale catalogs, fonts, assets) are treated
/// uniformly. The final manifest is deterministically sorted by relative path.
#[derive(Default)]
pub struct Inventory {
    files: Vec<ManifestFile>,
}

impl Inventory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, file: ManifestFile) -> Result<(), Error> {
        manifest::validate_path(&file.path).map_err(|_| Error::InvalidPath)?;
        decode_sha256(&file.sha256)?;
        if self.files.len() >= MAX_FILES {
            return Err(Error::TooManyFiles);
        }
        if self.files.iter().any(|other| other.path == file.path) {
            return Err(Error::InvalidManifest);
        }
        self.files.push(file);
        Ok(())
    }

    pub fn into_files(mut self) -> Vec<ManifestFile> {
        self.files.sort_by(|a, b| a.path.cmp(&b.path));
        self.files
    }

    pub fn finish(self, developer: DeveloperManifest) -> Result<Manifest, Error> {
        developer
            .into_bundle_manifest(self.into_files())
            .map_err(|_| Error::InvalidManifest)
    }
}

/// Domain-separated signed message over the **exact** serialized runtime manifest.
///
/// Ed25519 only signs this buffer, but the authenticated manifest contains the
/// SHA-256 of *every* executable and resource. Signature bytes live separately
/// in .xila/manifest.sig, avoiding a circular digest.
pub fn signing_message(manifest_bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let size = SIGNED_DOMAIN
        .len()
        .checked_add(4)
        .and_then(|n| n.checked_add(manifest_bytes.len()))
        .ok_or(Error::InvalidManifest)?;
    let mut output = vec![0_u8; size];
    let data = manifest::signed_message_into(manifest_bytes, &mut output)
        .map_err(|_| Error::InvalidManifest)?;
    let length = data.len();
    output.truncate(length);
    Ok(output)
}

/// Verify a detached ordinary Ed25519 signature against the raw runtime
/// manifest. Trust in the supplied public key is the caller's responsibility.
pub fn verify_signature(
    manifest_bytes: &[u8],
    signature: &[u8; 64],
    trusted_key: &PublicKey,
) -> Result<(), Error> {
    let message = signing_message(manifest_bytes)?;
    trusted_key
        .verify(&message, signature)
        .map_err(|_| Error::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    use xila_package_manifest::{Application, FORMAT_VERSION, SCHEMA_URL};

    fn authoring() -> DeveloperManifest {
        DeveloperManifest {
            schema: None,
            format_version: FORMAT_VERSION,
            name: "community.example".to_string(),
            version: "1.0.0".to_string(),
            target: "wasm32-wasip1".to_string(),
            minimum_xila_abi: 1,
            capabilities: vec![],
            application: Some(Application {
                entrypoint: "bin/app.wasm".to_string(),
                display_name: "Example".to_string(),
                icon: "resources/icon.png".to_string(),
                show_in_launcher: true,
            }),
        }
    }

    #[test]
    fn streamed_hashes_and_resources_are_in_signed_inventory() {
        let mut inventory = Inventory::new();
        for (path, bytes) in [
            ("resources/icon.png", &b"icon"[..]),
            ("bin/app.wasm", &b"wasm"[..]),
        ] {
            let mut hasher = FileHasher::new(path).unwrap();
            hasher.update(&bytes[..2]).unwrap();
            hasher.update(&bytes[2..]).unwrap();
            let file = hasher.finish().unwrap();
            verify_bytes(&file, bytes).unwrap();
            assert_eq!(verify_bytes(&file, b"altered"), Err(Error::Mismatch));
            inventory.push(file).unwrap();
        }
        let manifest = inventory.finish(authoring()).unwrap();
        assert_eq!(manifest.schema.as_deref(), Some(SCHEMA_URL));
        assert_eq!(manifest.files[0].path, "bin/app.wasm");
        assert_eq!(manifest.files[1].path, "resources/icon.png");
        let bytes = manifest::encode(&manifest).unwrap();
        let signed = signing_message(bytes.as_bytes()).unwrap();
        assert!(signed.starts_with(SIGNED_DOMAIN));
    }

    #[test]
    fn rejects_unsafe_paths_and_malformed_digests() {
        assert!(matches!(
            FileHasher::new("../escape"),
            Err(Error::InvalidPath)
        ));
        assert_eq!(decode_sha256(&"A".repeat(64)), Err(Error::InvalidDigest));
        assert_eq!(decode_sha256("00"), Err(Error::InvalidDigest));
        let mut inventory = Inventory::new();
        let mut hasher = FileHasher::new("bin/app.wasm").unwrap();
        hasher.update(b"abc").unwrap();
        let file = hasher.finish().unwrap();
        inventory.push(file.clone()).unwrap();
        assert_eq!(inventory.push(file), Err(Error::InvalidManifest));
    }

    #[test]
    fn signature_message_rejects_excessive_manifest() {
        assert_eq!(
            signing_message(&vec![0; manifest::MAX_MANIFEST_BYTES + 1]),
            Err(Error::InvalidManifest)
        );
    }
}
