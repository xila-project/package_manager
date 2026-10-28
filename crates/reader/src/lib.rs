#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
extern crate alloc;

use tar_no_std::TarArchiveRef;
use xila_package_bundle::{verify_bytes, verify_signature};
use xila_package_manifest::{MANIFEST_PATH, Manifest, SIGNATURE_PATH};
use xila_package_verification::PublicKey;

/// Reasons a TAR archive, manifest or supplied signature was rejected.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidArchive,
    UnexpectedEntry,
    InvalidManifest,
    MissingSignature,
    InvalidSignature,
    InvalidDigest,
}

fn inspect_internal(bytes: &[u8], trusted: Option<&PublicKey>) -> Result<Manifest, Error> {
    let tar = TarArchiveRef::new(bytes).map_err(|_| Error::InvalidArchive)?;
    // The regular-file iterator silently ignores special entries. Every header
    // must therefore correspond to one ordinary entry under our strict profile.
    if tar.headers().count() != tar.entries().count() {
        return Err(Error::UnexpectedEntry);
    }
    let mut entries = tar.entries();
    let first = entries.next().ok_or(Error::InvalidManifest)?;
    if first
        .filename()
        .as_str()
        .map_err(|_| Error::InvalidArchive)?
        != MANIFEST_PATH
    {
        return Err(Error::InvalidManifest);
    }
    let raw_manifest = first.data();
    let manifest =
        xila_package_manifest::decode(raw_manifest).map_err(|_| Error::InvalidManifest)?;

    let mut entry = entries.next();
    let mut signature = None;
    if let Some(candidate) = entry.as_ref()
        && candidate
            .filename()
            .as_str()
            .map_err(|_| Error::InvalidArchive)?
            == SIGNATURE_PATH
    {
        let bytes = candidate.data();
        if bytes.len() != 64 {
            return Err(Error::InvalidSignature);
        }
        let mut sig = [0u8; 64];
        sig.copy_from_slice(bytes);
        signature = Some(sig);
        entry = entries.next();
    }

    if let Some(key) = trusted {
        let signature = signature.ok_or(Error::MissingSignature)?;
        verify_signature(raw_manifest, &signature, key).map_err(|_| Error::InvalidSignature)?;
    }

    for declared in &manifest.files {
        let present = entry.ok_or(Error::UnexpectedEntry)?;
        let filename = present.filename();
        let path = filename.as_str().map_err(|_| Error::InvalidArchive)?;
        if path != declared.path || present.size() as u64 != declared.size {
            return Err(Error::UnexpectedEntry);
        }
        verify_bytes(declared, present.data()).map_err(|_| Error::InvalidDigest)?;
        entry = entries.next();
    }
    if entry.is_some() {
        return Err(Error::UnexpectedEntry);
    }
    Ok(manifest)
}

/// Inspect and verify every listed file's content without authenticating its
/// publisher. MUST NOT be used as an install-time trust check.
pub fn inspect_unsigned(bytes: &[u8]) -> Result<Manifest, Error> {
    inspect_internal(bytes, None)
}

/// Authenticate the exact manifest bytes with an externally trusted Ed25519
/// public key, then verify all archive payloads against the signed inventory.
pub fn verify_signed(bytes: &[u8], key: &PublicKey) -> Result<Manifest, Error> {
    inspect_internal(bytes, Some(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_archive() {
        assert_eq!(inspect_unsigned(&[]), Err(Error::InvalidArchive));
    }
    #[test]
    fn rejects_missing_trustworthy_header() {
        assert_eq!(inspect_unsigned(&[0; 1024]), Err(Error::InvalidArchive));
    }
}
