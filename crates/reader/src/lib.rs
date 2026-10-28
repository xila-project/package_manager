#![no_std]
#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
extern crate alloc;

use alloc::vec;
use tar_no_std::TarArchiveRef;
use xila_package_manifest::{MANIFEST_PATH, Manifest, SIGNATURE_PATH, SIGNED_DOMAIN_V2};
use xila_package_verification::{ContentVerifier, PublicKey};

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

fn nibble(ch: u8) -> Result<u8, Error> {
    match ch {
        b'0'..=b'9' => Ok(ch - b'0'),
        b'a'..=b'f' => Ok(ch - b'a' + 10),
        _ => Err(Error::InvalidDigest),
    }
}

fn decode_digest(hex: &str) -> Result<[u8; 32], Error> {
    if hex.len() != 64 {
        return Err(Error::InvalidDigest);
    }
    let mut bytes = [0u8; 32];
    for (n, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[n] = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Ok(bytes)
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
        let mut message = vec![0u8; SIGNED_DOMAIN_V2.len() + 4 + raw_manifest.len()];
        let raw = xila_package_manifest::signed_message_for_version_into(
            manifest.format_version,
            raw_manifest,
            &mut message,
        )
            .map_err(|_| Error::InvalidManifest)?;
        key.verify(raw, &signature)
            .map_err(|_| Error::InvalidSignature)?;
    }

    for declared in &manifest.files {
        let present = entry.ok_or(Error::UnexpectedEntry)?;
        let filename = present.filename();
        let path = filename.as_str().map_err(|_| Error::InvalidArchive)?;
        if path != declared.path || present.size() as u64 != declared.size {
            return Err(Error::UnexpectedEntry);
        }
        let digest = decode_digest(&declared.sha256)?;
        let mut verifier =
            ContentVerifier::new(declared.size, digest).map_err(|_| Error::InvalidDigest)?;
        verifier
            .update(present.data())
            .map_err(|_| Error::InvalidDigest)?;
        verifier.verify().map_err(|_| Error::InvalidDigest)?;
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
