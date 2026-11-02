//! Generate and check registry entries for released, signed archives.
//!
//! Entries are derived from the archive itself so the registry never restates
//! (and can never contradict) the developer-signed manifest by hand.

use sha2::{Digest, Sha256};
use std::{fmt::Write as _, fs, io::Write, path::Path};
use xila_package_manifest::{
    Archive, Manifest, RegistryEntry, decode_registry_entry, encode_registry_entry,
};
use xila_package_verification::PublicKey;

use crate::{Result, invalid};

fn read_public_key(path: &Path) -> Result<PublicKey> {
    let raw: [u8; 32] = fs::read(path)?
        .try_into()
        .map_err(|_| invalid("public key must be exactly 32 raw bytes"))?;
    Ok(PublicKey::from_bytes(&raw).map_err(|_| invalid("invalid Ed25519 public key"))?)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

fn verified_manifest(archive: &[u8], public_key: &Path) -> Result<Manifest> {
    Ok(
        xila_package_reader::verify_signed(archive, &read_public_key(public_key)?)
            .map_err(|_| invalid("signed package verification failed"))?,
    )
}

/// Write the registry entry for `archive`, published by `publisher` at `url`.
pub fn entry(
    archive: &Path,
    public_key: &Path,
    publisher: &str,
    url: &str,
    output: &Path,
) -> Result<()> {
    let bytes = fs::read(archive)?;
    let manifest = verified_manifest(&bytes, public_key)?;
    let location = Archive {
        url: url.into(),
        sha256: sha256_hex(&bytes),
        size: bytes.len() as u64,
    };
    let entry = RegistryEntry::from_manifest(&manifest, publisher, location)
        .map_err(|_| invalid("invalid registry entry (publisher, URL or metadata)"))?;
    let text = encode_registry_entry(&entry).map_err(|_| invalid("invalid registry entry"))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(text.as_bytes())?;
    Ok(())
}

/// Check that `entry` describes exactly `archive`, signed by `public_key`.
pub fn verify(entry: &Path, archive: &Path, public_key: &Path) -> Result<()> {
    let entry =
        decode_registry_entry(&fs::read(entry)?).map_err(|_| invalid("invalid registry entry"))?;
    let bytes = fs::read(archive)?;
    if bytes.len() as u64 != entry.archive.size || sha256_hex(&bytes) != entry.archive.sha256 {
        return Err(invalid("archive size or SHA-256 differs from the registry entry").into());
    }
    let manifest = verified_manifest(&bytes, public_key)?;
    entry
        .check_manifest(&manifest)
        .map_err(|_| invalid("registry entry differs from the signed package manifest"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn hashes_as_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
