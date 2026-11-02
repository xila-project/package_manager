//! Generate and check registry entries for released, signed archives.
//!
//! Entries are derived from the archive itself so the registry never restates
//! (and can never contradict) the developer-signed manifest by hand.

use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use xila_package_manifest::{
    Archive, DeveloperKey, Manifest, RegistryEntry, decode_developer_key, decode_registry_entry,
    encode_registry_entry,
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

fn verify_archive(entry: &RegistryEntry, bytes: &[u8], key: &PublicKey) -> Result<()> {
    if bytes.len() as u64 != entry.archive.size || sha256_hex(bytes) != entry.archive.sha256 {
        return Err(invalid("archive size or SHA-256 differs from the registry entry").into());
    }
    let manifest = xila_package_reader::verify_signed(bytes, key)
        .map_err(|_| invalid("signed package verification failed"))?;
    entry
        .check_manifest(&manifest)
        .map_err(|_| invalid("registry entry differs from the signed package manifest"))?;
    Ok(())
}

/// Check that `entry` describes exactly `archive`, signed by `public_key`.
pub fn verify(entry: &Path, archive: &Path, public_key: &Path) -> Result<()> {
    let entry =
        decode_registry_entry(&fs::read(entry)?).map_err(|_| invalid("invalid registry entry"))?;
    verify_archive(&entry, &fs::read(archive)?, &read_public_key(public_key)?)
}

fn sorted_entries(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(directory)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    paths.sort();
    Ok(paths)
}

fn collect_json(directory: &Path, output: &mut Vec<PathBuf>) -> Result<()> {
    for path in sorted_entries(directory)? {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_json(&path, output)?;
        } else if metadata.is_file()
            && path
                .extension()
                .is_some_and(|extension| extension == "json")
        {
            output.push(path);
        } else if !(metadata.is_file() && path.file_name().is_some_and(|name| name == ".gitkeep")) {
            return Err(invalid(&format!("unexpected registry file: {}", path.display())).into());
        }
    }
    Ok(())
}

fn failure(path: &Path, message: &str) -> Box<dyn std::error::Error> {
    invalid(&format!("{}: {message}", path.display())).into()
}

/// Check a registry checkout: developer keys (`keys/developers/<id>.json`)
/// and entries (`packages/<name, dots as />/<version>.json`). Each entry must
/// be canonical, sit at its own path, and name a publisher whose key covers
/// its namespace. With `archives`, a directory of the downloaded `.xpk` files
/// (named after their URLs), each archive is also verified against its entry.
pub fn check(root: &Path, archives: Option<&Path>) -> Result<()> {
    let mut keys: BTreeMap<String, DeveloperKey> = BTreeMap::new();
    for path in sorted_entries(&root.join("keys/developers"))? {
        let key = decode_developer_key(&fs::read(&path)?)
            .map_err(|_| failure(&path, "invalid developer key"))?;
        if path.file_name().and_then(|name| name.to_str()) != Some(&format!("{}.json", key.id)) {
            return Err(failure(&path, "file name must be <id>.json"));
        }
        keys.insert(key.id.clone(), key);
    }

    let packages = root.join("packages");
    let mut files = Vec::new();
    collect_json(&packages, &mut files)?;
    for path in &files {
        let bytes = fs::read(path)?;
        let entry =
            decode_registry_entry(&bytes).map_err(|_| failure(path, "invalid registry entry"))?;
        let canonical =
            encode_registry_entry(&entry).map_err(|_| failure(path, "invalid registry entry"))?;
        if canonical.as_bytes() != bytes {
            return Err(failure(
                path,
                "entry is not canonical; regenerate it with `xila-package registry entry`",
            ));
        }
        let mut expected = packages.clone();
        expected.extend(entry.name.split('.'));
        expected.push(format!("{}.json", entry.version));
        if *path != expected {
            return Err(failure(
                path,
                &format!(
                    "entry for {} {} must be at {}",
                    entry.name,
                    entry.version,
                    expected.display()
                ),
            ));
        }
        let key = keys
            .get(&entry.publisher)
            .ok_or_else(|| failure(path, &format!("unknown publisher {}", entry.publisher)))?;
        if !key.authorizes(&entry.name) {
            return Err(failure(
                path,
                &format!("publisher {} may not publish {}", key.id, entry.name),
            ));
        }
        if let Some(archives) = archives {
            let name = entry
                .archive
                .url
                .rsplit('/')
                .next()
                .filter(|name| !name.is_empty() && *name != "." && *name != "..")
                .ok_or_else(|| failure(path, "archive URL has no file name"))?;
            let raw = key
                .public_key_bytes()
                .map_err(|_| failure(path, "invalid publisher key"))?;
            let public =
                PublicKey::from_bytes(&raw).map_err(|_| failure(path, "invalid publisher key"))?;
            verify_archive(&entry, &fs::read(archives.join(name))?, &public)
                .map_err(|error| failure(path, &error.to_string()))?;
        }
    }
    println!(
        "Checked {} developer key(s) and {} registry entr{}{}",
        keys.len(),
        files.len(),
        if files.len() == 1 { "y" } else { "ies" },
        if archives.is_some() {
            ", including their archives and signatures"
        } else {
            ""
        }
    );
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
