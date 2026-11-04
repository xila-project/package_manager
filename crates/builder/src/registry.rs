//! Generate and check registry entries for released, signed archives.
//!
//! Entries are derived from the archive itself so the registry never restates
//! (and can never contradict) the developer-signed manifest by hand.

use ed25519_dalek::{Signer, SigningKey};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt::Write as _,
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use xila_package_manager::trust::{self, TrustedRoot};
use xila_package_manifest::{
    Archive, DEVELOPER_KEY_DOMAIN, DeveloperKey, ENTRY_DOMAIN, INDEX_DOMAIN, INDEX_PATH,
    INDEX_SCHEMA_URL, Index, IndexFile, Manifest, NamedKey, ROOT_DOMAIN, ROOT_PATH,
    ROOT_SCHEMA_URL, RegistryEntry, Root, SIGNATURE_SUFFIX, TRUST_FORMAT_VERSION,
    decode_developer_key, decode_registry_entry, encode_index, encode_registry_entry, encode_root,
    signed_message,
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

// ---------------------------------------------------------------------------
// Repository signatures: root.json, index.json and detached .sig files.
// ---------------------------------------------------------------------------

fn read_raw_public_key(path: &Path) -> Result<[u8; 32]> {
    Ok(fs::read(path)?
        .try_into()
        .map_err(|_| invalid("public key must be exactly 32 raw bytes"))?)
}

fn base64(bytes: &[u8; 32]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(44);
    for chunk in bytes.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        for index in 0..4 {
            output.push(if index <= chunk.len() {
                TABLE[(value >> (18 - 6 * index) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    output
}

fn signature_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(SIGNATURE_SUFFIX);
    PathBuf::from(name)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

fn sign_bytes(key: &SigningKey, domain: &[u8], bytes: &[u8]) -> Result<[u8; 64]> {
    let message = signed_message(domain, bytes).map_err(|_| invalid("document too large"))?;
    Ok(key.sign(&message).to_bytes())
}

fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| invalid("system clock is before 1970"))?
        .as_secs())
}

/// Write `output` (`root.json`) and its signature: version `version`, signed by
/// `root_seed`, naming that key as root key and `repository_public_key` as the
/// repository key. Run offline; never overwrites.
pub fn root(
    root_seed: &Path,
    root_id: &str,
    repository_public_key: &Path,
    repository_id: &str,
    version: u64,
    output: &Path,
) -> Result<()> {
    let root_key = crate::key::read_seed(root_seed)?;
    let root = Root {
        schema: Some(ROOT_SCHEMA_URL.into()),
        format_version: TRUST_FORMAT_VERSION,
        version,
        root_keys: vec![NamedKey {
            id: root_id.into(),
            public_key: base64(&root_key.verifying_key().to_bytes()),
        }],
        repository_keys: vec![NamedKey {
            id: repository_id.into(),
            public_key: base64(&read_raw_public_key(repository_public_key)?),
        }],
    };
    let text = encode_root(&root).map_err(|_| {
        invalid("invalid root (version 0, bad identifier, or one key in both roles)")
    })?;
    let signature = sign_bytes(&root_key, ROOT_DOMAIN, text.as_bytes())?;
    let signature_file = signature_path(output);
    if signature_file.exists() {
        return Err(invalid("root signature output already exists").into());
    }
    write_new_file(output, text.as_bytes())?;
    write_new_file(&signature_file, &signature)?;
    Ok(())
}

/// Sign a checked registry into the new directory `output`: copy `root.json`
/// (already root-signed), sign every developer key and entry, and write a
/// signed `index.json` valid for `expires_in_days`. `version` defaults to the
/// current Unix time, so successive publications increase.
pub fn sign(
    registry: &Path,
    root_public_key: &Path,
    repository_seed: &Path,
    output: &Path,
    version: Option<u64>,
    expires_in_days: u64,
) -> Result<()> {
    check(registry, None)?;
    let pinned = [read_raw_public_key(root_public_key)?];
    let root_bytes = fs::read(registry.join(ROOT_PATH))?;
    let root_signature = fs::read(signature_path(&registry.join(ROOT_PATH)))?;
    let trusted = TrustedRoot::bootstrap(&root_bytes, &root_signature, &pinned, 0)
        .map_err(|error| invalid(&format!("{ROOT_PATH}: {error}")))?;
    let key = crate::key::read_seed(repository_seed)?;
    let public = base64(&key.verifying_key().to_bytes());
    if !trusted
        .root()
        .repository_keys
        .iter()
        .any(|listed| listed.public_key == public)
    {
        return Err(invalid("the signing key is not a repository key of root.json").into());
    }

    let version = match version {
        Some(version) => version,
        None => now()?,
    };
    let expires = expires_in_days
        .checked_mul(86_400)
        .and_then(|seconds| version.checked_add(seconds))
        .filter(|_| expires_in_days > 0)
        .ok_or_else(|| invalid("expiry must be at least one day"))?;

    fs::create_dir(output)?;
    write_new_file(&output.join(ROOT_PATH), &root_bytes)?;
    write_new_file(&signature_path(&output.join(ROOT_PATH)), &root_signature)?;

    let mut listed = Vec::new();
    collect_json(&registry.join("keys/developers"), &mut listed)?;
    let developer_keys = listed.len();
    collect_json(&registry.join("packages"), &mut listed)?;
    let mut files = Vec::with_capacity(listed.len());
    for (position, path) in listed.iter().enumerate() {
        let relative = path
            .strip_prefix(registry)
            .ok()
            .and_then(Path::to_str)
            .ok_or_else(|| invalid("registry path is not UTF-8"))?
            .to_owned();
        let bytes = fs::read(path)?;
        let domain = if position < developer_keys {
            DEVELOPER_KEY_DOMAIN
        } else {
            ENTRY_DOMAIN
        };
        let destination = output.join(&relative);
        fs::create_dir_all(destination.parent().expect("listed files have a parent"))?;
        write_new_file(&destination, &bytes)?;
        write_new_file(
            &signature_path(&destination),
            &sign_bytes(&key, domain, &bytes)?,
        )?;
        files.push(IndexFile {
            path: relative,
            sha256: sha256_hex(&bytes),
            size: bytes.len() as u64,
        });
    }
    files.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    let index = encode_index(&Index {
        schema: Some(INDEX_SCHEMA_URL.into()),
        format_version: TRUST_FORMAT_VERSION,
        version,
        expires,
        files,
    })
    .map_err(|_| invalid("invalid index"))?;
    write_new_file(&output.join(INDEX_PATH), index.as_bytes())?;
    write_new_file(
        &signature_path(&output.join(INDEX_PATH)),
        &sign_bytes(&key, INDEX_DOMAIN, index.as_bytes())?,
    )?;
    verify_signed(output, root_public_key, Some(version))
}

fn collect_site(root: &Path, directory: &Path, output: &mut Vec<String>) -> Result<()> {
    for path in sorted_entries(directory)? {
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            collect_site(root, &path, output)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .ok()
                .and_then(Path::to_str)
                .ok_or_else(|| invalid("registry path is not UTF-8"))?;
            output.push(relative.to_owned());
        } else {
            return Err(failure(&path, "unexpected file type"));
        }
    }
    Ok(())
}

/// Print `trust::fingerprint` of a raw public key file.
pub fn fingerprint(public_key: &Path) -> Result<()> {
    println!("{}", trust::fingerprint(&read_raw_public_key(public_key)?));
    Ok(())
}

/// Verify a signed registry the way a device would, from the pinned
/// `root_public_key`: root, index (and its expiry at `now`, if given), every
/// listed file and its own signature, and each entry's publisher. Rejects
/// unlisted files.
pub fn verify_signed(site: &Path, root_public_key: &Path, now: Option<u64>) -> Result<()> {
    let pinned = [read_raw_public_key(root_public_key)?];
    let read_signed = |relative: &str| -> Result<(Vec<u8>, Vec<u8>)> {
        let path = site.join(relative);
        let read = |path: &Path| {
            fs::read(path).map_err(|error| invalid(&format!("{}: {error}", path.display())))
        };
        Ok((read(&path)?, read(&signature_path(&path))?))
    };
    let (root, root_signature) = read_signed(ROOT_PATH)?;
    let trusted = TrustedRoot::bootstrap(&root, &root_signature, &pinned, 0)
        .map_err(|error| invalid(&format!("{ROOT_PATH}: {error}")))?;
    let (index, index_signature) = read_signed(INDEX_PATH)?;
    let index = trusted
        .verify_index(&index, &index_signature, 0, now)
        .map_err(|error| invalid(&format!("{INDEX_PATH}: {error}")))?;

    let mut present = Vec::new();
    for directory in ["keys", "packages"] {
        if site.join(directory).is_dir() {
            collect_site(site, &site.join(directory), &mut present)?;
        }
    }
    for path in &present {
        let listed = path.strip_suffix(SIGNATURE_SUFFIX).unwrap_or(path);
        if index.file(listed).is_none() {
            return Err(invalid(&format!("{path}: not listed in {INDEX_PATH}")).into());
        }
    }

    let mut developers: BTreeMap<String, DeveloperKey> = BTreeMap::new();
    for file in index
        .files
        .iter()
        .filter(|file| file.path.starts_with("keys/"))
    {
        let (bytes, signature) = read_signed(&file.path)?;
        let fail = |error: trust::Error| invalid(&format!("{}: {error}", file.path));
        trust::check_listed(&index, &file.path, &bytes).map_err(fail)?;
        let key = trusted
            .verify_developer_key(&bytes, &signature)
            .map_err(fail)?;
        if file.path != trust::developer_key_path(&key.id) {
            return Err(invalid(&format!("{}: file name must be <id>.json", file.path)).into());
        }
        developers.insert(key.id.clone(), key);
    }
    let mut entries = 0usize;
    for file in index
        .files
        .iter()
        .filter(|file| file.path.starts_with("packages/"))
    {
        let (bytes, signature) = read_signed(&file.path)?;
        let fail = |error: trust::Error| invalid(&format!("{}: {error}", file.path));
        trust::check_listed(&index, &file.path, &bytes).map_err(fail)?;
        let entry = trusted.verify_entry(&bytes, &signature).map_err(fail)?;
        if file.path != trust::entry_path(&entry.name, &entry.version) {
            return Err(invalid(&format!("{}: entry is not at its own path", file.path)).into());
        }
        let developer = developers.get(&entry.publisher).ok_or_else(|| {
            invalid(&format!(
                "{}: unknown publisher {}",
                file.path, entry.publisher
            ))
        })?;
        trust::publisher_key(&entry, developer).map_err(fail)?;
        entries += 1;
    }
    println!(
        "Verified signed registry: root v{} (root key {}), index v{} (expires {}), {} developer key(s), {} entr{}",
        trusted.version(),
        trust::fingerprint(&pinned[0]),
        index.version,
        index.expires,
        developers.len(),
        entries,
        if entries == 1 { "y" } else { "ies" }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_registry(directory: &Path) {
        fs::create_dir_all(directory.join("keys/developers")).unwrap();
        fs::create_dir_all(directory.join("packages/xila/clock")).unwrap();
        fs::write(
            directory.join("keys/developers/xila-project.json"),
            r#"{"id":"xila-project","author":"Xila Project","algorithm":"ed25519","public_key":"6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbc=","openssh":null,"namespaces":["xila"]}"#,
        )
        .unwrap();
        let entry = RegistryEntry {
            schema: Some(xila_package_manifest::REGISTRY_ENTRY_SCHEMA_URL.into()),
            format_version: 1,
            name: "xila.clock".into(),
            version: "0.1.0".into(),
            target: "wasm32-wasip1".into(),
            minimum_xila_abi: 1,
            capabilities: vec![],
            display_name: Some("Clock".into()),
            metadata: None,
            publisher: "xila-project".into(),
            archive: Archive {
                url: "https://example.com/clock.xpk".into(),
                sha256: "c".repeat(64),
                size: 10,
            },
        };
        fs::write(
            directory.join("packages/xila/clock/0.1.0.json"),
            encode_registry_entry(&entry).unwrap(),
        )
        .unwrap();
    }

    struct Keys {
        _directory: tempfile::TempDir,
        root_seed: PathBuf,
        root_public: PathBuf,
        repository_seed: PathBuf,
        repository_public: PathBuf,
    }

    fn new_keys() -> Keys {
        let directory = tempfile::tempdir().unwrap();
        let path = |name: &str| directory.path().join(name);
        crate::key::generate(&path("root.seed"), &path("root.pub")).unwrap();
        crate::key::generate(&path("repository.seed"), &path("repository.pub")).unwrap();
        Keys {
            root_seed: path("root.seed"),
            root_public: path("root.pub"),
            repository_seed: path("repository.seed"),
            repository_public: path("repository.pub"),
            _directory: directory,
        }
    }

    #[test]
    fn signs_and_verifies_a_registry_and_rejects_tampering() {
        let keys = new_keys();
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_registry(&registry);
        root(
            &keys.root_seed,
            "root-test",
            &keys.repository_public,
            "repository-test",
            1,
            &registry.join(ROOT_PATH),
        )
        .unwrap();
        // Never overwrites.
        assert!(
            root(
                &keys.root_seed,
                "root-test",
                &keys.repository_public,
                "repository-test",
                2,
                &registry.join(ROOT_PATH),
            )
            .is_err()
        );

        let site = temp.path().join("site");
        sign(
            &registry,
            &keys.root_public,
            &keys.repository_seed,
            &site,
            Some(1_000),
            30,
        )
        .unwrap();
        assert!(site.join("packages/xila/clock/0.1.0.json.sig").is_file());
        assert!(site.join("keys/developers/xila-project.json.sig").is_file());
        verify_signed(&site, &keys.root_public, Some(1_000)).unwrap();
        assert!(verify_signed(&site, &keys.root_public, Some(1_000 + 30 * 86_400)).is_err());
        // The repository key is not the root of trust.
        assert!(verify_signed(&site, &keys.repository_public, None).is_err());

        let entry = site.join("packages/xila/clock/0.1.0.json");
        let original = fs::read(&entry).unwrap();
        fs::write(
            &entry,
            String::from_utf8(original.clone())
                .unwrap()
                .replace("Clock", "Clocx"),
        )
        .unwrap();
        assert!(verify_signed(&site, &keys.root_public, None).is_err());
        fs::write(&entry, &original).unwrap();
        fs::write(site.join("packages/xila/clock/0.2.0.json"), &original).unwrap();
        assert!(verify_signed(&site, &keys.root_public, None).is_err());
        fs::remove_file(site.join("packages/xila/clock/0.2.0.json")).unwrap();
        verify_signed(&site, &keys.root_public, None).unwrap();
    }

    #[test]
    fn sign_requires_a_listed_repository_key() {
        let keys = new_keys();
        let other = new_keys();
        let temp = tempfile::tempdir().unwrap();
        let registry = temp.path().join("registry");
        write_registry(&registry);
        root(
            &keys.root_seed,
            "root-test",
            &keys.repository_public,
            "repository-test",
            1,
            &registry.join(ROOT_PATH),
        )
        .unwrap();
        for (root_public, seed) in [
            (&keys.root_public, &other.repository_seed),
            (&keys.root_public, &keys.root_seed),
            (&other.root_public, &keys.repository_seed),
        ] {
            assert!(
                sign(
                    &registry,
                    root_public,
                    seed,
                    &temp.path().join("site"),
                    Some(1),
                    30
                )
                .is_err()
            );
            let _ = fs::remove_dir_all(temp.path().join("site"));
        }
        // One key may not hold both roles.
        assert!(
            root(
                &keys.root_seed,
                "root-test",
                &keys.root_public,
                "repository-test",
                1,
                &temp.path().join("other-root.json"),
            )
            .is_err()
        );
    }

    #[test]
    fn hashes_as_lowercase_hex() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
