//! Build and sign self-contained Xila bundles (host tool only).
//!
//! The developer edits xila-package.json; build generates .xila/manifest.json
//! containing hashes for all files. The optional detached Ed25519 signature
//! authenticates the exact runtime manifest and hence every declared payload.

use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use ed25519_dalek::{Signer, SigningKey};
use xila_package_manifest::{
    Application, DEVELOPER_MANIFEST_FILENAME, DEVELOPER_SCHEMA_URL, DeveloperManifest,
    FORMAT_VERSION, MANIFEST_PATH, Manifest, SIGNATURE_PATH, SIGNED_DOMAIN, decode_developer,
    encode_developer,
};
use xila_package_verification::PublicKey;

use crate::{InventoryMode, Result, collect_files, hash_file, invalid, pack, safe_file};

fn check_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(invalid("expected a regular file (no symlinks)").into());
    }
    Ok(())
}

fn check_directory(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(invalid("expected a real directory (no symlinks)").into());
    }
    Ok(path.canonicalize()?)
}

fn output_parent(destination: &Path) -> Result<PathBuf> {
    if destination.file_name().is_none() {
        return Err(invalid("output path must end in a name").into());
    }
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    check_directory(parent)
}

fn check_output_outside_source(destination: &Path, source: &Path) -> Result<()> {
    if output_parent(destination)?.starts_with(source) {
        return Err(invalid("output cannot be inside the input directory").into());
    }
    Ok(())
}

fn check_output_absent(destination: &Path) -> Result<()> {
    if fs::symlink_metadata(destination).is_ok() {
        return Err(invalid("destination already exists; refusing to overwrite").into());
    }
    Ok(())
}

fn temporary_directory(destination: &Path) -> Result<PathBuf> {
    let name = destination
        .file_name()
        .ok_or_else(|| invalid("output path must have a filename"))?
        .to_string_lossy();
    Ok(destination.with_file_name(format!(".{name}.xila-build-{}", std::process::id())))
}

fn read_runtime_manifest(path: &Path) -> Result<(Manifest, Vec<u8>)> {
    check_regular_file(path)?;
    let raw = fs::read(path)?;
    let manifest =
        xila_package_manifest::decode(&raw).map_err(|_| invalid("invalid runtime manifest"))?;
    let canonical = xila_package_manifest::encode(&manifest)
        .map_err(|_| invalid("invalid runtime manifest"))?;
    if canonical.as_bytes() != raw {
        return Err(invalid("noncanonical runtime manifest").into());
    }
    Ok((manifest, raw))
}

fn signing_message(raw_manifest: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; SIGNED_DOMAIN.len() + 4 + raw_manifest.len()];
    let len = xila_package_manifest::signed_message_into(raw_manifest, &mut bytes)
        .map_err(|_| invalid("runtime manifest is too large"))?
        .len();
    bytes.truncate(len);
    Ok(bytes)
}

/// Prepare a developer-owned source directory. Generated hashes and signature
/// are deliberately absent from this human-authored configuration.
pub fn init(
    directory: &Path,
    name: &str,
    version: &str,
    target: &str,
    minimum_xila_abi: u32,
    entrypoint: Option<&str>,
    display_name: Option<&str>,
    icon: Option<&str>,
    standalone: bool,
) -> Result<()> {
    check_output_absent(directory)?;
    if standalone && (entrypoint.is_some() || display_name.is_some() || icon.is_some()) {
        return Err(invalid("standalone packages do not have application metadata").into());
    }
    let config = DeveloperManifest {
        schema: Some(DEVELOPER_SCHEMA_URL.into()),
        format_version: FORMAT_VERSION,
        name: name.into(),
        version: version.into(),
        target: target.into(),
        minimum_xila_abi,
        capabilities: vec![],
        application: if standalone {
            None
        } else {
            Some(Application {
                entrypoint: entrypoint.unwrap_or("bin/main.wasm").into(),
                display_name: display_name.unwrap_or(name).into(),
                icon: icon.unwrap_or_default().into(),
                show_in_launcher: true,
            })
        },
    };
    let text = encode_developer(&config).map_err(|_| invalid("invalid authoring metadata"))?;
    fs::create_dir(directory)?;
    let result = (|| -> Result<()> {
        fs::create_dir(directory.join("bin"))?;
        fs::create_dir(directory.join("resources"))?;
        fs::write(directory.join(DEVELOPER_MANIFEST_FILENAME), text)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(directory);
    }
    result
}

fn checked_signature(path: &Path) -> Result<[u8; 64]> {
    check_regular_file(path)?;
    let raw = fs::read(path)?;
    raw.try_into()
        .map_err(|_| invalid("signature must be exactly 64 raw Ed25519 bytes").into())
}

fn checked_public_key(path: &Path) -> Result<PublicKey> {
    check_regular_file(path)?;
    let raw: [u8; 32] = fs::read(path)?
        .try_into()
        .map_err(|_| invalid("public key must be exactly 32 raw Ed25519 bytes"))?;
    PublicKey::from_bytes(&raw).map_err(|_| invalid("invalid Ed25519 public key").into())
}

/// Sign the complete runtime file inventory with explicitly supplied key
/// material. The private 32-byte seed is never copied to the bundle.
fn sign_manifest(raw_manifest: &[u8], key_path: &Path) -> Result<[u8; 64]> {
    check_regular_file(key_path)?;
    let seed: [u8; 32] = fs::read(key_path)?
        .try_into()
        .map_err(|_| invalid("signing key must be a raw 32-byte Ed25519 seed").into())?;
    let signer = SigningKey::from_bytes(&seed);
    let message = signing_message(raw_manifest)?;
    let signature = signer.sign(&message).to_bytes();
    let public = PublicKey::from_bytes(&signer.verifying_key().to_bytes())
        .map_err(|_| invalid("invalid signing public key"))?;
    public
        .verify(&message, &signature)
        .map_err(|_| invalid("signature self-check failed"))?;
    Ok(signature)
}

/// Validate all files currently present on disk, not just the entrypoint.
/// Any edited translation, font, asset or executable invalidates the inventory.
fn inspect_bundle(root: &Path) -> Result<(Manifest, Vec<u8>, Option<[u8; 64]>)> {
    check_directory(&root.join(".xila"))?;
    let (manifest, raw) = read_runtime_manifest(&root.join(MANIFEST_PATH))?;
    let mut signature = None;
    for entry in fs::read_dir(root.join(".xila"))? {
        let entry = entry?;
        check_regular_file(&entry.path())?;
        if entry.file_name() == "manifest.sig" {
            signature = Some(checked_signature(&entry.path())?);
        } else if entry.file_name() != "manifest.json" {
            return Err(invalid("unexpected .xila metadata").into());
        }
    }
    if fs::symlink_metadata(root.join(DEVELOPER_MANIFEST_FILENAME)).is_ok() {
        return Err(invalid("developer config must not be shipped with the bundle").into());
    }
    let mut actual = Vec::new();
    collect_files(root, root, &mut actual, InventoryMode::Bundle)?;
    actual.sort_by(|a, b| a.path.cmp(&b.path));
    let mut declared = manifest.files.clone();
    declared.sort_by(|a, b| a.path.cmp(&b.path));
    if actual != declared {
        return Err(invalid("bundle file inventory/hashes differ from runtime manifest").into());
    }
    Ok((manifest, raw, signature))
}

/// Construct an unpacked bundle from a folder containing xila-package.json.
///
/// The runtime manifest contains hash+length+path for *every* payload file.
/// --signing-key is optional only for unsigned local development, and must
/// point to an external raw 32-byte Ed25519 seed.
pub fn build(source: &Path, output: &Path, signing_key: Option<&Path>) -> Result<()> {
    let source = check_directory(source)?;
    check_output_outside_source(output, &source)?;
    check_output_absent(output)?;
    if fs::symlink_metadata(source.join(".xila")).is_ok() {
        return Err(invalid(".xila is reserved for generated metadata").into());
    }
    let developer_path = source.join(DEVELOPER_MANIFEST_FILENAME);
    check_regular_file(&developer_path)?;
    let config = decode_developer(&fs::read(&developer_path)?)
        .map_err(|_| invalid("invalid developer manifest"))?;

    let mut files = Vec::new();
    collect_files(&source, &source, &mut files, InventoryMode::Developer)?;
    files.sort_by(|a, b| a.path.cmp(&b.path));
    for file in &files {
        // The native writer uses restricted USTAR and rejects longer names.
        if !file.path.is_ascii() || file.path.len() > 99 {
            return Err(invalid("payload filename must be ASCII and <= 99 bytes").into());
        }
    }
    let manifest = config
        .into_bundle_manifest(files)
        .map_err(|_| invalid("missing executable/icon or invalid application metadata"))?;
    let raw = xila_package_manifest::encode(&manifest)
        .map_err(|_| invalid("generated runtime manifest failed validation"))?;

    let signature = if let Some(key_path) = signing_key {
        let key_path = key_path.canonicalize()?;
        if key_path.starts_with(&source) {
            return Err(invalid("signing key must be outside source directory").into());
        }
        Some(sign_manifest(raw.as_bytes(), &key_path)?)
    } else {
        None
    };

    let stage = temporary_directory(output)?;
    fs::create_dir(&stage)?; // Exclusive: never remove an existing stage.
    let operation = (|| -> Result<()> {
        fs::create_dir(stage.join(".xila"))?;
        fs::write(stage.join(MANIFEST_PATH), &raw)?;
        if let Some(signature) = signature {
            fs::write(stage.join(SIGNATURE_PATH), signature)?;
        }
        for file in &manifest.files {
            let from = safe_file(&source, &file.path)?;
            let to = stage.join(&file.path);
            if let Some(parent) = to.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(from, &to)?;
            let (size, sha256) = hash_file(&to)?;
            if size != file.size || sha256 != file.sha256 {
                return Err(invalid("payload modified during bundle construction").into());
            }
        }
        let (persisted, persisted_raw, persisted_signature) = inspect_bundle(&stage)?;
        if persisted != manifest || persisted_raw != raw.as_bytes() {
            return Err(invalid("bundle changed during construction").into());
        }
        if let Some(signature) = signature {
            if persisted_signature != Some(signature) {
                return Err(invalid("signature was not persisted").into());
            }
        }
        check_output_absent(output)?;
        fs::rename(&stage, output)?;
        Ok(())
    })();
    if operation.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    operation
}

/// Export the exact bytes to be signed by an external signer/HSM/KMS/CI.
/// This supports developer-owned signing identities without exposing a key.
pub fn export_signing_payload(bundle: &Path, output: &Path) -> Result<()> {
    let root = check_directory(bundle)?;
    check_output_outside_source(output, &root)?;
    check_output_absent(output)?;
    let (_, raw, signature) = inspect_bundle(&root)?;
    if signature.is_some() {
        return Err(invalid("bundle is already signed").into());
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    file.write_all(&signing_message(&raw)?)?;
    file.sync_all()?;
    Ok(())
}

/// Attach a signature made elsewhere, after verifying it against a
/// developer-supplied raw 32-byte public key. Never accept blind signatures.
pub fn attach_signature(bundle: &Path, signature: &Path, public_key: &Path) -> Result<()> {
    let root = check_directory(bundle)?;
    let (_, raw, existing) = inspect_bundle(&root)?;
    if existing.is_some() {
        return Err(invalid("bundle is already signed").into());
    }
    let signature = checked_signature(signature)?;
    let public = checked_public_key(public_key)?;
    public
        .verify(&signing_message(&raw)?, &signature)
        .map_err(|_| invalid("detached signature did not verify"))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(SIGNATURE_PATH))?;
    file.write_all(&signature)?;
    file.sync_all()?;
    Ok(())
}

/// Validate manifest, all resources and optional publisher signature.
/// Unsigned bundles are only accepted when no public key was supplied.
pub fn verify(bundle: &Path, public_key: Option<&Path>) -> Result<Manifest> {
    let root = check_directory(bundle)?;
    let (manifest, raw, signature) = inspect_bundle(&root)?;
    if let Some(public_key) = public_key {
        let signature = signature.ok_or_else(|| invalid("signature is missing"))?;
        checked_public_key(public_key)?
            .verify(&signing_message(&raw)?, &signature)
            .map_err(|_| invalid("bundle signature invalid"))?;
    }
    Ok(manifest)
}

/// Write a deterministic .xpk TAR archive from the *already validated* bundle.
pub fn archive(bundle: &Path, output: &Path) -> Result<()> {
    let root = check_directory(bundle)?;
    check_output_outside_source(output, &root)?;
    check_output_absent(output)?;
    inspect_bundle(&root)?;
    pack(
        &root,
        &root.join(MANIFEST_PATH),
        output,
        fs::symlink_metadata(root.join(SIGNATURE_PATH))
            .is_ok()
            .then(|| root.join(SIGNATURE_PATH))
            .as_deref(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    use xila_package_manifest::{decode, decode_developer};

    fn setup(root: &Path) -> (PathBuf, PathBuf) {
        let source = root.join("source");
        init(
            &source,
            "community.weather",
            "1.0.0",
            "wasm32-wasip1",
            1,
            Some("bin/weather.wasm"),
            Some("Weather"),
            Some("resources/icon.png"),
            false,
        )
        .unwrap();
        fs::write(source.join("bin/weather.wasm"), b"wasm executable").unwrap();
        fs::create_dir_all(source.join("resources/translations")).unwrap();
        fs::write(source.join("resources/icon.png"), b"icon bytes").unwrap();
        fs::write(
            source.join("resources/translations/en.json"),
            b"{\"hello\":\"world\"}",
        )
        .unwrap();
        (source, root.join("Weather.app"))
    }

    #[test]
    fn init_and_build_have_distinct_authoring_and_signed_manifest() {
        let temp = tempdir().unwrap();
        let (source, bundle) = setup(temp.path());
        let authored =
            decode_developer(&fs::read(source.join(DEVELOPER_MANIFEST_FILENAME)).unwrap()).unwrap();
        assert_eq!(authored.name, "community.weather");
        build(&source, &bundle, None).unwrap();
        assert!(!bundle.join(DEVELOPER_MANIFEST_FILENAME).exists());
        assert!(bundle.join(MANIFEST_PATH).exists());
        assert!(!bundle.join(SIGNATURE_PATH).exists());
        let runtime = decode(&fs::read(bundle.join(MANIFEST_PATH)).unwrap()).unwrap();
        assert_eq!(runtime.files.len(), 3);
        assert!(
            runtime
                .files
                .iter()
                .any(|f| f.path == "resources/translations/en.json")
        );
        assert_eq!(runtime.application.unwrap().entrypoint, "bin/weather.wasm");
        assert_eq!(
            fs::read(bundle.join("resources/icon.png")).unwrap(),
            b"icon bytes"
        );
        assert!(verify(&bundle, None).is_ok());
        assert!(
            init(
                &source,
                "community.weather",
                "1.0.0",
                "wasm32-wasip1",
                1,
                None,
                None,
                None,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn archive_roundtrip_and_detect_resource_tampering() {
        let temp = tempdir().unwrap();
        let (source, bundle) = setup(temp.path());
        build(&source, &bundle, None).unwrap();
        let archive_path = temp.path().join("Weather.xpk");
        archive(&bundle, &archive_path).unwrap();
        let manifest =
            xila_package_reader::inspect_unsigned(&fs::read(&archive_path).unwrap()).unwrap();
        assert_eq!(manifest.files.len(), 3);

        fs::write(bundle.join("resources/icon.png"), b"changed").unwrap();
        assert!(verify(&bundle, None).is_err());
        assert!(archive(&bundle, &temp.path().join("tampered.xpk")).is_err());
        assert!(!temp.path().join("tampered.xpk").exists());
    }

    #[test]
    fn signed_bundle_authenticates_all_resources() {
        let temp = tempdir().unwrap();
        let (source, bundle) = setup(temp.path());
        let seed = [7u8; 32];
        let private_path = temp.path().join("private.key");
        let public_path = temp.path().join("public.key");
        fs::write(&private_path, seed).unwrap();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        fs::write(&public_path, public).unwrap();
        build(&source, &bundle, Some(&private_path)).unwrap();
        assert!(verify(&bundle, Some(&public_path)).is_ok());
        let xpk = temp.path().join("signed.xpk");
        archive(&bundle, &xpk).unwrap();
        let key = PublicKey::from_bytes(&public).unwrap();
        let manifest = xila_package_reader::verify_signed(&fs::read(&xpk).unwrap(), &key).unwrap();
        assert_eq!(manifest.files.len(), 3);

        fs::write(bundle.join("resources/translations/en.json"), b"evil").unwrap();
        assert!(verify(&bundle, Some(&public_path)).is_err());
        assert!(archive(&bundle, &temp.path().join("bad.xpk")).is_err());
    }

    #[test]
    fn external_signer_round_trip_and_invalid_signature() {
        let temp = tempdir().unwrap();
        let (source, bundle) = setup(temp.path());
        build(&source, &bundle, None).unwrap();
        let payload = temp.path().join("to-sign.bin");
        export_signing_payload(&bundle, &payload).unwrap();
        let seed = [8u8; 32];
        let signer = SigningKey::from_bytes(&seed);
        let public_path = temp.path().join("public.key");
        fs::write(&public_path, signer.verifying_key().to_bytes()).unwrap();
        let signature_path = temp.path().join("signature");
        fs::write(
            &signature_path,
            signer.sign(&fs::read(&payload).unwrap()).to_bytes(),
        )
        .unwrap();
        attach_signature(&bundle, &signature_path, &public_path).unwrap();
        assert!(verify(&bundle, Some(&public_path)).is_ok());
        assert!(export_signing_payload(&bundle, &temp.path().join("other.bin")).is_err());

        let new_bundle = temp.path().join("unsigned.app");
        build(&source, &new_bundle, None).unwrap();
        let wrong_sig = temp.path().join("wrong.sig");
        fs::write(&wrong_sig, [0u8; 64]).unwrap();
        assert!(attach_signature(&new_bundle, &wrong_sig, &public_path).is_err());
        assert!(!new_bundle.join(SIGNATURE_PATH).exists());
    }

    #[test]
    fn reject_unexpected_files_and_invalid_entrypoint() {
        let temp = tempdir().unwrap();
        let (source, bundle) = setup(temp.path());
        fs::remove_file(source.join("bin/weather.wasm")).unwrap();
        assert!(build(&source, &bundle, None).is_err());
        assert!(!bundle.exists());
        fs::write(source.join("bin/weather.wasm"), b"restored").unwrap();
        fs::create_dir(source.join(".xila")).unwrap();
        assert!(build(&source, &bundle, None).is_err());
    }

    #[test]
    fn do_not_overwrite_existing_bundle_or_build_inside_source() {
        let temp = tempdir().unwrap();
        let (source, bundle) = setup(temp.path());
        assert!(build(&source, &source.join("nested.app"), None).is_err());
        fs::create_dir(&bundle).unwrap();
        fs::write(bundle.join("important"), b"keep").unwrap();
        assert!(build(&source, &bundle, None).is_err());
        assert_eq!(fs::read(bundle.join("important")).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn reject_symlinked_payloads() {
        use std::os::unix::fs::symlink;
        let temp = tempdir().unwrap();
        let (source, bundle) = setup(temp.path());
        symlink(
            source.join("bin/weather.wasm"),
            source.join("shortcut.wasm"),
        )
        .unwrap();
        assert!(build(&source, &bundle, None).is_err());
        assert!(!bundle.exists());
    }

    #[test]
    fn executable_only_package_can_be_built() {
        let temp = tempdir().unwrap();
        let source = temp.path().join("tool");
        init(
            &source,
            "xila.tool",
            "1.0.0",
            "wasm32-wasip1",
            1,
            None,
            None,
            None,
            true,
        )
        .unwrap();
        fs::write(source.join("bin/tool.wasm"), b"standalone wasm").unwrap();
        let bundle = temp.path().join("Tool.app");
        build(&source, &bundle, None).unwrap();
        let manifest = verify(&bundle, None).unwrap();
        assert!(manifest.application.is_none());
    }
}
