//! Host-side construction of self-contained, relocatable Xila bundles.
//!
//! A bundle is a directory, not an installation or an active-version record:
//!
//! <bundle>/
//!   .xila/manifest.json
//!   .xila/manifest.sig (optional)
//!   <manifest.files[].path>
//!
//! The TAR representation uses exactly these relative paths and may later be
//! unpacked or copied by an application. This module never accesses Xila VFS.

use std::{
    fs,
    io,
    path::{Path, PathBuf},
};

use crate::{Result, collect_files, hash_file, invalid, pack, safe_file};
use xila_package_manifest::{MANIFEST_PATH, Manifest, SIGNATURE_PATH};

fn read_canonical_manifest(path: &Path) -> Result<(Manifest, Vec<u8>)> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(invalid("manifest must be a regular file").into());
    }
    let raw = fs::read(path)?;
    let manifest =
        xila_package_manifest::decode(&raw).map_err(|_| invalid("invalid bundle manifest"))?;
    let canonical =
        xila_package_manifest::encode(&manifest).map_err(|_| invalid("invalid bundle manifest"))?;
    if canonical.as_bytes() != raw {
        return Err(invalid(
            "manifest must use canonical JSON; regenerate it before building/signing",
        )
        .into());
    }
    Ok((manifest, raw))
}

fn checked_signature(path: &Path) -> Result<[u8; 64]> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(invalid("signature must be a regular file").into());
    }
    let raw = fs::read(path)?;
    Ok(raw
        .try_into()
        .map_err(|_| invalid("signature must be exactly 64 bytes"))?)
}

fn validate_payload_inventory(
    root: &Path,
    manifest: &Manifest,
    ignore_bundle_metadata: bool,
) -> Result<()> {
    let mut actual = Vec::new();
    collect_files(root, root, &mut actual, ignore_bundle_metadata)?;
    let mut expected = manifest.files.clone();
    actual.sort_by(|a, b| a.path.cmp(&b.path));
    expected.sort_by(|a, b| a.path.cmp(&b.path));
    if actual != expected {
        return Err(invalid(
            "payload inventory, file sizes or SHA-256 differ from the manifest; run manifest update",
        )
        .into());
    }
    Ok(())
}

fn destination_parent(destination: &Path) -> Result<PathBuf> {
    if destination.file_name().is_none() {
        return Err(invalid("output must name a bundle directory or archive").into());
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    Ok(parent.canonicalize()?)
}

fn reject_nested_output(destination: &Path, input_root: &Path) -> Result<()> {
    if destination_parent(destination)?.starts_with(input_root) {
        return Err(invalid("output must not reside inside the input directory").into());
    }
    Ok(())
}

fn stage_path(destination: &Path) -> Result<PathBuf> {
    let filename = destination
        .file_name()
        .ok_or_else(|| invalid("missing destination filename"))?
        .to_string_lossy();
    Ok(destination.with_file_name(format!(
        ".{filename}.xila-build-{}",
        std::process::id()
    )))
}

/// Create a **directory bundle**, not a TAR archive or an installed program.
///
/// All source payloads must be declared by the existing manifest, including
/// the application executable and icons. A standalone executable package
/// (application = null) works too. The caller supplies any detached signature
/// made over the exact canonical manifest bytes; this function does not sign.
pub fn build(
    source: &Path,
    manifest_path: &Path,
    destination: &Path,
    signature_path: Option<&Path>,
) -> Result<()> {
    let root = source.canonicalize()?;
    if !root.is_dir() {
        return Err(invalid("source must be a directory").into());
    }
    reject_nested_output(destination, &root)?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err(invalid("bundle output already exists").into());
    }
    let (manifest, raw_manifest) = read_canonical_manifest(manifest_path)?;
    if manifest_path.canonicalize()?.starts_with(&root) {
        return Err(invalid("manifest must be outside the payload directory").into());
    }
    // Capture signature before touching output and reject malformed metadata.
    let signature = signature_path.map(checked_signature).transpose()?;
    validate_payload_inventory(&root, &manifest, false)?;

    let stage = stage_path(destination)?;
    // Exclusive creation: never clean up or overwrite another build's stage.
    fs::create_dir(&stage)?;
    let result = (|| -> Result<()> {
        fs::create_dir(stage.join(".xila"))?;
        fs::write(stage.join(MANIFEST_PATH), &raw_manifest)?;
        if let Some(signature) = signature {
            fs::write(stage.join(SIGNATURE_PATH), signature)?;
        }

        for file in &manifest.files {
            let input = safe_file(&root, &file.path)?;
            let output = stage.join(&file.path);
            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent)?;
            }
            // Files are copied, not linked: a bundle is fully self-contained
            // and independent of source changes and build paths.
            fs::copy(input, &output)?;
            let (size, sha256) = hash_file(&output)?;
            if size != file.size || sha256 != file.sha256 {
                return Err(invalid("payload changed while creating the bundle").into());
            }
        }
        // Publish the finished directory only after validating it.
        validate_payload_inventory(&stage, &manifest, true)?;
        if fs::symlink_metadata(destination).is_ok() {
            return Err(invalid("bundle output already exists").into());
        }
        fs::rename(&stage, destination)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn check_bundle_metadata(directory: &Path) -> Result<(PathBuf, Option<PathBuf>, Manifest)> {
    let metadata = directory.join(".xila");
    if !fs::symlink_metadata(&metadata)?.is_dir() {
        return Err(invalid("bundle .xila must be a directory").into());
    }
    let manifest_path = directory.join(MANIFEST_PATH);
    let (manifest, _) = read_canonical_manifest(&manifest_path)?;
    let signature_path = directory.join(SIGNATURE_PATH);
    let mut signature_present = false;
    for entry in fs::read_dir(&metadata)? {
        let entry = entry?;
        let name = entry.file_name();
        let metadata = fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(invalid("bundle metadata must contain regular files only").into());
        }
        if name == "manifest.sig" {
            signature_present = true;
        } else if name != "manifest.json" {
            return Err(invalid("unknown bundle metadata file").into());
        }
    }
    let signature = if signature_present {
        checked_signature(&signature_path)?;
        Some(signature_path)
    } else {
        None
    };
    Ok((manifest_path, signature, manifest))
}

/// Produce a distributable .xpk from an already-built bundle directory.
///
/// Its TAR root has the same layout as the bundle directory, so unarchiving
/// yields a self-contained bundle. No install hook or VFS use is involved.
pub fn archive(bundle: &Path, output: &Path) -> Result<()> {
    if fs::symlink_metadata(bundle)?.file_type().is_symlink() {
        return Err(invalid("bundle root cannot be a symlink").into());
    }
    let root = bundle.canonicalize()?;
    if !root.is_dir() {
        return Err(invalid("bundle must be a directory").into());
    }
    reject_nested_output(output, &root)?;
    let (manifest_path, signature, manifest) = check_bundle_metadata(&root)?;
    validate_payload_inventory(&root, &manifest, true)?;
    pack(&root, &manifest_path, output, signature.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{generate, set_application};
    use std::{fs, path::Path};
    use tempfile::tempdir;

    fn prepare_application(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir_all(source.join("share/icons")).unwrap();
        fs::write(source.join("bin/weather.wasm"), b"wasm content").unwrap();
        fs::write(source.join("share/icons/weather.png"), b"icon content").unwrap();
        let manifest = root.join("manifest.json");
        generate(&source, &manifest, "community.weather", "1.2.3", "wasm32-wasip1", 2)
            .unwrap();
        set_application(
            &manifest,
            "bin/weather.wasm",
            "Weather",
            Some("share/icons/weather.png"),
            false,
        )
        .unwrap();
        (source, manifest, root.join("Weather.app"))
    }

    #[test]
    fn build_directory_and_archive_have_same_payload_and_app_metadata() {
        let dir = tempdir().unwrap();
        let (source, manifest, output) = prepare_application(dir.path());
        build(&source, &manifest, &output, None).unwrap();
        assert_eq!(
            fs::read(output.join("bin/weather.wasm")).unwrap(),
            b"wasm content"
        );
        assert_eq!(
            fs::read(output.join(MANIFEST_PATH)).unwrap(),
            fs::read(manifest).unwrap()
        );
        assert!(!output.join(SIGNATURE_PATH).exists());
        assert!(output.join("share/icons/weather.png").exists());

        let archive_path = dir.path().join("Weather.xpk");
        archive(&output, &archive_path).unwrap();
        let bytes = fs::read(&archive_path).unwrap();
        let inspected = xila_package_reader::inspect_unsigned(&bytes).unwrap();
        let app = inspected.application.unwrap();
        assert_eq!(app.entrypoint, "bin/weather.wasm");
        assert_eq!(app.icon, "share/icons/weather.png");
        assert_eq!(app.display_name, "Weather");
        assert!(app.show_in_launcher);

        // No references to the source directory: bundles survive its deletion.
        fs::remove_dir_all(source).unwrap();
        assert!(output.join("bin/weather.wasm").exists());
    }

    #[test]
    fn supports_standalone_executable_and_reproducible_archive() {
        let dir = tempdir().unwrap();
        let source = dir.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("binary.wasm"), b"binary").unwrap();
        let manifest = dir.path().join("manifest.json");
        generate(&source, &manifest, "xila.tool", "1.0.0", "wasm32-wasip1", 1).unwrap();
        let first = dir.path().join("first.app");
        let second = dir.path().join("second.app");
        build(&source, &manifest, &first, None).unwrap();
        build(&source, &manifest, &second, None).unwrap();
        let a = dir.path().join("first.xpk");
        let b = dir.path().join("second.xpk");
        archive(&first, &a).unwrap();
        archive(&second, &b).unwrap();
        assert_eq!(fs::read(a).unwrap(), fs::read(b).unwrap());
        assert!(
            xila_package_reader::inspect_unsigned(&fs::read(dir.path().join("first.xpk")).unwrap())
                .unwrap()
                .application
                .is_none()
        );
    }

    #[test]
    fn preserves_detached_signature_when_building_archive() {
        let dir = tempdir().unwrap();
        let (source, manifest, output) = prepare_application(dir.path());
        let sig_path = dir.path().join("manifest.sig");
        // Signature bytes are supplied by an external signer; the host builder
        // only validates their length and preserves them unchanged.
        fs::write(&sig_path, [42u8; 64]).unwrap();
        build(&source, &manifest, &output, Some(&sig_path)).unwrap();
        assert_eq!(fs::read(output.join(SIGNATURE_PATH)).unwrap(), [42u8; 64]);
        let archive_path = dir.path().join("Weather.xpk");
        archive(&output, &archive_path).unwrap();
        let bytes = fs::read(archive_path).unwrap();
        assert!(xila_package_reader::inspect_unsigned(&bytes).is_ok());
        assert!(bytes.windows(64).any(|window| window == [42u8; 64]));
    }

    #[test]
    fn never_publishes_partial_or_invalid_bundle() {
        let dir = tempdir().unwrap();
        let (source, manifest, output) = prepare_application(dir.path());
        fs::write(source.join("bin/weather.wasm"), b"changed").unwrap();
        assert!(build(&source, &manifest, &output, None).is_err());
        assert!(!output.exists());

        // An unlisted resource must never silently enter the bundle.
        fs::write(source.join("bin/weather.wasm"), b"wasm content").unwrap();
        fs::write(source.join("unexpected.txt"), b"extra").unwrap();
        assert!(build(&source, &manifest, &output, None).is_err());
        assert!(!output.exists());
        fs::remove_file(source.join("unexpected.txt")).unwrap();

        // Do not clobber any existing destination.
        fs::create_dir(&output).unwrap();
        fs::write(output.join("important"), b"keep").unwrap();
        assert!(build(&source, &manifest, &output, None).is_err());
        assert_eq!(fs::read(output.join("important")).unwrap(), b"keep");
    }

    #[test]
    fn rejects_nested_outputs_and_unexpected_bundle_metadata() {
        let dir = tempdir().unwrap();
        let (source, manifest, output) = prepare_application(dir.path());
        assert!(build(&source, &manifest, &source.join("nested.app"), None).is_err());
        build(&source, &manifest, &output, None).unwrap();

        fs::write(output.join(".xila/unknown"), b"extra").unwrap();
        assert!(archive(&output, &dir.path().join("bad.xpk")).is_err());
        fs::remove_file(output.join(".xila/unknown")).unwrap();

        assert!(archive(&output, &output.join("nested.xpk")).is_err());
        fs::write(output.join("payload.txt"), b"undeclared").unwrap();
        assert!(archive(&output, &dir.path().join("bad.xpk")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_source_symlinks() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let (source, manifest, output) = prepare_application(dir.path());
        symlink(source.join("bin/weather.wasm"), source.join("alias.wasm")).unwrap();
        assert!(build(&source, &manifest, &output, None).is_err());
        assert!(!output.exists());
    }
}
