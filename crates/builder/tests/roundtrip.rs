use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn command_generates_updates_and_packs() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("application");
    fs::create_dir_all(source.join("bin")).unwrap();
    fs::write(source.join("bin/calculator.wasm"), b"abc").unwrap();
    let manifest = temp.path().join("manifest.json");
    let archive = temp.path().join("calculator.xpk");
    let binary = env!("CARGO_BIN_EXE_xila-package");
    assert!(
        Command::new(binary)
            .args([
                "manifest",
                "generate",
                source.to_str().unwrap(),
                manifest.to_str().unwrap(),
                "xila.calculator",
                "1.0.0",
                "wasm32-wasip1",
                "1"
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(binary)
            .args([
                "manifest",
                "update",
                source.to_str().unwrap(),
                manifest.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(binary)
            .args([
                "pack",
                source.to_str().unwrap(),
                manifest.to_str().unwrap(),
                archive.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
    // A standalone binary is not automatically an application.
    let bytes = fs::read(&archive).unwrap();
    let contents = xila_package_reader::inspect_unsigned(&bytes).unwrap();
    assert!(contents.application.is_none());
    assert!(
        Command::new(binary)
            .args([
                "manifest",
                "application",
                manifest.to_str().unwrap(),
                "bin/calculator.wasm",
                "Calculator",
            ])
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new(binary)
            .args([
                "pack",
                source.to_str().unwrap(),
                manifest.to_str().unwrap(),
                archive.to_str().unwrap(),
            ])
            .status()
            .unwrap()
            .success()
    );
    let bytes = fs::read(&archive).unwrap();
    let contents = xila_package_reader::inspect_unsigned(&bytes).unwrap();
    let app = contents.application.as_ref().unwrap();
    assert_eq!(app.entrypoint, "bin/calculator.wasm");
    assert_eq!(app.display_name, "Calculator");
    assert!(app.show_in_launcher);
    assert_eq!(contents.name, "xila.calculator");
    assert_eq!(contents.files[0].path, "bin/calculator.wasm");
    let mutated = temp.path().join("mutated");
    fs::create_dir(&mutated).unwrap();
    fs::write(mutated.join("calculator.wasm"), b"modified").unwrap();
    assert!(
        !Command::new(binary)
            .args([
                "pack",
                mutated.to_str().unwrap(),
                manifest.to_str().unwrap(),
                archive.to_str().unwrap()
            ])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn supports_derived_help_and_version() {
    let binary = env!("CARGO_BIN_EXE_xila-package");
    for arguments in [
        vec!["--help"],
        vec!["--version"],
        vec!["manifest", "--help"],
        vec!["manifest", "generate", "--help"],
        vec!["manifest", "update", "--help"],
        vec!["manifest", "application", "--help"],
        vec!["pack", "--help"],
    ] {
        let output = Command::new(binary).args(arguments).output().unwrap();
        assert!(
            output.status.success(),
            "{:?}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty());
    }
    let output = Command::new(binary)
        .args(["manifest", "generat"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("generate"));
}

#[test]
fn external_signing_authenticates_manifest_and_payload() {
    use ed25519_dalek::{Signer, SigningKey};
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("bin")).unwrap();
    fs::write(source.join("bin/app.wasm"), b"wasm payload").unwrap();
    let manifest = temp.path().join("manifest.json");
    let payload = temp.path().join("payload.bin");
    let sig = temp.path().join("signature.bin");
    let key = temp.path().join("public.key");
    let archive = temp.path().join("app.xpk");
    let cli = env!("CARGO_BIN_EXE_xila-package");
    let args = |items: &[&str]| Command::new(cli).args(items).status().unwrap().success();
    assert!(args(&[
        "manifest",
        "generate",
        source.to_str().unwrap(),
        manifest.to_str().unwrap(),
        "xila.test",
        "1.0.0",
        "wasm32-wasip1",
        "1"
    ]));
    assert!(args(&[
        "manifest",
        "signing-payload",
        manifest.to_str().unwrap(),
        payload.to_str().unwrap()
    ]));
    let mut noncanonical = fs::read(&manifest).unwrap();
    noncanonical.push(b' ');
    let noncanonical_path = temp.path().join("noncanonical.json");
    fs::write(&noncanonical_path, noncanonical).unwrap();
    assert!(!args(&[
        "manifest",
        "signing-payload",
        noncanonical_path.to_str().unwrap(),
        temp.path().join("bad-payload").to_str().unwrap()
    ]));
    let signer = SigningKey::from_bytes(&[42; 32]);
    fs::write(&sig, signer.sign(&fs::read(&payload).unwrap()).to_bytes()).unwrap();
    fs::write(&key, signer.verifying_key().to_bytes()).unwrap();
    assert!(args(&[
        "pack",
        source.to_str().unwrap(),
        manifest.to_str().unwrap(),
        archive.to_str().unwrap(),
        sig.to_str().unwrap()
    ]));
    assert!(args(&[
        "verify",
        archive.to_str().unwrap(),
        key.to_str().unwrap()
    ]));
    let wrong = temp.path().join("wrong.key");
    fs::write(
        &wrong,
        SigningKey::from_bytes(&[43; 32]).verifying_key().to_bytes(),
    )
    .unwrap();
    assert!(!args(&[
        "verify",
        archive.to_str().unwrap(),
        wrong.to_str().unwrap()
    ]));
    let mut corrupted = fs::read(&archive).unwrap();
    let index = corrupted
        .windows(b"wasm payload".len())
        .position(|bytes| bytes == b"wasm payload")
        .unwrap();
    corrupted[index] ^= 1;
    fs::write(&archive, corrupted).unwrap();
    assert!(!args(&[
        "verify",
        archive.to_str().unwrap(),
        key.to_str().unwrap()
    ]));
}

#[test]
fn externally_signed_developer_bundle_authenticates_shortcut() {
    use ed25519_dalek::{Signer, SigningKey};
    let temp = tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(source.join("bin")).unwrap();
    fs::write(source.join("bin/example.wasm"), b"wasm payload").unwrap();
    fs::write(
        source.join("xila-package.json"),
        include_bytes!("../../../tests/fixtures/package-workflow-developer.json"),
    )
    .unwrap();
    fs::write(
        source.join("shortcut.json"),
        include_bytes!("../../../tests/fixtures/package-workflow-shortcut.json"),
    )
    .unwrap();
    let bundle = temp.path().join("bundle.app");
    let payload = temp.path().join("payload.bin");
    let sig = temp.path().join("signature.bin");
    let key = temp.path().join("public.key");
    let archive = temp.path().join("app.xpk");
    let cli = env!("CARGO_BIN_EXE_xila-package");
    let args = |items: &[&str]| Command::new(cli).args(items).status().unwrap().success();
    assert!(args(&[
        "bundle",
        "build",
        source.to_str().unwrap(),
        bundle.to_str().unwrap()
    ]));
    let manifest = bundle.join(".xila/manifest.json");
    assert!(args(&[
        "manifest",
        "signing-payload",
        manifest.to_str().unwrap(),
        payload.to_str().unwrap()
    ]));
    let signer = SigningKey::from_bytes(&[42; 32]);
    fs::write(&sig, signer.sign(&fs::read(&payload).unwrap()).to_bytes()).unwrap();
    fs::write(&key, signer.verifying_key().to_bytes()).unwrap();
    assert!(args(&[
        "pack",
        source.to_str().unwrap(),
        manifest.to_str().unwrap(),
        archive.to_str().unwrap(),
        sig.to_str().unwrap()
    ]));
    assert!(args(&[
        "verify",
        archive.to_str().unwrap(),
        key.to_str().unwrap()
    ]));
    let mut tampered = fs::read(&archive).unwrap();
    let needle = b"@bundle/bin/example.wasm";
    let index = tampered
        .windows(needle.len())
        .position(|b| b == needle)
        .unwrap();
    tampered[index] ^= 1;
    fs::write(&archive, tampered).unwrap();
    assert!(!args(&[
        "verify",
        archive.to_str().unwrap(),
        key.to_str().unwrap()
    ]));
}
