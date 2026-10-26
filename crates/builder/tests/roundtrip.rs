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
    let bytes = fs::read(&archive).unwrap();
    let contents = xila_package_reader::inspect_unsigned(&bytes).unwrap();
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
        vec!["pack", "--help"],
    ] {
        let output = Command::new(binary).args(arguments).output().unwrap();
        assert!(output.status.success(), "{:?}", String::from_utf8_lossy(&output.stderr));
        assert!(!output.stdout.is_empty());
    }
    let output = Command::new(binary).args(["manifest", "generat"]).output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("generate"));
}
