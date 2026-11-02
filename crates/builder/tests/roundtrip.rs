use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn command_generates_updates_and_packs() {
    let temp = tempdir().unwrap();
    let source = temp.path().join("application");
    fs::create_dir_all(source.join("executables")).unwrap();
    fs::write(source.join("executables/calculator.wasm"), b"abc").unwrap();
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
                "executables/calculator.wasm",
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
    assert_eq!(app.entrypoint, "executables/calculator.wasm");
    assert_eq!(app.display_name, "Calculator");
    assert!(app.show_in_launcher);
    assert_eq!(contents.name, "xila.calculator");
    assert_eq!(contents.files[0].path, "executables/calculator.wasm");
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
    fs::create_dir_all(source.join("executables")).unwrap();
    fs::write(source.join("executables/app.wasm"), b"wasm payload").unwrap();
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
    fs::create_dir_all(source.join("executables")).unwrap();
    fs::write(source.join("executables/example.wasm"), b"wasm payload").unwrap();
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
    let needle = b"@bundle/executables/example.wasm";
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

#[test]
fn key_commands_generate_and_derive_the_same_public_key() {
    let temp = tempdir().unwrap();
    let binary = env!("CARGO_BIN_EXE_xila-package");
    let path = |name: &str| temp.path().join(name).to_str().unwrap().to_owned();
    let run = |arguments: &[&str]| Command::new(binary).args(arguments).output().unwrap();

    assert!(
        run(&["key", "generate", &path("dev.seed"), &path("dev.pub")])
            .status
            .success()
    );
    assert!(
        run(&["key", "public", &path("dev.seed"), &path("derived.pub")])
            .status
            .success()
    );
    assert_eq!(
        fs::read(path("dev.pub")).unwrap(),
        fs::read(path("derived.pub")).unwrap()
    );

    let refused = run(&["key", "generate", &path("dev.seed"), &path("other.pub")]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("already exists"));
}

#[test]
fn registry_entry_is_generated_from_and_checked_against_a_signed_bundle() {
    let temp = tempdir().unwrap();
    let cli = env!("CARGO_BIN_EXE_xila-package");
    let path = |name: &str| temp.path().join(name).to_str().unwrap().to_owned();
    let run = |items: &[&str]| Command::new(cli).args(items).status().unwrap().success();
    let url = "https://github.com/xila-project/applications/releases/download/xila.clock-v0.1.0/xila.clock-0.1.0-wasm32-wasip1.xpk";

    assert!(run(&[
        "key",
        "generate",
        &path("dev.seed"),
        &path("dev.pub")
    ]));
    assert!(run(&[
        "key",
        "generate",
        &path("other.seed"),
        &path("other.pub")
    ]));
    for (source, payload) in [("source", &b"clock"[..]), ("changed", &b"clock v2"[..])] {
        fs::create_dir_all(temp.path().join(source).join("executables")).unwrap();
        fs::write(
            temp.path().join(source).join("executables/clock.wasm"),
            payload,
        )
        .unwrap();
        fs::write(
            temp.path().join(source).join("xila-package.json"),
            r#"{"format_version":1,"name":"xila.clock","version":"0.1.0","target":"wasm32-wasip1","minimum_xila_abi":1,"capabilities":[],"application":{"entrypoint":"executables/clock.wasm","display_name":"Clock","icon":"","show_in_launcher":true},"metadata":{"summary":"Shows the time","license":"Apache-2.0","source":"https://github.com/xila-project/applications","homepage":null}}"#,
        )
        .unwrap();
        let bundle = path(&format!("{source}.app"));
        assert!(run(&[
            "bundle",
            "build",
            &path(source),
            &bundle,
            "--signing-key",
            &path("dev.seed")
        ]));
        assert!(run(&[
            "bundle",
            "archive",
            &bundle,
            &path(&format!("{source}.xpk"))
        ]));
    }

    assert!(run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("dev.pub"),
        "xila-project",
        url,
        &path("entry.json")
    ]));
    let entry = fs::read_to_string(path("entry.json")).unwrap();
    assert!(entry.contains(r#""publisher":"xila-project""#), "{entry}");
    assert!(entry.contains(r#""summary":"Shows the time""#), "{entry}");
    assert!(entry.contains(r#""display_name":"Clock""#), "{entry}");
    assert!(run(&[
        "registry",
        "verify",
        &path("entry.json"),
        &path("source.xpk"),
        &path("dev.pub")
    ]));

    // A different archive, a different signer, or overwriting must all fail.
    assert!(!run(&[
        "registry",
        "verify",
        &path("entry.json"),
        &path("changed.xpk"),
        &path("dev.pub")
    ]));
    assert!(!run(&[
        "registry",
        "verify",
        &path("entry.json"),
        &path("source.xpk"),
        &path("other.pub")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("other.pub"),
        "xila-project",
        url,
        &path("other.json")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("dev.pub"),
        "xila-project",
        url,
        &path("entry.json")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("dev.pub"),
        "xila-project",
        "http://insecure",
        &path("insecure.json")
    ]));
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let value =
            chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for index in 0..4 {
            output.push(if index <= chunk.len() {
                TABLE[((value >> (18 - 6 * index)) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    output
}

#[test]
fn registry_check_validates_keys_placement_and_archives() {
    let temp = tempdir().unwrap();
    let cli = env!("CARGO_BIN_EXE_xila-package");
    let path = |name: &str| temp.path().join(name).to_str().unwrap().to_owned();
    let run = |items: &[&str]| {
        let output = Command::new(cli).args(items).output().unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };
    let url = "https://example.com/releases/xila.clock-0.1.0-wasm32-wasip1.xpk";

    assert!(run(&["key", "generate", &path("dev.seed"), &path("dev.pub")]).0);
    fs::create_dir_all(temp.path().join("src/executables")).unwrap();
    fs::write(temp.path().join("src/executables/clock.wasm"), b"clock").unwrap();
    fs::write(
        temp.path().join("src/xila-package.json"),
        r#"{"format_version":1,"name":"xila.clock","version":"0.1.0","target":"wasm32-wasip1","minimum_xila_abi":1,"capabilities":[],"application":{"entrypoint":"executables/clock.wasm","display_name":"Clock","icon":"","show_in_launcher":true},"metadata":null}"#,
    )
    .unwrap();
    assert!(
        run(&[
            "bundle",
            "build",
            &path("src"),
            &path("Clock.app"),
            "--signing-key",
            &path("dev.seed")
        ])
        .0
    );
    fs::create_dir(temp.path().join("archives")).unwrap();
    let archive = path("archives/xila.clock-0.1.0-wasm32-wasip1.xpk");
    assert!(run(&["bundle", "archive", &path("Clock.app"), &archive]).0);

    let registry = temp.path().join("registry");
    fs::create_dir_all(registry.join("keys/developers")).unwrap();
    fs::create_dir_all(registry.join("packages/xila/clock")).unwrap();
    let key = |namespaces: &str| {
        format!(
            r#"{{"id":"xila-project","author":"Xila Project","algorithm":"ed25519","public_key":"{}","openssh":null,"namespaces":[{namespaces}]}}"#,
            base64(&fs::read(path("dev.pub")).unwrap())
        )
    };
    let key_file = registry.join("keys/developers/xila-project.json");
    fs::write(&key_file, key(r#""xila""#)).unwrap();
    let entry_file = registry.join("packages/xila/clock/0.1.0.json");
    assert!(
        run(&[
            "registry",
            "entry",
            &archive,
            &path("dev.pub"),
            "xila-project",
            url,
            entry_file.to_str().unwrap()
        ])
        .0
    );
    let root = registry.to_str().unwrap();
    let archives = path("archives");

    assert!(run(&["registry", "check", root]).0);
    assert!(run(&["registry", "check", root, "--archives", &archives]).0);

    // A key that does not cover the namespace.
    fs::write(&key_file, key(r#""community""#)).unwrap();
    assert!(
        run(&["registry", "check", root])
            .1
            .contains("may not publish xila.clock")
    );
    fs::write(&key_file, key(r#""xila""#)).unwrap();

    // Misplaced, non-canonical and unknown-publisher entries.
    let entry = fs::read_to_string(&entry_file).unwrap();
    fs::create_dir_all(registry.join("packages/xila/other")).unwrap();
    fs::rename(&entry_file, registry.join("packages/xila/other/0.1.0.json")).unwrap();
    assert!(run(&["registry", "check", root]).1.contains("must be at"));
    fs::remove_dir_all(registry.join("packages/xila/other")).unwrap();
    fs::write(&entry_file, format!("{entry}\n")).unwrap();
    assert!(
        run(&["registry", "check", root])
            .1
            .contains("not canonical")
    );
    fs::write(
        &entry_file,
        entry.replace("\"xila-project\"", "\"someone\""),
    )
    .unwrap();
    assert!(
        run(&["registry", "check", root])
            .1
            .contains("unknown publisher someone")
    );
    fs::write(&entry_file, &entry).unwrap();

    // A tampered archive.
    let mut bytes = fs::read(&archive).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    fs::write(&archive, bytes).unwrap();
    assert!(
        run(&["registry", "check", root, "--archives", &archives])
            .1
            .contains("differs")
    );
}
