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
                "--xila-version",
                "0.1"
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
    assert_eq!(
        contents.xila_version,
        xila_package_manifest::XilaVersion::new(0, 1)
    );
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
fn bundle_init_requires_a_valid_xila_version() {
    let temporary = tempdir().unwrap();
    let directory = temporary.path().join("source");
    let binary = env!("CARGO_BIN_EXE_xila-package");
    let initialize = |version_arguments: &[&str]| {
        Command::new(binary)
            .args([
                "bundle",
                "init",
                directory.to_str().unwrap(),
                "example.xila.example",
                "2.0.0",
                "wasm32-wasip1",
            ])
            .args(version_arguments)
            .output()
            .unwrap()
    };
    for arguments in [&[][..], &["--xila-version", "1.3.2"][..]] {
        let output = initialize(arguments);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("--xila-version"));
        assert!(!directory.exists());
    }
    let output = initialize(&["--xila-version", "1.3"]);
    assert!(output.status.success(), "{:?}", output.stderr);
    let manifest = fs::read(directory.join("xila-package.json")).unwrap();
    let manifest = xila_package_manifest::decode_developer(&manifest).unwrap();
    assert_eq!(
        manifest.xila_version,
        xila_package_manifest::XilaVersion::new(1, 3)
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
        "--xila-version",
        "0.1"
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
        include_bytes!("fixtures/package-workflow-developer.json"),
    )
    .unwrap();
    fs::write(
        source.join("shortcut.json"),
        include_bytes!("fixtures/package-workflow-shortcut.json"),
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
            r#"{"format_version":2,"name":"xila.clock","version":"0.1.0","target":"wasm32-wasip1","xila_version":"0.1","capabilities":[],"application":{"entrypoint":"executables/clock.wasm","display_name":"Clock","icon":"","show_in_launcher":true},"metadata":{"summary":"Shows the time","license":"Apache-2.0","source":"https://github.com/xila-project/applications","homepage":null}}"#,
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
        "xila",
        url,
        &path("entry.json")
    ]));
    let entry = fs::read_to_string(path("entry.json")).unwrap();
    assert!(entry.contains(r#""publisher":"xila""#), "{entry}");
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
        "xila",
        url,
        &path("other.json")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("dev.pub"),
        "xila",
        url,
        &path("entry.json")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("dev.pub"),
        "xila",
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
    let url = "https://xila.example/releases/xila.clock-0.1.0-wasm32-wasip1.xpk";

    assert!(run(&["key", "generate", &path("dev.seed"), &path("dev.pub")]).0);
    fs::create_dir_all(temp.path().join("src/executables")).unwrap();
    fs::write(temp.path().join("src/executables/clock.wasm"), b"clock").unwrap();
    fs::write(
        temp.path().join("src/xila-package.json"),
        r#"{"format_version":2,"name":"xila.clock","version":"0.1.0","target":"wasm32-wasip1","xila_version":"0.1","capabilities":[],"application":{"entrypoint":"executables/clock.wasm","display_name":"Clock","icon":"","show_in_launcher":true},"metadata":null}"#,
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
            r#"{{"id":"xila","author":"Xila Project","algorithm":"ed25519","public_key":"{}","openssh":null,"namespaces":[{namespaces}]}}"#,
            base64(&fs::read(path("dev.pub")).unwrap())
        )
    };
    let key_file = registry.join("keys/developers/xila.json");
    fs::write(&key_file, key(r#""xila""#)).unwrap();
    let entry_file = registry.join("packages/xila/clock/0.1.0.json");
    assert!(
        run(&[
            "registry",
            "entry",
            &archive,
            &path("dev.pub"),
            "xila",
            url,
            entry_file.to_str().unwrap()
        ])
        .0
    );
    let root = registry.to_str().unwrap();
    let archives = path("archives");

    assert!(run(&["registry", "check", root]).0);
    assert!(run(&["registry", "check", root, "--archives", &archives]).0);

    // A key without the legacy grant may not publish xila.<name>.
    fs::write(
        &key_file,
        key(r#""xila""#).replace(r#","namespaces":["xila"]"#, ""),
    )
    .unwrap();
    assert!(
        run(&["registry", "check", root])
            .1
            .contains("may not publish xila.clock")
    );
    // Key files grant no namespace other than the legacy one.
    fs::write(&key_file, key(r#""community""#)).unwrap();
    assert!(
        run(&["registry", "check", root])
            .1
            .contains("invalid developer key")
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
    fs::write(&entry_file, entry.replace("\"xila\"", "\"someone\"")).unwrap();
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

#[test]
fn registry_init_creates_a_registry_that_signs_and_verifies_end_to_end() {
    let temp = tempdir().unwrap();
    let cli = env!("CARGO_BIN_EXE_xila-package");
    let path = |name: &str| temp.path().join(name).to_str().unwrap().to_owned();
    let run = |items: &[&str]| {
        let output = Command::new(cli).args(items).output().unwrap();
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    };

    // Create the registry; private keys go outside it.
    let (success, stdout, stderr) = run(&["registry", "init", &path("registry"), &path("private")]);
    assert!(success, "{stderr}");
    assert!(stdout.contains(&path("private")), "{stdout}");
    for file in ["root.json", "root.json.sig", "root.pub"] {
        assert!(temp.path().join("registry").join(file).is_file(), "{file}");
    }
    assert!(temp.path().join("registry/keys/developers").is_dir());
    assert!(temp.path().join("registry/packages").is_dir());
    let root = fs::read_to_string(path("registry/root.json")).unwrap();
    let repository_public = fs::read(path("private/repository.pub")).unwrap();
    assert!(root.contains(&base64(&repository_public)), "{root}");
    assert!(root.contains(r#""id":"repository""#), "{root}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for seed in ["private/root.seed", "private/repository.seed"] {
            let mode = fs::metadata(path(seed)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "{seed}");
        }
    }

    // Refuse a non-empty registry and a key directory inside the registry.
    assert!(!run(&["registry", "init", &path("registry"), &path("other")]).0);
    assert!(
        run(&["registry", "init", &path("second"), &path("second/keys")])
            .2
            .contains("outside the registry")
    );

    // Add a developer key and one entry for a test package.
    assert!(run(&["key", "generate", &path("dev.seed"), &path("dev.pub")]).0);
    fs::write(
        path("registry/keys/developers/tester.json"),
        format!(
            r#"{{"id":"tester","author":"Tester","algorithm":"ed25519","public_key":"{}","openssh":null}}"#,
            base64(&fs::read(path("dev.pub")).unwrap())
        ),
    )
    .unwrap();
    fs::create_dir(temp.path().join("registry/namespaces")).unwrap();
    fs::write(
        path("registry/namespaces/example.xila.json"),
        r#"{"format_version":1,"namespace":"example.xila","owner":{"kind":"domain","name":"xila.example"},"developer_keys":["tester"]}"#,
    )
    .unwrap();
    fs::create_dir_all(temp.path().join("source/executables")).unwrap();
    fs::write(temp.path().join("source/executables/clock.wasm"), b"clock").unwrap();
    fs::write(
        path("source/xila-package.json"),
        r#"{"format_version":2,"name":"example.xila.clock","version":"0.1.0","target":"wasm32-wasip1","xila_version":"0.1","capabilities":[],"application":{"entrypoint":"executables/clock.wasm","display_name":"Clock","icon":"","show_in_launcher":true},"metadata":null}"#,
    )
    .unwrap();
    assert!(
        run(&[
            "bundle",
            "build",
            &path("source"),
            &path("Clock.app"),
            "--signing-key",
            &path("dev.seed")
        ])
        .0
    );
    assert!(run(&["bundle", "archive", &path("Clock.app"), &path("Clock.xpk")]).0);
    fs::create_dir_all(temp.path().join("registry/packages/example/xila/clock")).unwrap();
    let (success, _, stderr) = run(&[
        "registry",
        "entry",
        &path("Clock.xpk"),
        &path("dev.pub"),
        "tester",
        "https://xila.example/releases/Clock.xpk",
        &path("registry/packages/example/xila/clock/0.1.0.json"),
    ]);
    assert!(success, "{stderr}");

    // Sign the site and verify it from the pinned root key, as a device would.
    let (success, _, stderr) = run(&[
        "registry",
        "sign",
        &path("registry"),
        &path("registry/root.pub"),
        &path("private/repository.seed"),
        &path("site"),
    ]);
    assert!(success, "{stderr}");
    let (success, stdout, stderr) = run(&[
        "registry",
        "verify-signed",
        &path("site"),
        &path("registry/root.pub"),
    ]);
    assert!(success, "{stderr}");
    assert!(
        stdout.contains("1 developer key(s), 1 namespace(s), 1 entry"),
        "{stdout}"
    );

    // The root seed is not a repository key: signing with it must fail.
    assert!(
        !run(&[
            "registry",
            "sign",
            &path("registry"),
            &path("registry/root.pub"),
            &path("private/root.seed"),
            &path("site-wrong"),
        ])
        .0
    );
}
