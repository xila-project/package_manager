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
                "dev.xila.calculator",
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
    assert_eq!(contents.name, "dev.xila.calculator");
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
        "dev.xila.test",
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
    let url = "https://github.com/xila-project/applications/releases/download/dev.xila.clock-v0.1.0/dev.xila.clock-0.1.0-wasm32-wasip1.xpk";

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
            r#"{"format_version":2,"name":"dev.xila.clock","version":"0.1.0","target":"wasm32-wasip1","xila_version":"0.1","capabilities":[],"application":{"entrypoint":"executables/clock.wasm","display_name":"Clock","icon":"","show_in_launcher":true},"metadata":{"summary":"Shows the time","license":"Apache-2.0","source":"https://github.com/xila-project/applications","homepage":null}}"#,
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
        url,
        &path("entry.json")
    ]));
    let entry = fs::read_to_string(path("entry.json")).unwrap();
    assert!(
        entry.contains(r#""package_key":{"generation":1,"public_key":"#),
        "{entry}"
    );
    assert!(entry.contains(r#""summary":"Shows the time""#), "{entry}");
    assert!(entry.contains(r#""display_name":"Clock""#), "{entry}");
    assert!(run(&[
        "registry",
        "verify",
        &path("entry.json"),
        &path("source.xpk")
    ]));

    let mut foreign_pin = xila_package_manifest::decode_registry_entry(entry.as_bytes()).unwrap();
    let foreign_key = fs::read(path("other.pub")).unwrap().try_into().unwrap();
    foreign_pin.package_key = xila_package_manifest::PackageKey::new(1, &foreign_key).unwrap();
    fs::write(
        path("foreign.json"),
        xila_package_manifest::encode_registry_entry(&foreign_pin).unwrap(),
    )
    .unwrap();
    assert!(!run(&[
        "registry",
        "verify",
        &path("foreign.json"),
        &path("source.xpk")
    ]));

    // A different archive, a different signer, or overwriting must all fail.
    assert!(!run(&[
        "registry",
        "verify",
        &path("entry.json"),
        &path("changed.xpk")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("other.pub"),
        url,
        &path("other.json")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("dev.pub"),
        url,
        &path("entry.json")
    ]));
    assert!(!run(&[
        "registry",
        "entry",
        &path("source.xpk"),
        &path("dev.pub"),
        "http://insecure",
        &path("insecure.json")
    ]));
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
    let url = "https://xila.example/releases/dev.xila.clock-0.1.0-wasm32-wasip1.xpk";

    assert!(run(&["key", "generate", &path("dev.seed"), &path("dev.pub")]).0);
    fs::create_dir_all(temp.path().join("src/executables")).unwrap();
    fs::write(temp.path().join("src/executables/clock.wasm"), b"clock").unwrap();
    fs::write(
        temp.path().join("src/xila-package.json"),
        r#"{"format_version":2,"name":"dev.xila.clock","version":"0.1.0","target":"wasm32-wasip1","xila_version":"0.1","capabilities":[],"application":{"entrypoint":"executables/clock.wasm","display_name":"Clock","icon":"","show_in_launcher":true},"metadata":null}"#,
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
    let archive = path("archives/dev.xila.clock-0.1.0-wasm32-wasip1.xpk");
    assert!(run(&["bundle", "archive", &path("Clock.app"), &archive]).0);

    let registry = temp.path().join("registry");
    fs::create_dir_all(registry.join("packages/dev/xila/clock")).unwrap();
    let entry_file = registry.join("packages/dev/xila/clock/0.1.0.json");
    assert!(
        run(&[
            "registry",
            "entry",
            &archive,
            &path("dev.pub"),
            url,
            entry_file.to_str().unwrap()
        ])
        .0
    );
    let root = registry.to_str().unwrap();
    let archives = path("archives");

    assert!(run(&["registry", "check", root]).0);
    assert!(run(&["registry", "check", root, "--archives", &archives]).0);

    let entry = fs::read_to_string(&entry_file).unwrap();
    fs::create_dir_all(registry.join("packages/dev/xila/other")).unwrap();
    fs::rename(
        &entry_file,
        registry.join("packages/dev/xila/other/0.1.0.json"),
    )
    .unwrap();
    assert!(
        run(&["registry", "check", root])
            .1
            .contains("not at its own path")
    );
    fs::remove_dir_all(registry.join("packages/dev/xila/other")).unwrap();
    fs::write(&entry_file, format!("{entry}\n")).unwrap();
    assert!(
        run(&["registry", "check", root])
            .1
            .contains("not canonical")
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
    assert!(temp.path().join("registry/rotations").is_dir());
    assert!(temp.path().join("registry/packages").is_dir());
    let root = fs::read_to_string(path("registry/root.json")).unwrap();
    let repository_public = fs::read(path("private/repository.pub"))
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        root.contains(&xila_package_manifest::encode_public_key(
            &repository_public
        )),
        "{root}"
    );
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

    // Add one entry for a test package with its own key.
    assert!(run(&["key", "generate", &path("dev.seed"), &path("dev.pub")]).0);
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
        stdout.contains("1 package entries and key rotations"),
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

#[test]
fn registry_init_validates_before_creating_and_cleans_up_on_failure() {
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
    #[cfg(unix)]
    let mode = |name: &str| {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path(name)).unwrap().permissions().mode() & 0o777
    };

    // A key directory inside the registry is refused before anything is
    // created, so the retry with a valid key directory succeeds.
    let (success, _, stderr) = run(&[
        "registry",
        "init",
        &path("registry"),
        &path("registry/keys"),
    ]);
    assert!(!success);
    assert!(stderr.contains("outside the registry"), "{stderr}");
    assert!(!temp.path().join("registry").exists());
    assert!(run(&["registry", "init", &path("registry"), &path("private")]).0);

    // An existing key directory keeps its permissions: a directory that is not
    // 0700 is refused untouched, and no registry is created.
    fs::create_dir(path("loose")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path("loose"), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let (success, _, stderr) = run(&["registry", "init", &path("other"), &path("loose")]);
    assert!(!success);
    assert!(stderr.contains("0700"), "{stderr}");
    #[cfg(unix)]
    assert_eq!(mode("loose"), 0o755);
    assert!(!temp.path().join("other").exists());

    // An existing non-empty key directory is refused even at 0700.
    fs::create_dir(path("full")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path("full"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(path("full/existing.seed"), b"seed").unwrap();
    let (success, _, stderr) = run(&["registry", "init", &path("third"), &path("full")]);
    assert!(!success);
    assert!(stderr.contains("not empty"), "{stderr}");
    assert!(!temp.path().join("third").exists());

    // An existing empty 0700 key directory is used as it is.
    fs::create_dir(path("keys")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path("keys"), fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(run(&["registry", "init", &path("third"), &path("keys")]).0);
    #[cfg(unix)]
    assert_eq!(mode("keys"), 0o700);
    assert!(temp.path().join("keys/root.seed").is_file());
    assert!(temp.path().join("third/root.json").is_file());

    // A `..` after a missing component is resolved, not dropped:
    // a/other/../reg/keys is a/reg/keys, inside the registry a/reg, so the
    // run is refused and nothing is created.
    fs::create_dir(path("a")).unwrap();
    let (success, _, stderr) = run(&[
        "registry",
        "init",
        &path("a/reg"),
        &path("a/other/../reg/keys"),
    ]);
    assert!(!success);
    assert!(stderr.contains("outside the registry"), "{stderr}");
    assert!(!temp.path().join("a/other").exists());
    assert!(!temp.path().join("a/reg").exists());

    // A failure after the keys were generated (an invalid root id fails when
    // root.json is written) removes everything this run created.
    let (success, _, stderr) = run(&[
        "registry",
        "init",
        &path("fourth"),
        &path("private2"),
        "--root-id",
        "Not A Valid Id",
    ]);
    assert!(!success);
    assert!(stderr.contains("invalid root"), "{stderr}");
    assert!(!temp.path().join("fourth").exists());
    assert!(!temp.path().join("private2").exists());

    // A pre-existing empty registry directory is left in place, still empty,
    // when a later step fails; only the key directory this run made is gone.
    fs::create_dir(path("kept")).unwrap();
    let (success, _, stderr) = run(&[
        "registry",
        "init",
        &path("kept"),
        &path("private3"),
        "--root-id",
        "Not A Valid Id",
    ]);
    assert!(!success);
    assert!(stderr.contains("invalid root"), "{stderr}");
    assert!(temp.path().join("kept").is_dir());
    assert!(fs::read_dir(path("kept")).unwrap().next().is_none());
    assert!(!temp.path().join("private3").exists());

    // Relative paths are resolved against the working directory.
    let output = Command::new(cli)
        .args(["registry", "init", "relative", "relative-keys"])
        .current_dir(temp.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(temp.path().join("relative/root.json").is_file());
    assert!(temp.path().join("relative-keys/root.seed").is_file());
}

#[test]
fn registry_publication_checks_ownership_and_key_rotations() {
    use xila_package_manifest::{
        PackageKey, RegistryEntry, decode_registry_entry, encode_registry_entry,
    };

    let temporary = tempdir().unwrap();
    let path = |name: &str| temporary.path().join(name).to_str().unwrap().to_owned();
    let run = |arguments: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_xila-package"))
            .args(arguments)
            .output()
            .unwrap()
    };
    let succeeds = |arguments: &[&str]| {
        let output = run(arguments);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    let rejects = |arguments: &[&str], message: &str| {
        let output = run(arguments);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success() && stderr.contains(message),
            "{stderr}"
        );
    };

    succeeds(&["registry", "init", &path("registry"), &path("private")]);
    for key in ["first", "second", "third"] {
        succeeds(&[
            "key",
            "generate",
            &path(&format!("{key}.seed")),
            &path(&format!("{key}.pub")),
        ]);
    }

    let package = "packages/dev/xila/clock";
    let rotations = "rotations/dev/xila/clock";
    for directory in [
        format!("registry/{package}"),
        format!("previous/{package}"),
        format!("previous/{rotations}"),
        format!("registry/{rotations}"),
    ] {
        fs::create_dir_all(path(&directory)).unwrap();
    }
    let first_path = path(&format!("registry/{package}/0.1.0.json"));
    let later_path = path(&format!("registry/{package}/0.2.0.json"));
    let second_path = path(&format!("registry/{package}/0.3.0.json"));
    let third_path = path(&format!("registry/{package}/0.4.0.json"));
    let second_rotation = path(&format!("registry/{rotations}/2.json"));
    let third_rotation = path(&format!("registry/{rotations}/3.json"));

    let mut entry = decode_registry_entry(include_bytes!(
        "../../../tests/fixtures/registry-entry.json"
    ))
    .unwrap();
    let pin = |generation, key| {
        let bytes = fs::read(path(&format!("{key}.pub")))
            .unwrap()
            .try_into()
            .unwrap();
        PackageKey::new(generation, &bytes).unwrap()
    };
    let write = |entry: &RegistryEntry, destination: &str| {
        fs::write(destination, encode_registry_entry(entry).unwrap()).unwrap()
    };
    entry.package_key = pin(1, "first");
    write(&entry, &first_path);

    let claim = path("claim.json");
    fs::write(&claim, r#"{"format_version":2,"namespace":"dev.xila","owner":{"kind":"domain","name":"xila.dev"}}"#).unwrap();
    succeeds(&["registry", "check-owner", &first_path, &claim]);
    fs::write(&claim, r#"{"format_version":2,"namespace":"example.xila","owner":{"kind":"domain","name":"xila.example"}}"#).unwrap();
    rejects(
        &["registry", "check-owner", &first_path, &claim],
        "exact namespace",
    );
    succeeds(&["registry", "check", &path("registry")]);

    entry.version = "0.2.0".into();
    entry.package_key = pin(1, "second");
    write(&entry, &later_path);
    rejects(
        &["registry", "check", &path("registry")],
        "does not use the pinned package key",
    );
    entry.package_key = pin(1, "first");
    write(&entry, &later_path);
    succeeds(&["registry", "check", &path("registry")]);
    for version in ["0.1.0", "0.2.0"] {
        fs::copy(
            path(&format!("registry/{package}/{version}.json")),
            path(&format!("previous/{package}/{version}.json")),
        )
        .unwrap();
    }

    succeeds(&[
        "registry",
        "rotate",
        "dev.xila.clock",
        "2",
        &path("first.seed"),
        &path("second.pub"),
        &second_rotation,
    ]);
    entry.version = "0.3.0".into();
    write(&entry, &second_path);
    rejects(
        &[
            "registry",
            "check",
            &path("registry"),
            "--previous",
            &path("previous"),
        ],
        "current package key",
    );

    entry.package_key = pin(2, "second");
    write(&entry, &second_path);
    succeeds(&[
        "registry",
        "check-rotation",
        &path("registry"),
        &first_path,
        &second_path,
    ]);
    let signature_path = format!("{second_rotation}.sig");
    let signature = fs::read(&signature_path).unwrap();
    let record = fs::read(&second_rotation).unwrap();
    fs::remove_file(&second_rotation).unwrap();
    rejects(
        &["registry", "check", &path("registry")],
        "rotation signature has no record",
    );
    fs::write(&second_rotation, record).unwrap();

    fs::remove_file(&signature_path).unwrap();
    rejects(
        &["registry", "check", &path("registry")],
        "rotation signature is missing",
    );
    fs::write(&signature_path, []).unwrap();
    rejects(
        &["registry", "check", &path("registry")],
        "rotation signature must be 64 bytes",
    );
    fs::write(&signature_path, [0; 64]).unwrap();
    rejects(
        &["registry", "check", &path("registry")],
        "signature not made by a trusted key",
    );
    fs::write(&signature_path, signature).unwrap();
    fs::copy(
        &second_rotation,
        path(&format!("previous/{rotations}/2.json")),
    )
    .unwrap();
    fs::copy(
        &signature_path,
        path(&format!("previous/{rotations}/2.json.sig")),
    )
    .unwrap();

    succeeds(&[
        "registry",
        "rotate",
        "dev.xila.clock",
        "3",
        &path("second.seed"),
        &path("first.pub"),
        &third_rotation,
    ]);
    rejects(
        &["registry", "check", &path("registry")],
        "package key already used by dev.xila.clock",
    );
    fs::remove_file(&third_rotation).unwrap();
    fs::remove_file(format!("{third_rotation}.sig")).unwrap();

    let mut other = entry.clone();
    other.name = "dev.xila.weather".into();
    other.package_key = pin(1, "second");
    let other_path = path("registry/packages/dev/xila/weather/0.3.0.json");
    fs::create_dir_all(path("registry/packages/dev/xila/weather")).unwrap();
    write(&other, &other_path);
    rejects(
        &["registry", "check", &path("registry")],
        "package key already used by dev.xila.clock",
    );
    fs::remove_file(other_path).unwrap();

    succeeds(&[
        "registry",
        "rotate",
        "dev.xila.clock",
        "3",
        &path("second.seed"),
        &path("third.pub"),
        &third_rotation,
    ]);
    entry.version = "0.4.0".into();
    entry.package_key = pin(3, "third");
    write(&entry, &third_path);
    succeeds(&[
        "registry",
        "check-rotation",
        &path("registry"),
        &first_path,
        &third_path,
    ]);
    fs::copy(
        &second_path,
        path(&format!("previous/{package}/0.3.0.json")),
    )
    .unwrap();
    succeeds(&[
        "registry",
        "check",
        &path("registry"),
        "--previous",
        &path("previous"),
    ]);

    succeeds(&[
        "registry",
        "sign",
        &path("registry"),
        &path("registry/root.pub"),
        &path("private/repository.seed"),
        &path("site"),
    ]);
    succeeds(&[
        "registry",
        "verify-signed",
        &path("site"),
        &path("registry/root.pub"),
    ]);
    let published_signature = path(&format!("site/{rotations}/2.json.sig"));
    assert_eq!(
        fs::read(&published_signature).unwrap(),
        fs::read(&signature_path).unwrap()
    );
    let published_rotation = path(&format!("site/{rotations}/2.json"));
    let original = fs::read(&published_rotation).unwrap();
    fs::write(&published_rotation, vec![b'['; original.len()]).unwrap();
    rejects(
        &[
            "registry",
            "verify-signed",
            &path("site"),
            &path("registry/root.pub"),
        ],
        "file is not listed in the index with this hash",
    );
    fs::write(&published_rotation, original).unwrap();
    fs::write(&published_signature, [0; 64]).unwrap();
    rejects(
        &[
            "registry",
            "verify-signed",
            &path("site"),
            &path("registry/root.pub"),
        ],
        "signature not made by a trusted key",
    );
}
