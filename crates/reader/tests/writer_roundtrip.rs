use xila_package_manifest::{Manifest, ManifestFile};
use xila_package_writer::{SourceFile, write_package};

fn fixture() -> Manifest {
    Manifest {
        schema: Some(xila_package_manifest::SCHEMA_URL.into()),
        format_version: xila_package_manifest::FORMAT_VERSION,
        name: "dev.xila.calculator".into(),
        version: "1.0.0".into(),
        target: "wasm32-wasip1".into(),
        xila_version: xila_package_manifest::XilaVersion::new(0, 1),
        capabilities: vec![],
        files: vec![ManifestFile {
            path: "executables/calculator.wasm".into(),
            size: 3,
            sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
        }],
        application: None,
        metadata: None,
    }
}

#[test]
fn round_trip_between_writer_and_reader() {
    let mut output = vec![];
    let file = SourceFile {
        path: "executables/calculator.wasm",
        bytes: b"abc",
    };
    write_package(&mut output, &fixture(), &[file], None).unwrap();
    let inspected = xila_package_reader::inspect_unsigned(&output).unwrap();
    assert_eq!(inspected, fixture());
    let offset = output
        .windows(3)
        .position(|window| window == b"abc")
        .unwrap();
    output[offset] ^= 1;
    assert!(xila_package_reader::inspect_unsigned(&output).is_err());
}
