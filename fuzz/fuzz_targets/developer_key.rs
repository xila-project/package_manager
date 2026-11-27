#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest::{PackageKind, decode_developer_key};
use xila_package_verification::PublicKey;

// Developer-key list parsing (keys/developers/<id>.json), the canonical
// base64 key decoding behind it and the authorization predicates.
fuzz_target!(|data: &[u8]| {
    if let Ok(key) = decode_developer_key(data) {
        // Serializing and decoding again gives back the same key.
        let encoded = miniserde::json::to_string(&key);
        assert_eq!(
            decode_developer_key(encoded.as_bytes()).as_ref(),
            Ok(&key),
            "developer key round-trip mismatch"
        );
        // The decoded key material parses as a strict Ed25519 public key.
        let bytes = key.public_key_bytes().unwrap();
        let _ = PublicKey::from_bytes(&bytes);
        // Authorization predicates never panic.
        for name in [
            "xila.clock",
            "example.xila.weather",
            "example.xila.tools.clock",
            "",
        ] {
            let _ = key.authorizes(name, None);
            let _ = key.authorizes_package(name, "wasm32-wasip1", None);
            let _ = key.authorizes_package(name, "thumbv7em-none-eabi", None);
        }
        let _ = key.authorizes_kind(PackageKind::Wasm);
        let _ = key.authorizes_kind(PackageKind::Native);
    }
});
