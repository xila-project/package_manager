#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;
use xila_package_manifest::decode_root;
use xila_package_verification::PublicKey;

// root.json parsing and its round-trip, including the base64 key decoding of
// every listed key.
fuzz_target!(|data: &[u8]| {
    if let Ok(root) = decode_root(data) {
        if let Ok(encoded) = manifest::encode_root(&root) {
            assert_eq!(
                decode_root(encoded.as_bytes()).as_ref(),
                Ok(&root),
                "root round-trip mismatch"
            );
        }
        for key in root.root_keys.iter().chain(&root.repository_keys) {
            if let Ok(bytes) = key.public_key_bytes() {
                let _ = PublicKey::from_bytes(&bytes);
            }
        }
        // Domain-separated signed messages stay bounded.
        assert!(manifest::signed_message(manifest::ROOT_DOMAIN, data).is_ok());
    }
});
