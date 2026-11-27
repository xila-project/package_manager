#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;

// Manifest parsing: decode (bounded miniserde JSON plus structural
// validation) and the encode -> decode round-trip.
fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = manifest::decode(data) {
        // A decoded manifest re-encodes and decodes to the same value.
        if let Ok(encoded) = manifest::encode(&parsed) {
            assert_eq!(
                manifest::decode(encoded.as_bytes()).as_ref(),
                Ok(&parsed),
                "manifest round-trip mismatch"
            );
        }
        // Building the signed message from the exact stored bytes never
        // fails on input that decoded successfully.
        let mut buffer =
            vec![0_u8; manifest::SIGNED_DOMAIN.len() + 4 + manifest::MAX_MANIFEST_BYTES];
        assert!(
            manifest::signed_message_into(data, &mut buffer).is_ok(),
            "signed message construction failed on a decoded manifest"
        );
    }
});
