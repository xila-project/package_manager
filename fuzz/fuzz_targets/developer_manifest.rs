#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;

// Developer manifest parsing (xila-package.json) and its round-trip.
fuzz_target!(|data: &[u8]| {
    if let Ok(parsed) = manifest::decode_developer(data) {
        if let Ok(encoded) = manifest::encode_developer(&parsed) {
            assert_eq!(
                manifest::decode_developer(encoded.as_bytes()).as_ref(),
                Ok(&parsed),
                "developer manifest round-trip mismatch"
            );
        }
    }
});
