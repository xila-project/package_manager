#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;

// Registry entry parsing and its round-trip.
fuzz_target!(|data: &[u8]| {
    if let Ok(entry) = manifest::decode_registry_entry(data) {
        if let Ok(encoded) = manifest::encode_registry_entry(&entry) {
            assert_eq!(
                manifest::decode_registry_entry(encoded.as_bytes()).as_ref(),
                Ok(&entry),
                "registry entry round-trip mismatch"
            );
        }
    }
});
