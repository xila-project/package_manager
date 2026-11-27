#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;
use xila_package_manifest::{decode_origin, decode_repository};

// Repository configuration and installed-package origin parsing, with
// round-trips and URL joining.
fuzz_target!(|data: &[u8]| {
    if let Ok(repository) = decode_repository(data) {
        if let Ok(encoded) = manifest::encode_repository(&repository) {
            assert_eq!(
                decode_repository(encoded.as_bytes()).as_ref(),
                Ok(&repository),
                "repository round-trip mismatch"
            );
        }
        let _ = repository.file_url("root.json");
        let _ = repository.root_key_bytes();
    }
    if let Ok(origin) = decode_origin(data) {
        if let Ok(encoded) = manifest::encode_origin(&origin) {
            assert_eq!(
                decode_origin(encoded.as_bytes()).as_ref(),
                Ok(&origin),
                "origin round-trip mismatch"
            );
        }
    }
});
