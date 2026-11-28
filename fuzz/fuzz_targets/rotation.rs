#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest::{decode_rotation, encode_rotation};

fuzz_target!(|data: &[u8]| {
    if let Ok(rotation) = decode_rotation(data) {
        let encoded = encode_rotation(&rotation).unwrap();
        assert_eq!(decode_rotation(encoded.as_bytes()).as_ref(), Ok(&rotation));
    }
});
