#![no_main]

use libfuzzer_sys::fuzz_target;
use xila_package_manifest as manifest;
use xila_package_verification::PublicKey;

// Signature and key decoding: strict Ed25519 public-key parsing and
// verification, plus strict fixed-width SHA-256 decoding on byte slices.
fuzz_target!(|data: &[u8]| {
    if data.len() >= 96 {
        let (key, rest) = data.split_at(32);
        let (signature, message) = rest.split_at(64);
        if let Ok(public) = PublicKey::from_slice(key) {
            let _ = public.verify_slice(message, signature);
            let signature: &[u8; 64] = signature.try_into().unwrap();
            let _ = public.verify(message, signature);
        }
        let key: &[u8; 32] = key.try_into().unwrap();
        let _ = PublicKey::from_bytes(key);
    }

    // Decode every bounded byte window that is valid UTF-8 as a digest.
    for start in 0..data.len().min(96) {
        for length in 0..=64 {
            let end = start + length;
            if end > data.len() {
                break;
            }
            if let Ok(text) = core::str::from_utf8(&data[start..end]) {
                let _ = manifest::decode_sha256(text);
            }
        }
    }
});
