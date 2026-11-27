#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use xila_package_reader::{
    StreamingVerifier, extract_streaming, inspect_streaming, inspect_unsigned, verify_signed,
};
use xila_package_verification::PublicKey;

// A valid trusted key used by the signed-reader paths of this target.
fn trusted_key() -> &'static PublicKey {
    static KEY: OnceLock<PublicKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]);
        PublicKey::from_bytes(&signing.verifying_key().to_bytes()).unwrap()
    })
}

// Archive / container reading: the in-memory TAR reader and the block-wise
// streaming verifier, unsigned and signed, on the same bytes.
fuzz_target!(|data: &[u8]| {
    let key = trusted_key();

    let _ = inspect_unsigned(data);
    let _ = verify_signed(data, key);

    // Streaming verifier over every complete 512-byte block.
    let blocks = data.as_chunks::<512>().0;
    let mut unsigned = StreamingVerifier::new(None);
    for block in blocks {
        let _ = unsigned.push(block);
    }
    let _ = unsigned.finish();

    let mut signed = StreamingVerifier::new(Some(key));
    for block in blocks {
        let _ = signed.extract(block);
    }
    let _ = signed.finish();

    // The same bytes zero-padded to a whole number of blocks (a partial
    // trailing block then reads as a TAR terminator).
    let mut padded = data.to_vec();
    padded.resize(padded.len().div_ceil(512) * 512, 0);
    let _ = inspect_unsigned(&padded);
    let mut padded_verifier = StreamingVerifier::new(None);
    for block in padded.as_chunks::<512>().0 {
        let _ = padded_verifier.push(block);
    }
    let _ = padded_verifier.finish();

    // Whole-stream helpers fed from a closure, signed and unsigned.
    let mut position = 0;
    let _ = inspect_streaming::<_, ()>(
        |buffer| match data.as_chunks::<512>().0.get(position) {
            Some(block) => {
                buffer.copy_from_slice(block);
                position += 1;
                Ok(true)
            }
            None => Ok(false),
        },
        None,
    );
    let mut position = 0;
    let _ = extract_streaming::<_, _, ()>(
        |buffer| match data.as_chunks::<512>().0.get(position) {
            Some(block) => {
                buffer.copy_from_slice(block);
                position += 1;
                Ok(true)
            }
            None => Ok(false),
        },
        Some(key),
        |_, chunk| {
            let _ = chunk.bytes.len();
            Ok(())
        },
    );
});
