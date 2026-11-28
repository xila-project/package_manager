//! Canonical Ed25519 public key encoding for package and registry metadata.

use alloc::string::String;

/// Encode 32 raw public key bytes as canonical base64.
pub fn encode_public_key(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(44);
    for chunk in bytes.chunks(3) {
        let mut block = [0u8; 3];
        block[..chunk.len()].copy_from_slice(chunk);
        let value = u32::from_be_bytes([0, block[0], block[1], block[2]]);
        for index in 0..4 {
            output.push(if index <= chunk.len() {
                ALPHABET[(value >> (18 - 6 * index) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    output
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode the canonical 44-character base64 form of 32 bytes.
pub(crate) fn decode_key(encoded: &str) -> Option<[u8; 32]> {
    let bytes = encoded.as_bytes();
    if bytes.len() != 44 || bytes[43] != b'=' {
        return None;
    }
    let mut output = [0u8; 33];
    for (chunk, out) in bytes[..44].chunks(4).zip(output.chunks_mut(3)) {
        let mut accumulator = 0u32;
        for (index, &byte) in chunk.iter().enumerate() {
            let value = if byte == b'=' && index == 3 {
                0
            } else {
                base64_value(byte)?
            };
            accumulator = (accumulator << 6) | u32::from(value);
        }
        out.copy_from_slice(&accumulator.to_be_bytes()[1..]);
    }
    // Reject non-canonical encodings: the unused low bits must be zero.
    if base64_value(bytes[42])? & 0b11 != 0 || output[32] != 0 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&output[..32]);
    Some(key)
}
