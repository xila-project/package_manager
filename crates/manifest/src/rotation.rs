//! Package key pins and changes authorized by the preceding key.

use alloc::{format, string::String};
use miniserde::{Deserialize, Serialize};

use crate::{Error, decode_versioned, encode_public_key, public_key::decode_key, valid_identifier};

pub const ROTATION_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/registry-rotation.schema.json";
pub const ROTATION_FORMAT_VERSION: u32 = 1;
pub const ROTATION_DOMAIN: &[u8] = b"XILA-PACKAGE-KEY-ROTATION-V1\0";
pub const MAX_ROTATION_BYTES: usize = 1024;
/// Generation 1 is the first key. Each identifier allows 32 rotations.
pub const MAX_KEY_GENERATION: u32 = 33;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageKey {
    pub generation: u32,
    /// Canonical base64 of the raw Ed25519 public key.
    pub public_key: String,
}

impl PackageKey {
    pub fn new(generation: u32, public_key: &[u8; 32]) -> Result<Self, Error> {
        let key = Self {
            generation,
            public_key: encode_public_key(public_key),
        };
        key.validate()?;
        Ok(key)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if !(1..=MAX_KEY_GENERATION).contains(&self.generation) {
            return Err(Error::InvalidPackageKey);
        }
        self.public_key_bytes()?;
        Ok(())
    }

    pub fn public_key_bytes(&self) -> Result<[u8; 32], Error> {
        decode_key(&self.public_key).ok_or(Error::InvalidPackageKey)
    }
}

/// A rotation from generation `generation - 1` to `generation` for one identifier.
/// Its detached signature must come from `previous_key`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rotation {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    pub name: String,
    pub generation: u32,
    pub previous_key: String,
    pub new_key: String,
}

impl Rotation {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|schema| schema != ROTATION_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != ROTATION_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if !valid_identifier(&self.name)
            || !(2..=MAX_KEY_GENERATION).contains(&self.generation)
            || self.previous_key_bytes()?
                == decode_key(&self.new_key).ok_or(Error::InvalidRotation)?
        {
            return Err(Error::InvalidRotation);
        }
        Ok(())
    }

    /// Decode the key that must authorize this rotation.
    pub fn previous_key_bytes(&self) -> Result<[u8; 32], Error> {
        decode_key(&self.previous_key).ok_or(Error::InvalidRotation)
    }
}

/// Registry-relative path of the rotation to `generation`.
pub fn rotation_path(name: &str, generation: u32) -> String {
    format!("rotations/{}/{generation}.json", name.replace('.', "/"))
}

pub fn decode_rotation(bytes: &[u8]) -> Result<Rotation, Error> {
    if bytes.len() > MAX_ROTATION_BYTES {
        return Err(Error::TooLarge);
    }
    let rotation: Rotation = decode_versioned(bytes, ROTATION_FORMAT_VERSION)?;
    rotation.validate()?;
    Ok(rotation)
}

pub fn encode_rotation(rotation: &Rotation) -> Result<String, Error> {
    rotation.validate()?;
    Ok(miniserde::json::to_string(rotation))
}
