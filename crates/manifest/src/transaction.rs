//! Device-side installation transaction journal.
//!
//! The journal records one package operation that changes the installed set
//! (install, upgrade or removal) before its first visible step, and is removed
//! after its last. After an interruption it tells recovery what was in flight,
//! so the device can finish or undo the operation instead of guessing from
//! left-over directories. Every directory it names is a single path component
//! inside the bundles directory, so a malformed journal cannot designate an
//! arbitrary path.

use alloc::string::String;
use miniserde::{Deserialize, Serialize};

use crate::{Error, MAX_MANIFEST_BYTES, Origin, valid_identifier};

pub const TRANSACTION_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/package-transaction.schema.json";
pub const TRANSACTION_FORMAT_VERSION: u32 = 2;

/// Prefix of a verified, sealed bundle waiting to be activated.
pub const STAGING_PREFIX: &str = ".incoming-";
/// Prefix of the bundle being replaced by an upgrade.
pub const PREVIOUS_PREFIX: &str = ".previous-";
/// Prefix of the bundle being removed.
pub const REMOVING_PREFIX: &str = ".removing-";
/// Prefix of a downloaded archive waiting to be verified.
pub const DOWNLOAD_PREFIX: &str = ".download-";

/// What a transaction does.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    #[serde(rename = "install")]
    Install,
    #[serde(rename = "upgrade")]
    Upgrade,
    #[serde(rename = "remove")]
    Remove,
}

/// One in-flight installation transaction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    pub operation: Operation,
    /// Package identifier; also the bundle directory name.
    pub name: String,
    /// Verified, sealed staging directory (install and upgrade).
    pub staging: Option<String>,
    /// Where the installed bundle is moved aside (upgrade and removal).
    pub previous: Option<String>,
    /// Origin recorded once the new bundle is active (install and upgrade).
    pub origin: Option<Origin>,
    /// Origin of the replaced or removed bundle, restored on rollback.
    pub previous_origin: Option<Origin>,
}

/// Whether `name` is a single path component starting with `prefix`.
pub fn is_temporary_name(name: &str, prefix: &str) -> bool {
    name.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty()
            && suffix.len() <= 128
            && suffix
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    })
}

/// Whether `name` is any temporary entry of the bundles directory.
pub fn is_temporary_entry(name: &str) -> bool {
    [
        STAGING_PREFIX,
        PREVIOUS_PREFIX,
        REMOVING_PREFIX,
        DOWNLOAD_PREFIX,
    ]
    .iter()
    .any(|prefix| is_temporary_name(name, prefix))
}

impl Transaction {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != TRANSACTION_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != TRANSACTION_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if !valid_identifier(&self.name) {
            return Err(Error::InvalidIdentifier);
        }
        for origin in [&self.origin, &self.previous_origin].into_iter().flatten() {
            origin.validate()?;
            if origin.name != self.name {
                return Err(Error::InvalidTransaction);
            }
        }
        let staging = self
            .staging
            .as_deref()
            .map(|name| is_temporary_name(name, STAGING_PREFIX));
        let previous = |prefix| {
            self.previous
                .as_deref()
                .map(|name| is_temporary_name(name, prefix))
        };
        let valid = match self.operation {
            Operation::Install => {
                staging == Some(true)
                    && self.previous.is_none()
                    && self.origin.is_some()
                    && self.previous_origin.is_none()
            }
            Operation::Upgrade => {
                staging == Some(true)
                    && previous(PREVIOUS_PREFIX) == Some(true)
                    && self.origin.is_some()
            }
            Operation::Remove => {
                staging.is_none()
                    && previous(REMOVING_PREFIX) == Some(true)
                    && self.origin.is_none()
            }
        };
        if !valid {
            return Err(Error::InvalidTransaction);
        }
        Ok(())
    }
}

pub fn decode_transaction(bytes: &[u8]) -> Result<Transaction, Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    crate::check_nesting_depth(source)?;
    let transaction: Transaction =
        miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)?;
    transaction.validate()?;
    Ok(transaction)
}

pub fn encode_transaction(transaction: &Transaction) -> Result<String, Error> {
    transaction.validate()?;
    Ok(miniserde::json::to_string(transaction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ORIGIN_FORMAT_VERSION, ORIGIN_SCHEMA_URL};
    use alloc::format;

    fn origin(version: &str) -> Origin {
        Origin {
            schema: Some(ORIGIN_SCHEMA_URL.into()),
            format_version: ORIGIN_FORMAT_VERSION,
            repository: Some("xila".into()),
            name: "dev.xila.clock".into(),
            version: version.into(),
            archive_sha256: "6976f8d118066b7294ac051160505b2c410fa9213cffa6a7c889946cf6fdbfcd"
                .into(),
            package_key: Some(crate::PackageKey {
                generation: 1,
                public_key: "6D1cvlGzCAITQrmkWjJgn97DW1s6p3zvDNe8a87pcbc=".into(),
            }),
        }
    }

    fn upgrade() -> Transaction {
        Transaction {
            schema: Some(TRANSACTION_SCHEMA_URL.into()),
            format_version: TRANSACTION_FORMAT_VERSION,
            operation: Operation::Upgrade,
            name: "dev.xila.clock".into(),
            staging: Some(format!("{STAGING_PREFIX}1")),
            previous: Some(format!("{PREVIOUS_PREFIX}dev.xila.clock")),
            origin: Some(origin("0.2.0")),
            previous_origin: Some(origin("0.1.0")),
        }
    }

    #[test]
    fn decodes_the_schema_fixture() {
        let fixture = include_bytes!("../../../tests/fixtures/package-transaction.json");
        let decoded = decode_transaction(fixture.trim_ascii_end()).unwrap();
        assert_eq!(decoded, upgrade());
    }

    #[test]
    fn transaction_round_trips() {
        let transaction = upgrade();
        let encoded = encode_transaction(&transaction).unwrap();
        assert!(encoded.contains(r#""operation":"upgrade""#), "{encoded}");
        assert_eq!(decode_transaction(encoded.as_bytes()).unwrap(), transaction);
    }

    #[test]
    fn rejects_paths_outside_the_bundles_directory() {
        for name in [
            "../system",
            ".incoming-",
            ".incoming-a/b",
            "bundle",
            ".previous-1",
        ] {
            let mut transaction = upgrade();
            transaction.staging = Some(name.into());
            assert_eq!(transaction.validate(), Err(Error::InvalidTransaction));
        }
        let mut transaction = upgrade();
        transaction.previous = Some("/applications/bundles/dev.xila.clock".into());
        assert_eq!(transaction.validate(), Err(Error::InvalidTransaction));
    }

    #[test]
    fn fields_must_match_the_operation() {
        let mut transaction = upgrade();
        transaction.operation = Operation::Install;
        assert_eq!(transaction.validate(), Err(Error::InvalidTransaction));
        let mut transaction = upgrade();
        transaction.origin.as_mut().unwrap().name = "dev.xila.other".into();
        assert_eq!(transaction.validate(), Err(Error::InvalidTransaction));
        let removal = Transaction {
            operation: Operation::Remove,
            staging: None,
            previous: Some(format!("{REMOVING_PREFIX}dev.xila.clock")),
            origin: None,
            ..upgrade()
        };
        assert!(removal.validate().is_ok());
        assert!(decode_transaction(b"{}").is_err());
    }

    #[test]
    fn recognizes_temporary_entries() {
        assert!(is_temporary_entry(".incoming-1f"));
        assert!(is_temporary_entry(".download-3.xpk"));
        assert!(is_temporary_entry(".previous-dev.xila.clock"));
        assert!(!is_temporary_entry("dev.xila.clock"));
        assert!(!is_temporary_entry(".hidden"));
        assert!(!is_temporary_entry(".incoming-"));
    }
}
