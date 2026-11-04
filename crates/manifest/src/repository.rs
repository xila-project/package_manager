//! Device-side repository configuration and installed-package origin.
//!
//! A device may use several registries. Each is configured with the root key
//! the user chose to trust (pinned out of band, or accepted on first use after
//! checking its fingerprint) and the highest metadata versions accepted, so a
//! repository can never roll back. Every installed package records the
//! repository it came from: updates only come from that repository, so adding
//! another one cannot replace an installed package.

use alloc::{string::String, vec::Vec};
use miniserde::{Deserialize, Serialize};

use crate::{
    Error, MAX_MANIFEST_BYTES, developer_key::decode_key, metadata::is_https_url,
    registry::valid_publisher, trust::valid_digest,
};

pub const REPOSITORY_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/repository.schema.json";
pub const ORIGIN_SCHEMA_URL: &str = "https://raw.githubusercontent.com/xila-project/package_manager/main/schemas/package-origin.schema.json";
pub const REPOSITORY_FORMAT_VERSION: u32 = 1;

/// One configured registry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Repository {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    /// Local name, e.g. `xila`; also the configuration file name.
    pub name: String,
    /// HTTPS base URL without a trailing slash, e.g. `https://registry.xila.dev`.
    pub url: String,
    /// Root key trusted for this repository (canonical base64).
    pub root_key: String,
    /// Highest `root.json` version accepted (0 before the first sync).
    pub root_version: u64,
    /// Highest `index.json` version accepted (0 before the first sync).
    pub index_version: u64,
}

impl Repository {
    pub fn new(name: &str, url: &str, root_key: &str) -> Result<Self, Error> {
        let repository = Self {
            schema: Some(REPOSITORY_SCHEMA_URL.into()),
            format_version: REPOSITORY_FORMAT_VERSION,
            name: name.into(),
            url: url.into(),
            root_key: root_key.into(),
            root_version: 0,
            index_version: 0,
        };
        repository.validate()?;
        Ok(repository)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != REPOSITORY_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != REPOSITORY_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        if !valid_publisher(&self.name)
            || !is_https_url(&self.url)
            || self.url.ends_with('/')
            || decode_key(&self.root_key).is_none()
        {
            return Err(Error::InvalidRepository);
        }
        Ok(())
    }

    pub fn root_key_bytes(&self) -> Result<[u8; 32], Error> {
        decode_key(&self.root_key).ok_or(Error::InvalidRepository)
    }

    /// Absolute URL of a registry-relative `path`.
    pub fn file_url(&self, path: &str) -> String {
        let mut url = String::with_capacity(self.url.len() + 1 + path.len());
        url.push_str(&self.url);
        url.push('/');
        url.push_str(path);
        url
    }
}

/// Where an installed package came from.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Origin {
    #[serde(rename = "$schema")]
    pub schema: Option<String>,
    pub format_version: u32,
    /// Name of the configured repository; `None` for a local archive.
    pub repository: Option<String>,
    pub name: String,
    pub version: String,
    /// SHA-256 of the installed archive.
    pub archive_sha256: String,
}

impl Origin {
    pub fn validate(&self) -> Result<(), Error> {
        if self
            .schema
            .as_deref()
            .is_some_and(|url| url != ORIGIN_SCHEMA_URL)
        {
            return Err(Error::InvalidSchema);
        }
        if self.format_version != REPOSITORY_FORMAT_VERSION {
            return Err(Error::UnsupportedVersion);
        }
        crate::validate_identity(&self.name, &self.version, "origin")?;
        if self
            .repository
            .as_deref()
            .is_some_and(|name| !valid_publisher(name))
            || !valid_digest(&self.archive_sha256)
        {
            return Err(Error::InvalidRepository);
        }
        Ok(())
    }
}

fn decode<T: miniserde::Deserialize>(bytes: &[u8]) -> Result<T, Error> {
    if bytes.len() > MAX_MANIFEST_BYTES {
        return Err(Error::TooLarge);
    }
    let source = core::str::from_utf8(bytes).map_err(|_| Error::InvalidJson)?;
    miniserde::json::from_str(source).map_err(|_| Error::InvalidJson)
}

pub fn decode_repository(bytes: &[u8]) -> Result<Repository, Error> {
    let repository: Repository = decode(bytes)?;
    repository.validate()?;
    Ok(repository)
}

pub fn encode_repository(repository: &Repository) -> Result<String, Error> {
    repository.validate()?;
    Ok(miniserde::json::to_string(repository))
}

pub fn decode_origin(bytes: &[u8]) -> Result<Origin, Error> {
    let origin: Origin = decode(bytes)?;
    origin.validate()?;
    Ok(origin)
}

pub fn encode_origin(origin: &Origin) -> Result<String, Error> {
    origin.validate()?;
    Ok(miniserde::json::to_string(origin))
}

/// A `MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]` version, for ordering only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticVersion<'a> {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub prerelease: Option<&'a str>,
}

impl<'a> SemanticVersion<'a> {
    pub fn parse(version: &'a str) -> Option<Self> {
        let version = version.split_once('+').map_or(version, |(core, _)| core);
        let (core, prerelease) = match version.split_once('-') {
            Some((core, prerelease)) if !prerelease.is_empty() => (core, Some(prerelease)),
            Some(_) => return None,
            None => (version, None),
        };
        let mut parts = core.split('.');
        let mut number = || {
            let part = parts.next()?;
            (!part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part == "0" || !part.starts_with('0')))
            .then(|| part.parse().ok())
            .flatten()
        };
        let parsed = Self {
            major: number()?,
            minor: number()?,
            patch: number()?,
            prerelease,
        };
        parts.next().is_none().then_some(parsed)
    }
}

impl Ord for SemanticVersion<'_> {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        use core::cmp::Ordering;
        (self.major, self.minor, self.patch)
            .cmp(&(other.major, other.minor, other.patch))
            .then_with(|| match (self.prerelease, other.prerelease) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => {
                    let mut a = a.split('.');
                    let mut b = b.split('.');
                    loop {
                        match (a.next(), b.next()) {
                            (None, None) => return Ordering::Equal,
                            (None, Some(_)) => return Ordering::Less,
                            (Some(_), None) => return Ordering::Greater,
                            (Some(x), Some(y)) => {
                                let numeric = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
                                let order = match (numeric(x), numeric(y)) {
                                    (true, true) => x.len().cmp(&y.len()).then_with(|| x.cmp(y)),
                                    (true, false) => Ordering::Less,
                                    (false, true) => Ordering::Greater,
                                    (false, false) => x.cmp(y),
                                };
                                if order != Ordering::Equal {
                                    return order;
                                }
                            }
                        }
                    }
                }
            })
    }
}

impl PartialOrd for SemanticVersion<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Versions of `name` listed in `index`, newest first. Only semantic versions
/// are listed, and prereleases only when `prereleases` is set; other versions
/// can still be installed by exact version.
pub fn index_versions<'a>(index: &'a crate::Index, name: &str, prereleases: bool) -> Vec<&'a str> {
    let mut prefix = String::from("packages/");
    for label in name.split('.') {
        prefix.push_str(label);
        prefix.push('/');
    }
    let mut versions: Vec<(SemanticVersion<'a>, &'a str)> = index
        .files
        .iter()
        .filter_map(|file| {
            let version = file
                .path
                .strip_prefix(prefix.as_str())?
                .strip_suffix(".json")?;
            if version.contains('/') {
                return None;
            }
            let parsed = SemanticVersion::parse(version)?;
            (prereleases || parsed.prerelease.is_none()).then_some((parsed, version))
        })
        .collect();
    versions.sort_by(|a, b| b.0.cmp(&a.0));
    versions.into_iter().map(|(_, version)| version).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{INDEX_SCHEMA_URL, Index, IndexFile, TRUST_FORMAT_VERSION};
    use alloc::vec;

    const KEY: &str = "AJEDFQ2MPtUO0vu/BnC7xX5Ag8sBuq6DF5+ShKfCQgU=";

    #[test]
    fn repository_round_trips_and_validates() {
        let repository = Repository::new("xila", "https://registry.xila.dev", KEY).unwrap();
        let decoded =
            decode_repository(encode_repository(&repository).unwrap().as_bytes()).unwrap();
        assert_eq!(decoded, repository);
        assert_eq!(
            repository.file_url("root.json"),
            "https://registry.xila.dev/root.json"
        );
        for (name, url, key) in [
            ("Xila", "https://registry.xila.dev", KEY),
            ("xila", "http://registry.xila.dev", KEY),
            ("xila", "https://registry.xila.dev/", KEY),
            ("xila", "https://registry.xila.dev", "AAAA"),
        ] {
            assert_eq!(
                Repository::new(name, url, key).err(),
                Some(Error::InvalidRepository)
            );
        }
    }

    #[test]
    fn origin_round_trips() {
        let origin = Origin {
            schema: Some(ORIGIN_SCHEMA_URL.into()),
            format_version: REPOSITORY_FORMAT_VERSION,
            repository: Some("xila".into()),
            name: "xila.clock".into(),
            version: "0.1.0".into(),
            archive_sha256: "a".repeat(64),
        };
        assert_eq!(
            decode_origin(encode_origin(&origin).unwrap().as_bytes()).unwrap(),
            origin
        );
        let mut local = origin.clone();
        local.repository = None;
        assert!(local.validate().is_ok());
        local.archive_sha256 = "x".into();
        assert_eq!(local.validate(), Err(Error::InvalidRepository));
    }

    #[test]
    fn semantic_versions_order_like_semver() {
        let ordered = [
            "0.9.0",
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "1.0.1",
            "1.10.0",
        ];
        for pair in ordered.windows(2) {
            assert!(
                SemanticVersion::parse(pair[0]).unwrap() < SemanticVersion::parse(pair[1]).unwrap(),
                "{} < {}",
                pair[0],
                pair[1]
            );
        }
        assert_eq!(
            SemanticVersion::parse("1.0.0+build.5"),
            SemanticVersion::parse("1.0.0")
        );
        for invalid in ["1.0", "1.0.0.0", "01.0.0", "1.0.0-", "v1.0.0", "1..0"] {
            assert!(SemanticVersion::parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn lists_versions_newest_first() {
        let file = |path: &str| IndexFile {
            path: path.into(),
            sha256: "a".repeat(64),
            size: 1,
        };
        let mut files = vec![
            file("packages/xila/clock/0.1.0.json"),
            file("packages/xila/clock/0.10.0.json"),
            file("packages/xila/clock/0.2.0.json"),
            file("packages/xila/clock/1.0.0-rc.1.json"),
            file("packages/xila/clock/nightly.json"),
            file("packages/xila/clock/extra/1.0.0.json"),
            file("packages/xila/clockwork/9.0.0.json"),
        ];
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let index = Index {
            schema: Some(INDEX_SCHEMA_URL.into()),
            format_version: TRUST_FORMAT_VERSION,
            version: 1,
            expires: 2,
            files,
        };
        assert_eq!(
            index_versions(&index, "xila.clock", false),
            ["0.10.0", "0.2.0", "0.1.0"]
        );
        assert_eq!(
            index_versions(&index, "xila.clock", true),
            ["1.0.0-rc.1", "0.10.0", "0.2.0", "0.1.0"]
        );
        assert!(index_versions(&index, "xila.weather", true).is_empty());
    }
}
