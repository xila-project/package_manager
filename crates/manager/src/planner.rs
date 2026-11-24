//! Bounded, deterministic dependency planner.
//!
//! [`plan`] turns install requests into an ordered list of [`Step`]s for the
//! local installer: dependencies come before the packages that need them, and
//! packages that are already installed and still suitable are left alone. It
//! reads authenticated [`RegistryEntry`] values through a [`Catalog`] and keeps
//! only the selected entries in memory.
//!
//! The planner is deliberately not a solver:
//!
//! - one version per package name;
//! - versions are tried in catalog order (newest first for [`IndexCatalog`]),
//!   and the first [`trust::compatible`] version that satisfies every
//!   requirement known *at that point* is selected;
//! - a selection is never revisited: a later requirement that the selected
//!   version does not satisfy is reported as [`Error::Conflict`] instead of
//!   searched for;
//! - dependency cycles are rejected ([`Error::Cycle`]), since no installation
//!   order exists for them;
//! - [`Limits`] cap the number of packages, fetched entries, dependencies per
//!   package and dependency depth, and exceeding one fails with
//!   [`Error::Limit`].
//!
//! The same inputs (catalog contents, requests and installed packages, in the
//! same order) always give the same plan or the same error.
//!
//! The planner changes nothing. For each step the caller downloads
//! `step.entry.archive`, checks its size and SHA-256, obtains the publisher key
//! with [`trust::publisher_key`] and hands the archive to the local installer.

use alloc::{
    collections::{BTreeMap, VecDeque},
    string::String,
    vec::Vec,
};
use core::{cmp::Ordering, fmt, str::FromStr};

use xila_package_manifest::{Index, RegistryEntry, SemanticVersion, XilaVersion, index_versions};

use crate::trust::{self, TrustedRoot};

/// Which versions of a package satisfy a dependency.
///
/// The text form is `*`, `=VERSION`, `>=VERSION` or `^VERSION`. Only `=`
/// accepts a prerelease or a version that is not semantic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionRequirement {
    /// Any release (`*`). Prereleases are excluded.
    Any,
    /// Exactly this version (`=1.2.3`).
    Exact(String),
    /// This release or a later one (`>=1.2.3`). Prereleases are excluded.
    AtLeast(String),
    /// A release compatible with this one (`^1.2.3`), as Cargo defines it:
    /// `>=1.2.3, <2.0.0`; `^0.2.3` means `>=0.2.3, <0.3.0` and `^0.0.3`
    /// means `=0.0.3`. Prereleases are excluded.
    Compatible(String),
}

/// A string is not a valid [`VersionRequirement`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidRequirement;

impl fmt::Display for InvalidRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("expected *, =VERSION, >=VERSION or ^VERSION")
    }
}

impl core::error::Error for InvalidRequirement {}

impl FromStr for VersionRequirement {
    type Err = InvalidRequirement;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let semantic = |version: &str| -> Result<String, InvalidRequirement> {
            match SemanticVersion::parse(version) {
                Some(parsed) if parsed.prerelease.is_none() => Ok(version.into()),
                _ => Err(InvalidRequirement),
            }
        };
        if value == "*" {
            Ok(Self::Any)
        } else if let Some(version) = value.strip_prefix(">=") {
            semantic(version).map(Self::AtLeast)
        } else if let Some(version) = value.strip_prefix('^') {
            semantic(version).map(Self::Compatible)
        } else if let Some(version) = value.strip_prefix('=') {
            let valid = !version.is_empty()
                && version.len() <= 64
                && version
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".+-".contains(&byte));
            valid
                .then(|| Self::Exact(version.into()))
                .ok_or(InvalidRequirement)
        } else {
            Err(InvalidRequirement)
        }
    }
}

impl fmt::Display for VersionRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => formatter.write_str("*"),
            Self::Exact(version) => write!(formatter, "={version}"),
            Self::AtLeast(version) => write!(formatter, ">={version}"),
            Self::Compatible(version) => write!(formatter, "^{version}"),
        }
    }
}

impl VersionRequirement {
    /// Whether `version` satisfies this requirement.
    pub fn matches(&self, version: &str) -> bool {
        let release =
            || SemanticVersion::parse(version).filter(|version| version.prerelease.is_none());
        match self {
            Self::Any => release().is_some(),
            Self::Exact(expected) => {
                expected == version
                    || matches!(
                        (SemanticVersion::parse(expected), SemanticVersion::parse(version)),
                        (Some(a), Some(b)) if a == b
                    )
            }
            Self::AtLeast(minimum) => match (release(), SemanticVersion::parse(minimum)) {
                (Some(version), Some(minimum)) => version >= minimum,
                _ => false,
            },
            Self::Compatible(base) => match (release(), SemanticVersion::parse(base)) {
                (Some(version), Some(base)) => {
                    version >= base
                        && version.major == base.major
                        && match (base.major, base.minor) {
                            (0, 0) => version.minor == 0 && version.patch == base.patch,
                            (0, minor) => version.minor == minor,
                            _ => true,
                        }
                }
                _ => false,
            },
        }
    }
}

/// A package name with the versions that satisfy it: an install request or
/// a package's dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub requirement: VersionRequirement,
}

impl Dependency {
    pub fn new(name: &str, requirement: VersionRequirement) -> Self {
        Self {
            name: name.into(),
            requirement,
        }
    }
}

/// One installable version: an authenticated registry entry and the
/// dependencies its signed metadata declares.
#[derive(Clone, Debug, PartialEq)]
pub struct Candidate {
    pub entry: RegistryEntry,
    pub dependencies: Vec<Dependency>,
}

/// A package recorded in the installer's database.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Installed {
    pub name: String,
    pub version: String,
    /// The dependencies it declared when it was installed.
    pub dependencies: Vec<Dependency>,
}

/// Where the planner finds installable versions.
pub trait Catalog {
    type Error;

    /// Versions of `name` to consider, in order of preference (normally
    /// newest first). An unknown package has no versions.
    fn versions(&mut self, name: &str) -> Result<Vec<String>, Self::Error>;

    /// The authenticated candidate for `name` at `version`. The planner
    /// checks that the entry's name and version are the ones it asked for.
    fn candidate(&mut self, name: &str, version: &str) -> Result<Candidate, Self::Error>;
}

/// Work and memory limits. Every plan stays within them or fails with
/// [`Error::Limit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Distinct packages considered, including installed ones that are kept.
    pub packages: usize,
    /// Candidates fetched from the catalog, in total.
    pub fetches: usize,
    /// Dependencies declared by one package.
    pub dependencies: usize,
    /// Dependency depth below a request (a request has depth 0).
    pub depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            packages: 32,
            fetches: 128,
            dependencies: 16,
            depth: 8,
        }
    }
}

/// The limit that a plan exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    Packages,
    Fetches,
    Dependencies,
    Depth,
}

/// The device the plan is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Environment<'a> {
    /// Target of the device, compared with [`RegistryEntry::target`].
    pub target: &'a str,
    /// Running Xila release, checked with [`trust::compatible`].
    pub xila_version: XilaVersion,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Options {
    pub limits: Limits,
    /// Move requested packages (not their dependencies) to the preferred
    /// suitable version even when the installed one is still suitable.
    pub upgrade: bool,
    /// Accept steps that replace an installed version with an older one.
    pub allow_downgrade: bool,
}

/// What a step does to the device.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Install,
    Upgrade { from: String },
    Downgrade { from: String },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Step {
    pub action: Action,
    /// The authenticated entry describing the archive to install.
    pub entry: RegistryEntry,
    pub dependencies: Vec<Dependency>,
}

/// Steps in installation order: each package after its dependencies.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Plan {
    pub steps: Vec<Step>,
}

/// Why no plan was produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error<E> {
    /// The catalog failed, for example an entry was not authentic.
    Catalog(E),
    /// The catalog has no version of the package.
    Missing {
        name: String,
    },
    /// No version is built for this target and running Xila release.
    Incompatible {
        name: String,
    },
    /// Compatible versions exist, but none satisfies every requirement.
    Unsatisfiable {
        name: String,
    },
    /// `version` was already selected for `name`, and `required_by` (a
    /// package, or `None` for a request) needs a version it does not satisfy.
    Conflict {
        name: String,
        version: String,
        required_by: Option<String>,
    },
    /// These packages depend on each other in a loop; the first is repeated
    /// at the end.
    Cycle {
        packages: Vec<String>,
    },
    /// Satisfying the plan requires an older version than the installed one.
    Downgrade {
        name: String,
        installed: String,
        candidate: String,
    },
    /// The catalog answered with an entry for another package or version.
    Substituted {
        name: String,
        version: String,
    },
    /// The installed package list names a package twice.
    DuplicateInstalled {
        name: String,
    },
    Limit(Limit),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => write!(formatter, "catalog error: {error}"),
            Self::Missing { name } => write!(formatter, "package {name} was not found"),
            Self::Incompatible { name } => write!(
                formatter,
                "no version of {name} is built for this target and Xila release"
            ),
            Self::Unsatisfiable { name } => write!(
                formatter,
                "no compatible version of {name} satisfies every requirement"
            ),
            Self::Conflict {
                name,
                version,
                required_by,
            } => match required_by {
                Some(package) => write!(
                    formatter,
                    "{package} needs a version of {name} other than the selected {version}"
                ),
                None => write!(
                    formatter,
                    "the request needs a version of {name} other than the selected {version}"
                ),
            },
            Self::Cycle { packages } => {
                formatter.write_str("dependency cycle: ")?;
                for (index, package) in packages.iter().enumerate() {
                    if index > 0 {
                        formatter.write_str(" -> ")?;
                    }
                    formatter.write_str(package)?;
                }
                Ok(())
            }
            Self::Downgrade {
                name,
                installed,
                candidate,
            } => write!(
                formatter,
                "{name} would be downgraded from {installed} to {candidate}"
            ),
            Self::Substituted { name, version } => write!(
                formatter,
                "the catalog returned another package for {name} {version}"
            ),
            Self::DuplicateInstalled { name } => {
                write!(formatter, "{name} is listed as installed twice")
            }
            Self::Limit(limit) => write!(formatter, "the plan exceeds the {limit:?} limit"),
        }
    }
}

struct Selection {
    version: String,
    dependencies: Vec<Dependency>,
    /// `None` when the installed version is kept.
    step: Option<(Action, RegistryEntry)>,
}

struct Planner<'a, C> {
    catalog: &'a mut C,
    environment: &'a Environment<'a>,
    options: &'a Options,
    installed: BTreeMap<&'a str, &'a Installed>,
    requested: Vec<&'a str>,
    requirements: BTreeMap<String, Vec<VersionRequirement>>,
    selections: BTreeMap<String, Selection>,
    fetches: usize,
}

fn order(a: &str, b: &str) -> Option<Ordering> {
    Some(SemanticVersion::parse(a)?.cmp(&SemanticVersion::parse(b)?))
}

impl<C: Catalog> Planner<'_, C> {
    /// Record a requirement on `name`; if `name` is already selected, the
    /// selected version must satisfy it.
    fn require(
        &mut self,
        name: &str,
        requirement: &VersionRequirement,
        required_by: Option<&str>,
    ) -> Result<bool, Error<C::Error>> {
        if let Some(selection) = self.selections.get(name)
            && !requirement.matches(&selection.version)
        {
            return Err(Error::Conflict {
                name: name.into(),
                version: selection.version.clone(),
                required_by: required_by.map(Into::into),
            });
        }
        let list = self.requirements.entry(name.into()).or_default();
        let new = list.is_empty();
        list.push(requirement.clone());
        Ok(new)
    }

    fn satisfies(&self, name: &str, version: &str) -> bool {
        self.requirements
            .get(name)
            .is_some_and(|list| list.iter().all(|item| item.matches(version)))
    }

    fn select(&mut self, name: &str) -> Result<(), Error<C::Error>> {
        if self.selections.len() >= self.options.limits.packages {
            return Err(Error::Limit(Limit::Packages));
        }
        let installed = self.installed.get(name).copied();
        let upgrade = self.options.upgrade && self.requested.contains(&name);
        if let Some(installed) = installed
            && !upgrade
            && self.satisfies(name, &installed.version)
        {
            self.selections.insert(
                name.into(),
                Selection {
                    version: installed.version.clone(),
                    dependencies: installed.dependencies.clone(),
                    step: None,
                },
            );
            return Ok(());
        }

        let versions = self.catalog.versions(name).map_err(Error::Catalog)?;
        if versions.is_empty() {
            return Err(Error::Missing { name: name.into() });
        }
        let listed = versions.clone();
        for version in versions {
            if !self.satisfies(name, &version) {
                continue;
            }
            if self.fetches >= self.options.limits.fetches {
                return Err(Error::Limit(Limit::Fetches));
            }
            self.fetches += 1;
            let candidate = self
                .catalog
                .candidate(name, &version)
                .map_err(Error::Catalog)?;
            if candidate.entry.name != name || candidate.entry.version != version {
                return Err(Error::Substituted {
                    name: name.into(),
                    version,
                });
            }
            if !trust::compatible(
                &candidate.entry,
                self.environment.target,
                self.environment.xila_version,
            ) {
                continue;
            }
            let step = match installed {
                None => Some(Action::Install),
                Some(installed) if installed.version == version => None,
                Some(installed) => match order(&version, &installed.version) {
                    Some(Ordering::Less) if !self.options.allow_downgrade => {
                        return Err(Error::Downgrade {
                            name: name.into(),
                            installed: installed.version.clone(),
                            candidate: version,
                        });
                    }
                    Some(Ordering::Less) => Some(Action::Downgrade {
                        from: installed.version.clone(),
                    }),
                    _ => Some(Action::Upgrade {
                        from: installed.version.clone(),
                    }),
                },
            };
            self.selections.insert(
                name.into(),
                Selection {
                    version,
                    dependencies: match (&step, installed) {
                        (None, Some(installed)) => installed.dependencies.clone(),
                        _ => candidate.dependencies,
                    },
                    step: step.map(|action| (action, candidate.entry)),
                },
            );
            return Ok(());
        }
        // Every version that satisfies the requirements is incompatible.
        // Report Unsatisfiable when another version would have been
        // compatible, Incompatible otherwise.
        let mut others = listed;
        others.retain(|version| !self.satisfies(name, version));
        for version in others {
            if self.fetches >= self.options.limits.fetches {
                // Cannot tell without exceeding the limit.
                return Err(Error::Unsatisfiable { name: name.into() });
            }
            self.fetches += 1;
            let candidate = self
                .catalog
                .candidate(name, &version)
                .map_err(Error::Catalog)?;
            if candidate.entry.name != name || candidate.entry.version != version {
                return Err(Error::Substituted {
                    name: name.into(),
                    version,
                });
            }
            if trust::compatible(
                &candidate.entry,
                self.environment.target,
                self.environment.xila_version,
            ) {
                return Err(Error::Unsatisfiable { name: name.into() });
            }
        }
        Err(Error::Incompatible { name: name.into() })
    }

    /// Post-order walk from the requests: each package after its
    /// dependencies. Kept packages are walked too, so cycles through them are
    /// found, but produce no step.
    fn order(mut self, requests: &[Dependency]) -> Result<Plan, Error<C::Error>> {
        #[derive(Clone, Copy, PartialEq)]
        enum Mark {
            Active,
            Done,
        }
        let mut marks: BTreeMap<String, Mark> = BTreeMap::new();
        let mut path: Vec<String> = Vec::new();
        let mut steps = Vec::new();
        // Explicit stack of (package, index of the next dependency to visit).
        let mut stack: Vec<(String, usize)> = Vec::new();
        for request in requests {
            if marks.contains_key(&request.name) {
                continue;
            }
            stack.push((request.name.clone(), 0));
            marks.insert(request.name.clone(), Mark::Active);
            path.push(request.name.clone());
            while let Some((name, next)) = stack.last_mut() {
                let dependency = self
                    .selections
                    .get(name.as_str())
                    .and_then(|selection| selection.dependencies.get(*next));
                if let Some(dependency) = dependency {
                    *next += 1;
                    match marks.get(&dependency.name) {
                        Some(Mark::Done) => {}
                        Some(Mark::Active) => {
                            let start = path
                                .iter()
                                .position(|package| *package == dependency.name)
                                .unwrap_or(0);
                            let mut packages = path[start..].to_vec();
                            packages.push(dependency.name.clone());
                            return Err(Error::Cycle { packages });
                        }
                        None => {
                            let name = dependency.name.clone();
                            marks.insert(name.clone(), Mark::Active);
                            path.push(name.clone());
                            stack.push((name, 0));
                        }
                    }
                } else {
                    let (name, _) = stack.pop().unwrap_or_default();
                    path.pop();
                    marks.insert(name.clone(), Mark::Done);
                    // A finished package is never visited again.
                    if let Some(selection) = self.selections.remove(&name)
                        && let Some((action, entry)) = selection.step
                    {
                        steps.push(Step {
                            action,
                            entry,
                            dependencies: selection.dependencies,
                        });
                    }
                }
            }
        }
        Ok(Plan { steps })
    }
}

/// Plan the installation of `requests` on a device that has `installed`.
///
/// Requests are resolved in order, then their dependencies breadth first.
/// Installed packages that are not replaced must still have their
/// dependencies satisfied after the plan, or [`Error::Conflict`] names them.
pub fn plan<C: Catalog>(
    catalog: &mut C,
    requests: &[Dependency],
    installed: &[Installed],
    environment: &Environment<'_>,
    options: &Options,
) -> Result<Plan, Error<C::Error>> {
    let mut installed_map = BTreeMap::new();
    for package in installed {
        if installed_map
            .insert(package.name.as_str(), package)
            .is_some()
        {
            return Err(Error::DuplicateInstalled {
                name: package.name.clone(),
            });
        }
    }
    let mut planner = Planner {
        catalog,
        environment,
        options,
        installed: installed_map,
        requested: requests
            .iter()
            .map(|request| request.name.as_str())
            .collect(),
        requirements: BTreeMap::new(),
        selections: BTreeMap::new(),
        fetches: 0,
    };

    let mut queue: VecDeque<(String, usize)> = VecDeque::new();
    for request in requests {
        if planner.require(&request.name, &request.requirement, None)? {
            queue.push_back((request.name.clone(), 0));
        }
    }
    while let Some((name, depth)) = queue.pop_front() {
        planner.select(&name)?;
        let dependencies = planner.selections[name.as_str()].dependencies.clone();
        if dependencies.len() > options.limits.dependencies {
            return Err(Error::Limit(Limit::Dependencies));
        }
        for dependency in &dependencies {
            if dependency.name == name {
                return Err(Error::Cycle {
                    packages: alloc::vec![name.clone(), name.clone()],
                });
            }
            if planner.require(&dependency.name, &dependency.requirement, Some(&name))? {
                if depth + 1 > options.limits.depth {
                    return Err(Error::Limit(Limit::Depth));
                }
                queue.push_back((dependency.name.clone(), depth + 1));
            }
        }
    }

    // Installed packages outside the plan keep working only if what they
    // depend on still satisfies them.
    for package in installed {
        if planner.selections.contains_key(&package.name) {
            continue;
        }
        for dependency in &package.dependencies {
            if let Some(selection) = planner.selections.get(&dependency.name)
                && !dependency.requirement.matches(&selection.version)
            {
                return Err(Error::Conflict {
                    name: dependency.name.clone(),
                    version: selection.version.clone(),
                    required_by: Some(package.name.clone()),
                });
            }
        }
    }

    planner.order(requests)
}

/// A [`Catalog`] over an authenticated `index.json`: entries are fetched by
/// path, authenticated with the repository key and checked against the
/// index's hash and size before use.
///
/// `fetch` returns the bytes of a registry-relative path and of its detached
/// signature (`<path>.sig`). Registry entries do not declare dependencies yet,
/// so every candidate has none.
pub struct IndexCatalog<'a, F> {
    root: &'a TrustedRoot,
    index: &'a Index,
    fetch: F,
}

/// Why an [`IndexCatalog`] could not provide a candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IndexCatalogError<E> {
    Fetch(E),
    Trust(trust::Error),
}

impl<E: fmt::Display> fmt::Display for IndexCatalogError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(error) => write!(formatter, "fetch failed: {error}"),
            Self::Trust(error) => write!(formatter, "{error}"),
        }
    }
}

impl<'a, F> IndexCatalog<'a, F> {
    /// `index` must come from [`TrustedRoot::verify_index`] on `root`.
    pub fn new(root: &'a TrustedRoot, index: &'a Index, fetch: F) -> Self {
        Self { root, index, fetch }
    }
}

/// The bytes of a registry file and of its detached signature.
pub struct Fetched {
    pub bytes: Vec<u8>,
    pub signature: Vec<u8>,
}

impl<E, F> Catalog for IndexCatalog<'_, F>
where
    F: FnMut(&str) -> Result<Fetched, E>,
{
    type Error = IndexCatalogError<E>;

    /// Every semantic version listed in the index, newest first, including
    /// prereleases (only an exact requirement accepts those).
    fn versions(&mut self, name: &str) -> Result<Vec<String>, Self::Error> {
        Ok(index_versions(self.index, name, true)
            .into_iter()
            .map(Into::into)
            .collect())
    }

    fn candidate(&mut self, name: &str, version: &str) -> Result<Candidate, Self::Error> {
        let path = trust::entry_path(name, version);
        let fetched = (self.fetch)(&path).map_err(IndexCatalogError::Fetch)?;
        trust::check_listed(self.index, &path, &fetched.bytes).map_err(IndexCatalogError::Trust)?;
        let entry = self
            .root
            .verify_entry(&fetched.bytes, &fetched.signature)
            .map_err(IndexCatalogError::Trust)?;
        Ok(Candidate {
            entry,
            dependencies: Vec::new(),
        })
    }
}

/// A [`Catalog`] held in memory, for local repositories and tests. Versions
/// of a package are offered newest first.
#[derive(Clone, Debug, Default)]
pub struct MemoryCatalog {
    candidates: Vec<Candidate>,
}

/// [`MemoryCatalog`] has no version with this name and version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotFound;

impl fmt::Display for NotFound {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("no such candidate")
    }
}

impl MemoryCatalog {
    pub fn new(candidates: Vec<Candidate>) -> Self {
        Self { candidates }
    }
}

impl Catalog for MemoryCatalog {
    type Error = NotFound;

    fn versions(&mut self, name: &str) -> Result<Vec<String>, NotFound> {
        let mut versions: Vec<&str> = self
            .candidates
            .iter()
            .filter(|candidate| candidate.entry.name == name)
            .map(|candidate| candidate.entry.version.as_str())
            .collect();
        // Newest first; versions that are not semantic come last, by text.
        versions.sort_by(
            |a, b| match (SemanticVersion::parse(a), SemanticVersion::parse(b)) {
                (Some(a), Some(b)) => b.cmp(&a),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => a.cmp(b),
            },
        );
        versions.dedup();
        Ok(versions.into_iter().map(Into::into).collect())
    }

    fn candidate(&mut self, name: &str, version: &str) -> Result<Candidate, NotFound> {
        self.candidates
            .iter()
            .find(|candidate| candidate.entry.name == name && candidate.entry.version == version)
            .cloned()
            .ok_or(NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, string::ToString, vec};
    use xila_package_manifest::{Archive, REGISTRY_FORMAT_VERSION};

    const TARGET: &str = "wasm32-wasip1";
    const RUNNING: XilaVersion = XilaVersion::new(0, 1);

    fn entry(name: &str, version: &str) -> RegistryEntry {
        RegistryEntry {
            schema: None,
            format_version: REGISTRY_FORMAT_VERSION,
            name: name.into(),
            version: version.into(),
            target: TARGET.into(),
            xila_version: RUNNING,
            capabilities: vec![],
            display_name: None,
            metadata: None,
            publisher: "xila".into(),
            archive: Archive {
                url: format!("https://xila.example/{name}-{version}.xpk"),
                sha256: "a".repeat(64),
                size: 1,
            },
        }
    }

    fn requirement(text: &str) -> VersionRequirement {
        text.parse().unwrap()
    }

    /// `"name version dependency:requirement…"`.
    fn candidate(description: &str) -> Candidate {
        let mut words = description.split(' ');
        let name = words.next().unwrap();
        let version = words.next().unwrap();
        Candidate {
            entry: entry(name, version),
            dependencies: words
                .map(|word| {
                    let (name, text) = word.split_once(':').unwrap();
                    Dependency::new(name, requirement(text))
                })
                .collect(),
        }
    }

    fn catalog(descriptions: &[&str]) -> MemoryCatalog {
        MemoryCatalog::new(descriptions.iter().map(|text| candidate(text)).collect())
    }

    fn request(name: &str, text: &str) -> Dependency {
        Dependency::new(name, requirement(text))
    }

    fn installed(name: &str, version: &str, dependencies: &[(&str, &str)]) -> Installed {
        Installed {
            name: name.into(),
            version: version.into(),
            dependencies: dependencies
                .iter()
                .map(|(name, text)| request(name, text))
                .collect(),
        }
    }

    const ENVIRONMENT: Environment<'static> = Environment {
        target: TARGET,
        xila_version: RUNNING,
    };

    fn run(
        catalog: &mut MemoryCatalog,
        requests: &[Dependency],
        installed: &[Installed],
        options: &Options,
    ) -> Result<Vec<(String, String, Action)>, Error<NotFound>> {
        plan(catalog, requests, installed, &ENVIRONMENT, options).map(|plan| {
            plan.steps
                .into_iter()
                .map(|step| (step.entry.name, step.entry.version, step.action))
                .collect()
        })
    }

    fn installs(steps: &[(&str, &str)]) -> Vec<(String, String, Action)> {
        steps
            .iter()
            .map(|(name, version)| (name.to_string(), version.to_string(), Action::Install))
            .collect()
    }

    #[test]
    fn requirements_parse_display_and_match() {
        for text in ["*", "=1.2.3", "=nightly", ">=1.2.3", "^0.2.0"] {
            assert_eq!(requirement(text).to_string(), text);
        }
        for text in [
            "",
            "1.2.3",
            ">=1.2",
            "^1.0.0-rc.1",
            "=",
            "= 1.0.0",
            "<2.0.0",
        ] {
            assert_eq!(text.parse::<VersionRequirement>(), Err(InvalidRequirement));
        }
        for (text, version, expected) in [
            ("*", "1.0.0", true),
            ("*", "1.0.0-rc.1", false),
            ("*", "nightly", false),
            ("=1.0.0-rc.1", "1.0.0-rc.1", true),
            ("=1.0.0", "1.0.0+build", true),
            ("=nightly", "nightly", true),
            ("=1.0.0", "1.0.1", false),
            (">=1.2.0", "1.2.0", true),
            (">=1.2.0", "2.0.0", true),
            (">=1.2.0", "1.1.9", false),
            (">=1.2.0", "1.3.0-rc.1", false),
            ("^1.2.0", "1.9.0", true),
            ("^1.2.0", "2.0.0", false),
            ("^1.2.0", "1.1.0", false),
            ("^0.2.1", "0.2.5", true),
            ("^0.2.1", "0.3.0", false),
            ("^0.0.3", "0.0.3", true),
            ("^0.0.3", "0.0.4", false),
        ] {
            assert_eq!(
                requirement(text).matches(version),
                expected,
                "{text} {version}"
            );
        }
    }

    #[test]
    fn installs_dependencies_first_and_prefers_new_versions() {
        let mut catalog = catalog(&[
            "xila.clock 1.0.0 xila.time:^1.0.0 xila.font:*",
            "xila.clock 1.1.0 xila.time:^1.1.0 xila.font:*",
            "xila.time 1.0.0",
            "xila.time 1.2.0 xila.font:>=0.1.0",
            "xila.time 2.0.0",
            "xila.font 0.1.0",
        ]);
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.clock", "*")],
                &[],
                &Options::default()
            ),
            Ok(installs(&[
                ("xila.font", "0.1.0"),
                ("xila.time", "1.2.0"),
                ("xila.clock", "1.1.0"),
            ]))
        );
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.clock", "=1.0.0")],
                &[],
                &Options::default()
            ),
            Ok(installs(&[
                ("xila.font", "0.1.0"),
                ("xila.time", "1.2.0"),
                ("xila.clock", "1.0.0"),
            ]))
        );
    }

    #[test]
    fn plans_are_deterministic() {
        let descriptions = [
            "xila.a 1.0.0 xila.c:* xila.b:*",
            "xila.b 1.0.0 xila.d:*",
            "xila.c 1.0.0 xila.d:*",
            "xila.d 1.0.0",
            "xila.d 1.1.0",
        ];
        let requests = [request("xila.a", "*")];
        let first = run(
            &mut catalog(&descriptions),
            &requests,
            &[],
            &Options::default(),
        );
        let mut reversed = descriptions;
        reversed.reverse();
        for _ in 0..3 {
            assert_eq!(
                run(&mut catalog(&reversed), &requests, &[], &Options::default()),
                first
            );
        }
        assert_eq!(
            first,
            Ok(installs(&[
                ("xila.d", "1.1.0"),
                ("xila.c", "1.0.0"),
                ("xila.b", "1.0.0"),
                ("xila.a", "1.0.0"),
            ]))
        );
    }

    #[test]
    fn skips_versions_for_other_targets_or_xila_releases() {
        let mut other_target = candidate("xila.clock 1.2.0");
        other_target.entry.target = "riscv32imc".into();
        let mut newer_xila = candidate("xila.clock 1.1.0");
        newer_xila.entry.xila_version = XilaVersion::new(0, 2);
        let mut catalog = MemoryCatalog::new(vec![
            other_target,
            newer_xila,
            candidate("xila.clock 1.0.0"),
        ]);
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.clock", "*")],
                &[],
                &Options::default()
            ),
            Ok(installs(&[("xila.clock", "1.0.0")]))
        );
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.clock", ">=1.1.0")],
                &[],
                &Options::default()
            ),
            Err(Error::Unsatisfiable {
                name: "xila.clock".into()
            })
        );

        let mut only = candidate("xila.clock 1.0.0");
        only.entry.target = "riscv32imc".into();
        assert_eq!(
            run(
                &mut MemoryCatalog::new(vec![only]),
                &[request("xila.clock", "*")],
                &[],
                &Options::default()
            ),
            Err(Error::Incompatible {
                name: "xila.clock".into()
            })
        );
    }

    #[test]
    fn reports_missing_and_unsatisfiable_packages() {
        let mut catalog = catalog(&["xila.clock 1.0.0 xila.time:^2.0.0", "xila.time 1.0.0"]);
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.weather", "*")],
                &[],
                &Options::default()
            ),
            Err(Error::Missing {
                name: "xila.weather".into()
            })
        );
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.clock", "*")],
                &[],
                &Options::default()
            ),
            Err(Error::Unsatisfiable {
                name: "xila.time".into()
            })
        );
    }

    #[test]
    fn reports_conflicting_requirements() {
        let mut catalog = catalog(&[
            "xila.a 1.0.0 xila.c:*",
            "xila.b 1.0.0 xila.c:^1.0.0",
            "xila.x 1.0.0 xila.b:*",
            "xila.c 1.0.0",
            "xila.c 2.0.0",
        ]);
        // Requirements known before a selection are all honoured: both
        // requests' dependencies are seen before xila.c is selected.
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.a", "*"), request("xila.b", "*")],
                &[],
                &Options::default()
            ),
            Ok(installs(&[
                ("xila.c", "1.0.0"),
                ("xila.a", "1.0.0"),
                ("xila.b", "1.0.0"),
            ]))
        );
        // xila.c 2.0.0 is selected (depth 1) before xila.b (depth 2) asks
        // for ^1.0.0: the planner reports it instead of backtracking.
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.a", "*"), request("xila.x", "*")],
                &[],
                &Options::default()
            ),
            Err(Error::Conflict {
                name: "xila.c".into(),
                version: "2.0.0".into(),
                required_by: Some("xila.b".into()),
            })
        );
        // The same conflict from an installed package that is kept.
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.a", "*")],
                &[installed("xila.b", "1.0.0", &[("xila.c", "^1.0.0")])],
                &Options::default()
            ),
            Err(Error::Conflict {
                name: "xila.c".into(),
                version: "2.0.0".into(),
                required_by: Some("xila.b".into()),
            })
        );
        // Two requests for incompatible versions of one package.
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.c", "=1.0.0"), request("xila.c", "=2.0.0")],
                &[],
                &Options::default()
            ),
            Err(Error::Unsatisfiable {
                name: "xila.c".into()
            })
        );
    }

    #[test]
    fn rejects_dependency_cycles() {
        let mut catalog = catalog(&[
            "xila.a 1.0.0 xila.b:*",
            "xila.b 1.0.0 xila.c:*",
            "xila.c 1.0.0 xila.a:*",
            "xila.self 1.0.0 xila.self:*",
        ]);
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.a", "*")],
                &[],
                &Options::default()
            ),
            Err(Error::Cycle {
                packages: vec![
                    "xila.a".into(),
                    "xila.b".into(),
                    "xila.c".into(),
                    "xila.a".into()
                ]
            })
        );
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.self", "*")],
                &[],
                &Options::default()
            ),
            Err(Error::Cycle {
                packages: vec!["xila.self".into(), "xila.self".into()]
            })
        );
        assert!(
            Error::<NotFound>::Cycle {
                packages: vec!["xila.a".into(), "xila.b".into(), "xila.a".into()]
            }
            .to_string()
            .ends_with("xila.a -> xila.b -> xila.a")
        );
    }

    #[test]
    fn keeps_suitable_installed_packages_and_upgrades_others() {
        let mut catalog = catalog(&[
            "xila.clock 1.0.0 xila.time:^1.0.0",
            "xila.clock 1.1.0 xila.time:^1.1.0",
            "xila.time 1.0.0",
            "xila.time 1.1.0",
        ]);
        let device = [
            installed("xila.clock", "1.0.0", &[("xila.time", "^1.0.0")]),
            installed("xila.time", "1.0.0", &[]),
        ];
        // Already satisfied: nothing to do.
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.clock", "*")],
                &device,
                &Options::default()
            ),
            Ok(vec![])
        );
        // Upgrading the request pulls the newer dependency it needs.
        let upgrade = Options {
            upgrade: true,
            ..Options::default()
        };
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.clock", "*")],
                &device,
                &upgrade
            ),
            Ok(vec![
                (
                    "xila.time".into(),
                    "1.1.0".into(),
                    Action::Upgrade {
                        from: "1.0.0".into()
                    }
                ),
                (
                    "xila.clock".into(),
                    "1.1.0".into(),
                    Action::Upgrade {
                        from: "1.0.0".into()
                    }
                ),
            ])
        );
    }

    #[test]
    fn protects_installed_dependents_and_refuses_downgrades() {
        let mut catalog = catalog(&["xila.time 1.0.0", "xila.time 2.0.0"]);
        let device = [
            installed("xila.clock", "1.0.0", &[("xila.time", "^1.0.0")]),
            installed("xila.time", "1.0.0", &[]),
        ];
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.time", "^2.0.0")],
                &device,
                &Options::default()
            ),
            Err(Error::Conflict {
                name: "xila.time".into(),
                version: "2.0.0".into(),
                required_by: Some("xila.clock".into()),
            })
        );

        let device = [installed("xila.time", "2.0.0", &[])];
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.time", "=1.0.0")],
                &device,
                &Options::default()
            ),
            Err(Error::Downgrade {
                name: "xila.time".into(),
                installed: "2.0.0".into(),
                candidate: "1.0.0".into(),
            })
        );
        let allow = Options {
            allow_downgrade: true,
            ..Options::default()
        };
        assert_eq!(
            run(
                &mut catalog,
                &[request("xila.time", "=1.0.0")],
                &device,
                &allow
            ),
            Ok(vec![(
                "xila.time".into(),
                "1.0.0".into(),
                Action::Downgrade {
                    from: "2.0.0".into()
                }
            )])
        );
        let twice = [
            installed("xila.time", "2.0.0", &[]),
            installed("xila.time", "1.0.0", &[]),
        ];
        assert_eq!(
            run(&mut catalog, &[request("xila.time", "*")], &twice, &allow),
            Err(Error::DuplicateInstalled {
                name: "xila.time".into()
            })
        );
    }

    #[test]
    fn enforces_limits() {
        let chain = [
            "xila.a 1.0.0 xila.b:*",
            "xila.b 1.0.0 xila.c:*",
            "xila.c 1.0.0 xila.d:*",
            "xila.d 1.0.0",
        ];
        let requests = [request("xila.a", "*")];
        let with = |limits: Limits| Options {
            limits,
            ..Options::default()
        };
        let default = Limits::default();
        for (limits, expected) in [
            (
                Limits {
                    packages: 3,
                    ..default
                },
                Limit::Packages,
            ),
            (
                Limits {
                    fetches: 3,
                    ..default
                },
                Limit::Fetches,
            ),
            (
                Limits {
                    depth: 2,
                    ..default
                },
                Limit::Depth,
            ),
        ] {
            assert_eq!(
                run(&mut catalog(&chain), &requests, &[], &with(limits)),
                Err(Error::Limit(expected))
            );
        }
        assert!(
            run(
                &mut catalog(&chain),
                &requests,
                &[],
                &with(Limits {
                    packages: 4,
                    fetches: 4,
                    depth: 3,
                    ..default
                })
            )
            .is_ok()
        );
        assert_eq!(
            run(
                &mut catalog(&[
                    "xila.a 1.0.0 xila.b:* xila.c:*",
                    "xila.b 1.0.0",
                    "xila.c 1.0.0"
                ]),
                &requests,
                &[],
                &with(Limits {
                    dependencies: 1,
                    ..default
                })
            ),
            Err(Error::Limit(Limit::Dependencies))
        );
    }

    /// Answers with another package than the one asked for.
    struct Substituting;

    impl Catalog for Substituting {
        type Error = NotFound;

        fn versions(&mut self, _: &str) -> Result<Vec<String>, NotFound> {
            Ok(vec!["1.0.0".into()])
        }

        fn candidate(&mut self, _: &str, version: &str) -> Result<Candidate, NotFound> {
            Ok(Candidate {
                entry: entry("xila.malware", version),
                dependencies: vec![],
            })
        }
    }

    #[test]
    fn rejects_substituted_entries() {
        assert_eq!(
            plan(
                &mut Substituting,
                &[request("xila.clock", "*")],
                &[],
                &ENVIRONMENT,
                &Options::default()
            ),
            Err(Error::Substituted {
                name: "xila.clock".into(),
                version: "1.0.0".into()
            })
        );
    }

    mod index {
        use super::*;
        use alloc::collections::BTreeMap;
        use ed25519_dalek::{Signer, SigningKey};
        use xila_package_manifest::{
            ENTRY_DOMAIN, INDEX_SCHEMA_URL, IndexFile, NamedKey, ROOT_DOMAIN, ROOT_SCHEMA_URL,
            Root, TRUST_FORMAT_VERSION, encode_registry_entry, encode_root, signed_message,
        };
        use xila_package_verification::Sha256Verifier;

        fn key(seed: u8) -> SigningKey {
            SigningKey::from_bytes(&[seed; 32])
        }

        fn base64(bytes: &[u8; 32]) -> String {
            const TABLE: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut output = String::new();
            for chunk in bytes.chunks(3) {
                let mut block = [0u8; 3];
                block[..chunk.len()].copy_from_slice(chunk);
                let value = u32::from_be_bytes([0, block[0], block[1], block[2]]);
                for index in 0..4 {
                    if index <= chunk.len() {
                        output.push(TABLE[(value >> (18 - 6 * index) & 63) as usize] as char);
                    } else {
                        output.push('=');
                    }
                }
            }
            output
        }

        fn sign(key: &SigningKey, domain: &[u8], bytes: &[u8]) -> Vec<u8> {
            key.sign(&signed_message(domain, bytes).unwrap())
                .to_bytes()
                .to_vec()
        }

        fn sha256_hex(bytes: &[u8]) -> String {
            let mut hasher = Sha256Verifier::new();
            hasher.update(bytes).unwrap();
            hasher
                .finalize()
                .unwrap()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        }

        fn trusted() -> TrustedRoot {
            let named = |id: &str, key: &SigningKey| NamedKey {
                id: id.into(),
                public_key: base64(&key.verifying_key().to_bytes()),
            };
            let root = encode_root(&Root {
                schema: Some(ROOT_SCHEMA_URL.into()),
                format_version: TRUST_FORMAT_VERSION,
                version: 1,
                root_keys: vec![named("root", &key(1))],
                repository_keys: vec![named("repository", &key(2))],
            })
            .unwrap();
            TrustedRoot::bootstrap(
                root.as_bytes(),
                &sign(&key(1), ROOT_DOMAIN, root.as_bytes()),
                &[key(1).verifying_key().to_bytes()],
                0,
            )
            .unwrap()
        }

        /// A registry with `xila.clock` 0.1.0 and 0.2.0, the latter built
        /// for a newer Xila release.
        fn registry() -> (Index, BTreeMap<String, Fetched>) {
            let mut files = Vec::new();
            let mut site = BTreeMap::new();
            for (version, xila_version) in [("0.1.0", RUNNING), ("0.2.0", XilaVersion::new(0, 2))] {
                let mut entry = entry("xila.clock", version);
                entry.xila_version = xila_version;
                let bytes = encode_registry_entry(&entry).unwrap().into_bytes();
                let path = trust::entry_path("xila.clock", version);
                files.push(IndexFile {
                    path: path.clone(),
                    sha256: sha256_hex(&bytes),
                    size: bytes.len() as u64,
                });
                site.insert(
                    path,
                    Fetched {
                        signature: sign(&key(2), ENTRY_DOMAIN, &bytes),
                        bytes,
                    },
                );
            }
            let index = Index {
                schema: Some(INDEX_SCHEMA_URL.into()),
                format_version: TRUST_FORMAT_VERSION,
                version: 1,
                expires: u64::MAX,
                files,
            };
            (index, site)
        }

        fn fetch_from(
            site: &BTreeMap<String, Fetched>,
        ) -> impl FnMut(&str) -> Result<Fetched, NotFound> + '_ {
            |path| {
                site.get(path)
                    .map(|file| Fetched {
                        bytes: file.bytes.clone(),
                        signature: file.signature.clone(),
                    })
                    .ok_or(NotFound)
            }
        }

        #[test]
        fn plans_from_authenticated_registry_entries() {
            let root = trusted();
            let (index, site) = registry();
            let mut catalog = IndexCatalog::new(&root, &index, fetch_from(&site));
            let plan = plan(
                &mut catalog,
                &[request("xila.clock", "*")],
                &[],
                &ENVIRONMENT,
                &Options::default(),
            )
            .unwrap();
            assert_eq!(plan.steps.len(), 1);
            assert_eq!(plan.steps[0].entry.version, "0.1.0");
            assert_eq!(plan.steps[0].action, Action::Install);
        }

        #[test]
        fn rejects_altered_or_forged_entries() {
            let root = trusted();
            let (index, mut site) = registry();
            let path = trust::entry_path("xila.clock", "0.2.0");
            // Altered bytes no longer match the index.
            site.get_mut(&path).unwrap().bytes[0] = b' ';
            let mut catalog = IndexCatalog::new(&root, &index, fetch_from(&site));
            assert_eq!(
                plan(
                    &mut catalog,
                    &[request("xila.clock", "*")],
                    &[],
                    &ENVIRONMENT,
                    &Options::default()
                ),
                Err(Error::Catalog(IndexCatalogError::Trust(
                    trust::Error::NotListed
                )))
            );

            // Listed bytes signed by a key other than the repository key.
            let (index, mut site) = registry();
            let file = site.get_mut(&path).unwrap();
            file.signature = sign(&key(3), ENTRY_DOMAIN, &file.bytes);
            let mut catalog = IndexCatalog::new(&root, &index, fetch_from(&site));
            assert_eq!(
                plan(
                    &mut catalog,
                    &[request("xila.clock", "*")],
                    &[],
                    &ENVIRONMENT,
                    &Options::default()
                ),
                Err(Error::Catalog(IndexCatalogError::Trust(
                    trust::Error::InvalidSignature
                )))
            );

            // A missing file is a fetch error, not a silent skip.
            let (index, mut site) = registry();
            site.remove(&path);
            let mut catalog = IndexCatalog::new(&root, &index, fetch_from(&site));
            assert_eq!(
                plan(
                    &mut catalog,
                    &[request("xila.clock", "*")],
                    &[],
                    &ENVIRONMENT,
                    &Options::default()
                ),
                Err(Error::Catalog(IndexCatalogError::Fetch(NotFound)))
            );
        }
    }
}
