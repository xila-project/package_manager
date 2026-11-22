#![no_std]
#![forbid(unsafe_code)]
//! # Xila package manager
//!
//! Platform-independent coordination layer for Xila application installation
//! and repository operations.
//!
//! - [`trust`]: verify registry metadata from a pinned root key down to the
//!   developer key that may publish a package (`no_std + alloc`).
//! - [`installation`]: crash-consistent install, upgrade, removal and
//!   recovery of verified bundles over a small [`installation::Storage`]
//!   trait, with a transaction journal (`no_std + alloc`).
//!
//! The other subcrates provide:
//!
//! - `xila-package-manifest`: versioned `no_std + alloc` formats.
//! - `xila-package-reader`: TAR inspection and verification.
//! - `xila-package-verification`: cryptographic primitives.
//! - `xila-package-writer`: host-only TAR creation.
//! - `xila-package-builder`: host-only command-line packaging (`xila-package`).
//!
//! Archive extraction, networking and privilege checks stay with the device:
//! the installer verifies a package into a staging directory, then hands it to
//! [`installation::activate`].

extern crate alloc;

pub mod installation;
pub mod trust;
