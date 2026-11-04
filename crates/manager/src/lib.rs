#![no_std]
#![forbid(unsafe_code)]
//! # Xila package manager
//!
//! Platform-independent coordination layer for Xila application installation
//! and repository operations.
//!
//! - [`trust`]: verify registry metadata from a pinned root key down to the
//!   developer key that may publish a package (`no_std + alloc`).
//!
//! The other subcrates provide:
//!
//! - `xila-package-manifest`: versioned `no_std + alloc` formats.
//! - `xila-package-reader`: TAR inspection and verification.
//! - `xila-package-verification`: cryptographic primitives.
//! - `xila-package-writer`: host-only TAR creation.
//! - `xila-package-builder`: host-only command-line packaging (`xila-package`).
//!
//! The eventual embedded installer will require explicit abstractions for
//! filesystems, networking and atomic installation; none is introduced here.

extern crate alloc;

pub mod trust;
