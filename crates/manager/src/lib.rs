#![no_std]
#![forbid(unsafe_code)]
//! # Xila package manager
//!
//! The portable, offline-first lifecycle contract lives in [`lifecycle`].
//! It validates install policies, immutable bundle paths, the persistent
//! activation record and the backend guarantees required for power-loss-safe
//! publication.
//!
//! This is a **planning/metadata layer**, not yet a working installer.
//! Archive extraction, trusted-key selection, VFS integration, streaming
//! writes and actual power-loss guarantees remain platform responsibilities.
//! Never treat a planned path or activation digest alone as authorization
//! to execute code.
//!
//! See [Core #491](https://github.com/xila-project/core/issues/491).

extern crate alloc;

pub mod lifecycle;
pub mod installer;
