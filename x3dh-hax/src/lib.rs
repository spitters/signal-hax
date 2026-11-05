// Copyright (c) 2026 CatCrypt Contributors. MIT license.
//! Signal X3DH key agreement: Hax-extractable implementation.
//!
//! This crate implements the X3DH (Extended Triple Diffie-Hellman) key
//! agreement protocol used in Signal in a trait-based style suitable for
//! hax extraction to Lean 4. The `X3dhCrypto` trait abstracts DH, KDF,
//! and signature operations; the modules of `src/` use fixed-size arrays
//! and bounded loops. The Lean extraction and its correspondence to the
//! model are described in the README.

#![cfg_attr(not(test), no_std)]

pub mod types;
pub mod protocol;
pub mod typestate_fsm;

pub use types::*;
pub use protocol::*;

#[cfg(kani)]
mod kani;
