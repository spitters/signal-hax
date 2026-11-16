// Copyright (c) 2026 CatCrypt Contributors. MIT license.
//! Signal X3DH key agreement: Hax-extractable implementation.
//!
//! This crate implements the X3DH (Extended Triple Diffie-Hellman) key
//! agreement protocol used in Signal in a trait-based style suitable for
//! hax extraction to Lean 4. The `X3dhCrypto` trait abstracts DH, KDF,
//! signature operations and the input check of peer public keys; the modules
//! of `src/` use fixed-size arrays and bounded loops. `subgroup` implements
//! the input check for X25519 (membership in the prime-order subgroup, the
//! identity excluded). The
//! Lean extraction and its correspondence to the model are described in the
//! README.

#![cfg_attr(not(test), no_std)]

pub mod types;
pub mod protocol;
pub mod typestate_fsm;

// The subgroup check is a leaf primitive: the extracted protocol calls it through
// `X3dhCrypto::valid_pub`, and the Lean model gives it by its specification
// (`subgroupCheckU` with the identity excluded), so the module is not extracted.
#[cfg(not(hax))]
pub mod subgroup;

pub use types::*;
pub use protocol::*;

#[cfg(kani)]
mod kani;
