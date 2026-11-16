// Copyright (c) 2026 CatCrypt Contributors. MIT license.
//! Signal PQXDH key agreement: Hax-extractable implementation.
//!
//! This crate implements the PQXDH (Post-Quantum Extended Diffie-Hellman)
//! key agreement protocol used in Signal. PQXDH extends X3DH by a KEM
//! encapsulation on top of the X25519 DH operations; the tests and the Lean
//! proofs use ML-KEM-768.
//!
//! The modules of `src/` use fixed-size arrays and bounded loops; the
//! `PqxdhCrypto` trait abstracts DH, KEM, KDF, signature operations and the
//! input check of peer public keys. `subgroup` implements the input check for
//! X25519 (membership in the prime-order subgroup, the identity excluded).
//! The Lean extraction and its correspondence to the model are described in
//! the README.
//!
//! ## Protocol (Signal PQXDH Specification, September 2023)
//!
//! Alice (initiator) and Bob (responder):
//!
//! 1. DH1 = DH(IK_A, SPK_B)
//! 2. DH2 = DH(EK_A, IK_B)
//! 3. DH3 = DH(EK_A, SPK_B)
//! 4. DH4 = DH(EK_A, OPK_B) — optional
//! 5. (ct, pq_ss) = KEM.Encaps(PQPK_B)
//! 6. SK = KDF(F || DH1 || DH2 || DH3 || DH4 || pq_ss)
//!
//! ## Extraction
//!
//! The Lean extraction is made from the hax frontend export and the
//! `haxpipeT` translator of hax-lean:
//!
//! ```bash
//! cargo hax json --use-ids
//! ```

#![cfg_attr(not(test), no_std)]

pub mod types;
pub mod protocol;
pub mod typestate_fsm;

// The subgroup check is a leaf primitive: the extracted protocol calls it through
// `PqxdhCrypto::valid_pub`, and the Lean model gives it by its specification
// (`subgroupCheckU` with the identity excluded), so the module is not extracted.
#[cfg(not(hax))]
pub mod subgroup;

pub use types::*;
pub use protocol::*;

#[cfg(kani)]
mod kani;
