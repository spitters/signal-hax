//! PQXDH type definitions.
//!
//! DH and session types are fixed at 32 bytes (X25519, HKDF output).
//! KEM types are parametric: `PqxdhPreKeyBundle<KEM_PK>` and
//! `PqxdhInitMessage<KEM_CT>` carry the KEM key/ciphertext at their
//! actual size, determined by the `PqxdhCrypto` instance.
//!
//! Toy instance (Kani, unit tests): KEM_PK = KEM_SK = KEM_CT = 32.
//! ML-KEM-768 (tests/reference_crosscheck.rs): KEM_PK = 1184, KEM_SK = 2400, KEM_CT = 1088.

/// DH key (X25519): 32 bytes.
pub type PqxdhDhKey = [u8; 32];

/// KEM shared secret: always 32 bytes (ML-KEM outputs 32).
pub type PqxdhKemSs = [u8; 32];

/// Signature: 64 bytes (Ed25519 / XEdDSA).
pub type PqxdhSignature = [u8; 64];

/// Session key (HKDF output): 32 bytes.
pub type PqxdhSessionKey = [u8; 32];

/// Zero DH key.
pub const ZERO_DH_KEY: PqxdhDhKey = [0u8; 32];

/// Zero KEM shared secret.
pub const ZERO_KEM_SS: PqxdhKemSs = [0u8; 32];

/// Zero signature.
pub const ZERO_SIGNATURE: PqxdhSignature = [0u8; 64];

/// Zero session key.
pub const ZERO_SESSION_KEY: PqxdhSessionKey = [0u8; 32];

/// Pre-key bundle published by the responder (Bob).
///
/// `KEM_PK` is the byte length of the KEM encapsulation key.
/// Toy instance: 32. ML-KEM-768: 1184.
#[derive(Clone, Copy, Debug)]
pub struct PqxdhPreKeyBundle<const KEM_PK: usize> {
    pub ik:       PqxdhDhKey,
    pub spk:      PqxdhDhKey,
    pub opk:      PqxdhDhKey,
    pub pqpk:     [u8; KEM_PK],
    pub spk_sig:  PqxdhSignature,
    pub pqpk_sig: PqxdhSignature,
}

/// Initiator's message to the responder.
///
/// `KEM_CT` is the byte length of the KEM ciphertext.
/// Toy instance: 32. ML-KEM-768: 1088.
#[derive(Clone, Copy, Debug)]
pub struct PqxdhInitMessage<const KEM_CT: usize> {
    pub ik_a:   PqxdhDhKey,
    pub ek_a:   PqxdhDhKey,
    pub kem_ct: [u8; KEM_CT],
    pub opk_id: [u8; 4],
}

/// XOR two 32-byte blocks.
pub fn xor_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 { out[i] = a[i] ^ b[i]; i += 1; }
    out
}

/// Wrapping-add two 32-byte blocks (byte-wise).
pub fn wrapping_add_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 { out[i] = a[i].wrapping_add(b[i]); i += 1; }
    out
}
