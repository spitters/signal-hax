//! X3DH type definitions.
//!
//! All types use fixed-size arrays for hax extraction compatibility.

/// DH key (Curve25519): 32 bytes.
pub type X3dhKey = [u8; 32];

/// Signature: 64 bytes (Ed25519 convention).
pub type X3dhSignature = [u8; 64];

/// Session key (KDF output): 32 bytes.
pub type X3dhSessionKey = [u8; 32];

/// Zero key.
pub const ZERO_KEY: X3dhKey = [0u8; 32];

/// Zero signature.
pub const ZERO_SIGNATURE: X3dhSignature = [0u8; 64];

/// Zero session key.
pub const ZERO_SESSION_KEY: X3dhSessionKey = [0u8; 32];

/// Pre-key bundle published by the responder (Bob).
#[derive(Clone, Copy, Debug)]
pub struct X3dhPreKeyBundle {
    /// Identity key (long-term public key).
    pub ik: X3dhKey,
    /// Signed pre-key (medium-term).
    pub spk: X3dhKey,
    /// One-time pre-key (optional, single-use).
    pub opk: X3dhKey,
    /// Signature over spk by ik.
    pub sig: X3dhSignature,
}

/// Initiator's message to the responder.
#[derive(Clone, Copy, Debug)]
pub struct X3dhInitMessage {
    /// Initiator's identity key.
    pub ik_a: X3dhKey,
    /// Initiator's ephemeral key.
    pub ek_a: X3dhKey,
    /// Which one-time pre-key was used (opaque identifier).
    pub opk_id: [u8; 4],
}

/// XOR two 32-byte blocks.
pub fn xor_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}
