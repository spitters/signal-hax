// Copyright (c) 2026 CatCrypt Contributors. MIT license.
//! Signal Double Ratchet — Hax-extractable implementation over a dependency trait.
//!
//! The Double Ratchet algorithm combines a symmetric-key ratchet (KDF chain)
//! with a Diffie-Hellman ratchet. The protocol logic of this crate (the ratchet
//! state, the chain-key step, the root step on a new DH output, the message-key
//! derivation and the header handling) is Rust over the [`DoubleRatchetDeps`]
//! trait, which carries the primitives: HMAC-SHA-256, HKDF-SHA-256, X25519 and
//! the message encryption. The crate implements no primitive itself.
//!
//! Symmetric KDF chain step:
//!   kdf_chain_step(chain_key) -> (new_chain_key, message_key)
//!     new_chain_key = HMAC-SHA-256(chain_key, ck_const(0x01))
//!     message_key   = HMAC-SHA-256(chain_key, ck_const(0x02))
//! where `ck_const(c)` is the 32-byte block of bytes `c`.
//!
//! Root step (Signal `KDF_RK`):
//!   prk = HKDF-Extract(root_key, dh_output)
//!   new_root_key  = HKDF-Expand(prk, [0x01; 32])
//!   new_chain_key = HKDF-Expand(prk, [0x02; 32])
//!
//! These constants differ from the Signal specification; the README lists the
//! deviations. The Lean extraction and its correspondence to the model are
//! described in the README.

#![no_std]

pub mod typestate_fsm;

/// Maximum message length in bytes.
pub const MAX_MSG_LEN: usize = 256;

/// Maximum plaintext length.
pub const MAX_PLAINTEXT_LEN: usize = 256;

// =========================================================================
// Dependency trait: the primitives
// =========================================================================

/// The primitives of the double ratchet: HMAC-SHA-256, HKDF-SHA-256, X25519
/// and the message encryption. An implementation backs them by a
/// cryptographic library.
pub trait DoubleRatchetDeps {
    /// HMAC-SHA-256 under a 32-byte key on a 32-byte message.
    fn hmac_sha256(key: &[u8; 32], msg: &[u8; 32]) -> [u8; 32];
    /// HKDF-SHA-256 Extract with the salt `salt` and the input keying material `ikm`.
    fn hkdf_extract(salt: &[u8; 32], ikm: &[u8; 32]) -> [u8; 32];
    /// HKDF-SHA-256 Expand of one 32-byte block under the 32-byte info `info`.
    fn hkdf_expand(prk: &[u8; 32], info: &[u8; 32]) -> [u8; 32];
    /// X25519: `x25519(sk, pk)` is the shared secret of the secret key `sk`
    /// and the public key `pk`.
    fn x25519(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32];
    /// Encryption of the first `pt_len` bytes of `plaintext` under the message
    /// key `mk` with associated data `ad`.
    fn aead_encrypt(
        mk: &[u8; 32],
        plaintext: &[u8],
        pt_len: usize,
        ad: &[u8; 32],
    ) -> [u8; MAX_PLAINTEXT_LEN];
    /// Decryption of the first `ct_len` bytes of `ciphertext` under the message
    /// key `mk` with associated data `ad`.
    fn aead_decrypt(
        mk: &[u8; 32],
        ciphertext: &[u8],
        ct_len: usize,
        ad: &[u8; 32],
    ) -> [u8; MAX_PLAINTEXT_LEN];
}

// =========================================================================
// Double Ratchet operations over the primitives
// =========================================================================

/// The 32-byte HMAC message block of the chain-step constant `c`.
pub fn ck_const(c: u8) -> [u8; 32] {
    [c; 32]
}

/// Chain-key KDF: `kdf_ck(chain_key, constant) = HMAC-SHA-256(chain_key, ck_const(constant))`.
pub fn kdf_ck<D: DoubleRatchetDeps>(chain_key: &[u8; 32], constant: u8) -> [u8; 32] {
    D::hmac_sha256(chain_key, &ck_const(constant))
}

/// Root-key KDF: from a root key and a DH output, the new root key and the
/// chain key, HKDF-SHA-256 with the root key as salt, expanded under the info
/// blocks `[0x01; 32]` and `[0x02; 32]`.
pub fn kdf_rk<D: DoubleRatchetDeps>(
    root_key: &[u8; 32],
    dh_output: &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let prk = D::hkdf_extract(root_key, dh_output);
    let new_rk = D::hkdf_expand(&prk, &[0x01u8; 32]);
    let new_ck = D::hkdf_expand(&prk, &[0x02u8; 32]);
    (new_rk, new_ck)
}

/// Diffie-Hellman computation: `DH(my_sk, their_pk)`, X25519 of the dependency.
pub fn dh<D: DoubleRatchetDeps>(my_sk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
    D::x25519(my_sk, their_pk)
}

// =========================================================================
// Symmetric ratchet: KDF chain step
// =========================================================================

/// Perform one step of the symmetric KDF chain.
///
/// Given a chain key, produces:
///   - new_chain_key = KDF(chain_key, 0x01)
///   - message_key   = KDF(chain_key, 0x02)
///
/// The old chain key is discarded after this step (forward secrecy).
pub fn kdf_chain_step<D: DoubleRatchetDeps>(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let new_ck = kdf_ck::<D>(ck, 0x01);
    let mk = kdf_ck::<D>(ck, 0x02);
    (new_ck, mk)
}

/// Advance a chain key by `steps` steps, returning the final chain key: the
/// chain key of `steps` applications of `kdf_chain_step`. Used for skipping
/// messages.
pub fn kdf_chain_advance<D: DoubleRatchetDeps>(ck: &[u8; 32], steps: usize) -> [u8; 32] {
    let mut current = *ck;
    for _i in 0..steps {
        let (next_ck, _mk) = kdf_chain_step::<D>(&current);
        current = next_ck;
    }
    current
}

/// The [`typestate_fsm::DoubleRatchetOps`] of a dependency: the session FSM
/// over `kdf_ck`, `kdf_rk` and `dh` of `D`.
pub struct Ops<D>(core::marker::PhantomData<D>);

impl<D: DoubleRatchetDeps> typestate_fsm::DoubleRatchetOps for Ops<D> {
    fn kdf_ck(chain_key: &[u8; 32], constant: u8) -> [u8; 32] {
        kdf_ck::<D>(chain_key, constant)
    }
    fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        kdf_rk::<D>(root_key, dh_output)
    }
    fn dh(my_sk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32] {
        dh::<D>(my_sk, their_pk)
    }
}

// =========================================================================
// Ratchet state
// =========================================================================

/// Message header sent alongside each ciphertext.
///
/// Contains the sender's current DH public key and the message number
/// in the current sending chain.
#[derive(Clone, Copy)]
pub struct MessageHeader {
    /// Sender's current DH ratchet public key.
    pub dh_public: [u8; 32],
    /// Message number in the current sending chain (0-indexed).
    pub msg_number: u32,
    /// Number of messages in the previous sending chain.
    pub prev_chain_len: u32,
}

/// Double Ratchet state for one party.
///
/// Contains root key, sending/receiving chain keys, message counters,
/// and the party's current DH key pair.
#[derive(Clone, Copy)]
pub struct RatchetState {
    /// Root key: used in the DH ratchet to derive new chain keys.
    pub root_key: [u8; 32],
    /// Sending chain key: ratcheted for each outgoing message.
    pub send_ck: [u8; 32],
    /// Receiving chain key: ratcheted for each incoming message.
    pub recv_ck: [u8; 32],
    /// Number of messages sent in the current sending chain.
    pub send_n: u32,
    /// Number of messages received in the current receiving chain.
    pub recv_n: u32,
    /// Our current DH secret key.
    pub my_sk: [u8; 32],
    /// Our current DH public key.
    pub my_pk: [u8; 32],
    /// Remote party's current DH public key.
    pub remote_pk: [u8; 32],
    /// Number of messages sent in the previous sending chain.
    pub prev_send_n: u32,
}

/// Initialize a ratchet state for the initiator (Alice).
///
/// Alice has performed the initial DH exchange and knows:
/// - shared root key
/// - her own DH keypair
/// - Bob's DH public key
///
/// She derives the initial sending chain key via a DH ratchet step.
pub fn ratchet_init_initiator<D: DoubleRatchetDeps>(
    root_key: &[u8; 32],
    my_sk: &[u8; 32],
    my_pk: &[u8; 32],
    remote_pk: &[u8; 32],
) -> RatchetState {
    let dh_out = dh::<D>(my_sk, remote_pk);
    let (new_rk, send_ck) = kdf_rk::<D>(root_key, &dh_out);
    RatchetState {
        root_key: new_rk,
        send_ck,
        recv_ck: *root_key, // will be set on first DH ratchet
        send_n: 0,
        recv_n: 0,
        my_sk: *my_sk,
        my_pk: *my_pk,
        remote_pk: *remote_pk,
        prev_send_n: 0,
    }
}

/// Initialize a ratchet state for the responder (Bob).
///
/// Bob knows the shared root key and his own DH keypair.
/// He has not yet received Alice's first message, so the sending chain
/// is not yet initialized (it will be on the first DH ratchet).
pub fn ratchet_init_responder(
    root_key: &[u8; 32],
    my_sk: &[u8; 32],
    my_pk: &[u8; 32],
    remote_pk: &[u8; 32],
) -> RatchetState {
    RatchetState {
        root_key: *root_key,
        send_ck: *root_key, // placeholder, set on first DH ratchet
        recv_ck: *root_key, // placeholder, set on first received message
        send_n: 0,
        recv_n: 0,
        my_sk: *my_sk,
        my_pk: *my_pk,
        remote_pk: *remote_pk,
        prev_send_n: 0,
    }
}

// =========================================================================
// Encrypt / Decrypt (symmetric ratchet only)
// =========================================================================

/// Encrypt a plaintext using the symmetric ratchet.
///
/// 1. Ratchets the sending chain key to produce a message key.
/// 2. Encrypts the plaintext under the message key with the dependency's
///    `aead_encrypt`, the sender's DH public key as associated data.
/// 3. Returns updated state, message header, and ciphertext.
pub fn ratchet_encrypt<D: DoubleRatchetDeps>(
    state: &RatchetState,
    plaintext: &[u8],
    pt_len: usize,
) -> (RatchetState, MessageHeader, [u8; MAX_PLAINTEXT_LEN]) {
    // Step the sending chain
    let (new_send_ck, mk) = kdf_chain_step::<D>(&state.send_ck);

    // Build header
    let header = MessageHeader {
        dh_public: state.my_pk,
        msg_number: state.send_n,
        prev_chain_len: state.prev_send_n,
    };

    // Encrypt under the message key, the sender's DH public key as associated data
    let ciphertext = D::aead_encrypt(&mk, plaintext, pt_len, &state.my_pk);

    // Update state
    let new_state = RatchetState {
        root_key: state.root_key,
        send_ck: new_send_ck,
        recv_ck: state.recv_ck,
        send_n: state.send_n + 1,
        recv_n: state.recv_n,
        my_sk: state.my_sk,
        my_pk: state.my_pk,
        remote_pk: state.remote_pk,
        prev_send_n: state.prev_send_n,
    };

    (new_state, header, ciphertext)
}

/// Decrypt a ciphertext using the symmetric ratchet.
///
/// 1. Ratchets the receiving chain key to produce a message key.
/// 2. Decrypts the ciphertext under the message key with the dependency's
///    `aead_decrypt`, the header's DH public key as associated data.
/// 3. Returns updated state and plaintext.
///
/// This function does not handle out-of-order messages, does not perform a
/// DH ratchet step on a new remote DH key, and does not check that
/// `header.dh_public` equals `state.remote_pk`.
pub fn ratchet_decrypt<D: DoubleRatchetDeps>(
    state: &RatchetState,
    header: &MessageHeader,
    ciphertext: &[u8],
    ct_len: usize,
) -> (RatchetState, [u8; MAX_PLAINTEXT_LEN]) {
    // Step the receiving chain
    let (new_recv_ck, mk) = kdf_chain_step::<D>(&state.recv_ck);

    // Decrypt under the message key, the sender's DH public key as associated data
    let plaintext = D::aead_decrypt(&mk, ciphertext, ct_len, &header.dh_public);

    // Update state
    let new_state = RatchetState {
        root_key: state.root_key,
        send_ck: state.send_ck,
        recv_ck: new_recv_ck,
        send_n: state.send_n,
        recv_n: state.recv_n + 1,
        my_sk: state.my_sk,
        my_pk: state.my_pk,
        remote_pk: state.remote_pk,
        prev_send_n: state.prev_send_n,
    };

    (new_state, plaintext)
}

/// Perform a DH ratchet step upon receiving a new remote DH public key.
///
/// 1. Compute DH with our current secret key and the new remote public key.
/// 2. Derive new root key and receiving chain key.
/// 3. Take the caller's new DH keypair `(new_my_sk, new_my_pk)`.
/// 4. Compute DH with new secret key and remote public key.
/// 5. Derive new root key and sending chain key.
pub fn dh_ratchet_step<D: DoubleRatchetDeps>(
    state: &RatchetState,
    new_remote_pk: &[u8; 32],
    new_my_sk: &[u8; 32],
    new_my_pk: &[u8; 32],
) -> RatchetState {
    // First DH: derive receiving chain
    let dh_out1 = dh::<D>(&state.my_sk, new_remote_pk);
    let (rk1, new_recv_ck) = kdf_rk::<D>(&state.root_key, &dh_out1);

    // Second DH: derive sending chain with new keypair
    let dh_out2 = dh::<D>(new_my_sk, new_remote_pk);
    let (rk2, new_send_ck) = kdf_rk::<D>(&rk1, &dh_out2);

    RatchetState {
        root_key: rk2,
        send_ck: new_send_ck,
        recv_ck: new_recv_ck,
        send_n: 0,
        recv_n: 0,
        my_sk: *new_my_sk,
        my_pk: *new_my_pk,
        remote_pk: *new_remote_pk,
        prev_send_n: state.send_n,
    }
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
pub(crate) mod test_deps {
    //! A reference dependency for the unit tests: HMAC-SHA-256 and HKDF-SHA-256
    //! of RustCrypto, a byte-wise XOR in place of X25519 and the XOR keystream
    //! under the message key as encryption.
    use super::{DoubleRatchetDeps, MAX_PLAINTEXT_LEN};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    pub(crate) struct RefDeps;

    fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
        mac.update(msg);
        mac.finalize().into_bytes().into()
    }

    fn xor_stream(mk: &[u8; 32], data: &[u8], len: usize) -> [u8; MAX_PLAINTEXT_LEN] {
        let mut out = [0u8; MAX_PLAINTEXT_LEN];
        for i in 0..MAX_PLAINTEXT_LEN {
            if i < len {
                out[i] = data[i] ^ mk[i % 32];
            }
        }
        out
    }

    impl DoubleRatchetDeps for RefDeps {
        fn hmac_sha256(key: &[u8; 32], msg: &[u8; 32]) -> [u8; 32] {
            hmac(key, msg)
        }
        fn hkdf_extract(salt: &[u8; 32], ikm: &[u8; 32]) -> [u8; 32] {
            hmac(salt, ikm)
        }
        fn hkdf_expand(prk: &[u8; 32], info: &[u8; 32]) -> [u8; 32] {
            let mut m = [0u8; 33];
            m[..32].copy_from_slice(info);
            m[32] = 0x01;
            hmac(prk, &m)
        }
        fn x25519(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for i in 0..32 {
                out[i] = sk[i] ^ pk[i];
            }
            out
        }
        fn aead_encrypt(mk: &[u8; 32], pt: &[u8], len: usize, _ad: &[u8; 32])
            -> [u8; MAX_PLAINTEXT_LEN] {
            xor_stream(mk, pt, len)
        }
        fn aead_decrypt(mk: &[u8; 32], ct: &[u8], len: usize, _ad: &[u8; 32])
            -> [u8; MAX_PLAINTEXT_LEN] {
            xor_stream(mk, ct, len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_deps::RefDeps;
    use super::*;

    // --- KDF chain step tests ---

    #[test]
    fn test_kdf_chain_step_deterministic() {
        let ck: [u8; 32] = [0xaa; 32];
        let (ck1, mk1) = kdf_chain_step::<RefDeps>(&ck);
        let (ck2, mk2) = kdf_chain_step::<RefDeps>(&ck);
        assert_eq!(ck1, ck2, "chain step must be deterministic (CK)");
        assert_eq!(mk1, mk2, "chain step must be deterministic (MK)");
    }

    #[test]
    fn test_kdf_chain_step_ck_mk_differ() {
        let ck: [u8; 32] = [0xbb; 32];
        let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);
        assert_ne!(new_ck, mk, "chain key and message key must differ");
    }

    #[test]
    fn test_kdf_chain_step_differs_from_input() {
        let ck: [u8; 32] = [0xcc; 32];
        let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);
        assert_ne!(new_ck, ck, "new CK must differ from input CK");
        assert_ne!(mk, ck, "MK must differ from input CK");
    }
}
