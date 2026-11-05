//! Property-based equivalence tests against RustCrypto.
//!
//! `doubleratchet-hax` calls its primitives through the `DoubleRatchetDeps`
//! trait; these proptests run the crate over the reference dependency of
//! `tests/common` (RustCrypto `sha2`/`hmac`) and check the KDF chain against
//! RustCrypto on random inputs, plus a handful of property-level invariants on
//! the KDF chain and the ratchet encrypt/decrypt path.
//!
//! ## What is *not* checked here
//!
//! The X25519 of the reference dependency is a stub (`dh::<RefDeps>(a, b) =
//! a XOR b`, see `tests/common/mod.rs`) and its cipher is a stream XOR under
//! the HMAC-derived message key; neither is real DH nor real AEAD. The
//! proptests below therefore assert structural properties of the KDF chain and
//! the ratchet functions, not cryptographic security.
//!
//! ## References
//!
//! - FIPS 180-4 — SHA-256
//! - RFC 2104 — HMAC
//! - Signal — Double Ratchet Algorithm, <https://signal.org/docs/specifications/doubleratchet/>

mod common;
use common::RefDeps;
use doubleratchet_hax::*;
use hmac::{Hmac, Mac};
use proptest::prelude::*;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

proptest! {
    /// The chain-key KDF over the reference dependency agrees with
    /// `hmac::Hmac<Sha256>` on the constant block `[c; 32]`.
    #[test]
    fn prop_kdf_ck_matches_rustcrypto(ck in any::<[u8; 32]>(), c in any::<u8>()) {
        let ours = kdf_ck::<RefDeps>(&ck, c);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&ck).unwrap();
        mac.update(&[c; 32]);
        let theirs: [u8; 32] = mac.finalize().into_bytes().into();
        prop_assert_eq!(ours, theirs);
    }

    /// `kdf_ck` domain separation: `kdf_ck::<RefDeps>(_, 0x01) != kdf_ck::<RefDeps>(_, 0x02)`.
    #[test]
    fn prop_kdf_ck_domain_separation(ck in any::<[u8; 32]>()) {
        let chain_next = kdf_ck::<RefDeps>(&ck, 0x01);
        let msg_key    = kdf_ck::<RefDeps>(&ck, 0x02);
        prop_assert_ne!(chain_next, msg_key);
    }

    /// `kdf_chain_step` matches the component-wise KDF with constants 1, 2.
    #[test]
    fn prop_kdf_chain_step_matches_components(ck in any::<[u8; 32]>()) {
        let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);
        prop_assert_eq!(new_ck, kdf_ck::<RefDeps>(&ck, 0x01));
        prop_assert_eq!(mk,     kdf_ck::<RefDeps>(&ck, 0x02));
    }

    /// `kdf_rk` yields disjoint root and chain keys: new_rk != new_ck.
    #[test]
    fn prop_kdf_rk_domain_separation(
        rk in any::<[u8; 32]>(),
        dh in any::<[u8; 32]>(),
    ) {
        let (new_rk, new_ck) = kdf_rk::<RefDeps>(&rk, &dh);
        prop_assert_ne!(new_rk, new_ck);
    }

    /// `kdf_chain_advance::<RefDeps>(_, n)` iterates `kdf_chain_step` n times.
    #[test]
    fn prop_kdf_chain_advance_equals_iterated_step(
        ck in any::<[u8; 32]>(),
        n in 0usize..16,
    ) {
        let advanced = kdf_chain_advance::<RefDeps>(&ck, n);
        let mut iterated = ck;
        for _ in 0..n {
            let (next, _mk) = kdf_chain_step::<RefDeps>(&iterated);
            iterated = next;
        }
        prop_assert_eq!(advanced, iterated);
    }

    /// Encrypt then decrypt on the same ratchet state recovers the plaintext.
    ///
    /// We share one `RatchetState` between sender and receiver and advance
    /// both chains in lockstep — this is a structural roundtrip test of the
    /// KDF chain + XOR stream cipher, not a protocol-agreement test.
    #[test]
    fn prop_encrypt_decrypt_roundtrip(
        root in any::<[u8; 32]>(),
        ck   in any::<[u8; 32]>(),
        dh   in any::<[u8; 32]>(),
        pt   in prop::collection::vec(any::<u8>(), 0..=MAX_PLAINTEXT_LEN),
    ) {
        let state = RatchetState {
            root_key: root,
            send_ck: ck,
            recv_ck: ck,
            send_n: 0,
            recv_n: 0,
            my_sk: dh,
            my_pk: dh,
            remote_pk: dh,
            prev_send_n: 0,
        };

        let (state_after_send, header, ct) = ratchet_encrypt::<RefDeps>(&state, &pt, pt.len());
        let (_state_after_recv, recovered) = ratchet_decrypt::<RefDeps>(&state, &header, &ct, pt.len());

        for i in 0..pt.len() {
            prop_assert_eq!(recovered[i], pt[i]);
        }
        prop_assert_eq!(state_after_send.send_n, 1);
    }
}
