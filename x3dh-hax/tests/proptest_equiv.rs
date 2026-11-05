//! Property-based equivalence tests against production crypto libraries.
//!
//! For randomly generated 32-byte inputs, these tests check byte-level
//! agreement between:
//!
//! 1. `initiate::<RealX3dh>` / `respond::<RealX3dh>`, where `RealX3dh`
//!    instantiates the `X3dhCrypto` trait with `x25519-dalek` for DH and
//!    `hkdf`+`sha2` for the KDF, **and**
//! 2. A reference computation that calls the same production primitives
//!    directly in the X3DH formula.
//!
//! `cross_lib.rs` computes the formula on fixed inputs without calling the
//! crate's functions; this file runs the crate's functions on random inputs.
//!
//! ## What is *not* checked here
//!
//! - Signatures. The SPK signature path in X3DH uses XEdDSA on X25519 keys,
//!   which is its own primitive; the trait treats it as a black box. This
//!   test stubs `sign`/`verify` so that the DH/KDF equivalence is isolated.
//! - Equivalence to `libsignal-protocol`. No test of the crate runs against it.
//!
//! ## Reference
//!
//! Signal — The X3DH Key Agreement Protocol, November 2016 (revised 2024),
//! <https://signal.org/docs/specifications/x3dh/>.

use hkdf::Hkdf;
use proptest::prelude::*;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use x3dh_hax::*;

// ============================================================
// RealX3dh: X3dhCrypto backed by x25519-dalek + HKDF-SHA256
// ============================================================

#[derive(Clone, Copy)]
struct RealX3dh;

impl X3dhCrypto for RealX3dh {
    fn dh(secret: &X3dhKey, peer_pub: &X3dhKey) -> X3dhKey {
        let s = StaticSecret::from(*secret);
        let p = PublicKey::from(*peer_pub);
        *s.diffie_hellman(&p).as_bytes()
    }

    fn dh_pub(secret: &X3dhKey) -> X3dhKey {
        let s = StaticSecret::from(*secret);
        *PublicKey::from(&s).as_bytes()
    }

    fn kdf(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey, dh4: &X3dhKey) -> X3dhSessionKey {
        kdf_4(dh1, dh2, dh3, dh4)
    }

    // Signatures are out of scope for this equivalence test.
    fn sign(_ik_secret: &X3dhKey, _msg: &X3dhKey) -> X3dhSignature {
        [0u8; 64]
    }

    fn verify(_ik_pub: &X3dhKey, _msg: &X3dhKey, _sig: &X3dhSignature) -> bool {
        true
    }
}

/// X3DH KDF per spec: `SK = HKDF(salt=0, ikm = 0xFF*32 || DH1||DH2||DH3||DH4, info = "WhisperText")`.
///
/// The trait's `kdf` has fixed arity 4, so when no OPK is available the caller
/// pads with `ZERO_KEY`. This helper matches that convention exactly — which
/// is why the reference computation below also pads with zeros rather than
/// omitting the fourth DH, as `cross_lib.rs` does.
fn kdf_4(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32], dh4: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 32 + 32 * 4];
    ikm[..32].fill(0xFF);
    ikm[32..64].copy_from_slice(dh1);
    ikm[64..96].copy_from_slice(dh2);
    ikm[96..128].copy_from_slice(dh3);
    ikm[128..160].copy_from_slice(dh4);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"WhisperText", &mut sk).unwrap();
    sk
}

/// Reference: compute the X3DH session key by calling x25519-dalek + HKDF
/// directly, without going through `initiate` / `respond`.
fn reference_sk(
    ik_a: &X3dhKey,
    ek_a: &X3dhKey,
    ik_b_pub: &X3dhKey,
    spk_b_pub: &X3dhKey,
    opk_b_pub: &X3dhKey,
    use_opk: bool,
) -> X3dhSessionKey {
    let ik_a_s = StaticSecret::from(*ik_a);
    let ek_a_s = StaticSecret::from(*ek_a);
    let dh1 = *ik_a_s.diffie_hellman(&PublicKey::from(*spk_b_pub)).as_bytes();
    let dh2 = *ek_a_s.diffie_hellman(&PublicKey::from(*ik_b_pub)).as_bytes();
    let dh3 = *ek_a_s.diffie_hellman(&PublicKey::from(*spk_b_pub)).as_bytes();
    let dh4 = if use_opk {
        *ek_a_s.diffie_hellman(&PublicKey::from(*opk_b_pub)).as_bytes()
    } else {
        [0u8; 32]
    };
    kdf_4(&dh1, &dh2, &dh3, &dh4)
}

// ============================================================
// Proptest suite
// ============================================================

proptest! {
    /// `dh_pub` matches `PublicKey::from(StaticSecret::from(_))` bytewise.
    #[test]
    fn prop_dh_pub_matches_dalek(secret in any::<[u8; 32]>()) {
        let via_trait = RealX3dh::dh_pub(&secret);
        let via_dalek = *PublicKey::from(&StaticSecret::from(secret)).as_bytes();
        prop_assert_eq!(via_trait, via_dalek);
    }

    /// Bilateral DH agreement via the trait matches a direct x25519-dalek call.
    #[test]
    fn prop_dh_agreement_matches_dalek(
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
    ) {
        let a_pub = RealX3dh::dh_pub(&a);
        let b_pub = RealX3dh::dh_pub(&b);

        let via_trait_ab = RealX3dh::dh(&a, &b_pub);
        let via_trait_ba = RealX3dh::dh(&b, &a_pub);
        prop_assert_eq!(via_trait_ab, via_trait_ba, "DH commutativity");

        let via_dalek = *StaticSecret::from(a)
            .diffie_hellman(&PublicKey::from(b_pub))
            .as_bytes();
        prop_assert_eq!(via_trait_ab, via_dalek);
    }

    /// `initiate::<RealX3dh>` (4DH path) produces the same session key as a
    /// direct x25519-dalek + HKDF computation.
    #[test]
    fn prop_initiate_4dh_equivalent(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
        opk_b in any::<[u8; 32]>(),
    ) {
        let ik_b_pub  = RealX3dh::dh_pub(&ik_b);
        let spk_b_pub = RealX3dh::dh_pub(&spk_b);
        let opk_b_pub = RealX3dh::dh_pub(&opk_b);
        let bundle = X3dhPreKeyBundle {
            ik: ik_b_pub, spk: spk_b_pub, opk: opk_b_pub, sig: ZERO_SIGNATURE,
        };

        let (sk_hax, _msg, _sig_valid) =
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, true);
        let sk_ref = reference_sk(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, &opk_b_pub, true);
        prop_assert_eq!(sk_hax, sk_ref);
    }

    /// `initiate::<RealX3dh>` (3DH path, OPK absent) matches the reference.
    #[test]
    fn prop_initiate_3dh_equivalent(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
    ) {
        let ik_b_pub  = RealX3dh::dh_pub(&ik_b);
        let spk_b_pub = RealX3dh::dh_pub(&spk_b);
        let bundle = X3dhPreKeyBundle {
            ik: ik_b_pub, spk: spk_b_pub, opk: ZERO_KEY, sig: ZERO_SIGNATURE,
        };

        let (sk_hax, _msg, _sig_valid) =
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, false);
        let sk_ref = reference_sk(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, &ZERO_KEY, false);
        prop_assert_eq!(sk_hax, sk_ref);
    }

    /// Alice and Bob derive identical session keys under `RealX3dh`, for both
    /// 3DH and 4DH variants.
    #[test]
    fn prop_alice_bob_agree(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
        opk_b in any::<[u8; 32]>(),
        use_opk in any::<bool>(),
    ) {
        let ik_b_pub  = RealX3dh::dh_pub(&ik_b);
        let spk_b_pub = RealX3dh::dh_pub(&spk_b);
        let opk_b_pub = RealX3dh::dh_pub(&opk_b);
        let bundle = X3dhPreKeyBundle {
            ik: ik_b_pub, spk: spk_b_pub, opk: opk_b_pub, sig: ZERO_SIGNATURE,
        };

        let (sk_a, msg, _sig_valid) =
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, use_opk);
        let sk_b = respond::<RealX3dh>(&ik_b, &spk_b, &opk_b, &msg, use_opk);
        prop_assert_eq!(sk_a, sk_b);
    }
}
