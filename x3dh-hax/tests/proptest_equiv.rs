//! Property-based equivalence tests against production crypto libraries.
//!
//! For randomly generated 32-byte inputs, these tests check byte-level
//! agreement between:
//!
//! 1. `initiate::<RealX3dh>` / `respond::<RealX3dh>`, where `RealX3dh`
//!    instantiates the `X3dhCrypto` trait with `x25519-dalek` for DH and
//!    `hkdf`+`sha2` for the KDF (HKDF-SHA256 with the info `"WhisperText"`,
//!    as in `cross_lib.rs`), **and**
//! 2. A reference computation that calls the same production primitives
//!    directly in the X3DH formula.
//!
//! It also checks the input check: peer public keys outside the prime-order
//! subgroup (twist points, points with a component of order 8) and the
//! identity `0` make `initiate` and `respond` return `None`
//! (`prop_peer_keys_outside_subgroup_rejected`, `prop_identity_rejected`).
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

use curve25519_dalek::constants::EIGHT_TORSION;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::{EdwardsPoint, Scalar};
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

    fn kdf3(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey) -> X3dhSessionKey {
        kdf_3(dh1, dh2, dh3)
    }

    // Signatures are out of scope for this equivalence test.
    fn sign(_ik_secret: &X3dhKey, _msg: &X3dhKey) -> X3dhSignature {
        [0u8; 64]
    }

    fn verify(_ik_pub: &X3dhKey, _msg: &X3dhKey, _sig: &X3dhSignature) -> bool {
        true
    }

    fn valid_pub(pk: &X3dhKey) -> bool {
        x3dh_hax::subgroup::valid_pub(pk)
    }
}

/// HKDF info string of the KDF, as in `cross_lib.rs`.
const KDF_INFO: &[u8] = b"WhisperText";

/// X3DH KDF with a one-time prekey:
/// `SK = HKDF(salt=0, ikm = 0xFF*32 || DH1||DH2||DH3||DH4, info = "WhisperText")`.
fn kdf_4(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32], dh4: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 32 + 32 * 4];
    ikm[..32].fill(0xFF);
    ikm[32..64].copy_from_slice(dh1);
    ikm[64..96].copy_from_slice(dh2);
    ikm[96..128].copy_from_slice(dh3);
    ikm[128..160].copy_from_slice(dh4);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(KDF_INFO, &mut sk).unwrap();
    sk
}

/// X3DH KDF without a one-time prekey:
/// `SK = HKDF(salt=0, ikm = 0xFF*32 || DH1||DH2||DH3, info = "WhisperText")`.
fn kdf_3(dh1: &[u8; 32], dh2: &[u8; 32], dh3: &[u8; 32]) -> [u8; 32] {
    let mut ikm = [0u8; 32 + 32 * 3];
    ikm[..32].fill(0xFF);
    ikm[32..64].copy_from_slice(dh1);
    ikm[64..96].copy_from_slice(dh2);
    ikm[96..128].copy_from_slice(dh3);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(KDF_INFO, &mut sk).unwrap();
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
    if use_opk {
        let dh4 = *ek_a_s.diffie_hellman(&PublicKey::from(*opk_b_pub)).as_bytes();
        kdf_4(&dh1, &dh2, &dh3, &dh4)
    } else {
        kdf_3(&dh1, &dh2, &dh3)
    }
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
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, true)
                .expect("X25519 public keys pass the input check");
        let sk_ref =
            reference_sk(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, &opk_b_pub, true);
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
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, false)
                .expect("X25519 public keys pass the input check");
        let sk_ref =
            reference_sk(&ik_a, &ek_a, &ik_b_pub, &spk_b_pub, &ZERO_KEY, false);
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
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, use_opk)
                .expect("X25519 public keys pass the input check");
        let sk_b = respond::<RealX3dh>(&ik_b, &spk_b, &opk_b, &msg, use_opk)
            .expect("X25519 public keys pass the input check");
        prop_assert_eq!(sk_a, sk_b);
    }

    /// A bundle with a public key outside the prime-order subgroup (a point of
    /// the twist, or a subgroup point plus a point of order 8) is rejected by
    /// `initiate`, and an initial message with such a key by `respond`.
    #[test]
    fn prop_peer_keys_outside_subgroup_rejected(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
        opk_b in any::<[u8; 32]>(),
        bad_seed in any::<[u8; 32]>(),
        twist in any::<bool>(),
        slot in 0usize..3,
    ) {
        let bad = if twist { twist_point(&bad_seed) } else { torsion_point(&bad_seed) };
        prop_assert!(!RealX3dh::valid_pub(&bad));
        let mut bundle = X3dhPreKeyBundle {
            ik: RealX3dh::dh_pub(&ik_b),
            spk: RealX3dh::dh_pub(&spk_b),
            opk: RealX3dh::dh_pub(&opk_b),
            sig: ZERO_SIGNATURE,
        };
        let (_, msg, _) = initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, true)
            .expect("X25519 public keys pass the input check");
        match slot {
            0 => bundle.ik = bad,
            1 => bundle.spk = bad,
            _ => bundle.opk = bad,
        }
        prop_assert!(initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, true).is_none());
        // Without the one-time prekey, its key is not decoded.
        prop_assert_eq!(
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, false).is_none(),
            slot != 2
        );
        let bad_msg = if slot == 0 {
            X3dhInitMessage { ik_a: bad, ..msg }
        } else {
            X3dhInitMessage { ek_a: bad, ..msg }
        };
        prop_assert!(respond::<RealX3dh>(&ik_b, &spk_b, &opk_b, &bad_msg, true).is_none());
        prop_assert!(respond::<RealX3dh>(&ik_b, &spk_b, &opk_b, &msg, true).is_some());
    }

    /// The identity `0` is a point of the subgroup and fails the input check:
    /// a bundle carrying it as `ik`, `spk` or (when used) `opk` is rejected by
    /// `initiate`, and an initial message carrying it as `ik_a` or `ek_a` by
    /// `respond`, with and without the one-time prekey.
    #[test]
    fn prop_identity_rejected(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
        opk_b in any::<[u8; 32]>(),
        slot in 0usize..3,
        use_opk in any::<bool>(),
    ) {
        let id = [0u8; 32];
        prop_assert!(x3dh_hax::subgroup::is_subgroup_point(&id));
        prop_assert!(!RealX3dh::valid_pub(&id));
        let mut bundle = X3dhPreKeyBundle {
            ik: RealX3dh::dh_pub(&ik_b),
            spk: RealX3dh::dh_pub(&spk_b),
            opk: RealX3dh::dh_pub(&opk_b),
            sig: ZERO_SIGNATURE,
        };
        let (_, msg, _) = initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, use_opk)
            .expect("X25519 public keys pass the input check");
        match slot {
            0 => bundle.ik = id,
            1 => bundle.spk = id,
            _ => bundle.opk = id,
        }
        prop_assert_eq!(
            initiate::<RealX3dh>(&ik_a, &ek_a, &bundle, use_opk).is_none(),
            slot != 2 || use_opk
        );
        let id_msg = if slot == 0 {
            X3dhInitMessage { ik_a: id, ..msg }
        } else {
            X3dhInitMessage { ek_a: id, ..msg }
        };
        prop_assert!(respond::<RealX3dh>(&ik_b, &spk_b, &opk_b, &id_msg, use_opk).is_none());
    }
}

/// The u-coordinate of a point of the quadratic twist: the first canonical
/// string from `seed` on that `MontgomeryPoint::to_edwards` finds no point of
/// the curve (strings below `p`, bit 255 clear).
fn twist_point(seed: &[u8; 32]) -> X3dhKey {
    let mut u = *seed;
    u[31] &= 0x3f;
    loop {
        if MontgomeryPoint(u).to_edwards(0).is_none() {
            return u;
        }
        u[0] = u[0].wrapping_add(1);
        if u[0] == 0 {
            u[1] = u[1].wrapping_add(1);
        }
    }
}

/// The u-coordinate of `s B + T` for the scalar of `seed` and a point `T` of
/// order 8.
fn torsion_point(seed: &[u8; 32]) -> X3dhKey {
    let s = Scalar::from_bytes_mod_order(*seed);
    let p = EdwardsPoint::mul_base(&s) + EIGHT_TORSION[1];
    p.to_montgomery().to_bytes()
}
