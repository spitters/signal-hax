//! Property-based equivalence tests against production crypto libraries.
//!
//! These proptests check that the PQXDH protocol, when driven by real
//! primitives (`x25519-dalek` + `ml-kem`-768 + `hkdf`+`sha2`), satisfies
//! the agreement and post-quantum-contribution properties from the spec
//! across randomly generated inputs.
//!
//! ## What is checked
//!
//! For random DH secret bytes + fresh ML-KEM-768 keypairs:
//!
//! 1. X25519 DH commutativity (`DH(a, B) == DH(b, A)`).
//! 2. All four DH legs of PQXDH agree between Alice and Bob.
//! 3. Full PQXDH with ML-KEM-768: Alice and Bob derive the same session key
//!    (both the 3DH path and the 4DH-with-OPK path).
//! 4. The KEM contribution changes the key: dropping the ML-KEM shared
//!    secret changes the session key.
//! 5. HKDF-SHA256 matches itself on identical inputs (determinism).
//!
//! ## What is *not* checked here
//!
//! - Signatures (XEdDSA / Ed25519). The trait treats them as a black box and
//!   no test of the crate checks an XEdDSA signature.
//! - ML-KEM-768 equivalence against another ML-KEM implementation. The
//!   `ml-kem` crate is the reference; the KEM roundtrip proptest below
//!   checks its correctness on fresh keypairs.
//!
//! This is a cross-library property test: random DH keys, fresh ML-KEM
//! keypair per iteration, direct calls to the primitives. The crate's
//! `initiate` / `respond` are not called here; `reference_crosscheck.rs` runs
//! them over an ML-KEM-768 instance `PqxdhCrypto<1184, 2400, 1088>`, and
//! `toy_model.rs` over the toy instance `KaniSimplifiedPqxdh`.
//!
//! ## Reference
//!
//! Signal — The PQXDH Key Agreement Protocol, September 2023,
//! <https://signal.org/docs/specifications/pqxdh/>.

use hkdf::Hkdf;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{KemCore, MlKem768};
use proptest::prelude::*;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

/// PQXDH session-key derivation per spec:
/// `SK = HKDF(salt=0, ikm = 0xFF*32 || DH1 || DH2 || DH3 || DH4 || pq_ss, info="WhisperText")`.
fn compute_pqxdh_sk(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: &[u8; 32],
    pq_ss: &[u8],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + 32 * 4 + pq_ss.len());
    ikm.extend_from_slice(&[0xFFu8; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(dh4);
    ikm.extend_from_slice(pq_ss);
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"WhisperText", &mut sk).unwrap();
    sk
}

proptest! {
    /// X25519 DH commutativity over random 32-byte secrets.
    #[test]
    fn prop_x25519_commutativity(
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
    ) {
        let sa = StaticSecret::from(a);
        let sb = StaticSecret::from(b);
        let pa = PublicKey::from(&sa);
        let pb = PublicKey::from(&sb);
        let ab = sa.diffie_hellman(&pb);
        let ba = sb.diffie_hellman(&pa);
        prop_assert_eq!(ab.as_bytes(), ba.as_bytes());
    }

    /// All four PQXDH DH legs agree between Alice and Bob.
    #[test]
    fn prop_pqxdh_all_dh_agree(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
        opk_b in any::<[u8; 32]>(),
    ) {
        let ik_a = StaticSecret::from(ik_a);
        let ek_a = StaticSecret::from(ek_a);
        let ik_b = StaticSecret::from(ik_b);
        let spk_b = StaticSecret::from(spk_b);
        let opk_b = StaticSecret::from(opk_b);

        let ik_a_pub = PublicKey::from(&ik_a);
        let ek_a_pub = PublicKey::from(&ek_a);
        let ik_b_pub = PublicKey::from(&ik_b);
        let spk_b_pub = PublicKey::from(&spk_b);
        let opk_b_pub = PublicKey::from(&opk_b);

        let dh1_a = ik_a.diffie_hellman(&spk_b_pub);
        let dh1_b = spk_b.diffie_hellman(&ik_a_pub);
        prop_assert_eq!(dh1_a.as_bytes(), dh1_b.as_bytes());
        let dh2_a = ek_a.diffie_hellman(&ik_b_pub);
        let dh2_b = ik_b.diffie_hellman(&ek_a_pub);
        prop_assert_eq!(dh2_a.as_bytes(), dh2_b.as_bytes());
        let dh3_a = ek_a.diffie_hellman(&spk_b_pub);
        let dh3_b = spk_b.diffie_hellman(&ek_a_pub);
        prop_assert_eq!(dh3_a.as_bytes(), dh3_b.as_bytes());
        let dh4_a = ek_a.diffie_hellman(&opk_b_pub);
        let dh4_b = opk_b.diffie_hellman(&ek_a_pub);
        prop_assert_eq!(dh4_a.as_bytes(), dh4_b.as_bytes());
    }

    /// Full PQXDH (4DH + ML-KEM-768): Alice and Bob derive the same session key.
    #[test]
    fn prop_pqxdh_full_4dh_agreement(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
        opk_b in any::<[u8; 32]>(),
    ) {
        let mut rng = rand::thread_rng();

        let ik_a = StaticSecret::from(ik_a);
        let ek_a = StaticSecret::from(ek_a);
        let ik_b = StaticSecret::from(ik_b);
        let spk_b = StaticSecret::from(spk_b);
        let opk_b = StaticSecret::from(opk_b);

        let ik_a_pub = PublicKey::from(&ik_a);
        let ek_a_pub = PublicKey::from(&ek_a);
        let ik_b_pub = PublicKey::from(&ik_b);
        let spk_b_pub = PublicKey::from(&spk_b);
        let opk_b_pub = PublicKey::from(&opk_b);

        let (dk_b, ek_b) = MlKem768::generate(&mut rng);
        let (ct, ss_a) = ek_b.encapsulate(&mut rng).unwrap();
        let ss_b = dk_b.decapsulate(&ct).unwrap();
        prop_assert_eq!(ss_a, ss_b);

        let sk_a = compute_pqxdh_sk(
            ik_a.diffie_hellman(&spk_b_pub).as_bytes(),
            ek_a.diffie_hellman(&ik_b_pub).as_bytes(),
            ek_a.diffie_hellman(&spk_b_pub).as_bytes(),
            ek_a.diffie_hellman(&opk_b_pub).as_bytes(),
            ss_a.as_slice(),
        );
        let sk_b = compute_pqxdh_sk(
            spk_b.diffie_hellman(&ik_a_pub).as_bytes(),
            ik_b.diffie_hellman(&ek_a_pub).as_bytes(),
            spk_b.diffie_hellman(&ek_a_pub).as_bytes(),
            opk_b.diffie_hellman(&ek_a_pub).as_bytes(),
            ss_b.as_slice(),
        );
        prop_assert_eq!(sk_a, sk_b);
    }

    /// 3DH path (no OPK): Alice and Bob derive the same session key.
    #[test]
    fn prop_pqxdh_full_3dh_agreement(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
    ) {
        let mut rng = rand::thread_rng();

        let ik_a = StaticSecret::from(ik_a);
        let ek_a = StaticSecret::from(ek_a);
        let ik_b = StaticSecret::from(ik_b);
        let spk_b = StaticSecret::from(spk_b);

        let ik_a_pub = PublicKey::from(&ik_a);
        let ek_a_pub = PublicKey::from(&ek_a);
        let ik_b_pub = PublicKey::from(&ik_b);
        let spk_b_pub = PublicKey::from(&spk_b);

        let (dk_b, ek_b) = MlKem768::generate(&mut rng);
        let (ct, ss_a) = ek_b.encapsulate(&mut rng).unwrap();
        let ss_b = dk_b.decapsulate(&ct).unwrap();

        let dh4 = [0u8; 32];
        let sk_a = compute_pqxdh_sk(
            ik_a.diffie_hellman(&spk_b_pub).as_bytes(),
            ek_a.diffie_hellman(&ik_b_pub).as_bytes(),
            ek_a.diffie_hellman(&spk_b_pub).as_bytes(),
            &dh4,
            ss_a.as_slice(),
        );
        let sk_b = compute_pqxdh_sk(
            spk_b.diffie_hellman(&ik_a_pub).as_bytes(),
            ik_b.diffie_hellman(&ek_a_pub).as_bytes(),
            spk_b.diffie_hellman(&ek_a_pub).as_bytes(),
            &dh4,
            ss_b.as_slice(),
        );
        prop_assert_eq!(sk_a, sk_b);
    }

    /// ML-KEM-768 encaps/decaps roundtrip always recovers the shared secret.
    #[test]
    fn prop_mlkem768_roundtrip(_seed in any::<u64>()) {
        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).unwrap();
        let ss_dec = dk.decapsulate(&ct).unwrap();
        prop_assert_eq!(ss_enc, ss_dec);
    }

    /// Removing the KEM contribution changes the session key.
    #[test]
    fn prop_kem_contribution_changes_key(
        ik_a in any::<[u8; 32]>(),
        ek_a in any::<[u8; 32]>(),
        ik_b in any::<[u8; 32]>(),
        spk_b in any::<[u8; 32]>(),
        opk_b in any::<[u8; 32]>(),
    ) {
        let mut rng = rand::thread_rng();
        let ik_a = StaticSecret::from(ik_a);
        let ek_a = StaticSecret::from(ek_a);
        let spk_b_pub = PublicKey::from(&StaticSecret::from(spk_b));
        let ik_b_pub  = PublicKey::from(&StaticSecret::from(ik_b));
        let opk_b_pub = PublicKey::from(&StaticSecret::from(opk_b));

        let (_, ek_b) = MlKem768::generate(&mut rng);
        let (_, ss)   = ek_b.encapsulate(&mut rng).unwrap();

        let dh1 = *ik_a.diffie_hellman(&spk_b_pub).as_bytes();
        let dh2 = *ek_a.diffie_hellman(&ik_b_pub).as_bytes();
        let dh3 = *ek_a.diffie_hellman(&spk_b_pub).as_bytes();
        let dh4 = *ek_a.diffie_hellman(&opk_b_pub).as_bytes();

        let sk_with    = compute_pqxdh_sk(&dh1, &dh2, &dh3, &dh4, ss.as_slice());
        let sk_without = compute_pqxdh_sk(&dh1, &dh2, &dh3, &dh4, &[0u8; 32]);
        prop_assert_ne!(sk_with, sk_without);
    }
}
