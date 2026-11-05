//! Cross-library validation tests for PQXDH.
//!
//! Tests the PQXDH protocol structure against real cryptographic libraries:
//! - `x25519-dalek` for X25519 DH operations
//! - `ml-kem` (RustCrypto) for ML-KEM-768 key encapsulation
//! - `hkdf` + `sha2` for HKDF-SHA256 key derivation
//!
//! These tests compute the PQXDH formula directly with these libraries; they do
//! not call the crate's protocol functions. They also check the X25519 test
//! vector of RFC 7748 §6.1 and the HKDF-SHA256 test cases 1 and 3 of RFC 5869
//! Appendix A.
//!
//! ## Reference
//!
//! Signal — The PQXDH Key Agreement Protocol, September 2023
//! https://signal.org/docs/specifications/pqxdh/

use x25519_dalek::{StaticSecret, PublicKey};
use ml_kem::{MlKem768, KemCore};
use ml_kem::kem::{Encapsulate, Decapsulate};
use hkdf::Hkdf;
use sha2::Sha256;

// ============================================================
// 1. X25519 DH commutativity (PQXDH's classical component)
// ============================================================

#[test]
fn cross_x25519_dh_commutativity() {
    let a = StaticSecret::from([10u8; 32]);
    let b = StaticSecret::from([40u8; 32]);
    let ga = PublicKey::from(&a);
    let gb = PublicKey::from(&b);
    let gab = a.diffie_hellman(&gb);
    let gba = b.diffie_hellman(&ga);
    assert_eq!(gab.as_bytes(), gba.as_bytes(), "X25519 DH commutativity");
}

// ============================================================
// 2. All 4 DH operations in PQXDH match between Alice and Bob
// ============================================================

#[test]
fn cross_pqxdh_4dh_structure() {
    let ik_a = StaticSecret::from([10u8; 32]);
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);
    let opk_b = StaticSecret::from([50u8; 32]);

    let ik_a_pub = PublicKey::from(&ik_a);
    let ek_a_pub = PublicKey::from(&ek_a);
    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);
    let opk_b_pub = PublicKey::from(&opk_b);

    // Alice's side
    let dh1_a = ik_a.diffie_hellman(&spk_b_pub);
    let dh2_a = ek_a.diffie_hellman(&ik_b_pub);
    let dh3_a = ek_a.diffie_hellman(&spk_b_pub);
    let dh4_a = ek_a.diffie_hellman(&opk_b_pub);

    // Bob's side
    let dh1_b = spk_b.diffie_hellman(&ik_a_pub);
    let dh2_b = ik_b.diffie_hellman(&ek_a_pub);
    let dh3_b = spk_b.diffie_hellman(&ek_a_pub);
    let dh4_b = opk_b.diffie_hellman(&ek_a_pub);

    assert_eq!(dh1_a.as_bytes(), dh1_b.as_bytes(), "DH1: DH(IK_A, SPK_B)");
    assert_eq!(dh2_a.as_bytes(), dh2_b.as_bytes(), "DH2: DH(EK_A, IK_B)");
    assert_eq!(dh3_a.as_bytes(), dh3_b.as_bytes(), "DH3: DH(EK_A, SPK_B)");
    assert_eq!(dh4_a.as_bytes(), dh4_b.as_bytes(), "DH4: DH(EK_A, OPK_B)");
}

// ============================================================
// 3. ML-KEM-768 encaps/decaps roundtrip
// ============================================================

#[test]
fn cross_mlkem768_roundtrip() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, ss_enc) = ek.encapsulate(&mut rng).unwrap();
    let ss_dec = dk.decapsulate(&ct).unwrap();
    assert_eq!(ss_enc, ss_dec, "ML-KEM-768 encaps/decaps roundtrip");
}

#[test]
fn cross_mlkem768_multiple_roundtrips() {
    let mut rng = rand::thread_rng();
    for _ in 0..5 {
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss_enc) = ek.encapsulate(&mut rng).unwrap();
        let ss_dec = dk.decapsulate(&ct).unwrap();
        assert_eq!(ss_enc, ss_dec, "ML-KEM-768 roundtrip");
    }
}

#[test]
fn cross_mlkem768_different_keypairs_different_keys() {
    let mut rng = rand::thread_rng();
    let (_, ek1) = MlKem768::generate(&mut rng);
    let (_, ek2) = MlKem768::generate(&mut rng);
    let (_, ss1) = ek1.encapsulate(&mut rng).unwrap();
    let (_, ss2) = ek2.encapsulate(&mut rng).unwrap();
    // Different keypairs should (with overwhelming probability) give different shared secrets
    assert_ne!(ss1, ss2, "different KEM keypairs => different shared secrets");
}

// ============================================================
// 4. ML-KEM shared secret is 32 bytes
// ============================================================

#[test]
fn cross_mlkem768_ss_size() {
    let mut rng = rand::thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);
    let (ct, ss_enc) = ek.encapsulate(&mut rng).unwrap();
    let ss_dec = dk.decapsulate(&ct).unwrap();
    // ML-KEM shared secret is 32 bytes, matching our PqxdhKemSs type
    assert_eq!(ss_enc.as_slice().len(), 32, "ML-KEM-768 shared secret = 32 bytes");
    assert_eq!(ss_dec.as_slice().len(), 32, "decaps shared secret = 32 bytes");
}

// ============================================================
// 5. HKDF-SHA256 determinism
// ============================================================

#[test]
fn cross_hkdf_sha256_determinism() {
    let ikm = [0x42u8; 64];
    let salt = [0u8; 32];
    let info = b"WhisperText";

    let hk1 = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut out1 = [0u8; 32];
    hk1.expand(info, &mut out1).unwrap();

    let hk2 = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut out2 = [0u8; 32];
    hk2.expand(info, &mut out2).unwrap();

    assert_eq!(out1, out2, "HKDF-SHA256 is deterministic");
}

#[test]
fn cross_hkdf_sha256_different_inputs() {
    let info = b"WhisperText";

    let ikm1 = [0x42u8; 64];
    let ikm2 = [0x43u8; 64];

    let hk1 = Hkdf::<Sha256>::new(None, &ikm1);
    let mut out1 = [0u8; 32];
    hk1.expand(info, &mut out1).unwrap();

    let hk2 = Hkdf::<Sha256>::new(None, &ikm2);
    let mut out2 = [0u8; 32];
    hk2.expand(info, &mut out2).unwrap();

    assert_ne!(out1, out2, "different IKM => different HKDF output");
}

// ============================================================
// 6. Full PQXDH protocol with real crypto (main validation)
// ============================================================

/// Compute the PQXDH session key with real crypto libraries.
///
/// SK = HKDF(salt=0, ikm = 0xFF*32 || DH1 || DH2 || DH3 || DH4 || pq_ss,
///           info = "WhisperText")
///
/// The info string is the one the tests of this crate use; the PQXDH
/// specification leaves it to the application.
fn compute_pqxdh_sk(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: &[u8; 32],
    pq_ss: &[u8],
) -> [u8; 32] {
    // Per Signal spec: prepend 0xFF * 32 padding
    let mut ikm = Vec::with_capacity(32 + 32 * 4 + pq_ss.len());
    ikm.extend_from_slice(&[0xFFu8; 32]); // F-byte padding
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    ikm.extend_from_slice(dh4);
    ikm.extend_from_slice(pq_ss);

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    // The tests of this crate use info = "WhisperText".
    hk.expand(b"WhisperText", &mut sk).unwrap();
    sk
}

#[test]
fn cross_pqxdh_full_protocol_with_opk() {
    let mut rng = rand::thread_rng();

    // Key generation
    let ik_a = StaticSecret::from([10u8; 32]);
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);
    let opk_b = StaticSecret::from([50u8; 32]);

    let ik_a_pub = PublicKey::from(&ik_a);
    let ek_a_pub = PublicKey::from(&ek_a);
    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);
    let opk_b_pub = PublicKey::from(&opk_b);

    // ML-KEM-768 keypair for Bob
    let (dk_b, ek_b) = MlKem768::generate(&mut rng);

    // === Alice's side ===
    let dh1_a = ik_a.diffie_hellman(&spk_b_pub);
    let dh2_a = ek_a.diffie_hellman(&ik_b_pub);
    let dh3_a = ek_a.diffie_hellman(&spk_b_pub);
    let dh4_a = ek_a.diffie_hellman(&opk_b_pub);
    let (ct, kem_ss_a) = ek_b.encapsulate(&mut rng).unwrap();

    let sk_a = compute_pqxdh_sk(
        dh1_a.as_bytes(), dh2_a.as_bytes(),
        dh3_a.as_bytes(), dh4_a.as_bytes(),
        kem_ss_a.as_slice(),
    );

    // === Bob's side ===
    let dh1_b = spk_b.diffie_hellman(&ik_a_pub);
    let dh2_b = ik_b.diffie_hellman(&ek_a_pub);
    let dh3_b = spk_b.diffie_hellman(&ek_a_pub);
    let dh4_b = opk_b.diffie_hellman(&ek_a_pub);
    let kem_ss_b = dk_b.decapsulate(&ct).unwrap();

    let sk_b = compute_pqxdh_sk(
        dh1_b.as_bytes(), dh2_b.as_bytes(),
        dh3_b.as_bytes(), dh4_b.as_bytes(),
        kem_ss_b.as_slice(),
    );

    // Both sides must agree
    assert_eq!(sk_a, sk_b, "PQXDH full protocol: Alice and Bob derive same session key");
    assert_ne!(sk_a, [0u8; 32], "session key is non-zero");
}

#[test]
fn cross_pqxdh_full_protocol_without_opk() {
    let mut rng = rand::thread_rng();

    let ik_a = StaticSecret::from([10u8; 32]);
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);

    let ik_a_pub = PublicKey::from(&ik_a);
    let ek_a_pub = PublicKey::from(&ek_a);
    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);

    let (dk_b, ek_b) = MlKem768::generate(&mut rng);

    // Alice (3DH: no OPK)
    let dh1_a = ik_a.diffie_hellman(&spk_b_pub);
    let dh2_a = ek_a.diffie_hellman(&ik_b_pub);
    let dh3_a = ek_a.diffie_hellman(&spk_b_pub);
    let dh4_zero = [0u8; 32]; // no OPK
    let (ct, kem_ss_a) = ek_b.encapsulate(&mut rng).unwrap();

    let sk_a = compute_pqxdh_sk(
        dh1_a.as_bytes(), dh2_a.as_bytes(),
        dh3_a.as_bytes(), &dh4_zero,
        kem_ss_a.as_slice(),
    );

    // Bob (3DH: no OPK)
    let dh1_b = spk_b.diffie_hellman(&ik_a_pub);
    let dh2_b = ik_b.diffie_hellman(&ek_a_pub);
    let dh3_b = spk_b.diffie_hellman(&ek_a_pub);
    let kem_ss_b = dk_b.decapsulate(&ct).unwrap();

    let sk_b = compute_pqxdh_sk(
        dh1_b.as_bytes(), dh2_b.as_bytes(),
        dh3_b.as_bytes(), &dh4_zero,
        kem_ss_b.as_slice(),
    );

    assert_eq!(sk_a, sk_b, "PQXDH 3DH+KEM: both sides agree");
}

// ============================================================
// 7. PQ contribution: removing KEM changes the session key
// ============================================================

#[test]
fn cross_pqxdh_pq_contribution() {
    let mut rng = rand::thread_rng();

    let ik_a = StaticSecret::from([10u8; 32]);
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);
    let opk_b = StaticSecret::from([50u8; 32]);

    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);
    let opk_b_pub = PublicKey::from(&opk_b);

    let dh1 = ik_a.diffie_hellman(&spk_b_pub);
    let dh2 = ek_a.diffie_hellman(&ik_b_pub);
    let dh3 = ek_a.diffie_hellman(&spk_b_pub);
    let dh4 = ek_a.diffie_hellman(&opk_b_pub);

    // PQXDH with real KEM
    let (_, ek_b) = MlKem768::generate(&mut rng);
    let (_, kem_ss) = ek_b.encapsulate(&mut rng).unwrap();
    let sk_with_kem = compute_pqxdh_sk(
        dh1.as_bytes(), dh2.as_bytes(),
        dh3.as_bytes(), dh4.as_bytes(),
        kem_ss.as_slice(),
    );

    // X3DH without KEM (use zero for KEM shared secret)
    let sk_without_kem = compute_pqxdh_sk(
        dh1.as_bytes(), dh2.as_bytes(),
        dh3.as_bytes(), dh4.as_bytes(),
        &[0u8; 32],
    );

    assert_ne!(sk_with_kem, sk_without_kem,
        "PQ KEM contribution changes the session key");
}

// ============================================================
// 8. X25519 key generation determinism
// ============================================================

#[test]
fn cross_x25519_keygen_determinism() {
    let s1 = StaticSecret::from([42u8; 32]);
    let s2 = StaticSecret::from([42u8; 32]);
    let p1 = PublicKey::from(&s1);
    let p2 = PublicKey::from(&s2);
    assert_eq!(p1.as_bytes(), p2.as_bytes(), "deterministic X25519 key generation");

    let s3 = StaticSecret::from([17u8; 32]);
    let p3 = PublicKey::from(&s3);
    assert_ne!(p1.as_bytes(), p3.as_bytes(), "different secrets => different public keys");
}

// ============================================================
// 9. HKDF info string matters
// ============================================================

#[test]
fn cross_hkdf_info_string_matters() {
    let ikm = [0x42u8; 192];

    let hk1 = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk1 = [0u8; 32];
    hk1.expand(b"WhisperText", &mut sk1).unwrap();

    let hk2 = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk2 = [0u8; 32];
    hk2.expand(b"DifferentInfo", &mut sk2).unwrap();

    assert_ne!(sk1, sk2, "different HKDF info strings produce different keys");
}

// ============================================================
// 10. PQXDH 3DH vs 4DH with real crypto
// ============================================================

#[test]
fn cross_pqxdh_3dh_vs_4dh() {
    let mut rng = rand::thread_rng();

    let ik_a = StaticSecret::from([10u8; 32]);
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);
    let opk_b = StaticSecret::from([50u8; 32]);

    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);
    let opk_b_pub = PublicKey::from(&opk_b);

    let dh1 = ik_a.diffie_hellman(&spk_b_pub);
    let dh2 = ek_a.diffie_hellman(&ik_b_pub);
    let dh3 = ek_a.diffie_hellman(&spk_b_pub);
    let dh4 = ek_a.diffie_hellman(&opk_b_pub);

    let (_, ek_b) = MlKem768::generate(&mut rng);
    let (_, kem_ss) = ek_b.encapsulate(&mut rng).unwrap();

    // 4DH + KEM
    let sk_4dh = compute_pqxdh_sk(
        dh1.as_bytes(), dh2.as_bytes(),
        dh3.as_bytes(), dh4.as_bytes(),
        kem_ss.as_slice(),
    );

    // 3DH + KEM (zero DH4)
    let sk_3dh = compute_pqxdh_sk(
        dh1.as_bytes(), dh2.as_bytes(),
        dh3.as_bytes(), &[0u8; 32],
        kem_ss.as_slice(),
    );

    assert_ne!(sk_3dh, sk_4dh, "3DH+KEM and 4DH+KEM produce different keys with real crypto");
}

// ============================================================
// 11. DH output sizes match our type definitions
// ============================================================

#[test]
fn cross_type_sizes_match() {
    let s = StaticSecret::from([1u8; 32]);
    let p = PublicKey::from(&s);
    let dh = s.diffie_hellman(&p);

    assert_eq!(p.as_bytes().len(), 32, "X25519 public key = 32 bytes = PqxdhDhKey");
    assert_eq!(dh.as_bytes().len(), 32, "X25519 DH output = 32 bytes = PqxdhDhKey");
    assert_eq!(
        core::mem::size_of::<pqxdh_hax::PqxdhDhKey>(), 32,
        "PqxdhDhKey matches X25519 key size"
    );
    assert_eq!(
        core::mem::size_of::<pqxdh_hax::PqxdhKemSs>(), 32,
        "PqxdhKemSs matches ML-KEM shared secret size"
    );
    assert_eq!(
        core::mem::size_of::<pqxdh_hax::PqxdhSessionKey>(), 32,
        "PqxdhSessionKey matches HKDF output size"
    );
}

// ============================================================
// 12. Forward secrecy: different ephemeral keys with real crypto
// ============================================================

#[test]
fn cross_pqxdh_forward_secrecy() {
    let mut rng = rand::thread_rng();

    let ik_a = StaticSecret::from([10u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);
    let opk_b = StaticSecret::from([50u8; 32]);

    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);
    let opk_b_pub = PublicKey::from(&opk_b);

    // Session 1 with ephemeral key 1
    let ek_a1 = StaticSecret::from([20u8; 32]);
    let dh1 = ik_a.diffie_hellman(&spk_b_pub);
    let dh2_1 = ek_a1.diffie_hellman(&ik_b_pub);
    let dh3_1 = ek_a1.diffie_hellman(&spk_b_pub);
    let dh4_1 = ek_a1.diffie_hellman(&opk_b_pub);
    let (_, ek_b1) = MlKem768::generate(&mut rng);
    let (_, kem_ss1) = ek_b1.encapsulate(&mut rng).unwrap();

    let sk1 = compute_pqxdh_sk(
        dh1.as_bytes(), dh2_1.as_bytes(),
        dh3_1.as_bytes(), dh4_1.as_bytes(),
        kem_ss1.as_slice(),
    );

    // Session 2 with different ephemeral key
    let ek_a2 = StaticSecret::from([21u8; 32]);
    let dh2_2 = ek_a2.diffie_hellman(&ik_b_pub);
    let dh3_2 = ek_a2.diffie_hellman(&spk_b_pub);
    let dh4_2 = ek_a2.diffie_hellman(&opk_b_pub);
    let (_, ek_b2) = MlKem768::generate(&mut rng);
    let (_, kem_ss2) = ek_b2.encapsulate(&mut rng).unwrap();

    let sk2 = compute_pqxdh_sk(
        dh1.as_bytes(), dh2_2.as_bytes(),
        dh3_2.as_bytes(), dh4_2.as_bytes(),
        kem_ss2.as_slice(),
    );

    assert_ne!(sk1, sk2, "different ephemeral keys => different session keys (forward secrecy)");
}

// ============================================================
// OFFICIAL TEST VECTORS
// ============================================================

// ============================================================
// 13. RFC 7748 Section 6.1 — X25519 test vector
// ============================================================

#[test]
fn rfc7748_x25519_test_vector() {
    // From RFC 7748 Section 6.1
    let alice_private = hex::decode(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ).unwrap();
    let bob_private = hex::decode(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    ).unwrap();
    let shared_secret_expected = hex::decode(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    ).unwrap();

    let mut ask = [0u8; 32];
    ask.copy_from_slice(&alice_private);
    let mut bsk = [0u8; 32];
    bsk.copy_from_slice(&bob_private);

    let alice_sk = StaticSecret::from(ask);
    let bob_sk = StaticSecret::from(bsk);
    let bob_pk = PublicKey::from(&bob_sk);

    let shared = alice_sk.diffie_hellman(&bob_pk);
    assert_eq!(shared.as_bytes(), shared_secret_expected.as_slice(),
        "RFC 7748 Section 6.1: X25519 shared secret");
}

// ============================================================
// 14. RFC 5869 Appendix A — HKDF-SHA256 Test Case 1
// ============================================================

#[test]
fn rfc5869_hkdf_sha256_test_case_1() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let salt = hex::decode("000102030405060708090a0b0c").unwrap();
    let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
    let expected_okm = hex::decode(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    ).unwrap();

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; 42];
    hk.expand(&info, &mut okm).unwrap();
    assert_eq!(okm, expected_okm, "RFC 5869 Test Case 1: HKDF-SHA256");
}

// ============================================================
// 15. RFC 5869 Appendix A — HKDF-SHA256 Test Case 3
// ============================================================

#[test]
fn rfc5869_hkdf_sha256_test_case_3() {
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let expected_okm = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8"
    ).unwrap();

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = vec![0u8; 42];
    hk.expand(&[], &mut okm).unwrap();
    assert_eq!(okm, expected_okm, "RFC 5869 Test Case 3: HKDF-SHA256 (no salt/info)");
}
