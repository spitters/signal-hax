//! Cross-library tests for the X3DH formula.
//!
//! These tests compute the X3DH session-key formula directly with
//! `x25519-dalek` (X25519) and `hkdf` + `sha2` (HKDF-SHA256); they do not call
//! the crate's `initiate` / `respond` (that is done in `proptest_equiv.rs`).
//! They check agreement of both sides on fixed keys with and without the
//! one-time prekey, that the inputs and the 0xFF padding change the key, the
//! sizes of the crate's key types, the X25519 test vector of RFC 7748 §6.1 and
//! the HKDF-SHA256 test cases 1-3 of RFC 5869 Appendix A.
//!
//! ## Reference
//!
//! Signal — The X3DH Key Agreement Protocol, November 2016 (revised 2024)
//! https://signal.org/docs/specifications/x3dh/

use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::Sha256;

// ============================================================
// Helper: compute X3DH session key per Signal spec
// ============================================================

/// Compute X3DH session key per Signal specification.
///
/// SK = HKDF(salt=0, ikm = 0xFF*32 || DH1 || DH2 || DH3 [|| DH4],
///           info = "WhisperText")
fn compute_x3dh_sk(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    dh4: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + 32 * 4);
    ikm.extend_from_slice(&[0xFFu8; 32]); // F-byte padding per spec
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    if let Some(d4) = dh4 {
        ikm.extend_from_slice(d4);
    }

    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut sk = [0u8; 32];
    hk.expand(b"WhisperText", &mut sk).unwrap();
    sk
}

// ============================================================
// 1. Full X3DH with OPK (4DH) — spec-compliant
// ============================================================

#[test]
fn cross_x3dh_full_4dh() {
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

    let sk_a = compute_x3dh_sk(
        dh1_a.as_bytes(), dh2_a.as_bytes(),
        dh3_a.as_bytes(), Some(dh4_a.as_bytes()),
    );

    // Bob's side
    let dh1_b = spk_b.diffie_hellman(&ik_a_pub);
    let dh2_b = ik_b.diffie_hellman(&ek_a_pub);
    let dh3_b = spk_b.diffie_hellman(&ek_a_pub);
    let dh4_b = opk_b.diffie_hellman(&ek_a_pub);

    let sk_b = compute_x3dh_sk(
        dh1_b.as_bytes(), dh2_b.as_bytes(),
        dh3_b.as_bytes(), Some(dh4_b.as_bytes()),
    );

    assert_eq!(sk_a, sk_b, "X3DH 4DH: Alice and Bob derive same session key");
    assert_ne!(sk_a, [0u8; 32], "session key is non-zero");
}

// ============================================================
// 2. Full X3DH without OPK (3DH) — spec-compliant
// ============================================================

#[test]
fn cross_x3dh_full_3dh() {
    let ik_a = StaticSecret::from([10u8; 32]);
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);

    let ik_a_pub = PublicKey::from(&ik_a);
    let ek_a_pub = PublicKey::from(&ek_a);
    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);

    // Alice
    let dh1_a = ik_a.diffie_hellman(&spk_b_pub);
    let dh2_a = ek_a.diffie_hellman(&ik_b_pub);
    let dh3_a = ek_a.diffie_hellman(&spk_b_pub);
    let sk_a = compute_x3dh_sk(dh1_a.as_bytes(), dh2_a.as_bytes(), dh3_a.as_bytes(), None);

    // Bob
    let dh1_b = spk_b.diffie_hellman(&ik_a_pub);
    let dh2_b = ik_b.diffie_hellman(&ek_a_pub);
    let dh3_b = spk_b.diffie_hellman(&ek_a_pub);
    let sk_b = compute_x3dh_sk(dh1_b.as_bytes(), dh2_b.as_bytes(), dh3_b.as_bytes(), None);

    assert_eq!(sk_a, sk_b, "X3DH 3DH: Alice and Bob derive same session key");
}

// ============================================================
// 3. 3DH and 4DH produce different keys
// ============================================================

#[test]
fn cross_x3dh_3dh_vs_4dh() {
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

    let sk_3dh = compute_x3dh_sk(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), None);
    let sk_4dh = compute_x3dh_sk(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), Some(dh4.as_bytes()));

    assert_ne!(sk_3dh, sk_4dh, "3DH and 4DH produce different keys with real crypto");
}

// ============================================================
// 4. Forward secrecy: different ephemeral keys
// ============================================================

#[test]
fn cross_x3dh_forward_secrecy() {
    let ik_a = StaticSecret::from([10u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);

    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);

    let ek_a1 = StaticSecret::from([20u8; 32]);
    let dh1 = ik_a.diffie_hellman(&spk_b_pub);
    let dh2_1 = ek_a1.diffie_hellman(&ik_b_pub);
    let dh3_1 = ek_a1.diffie_hellman(&spk_b_pub);
    let sk1 = compute_x3dh_sk(dh1.as_bytes(), dh2_1.as_bytes(), dh3_1.as_bytes(), None);

    let ek_a2 = StaticSecret::from([21u8; 32]);
    let dh2_2 = ek_a2.diffie_hellman(&ik_b_pub);
    let dh3_2 = ek_a2.diffie_hellman(&spk_b_pub);
    let sk2 = compute_x3dh_sk(dh1.as_bytes(), dh2_2.as_bytes(), dh3_2.as_bytes(), None);

    assert_ne!(sk1, sk2, "different ephemeral keys => different session keys (forward secrecy)");
}

// ============================================================
// 5. HKDF F-byte padding changes the output
// ============================================================

#[test]
fn cross_x3dh_f_byte_padding() {
    let dh1 = [0x11u8; 32];
    let dh2 = [0x22u8; 32];
    let dh3 = [0x33u8; 32];

    // With F-byte padding (spec-compliant)
    let sk_with_f = compute_x3dh_sk(&dh1, &dh2, &dh3, None);

    // Without F-byte padding (wrong)
    let mut ikm_no_f = Vec::new();
    ikm_no_f.extend_from_slice(&dh1);
    ikm_no_f.extend_from_slice(&dh2);
    ikm_no_f.extend_from_slice(&dh3);
    let hk = Hkdf::<Sha256>::new(None, &ikm_no_f);
    let mut sk_no_f = [0u8; 32];
    hk.expand(b"WhisperText", &mut sk_no_f).unwrap();

    assert_ne!(sk_with_f, sk_no_f, "F-byte padding affects output (spec compliance matters)");
}

// ============================================================
// 6. Determinism: same inputs produce same output
// ============================================================

#[test]
fn cross_x3dh_determinism() {
    let ik_a = StaticSecret::from([10u8; 32]);
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);

    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);

    let dh1 = ik_a.diffie_hellman(&spk_b_pub);
    let dh2 = ek_a.diffie_hellman(&ik_b_pub);
    let dh3 = ek_a.diffie_hellman(&spk_b_pub);

    let sk1 = compute_x3dh_sk(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), None);
    let sk2 = compute_x3dh_sk(dh1.as_bytes(), dh2.as_bytes(), dh3.as_bytes(), None);

    assert_eq!(sk1, sk2, "X3DH is deterministic");
}

// ============================================================
// 7. DH output is 32 bytes (matches X3dhKey type)
// ============================================================

#[test]
fn cross_x3dh_type_sizes() {
    let s = StaticSecret::from([1u8; 32]);
    let p = PublicKey::from(&s);
    let dh = s.diffie_hellman(&p);

    assert_eq!(p.as_bytes().len(), 32, "X25519 public key = 32 bytes = X3dhKey");
    assert_eq!(dh.as_bytes().len(), 32, "X25519 DH result = 32 bytes = X3dhKey");
    assert_eq!(core::mem::size_of::<x3dh_hax::types::X3dhKey>(), 32);
    assert_eq!(core::mem::size_of::<x3dh_hax::types::X3dhSessionKey>(), 32);
}

// ============================================================
// 8. Multiple sessions with different identity keys
// ============================================================

#[test]
fn cross_x3dh_different_identities() {
    let ek_a = StaticSecret::from([20u8; 32]);
    let ik_b = StaticSecret::from([30u8; 32]);
    let spk_b = StaticSecret::from([40u8; 32]);

    let ik_b_pub = PublicKey::from(&ik_b);
    let spk_b_pub = PublicKey::from(&spk_b);

    // Alice with identity key 1
    let ik_a1 = StaticSecret::from([10u8; 32]);
    let dh1_1 = ik_a1.diffie_hellman(&spk_b_pub);
    let dh2_1 = ek_a.diffie_hellman(&ik_b_pub);
    let dh3_1 = ek_a.diffie_hellman(&spk_b_pub);
    let sk1 = compute_x3dh_sk(dh1_1.as_bytes(), dh2_1.as_bytes(), dh3_1.as_bytes(), None);

    // Alice with identity key 2
    let ik_a2 = StaticSecret::from([11u8; 32]);
    let dh1_2 = ik_a2.diffie_hellman(&spk_b_pub);
    let sk2 = compute_x3dh_sk(dh1_2.as_bytes(), dh2_1.as_bytes(), dh3_1.as_bytes(), None);

    assert_ne!(sk1, sk2, "different identity keys => different session keys");
}

// ============================================================
// OFFICIAL TEST VECTORS
// ============================================================

// ============================================================
// 9. RFC 7748 Section 6.1 — X25519 test vector
// ============================================================

#[test]
fn rfc7748_x25519_test_vector() {
    // From RFC 7748 Section 6.1
    let alice_private = hex::decode(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ).unwrap();
    let alice_public_expected = hex::decode(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    ).unwrap();
    let bob_private = hex::decode(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    ).unwrap();
    let bob_public_expected = hex::decode(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    ).unwrap();
    let shared_secret_expected = hex::decode(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    ).unwrap();

    let mut alice_sk_bytes = [0u8; 32];
    alice_sk_bytes.copy_from_slice(&alice_private);
    let mut bob_sk_bytes = [0u8; 32];
    bob_sk_bytes.copy_from_slice(&bob_private);

    let alice_sk = StaticSecret::from(alice_sk_bytes);
    let bob_sk = StaticSecret::from(bob_sk_bytes);

    let alice_pk = PublicKey::from(&alice_sk);
    let bob_pk = PublicKey::from(&bob_sk);

    assert_eq!(alice_pk.as_bytes(), alice_public_expected.as_slice(),
        "RFC 7748: Alice public key");
    assert_eq!(bob_pk.as_bytes(), bob_public_expected.as_slice(),
        "RFC 7748: Bob public key");

    let shared_ab = alice_sk.diffie_hellman(&bob_pk);
    let shared_ba = bob_sk.diffie_hellman(&alice_pk);

    assert_eq!(shared_ab.as_bytes(), shared_secret_expected.as_slice(),
        "RFC 7748: shared secret (Alice computes)");
    assert_eq!(shared_ba.as_bytes(), shared_secret_expected.as_slice(),
        "RFC 7748: shared secret (Bob computes)");
}

// ============================================================
// 10. RFC 5869 Appendix A — HKDF-SHA256 Test Case 1
// ============================================================

#[test]
fn rfc5869_hkdf_sha256_test_case_1() {
    // RFC 5869 Appendix A, Test Case 1
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
// 11. RFC 5869 Appendix A — HKDF-SHA256 Test Case 2
// ============================================================

#[test]
fn rfc5869_hkdf_sha256_test_case_2() {
    // RFC 5869 Appendix A, Test Case 2 (longer inputs)
    let ikm = hex::decode(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
         202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
         404142434445464748494a4b4c4d4e4f"
    ).unwrap();
    let salt = hex::decode(
        "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f\
         808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f\
         a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    ).unwrap();
    let info = hex::decode(
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf\
         d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef\
         f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
    ).unwrap();
    let expected_okm = hex::decode(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
         59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
         cc30c58179ec3e87c14c01d5c1f3434f1d87"
    ).unwrap();

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut okm = vec![0u8; 82];
    hk.expand(&info, &mut okm).unwrap();

    assert_eq!(okm, expected_okm, "RFC 5869 Test Case 2: HKDF-SHA256 (long)");
}

// ============================================================
// 12. RFC 5869 Appendix A — HKDF-SHA256 Test Case 3
// ============================================================

#[test]
fn rfc5869_hkdf_sha256_test_case_3() {
    // RFC 5869 Appendix A, Test Case 3 (zero-length salt and info)
    let ikm = hex::decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b").unwrap();
    let expected_okm = hex::decode(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
         9d201395faa4b61a96c8"
    ).unwrap();

    // No salt, no info
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = vec![0u8; 42];
    hk.expand(&[], &mut okm).unwrap();

    assert_eq!(okm, expected_okm, "RFC 5869 Test Case 3: HKDF-SHA256 (no salt/info)");
}
