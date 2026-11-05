//! Protocol tests for X3DH over a toy model of the primitives.
//!
//! `KaniSimplifiedX3dh` instantiates `X3dhCrypto` with exponentiation in
//! Z_{65537}^* as DH and with deterministic arithmetic stand-ins for the
//! signature and the KDF; it is not a cryptographic implementation, and the
//! expected values are not published known answers. The tests run
//! `create_bundle`, `initiate` and `respond` over this model and check bundle
//! creation, 3DH/4DH key agreement, that different ephemeral keys give
//! different session keys, and signature verification.

use x3dh_hax::types::*;
use x3dh_hax::protocol::*;

// ============================================================
// Kani-simplified X3dhCrypto over Z_{65537}^*
// ============================================================

const P: u64 = 65537;
const G: u64 = 3;

fn tmul(a: u64, b: u64) -> u64 { (a * b) % P }
fn tpow(mut base: u64, mut exp: u64) -> u64 {
    let mut r: u64 = 1; base %= P;
    while exp > 0 {
        if exp & 1 == 1 { r = tmul(r, base); }
        exp >>= 1; base = tmul(base, base);
    }
    r
}

fn val_to_key(v: u64) -> X3dhKey {
    let mut k = ZERO_KEY;
    let b = (v % P).to_be_bytes();
    k[24..32].copy_from_slice(&b);
    k
}
fn key_to_val(k: &X3dhKey) -> u64 {
    let mut v: u64 = 0;
    for i in 24..32 { v = (v << 8) | k[i] as u64; }
    v % P
}

#[allow(dead_code)]
fn kani_simplified_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 1;
    for &b in data { h = (h.wrapping_mul(31).wrapping_add(b as u64)) % P; }
    if h == 0 { 1 } else { h }
}

#[derive(Copy, Clone)]
struct KaniSimplifiedX3dh;

impl X3dhCrypto for KaniSimplifiedX3dh {
    fn dh(secret: &X3dhKey, peer_pub: &X3dhKey) -> X3dhKey {
        val_to_key(tpow(key_to_val(peer_pub), key_to_val(secret)))
    }
    fn dh_pub(secret: &X3dhKey) -> X3dhKey {
        val_to_key(tpow(G, key_to_val(secret)))
    }
    fn kdf(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey, dh4: &X3dhKey) -> X3dhSessionKey {
        let v1 = key_to_val(dh1);
        let v2 = key_to_val(dh2);
        let v3 = key_to_val(dh3);
        let v4 = key_to_val(dh4);
        let result = v1.wrapping_mul(v2.wrapping_add(1))
            .wrapping_add(v3.wrapping_mul(v4.wrapping_add(1))) % P;
        let mut sk = ZERO_SESSION_KEY;
        let b = result.to_be_bytes();
        sk[24..32].copy_from_slice(&b);
        sk
    }
    fn sign(ik_secret: &X3dhKey, msg: &X3dhKey) -> X3dhSignature {
        // Kani-simplified signature: hash(ik_secret || msg) placed in first 32 bytes
        let sv = key_to_val(ik_secret);
        let mv = key_to_val(msg);
        let sig_val = sv.wrapping_mul(mv).wrapping_add(42) % P;
        let mut sig = ZERO_SIGNATURE;
        let b = sig_val.to_be_bytes();
        sig[24..32].copy_from_slice(&b);
        // Second half: hash for verification binding
        let verify_val = tpow(G, sv).wrapping_mul(mv).wrapping_add(42) % P;
        let b2 = verify_val.to_be_bytes();
        sig[56..64].copy_from_slice(&b2);
        sig
    }
    fn verify(ik_pub: &X3dhKey, msg: &X3dhKey, sig: &X3dhSignature) -> bool {
        // Verify: check that second half matches hash(ik_pub, msg)
        let pv = key_to_val(ik_pub);
        let mv = key_to_val(msg);
        let expected_val = pv.wrapping_mul(mv).wrapping_add(42) % P;
        let expected_bytes = expected_val.to_be_bytes();
        let mut ok = true;
        for i in 0..8 {
            if sig[56 + i] != expected_bytes[i] { ok = false; }
        }
        ok
    }
}

// ============================================================
// 1. DH commutativity
// ============================================================

#[test]
fn kat_dh_commutativity() {
    let a = val_to_key(42);
    let b = val_to_key(17);
    let ga = KaniSimplifiedX3dh::dh_pub(&a);
    let gb = KaniSimplifiedX3dh::dh_pub(&b);
    let gab = KaniSimplifiedX3dh::dh(&a, &gb);
    let gba = KaniSimplifiedX3dh::dh(&b, &ga);
    assert_eq!(gab, gba, "DH commutativity");
}

// ============================================================
// 2. Bundle creation
// ============================================================

#[test]
fn kat_create_bundle() {
    let ik = val_to_key(42);
    let spk = val_to_key(17);
    let opk = val_to_key(99);

    let bundle = create_bundle::<KaniSimplifiedX3dh>(&ik, &spk, &opk);

    assert_eq!(bundle.ik, KaniSimplifiedX3dh::dh_pub(&ik), "bundle.ik = pub(ik)");
    assert_eq!(bundle.spk, KaniSimplifiedX3dh::dh_pub(&spk), "bundle.spk = pub(spk)");
    assert_eq!(bundle.opk, KaniSimplifiedX3dh::dh_pub(&opk), "bundle.opk = pub(opk)");
    assert!(KaniSimplifiedX3dh::verify(&bundle.ik, &bundle.spk, &bundle.sig), "SPK signature verifies");
}

// ============================================================
// 3. X3DH with OPK (4DH)
// ============================================================

#[test]
fn kat_x3dh_with_opk() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);

    let bundle = create_bundle::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b);
    let (sk_a, msg, sig_valid) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a, &bundle, true);
    assert!(sig_valid, "SPK signature valid");

    let sk_b = respond::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b, &msg, true);
    assert_eq!(sk_a, sk_b, "4DH: both sides derive same session key");
}

// ============================================================
// 4. X3DH without OPK (3DH)
// ============================================================

#[test]
fn kat_x3dh_without_opk() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50); // present but not used

    let bundle = create_bundle::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b);
    let (sk_a, msg, _) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a, &bundle, false);

    let sk_b = respond::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b, &msg, false);
    assert_eq!(sk_a, sk_b, "3DH: both sides derive same session key");
}

// ============================================================
// 5. 3DH and 4DH produce different keys
// ============================================================

#[test]
fn kat_3dh_vs_4dh() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);

    let bundle = create_bundle::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b);
    let (sk_3dh, _, _) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a, &bundle, false);
    let (sk_4dh, _, _) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a, &bundle, true);

    assert_ne!(sk_3dh, sk_4dh, "3DH and 4DH produce different keys");
}

// ============================================================
// 6. Wrong SPK signature detection
// ============================================================

#[test]
fn kat_wrong_spk_signature() {
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);

    let mut bundle = create_bundle::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b);
    // Tamper with signature
    bundle.sig[60] ^= 0xFF;

    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let (_, _, sig_valid) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a, &bundle, true);
    assert!(!sig_valid, "tampered SPK signature should fail");
}

// ============================================================
// 7. Different ephemeral keys produce different session keys
// ============================================================

#[test]
fn kat_different_ephemeral_keys() {
    let ik_a = val_to_key(10);
    let ek_a1 = val_to_key(20);
    let ek_a2 = val_to_key(21);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);

    let bundle = create_bundle::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b);
    let (sk1, _, _) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a1, &bundle, true);
    let (sk2, _, _) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a2, &bundle, true);

    assert_ne!(sk1, sk2, "different ephemeral keys => different session keys (forward secrecy)");
}

// ============================================================
// 8. Initiate message contains correct public keys
// ============================================================

#[test]
fn kat_init_message_content() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);

    let bundle = create_bundle::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b);
    let (_, msg, _) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a, &bundle, true);

    assert_eq!(msg.ik_a, KaniSimplifiedX3dh::dh_pub(&ik_a), "msg contains Alice's IK");
    assert_eq!(msg.ek_a, KaniSimplifiedX3dh::dh_pub(&ek_a), "msg contains Alice's EK");
    assert_eq!(msg.opk_id, [0, 0, 0, 1], "opk_id indicates OPK used");
}

// ============================================================
// 9. Without OPK, opk_id is zero
// ============================================================

#[test]
fn kat_no_opk_id() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);

    let bundle = create_bundle::<KaniSimplifiedX3dh>(&ik_b, &spk_b, &opk_b);
    let (_, msg, _) = initiate::<KaniSimplifiedX3dh>(&ik_a, &ek_a, &bundle, false);

    assert_eq!(msg.opk_id, [0, 0, 0, 0], "opk_id is zero when OPK not used");
}

// ============================================================
// 10. DH consistency across X3DH operations
// ============================================================

#[test]
fn kat_dh_consistency() {
    let ik_a = val_to_key(10);
    let spk_b = val_to_key(40);
    let ik_b = val_to_key(30);
    let ek_a = val_to_key(20);

    // DH1 = DH(IK_A, SPK_B) on both sides
    let dh1_a = KaniSimplifiedX3dh::dh(&ik_a, &KaniSimplifiedX3dh::dh_pub(&spk_b));
    let dh1_b = KaniSimplifiedX3dh::dh(&spk_b, &KaniSimplifiedX3dh::dh_pub(&ik_a));
    assert_eq!(dh1_a, dh1_b, "DH1 matches on both sides");

    // DH2 = DH(EK_A, IK_B)
    let dh2_a = KaniSimplifiedX3dh::dh(&ek_a, &KaniSimplifiedX3dh::dh_pub(&ik_b));
    let dh2_b = KaniSimplifiedX3dh::dh(&ik_b, &KaniSimplifiedX3dh::dh_pub(&ek_a));
    assert_eq!(dh2_a, dh2_b, "DH2 matches on both sides");
}

// ============================================================
// 11. Signature determinism
// ============================================================

#[test]
fn kat_signature_determinism() {
    let ik = val_to_key(42);
    let msg = val_to_key(17);
    let sig1 = KaniSimplifiedX3dh::sign(&ik, &msg);
    let sig2 = KaniSimplifiedX3dh::sign(&ik, &msg);
    assert_eq!(sig1, sig2, "signature is deterministic");
}

// ============================================================
// 12. Type sizes
// ============================================================

#[test]
fn kat_type_sizes() {
    assert_eq!(core::mem::size_of::<X3dhKey>(), 32, "X3dhKey = 32 bytes");
    assert_eq!(core::mem::size_of::<X3dhSignature>(), 64, "X3dhSignature = 64 bytes");
    assert_eq!(core::mem::size_of::<X3dhSessionKey>(), 32, "X3dhSessionKey = 32 bytes");
}

// ============================================================
// 13. Cross-library: x25519-dalek DH commutativity
// ============================================================

#[test]
fn test_cross_x3dh_dh() {
    use x25519_dalek::{StaticSecret, PublicKey};

    let alice_ik = StaticSecret::from([10u8; 32]);
    let bob_spk = StaticSecret::from([40u8; 32]);

    let alice_ik_pub = PublicKey::from(&alice_ik);
    let bob_spk_pub = PublicKey::from(&bob_spk);

    // DH(IK_A, SPK_B) = DH(SPK_B, IK_A)
    let dh_ab = alice_ik.diffie_hellman(&bob_spk_pub);
    let dh_ba = bob_spk.diffie_hellman(&alice_ik_pub);
    assert_eq!(dh_ab.as_bytes(), dh_ba.as_bytes(), "x25519 DH commutativity for X3DH");
}

// ============================================================
// 14. Cross-library: x25519-dalek 4DH structure
// ============================================================

#[test]
fn test_cross_x3dh_4dh_structure() {
    use x25519_dalek::{StaticSecret, PublicKey};

    // All 4 DH operations that make up X3DH
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

    assert_eq!(dh1_a.as_bytes(), dh1_b.as_bytes(), "DH1 matches");
    assert_eq!(dh2_a.as_bytes(), dh2_b.as_bytes(), "DH2 matches");
    assert_eq!(dh3_a.as_bytes(), dh3_b.as_bytes(), "DH3 matches");
    assert_eq!(dh4_a.as_bytes(), dh4_b.as_bytes(), "DH4 matches");

    // All 4 DH results are 32 bytes
    assert_eq!(dh1_a.as_bytes().len(), 32, "DH result = 32 bytes");
    assert_eq!(core::mem::size_of::<X3dhKey>(), 32, "X3dhKey matches DH output size");
}

// ============================================================
// 15. Cross-library: x25519-dalek key generation
// ============================================================

#[test]
fn test_cross_x3dh_keygen() {
    use x25519_dalek::{StaticSecret, PublicKey};

    let s1 = StaticSecret::from([42u8; 32]);
    let s2 = StaticSecret::from([42u8; 32]);
    let p1 = PublicKey::from(&s1);
    let p2 = PublicKey::from(&s2);
    assert_eq!(p1.as_bytes(), p2.as_bytes(), "deterministic key generation");

    let s3 = StaticSecret::from([17u8; 32]);
    let p3 = PublicKey::from(&s3);
    assert_ne!(p1.as_bytes(), p3.as_bytes(), "different secrets => different keys");
}
