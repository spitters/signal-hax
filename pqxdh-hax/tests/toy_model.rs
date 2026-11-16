//! Protocol tests for PQXDH over a toy model of the primitives.
//!
//! `KaniSimplifiedPqxdh` instantiates `PqxdhCrypto<32, 32, 32>` with
//! exponentiation in Z_{65537}^* as DH, an XOR-based KEM and deterministic
//! arithmetic stand-ins for the signature and the KDF; it is not a
//! cryptographic implementation, and the expected values are not published
//! known answers. The tests run `create_bundle`, `initiate` and `respond` over
//! this model and check bundle creation, signature verification, 4DH+KEM and
//! 3DH+KEM key agreement, and that the ephemeral keys and the KEM randomness
//! change the session key.
//!
//! ## Test categories
//!
//! 1. DH commutativity
//! 2. KEM roundtrip
//! 3. Bundle creation + signature verification
//! 4. PQXDH with OPK (4DH + KEM)
//! 5. PQXDH without OPK (3DH + KEM)
//! 6. 3DH+KEM vs 4DH+KEM produce different keys
//! 7. Wrong signature detection (SPK and PQPK)
//! 8. Different ephemeral keys → different session keys
//! 9. Different KEM randomness → different session keys
//! 10. Init message content
//! 11. DH consistency across protocol
//! 12. KEM wrong key rejection
//! 13. Type sizes
//! 14. Determinism
//! 15. PQ contribution
//! 16. Input check of peer public keys, including the identity `1` of the
//!     toy group

use pqxdh_hax::types::*;
use pqxdh_hax::protocol::*;

// ============================================================
// Kani-simplified PqxdhCrypto over Z_{65537}^* (DH) + XOR (KEM)
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

fn val_to_key(v: u64) -> PqxdhDhKey {
    let mut k = [0u8; 32];
    let b = (v % P).to_be_bytes();
    k[24..32].copy_from_slice(&b);
    k
}
fn key_to_val(k: &[u8; 32]) -> u64 {
    let mut v: u64 = 0;
    for i in 24..32 { v = (v << 8) | k[i] as u64; }
    v % P
}

/// KEM key derivation constant.
const KEM_PK_CONST: [u8; 32] = {
    let mut c = [0u8; 32];
    c[0] = 0x05;
    c[1] = 0x50; // 'P'
    c[2] = 0x4B; // 'K'
    c
};

/// KDF domain separation constants.
const KDF_CONST: [u8; 32] = {
    let mut c = [0u8; 32];
    c[0] = 0x07;
    c[1] = 0x50; // 'P'
    c[2] = 0x51; // 'Q'
    c
};

#[derive(Copy, Clone)]
struct KaniSimplifiedPqxdh;

impl PqxdhCrypto<32, 32, 32> for KaniSimplifiedPqxdh {
    fn dh(secret: &PqxdhDhKey, peer_pub: &PqxdhDhKey) -> PqxdhDhKey {
        val_to_key(tpow(key_to_val(peer_pub), key_to_val(secret)))
    }
    fn dh_pub(secret: &PqxdhDhKey) -> PqxdhDhKey {
        val_to_key(tpow(G, key_to_val(secret)))
    }

    fn kem_keygen(seed: &PqxdhKemSs) -> ([u8; 32], [u8; 32]) {
        let pk = xor_32(seed, &KEM_PK_CONST);
        let sk = *seed;
        (pk, sk)
    }
    fn kem_encaps(pk: &[u8; 32], randomness: &PqxdhKemSs) -> ([u8; 32], PqxdhKemSs) {
        let ct = xor_32(randomness, pk);
        let ss = *randomness;
        (ct, ss)
    }
    fn kem_decaps(sk: &[u8; 32], ct: &[u8; 32]) -> PqxdhKemSs {
        let pk_recovered = xor_32(sk, &KEM_PK_CONST);
        xor_32(ct, &pk_recovered)
    }
    fn kem_pk_encode(pk: &[u8; 32]) -> [u8; 32] { *pk }

    fn kdf(
        dh1: &PqxdhDhKey, dh2: &PqxdhDhKey, dh3: &PqxdhDhKey,
        dh4: &PqxdhDhKey, kem_ss: &PqxdhKemSs,
    ) -> PqxdhSessionKey {
        // Kani-simplified KDF: XOR all inputs together, then add domain constant
        let mut acc = xor_32(dh1, dh2);
        acc = xor_32(&acc, dh3);
        acc = xor_32(&acc, dh4);
        acc = xor_32(&acc, kem_ss);
        wrapping_add_32(&acc, &KDF_CONST)
    }

    fn sign(ik_secret: &PqxdhDhKey, msg: &[u8; 32]) -> PqxdhSignature {
        let sv = key_to_val(ik_secret);
        let mv = key_to_val(msg);
        let sig_val = sv.wrapping_mul(mv).wrapping_add(42) % P;
        let mut sig = ZERO_SIGNATURE;
        let b = sig_val.to_be_bytes();
        sig[24..32].copy_from_slice(&b);
        // Verification binding: hash(pub(ik), msg)
        let verify_val = tpow(G, sv).wrapping_mul(mv).wrapping_add(42) % P;
        let b2 = verify_val.to_be_bytes();
        sig[56..64].copy_from_slice(&b2);
        sig
    }
    fn verify(ik_pub: &PqxdhDhKey, msg: &[u8; 32], sig: &PqxdhSignature) -> bool {
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
    /// A toy public key is a value in `[2, P)` held in the last eight bytes:
    /// an element of Z_P^* other than the identity `1`.
    fn valid_pub(pk: &PqxdhDhKey) -> bool {
        let mut v: u64 = 0;
        for i in 24..32 { v = (v << 8) | pk[i] as u64; }
        pk[..24].iter().all(|&b| b == 0) && v > 1 && v < P
    }
}

// ============================================================
// 1. DH commutativity
// ============================================================

#[test]
fn kat_dh_commutativity() {
    let a = val_to_key(42);
    let b = val_to_key(17);
    let ga = KaniSimplifiedPqxdh::dh_pub(&a);
    let gb = KaniSimplifiedPqxdh::dh_pub(&b);
    let gab = KaniSimplifiedPqxdh::dh(&a, &gb);
    let gba = KaniSimplifiedPqxdh::dh(&b, &ga);
    assert_eq!(gab, gba, "DH commutativity");
}

// ============================================================
// 2. KEM roundtrip
// ============================================================

#[test]
fn kat_kem_roundtrip() {
    let seed = val_to_key(77);
    let (pk, sk) = KaniSimplifiedPqxdh::kem_keygen(&seed);
    let randomness = val_to_key(99);
    let (ct, ss_enc) = KaniSimplifiedPqxdh::kem_encaps(&pk, &randomness);
    let ss_dec = KaniSimplifiedPqxdh::kem_decaps(&sk, &ct);
    assert_eq!(ss_enc, ss_dec, "KEM encaps/decaps roundtrip");
}

#[test]
fn kat_kem_multiple_randomness() {
    let seed = val_to_key(33);
    let (pk, sk) = KaniSimplifiedPqxdh::kem_keygen(&seed);
    for r in [1u64, 100, 9999, 65536] {
        let randomness = val_to_key(r);
        let (ct, ss_enc) = KaniSimplifiedPqxdh::kem_encaps(&pk, &randomness);
        let ss_dec = KaniSimplifiedPqxdh::kem_decaps(&sk, &ct);
        assert_eq!(ss_enc, ss_dec, "roundtrip for randomness {}", r);
    }
}

// ============================================================
// 3. Bundle creation + signature verification
// ============================================================

#[test]
fn kat_create_bundle() {
    let ik = val_to_key(42);
    let spk = val_to_key(17);
    let opk = val_to_key(99);
    let kem_seed = val_to_key(55);

    let (bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik, &spk, &opk, &kem_seed);

    assert_eq!(bundle.ik, KaniSimplifiedPqxdh::dh_pub(&ik), "bundle.ik = pub(ik)");
    assert_eq!(bundle.spk, KaniSimplifiedPqxdh::dh_pub(&spk), "bundle.spk = pub(spk)");
    assert_eq!(bundle.opk, KaniSimplifiedPqxdh::dh_pub(&opk), "bundle.opk = pub(opk)");
    assert!(KaniSimplifiedPqxdh::verify(&bundle.ik, &bundle.spk, &bundle.spk_sig), "SPK sig valid");
    assert!(KaniSimplifiedPqxdh::verify(&bundle.ik, &bundle.pqpk, &bundle.pqpk_sig), "PQPK sig valid");
}

// ============================================================
// 4. PQXDH with OPK (4DH + KEM)
// ============================================================

#[test]
fn kat_pqxdh_with_opk() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let kem_rand = val_to_key(70);
    let (sk_a, msg, spk_ok, pqpk_ok) =
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, true).unwrap();
    assert!(spk_ok, "SPK signature valid");
    assert!(pqpk_ok, "PQPK signature valid");

    let sk_b = respond::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &pqsk, &msg, true).unwrap();
    assert_eq!(sk_a, sk_b, "4DH+KEM: both sides derive same session key");
}

// ============================================================
// 5. PQXDH without OPK (3DH + KEM)
// ============================================================

#[test]
fn kat_pqxdh_without_opk() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let kem_rand = val_to_key(70);
    let (sk_a, msg, _, _) =
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, false).unwrap();
    let sk_b = respond::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &pqsk, &msg, false).unwrap();
    assert_eq!(sk_a, sk_b, "3DH+KEM: both sides derive same session key");
}

// ============================================================
// 6. 3DH+KEM vs 4DH+KEM produce different keys
// ============================================================

#[test]
fn kat_3dh_vs_4dh() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let kem_rand = val_to_key(70);
    let (sk_3dh, _, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, false).unwrap();
    let (sk_4dh, _, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, true).unwrap();
    assert_ne!(sk_3dh, sk_4dh, "3DH+KEM and 4DH+KEM produce different keys");
}

// ============================================================
// 7. Wrong signature detection
// ============================================================

#[test]
fn kat_wrong_spk_signature() {
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (mut bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    bundle.spk_sig[60] ^= 0xFF; // tamper

    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let kem_rand = val_to_key(70);
    let (_, _, spk_ok, pqpk_ok) =
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, true).unwrap();
    assert!(!spk_ok, "tampered SPK signature detected");
    assert!(pqpk_ok, "PQPK signature still valid");
}

#[test]
fn kat_wrong_pqpk_signature() {
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (mut bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    bundle.pqpk_sig[60] ^= 0xFF; // tamper

    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let kem_rand = val_to_key(70);
    let (_, _, spk_ok, pqpk_ok) =
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, true).unwrap();
    assert!(spk_ok, "SPK signature still valid");
    assert!(!pqpk_ok, "tampered PQPK signature detected");
}

// ============================================================
// 8. Different ephemeral keys → different session keys
// ============================================================

#[test]
fn kat_different_ephemeral_keys() {
    let ik_a = val_to_key(10);
    let ek_a1 = val_to_key(20);
    let ek_a2 = val_to_key(21);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let kem_rand = val_to_key(70);
    let (sk1, _, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a1, &bundle, &kem_rand, true).unwrap();
    let (sk2, _, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a2, &bundle, &kem_rand, true).unwrap();
    assert_ne!(sk1, sk2, "different ephemeral keys => different session keys");
}

// ============================================================
// 9. Different KEM randomness → different session keys
// ============================================================

#[test]
fn kat_different_kem_randomness() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let (sk1, _, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &val_to_key(70), true).unwrap();
    let (sk2, _, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &val_to_key(71), true).unwrap();
    assert_ne!(sk1, sk2, "different KEM randomness => different session keys (PQ contribution)");
}

// ============================================================
// 10. Init message content
// ============================================================

#[test]
fn kat_init_message_content() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let kem_rand = val_to_key(70);
    let (_, msg, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, true).unwrap();

    assert_eq!(msg.ik_a, KaniSimplifiedPqxdh::dh_pub(&ik_a), "msg contains Alice's IK");
    assert_eq!(msg.ek_a, KaniSimplifiedPqxdh::dh_pub(&ek_a), "msg contains Alice's EK");
    assert_ne!(msg.kem_ct, [0u8; 32], "KEM ciphertext is non-zero");
    assert_eq!(msg.opk_id, [0, 0, 0, 1], "opk_id indicates OPK used");
}

#[test]
fn kat_init_message_no_opk() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let kem_rand = val_to_key(70);
    let (_, msg, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, false).unwrap();
    assert_eq!(msg.opk_id, [0, 0, 0, 0], "opk_id is zero when OPK not used");
}

// ============================================================
// 11. DH consistency across protocol
// ============================================================

#[test]
fn kat_dh_consistency() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);

    // DH1 = DH(IK_A, SPK_B) on both sides
    let dh1_a = KaniSimplifiedPqxdh::dh(&ik_a, &KaniSimplifiedPqxdh::dh_pub(&spk_b));
    let dh1_b = KaniSimplifiedPqxdh::dh(&spk_b, &KaniSimplifiedPqxdh::dh_pub(&ik_a));
    assert_eq!(dh1_a, dh1_b, "DH1 matches");

    // DH2 = DH(EK_A, IK_B)
    let dh2_a = KaniSimplifiedPqxdh::dh(&ek_a, &KaniSimplifiedPqxdh::dh_pub(&ik_b));
    let dh2_b = KaniSimplifiedPqxdh::dh(&ik_b, &KaniSimplifiedPqxdh::dh_pub(&ek_a));
    assert_eq!(dh2_a, dh2_b, "DH2 matches");

    // DH3 = DH(EK_A, SPK_B)
    let dh3_a = KaniSimplifiedPqxdh::dh(&ek_a, &KaniSimplifiedPqxdh::dh_pub(&spk_b));
    let dh3_b = KaniSimplifiedPqxdh::dh(&spk_b, &KaniSimplifiedPqxdh::dh_pub(&ek_a));
    assert_eq!(dh3_a, dh3_b, "DH3 matches");
}

// ============================================================
// 12. KEM wrong key rejection
// ============================================================

#[test]
fn kat_kem_wrong_key() {
    let seed_a = val_to_key(11);
    let seed_b = val_to_key(22);
    let (pk_a, _sk_a) = KaniSimplifiedPqxdh::kem_keygen(&seed_a);
    let (_pk_b, sk_b) = KaniSimplifiedPqxdh::kem_keygen(&seed_b);

    let randomness = val_to_key(33);
    let (ct, ss_enc) = KaniSimplifiedPqxdh::kem_encaps(&pk_a, &randomness);
    let ss_dec_wrong = KaniSimplifiedPqxdh::kem_decaps(&sk_b, &ct);
    assert_ne!(ss_enc, ss_dec_wrong, "wrong KEM key => wrong shared secret");
}

// ============================================================
// 13. Type sizes
// ============================================================

#[test]
fn kat_type_sizes() {
    assert_eq!(core::mem::size_of::<PqxdhDhKey>(), 32, "DH key = 32 bytes");
    assert_eq!(core::mem::size_of::<[u8; 32]>(), 32, "Kani-simplified KEM pk = 32 bytes");
    assert_eq!(core::mem::size_of::<PqxdhKemSs>(), 32, "KEM ss = 32 bytes");
    assert_eq!(core::mem::size_of::<PqxdhSignature>(), 64, "Signature = 64 bytes");
    assert_eq!(core::mem::size_of::<PqxdhSessionKey>(), 32, "Session key = 32 bytes");
}

// ============================================================
// 14. Determinism
// ============================================================

#[test]
fn kat_determinism() {
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);
    let kem_rand = val_to_key(70);

    let (bundle1, pqsk1) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);
    let (bundle2, pqsk2) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);

    let (sk_a1, msg1, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle1, &kem_rand, true).unwrap();
    let (sk_a2, msg2, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle2, &kem_rand, true).unwrap();
    assert_eq!(sk_a1, sk_a2, "deterministic session key (Alice)");
    assert_eq!(msg1.kem_ct, msg2.kem_ct, "deterministic KEM ciphertext");

    let sk_b1 = respond::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &pqsk1, &msg1, true).unwrap();
    let sk_b2 = respond::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &pqsk2, &msg2, true).unwrap();
    assert_eq!(sk_b1, sk_b2, "deterministic session key (Bob)");
    assert_eq!(sk_a1, sk_b1, "Alice and Bob agree");
}

// ============================================================
// 15. PQ contribution: KEM shared secret actually affects output
// ============================================================

#[test]
fn kat_pq_contribution() {
    // Replacing the KEM shared secret with zero changes the session key.
    let ik_a = val_to_key(10);
    let ek_a = val_to_key(20);
    let ik_b = val_to_key(30);
    let spk_b = val_to_key(40);
    let opk_b = val_to_key(50);
    let kem_seed = val_to_key(60);

    let (bundle, pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &kem_seed);

    // Session with real KEM randomness
    let kem_rand = val_to_key(70);
    let (sk_with_kem, msg, _, _) =
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand, true).unwrap();
    let sk_b = respond::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &pqsk, &msg, true).unwrap();
    assert_eq!(sk_with_kem, sk_b, "real KEM: both sides agree");

    // Session with different KEM randomness
    let kem_rand2 = val_to_key(71);
    let (sk_different_rand, _, _, _) =
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, &bundle, &kem_rand2, true).unwrap();
    assert_ne!(sk_with_kem, sk_different_rand,
        "different KEM randomness => different session key");

    // Manually compute with zero KEM shared secret
    let dh1 = KaniSimplifiedPqxdh::dh(&ik_a, &bundle.spk);
    let dh2 = KaniSimplifiedPqxdh::dh(&ek_a, &bundle.ik);
    let dh3 = KaniSimplifiedPqxdh::dh(&ek_a, &bundle.spk);
    let dh4 = KaniSimplifiedPqxdh::dh(&ek_a, &bundle.opk);
    let sk_no_kem = KaniSimplifiedPqxdh::kdf(&dh1, &dh2, &dh3, &dh4, &ZERO_KEM_SS);
    assert_ne!(sk_with_kem, sk_no_kem,
        "removing KEM contribution changes session key");
}

// ============================================================
// 16. Input check of peer public keys
// ============================================================

/// A key outside the toy group: the value `P`, which is not reduced.
fn invalid_key() -> PqxdhDhKey {
    let mut k = [0u8; 32];
    k[24..32].copy_from_slice(&P.to_be_bytes());
    k
}

#[test]
fn initiate_rejects_invalid_bundle_keys() {
    let (ik_a, ek_a, kem_rand) = (val_to_key(10), val_to_key(20), val_to_key(70));
    let (bundle, _pqsk) = create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(
        &val_to_key(30), &val_to_key(40), &val_to_key(50), &val_to_key(60));
    let init = |b: &PqxdhPreKeyBundle<32>, use_opk: bool| {
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, b, &kem_rand, use_opk)
    };
    assert!(init(&bundle, true).is_some());
    let bad_ik = PqxdhPreKeyBundle { ik: invalid_key(), ..bundle };
    let bad_spk = PqxdhPreKeyBundle { spk: invalid_key(), ..bundle };
    let bad_opk = PqxdhPreKeyBundle { opk: invalid_key(), ..bundle };
    assert!(init(&bad_ik, true).is_none());
    assert!(init(&bad_spk, false).is_none());
    assert!(init(&bad_opk, true).is_none());
    // Without the one-time prekey, its key is not used and not checked.
    assert!(init(&bad_opk, false).is_some());
}

#[test]
fn respond_rejects_invalid_message_keys() {
    let (ik_b, spk_b, opk_b) = (val_to_key(30), val_to_key(40), val_to_key(50));
    let (bundle, pqsk) =
        create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &val_to_key(60));
    let (_, msg, _, _) = initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(
        &val_to_key(10), &val_to_key(20), &bundle, &val_to_key(70), true).unwrap();
    let resp = |m: &PqxdhInitMessage<32>, use_opk: bool| {
        respond::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &pqsk, m, use_opk)
    };
    assert!(resp(&msg, true).is_some());
    let bad_ik = PqxdhInitMessage { ik_a: invalid_key(), ..msg };
    let bad_ek = PqxdhInitMessage { ek_a: [0u8; 32], ..msg };
    assert!(resp(&bad_ik, true).is_none());
    assert!(resp(&bad_ek, false).is_none());
}

/// The identity `1` of the toy group is rejected in every checked position:
/// on it every DH value would be the identity, independent of the secret.
#[test]
fn identity_key_rejected() {
    let one = val_to_key(1);
    assert!(!KaniSimplifiedPqxdh::valid_pub(&one));
    let (ik_b, spk_b, opk_b) = (val_to_key(30), val_to_key(40), val_to_key(50));
    let (bundle, pqsk) =
        create_bundle::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &val_to_key(60));
    let (ik_a, ek_a, kem_rand) = (val_to_key(10), val_to_key(20), val_to_key(70));
    let init = |b: &PqxdhPreKeyBundle<32>, use_opk: bool| {
        initiate::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_a, &ek_a, b, &kem_rand, use_opk)
    };
    assert!(init(&PqxdhPreKeyBundle { ik: one, ..bundle }, false).is_none());
    assert!(init(&PqxdhPreKeyBundle { spk: one, ..bundle }, false).is_none());
    assert!(init(&PqxdhPreKeyBundle { opk: one, ..bundle }, true).is_none());
    let (_, msg, _, _) = init(&bundle, true).unwrap();
    let resp = |m: &PqxdhInitMessage<32>, use_opk: bool| {
        respond::<KaniSimplifiedPqxdh, 32, 32, 32>(&ik_b, &spk_b, &opk_b, &pqsk, m, use_opk)
    };
    assert!(resp(&PqxdhInitMessage { ik_a: one, ..msg }, true).is_none());
    assert!(resp(&PqxdhInitMessage { ek_a: one, ..msg }, true).is_none());
    assert!(resp(&PqxdhInitMessage { ek_a: one, ..msg }, false).is_none());
}
