//! Reference cross-checks for pqxdh-hax's post-quantum KEM against the `ml-kem`
//! crate (RustCrypto FIPS 203 ML-KEM-768).
//!
//! The KEM trait of pqxdh-hax is generic over the KEM key/ciphertext sizes:
//!
//!   `trait PqxdhCrypto<const KEM_PK: usize, const KEM_SK: usize, const KEM_CT: usize>`
//!
//! The crate itself ships only a 32-byte XOR placeholder instance (`KaniPqxdh`,
//! under `#[cfg(kani)]`). This file supplies an ML-KEM-768 instance at the sizes
//! `<1184, 2400, 1088>` and runs the crate's protocol functions
//! (`create_bundle` / `initiate` / `respond`) over ML-KEM-768 (`ml-kem`), X25519
//! (`x25519-dalek`) and HKDF-SHA256 (`hkdf`).
//!
//! Each test is labeled with the strength it achieves:
//!
//!   [REAL-KEM]    OUR `PqxdhCrypto` KEM (wired to `ml-kem`) satisfies the KEM
//!                 correctness property `decaps(sk, encaps(pk).ct) ==
//!                 encaps(pk).ss` over several seeds.
//!   [REAL-AGREE]  OUR adapter round-trips against the RAW `ml-kem` API in both
//!                 directions (raw-encaps → our-decaps, and our-encaps →
//!                 raw-decaps agree byte-for-byte on the shared secret). This
//!                 ties our KEM to the reference and exercises the byte
//!                 (de)serialization path.
//!   [REAL-DET]    ml-kem is reproducible: fixed seed => identical outputs.
//!   [REAL-STRUCT] FIPS 203 ML-KEM-768 byte sizes (ek 1184, dk 2400, ct 1088).
//!   [REAL-PROTO]  OUR full pqxdh protocol (`initiate`/`respond`) with real
//!                 ML-KEM-768 + X25519 + HKDF: Alice and Bob derive the same
//!                 session key.
//!
//! Signatures in this instance are a key-independent, internally consistent
//! stand-in (`sign` then `verify` holds): the KEM/DH/KDF are the primitives
//! under test here; PQXDH signatures (XEdDSA) are not tested. No test asserts a
//! fixed KEM output: every value is computed by `ml-kem`, `x25519-dalek`,
//! `hkdf`, or the crate's protocol functions.
//!
//! ## References
//! - FIPS 203, ML-KEM, NIST, August 2024
//! - RustCrypto `ml-kem` 0.2 (ACVP-validated)
//! - Signal, The PQXDH Key Agreement Protocol, September 2023

use pqxdh_hax::types::*;
use pqxdh_hax::protocol::{PqxdhCrypto, create_bundle, initiate, respond};

use ml_kem::{MlKem768, KemCore, EncodedSizeUser, Encoded};
use ml_kem::kem::{Encapsulate, Decapsulate};
use x25519_dalek::{StaticSecret, PublicKey};
use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use rand::SeedableRng;
use rand::rngs::StdRng;

type Ek = <MlKem768 as KemCore>::EncapsulationKey;
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

// ============================================================
// Real ML-KEM-768 instance of pqxdh's generic PqxdhCrypto trait
// ============================================================

#[derive(Copy, Clone)]
struct RealMlKem768;

impl PqxdhCrypto<1184, 2400, 1088> for RealMlKem768 {
    // ── DH: real X25519 (x25519-dalek) ──
    fn dh(secret: &PqxdhDhKey, peer_pub: &PqxdhDhKey) -> PqxdhDhKey {
        *StaticSecret::from(*secret)
            .diffie_hellman(&PublicKey::from(*peer_pub))
            .as_bytes()
    }
    fn dh_pub(secret: &PqxdhDhKey) -> PqxdhDhKey {
        PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
    }

    // ── KEM: real ML-KEM-768 (RustCrypto ml-kem), deterministic from seed ──
    fn kem_keygen(seed: &PqxdhKemSs) -> ([u8; 1184], [u8; 2400]) {
        let mut rng = StdRng::from_seed(*seed);
        let (dk, ek) = MlKem768::generate(&mut rng);
        let mut pk = [0u8; 1184];
        pk.copy_from_slice(&ek.as_bytes()[..]);
        let mut sk = [0u8; 2400];
        sk.copy_from_slice(&dk.as_bytes()[..]);
        (pk, sk)
    }
    fn kem_encaps(pk: &[u8; 1184], randomness: &PqxdhKemSs) -> ([u8; 1088], PqxdhKemSs) {
        let ek = Ek::from_bytes(&Encoded::<Ek>::try_from(&pk[..]).unwrap());
        let mut rng = StdRng::from_seed(*randomness);
        let (ct, ss) = ek.encapsulate(&mut rng).unwrap();
        let mut ctb = [0u8; 1088];
        ctb.copy_from_slice(&ct[..]);
        let mut ssb = [0u8; 32];
        ssb.copy_from_slice(&ss[..]);
        (ctb, ssb)
    }
    fn kem_decaps(sk: &[u8; 2400], ct: &[u8; 1088]) -> PqxdhKemSs {
        let dk = Dk::from_bytes(&Encoded::<Dk>::try_from(&sk[..]).unwrap());
        let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(&ct[..]).unwrap();
        let ss = dk.decapsulate(&ct_arr).unwrap();
        let mut ssb = [0u8; 32];
        ssb.copy_from_slice(&ss[..]);
        ssb
    }
    fn kem_pk_encode(pk: &[u8; 1184]) -> [u8; 32] {
        // The ML-KEM-768 ek is 1184 bytes; the signable message is its SHA-256.
        // The PQXDH specification signs EncodeKEM(PQPK) itself.
        let mut h = Sha256::new();
        h.update(&pk[..]);
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    // ── KDF: real HKDF-SHA256, per Signal PQXDH spec ──
    fn kdf(
        dh1: &PqxdhDhKey, dh2: &PqxdhDhKey,
        dh3: &PqxdhDhKey, dh4: &PqxdhDhKey,
        kem_ss: &PqxdhKemSs,
    ) -> PqxdhSessionKey {
        let mut ikm = Vec::with_capacity(32 * 6);
        ikm.extend_from_slice(&[0xFFu8; 32]); // F-byte padding
        ikm.extend_from_slice(dh1);
        ikm.extend_from_slice(dh2);
        ikm.extend_from_slice(dh3);
        ikm.extend_from_slice(dh4);
        ikm.extend_from_slice(kem_ss);
        let hk = Hkdf::<Sha256>::new(None, &ikm);
        let mut sk = [0u8; 32];
        hk.expand(b"WhisperText", &mut sk).unwrap();
        sk
    }

    // ── Signatures: consistent key-independent stand-in (see module docs) ──
    fn sign(_ik_secret: &PqxdhDhKey, msg: &[u8; 32]) -> PqxdhSignature {
        let mut h = Sha256::new();
        h.update(b"pqxdh-sig");
        h.update(msg);
        let d = h.finalize();
        let mut sig = ZERO_SIGNATURE;
        sig[0..32].copy_from_slice(&d);
        sig
    }
    fn verify(_ik_pub: &PqxdhDhKey, msg: &[u8; 32], sig: &PqxdhSignature) -> bool {
        let mut h = Sha256::new();
        h.update(b"pqxdh-sig");
        h.update(msg);
        let d = h.finalize();
        sig[0..32] == d[..]
    }
}

fn seed(n: u8) -> [u8; 32] { [n; 32] }

// ============================================================
// 1. [REAL-KEM] KEM correctness of OUR ml-kem-wired instance
// ============================================================

#[test]
fn our_mlkem_kem_correctness_over_seeds() {
    for i in 0..6u8 {
        let ks = seed(i.wrapping_mul(41).wrapping_add(1));
        let rs = seed(i.wrapping_mul(97).wrapping_add(5));
        let (pk, sk) = RealMlKem768::kem_keygen(&ks);
        let (ct, ss_enc) = RealMlKem768::kem_encaps(&pk, &rs);
        let ss_dec = RealMlKem768::kem_decaps(&sk, &ct);
        assert_eq!(ss_enc, ss_dec, "our ML-KEM-768 decaps(encaps) == ss (seed {i})");
    }
}

// ============================================================
// 2. [REAL-AGREE] OUR adapter agrees with the RAW ml-kem API (both ways)
// ============================================================

#[test]
fn our_adapter_agrees_with_raw_mlkem() {
    let ks = seed(0x31);
    let rs = seed(0x32);
    let (pk, sk) = RealMlKem768::kem_keygen(&ks);

    // (a) raw ml-kem encapsulate  →  our kem_decaps
    let ek = Ek::from_bytes(&Encoded::<Ek>::try_from(&pk[..]).unwrap());
    let mut rng = StdRng::from_seed(rs);
    let (raw_ct, raw_ss) = ek.encapsulate(&mut rng).unwrap();
    let mut raw_ct_b = [0u8; 1088];
    raw_ct_b.copy_from_slice(&raw_ct[..]);
    let our_ss = RealMlKem768::kem_decaps(&sk, &raw_ct_b);
    assert_eq!(&our_ss[..], &raw_ss[..], "raw ml-kem encaps then OUR decaps agree");

    // (b) our kem_encaps  →  raw ml-kem decapsulate
    let (our_ct, our_ss2) = RealMlKem768::kem_encaps(&pk, &rs);
    // Same seed drives both, so the adapter must reproduce the raw ciphertext.
    assert_eq!(&our_ct[..], &raw_ct[..], "our encaps ciphertext == raw ml-kem ciphertext");
    let dk = Dk::from_bytes(&Encoded::<Dk>::try_from(&sk[..]).unwrap());
    let ct_arr = ml_kem::Ciphertext::<MlKem768>::try_from(&our_ct[..]).unwrap();
    let raw_ss2 = dk.decapsulate(&ct_arr).unwrap();
    assert_eq!(&our_ss2[..], &raw_ss2[..], "our encaps then RAW decaps agree");
}

// ============================================================
// 3. [REAL-DET] determinism of the ml-kem-wired instance
// ============================================================

#[test]
fn our_mlkem_deterministic() {
    let (pk1, sk1) = RealMlKem768::kem_keygen(&seed(0x11));
    let (pk2, sk2) = RealMlKem768::kem_keygen(&seed(0x11));
    assert_eq!(&pk1[..], &pk2[..], "same seed => identical ek");
    assert_eq!(&sk1[..], &sk2[..], "same seed => identical dk");
    let (ct1, ss1) = RealMlKem768::kem_encaps(&pk1, &seed(0x22));
    let (ct2, ss2) = RealMlKem768::kem_encaps(&pk2, &seed(0x22));
    assert_eq!(&ct1[..], &ct2[..], "same seed+rnd => identical ciphertext");
    assert_eq!(ss1, ss2, "same seed+rnd => identical shared secret");
}

// ============================================================
// 4. [REAL-STRUCT] FIPS 203 ML-KEM-768 byte sizes
// ============================================================

#[test]
fn our_mlkem_fips203_sizes() {
    let (pk, sk) = RealMlKem768::kem_keygen(&seed(0x42));
    let (ct, ss) = RealMlKem768::kem_encaps(&pk, &seed(0x43));
    assert_eq!(pk.len(), 1184, "ML-KEM-768 ek = 1184 bytes");
    assert_eq!(sk.len(), 2400, "ML-KEM-768 dk = 2400 bytes");
    assert_eq!(ct.len(), 1088, "ML-KEM-768 ct = 1088 bytes");
    assert_eq!(ss.len(), 32, "ML-KEM-768 ss = 32 bytes");
    // The sizes of the instance match those of the raw ml-kem crate.
    let (_, ek) = MlKem768::generate(&mut StdRng::from_seed(seed(0x42)));
    assert_eq!(ek.as_bytes().len(), 1184);
    // The shipped Kani placeholder uses 32-byte keys — 37x too small to hold this.
    assert!(pk.len() > 32 * 30,
        "real ML-KEM-768 ek cannot fit in the shipped 32-byte Kani placeholder");
}

// ============================================================
// 5. [REAL-PROTO] full pqxdh protocol with real ML-KEM-768 + X25519 + HKDF
// ============================================================

#[test]
fn full_pqxdh_protocol_with_opk_real_mlkem() {
    // Bob's long-term / signed / one-time secrets, and his KEM seed.
    let ik_b = seed(0x30);
    let spk_b = seed(0x40);
    let opk_b = seed(0x50);
    let pqkem_seed = seed(0x60);

    let (bundle, pqsk_b) =
        create_bundle::<RealMlKem768, 1184, 2400, 1088>(&ik_b, &spk_b, &opk_b, &pqkem_seed);

    // Alice's identity + ephemeral secrets and KEM randomness.
    let ik_a = seed(0x10);
    let ek_a = seed(0x20);
    let kem_rand = seed(0x70);

    let (sk_a, msg, spk_valid, pqpk_valid) =
        initiate::<RealMlKem768, 1184, 2400, 1088>(&ik_a, &ek_a, &bundle, &kem_rand, true);
    let sk_b =
        respond::<RealMlKem768, 1184, 2400, 1088>(&ik_b, &spk_b, &opk_b, &pqsk_b, &msg, true);

    assert!(spk_valid && pqpk_valid, "bundle signatures verify (consistent stand-in)");
    assert_eq!(sk_a, sk_b,
        "PQXDH with real ML-KEM-768 + X25519 + HKDF: Alice and Bob agree on the session key");
    assert_ne!(sk_a, ZERO_SESSION_KEY, "session key is non-zero");
}

#[test]
fn full_pqxdh_protocol_without_opk_real_mlkem() {
    let ik_b = seed(0x31);
    let spk_b = seed(0x41);
    let opk_b = seed(0x51); // present in bundle but unused (3DH)
    let pqkem_seed = seed(0x61);

    let (bundle, pqsk_b) =
        create_bundle::<RealMlKem768, 1184, 2400, 1088>(&ik_b, &spk_b, &opk_b, &pqkem_seed);

    let ik_a = seed(0x11);
    let ek_a = seed(0x21);
    let kem_rand = seed(0x71);

    let (sk_a, msg, _, _) =
        initiate::<RealMlKem768, 1184, 2400, 1088>(&ik_a, &ek_a, &bundle, &kem_rand, false);
    let sk_b =
        respond::<RealMlKem768, 1184, 2400, 1088>(&ik_b, &spk_b, &opk_b, &pqsk_b, &msg, false);

    assert_eq!(sk_a, sk_b, "PQXDH 3DH + real ML-KEM-768: both sides agree");
}

// ============================================================
// 6. [REAL-PROTO] the PQ contribution changes the session key (real ML-KEM)
// ============================================================

#[test]
fn pq_contribution_changes_session_key_real_mlkem() {
    // Two runs identical except for the KEM keypair seed => the ML-KEM shared
    // secret differs => the session key differs. Confirms the PQ KEM is mixed in.
    let ik_b = seed(0x33);
    let spk_b = seed(0x43);
    let opk_b = seed(0x53);
    let ik_a = seed(0x13);
    let ek_a = seed(0x23);
    let kem_rand = seed(0x73);

    let (bundle1, _) =
        create_bundle::<RealMlKem768, 1184, 2400, 1088>(&ik_b, &spk_b, &opk_b, &seed(0x63));
    let (sk1, _, _, _) =
        initiate::<RealMlKem768, 1184, 2400, 1088>(&ik_a, &ek_a, &bundle1, &kem_rand, true);

    let (bundle2, _) =
        create_bundle::<RealMlKem768, 1184, 2400, 1088>(&ik_b, &spk_b, &opk_b, &seed(0x64));
    let (sk2, _, _, _) =
        initiate::<RealMlKem768, 1184, 2400, 1088>(&ik_a, &ek_a, &bundle2, &kem_rand, true);

    assert_ne!(sk1, sk2, "different ML-KEM keypair => different session key");
}
