//! Reference cross-checks of doubleratchet-hax against independent implementations of the
//! primitives (RustCrypto `hmac`, `hkdf`, `aes`, `cbc`).
//!
//! The crate implements the protocol logic of the Signal Double Ratchet over the
//! `DoubleRatchetDeps` trait; the tests run it over the reference dependency `RefDeps` of
//! `tests/common`. They check, byte for byte:
//!
//! - `kdf_ck(ck) = (HMAC-SHA-256(ck, 0x02), HMAC-SHA-256(ck, 0x01))` (7.2, libsignal seeds);
//! - `kdf_rk(rk, dh)` is the 64-byte output of HKDF-SHA-256 with salt `rk`, input `dh` and
//!   info `"WhisperRatchet"`, split into root key and chain key (libsignal `create_chain`);
//! - the header encoding `dh || pn || n` (big-endian) and `CONCAT(AD, header)`;
//! - `ct_len(pt_len)` is the length of the deployed ciphertext;
//! - each ciphertext of `ratchet_encrypt` equals the 7.2 encryption, recomputed from the
//!   independent chain, of the plaintext under `CONCAT(AD, header)`.
//!
//! References: RFC 2104 (HMAC), RFC 5869 (HKDF), FIPS 197 (AES), NIST SP 800-38A (CBC),
//! Signal, The Double Ratchet Algorithm, Revision 4, sections 3.4 and 7.2.

mod common;
use common::{buf, hmac, keypair_of, signal_decrypt, signal_encrypt, test_ad, RefDeps};
use doubleratchet_hax::{
    concat_ad, ct_len, dh, encode_header, kdf_ck, kdf_rk, ratchet_encrypt, ratchet_init_alice,
    split64, MessageHeader, AD_LEN, CHAIN_KEY_SEED, FULL_AD_LEN, HEADER_LEN, KDF_RK_INFO,
    MAX_CT_LEN, MAX_PLAINTEXT_LEN, MESSAGE_KEY_SEED, TAG_LEN,
};
use hkdf::Hkdf;
use sha2::Sha256;

// A deterministic byte generator, so the tests sweep many inputs without an rng dependency.
fn lcg32(seed: u64) -> [u8; 32] {
    let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    let mut out = [0u8; 32];
    for b in out.iter_mut() {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *b = (x >> 33) as u8;
    }
    out
}

#[test]
fn constants_are_the_libsignal_values() {
    assert_eq!(KDF_RK_INFO, *b"WhisperRatchet");
    assert_eq!(MESSAGE_KEY_SEED, [0x01]);
    assert_eq!(CHAIN_KEY_SEED, [0x02]);
    assert_eq!(TAG_LEN, 8);
    assert_eq!(FULL_AD_LEN, AD_LEN + HEADER_LEN);
}

#[test]
fn kdf_ck_matches_independent_hmac() {
    for seed in 0..16u64 {
        let ck = lcg32(0xC0FFEE ^ seed);
        let (next_ck, mk) = kdf_ck::<RefDeps>(&ck);
        assert_eq!(next_ck, hmac(&ck, &[0x02]), "next chain key = HMAC(ck, 0x02)");
        assert_eq!(mk, hmac(&ck, &[0x01]), "message key = HMAC(ck, 0x01)");
    }
}

#[test]
fn kdf_rk_matches_independent_hkdf() {
    for seed in 0..16u64 {
        let rk = lcg32(0xD00D ^ seed);
        let sk = lcg32(0xBEEF ^ seed);
        let pk = keypair_of(0x77, seed as u32).1;
        let dh_out = dh::<RefDeps>(&sk, &pk);
        let mut okm = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&rk[..]), &dh_out)
            .expand(b"WhisperRatchet", &mut okm)
            .expect("64 bytes");
        let (new_rk, new_ck) = kdf_rk::<RefDeps>(&rk, &dh_out);
        assert_eq!(new_rk[..], okm[..32], "root key = HKDF output bytes 0..32");
        assert_eq!(new_ck[..], okm[32..], "chain key = HKDF output bytes 32..64");
        assert_eq!(split64(&okm), (new_rk, new_ck));
    }
}

#[test]
fn x25519_agreement_of_the_reference() {
    let (a_sk, a_pk) = keypair_of(0xa0, 0);
    let (b_sk, b_pk) = keypair_of(0xb0, 0);
    assert_eq!(dh::<RefDeps>(&a_sk, &b_pk), dh::<RefDeps>(&b_sk, &a_pk));
}

#[test]
fn encode_header_byte_layout() {
    let h = MessageHeader { dh: lcg32(5), pn: 0x0102_0304, n: 0xa0b0_c0d0 };
    let e = encode_header(&h);
    assert_eq!(e[..32], h.dh[..]);
    assert_eq!(e[32..36], [0x01, 0x02, 0x03, 0x04]);
    assert_eq!(e[36..40], [0xa0, 0xb0, 0xc0, 0xd0]);
    let mut expected = Vec::new();
    expected.extend_from_slice(&h.dh);
    expected.extend_from_slice(&h.pn.to_be_bytes());
    expected.extend_from_slice(&h.n.to_be_bytes());
    assert_eq!(e[..], expected[..]);

    let ad = test_ad();
    let full = concat_ad(&ad, &h);
    assert_eq!(full[..AD_LEN], ad[..]);
    assert_eq!(full[AD_LEN..], e[..]);
}

#[test]
fn ct_len_is_the_deployed_ciphertext_length() {
    let mk = lcg32(9);
    let ad = [0x5c; FULL_AD_LEN];
    for pt_len in 0..=MAX_PLAINTEXT_LEN {
        let pt = vec![0x3a; pt_len];
        let ct = signal_encrypt(&mk, &pt, &ad);
        assert_eq!(ct.len(), ct_len(pt_len), "ct_len({pt_len})");
        assert!(ct_len(pt_len) <= MAX_CT_LEN);
        assert_eq!(signal_decrypt(&mk, &ct, &ad), Some(pt));
    }
}

/// The ciphertexts of `ratchet_encrypt` equal the 7.2 encryption under the message keys of an
/// independent recomputation of the sending chain, with the associated data
/// `AD || dh || pn || n`.
#[test]
fn ratchet_encrypt_matches_independent_encryption() {
    let (a_sk, a_pk) = keypair_of(0xa0, 0);
    let (_b_sk, b_pk) = keypair_of(0xb0, 0);
    let sk = [0x11u8; 32];
    let ad = test_ad();
    let mut st = ratchet_init_alice::<RefDeps>(&sk, &b_pk, &a_sk, &a_pk);

    // Independent sending chain: KDF_RK by HKDF, then KDF_CK by HMAC.
    let mut okm = [0u8; 64];
    Hkdf::<Sha256>::new(Some(&sk[..]), &x25519_dalek::x25519(a_sk, b_pk))
        .expand(b"WhisperRatchet", &mut okm)
        .expect("64 bytes");
    let mut ck: [u8; 32] = okm[32..].try_into().unwrap();
    assert_eq!(st.cks, Some(ck));

    let messages: [&[u8]; 5] = [
        b"ratchet message zero",
        b"the second plaintext, a little longer than the first one here",
        b"three",
        b"",
        &[0xee; MAX_PLAINTEXT_LEN],
    ];
    for (i, &msg) in messages.iter().enumerate() {
        let mk = hmac(&ck, &[0x01]);
        ck = hmac(&ck, &[0x02]);
        let (b, n) = buf(msg);
        let (st1, h, ct, len) = ratchet_encrypt::<RefDeps>(&st, &b, n, &ad).expect("chain");
        assert_eq!((h.dh, h.pn, h.n), (a_pk, 0, i as u32), "header of message {i}");
        let mut full_ad = ad.to_vec();
        full_ad.extend_from_slice(&a_pk);
        full_ad.extend_from_slice(&0u32.to_be_bytes());
        full_ad.extend_from_slice(&(i as u32).to_be_bytes());
        let expected = signal_encrypt(&mk, msg, &full_ad);
        assert_eq!(len, expected.len());
        assert_eq!(ct[..len], expected[..], "ciphertext of message {i}");
        assert!(ct[len..].iter().all(|x| *x == 0), "the buffer is zero after the ciphertext");
        st = st1;
    }
    assert_eq!(st.cks, Some(ck));
    assert_eq!(st.ns, messages.len() as u32);
}
