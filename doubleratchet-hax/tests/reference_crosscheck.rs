//! Reference cross-checks for doubleratchet-hax against an independent
//! implementation of the primitives (RustCrypto `sha2` / `hmac`).
//!
//! ## What is tied to what
//!
//! The crate implements the protocol logic of the Signal Double Ratchet over the
//! `DoubleRatchetDeps` trait; the tests run it over the reference dependency
//! `RefDeps` of `tests/common` (RustCrypto HMAC-SHA-256 and HKDF-SHA-256). The
//! chain is
//!
//!   kdf_ck(ck, c)      = HMAC-SHA-256(ck, [c; 32])
//!   kdf_chain_step(ck) = (kdf_ck(ck, 0x01), kdf_ck(ck, 0x02))
//!   kdf_rk(rk, dh)     = (HKDF-SHA-256(rk, dh, [0x01; 32]),
//!                         HKDF-SHA-256(rk, dh, [0x02; 32]))
//!
//! and the tests check, byte for byte, that the crate's kdf_ck / kdf_rk /
//! kdf_chain_step / kdf_chain_advance / ratchet_encrypt / ratchet_decrypt agree
//! with an independent recomputation built on the RustCrypto `hmac` crate, and
//! that the symmetric-ratchet keystream round-trips.
//!
//! ## Scope
//!
//! The reference dependency's X25519 is a byte-wise XOR stub and its encryption
//! is the XOR keystream under the message key. This file does not claim the DH
//! ratchet is validated against X25519 and does not assert two-party
//! convergence (the XOR stub lacks the symmetry DH(a,B) = DH(b,A)).
//!
//! ## References
//! - RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
//! - RFC 2104: HMAC: Keyed-Hashing for Message Authentication
//! - FIPS 180-4 / RFC 6234: SHA-256
//! - RustCrypto `sha2` / `hmac`

mod common;
use common::RefDeps;
use doubleratchet_hax::{
    dh, kdf_chain_advance, kdf_chain_step, kdf_ck, kdf_rk, ratchet_decrypt, ratchet_encrypt,
    ratchet_init_initiator, MAX_PLAINTEXT_LEN,
};

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

// Independent HMAC-SHA-256 via the RustCrypto `hmac` crate.
fn ref_hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    let out = mac.finalize().into_bytes();
    let mut a = [0u8; 32];
    a.copy_from_slice(&out);
    a
}

// A cheap deterministic byte generator so the tests sweep many inputs
// without an rng dependency.
fn lcg_bytes(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(1);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        out.push((x >> 33) as u8);
    }
    out
}

// ===========================================================================
// 1. crate kdf_ck / kdf_chain_step == independent HMAC of the crate's
//    chain-step constants.
// ===========================================================================

#[test]
fn kdf_chain_step_matches_independent_hmac() {
    for seed in 0..16u64 {
        let ck0: [u8; 32] = {
            let v = lcg_bytes(0xC0FFEE ^ seed, 32);
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        };

        // Independent chain step: new_ck = HMAC(ck, [0x01; 32]), mk = HMAC(ck, [0x02; 32]).
        let ref_ck = ref_hmac_sha256(&ck0, &[0x01; 32]);
        let ref_mk = ref_hmac_sha256(&ck0, &[0x02; 32]);

        assert_eq!(kdf_ck::<RefDeps>(&ck0, 0x01), ref_ck, "kdf_ck::<RefDeps>(_,0x01) == HMAC(ck,0x01)");
        assert_eq!(kdf_ck::<RefDeps>(&ck0, 0x02), ref_mk, "kdf_ck::<RefDeps>(_,0x02) == HMAC(ck,0x02)");

        let (crate_ck, crate_mk) = kdf_chain_step::<RefDeps>(&ck0);
        assert_eq!(crate_ck, ref_ck, "kdf_chain_step CK == independent HMAC");
        assert_eq!(crate_mk, ref_mk, "kdf_chain_step MK == independent HMAC");
    }
}

// ===========================================================================
// 2. crate kdf_chain_advance == N independent HMAC chain steps.
// ===========================================================================

#[test]
fn kdf_chain_advance_matches_independent_hmac() {
    let ck0: [u8; 32] = [0x42u8; 32];
    for steps in 0..12usize {
        // Independent advance: repeatedly ck <- HMAC(ck, 0x01).
        let mut cur = ck0;
        for _ in 0..steps {
            cur = ref_hmac_sha256(&cur, &[0x01; 32]);
        }
        assert_eq!(
            kdf_chain_advance::<RefDeps>(&ck0, steps),
            cur,
            "kdf_chain_advance::<RefDeps>({steps}) == {steps} independent HMAC steps"
        );
    }
}

// ===========================================================================
// 3. crate kdf_rk == independent HKDF of (rk, dh_out).
//    The DH input is the crate's OWN (XOR-stub) dh::<RefDeps>(); the KDF is the
//    independent HMAC. This ties the root-key KDF to an independent reference.
// ===========================================================================

#[test]
fn kdf_rk_matches_independent_hmac() {
    for seed in 0..12u64 {
        let rk: [u8; 32] = {
            let v = lcg_bytes(0xD00D ^ seed, 32);
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        };
        let sk: [u8; 32] = {
            let v = lcg_bytes(0xBEEF ^ seed, 32);
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        };
        let pk: [u8; 32] = {
            let v = lcg_bytes(0xF00D ^ seed, 32);
            let mut a = [0u8; 32];
            a.copy_from_slice(&v);
            a
        };

        let dh_out = dh::<RefDeps>(&sk, &pk); // crate's own (XOR-stub) DH output
        // Independent HKDF-SHA-256 (RFC 5869): PRK = HMAC(rk, dh), one Expand
        // block T(1) = HMAC(PRK, info || 0x01) under the info blocks [c; 32].
        let prk = ref_hmac_sha256(&rk, &dh_out);
        let mut in1 = [0x01u8; 33];
        in1[32] = 0x01;
        let mut in2 = [0x02u8; 33];
        in2[32] = 0x01;

        let ref_rk = ref_hmac_sha256(&prk, &in1);
        let ref_ck = ref_hmac_sha256(&prk, &in2);

        let (new_rk, new_ck) = kdf_rk::<RefDeps>(&rk, &dh_out);
        assert_eq!(new_rk, ref_rk, "kdf_rk new_rk == HKDF(rk, dh, [0x01; 32])");
        assert_eq!(new_ck, ref_ck, "kdf_rk new_ck == HKDF(rk, dh, [0x02; 32])");
    }
}

// ===========================================================================
// 4. the symmetric ratchet keystream round-trips and matches an
//    independent HMAC keystream recomputation.
//
//    We drive the crate's OWN ratchet_encrypt / ratchet_decrypt. Encryption
//    steps the sending chain; decryption steps a receiving chain initialised to
//    the same chain key, so it recovers the plaintext (round-trip). We also
//    recompute the message-key stream independently via the `hmac` crate and
//    confirm each ciphertext equals plaintext XOR that independent keystream.
// ===========================================================================

#[test]
fn symmetric_ratchet_keystream_matches_independent_hmac() {
    let root_key = [0x11u8; 32];
    let my_sk = [0x22u8; 32];
    let my_pk = [0x33u8; 32];
    let remote_pk = [0x44u8; 32];

    // Sender state (initiator derives a real send chain key via kdf_rk).
    let mut send_state = ratchet_init_initiator::<RefDeps>(&root_key, &my_sk, &my_pk, &remote_pk);

    // Receiver whose receiving chain starts at the SAME chain key as the
    // sender's send chain, so decryption tracks encryption.
    let mut recv_state = send_state; // Copy; recv_ck is set below.
    recv_state.recv_ck = send_state.send_ck;

    // Independent chain key mirror (RustCrypto hmac).
    let mut ref_ck = send_state.send_ck;

    let messages: [&[u8]; 4] = [
        b"ratchet message zero",
        b"the second plaintext, a little longer than the first one here",
        b"three",
        b"", // empty plaintext is valid
    ];

    for (i, &pt) in messages.iter().enumerate() {
        let pt_len = pt.len();
        let mut pt_buf = [0u8; MAX_PLAINTEXT_LEN];
        pt_buf[..pt_len].copy_from_slice(pt);

        // Independent message key for THIS step: mk = HMAC(ck, 0x02).
        let ref_mk = ref_hmac_sha256(&ref_ck, &[0x02; 32]);
        // Advance the independent chain: ck <- HMAC(ck, 0x01).
        ref_ck = ref_hmac_sha256(&ref_ck, &[0x01; 32]);

        // Crate encryption.
        let (next_send, _hdr, ct) = ratchet_encrypt::<RefDeps>(&send_state, &pt_buf, pt_len);
        send_state = next_send;

        // Ciphertext must equal plaintext XOR the INDEPENDENT keystream.
        for j in 0..pt_len {
            assert_eq!(
                ct[j],
                pt_buf[j] ^ ref_mk[j % 32],
                "ct[{j}] == pt ^ independent HMAC keystream (msg {i})"
            );
        }

        // Crate decryption round-trips.
        let header = doubleratchet_hax::MessageHeader {
            dh_public: my_pk,
            msg_number: i as u32,
            prev_chain_len: 0,
        };
        let (next_recv, rec) = ratchet_decrypt::<RefDeps>(&recv_state, &header, &ct, pt_len);
        recv_state = next_recv;
        assert_eq!(&rec[..pt_len], &pt_buf[..pt_len], "decrypt recovers plaintext (msg {i})");
    }
}
