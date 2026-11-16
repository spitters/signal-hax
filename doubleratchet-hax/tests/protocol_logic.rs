//! Protocol-logic and property tests of the Signal Double Ratchet. The specification has no
//! published test vectors, so these tests check protocol-level properties (determinism, key
//! uniqueness, round trip, forward secrecy of the chain, rejection under a wrong key, the DH
//! ratchet step, the header contents) over the reference dependency of `tests/common`.

mod common;
use common::{alice_and_bob, buf, test_ad, RefDeps};
use doubleratchet_hax::*;

fn test_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Iterates the chain `n` times and returns the final chain key.
fn advance(ck: &[u8; 32], n: usize) -> [u8; 32] {
    let mut c = *ck;
    for _ in 0..n {
        c = kdf_ck::<RefDeps>(&c).0;
    }
    c
}

// ============================================================
// KDF chain
// ============================================================

#[test]
fn kdf_chain_deterministic() {
    let ck = test_key(0x42);
    assert_eq!(kdf_ck::<RefDeps>(&ck), kdf_ck::<RefDeps>(&ck));
}

#[test]
fn chain_step_ck_mk_differ() {
    let (new_ck, mk) = kdf_ck::<RefDeps>(&test_key(0x55));
    assert_ne!(new_ck, mk, "CK and MK from the same step differ");
}

#[test]
fn multiple_steps_unique_keys() {
    let mut ck = test_key(0x77);
    let mut cks = Vec::new();
    let mut mks = Vec::new();
    for _ in 0..10 {
        let (next, mk) = kdf_ck::<RefDeps>(&ck);
        cks.push(next);
        mks.push(mk);
        ck = next;
    }
    for i in 0..10 {
        for j in (i + 1)..10 {
            assert_ne!(cks[i], cks[j], "chain keys at steps {i} and {j} differ");
            assert_ne!(mks[i], mks[j], "message keys at steps {i} and {j} differ");
        }
    }
}

#[test]
fn chain_step_output_differs_from_input() {
    let ck = test_key(0x99);
    let (new_ck, mk) = kdf_ck::<RefDeps>(&ck);
    assert_ne!(new_ck, ck);
    assert_ne!(mk, ck);
}

#[test]
fn different_initial_keys_diverge() {
    let (ca, ma) = kdf_ck::<RefDeps>(&test_key(0xaa));
    let (cb, mb) = kdf_ck::<RefDeps>(&test_key(0xbb));
    assert_ne!(ca, cb);
    assert_ne!(ma, mb);
}

/// From the chain key at step 2 the message key of step 0 is not obtained by stepping
/// forward, and the advanced chain does not return to the initial message key.
#[test]
fn forward_secrecy_of_the_chain() {
    let initial = test_key(0xdd);
    let mk0 = kdf_ck::<RefDeps>(&initial).1;
    let ck2 = advance(&initial, 2);
    for k in 0..16 {
        assert_ne!(kdf_ck::<RefDeps>(&advance(&ck2, k)).1, mk0, "step {k} from step 2");
    }
    assert_ne!(advance(&initial, 10), initial);
}

#[test]
fn chain_advance_zero_steps() {
    assert_eq!(advance(&test_key(0x44), 0), test_key(0x44));
}

#[test]
fn kdf_rk_outputs_differ() {
    let rk = test_key(0x11);
    let (new_rk, new_ck) = kdf_rk::<RefDeps>(&rk, &test_key(0x22));
    assert_ne!(new_rk, new_ck);
    assert_ne!(new_rk, rk);
}

// ============================================================
// Encryption and decryption
// ============================================================

#[test]
fn encrypt_decrypt_roundtrip() {
    let (mut alice, mut bob) = alice_and_bob();
    let messages: [&[u8]; 6] = [
        b"Hello, Signal!",
        &[0x01; 32],
        b"Third",
        b"Fourth message is a bit longer than the others",
        b"",
        &[0x7f; MAX_PLAINTEXT_LEN],
    ];
    for msg in messages {
        let m = alice.send(msg);
        bob.receive(&m);
    }
    assert_eq!(alice.st.ns, 6);
    assert_eq!(bob.st.nr, 6);
}

#[test]
fn ciphertext_differs_from_plaintext() {
    let (mut alice, _bob) = alice_and_bob();
    let msg = b"This should be encrypted";
    let m = alice.send(msg);
    assert_ne!(&m.ct[..msg.len()], &msg[..]);
}

#[test]
fn successive_encryptions_differ() {
    let (mut alice, _bob) = alice_and_bob();
    let m1 = alice.send(b"Same message");
    let m2 = alice.send(b"Same message");
    assert_eq!(m1.len, m2.len);
    assert_ne!(m1.ct[..m1.len], m2.ct[..m2.len]);
}

/// Decryption under a wrong receiving chain key is rejected.
#[test]
fn wrong_key_fails_decryption() {
    let (mut alice, mut bob) = alice_and_bob();
    let m0 = alice.send(b"first");
    bob.receive(&m0);
    let m1 = alice.send(b"Secret message");
    let mut bad = bob.st;
    bad.ckr = Some(test_key(0xff));
    let (sk, pk) = bob.next_keypair();
    assert!(
        ratchet_decrypt::<RefDeps>(&bad, &m1.h, &m1.ct, m1.len, &test_ad(), &sk, &pk).is_none()
    );
    bob.receive(&m1);
}

/// Decryption under the wrong associated data of the key agreement is rejected.
#[test]
fn wrong_associated_data_fails_decryption() {
    let (mut alice, bob) = alice_and_bob();
    let m = alice.send(b"bound to the session");
    let mut ad = test_ad();
    ad[0] ^= 1;
    let (sk, pk) = bob.next_keypair();
    assert!(ratchet_decrypt::<RefDeps>(&bob.st, &m.h, &m.ct, m.len, &ad, &sk, &pk).is_none());
}

// ============================================================
// DH ratchet step
// ============================================================

#[test]
fn dh_ratchet_changes_keys_and_counters() {
    let (mut alice, _bob) = alice_and_bob();
    let _ = alice.send(b"one");
    let _ = alice.send(b"two");
    let a = alice.st;
    let new_remote = common::keypair_of(0x50, 0).1;
    let (n_sk, n_pk) = common::keypair_of(0x60, 0);
    let a2 = dh_ratchet::<RefDeps>(&a, &new_remote, &n_sk, &n_pk);
    assert_ne!(a2.rk, a.rk, "root key changes");
    assert!(a2.cks.is_some() && a2.cks != a.cks, "a new sending chain");
    assert_eq!(a.ckr, None);
    assert!(a2.ckr.is_some(), "a receiving chain");
    assert_eq!((a2.ns, a2.nr, a2.pn), (0, 0, a.ns), "PN = Ns, Ns = Nr = 0");
    assert_eq!(a2.dhr, Some(new_remote));
    assert_eq!((a2.dhs_sk, a2.dhs_pk), (n_sk, n_pk));

    // The two halves compose to the step.
    let r = dh_ratchet_recv_half::<RefDeps>(&a, &new_remote);
    assert_eq!(r.cks, a.cks, "the receiving half leaves the sending chain");
    assert_eq!(r.dhs_pk, a.dhs_pk, "the receiving half leaves the key pair");
    let s = dh_ratchet_send_half::<RefDeps>(&r, &n_sk, &n_pk);
    assert_eq!(common::view(&s), common::view(&a2));
}

#[test]
fn send_half_without_remote_key_is_identity() {
    let (_alice, bob) = alice_and_bob();
    let (n_sk, n_pk) = common::keypair_of(0x61, 0);
    let s = dh_ratchet_send_half::<RefDeps>(&bob.st, &n_sk, &n_pk);
    assert_eq!(common::view(&s), common::view(&bob.st));
}

// ============================================================
// Header
// ============================================================

#[test]
fn header_metadata() {
    let (mut alice, _bob) = alice_and_bob();
    for expected_n in 0..3u32 {
        let m = alice.send(b"test");
        assert_eq!(m.h.n, expected_n);
        assert_eq!(m.h.pn, 0);
        assert_eq!(m.h.dh, alice.st.dhs_pk);
    }
}

#[test]
fn encrypt_empty_plaintext() {
    let (mut alice, mut bob) = alice_and_bob();
    let m = alice.send(b"");
    assert_eq!(m.len, ct_len(0));
    let (sk, pk) = bob.next_keypair();
    let (_s, pt, n) =
        ratchet_decrypt::<RefDeps>(&bob.st, &m.h, &m.ct, m.len, &test_ad(), &sk, &pk)
            .expect("accepted");
    assert_eq!(n, 0);
    assert!(pt.iter().all(|b| *b == 0), "the plaintext buffer is zero");
    bob.receive(&m);
}

#[test]
fn encrypt_does_not_touch_the_receiving_side() {
    let (mut alice, _bob) = alice_and_bob();
    let before = alice.st;
    let (b, n) = buf(b"x");
    let (after, _h, _ct, _len) =
        ratchet_encrypt::<RefDeps>(&before, &b, n, &test_ad()).expect("chain");
    assert_eq!(after.ckr, before.ckr);
    assert_eq!(after.nr, before.nr);
    assert_eq!(after.rk, before.rk);
    assert_eq!(after.sk_used, before.sk_used);
    alice.st = after;
}
