//! Authentication of the header, the associated data and the ciphertext, and transactional
//! decryption, against sections 3.4, 3.5 and 7.2 of the Signal specification.
//!
//! The associated data of each message is `CONCAT(AD, header)`. A change of the header's
//! `dh`, `pn` or `n`, of one byte of the key-agreement AD, of one byte of the ciphertext or
//! of the tag, or of the ciphertext length is rejected, every field of the receiver's state
//! is unchanged, and the genuine message is accepted afterwards. The check runs at the
//! receiver's first message (which performs the DH ratchet step), at a later message of the
//! same chain, and at the first message of a new chain.

mod common;
use common::{alice_and_bob, test_ad, view, Party, RefDeps, Sent};
use doubleratchet_hax::{ratchet_decrypt, MAX_CT_LEN, TAG_LEN};

/// The modifications of a sent message, with a description of each.
fn tamperings(m: &Sent) -> Vec<(String, Sent, [u8; 64])> {
    let ad = test_ad();
    let mut out = Vec::new();
    let mut t = m.clone();
    t.h.dh[0] ^= 1;
    out.push(("header dh".to_string(), t, ad));
    let mut t = m.clone();
    t.h.pn ^= 1;
    out.push(("header pn".to_string(), t, ad));
    let mut t = m.clone();
    t.h.n += 1;
    out.push(("header n".to_string(), t, ad));
    for i in [0usize, 31, 32, 63] {
        let mut bad_ad = ad;
        bad_ad[i] ^= 0x40;
        out.push((format!("AD byte {i}"), m.clone(), bad_ad));
    }
    for i in [0usize, m.len / 2, m.len - TAG_LEN - 1, m.len - TAG_LEN, m.len - 1] {
        let mut t = m.clone();
        t.ct[i] ^= 0x01;
        out.push((format!("ciphertext byte {i}"), t, ad));
    }
    let mut t = m.clone();
    t.len -= 1;
    out.push(("ciphertext length - 1".to_string(), t, ad));
    if m.len + 16 <= MAX_CT_LEN {
        let mut t = m.clone();
        t.len += 16;
        out.push(("ciphertext length + 16".to_string(), t, ad));
    }
    out
}

/// Every modification of `m` is rejected with the state of `p` unchanged; then `m` is
/// accepted.
fn check_tampering(p: &mut Party, m: &Sent) {
    let (sk, pk) = p.next_keypair();
    let before = view(&p.st);
    for (what, t, ad) in tamperings(m) {
        let r = ratchet_decrypt::<RefDeps>(&p.st, &t.h, &t.ct, t.len, &ad, &sk, &pk);
        assert!(r.is_none(), "a change of the {what} is rejected");
        assert_eq!(view(&p.st), before);
    }
    p.receive(m);
}

#[test]
fn tampering_at_first_receipt_is_rejected() {
    let (mut alice, mut bob) = alice_and_bob();
    let m = alice.send(b"the first message of the session");
    check_tampering(&mut bob, &m);
}

#[test]
fn tampering_within_a_chain_is_rejected() {
    let (mut alice, mut bob) = alice_and_bob();
    let m0 = alice.send(b"zero");
    bob.receive(&m0);
    let m1 = alice.send(&[0x42; 100]);
    check_tampering(&mut bob, &m1);
    let m2 = alice.send(&[0x43; 256]);
    check_tampering(&mut bob, &m2);
}

#[test]
fn tampering_at_a_new_chain_is_rejected() {
    let (mut alice, mut bob) = alice_and_bob();
    let m0 = alice.send(b"zero");
    bob.receive(&m0);
    let r = bob.send(b"reply");
    check_tampering(&mut alice, &r);
    let m1 = alice.send(b"new chain");
    assert_eq!(m1.h.pn, 1);
    check_tampering(&mut bob, &m1);
}

/// A message of Alice to Bob is not accepted by Alice herself, nor by a responder of another
/// session.
#[test]
fn message_is_bound_to_the_session() {
    let (mut alice, _bob) = alice_and_bob();
    let m = alice.send(b"for bob");
    let (sk, pk) = alice.next_keypair();
    assert!(ratchet_decrypt::<RefDeps>(&alice.st, &m.h, &m.ct, m.len, &test_ad(), &sk, &pk)
        .is_none());
    let (b_sk, b_pk) = common::keypair_of(0xb0, 0);
    let other = doubleratchet_hax::ratchet_init_bob(&[0x99; 32], &b_sk, &b_pk);
    let mut eve = Party { st: other, tag: 0xe0, next_kp: 0 };
    assert!(eve.try_receive(&m).is_none(), "another shared secret rejects");
}
