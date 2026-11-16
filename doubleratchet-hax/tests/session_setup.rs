//! Session setup and the DH ratchet step on receipt, against sections 3.3 and 3.5 of the
//! Signal specification.
//!
//! `RatchetInitAlice` sets `DHr` to the responder's key, derives `RK, CKs` from the shared
//! secret and sets `CKr = None`; `RatchetInitBob` sets `DHr = None`, `RK = SK` and
//! `CKs = CKr = None`. The tests check, over the reference dependency of `tests/common`
//! (X25519 of `x25519-dalek`, the deployed message encryption):
//!
//! - after `ratchet_init_alice` no key field equals the shared secret; after
//!   `ratchet_init_bob` the shared secret is the root key and the value of no other field;
//! - an encryption at the responder before its first receipt is refused, and so is a
//!   decryption at the initiator before its first receipt;
//! - the responder's first decryption performs the DH ratchet step from `DHr = None`;
//! - a conversation driven by `ratchet_encrypt` and `ratchet_decrypt` only agrees, and the
//!   key pair supplied to `ratchet_decrypt` is used exactly on a header with a new ratchet
//!   key.
//!
//! Reference: Signal, The Double Ratchet Algorithm, Revision 4, sections 3.3 and 3.5,
//! <https://signal.org/docs/specifications/doubleratchet/>.

mod common;
use common::{alice_and_bob, buf, keypair_of, message, test_ad, view, RefDeps, SK};
use doubleratchet_hax::{
    dh, kdf_rk, ratchet_decrypt, ratchet_encrypt, ratchet_init_alice, ratchet_init_bob,
    RatchetState, MAX_CT_LEN,
};
use proptest::prelude::*;

/// The 32-byte fields of a state that hold key material, absent chain keys omitted.
fn key_fields(s: &RatchetState) -> Vec<[u8; 32]> {
    let mut v = vec![s.rk, s.dhs_sk, s.dhs_pk];
    v.extend(s.dhr);
    v.extend(s.cks);
    v.extend(s.ckr);
    v
}

proptest! {
    /// After `ratchet_init_alice` the state holds a sending chain key, no receiving chain
    /// key, the responder's key as `DHr`, and no field equal to the shared secret.
    #[test]
    fn alice_setup_holds_no_shared_secret(
        sk in any::<[u8; 32]>(),
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
    ) {
        let (a_sk, a_pk) = common::keypair(a);
        let (_b_sk, b_pk) = common::keypair(b);
        prop_assume!(a_sk != sk && a_pk != sk && b_pk != sk);
        let s = ratchet_init_alice::<RefDeps>(&sk, &b_pk, &a_sk, &a_pk);
        prop_assert!(s.cks.is_some());
        prop_assert_eq!(s.ckr, None);
        prop_assert_eq!(s.dhr, Some(b_pk));
        prop_assert_eq!((s.ns, s.nr, s.pn), (0, 0, 0));
        prop_assert!(s.sk_used.iter().all(|u| !*u));
        for f in key_fields(&s) {
            prop_assert_ne!(f, sk);
        }
    }

    /// After `ratchet_init_bob` the state holds no chain key, no remote key, and the shared
    /// secret as its root key only.
    #[test]
    fn bob_setup_holds_shared_secret_only_as_root_key(
        sk in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
    ) {
        let (b_sk, b_pk) = common::keypair(b);
        prop_assume!(b_sk != sk && b_pk != sk);
        let s = ratchet_init_bob(&sk, &b_sk, &b_pk);
        prop_assert_eq!(s.rk, sk);
        prop_assert_eq!(s.cks, None);
        prop_assert_eq!(s.ckr, None);
        prop_assert_eq!(s.dhr, None);
        prop_assert_eq!(key_fields(&s).iter().filter(|f| **f == sk).count(), 1);
    }
}

/// The responder refuses an encryption before its first receipt; the initiator refuses a
/// decryption before its first receipt, also after it has sent, and its state stays.
#[test]
fn operations_before_the_first_receipt_are_refused() {
    let (mut alice, bob) = alice_and_bob();
    let ad = test_ad();
    let (b, n) = buf(b"message");
    assert!(ratchet_encrypt::<RefDeps>(&bob.st, &b, n, &ad).is_none());

    // A message under Bob's initial ratchet key, which Alice holds as DHr: no receiving
    // chain exists, so it is refused.
    let (n_sk, n_pk) = keypair_of(0xa0, 1);
    let h = doubleratchet_hax::MessageHeader { dh: keypair_of(0xb0, 0).1, pn: 0, n: 0 };
    let ct = [0u8; MAX_CT_LEN];
    assert!(ratchet_decrypt::<RefDeps>(&alice.st, &h, &ct, 24, &ad, &n_sk, &n_pk).is_none());
    let _ = alice.send(b"first");
    assert!(ratchet_decrypt::<RefDeps>(&alice.st, &h, &ct, 24, &ad, &n_sk, &n_pk).is_none());
}

/// Bob's first decryption performs the DH ratchet step from `DHr = None`: his receiving chain
/// is Alice's initial sending chain, his new key pair is the supplied one, and his sending
/// chain is derived from it.
#[test]
fn first_receipt_performs_the_dh_step() {
    let (mut alice, mut bob) = alice_and_bob();
    let a_cks0 = alice.st.cks;
    let m = alice.send(b"hello bob");
    let (n_sk, n_pk) = bob.next_keypair();
    let bob0 = bob.st;
    bob.receive(&m);
    let st = bob.st;
    assert_eq!(st.dhr, Some(alice.st.dhs_pk), "DHr is Alice's ratchet key");
    assert_eq!((st.dhs_sk, st.dhs_pk), (n_sk, n_pk), "DHs is the supplied key pair");
    assert_eq!((st.ns, st.nr, st.pn), (0, 1, 0));
    // Receiving half: RK1, CKr = KDF_RK(SK, DH(b0, A)) with CKr Alice's initial chain.
    let (rk1, ckr) = kdf_rk::<RefDeps>(&SK, &dh::<RefDeps>(&bob0.dhs_sk, &alice.st.dhs_pk));
    assert_eq!(Some(ckr), a_cks0, "Bob's receiving chain is Alice's initial sending chain");
    // Sending half: RK2, CKs = KDF_RK(RK1, DH(new, A)).
    let (rk2, cks) = kdf_rk::<RefDeps>(&rk1, &dh::<RefDeps>(&n_sk, &alice.st.dhs_pk));
    assert_eq!(st.rk, rk2);
    assert_eq!(st.cks, Some(cks));
    assert_eq!(bob.next_kp, 2, "the supplied key pair was used");
}

/// A ping-pong conversation driven by `ratchet_encrypt` and `ratchet_decrypt` only; each
/// receipt uses the supplied key pair exactly when the header carries a new ratchet key.
#[test]
fn conversation_from_setup_agrees() {
    let (mut alice, mut bob) = alice_and_bob();
    let rounds: [(bool, usize); 6] = [(true, 2), (false, 3), (true, 1), (false, 1), (true, 4), (false, 2)];
    let mut ratchets = 0;
    for (r, &(alice_sends, k)) in rounds.iter().enumerate() {
        for i in 0..k {
            let (snd, rcv) = if alice_sends { (&mut alice, &mut bob) } else { (&mut bob, &mut alice) };
            let m = snd.send(&message(r as u8, i));
            let new_key = rcv.st.dhr != Some(m.h.dh);
            let before_kp = rcv.next_kp;
            rcv.receive(&m);
            assert_eq!(rcv.next_kp == before_kp + 1, new_key, "key pair used iff new ratchet key");
            assert_eq!(rcv.st.dhr, Some(m.h.dh));
            if new_key {
                ratchets += 1;
                assert_eq!(m.h.n, 0, "the first message of each round opens a new chain");
            }
        }
    }
    assert_eq!(ratchets, rounds.len(), "one DH ratchet step per round");
    assert_eq!(alice.next_kp, 1 + 3, "Alice received three rounds");
    assert_eq!(bob.next_kp, 1 + 3, "Bob received three rounds");
    assert!(alice.st.sk_used.iter().all(|u| !*u) && bob.st.sk_used.iter().all(|u| !*u));
}

/// The headers carry `PN`: after a DH ratchet step the first header of the new sending
/// chain names the length of the previous one.
#[test]
fn headers_carry_previous_chain_length() {
    let (mut alice, mut bob) = alice_and_bob();
    for i in 0..3 {
        let m = alice.send(&message(0, i));
        assert_eq!((m.h.pn, m.h.n), (0, i as u32));
        bob.receive(&m);
    }
    let m = bob.send(b"reply");
    alice.receive(&m);
    let m = alice.send(b"next chain");
    assert_eq!((m.h.pn, m.h.n), (3, 0));
    assert_eq!(m.h.dh, alice.st.dhs_pk);
    let before = view(&bob.st);
    bob.receive(&m);
    assert_ne!(view(&bob.st), before);
}
