//! Out-of-order delivery, the skipped-message-key store, `MAX_SKIP` and replay rejection,
//! against `RatchetReceiveKey`, `TrySkippedMessageKeys` and `SkipMessageKeys` of section 3.5
//! of the Signal specification.
//!
//! The tests check, over the reference dependency of `tests/common`:
//!
//! - every permutation tested of up to `MAX_SKIP + 1` messages of one chain decrypts;
//! - messages of the previous chain decrypt after the first message of the new chain, whose
//!   header carries the length `pn` of the previous chain;
//! - a jump of `MAX_SKIP + 1` positions is rejected with the state unchanged, a jump of
//!   `MAX_SKIP` is accepted;
//! - a full store rejects a message that needs a further slot, with the state unchanged;
//! - a skipped key is used once: a second delivery is rejected (decision D6 for a position
//!   of the current chain), and the cleared slot holds zero bytes;
//! - a replay of an in-order message is rejected, and so is a replay into a closed chain,
//!   whose DH attempt fails under the AEAD;
//! - a property test: random delivery orders over two chains within the bounds decrypt
//!   every message.

mod common;
use common::{alice_and_bob, free_slots_are_zero, message, stored, view, Party, Sent};
use doubleratchet_hax::{MAX_SKIP, MAX_STORED};
use proptest::prelude::*;

/// Alice sends `k` messages of her current chain.
fn burst(alice: &mut Party, tag: u8, k: usize) -> Vec<Sent> {
    (0..k).map(|i| alice.send(&message(tag, i))).collect()
}

/// Asserts that `m` is rejected and that the party's state is unchanged.
fn assert_rejected(p: &mut Party, m: &Sent, why: &str) {
    let before = view(&p.st);
    let kp = p.next_kp;
    assert!(p.try_receive(m).is_none(), "{why}: rejected");
    assert_eq!(view(&p.st), before, "{why}: state unchanged");
    assert_eq!(p.next_kp, kp);
}

#[test]
fn in_chain_permutations_decrypt() {
    let k = MAX_SKIP as usize + 1;
    let orders: Vec<Vec<usize>> = vec![
        (0..k).rev().collect(),
        (0..k).map(|i| (i * 5) % k).collect(),
        {
            let mut v: Vec<usize> = (0..k).collect();
            v.swap(0, k - 1);
            v
        },
    ];
    for order in orders {
        let (mut alice, mut bob) = alice_and_bob();
        let msgs = burst(&mut alice, 1, k);
        for &i in &order {
            bob.receive(&msgs[i]);
            assert!(free_slots_are_zero(&bob.st));
        }
        assert_eq!(stored(&bob.st), 0, "every skipped key was used");
        assert_eq!(bob.st.nr, k as u32);
    }
}

#[test]
fn previous_chain_after_new_chain() {
    let (mut alice, mut bob) = alice_and_bob();
    let a1 = burst(&mut alice, 1, 3);
    bob.receive(&a1[0]);
    let r = bob.send(b"reply");
    alice.receive(&r);
    let a2 = burst(&mut alice, 2, 2);
    assert_eq!((a2[0].h.pn, a2[0].h.n), (3, 0), "the new chain names the old length");

    bob.receive(&a2[1]);
    assert_eq!(stored(&bob.st), 3, "a1[1], a1[2] through pn and a2[0] through n");
    bob.receive(&a1[2]);
    bob.receive(&a2[0]);
    bob.receive(&a1[1]);
    assert_eq!(stored(&bob.st), 0);
    assert!(free_slots_are_zero(&bob.st));
}

#[test]
fn jump_over_max_skip_is_rejected() {
    let k = MAX_SKIP as usize + 2;
    let (mut alice, mut bob) = alice_and_bob();
    let msgs = burst(&mut alice, 1, k);
    // The first receipt at n = MAX_SKIP + 1 skips MAX_SKIP + 1 keys.
    assert_rejected(&mut bob, &msgs[k - 1], "jump of MAX_SKIP + 1");
    // At n = MAX_SKIP exactly MAX_SKIP keys are skipped.
    bob.receive(&msgs[k - 2]);
    assert_eq!(stored(&bob.st), MAX_SKIP as usize);
    bob.receive(&msgs[k - 1]);
    bob.receive(&msgs[0]);
}

#[test]
fn jump_over_max_skip_through_pn_is_rejected() {
    let (mut alice, mut bob) = alice_and_bob();
    let a1 = burst(&mut alice, 1, MAX_SKIP as usize + 2);
    bob.receive(&a1[0]);
    let r = bob.send(b"reply");
    alice.receive(&r);
    let a2 = burst(&mut alice, 2, 1);
    // pn = MAX_SKIP + 2 and Nr = 1: MAX_SKIP + 1 keys of the old chain would be skipped.
    assert_rejected(&mut bob, &a2[0], "jump through pn");
    bob.receive(&a1[1]);
    bob.receive(&a2[0]);
}

/// Fills the store with `MAX_STORED` keys over two chains, then a message that needs one more
/// slot is rejected; after one stored key is used the message is accepted.
#[test]
fn full_store_rejects() {
    let skip = MAX_SKIP as usize;
    assert_eq!(MAX_STORED, 2 * skip, "the scenario fills the store with two jumps");
    let (mut alice, mut bob) = alice_and_bob();
    let a1 = burst(&mut alice, 1, skip + 1);
    bob.receive(&a1[skip]);
    let r1 = bob.send(b"reply one");
    alice.receive(&r1);
    let a2 = burst(&mut alice, 2, skip + 1);
    bob.receive(&a2[skip]);
    assert_eq!(stored(&bob.st), MAX_STORED, "the store is full");
    let r2 = bob.send(b"reply two");
    alice.receive(&r2);
    let a3 = burst(&mut alice, 3, 2);
    assert_rejected(&mut bob, &a3[1], "a skipped key into a full store");
    // A message that needs no slot is accepted.
    bob.receive(&a3[0]);
    bob.receive(&a3[1]);
    // Stored keys of both closed chains are still usable.
    bob.receive(&a1[0]);
    bob.receive(&a2[3]);
    assert_eq!(stored(&bob.st), MAX_STORED - 2);
    assert!(free_slots_are_zero(&bob.st));
}

#[test]
fn skipped_key_is_used_once() {
    let (mut alice, mut bob) = alice_and_bob();
    let msgs = burst(&mut alice, 1, 3);
    bob.receive(&msgs[2]);
    assert_eq!(stored(&bob.st), 2);
    bob.receive(&msgs[0]);
    assert_eq!(stored(&bob.st), 1);
    assert!(free_slots_are_zero(&bob.st), "the cleared slot holds zero bytes");
    assert_rejected(&mut bob, &msgs[0], "second delivery of a skipped message");
    assert_rejected(&mut bob, &msgs[2], "replay of the in-order message");
    bob.receive(&msgs[1]);
}

#[test]
fn replay_in_order_is_rejected() {
    let (mut alice, mut bob) = alice_and_bob();
    let msgs = burst(&mut alice, 1, 2);
    bob.receive(&msgs[0]);
    assert_rejected(&mut bob, &msgs[0], "replay at the current chain");
    bob.receive(&msgs[1]);
    assert_rejected(&mut bob, &msgs[1], "replay at the current chain");
}

/// A delivered message of a closed chain whose key is not stored: its ratchet key differs
/// from `DHr`, so the DH ratchet step is attempted, the AEAD rejects, and the state stays.
#[test]
fn replay_into_closed_chain_is_rejected() {
    let (mut alice, mut bob) = alice_and_bob();
    let a1 = burst(&mut alice, 1, 2);
    bob.receive(&a1[0]);
    bob.receive(&a1[1]);
    let r = bob.send(b"reply");
    alice.receive(&r);
    let a2 = burst(&mut alice, 2, 1);
    bob.receive(&a2[0]);
    assert_rejected(&mut bob, &a1[0], "replay into a closed chain");
    assert_rejected(&mut bob, &a1[1], "replay into a closed chain");
}

/// A header with an unknown ratchet key is rejected under the AEAD, the state stays, and
/// the genuine message is accepted afterwards.
#[test]
fn unknown_ratchet_key_is_rejected() {
    let (mut alice, mut bob) = alice_and_bob();
    let m0 = alice.send(b"zero");
    bob.receive(&m0);
    let m1 = alice.send(b"one");
    let mut forged = m1.clone();
    forged.h.dh = common::keypair_of(0xee, 0).1;
    assert_rejected(&mut bob, &forged, "unknown ratchet key");
    bob.receive(&m1);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// Two chains of Alice: the first message delivered to Bob is a random one of chain 1;
    /// after Bob's reply opens Alice's chain 2, the remaining messages of chain 1 and all of
    /// chain 2 are delivered in a random interleaving. Every message decrypts, every stored
    /// key is used, and free slots hold zero bytes throughout.
    #[test]
    fn random_delivery_orders_decrypt(
        (k1, k2, first, order) in (1usize..=MAX_SKIP as usize, 1usize..=MAX_SKIP as usize)
            .prop_flat_map(|(k1, k2)| (
                Just(k1),
                Just(k2),
                0..k1,
                Just((0..k1 - 1 + k2).collect::<Vec<usize>>()).prop_shuffle(),
            ))
    ) {
        let (mut alice, mut bob) = alice_and_bob();
        let a1 = burst(&mut alice, 1, k1);
        let first_pt = bob.try_receive(&a1[first]);
        prop_assert_eq!(first_pt, Some(a1[first].pt.clone()));
        let r = bob.send(b"reply");
        alice.receive(&r);
        let a2 = burst(&mut alice, 2, k2);
        let rest: Vec<&Sent> = a1
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != first)
            .map(|(_, m)| m)
            .chain(a2.iter())
            .collect();
        prop_assert_eq!(rest.len(), order.len());
        for &j in &order {
            let got = bob.try_receive(rest[j]);
            prop_assert_eq!(got, Some(rest[j].pt.clone()));
            prop_assert!(free_slots_are_zero(&bob.st));
        }
        prop_assert_eq!(stored(&bob.st), 0);
        prop_assert_eq!(bob.next_kp, 3, "two DH ratchet steps");
    }
}
