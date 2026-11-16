// Copyright (c) 2026 CatCrypt Contributors. MIT license.
//! Typestate encoding of the Signal Double Ratchet session.
//!
//! A session is a thin wrapper of [`RatchetState`] with a step counter; its transitions call
//! the ratchet functions of the crate ([`ratchet_init_alice`], [`ratchet_init_bob`],
//! [`ratchet_encrypt`], [`ratchet_decrypt`]), so the key logic has one implementation.
//! Once established, a party repeatedly sends and receives. The state type `Session` recurs:
//! each transition consumes `self` and returns the next `Session`, at `step + 1` when the
//! transition succeeds. Move semantics enforce linear step threading: a stale `Session`
//! value cannot be reused after it has ratcheted, so two sends cannot use the same chain-key
//! step.
//!
//!   * a party cannot send before establishing: `Uninitialized` has no `send`;
//!   * a party cannot reuse a step: the `Session` value is moved by its transition.
//!
//! Illegal orderings are compile errors (see the `compile_fail` doctests). A refused
//! operation is a run-time result: `send` without a sending chain and `receive` of a rejected
//! message return the session unchanged together with `None` (3.5 of the specification: on
//! an exception the changes to the state are discarded). The DH ratchet step is part of
//! `receive`, which takes the key pair of `GENERATE_DH` from the caller.

/// Ghost operations: a socket write in a running build, a trace entry in the symbolic build,
/// erased in a proof build.
pub trait DoubleRatchetGhost {
    /// A protocol event fires (tag: 3 = established, 0 = sent, 1 = received).
    fn event(&mut self, tag: u8, step: u64);
}

use crate::{
    ratchet_decrypt, ratchet_encrypt, ratchet_init_alice, ratchet_init_bob, DoubleRatchetDeps,
    MessageHeader, RatchetState, AD_LEN, MAX_CT_LEN, MAX_PLAINTEXT_LEN,
};

/// State: no ratchet session yet. The transitions are `establish_alice` and
/// `establish_bob`.
pub struct Uninitialized;

/// State: an established session at `step`, holding the ratchet state.
///
/// ```
/// use doubleratchet_hax::DoubleRatchetDeps;
/// use doubleratchet_hax::typestate_fsm::{Uninitialized, DoubleRatchetGhost};
/// # struct D; impl DoubleRatchetDeps for D {
/// #   fn hmac_sha256(_: &[u8;32], _: &[u8;1]) -> [u8;32] { [0u8;32] }
/// #   fn hkdf_extract(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] }
/// #   fn hkdf_expand_64(_: &[u8;32], _: &[u8;14]) -> [u8;64] { [0u8;64] }
/// #   fn x25519(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] }
/// #   fn aead_encrypt(_: &[u8;32], _: &[u8;256], _: usize, _: &[u8;104]) -> [u8;280] {
/// #     [0u8;280] }
/// #   fn aead_decrypt(_: &[u8;32], _: &[u8;280], _: usize, _: &[u8;104])
/// #     -> Option<([u8;256], usize)> { None } }
/// # struct G; impl DoubleRatchetGhost for G { fn event(&mut self, _: u8, _: u64) {} }
/// let mut g = G;
/// let s = Uninitialized.establish_alice::<D, _>(&mut g, [0u8;32], [1u8;32], [2u8;32], [3u8;32]);
/// let (s, sent) = s.send::<D, _>(&mut g, &[0u8;256], 5, &[0u8;64]);
/// assert!(sent.is_some());
/// assert_eq!(s.step(), 1);
/// ```
pub struct Session {
    st: RatchetState,
    step: u64,
}

impl Uninitialized {
    /// Transition `Uninitialized -> Session` at step 0: `RatchetInitAlice` at the shared
    /// secret `sk`, the responder's ratchet public key `bob_pk` and the initiator's key pair
    /// `(my_sk, my_pk)`.
    ///
    /// ```compile_fail
    /// // Cannot send before establishing: `Uninitialized` has no `send`.
    /// use doubleratchet_hax::DoubleRatchetDeps;
    /// use doubleratchet_hax::typestate_fsm::{Uninitialized, DoubleRatchetGhost};
    /// # struct D; impl DoubleRatchetDeps for D {
    /// #   fn hmac_sha256(_: &[u8;32], _: &[u8;1]) -> [u8;32] { [0u8;32] }
    /// #   fn hkdf_extract(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] }
    /// #   fn hkdf_expand_64(_: &[u8;32], _: &[u8;14]) -> [u8;64] { [0u8;64] }
    /// #   fn x25519(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] }
    /// #   fn aead_encrypt(_: &[u8;32], _: &[u8;256], _: usize, _: &[u8;104]) -> [u8;280] {
    /// #     [0u8;280] }
    /// #   fn aead_decrypt(_: &[u8;32], _: &[u8;280], _: usize, _: &[u8;104])
    /// #     -> Option<([u8;256], usize)> { None } }
    /// # struct G; impl DoubleRatchetGhost for G { fn event(&mut self, _: u8, _: u64) {} }
    /// let mut g = G;
    /// let _ = Uninitialized.send::<D, _>(&mut g, &[0u8;256], 0, &[0u8;64]);
    /// ```
    pub fn establish_alice<D: DoubleRatchetDeps, G: DoubleRatchetGhost>(
        self,
        ghost: &mut G,
        sk: [u8; 32],
        bob_pk: [u8; 32],
        my_sk: [u8; 32],
        my_pk: [u8; 32],
    ) -> Session {
        ghost.event(3, 0);
        Session { st: ratchet_init_alice::<D>(&sk, &bob_pk, &my_sk, &my_pk), step: 0 }
    }

    /// Transition `Uninitialized -> Session` at step 0: `RatchetInitBob` at the shared
    /// secret `sk` and the responder's key pair `(my_sk, my_pk)`.
    pub fn establish_bob<G: DoubleRatchetGhost>(
        self,
        ghost: &mut G,
        sk: [u8; 32],
        my_sk: [u8; 32],
        my_pk: [u8; 32],
    ) -> Session {
        ghost.event(3, 0);
        Session { st: ratchet_init_bob(&sk, &my_sk, &my_pk), step: 0 }
    }
}

impl Session {
    /// The current step count.
    pub fn step(&self) -> u64 {
        self.step
    }

    /// The ratchet state of the session.
    pub fn state(&self) -> &RatchetState {
        &self.st
    }

    /// Transition `Session -> Session`: [`ratchet_encrypt`] of the first `pt_len` bytes of
    /// `pt` with the associated data `ad`. On success the session is at `step + 1` and the
    /// header, the ciphertext buffer and the ciphertext length are returned. Without a
    /// sending chain the session is returned unchanged with `None`, and no ghost operation
    /// is called.
    ///
    /// ```compile_fail
    /// // Cannot reuse a step: `Session` is moved by the first `send`.
    /// use doubleratchet_hax::DoubleRatchetDeps;
    /// use doubleratchet_hax::typestate_fsm::{Uninitialized, DoubleRatchetGhost};
    /// # struct D; impl DoubleRatchetDeps for D {
    /// #   fn hmac_sha256(_: &[u8;32], _: &[u8;1]) -> [u8;32] { [0u8;32] }
    /// #   fn hkdf_extract(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] }
    /// #   fn hkdf_expand_64(_: &[u8;32], _: &[u8;14]) -> [u8;64] { [0u8;64] }
    /// #   fn x25519(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] }
    /// #   fn aead_encrypt(_: &[u8;32], _: &[u8;256], _: usize, _: &[u8;104]) -> [u8;280] {
    /// #     [0u8;280] }
    /// #   fn aead_decrypt(_: &[u8;32], _: &[u8;280], _: usize, _: &[u8;104])
    /// #     -> Option<([u8;256], usize)> { None } }
    /// # struct G; impl DoubleRatchetGhost for G { fn event(&mut self, _: u8, _: u64) {} }
    /// let mut g = G;
    /// let s = Uninitialized.establish_alice::<D, _>(&mut g, [0u8;32], [1u8;32], [2u8;32], [3u8;32]);
    /// let _a = s.send::<D, _>(&mut g, &[0u8;256], 0, &[0u8;64]);
    /// let _b = s.send::<D, _>(&mut g, &[0u8;256], 0, &[0u8;64]);
    /// ```
    pub fn send<D: DoubleRatchetDeps, G: DoubleRatchetGhost>(
        self,
        ghost: &mut G,
        pt: &[u8; MAX_PLAINTEXT_LEN],
        pt_len: usize,
        ad: &[u8; AD_LEN],
    ) -> (Session, Option<(MessageHeader, [u8; MAX_CT_LEN], usize)>) {
        match ratchet_encrypt::<D>(&self.st, pt, pt_len, ad) {
            Some((st1, h, ct, n)) => {
                ghost.event(0, self.step + 1);
                (Session { st: st1, step: self.step + 1 }, Some((h, ct, n)))
            }
            None => (self, None),
        }
    }

    /// Transition `Session -> Session`: [`ratchet_decrypt`] of the first `ct_len` bytes of
    /// `ct` under the header `h` and the associated data `ad`, with `(new_sk, new_pk)` the
    /// key pair of the DH ratchet step if the header carries a new ratchet key. On success
    /// the session is at `step + 1` and the plaintext buffer and its length are returned. On
    /// rejection the session is returned unchanged with `None`, and no ghost operation is
    /// called.
    pub fn receive<D: DoubleRatchetDeps, G: DoubleRatchetGhost>(
        self,
        ghost: &mut G,
        h: &MessageHeader,
        ct: &[u8; MAX_CT_LEN],
        ct_len: usize,
        ad: &[u8; AD_LEN],
        new_sk: &[u8; 32],
        new_pk: &[u8; 32],
    ) -> (Session, Option<([u8; MAX_PLAINTEXT_LEN], usize)>) {
        match ratchet_decrypt::<D>(&self.st, h, ct, ct_len, ad, new_sk, new_pk) {
            Some((st1, pt, n)) => {
                ghost.event(1, self.step + 1);
                (Session { st: st1, step: self.step + 1 }, Some((pt, n)))
            }
            None => (self, None),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;
    use crate::test_deps::{keypair_of, test_ad, view, RefDeps};

    #[derive(Default)]
    struct TraceGhost {
        events: Vec<(u8, u64)>,
    }
    impl DoubleRatchetGhost for TraceGhost {
        fn event(&mut self, tag: u8, step: u64) {
            self.events.push((tag, step));
        }
    }

    fn pt(msg: &[u8]) -> [u8; MAX_PLAINTEXT_LEN] {
        let mut b = [0u8; MAX_PLAINTEXT_LEN];
        b[..msg.len()].copy_from_slice(msg);
        b
    }

    /// The session transitions compute the same states, headers and ciphertexts as the
    /// ratchet functions called directly, and record one event per successful transition.
    #[test]
    fn session_matches_ratchet_functions() {
        let sk = [7u8; 32];
        let (a_sk, a_pk) = keypair_of(0xa0, 0);
        let (b_sk, b_pk) = keypair_of(0xb0, 0);
        let (n_sk, n_pk) = keypair_of(0xb0, 1);
        let ad = test_ad();

        // Straight-line: Alice sends twice, Bob receives the second message.
        let a0 = ratchet_init_alice::<RefDeps>(&sk, &b_pk, &a_sk, &a_pk);
        let (a1, _h0, _c0, _l0) =
            ratchet_encrypt::<RefDeps>(&a0, &pt(b"one"), 3, &ad).expect("sending chain");
        let (a2, h1, c1, l1) =
            ratchet_encrypt::<RefDeps>(&a1, &pt(b"two"), 3, &ad).expect("sending chain");
        let b0 = ratchet_init_bob(&sk, &b_sk, &b_pk);
        let (b1, p1, m1) = ratchet_decrypt::<RefDeps>(&b0, &h1, &c1, l1, &ad, &n_sk, &n_pk)
            .expect("accepted");

        // Typestate.
        let mut ga = TraceGhost::default();
        let mut gb = TraceGhost::default();
        let sa = Uninitialized.establish_alice::<RefDeps, _>(&mut ga, sk, b_pk, a_sk, a_pk);
        let (sa, _) = sa.send::<RefDeps, _>(&mut ga, &pt(b"one"), 3, &ad);
        let (sa, sent) = sa.send::<RefDeps, _>(&mut ga, &pt(b"two"), 3, &ad);
        let (h, c, l) = sent.expect("sending chain");
        let sb = Uninitialized.establish_bob(&mut gb, sk, b_sk, b_pk);
        let (sb, got) = sb.receive::<RefDeps, _>(&mut gb, &h, &c, l, &ad, &n_sk, &n_pk);
        let (p, m) = got.expect("accepted");

        assert_eq!(view(sa.state()), view(&a2));
        assert_eq!(view(sb.state()), view(&b1));
        assert_eq!((h.dh, h.pn, h.n), (h1.dh, h1.pn, h1.n));
        assert_eq!((c, l), (c1, l1));
        assert_eq!((p, m), (p1, m1));
        assert_eq!(&p[..m], b"two");
        assert_eq!(sa.step(), 2);
        assert_eq!(sb.step(), 1);
        assert_eq!(ga.events, [(3, 0), (0, 1), (0, 2)]);
        assert_eq!(gb.events, [(3, 0), (1, 1)]);
    }

    /// A refused send and a rejected receive return the session unchanged and call no
    /// ghost operation; the session then accepts the genuine message.
    #[test]
    fn refusal_keeps_the_session() {
        let sk = [5u8; 32];
        let (a_sk, a_pk) = keypair_of(0xa0, 0);
        let (b_sk, b_pk) = keypair_of(0xb0, 0);
        let (n_sk, n_pk) = keypair_of(0xb0, 1);
        let ad = test_ad();
        let mut ga = TraceGhost::default();
        let mut gb = TraceGhost::default();

        let sb = Uninitialized.establish_bob(&mut gb, sk, b_sk, b_pk);
        let before = view(sb.state());
        let (sb, sent) = sb.send::<RefDeps, _>(&mut gb, &pt(b"early"), 5, &ad);
        assert!(sent.is_none(), "the responder has no sending chain before receiving");
        assert_eq!(view(sb.state()), before);
        assert_eq!(sb.step(), 0);

        let sa = Uninitialized.establish_alice::<RefDeps, _>(&mut ga, sk, b_pk, a_sk, a_pk);
        let (_sa, sent) = sa.send::<RefDeps, _>(&mut ga, &pt(b"hello"), 5, &ad);
        let (h, c, l) = sent.expect("sending chain");
        let mut bad = c;
        bad[0] ^= 1;
        let (sb, got) = sb.receive::<RefDeps, _>(&mut gb, &h, &bad, l, &ad, &n_sk, &n_pk);
        assert!(got.is_none(), "a modified ciphertext is rejected");
        assert_eq!(view(sb.state()), before, "a rejected message changes no state");
        assert_eq!(sb.step(), 0);
        assert_eq!(gb.events, [(3, 0)], "a refusal records no event");

        let (sb, got) = sb.receive::<RefDeps, _>(&mut gb, &h, &c, l, &ad, &n_sk, &n_pk);
        let (p, m) = got.expect("the genuine message is accepted");
        assert_eq!(&p[..m], b"hello");
        assert_eq!(sb.step(), 1);
        assert_eq!(sb.state().dhs_pk, n_pk, "the first receipt performs the DH ratchet step");
    }

    /// After `establish_alice` no key field equals the shared secret it was given; the
    /// session holds a sending chain and no receiving chain (`RatchetInitAlice`).
    #[test]
    fn establish_alice_holds_no_shared_secret() {
        for seed in 0..16u8 {
            let sk = [seed.wrapping_mul(17).wrapping_add(3); 32];
            let (my_sk, my_pk) = keypair_of(0x40, seed as u32);
            let (_b_sk, b_pk) = keypair_of(0xc0, seed as u32);
            let mut g = TraceGhost::default();
            let s = Uninitialized.establish_alice::<RefDeps, _>(&mut g, sk, b_pk, my_sk, my_pk);
            let st = s.state();
            assert!(st.cks.is_some(), "the initiator derives a sending chain");
            assert_eq!(st.ckr, None, "the initiator holds no receiving chain key");
            assert_eq!(st.dhr, Some(b_pk));
            assert_ne!(st.rk, sk, "the root key is derived from the shared secret");
            assert_ne!(st.cks, Some(sk), "the sending chain key is not the shared secret");
        }
    }
}
