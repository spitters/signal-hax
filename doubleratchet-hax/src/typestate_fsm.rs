// Copyright (c) 2026 CatCrypt Contributors. MIT license.
//! Typestate encoding of the Signal Double Ratchet session FSM.
//!
//! The session as a typestate machine; each transition is one protocol step.
//! Unlike a terminating handshake, a ratchet session is a *loop*: once
//! established, a party repeatedly sends, receives, or performs a DH ratchet
//! step, each transition advancing the ratchet state by one step.
//! The typestate encoding models this with a *recurring* state type `Session`,
//! whose transitions consume `self` and return the next `Session` (at
//! `step + 1`). Move semantics then enforce **linear step threading**: a stale
//! `Session` value cannot be reused after it has ratcheted, so two sends can
//! never race the same chain-key step.
//!
//!   * you cannot send before establishing — `Uninitialized` has no `send`;
//!   * you cannot reuse a step — the `Session` value is moved by its transition.
//!
//! Illegal orderings are compile errors (see the `compile_fail` doctests). The
//! ratchet crypto (HMAC-SHA-256 KDF chain, HKDF root step, DH — the crate's
//! `kdf_ck` / `kdf_rk` / `dh` over its `DoubleRatchetDeps`) is factored behind
//! the `DoubleRatchetOps` trait, so the FSM itself is first-order control over
//! a step counter and the chain keys. The test `dr_matches_straight_line`
//! checks that the FSM produces the same chain keys and trace as the same steps
//! written as one straight-line function.

/// Ghost operations: a socket write in a running build, a trace entry in the
/// symbolic build, erased in a proof build.
pub trait DoubleRatchetGhost {
    /// A message is sent at `step`, carrying its derived message key.
    fn send(&mut self, step: u64, msg_key: &[u8; 32]);
    /// A message is received at `step`, carrying its derived message key.
    fn recv(&mut self, step: u64, msg_key: &[u8; 32]);
    /// A protocol event fires (tag: 3=established, 0=sent, 1=received, 2=dh-ratchet).
    fn event(&mut self, tag: u8, step: u64);
}

/// The ratchet crypto. `crate::Ops<D>` implements it by the crate's
/// `kdf_ck` / `kdf_rk` / `dh` (HMAC-SHA-256 KDF chain, HKDF root step and DH)
/// over a dependency `D`.
pub trait DoubleRatchetOps {
    /// Chain-key KDF: `kdf_ck(chain_key, constant)`. Constant `0x01` advances
    /// the chain, `0x02` derives the message key.
    fn kdf_ck(chain_key: &[u8; 32], constant: u8) -> [u8; 32];
    /// Root-key KDF: `(new_root, new_chain) = kdf_rk(root_key, dh_output)`.
    fn kdf_rk(root_key: &[u8; 32], dh_output: &[u8; 32]) -> ([u8; 32], [u8; 32]);
    /// Diffie-Hellman: `dh(my_sk, their_pk) -> shared secret`.
    fn dh(my_sk: &[u8; 32], their_pk: &[u8; 32]) -> [u8; 32];
}

/// State: no ratchet session yet. The only transition is `establish`.
pub struct Uninitialized;

/// State: an established session at `step`, holding the root key and the
/// sending/receiving chain keys. Recurs: every send/receive/dh-ratchet
/// transition returns a fresh `Session` at `step + 1`.
pub struct Session {
    root_key: [u8; 32],
    send_ck: [u8; 32],
    recv_ck: [u8; 32],
    send_n: u32,
    recv_n: u32,
    my_sk: [u8; 32],
    my_pk: [u8; 32],
    remote_pk: [u8; 32],
    step: u64,
}

impl Uninitialized {
    /// Transition `Uninitialized -> Session` at step 0: the initiator's DH
    /// ratchet, deriving the initial sending chain key.
    ///
    /// ```compile_fail
    /// // Cannot send before establishing: `Uninitialized` has no `send`.
    /// use doubleratchet_hax::typestate_fsm::{Uninitialized, DoubleRatchetOps, DoubleRatchetGhost};
    /// # struct O; impl DoubleRatchetOps for O {
    /// #   fn kdf_ck(_: &[u8;32], _: u8) -> [u8;32] { [0u8;32] }
    /// #   fn kdf_rk(_: &[u8;32], _: &[u8;32]) -> ([u8;32],[u8;32]) { ([0u8;32],[0u8;32]) }
    /// #   fn dh(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] } }
    /// # struct G; impl DoubleRatchetGhost for G {
    /// #   fn send(&mut self, _: u64, _: &[u8;32]) {} fn recv(&mut self, _: u64, _: &[u8;32]) {}
    /// #   fn event(&mut self, _: u8, _: u64) {} }
    /// let mut g = G;
    /// let _ = Uninitialized.send::<O, _>(&mut g);
    /// ```
    pub fn establish<O: DoubleRatchetOps, G: DoubleRatchetGhost>(
        self,
        ghost: &mut G,
        root_key: [u8; 32],
        my_sk: [u8; 32],
        my_pk: [u8; 32],
        remote_pk: [u8; 32],
    ) -> Session {
        let dh_out = O::dh(&my_sk, &remote_pk);
        let (new_rk, send_ck) = O::kdf_rk(&root_key, &dh_out);
        ghost.event(3, 0);
        Session {
            root_key: new_rk,
            send_ck,
            recv_ck: root_key,
            send_n: 0,
            recv_n: 0,
            my_sk,
            my_pk,
            remote_pk,
            step: 0,
        }
    }
}

impl Session {
    /// The current step count.
    pub fn step(&self) -> u64 {
        self.step
    }

    /// The current root key.
    pub fn root_key(&self) -> &[u8; 32] {
        &self.root_key
    }

    /// The current sending chain key.
    pub fn send_ck(&self) -> &[u8; 32] {
        &self.send_ck
    }

    /// The current receiving chain key.
    pub fn recv_ck(&self) -> &[u8; 32] {
        &self.recv_ck
    }

    /// The number of messages sent in the current sending chain.
    pub fn send_n(&self) -> u32 {
        self.send_n
    }

    /// The number of messages received in the current receiving chain.
    pub fn recv_n(&self) -> u32 {
        self.recv_n
    }

    /// Our current DH public key.
    pub fn my_pk(&self) -> &[u8; 32] {
        &self.my_pk
    }

    /// The remote party's current DH public key.
    pub fn remote_pk(&self) -> &[u8; 32] {
        &self.remote_pk
    }

    /// Transition `Session -> Session` (step + 1): symmetric ratchet on the
    /// sending chain — derive a message key and advance `send_ck`.
    ///
    /// Consumes `self`, so a ratcheted step cannot be reused.
    ///
    /// ```compile_fail
    /// // Cannot reuse a step: `Session` is moved by the first `send`.
    /// use doubleratchet_hax::typestate_fsm::{Uninitialized, DoubleRatchetOps, DoubleRatchetGhost};
    /// # struct O; impl DoubleRatchetOps for O {
    /// #   fn kdf_ck(_: &[u8;32], _: u8) -> [u8;32] { [0u8;32] }
    /// #   fn kdf_rk(_: &[u8;32], _: &[u8;32]) -> ([u8;32],[u8;32]) { ([0u8;32],[0u8;32]) }
    /// #   fn dh(_: &[u8;32], _: &[u8;32]) -> [u8;32] { [0u8;32] } }
    /// # struct G; impl DoubleRatchetGhost for G {
    /// #   fn send(&mut self, _: u64, _: &[u8;32]) {} fn recv(&mut self, _: u64, _: &[u8;32]) {}
    /// #   fn event(&mut self, _: u8, _: u64) {} }
    /// let mut g = G;
    /// let s = Uninitialized.establish::<O, _>(&mut g, [0u8;32], [1u8;32], [2u8;32], [3u8;32]);
    /// let _a = s.send::<O, _>(&mut g);
    /// let _b = s.send::<O, _>(&mut g);
    /// ```
    pub fn send<O: DoubleRatchetOps, G: DoubleRatchetGhost>(self, ghost: &mut G) -> Session {
        let new_send_ck = O::kdf_ck(&self.send_ck, 0x01);
        let mk = O::kdf_ck(&self.send_ck, 0x02);
        ghost.send(self.step, &mk);
        ghost.event(0, self.step + 1);
        Session {
            send_ck: new_send_ck,
            send_n: self.send_n + 1,
            step: self.step + 1,
            ..self
        }
    }

    /// Transition `Session -> Session` (step + 1): symmetric ratchet on the
    /// receiving chain. Consumes `self`.
    pub fn receive<O: DoubleRatchetOps, G: DoubleRatchetGhost>(self, ghost: &mut G) -> Session {
        let new_recv_ck = O::kdf_ck(&self.recv_ck, 0x01);
        let mk = O::kdf_ck(&self.recv_ck, 0x02);
        ghost.recv(self.step, &mk);
        ghost.event(1, self.step + 1);
        Session {
            recv_ck: new_recv_ck,
            recv_n: self.recv_n + 1,
            step: self.step + 1,
            ..self
        }
    }

    /// Transition `Session -> Session` (step + 1): DH ratchet step on receiving
    /// a new remote DH public key — derive fresh receiving and sending chains
    /// under a new keypair. Consumes `self`.
    pub fn dh_ratchet<O: DoubleRatchetOps, G: DoubleRatchetGhost>(
        self,
        ghost: &mut G,
        new_remote_pk: &[u8; 32],
        new_my_sk: &[u8; 32],
        new_my_pk: &[u8; 32],
    ) -> Session {
        let dh1 = O::dh(&self.my_sk, new_remote_pk);
        let (rk1, new_recv_ck) = O::kdf_rk(&self.root_key, &dh1);
        let dh2 = O::dh(new_my_sk, new_remote_pk);
        let (rk2, new_send_ck) = O::kdf_rk(&rk1, &dh2);
        ghost.event(2, self.step + 1);
        Session {
            root_key: rk2,
            send_ck: new_send_ck,
            recv_ck: new_recv_ck,
            send_n: 0,
            recv_n: 0,
            my_sk: *new_my_sk,
            my_pk: *new_my_pk,
            remote_pk: *new_remote_pk,
            step: self.step + 1,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec::Vec;

    use super::*;
    use crate::test_deps::RefDeps;
    use crate::{dh, kdf_ck, kdf_rk};

    /// Concrete ops: the crate's KDF chain, root step and DH over the reference
    /// dependency.
    type RealOps = crate::Ops<RefDeps>;

    #[derive(Default)]
    struct TraceGhost {
        sends: Vec<(u64, [u8; 32])>,
        recvs: Vec<(u64, [u8; 32])>,
        events: Vec<(u8, u64)>,
    }
    impl DoubleRatchetGhost for TraceGhost {
        fn send(&mut self, step: u64, msg_key: &[u8; 32]) {
            self.sends.push((step, *msg_key));
        }
        fn recv(&mut self, step: u64, msg_key: &[u8; 32]) {
            self.recvs.push((step, *msg_key));
        }
        fn event(&mut self, tag: u8, step: u64) {
            self.events.push((tag, step));
        }
    }

    /// Straight-line reference: establish, send, send — two steps
    /// on the sending chain, using the crate's real KDF directly.
    fn run_two_steps<G: DoubleRatchetGhost>(
        ghost: &mut G,
        root_key: &[u8; 32],
        my_sk: &[u8; 32],
        remote_pk: &[u8; 32],
    ) -> ([u8; 32], [u8; 32]) {
        // establish (initiator DH ratchet)
        let dh_out = dh::<RefDeps>(my_sk, remote_pk);
        let (rk0, send_ck0) = kdf_rk::<RefDeps>(root_key, &dh_out);
        ghost.event(3, 0);
        // step 0 -> 1 (send)
        let send_ck1 = kdf_ck::<RefDeps>(&send_ck0, 0x01);
        let mk0 = kdf_ck::<RefDeps>(&send_ck0, 0x02);
        ghost.send(0, &mk0);
        ghost.event(0, 1);
        // step 1 -> 2 (send)
        let send_ck2 = kdf_ck::<RefDeps>(&send_ck1, 0x01);
        let mk1 = kdf_ck::<RefDeps>(&send_ck1, 0x02);
        ghost.send(1, &mk1);
        ghost.event(0, 2);
        (rk0, send_ck2)
    }

    #[test]
    fn dr_matches_straight_line() {
        let root_key = [7u8; 32];
        let my_sk = [1u8; 32];
        let my_pk = [9u8; 32];
        let remote_pk = [2u8; 32];

        // Straight-line function.
        let mut g_line = TraceGhost::default();
        let (rk_line, sck_line) =
            run_two_steps(&mut g_line, &root_key, &my_sk, &remote_pk);

        // Typestate FSM: the ratchet loop, threaded linearly.
        let mut g_fsm = TraceGhost::default();
        let s0 = Uninitialized.establish::<RealOps, _>(&mut g_fsm, root_key, my_sk, my_pk, remote_pk);
        let s1 = s0.send::<RealOps, _>(&mut g_fsm);
        let s2 = s1.send::<RealOps, _>(&mut g_fsm);

        assert_eq!(s2.step(), 2, "two sends advance to step 2");
        assert_eq!(s2.send_n(), 2, "two messages on the sending chain");
        assert_eq!(*s2.root_key(), rk_line, "root-key differs");
        assert_eq!(*s2.send_ck(), sck_line, "sending chain-key differs");
        assert_eq!(g_fsm.sends, g_line.sends, "send trace differs");
        assert_eq!(g_fsm.events, g_line.events, "event trace differs");
        assert_eq!(g_fsm.sends.len(), 2, "two messages sent");
        assert_eq!(g_fsm.events.len(), 3, "establish + two sends");
    }

    /// The FSM is deterministic: re-driving the same transitions from the same
    /// inputs yields an identical final state and trace.
    #[test]
    fn dr_send_receive_dh_ratchet_deterministic() {
        let root_key = [5u8; 32];
        let my_sk = [1u8; 32];
        let my_pk = [8u8; 32];
        let remote_pk = [2u8; 32];
        let next_remote = [3u8; 32];
        let next_sk = [4u8; 32];
        let next_pk = [6u8; 32];

        let drive = |g: &mut TraceGhost| -> ([u8; 32], u64) {
            let s = Uninitialized
                .establish::<RealOps, _>(g, root_key, my_sk, my_pk, remote_pk)
                .send::<RealOps, _>(g)
                .receive::<RealOps, _>(g)
                .dh_ratchet::<RealOps, _>(g, &next_remote, &next_sk, &next_pk);
            (*s.send_ck(), s.step())
        };

        let mut g_a = TraceGhost::default();
        let (sck_a, step_a) = drive(&mut g_a);
        let mut g_b = TraceGhost::default();
        let (sck_b, step_b) = drive(&mut g_b);

        assert_eq!(step_a, 3, "establish + send + receive + dh-ratchet = step 3");
        assert_eq!(sck_a, sck_b, "final sending chain-key must be deterministic");
        assert_eq!(step_a, step_b);
        assert_eq!(g_a.sends, g_b.sends);
        assert_eq!(g_a.recvs, g_b.recvs);
        assert_eq!(g_a.events, g_b.events);
        assert_eq!(g_a.events.len(), 4, "establish + send + receive + dh-ratchet");
    }
}
