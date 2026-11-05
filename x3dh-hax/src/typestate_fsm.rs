//! Typestate encoding of the Signal X3DH initiator FSM.
//!
//! The initiator session as a typestate machine; each transition is one
//! protocol step. The initiator (Alice) runs a two-step machine: receive Bob's
//! pre-key bundle, then send the initial message. Each state is a distinct Rust
//! type; a transition consumes one state value and returns the next, so move
//! semantics make the Rust compiler check the ordering:
//!
//!   * you cannot send the init message before receiving a bundle — `Start` has
//!     no `send_init`;
//!   * you cannot process a bundle twice — `Start` is moved by `receive_bundle`.
//!
//! Illegal orderings are compile errors (see the `compile_fail` doctests). The
//! socket I/O is factored into the `X3dhGhost` instance and the DH/KDF crypto
//! into `X3dhCrypto`, so the module is first-order control only. The test
//! `signal_matches_straight_line` checks that the machine produces the same
//! session key, signature verdict and message/event trace as the same steps
//! written as one straight-line function.

use crate::protocol::{initiate, X3dhCrypto};
use crate::types::{X3dhInitMessage, X3dhKey, X3dhPreKeyBundle, X3dhSessionKey};

/// Ghost operations: a socket write in a running build, a trace entry in the
/// symbolic build, erased in a proof build.
pub trait X3dhGhost {
    /// The initial message is emitted on the wire.
    fn send_init(&mut self, msg: &X3dhInitMessage);
    /// A protocol event fires (tag: 0=bundle received, 1=init sent).
    fn event(&mut self, tag: u8, key: &X3dhKey);
}

/// State 0: nothing received. The only transition is `receive_bundle`.
pub struct Start;

/// State 1: Bob's pre-key bundle has been received; ready to send the init
/// message.
pub struct BundleReceived {
    bundle: X3dhPreKeyBundle,
}

/// State 2 (terminal): the session key is established.
pub struct SessionEstablished {
    session_key: X3dhSessionKey,
    sig_valid: bool,
}

impl Start {
    /// Transition `Start -> BundleReceived`: accept Bob's pre-key bundle.
    ///
    /// ```compile_fail
    /// // Cannot send before receiving a bundle: `Start` has no `send_init`.
    /// use x3dh_hax::typestate_fsm::Start;
    /// # struct G; impl x3dh_hax::typestate_fsm::X3dhGhost for G {
    /// #   fn send_init(&mut self, _: &x3dh_hax::types::X3dhInitMessage) {}
    /// #   fn event(&mut self, _: u8, _: &x3dh_hax::types::X3dhKey) {} }
    /// let mut g = G;
    /// let _ = Start.send_init(&mut g, &[0u8; 32], &[0u8; 32], false);
    /// ```
    ///
    /// ```compile_fail
    /// // Cannot receive twice: `Start` is moved by the first `receive_bundle`.
    /// use x3dh_hax::typestate_fsm::Start;
    /// use x3dh_hax::types::{X3dhPreKeyBundle, ZERO_KEY, ZERO_SIGNATURE};
    /// # struct G; impl x3dh_hax::typestate_fsm::X3dhGhost for G {
    /// #   fn send_init(&mut self, _: &x3dh_hax::types::X3dhInitMessage) {}
    /// #   fn event(&mut self, _: u8, _: &x3dh_hax::types::X3dhKey) {} }
    /// let mut g = G;
    /// let b = X3dhPreKeyBundle { ik: ZERO_KEY, spk: ZERO_KEY, opk: ZERO_KEY, sig: ZERO_SIGNATURE };
    /// let s = Start;
    /// let _a = s.receive_bundle(&mut g, b);
    /// let _c = s.receive_bundle(&mut g, b);
    /// ```
    pub fn receive_bundle<G: X3dhGhost>(
        self,
        ghost: &mut G,
        bundle: X3dhPreKeyBundle,
    ) -> BundleReceived {
        ghost.event(0, &bundle.ik);
        BundleReceived { bundle }
    }
}

impl BundleReceived {
    /// Transition `BundleReceived -> SessionEstablished`: run X3DH and emit the
    /// initial message. Consumes `self`, so the bundle cannot be reused.
    pub fn send_init<C: X3dhCrypto, G: X3dhGhost>(
        self,
        ghost: &mut G,
        ik_a_secret: &X3dhKey,
        ek_a_secret: &X3dhKey,
        use_opk: bool,
    ) -> SessionEstablished {
        let (sk, msg, sig_valid) =
            initiate::<C>(ik_a_secret, ek_a_secret, &self.bundle, use_opk);
        ghost.send_init(&msg);
        ghost.event(1, &msg.ek_a);
        SessionEstablished { session_key: sk, sig_valid }
    }
}

impl SessionEstablished {
    /// The established session key.
    pub fn session_key(&self) -> &X3dhSessionKey {
        &self.session_key
    }

    /// Whether the signed pre-key signature verified.
    pub fn sig_valid(&self) -> bool {
        self.sig_valid
    }
}

/// Drive the full Signal X3DH initiator handshake through the typestate FSM.
pub fn run_signal_handshake<C: X3dhCrypto, G: X3dhGhost>(
    ghost: &mut G,
    ik_a_secret: &X3dhKey,
    ek_a_secret: &X3dhKey,
    bundle: X3dhPreKeyBundle,
    use_opk: bool,
) -> (X3dhSessionKey, bool) {
    let est = Start
        .receive_bundle(ghost, bundle)
        .send_init::<C, G>(ghost, ik_a_secret, ek_a_secret, use_opk);
    (*est.session_key(), est.sig_valid())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{X3dhSignature, ZERO_KEY, ZERO_SIGNATURE};

    /// Straight-line reference: the same operations as one function, no typestate.
    fn signal_handshake<C: X3dhCrypto, G: X3dhGhost>(
        ghost: &mut G,
        ik_a_secret: &X3dhKey,
        ek_a_secret: &X3dhKey,
        bundle: &X3dhPreKeyBundle,
        use_opk: bool,
    ) -> (X3dhSessionKey, bool) {
        ghost.event(0, &bundle.ik);
        let (sk, msg, sig_valid) =
            initiate::<C>(ik_a_secret, ek_a_secret, bundle, use_opk);
        ghost.send_init(&msg);
        ghost.event(1, &msg.ek_a);
        (sk, sig_valid)
    }

    /// Trivial deterministic crypto to exercise the flow (not real crypto).
    #[derive(Copy, Clone)]
    struct DummyCrypto;
    impl X3dhCrypto for DummyCrypto {
        fn dh(secret: &X3dhKey, peer_pub: &X3dhKey) -> X3dhKey {
            crate::types::xor_32(secret, peer_pub)
        }
        fn dh_pub(secret: &X3dhKey) -> X3dhKey {
            *secret
        }
        fn kdf(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey, dh4: &X3dhKey) -> X3dhSessionKey {
            let a = crate::types::xor_32(dh1, dh2);
            let b = crate::types::xor_32(dh3, dh4);
            crate::types::xor_32(&a, &b)
        }
        fn sign(_ik_secret: &X3dhKey, _msg: &X3dhKey) -> X3dhSignature {
            ZERO_SIGNATURE
        }
        fn verify(_ik_pub: &X3dhKey, _msg: &X3dhKey, _sig: &X3dhSignature) -> bool {
            true
        }
    }

    /// Trace-recording ghost. Sends are the flattened init-message fields;
    /// events are `(tag, key)` pairs — all arrays of `u8`, so directly comparable.
    #[derive(Default)]
    struct TraceGhost {
        sends: Vec<([u8; 32], [u8; 32], [u8; 4])>,
        events: Vec<(u8, [u8; 32])>,
    }
    impl X3dhGhost for TraceGhost {
        fn send_init(&mut self, msg: &X3dhInitMessage) {
            self.sends.push((msg.ik_a, msg.ek_a, msg.opk_id));
        }
        fn event(&mut self, tag: u8, key: &X3dhKey) {
            self.events.push((tag, *key));
        }
    }

    #[test]
    fn signal_matches_straight_line() {
        let ik_a = [1u8; 32];
        let ek_a = [2u8; 32];
        let bundle = X3dhPreKeyBundle {
            ik: [3u8; 32],
            spk: [4u8; 32],
            opk: [5u8; 32],
            sig: ZERO_SIGNATURE,
        };

        let mut g_line = TraceGhost::default();
        let (sk_line, ok_line) =
            signal_handshake::<DummyCrypto, _>(&mut g_line, &ik_a, &ek_a, &bundle, true);

        let mut g_fsm = TraceGhost::default();
        let (sk_fsm, ok_fsm) =
            run_signal_handshake::<DummyCrypto, _>(&mut g_fsm, &ik_a, &ek_a, bundle, true);

        assert_eq!(sk_fsm, sk_line, "session key differs");
        assert_eq!(ok_fsm, ok_line, "sig verdict differs");
        assert_eq!(g_fsm.sends, g_line.sends, "send trace differs");
        assert_eq!(g_fsm.events, g_line.events, "event trace differs");
        assert_eq!(g_fsm.sends.len(), 1, "one init message on the wire");
        assert_eq!(g_fsm.events.len(), 2, "bundle-received + init-sent events");
    }

    #[test]
    fn established_exposes_key_and_verdict() {
        let mut g = TraceGhost::default();
        let bundle = X3dhPreKeyBundle {
            ik: ZERO_KEY,
            spk: ZERO_KEY,
            opk: ZERO_KEY,
            sig: ZERO_SIGNATURE,
        };
        let est = Start
            .receive_bundle(&mut g, bundle)
            .send_init::<DummyCrypto, _>(&mut g, &[1u8; 32], &[2u8; 32], false);
        assert!(est.sig_valid());
        let _k = *est.session_key();
    }
}
