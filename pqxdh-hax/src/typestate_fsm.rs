//! Typestate encoding of the PQXDH initiator (Alice) FSM.
//!
//! The initiator session as a typestate machine; each transition is one
//! protocol step. `pqxdh_initiate_term` writes the same message flow as one
//! straight-line function. In the machine each protocol state is a distinct
//! Rust type, and a transition *consumes* one state value and returns the next.
//! Move semantics then make the Rust compiler check the state-machine
//! structure:
//!
//!   * you cannot send the init message before receiving Bob's pre-key bundle —
//!     `Init` has no `send_init`;
//!   * you cannot repeat a step — the state value is moved out by the transition;
//!   * you cannot act after termination — `Established` exposes no transition.
//!
//! Illegal orderings are therefore compile errors, not runtime checks: code
//! that mis-orders or duplicates a transition does not type-check.
//!
//! The socket I/O stays outside the machine: the `send` is a call on the
//! `PqxdhGhost` instance, and the DH/KEM/KDF go through the `PqxdhCrypto`
//! trait. The test `pqxdh_matches_straight_line` checks that the machine
//! produces the same message/event trace and session key as the straight-line
//! function.

extern crate alloc;
use alloc::vec::Vec;

use crate::protocol::PqxdhCrypto;
use crate::types::{
    PqxdhDhKey, PqxdhInitMessage, PqxdhKemSs, PqxdhPreKeyBundle, PqxdhSessionKey, ZERO_DH_KEY,
};

/// Ghost operations. Erased in a proof build; a socket write in a running build;
/// a trace entry in the symbolic build. The payload is a **real value** computed
/// by the protocol, so the ghost cannot record a message that does not exist.
pub trait PqxdhGhost {
    /// A message is emitted on the wire.
    fn send_msg(&mut self, msg: &[u8; 32]);
    /// A protocol event fires (tag: 0=BundleReceived, 1=InitMessage).
    fn event(&mut self, tag: u8, content: &[u8; 32]);
}

/// Proof/erased instance: the ghost operations vanish.
pub struct NoOpGhost;
impl PqxdhGhost for NoOpGhost {
    fn send_msg(&mut self, _msg: &[u8; 32]) {}
    fn event(&mut self, _tag: u8, _content: &[u8; 32]) {}
}

/// Recording instance: stores the sent messages and the events in order.
#[derive(Default)]
pub struct TraceGhost {
    /// Sent messages, in order.
    pub sends: Vec<[u8; 32]>,
    /// Fired events `(tag, content)`, in order.
    pub events: Vec<(u8, [u8; 32])>,
}
impl PqxdhGhost for TraceGhost {
    fn send_msg(&mut self, msg: &[u8; 32]) {
        self.sends.push(*msg);
    }
    fn event(&mut self, tag: u8, content: &[u8; 32]) {
        self.events.push((tag, *content));
    }
}

/// State 0: nothing done. The only transition is `recv_bundle`.
pub struct Init;

/// State 1: Bob's pre-key bundle has been received and its signatures verified;
/// awaiting Alice's init send. The bundle is retained because it feeds the DH/KEM
/// computation.
pub struct BundleVerified<const KEM_PK: usize> {
    bundle: PqxdhPreKeyBundle<KEM_PK>,
    spk_sig_valid: bool,
    pqpk_sig_valid: bool,
}

/// State 2 (terminal): the session key is established. No transition leaves this
/// state.
pub struct Established {
    session_key: PqxdhSessionKey,
}

impl Init {
    /// Transition `Init -> BundleVerified`: record Bob's pre-key bundle and
    /// verify the SPK and PQPK signatures.
    ///
    /// Consumes `self`, so an `Init` cannot be reused to receive twice.
    ///
    /// ```compile_fail
    /// // Cannot send the init message before receiving the bundle:
    /// // `Init` has no `send_init`.
    /// use pqxdh_hax::typestate_fsm::{Init, NoOpGhost};
    /// let mut g = NoOpGhost;
    /// let _ = Init.send_init(&mut g);
    /// ```
    ///
    /// ```compile_fail
    /// // Cannot receive twice: the `Init` value is moved by the first receive.
    /// use pqxdh_hax::typestate_fsm::{Init, NoOpGhost};
    /// use pqxdh_hax::types::PqxdhPreKeyBundle;
    /// let mut g = NoOpGhost;
    /// let bundle: PqxdhPreKeyBundle<32> = PqxdhPreKeyBundle {
    ///     ik: [0u8; 32], spk: [0u8; 32], opk: [0u8; 32],
    ///     pqpk: [0u8; 32], spk_sig: [0u8; 64], pqpk_sig: [0u8; 64],
    /// };
    /// let s = Init;
    /// let _a = s.recv_bundle(&mut g, &bundle);
    /// let _b = s.recv_bundle(&mut g, &bundle);
    /// ```
    pub fn recv_bundle<
        C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
        const KEM_PK: usize,
        const KEM_SK: usize,
        const KEM_CT: usize,
        G: PqxdhGhost,
    >(
        self,
        ghost: &mut G,
        bundle: &PqxdhPreKeyBundle<KEM_PK>,
    ) -> BundleVerified<KEM_PK> {
        ghost.event(0, &bundle.ik);
        let spk_sig_valid = C::verify(&bundle.ik, &bundle.spk, &bundle.spk_sig);
        let pqpk_sig_valid = C::verify(&bundle.ik, &C::kem_pk_encode(&bundle.pqpk), &bundle.pqpk_sig);
        BundleVerified {
            bundle: *bundle,
            spk_sig_valid,
            pqpk_sig_valid,
        }
    }
}

impl<const KEM_PK: usize> BundleVerified<KEM_PK> {
    /// Whether both pre-key-bundle signatures verified.
    pub fn signatures_valid(&self) -> bool {
        self.spk_sig_valid && self.pqpk_sig_valid
    }

    /// Transition `BundleVerified -> Established`: run the DH/KEM ladder, derive
    /// the session key, and emit Alice's init message.
    ///
    /// Consumes `self`, so the init message cannot be sent twice.
    pub fn send_init<
        C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
        const KEM_SK: usize,
        const KEM_CT: usize,
        G: PqxdhGhost,
    >(
        self,
        ghost: &mut G,
        ik_a_secret: &PqxdhDhKey,
        ek_a_secret: &PqxdhDhKey,
        kem_randomness: &PqxdhKemSs,
        use_opk: bool,
    ) -> Established {
        let bundle = &self.bundle;
        let ik_a_pub = C::dh_pub(ik_a_secret);
        let ek_a_pub = C::dh_pub(ek_a_secret);

        let dh1 = C::dh(ik_a_secret, &bundle.spk);
        let dh2 = C::dh(ek_a_secret, &bundle.ik);
        let dh3 = C::dh(ek_a_secret, &bundle.spk);
        let dh4 = if use_opk {
            C::dh(ek_a_secret, &bundle.opk)
        } else {
            ZERO_DH_KEY
        };

        let (kem_ct, kem_ss) = C::kem_encaps(&bundle.pqpk, kem_randomness);
        let session_key = C::kdf(&dh1, &dh2, &dh3, &dh4, &kem_ss);

        let msg: PqxdhInitMessage<KEM_CT> = PqxdhInitMessage {
            ik_a: ik_a_pub,
            ek_a: ek_a_pub,
            kem_ct,
            opk_id: if use_opk { [0, 0, 0, 1] } else { [0, 0, 0, 0] },
        };
        ghost.event(1, &msg.ek_a);
        ghost.send_msg(&msg.ek_a);

        Established { session_key }
    }
}

impl Established {
    /// The established session key.
    pub fn key(&self) -> &PqxdhSessionKey {
        &self.session_key
    }

    /// Consume the terminal state and take ownership of the session key.
    pub fn into_key(self) -> PqxdhSessionKey {
        self.session_key
    }
}

/// Drive the full initiator exchange through the typestate FSM. The state values
/// thread `Init -> BundleVerified -> Established`; the Rust type checker verifies
/// that the transitions occur in exactly this order.
pub fn run_pqxdh<
    C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
    const KEM_PK: usize,
    const KEM_SK: usize,
    const KEM_CT: usize,
    G: PqxdhGhost,
>(
    ghost: &mut G,
    bundle: &PqxdhPreKeyBundle<KEM_PK>,
    ik_a_secret: &PqxdhDhKey,
    ek_a_secret: &PqxdhDhKey,
    kem_randomness: &PqxdhKemSs,
    use_opk: bool,
) -> PqxdhSessionKey {
    Init.recv_bundle::<C, KEM_PK, KEM_SK, KEM_CT, G>(ghost, bundle)
        .send_init::<C, KEM_SK, KEM_CT, G>(ghost, ik_a_secret, ek_a_secret, kem_randomness, use_opk)
        .into_key()
}

/// The same message flow as the typestate machine, written as one
/// straight-line function; `pqxdh_matches_straight_line` compares the two.
pub fn pqxdh_initiate_term<
    C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
    const KEM_PK: usize,
    const KEM_SK: usize,
    const KEM_CT: usize,
    G: PqxdhGhost,
>(
    ghost: &mut G,
    bundle: &PqxdhPreKeyBundle<KEM_PK>,
    ik_a_secret: &PqxdhDhKey,
    ek_a_secret: &PqxdhDhKey,
    kem_randomness: &PqxdhKemSs,
    use_opk: bool,
) -> PqxdhSessionKey {
    ghost.event(0, &bundle.ik);
    let _spk_sig_valid = C::verify(&bundle.ik, &bundle.spk, &bundle.spk_sig);
    let _pqpk_sig_valid = C::verify(&bundle.ik, &C::kem_pk_encode(&bundle.pqpk), &bundle.pqpk_sig);

    let ik_a_pub = C::dh_pub(ik_a_secret);
    let ek_a_pub = C::dh_pub(ek_a_secret);

    let dh1 = C::dh(ik_a_secret, &bundle.spk);
    let dh2 = C::dh(ek_a_secret, &bundle.ik);
    let dh3 = C::dh(ek_a_secret, &bundle.spk);
    let dh4 = if use_opk {
        C::dh(ek_a_secret, &bundle.opk)
    } else {
        ZERO_DH_KEY
    };

    let (kem_ct, kem_ss) = C::kem_encaps(&bundle.pqpk, kem_randomness);
    let session_key = C::kdf(&dh1, &dh2, &dh3, &dh4, &kem_ss);

    let msg: PqxdhInitMessage<KEM_CT> = PqxdhInitMessage {
        ik_a: ik_a_pub,
        ek_a: ek_a_pub,
        kem_ct,
        opk_id: if use_opk { [0, 0, 0, 1] } else { [0, 0, 0, 0] },
    };
    ghost.event(1, &msg.ek_a);
    ghost.send_msg(&msg.ek_a);

    session_key
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{xor_32, PqxdhSignature, ZERO_SIGNATURE};

    /// A trivial deterministic `PqxdhCrypto<32,32,32>` used to exercise flow
    /// (not real crypto): enough to compare the typestate FSM against the
    /// straight-line function. Signatures verify unconditionally.
    #[derive(Copy, Clone)]
    struct DummyCrypto;
    impl PqxdhCrypto<32, 32, 32> for DummyCrypto {
        fn dh(secret: &PqxdhDhKey, peer_pub: &PqxdhDhKey) -> PqxdhDhKey {
            xor_32(secret, peer_pub)
        }
        fn dh_pub(secret: &PqxdhDhKey) -> PqxdhDhKey {
            *secret
        }
        fn kem_keygen(seed: &PqxdhKemSs) -> ([u8; 32], [u8; 32]) {
            (*seed, *seed)
        }
        fn kem_encaps(pk: &[u8; 32], randomness: &PqxdhKemSs) -> ([u8; 32], PqxdhKemSs) {
            (xor_32(pk, randomness), *randomness)
        }
        fn kem_decaps(sk: &[u8; 32], ct: &[u8; 32]) -> PqxdhKemSs {
            xor_32(ct, sk)
        }
        fn kem_pk_encode(pk: &[u8; 32]) -> [u8; 32] {
            *pk
        }
        fn kdf(
            dh1: &PqxdhDhKey,
            dh2: &PqxdhDhKey,
            dh3: &PqxdhDhKey,
            dh4: &PqxdhDhKey,
            kem_ss: &PqxdhKemSs,
        ) -> PqxdhSessionKey {
            let mut acc = xor_32(dh1, dh2);
            acc = xor_32(&acc, dh3);
            acc = xor_32(&acc, dh4);
            xor_32(&acc, kem_ss)
        }
        fn sign(_ik_secret: &PqxdhDhKey, _msg: &[u8; 32]) -> PqxdhSignature {
            ZERO_SIGNATURE
        }
        fn verify(_ik_pub: &PqxdhDhKey, _msg: &[u8; 32], _sig: &PqxdhSignature) -> bool {
            true
        }
    }

    fn dummy_bundle() -> PqxdhPreKeyBundle<32> {
        PqxdhPreKeyBundle {
            ik: [10u8; 32],
            spk: [11u8; 32],
            opk: [12u8; 32],
            pqpk: [13u8; 32],
            spk_sig: ZERO_SIGNATURE,
            pqpk_sig: ZERO_SIGNATURE,
        }
    }

    /// The typestate FSM realizes the *identical* session key and the identical
    /// message/event trace as the straight-line function.
    #[test]
    fn pqxdh_matches_straight_line() {
        let bundle = dummy_bundle();
        let ik_a = [1u8; 32];
        let ek_a = [2u8; 32];
        let rand = [3u8; 32];

        // Straight-line function.
        let mut g_line = TraceGhost::default();
        let sk_line = pqxdh_initiate_term::<DummyCrypto, 32, 32, 32, _>(
            &mut g_line,
            &bundle,
            &ik_a,
            &ek_a,
            &rand,
            true,
        );

        // Typestate FSM — same inputs, same trivial crypto.
        let mut g_fsm = TraceGhost::default();
        let sk_fsm = run_pqxdh::<DummyCrypto, 32, 32, 32, _>(
            &mut g_fsm, &bundle, &ik_a, &ek_a, &rand, true,
        );

        assert_eq!(sk_fsm, sk_line, "typestate FSM key differs from straight-line function");
        assert_eq!(g_fsm.sends, g_line.sends, "send trace differs");
        assert_eq!(g_fsm.events, g_line.events, "event trace differs");
        assert_eq!(g_fsm.sends.len(), 1, "init message on the wire");
        assert_eq!(g_fsm.events.len(), 2, "BundleReceived + InitMessage events");
    }

    /// The terminal state is reachable; the intermediate state exposes the
    /// signature-validity check.
    #[test]
    fn established_exposes_key() {
        let bundle = dummy_bundle();
        let mut g = TraceGhost::default();
        let verified = Init.recv_bundle::<DummyCrypto, 32, 32, 32, _>(&mut g, &bundle);
        assert!(verified.signatures_valid());
        let est = verified.send_init::<DummyCrypto, 32, 32, _>(
            &mut g,
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            true,
        );
        let by_ref = *est.key();
        let owned = est.into_key();
        assert_eq!(by_ref, owned);
    }
}
