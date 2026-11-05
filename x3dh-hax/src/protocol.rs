//! X3DH protocol operations (Signal's Extended Triple Diffie-Hellman).
//!
//! Abstract over cryptographic operations via the `X3dhCrypto` trait.

use crate::types::*;

/// Abstract cryptographic operations for X3DH.
pub trait X3dhCrypto: Copy {
    /// DH: compute shared secret from own secret and peer's public key.
    fn dh(secret: &X3dhKey, peer_pub: &X3dhKey) -> X3dhKey;

    /// Compute public key from secret key.
    fn dh_pub(secret: &X3dhKey) -> X3dhKey;

    /// KDF: derive session key from concatenated DH outputs.
    /// Takes up to 4 DH results (3DH or 4DH depending on whether OPK is available).
    fn kdf(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey, dh4: &X3dhKey) -> X3dhSessionKey;

    /// Sign: sign a message (SPK) with identity key.
    fn sign(ik_secret: &X3dhKey, msg: &X3dhKey) -> X3dhSignature;

    /// Verify: verify signature on a message with identity key.
    fn verify(ik_pub: &X3dhKey, msg: &X3dhKey, sig: &X3dhSignature) -> bool;
}

/// Zero key constant for 4DH padding when OPK is absent.
const ZERO: X3dhKey = ZERO_KEY;

/// Create a pre-key bundle for publishing.
///
/// Takes identity key, signed pre-key, and one-time pre-key secrets.
/// Returns the bundle with public keys and signature.
pub fn create_bundle<C: X3dhCrypto>(
    ik_secret: &X3dhKey,
    spk_secret: &X3dhKey,
    opk_secret: &X3dhKey,
) -> X3dhPreKeyBundle {
    let ik_pub = C::dh_pub(ik_secret);
    let spk_pub = C::dh_pub(spk_secret);
    let opk_pub = C::dh_pub(opk_secret);
    let sig = C::sign(ik_secret, &spk_pub);

    X3dhPreKeyBundle {
        ik: ik_pub,
        spk: spk_pub,
        opk: opk_pub,
        sig,
    }
}

/// Initiator (Alice) performs X3DH with Bob's pre-key bundle.
///
/// Computes:
///   DH1 = DH(IK_A, SPK_B)
///   DH2 = DH(EK_A, IK_B)
///   DH3 = DH(EK_A, SPK_B)
///   DH4 = DH(EK_A, OPK_B)  (if OPK available)
///   SK  = KDF(DH1 || DH2 || DH3 || DH4)
///
/// Returns (session_key, init_message, sig_valid).
pub fn initiate<C: X3dhCrypto>(
    ik_a_secret: &X3dhKey,
    ek_a_secret: &X3dhKey,
    bundle: &X3dhPreKeyBundle,
    use_opk: bool,
) -> (X3dhSessionKey, X3dhInitMessage, bool) {
    // Verify SPK signature
    let sig_valid = C::verify(&bundle.ik, &bundle.spk, &bundle.sig);

    let ik_a_pub = C::dh_pub(ik_a_secret);
    let ek_a_pub = C::dh_pub(ek_a_secret);

    // DH1 = DH(IK_A, SPK_B)
    let dh1 = C::dh(ik_a_secret, &bundle.spk);

    // DH2 = DH(EK_A, IK_B)
    let dh2 = C::dh(ek_a_secret, &bundle.ik);

    // DH3 = DH(EK_A, SPK_B)
    let dh3 = C::dh(ek_a_secret, &bundle.spk);

    // DH4 = DH(EK_A, OPK_B) or zero
    let dh4 = if use_opk {
        C::dh(ek_a_secret, &bundle.opk)
    } else {
        ZERO
    };

    let sk = C::kdf(&dh1, &dh2, &dh3, &dh4);

    let msg = X3dhInitMessage {
        ik_a: ik_a_pub,
        ek_a: ek_a_pub,
        opk_id: if use_opk { [0, 0, 0, 1] } else { [0, 0, 0, 0] },
    };

    (sk, msg, sig_valid)
}

/// Responder (Bob) processes Alice's X3DH message.
///
/// Computes the same DH operations from Bob's side:
///   DH1 = DH(SPK_B, IK_A)
///   DH2 = DH(IK_B, EK_A)
///   DH3 = DH(SPK_B, EK_A)
///   DH4 = DH(OPK_B, EK_A)  (if OPK was used)
///
/// Returns session_key.
pub fn respond<C: X3dhCrypto>(
    ik_b_secret: &X3dhKey,
    spk_b_secret: &X3dhKey,
    opk_b_secret: &X3dhKey,
    msg: &X3dhInitMessage,
    use_opk: bool,
) -> X3dhSessionKey {
    // DH1 = DH(SPK_B, IK_A)
    let dh1 = C::dh(spk_b_secret, &msg.ik_a);

    // DH2 = DH(IK_B, EK_A)
    let dh2 = C::dh(ik_b_secret, &msg.ek_a);

    // DH3 = DH(SPK_B, EK_A)
    let dh3 = C::dh(spk_b_secret, &msg.ek_a);

    // DH4 = DH(OPK_B, EK_A) or zero
    let dh4 = if use_opk {
        C::dh(opk_b_secret, &msg.ek_a)
    } else {
        ZERO
    };

    C::kdf(&dh1, &dh2, &dh3, &dh4)
}
