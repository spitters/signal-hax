//! X3DH protocol operations (Signal's Extended Triple Diffie-Hellman).
//!
//! Abstract over cryptographic operations via the `X3dhCrypto` trait.
//!
//! Every public key received from the peer (the identity key, the signed
//! prekey and, when it is used, the one-time prekey of a bundle; the identity
//! key and the ephemeral key of an initial message) passes the input check
//! `X3dhCrypto::valid_pub` before any Diffie-Hellman value is computed on it;
//! `initiate` and `respond` return `None` when one fails. For X25519 the check
//! is membership in the prime-order subgroup with the identity excluded
//! (`crate::subgroup::valid_pub`): it rejects the u-coordinates of points of
//! the quadratic twist and of points with a component of order 2, 4 or 8,
//! non-canonical strings, and the encoding `0` of the identity. With a
//! clamped X25519 scalar, no Diffie-Hellman value computed on an accepted key
//! is then the all-zero output of RFC 7748 §6.1.
//!
//! The key derivation takes the Diffie-Hellman values alone, as in the
//! specification (`SK = KDF(DH1 || DH2 || DH3 [|| DH4])`); the identities of
//! the parties are bound by the values themselves, `DH1` and `DH2` being
//! computed on the identity keys.

use crate::types::*;

/// Abstract cryptographic operations for X3DH.
pub trait X3dhCrypto: Copy {
    /// DH: compute shared secret from own secret and peer's public key.
    fn dh(secret: &X3dhKey, peer_pub: &X3dhKey) -> X3dhKey;

    /// Compute public key from secret key.
    fn dh_pub(secret: &X3dhKey) -> X3dhKey;

    /// KDF with a one-time prekey: the session key derived from
    /// DH1 || DH2 || DH3 || DH4. The padding `F` and the info string of the
    /// specification are constants of the instance.
    fn kdf(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey, dh4: &X3dhKey) -> X3dhSessionKey;

    /// KDF without a one-time prekey: the session key derived from
    /// DH1 || DH2 || DH3.
    fn kdf3(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey) -> X3dhSessionKey;

    /// Sign: sign a message (SPK) with identity key.
    fn sign(ik_secret: &X3dhKey, msg: &X3dhKey) -> X3dhSignature;

    /// Verify: verify signature on a message with identity key.
    fn verify(ik_pub: &X3dhKey, msg: &X3dhKey, sig: &X3dhSignature) -> bool;

    /// Input check of a public key received from the peer: `true` when `pk`
    /// encodes an element other than the identity of the prime-order group
    /// on which `dh` is the group exponentiation. For X25519 this is
    /// `crate::subgroup::valid_pub`.
    fn valid_pub(pk: &X3dhKey) -> bool;
}

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
/// Returns `None` when a public key of the bundle that the computation uses
/// (`ik`, `spk`, and `opk` when `use_opk`) fails the input check `valid_pub`.
/// Otherwise computes:
///   DH1 = DH(IK_A, SPK_B)
///   DH2 = DH(EK_A, IK_B)
///   DH3 = DH(EK_A, SPK_B)
///   DH4 = DH(EK_A, OPK_B)  (if OPK available)
///   SK  = KDF(DH1 || DH2 || DH3 || DH4)  with OPK
///   SK  = KDF(DH1 || DH2 || DH3)         without OPK
///
/// and returns `Some((session_key, init_message, sig_valid))`.
pub fn initiate<C: X3dhCrypto>(
    ik_a_secret: &X3dhKey,
    ek_a_secret: &X3dhKey,
    bundle: &X3dhPreKeyBundle,
    use_opk: bool,
) -> Option<(X3dhSessionKey, X3dhInitMessage, bool)> {
    // Input check of the peer public keys
    let keys_valid = C::valid_pub(&bundle.ik)
        && C::valid_pub(&bundle.spk)
        && (!use_opk || C::valid_pub(&bundle.opk));
    if keys_valid {
        Some(initiate_checked::<C>(ik_a_secret, ek_a_secret, bundle, use_opk))
    } else {
        None
    }
}

/// `initiate` on a bundle whose public keys passed the input check.
fn initiate_checked<C: X3dhCrypto>(
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

    // With OPK: DH4 = DH(EK_A, OPK_B) and SK = KDF(DH1 || DH2 || DH3 || DH4).
    // Without OPK: SK = KDF(DH1 || DH2 || DH3).
    let sk = if use_opk {
        let dh4 = C::dh(ek_a_secret, &bundle.opk);
        C::kdf(&dh1, &dh2, &dh3, &dh4)
    } else {
        C::kdf3(&dh1, &dh2, &dh3)
    };

    let msg = X3dhInitMessage {
        ik_a: ik_a_pub,
        ek_a: ek_a_pub,
        opk_id: if use_opk { [0, 0, 0, 1] } else { [0, 0, 0, 0] },
    };

    (sk, msg, sig_valid)
}

/// Responder (Bob) processes Alice's X3DH message.
///
/// Returns `None` when a public key of the message (`ik_a`, `ek_a`) fails
/// the input check `valid_pub`. Otherwise computes the same DH operations
/// from Bob's side:
///   DH1 = DH(SPK_B, IK_A)
///   DH2 = DH(IK_B, EK_A)
///   DH3 = DH(SPK_B, EK_A)
///   DH4 = DH(OPK_B, EK_A)  (if OPK was used)
///   SK  = KDF(DH1 || DH2 || DH3 || DH4)  with OPK
///   SK  = KDF(DH1 || DH2 || DH3)         without OPK
///
/// and returns `Some(session_key)`.
pub fn respond<C: X3dhCrypto>(
    ik_b_secret: &X3dhKey,
    spk_b_secret: &X3dhKey,
    opk_b_secret: &X3dhKey,
    msg: &X3dhInitMessage,
    use_opk: bool,
) -> Option<X3dhSessionKey> {
    // Input check of the peer public keys
    if C::valid_pub(&msg.ik_a) && C::valid_pub(&msg.ek_a) {
        Some(respond_checked::<C>(ik_b_secret, spk_b_secret, opk_b_secret, msg, use_opk))
    } else {
        None
    }
}

/// `respond` on a message whose public keys passed the input check.
fn respond_checked<C: X3dhCrypto>(
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

    // With OPK: DH4 = DH(OPK_B, EK_A) and SK = KDF(DH1 || DH2 || DH3 || DH4).
    // Without OPK: SK = KDF(DH1 || DH2 || DH3).
    if use_opk {
        let dh4 = C::dh(opk_b_secret, &msg.ek_a);
        C::kdf(&dh1, &dh2, &dh3, &dh4)
    } else {
        C::kdf3(&dh1, &dh2, &dh3)
    }
}
