//! PQXDH protocol operations (Signal's Post-Quantum Extended Diffie-Hellman).
//!
//! The `PqxdhCrypto` trait is generic over KEM key and ciphertext sizes:
//!   `impl PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>`
//!
//! Toy instance: `<32, 32, 32>` for the Kani harnesses and the unit tests.
//! ML-KEM-768: `<1184, 2400, 1088>`, instantiated in `tests/reference_crosscheck.rs`.
//!
//! ## Protocol (Signal PQXDH Specification, September 2023)
//!
//! Bob publishes: IK_B, SPK_B (signed), OPK_B (optional), PQPK_B (signed)
//!
//! Alice computes:
//!   DH1 = DH(IK_A, SPK_B)
//!   DH2 = DH(EK_A, IK_B)
//!   DH3 = DH(EK_A, SPK_B)
//!   DH4 = DH(EK_A, OPK_B)        (if OPK available)
//!   (ct, pq_ss) = Encaps(PQPK_B)
//!   SK  = KDF(F || DH1 || DH2 || DH3 [|| DH4] || pq_ss)
//!
//! Every Diffie-Hellman public key received from the peer (the identity key,
//! the signed prekey and, when it is used, the one-time prekey of a bundle;
//! the identity key and the ephemeral key of an initial message) passes the
//! input check `PqxdhCrypto::valid_pub` before any Diffie-Hellman value is
//! computed on it; `initiate` and `respond` return `None` when one fails. For
//! X25519 the check is membership in the prime-order subgroup with the
//! identity excluded (`crate::subgroup::valid_pub`).

use crate::types::*;

/// Abstract cryptographic operations for PQXDH.
///
/// Generic over `KEM_PK`, `KEM_SK`, `KEM_CT`: the byte lengths of the
/// KEM encapsulation key, decapsulation key, and ciphertext respectively.
/// The haxpipeT extraction represents the KEM arrays as `Array Int`, without the
/// size parameters.
pub trait PqxdhCrypto<const KEM_PK: usize, const KEM_SK: usize, const KEM_CT: usize>:
    Copy
{
    // ── DH (X25519) ──────────────────────────────────────────────

    fn dh(secret: &PqxdhDhKey, peer_pub: &PqxdhDhKey) -> PqxdhDhKey;
    fn dh_pub(secret: &PqxdhDhKey) -> PqxdhDhKey;

    // ── KEM ──────────────────────────────────────────────────────

    fn kem_keygen(seed: &PqxdhKemSs) -> ([u8; KEM_PK], [u8; KEM_SK]);
    fn kem_encaps(pk: &[u8; KEM_PK], randomness: &PqxdhKemSs)
        -> ([u8; KEM_CT], PqxdhKemSs);
    fn kem_decaps(sk: &[u8; KEM_SK], ct: &[u8; KEM_CT]) -> PqxdhKemSs;

    /// Encode the KEM public key as a 32-byte signable message.
    ///
    /// This is the value that `sign`/`verify` operate on for PQPK signatures.
    /// The toy instance copies its 32-byte key; the ML-KEM-768 instance of
    /// `tests/reference_crosscheck.rs` returns SHA-256(pk). The PQXDH
    /// specification signs EncodeKEM(PQPK) itself, so with that instance the
    /// signed message differs from the specification's.
    fn kem_pk_encode(pk: &[u8; KEM_PK]) -> [u8; 32];

    // ── KDF (HKDF-SHA256) ────────────────────────────────────────

    /// SK = HKDF(salt=0, ikm = F||DH1||DH2||DH3||DH4||pq_ss, info); the info
    /// string is chosen by the instance, and the test instances use "WhisperText".
    fn kdf(
        dh1: &PqxdhDhKey, dh2: &PqxdhDhKey,
        dh3: &PqxdhDhKey, dh4: &PqxdhDhKey,
        kem_ss: &PqxdhKemSs,
    ) -> PqxdhSessionKey;

    // ── Signatures (XEdDSA / Ed25519) ────────────────────────────

    fn sign(ik_secret: &PqxdhDhKey, msg: &[u8; 32]) -> PqxdhSignature;
    fn verify(ik_pub: &PqxdhDhKey, msg: &[u8; 32], sig: &PqxdhSignature) -> bool;

    // ── Input check of peer public keys ──────────────────────────

    /// Input check of a Diffie-Hellman public key received from the peer:
    /// `true` when `pk` encodes an element other than the identity of the
    /// prime-order group on which `dh` is the group exponentiation. For
    /// X25519 this is `crate::subgroup::valid_pub`.
    fn valid_pub(pk: &PqxdhDhKey) -> bool;
}

/// Create a PQXDH pre-key bundle for publishing (Bob).
pub fn create_bundle<
    C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
    const KEM_PK: usize, const KEM_SK: usize, const KEM_CT: usize,
>(
    ik_secret:   &PqxdhDhKey,
    spk_secret:  &PqxdhDhKey,
    opk_secret:  &PqxdhDhKey,
    pqkem_seed:  &PqxdhKemSs,
) -> (PqxdhPreKeyBundle<KEM_PK>, [u8; KEM_SK]) {
    let ik_pub  = C::dh_pub(ik_secret);
    let spk_pub = C::dh_pub(spk_secret);
    let opk_pub = C::dh_pub(opk_secret);
    let (pqpk, pqsk) = C::kem_keygen(pqkem_seed);

    let spk_sig  = C::sign(ik_secret, &spk_pub);
    let pqpk_sig = C::sign(ik_secret, &C::kem_pk_encode(&pqpk));

    let bundle = PqxdhPreKeyBundle { ik: ik_pub, spk: spk_pub, opk: opk_pub,
                                     pqpk, spk_sig, pqpk_sig };
    (bundle, pqsk)
}

/// Initiator (Alice) performs PQXDH.
///
/// Returns `None` when a Diffie-Hellman public key of the bundle that the
/// computation uses (`ik`, `spk`, and `opk` when `use_opk`) fails the input
/// check `valid_pub`; otherwise `Some((session_key, init_message,
/// spk_sig_valid, pqpk_sig_valid))` of `initiate_checked`.
pub fn initiate<
    C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
    const KEM_PK: usize, const KEM_SK: usize, const KEM_CT: usize,
>(
    ik_a_secret:    &PqxdhDhKey,
    ek_a_secret:    &PqxdhDhKey,
    bundle:         &PqxdhPreKeyBundle<KEM_PK>,
    kem_randomness: &PqxdhKemSs,
    use_opk:        bool,
) -> Option<(PqxdhSessionKey, PqxdhInitMessage<KEM_CT>, bool, bool)> {
    // Input check of the peer public keys
    let keys_valid = C::valid_pub(&bundle.ik)
        && C::valid_pub(&bundle.spk)
        && (!use_opk || C::valid_pub(&bundle.opk));
    if keys_valid {
        Some(initiate_checked::<C, KEM_PK, KEM_SK, KEM_CT>(
            ik_a_secret, ek_a_secret, bundle, kem_randomness, use_opk,
        ))
    } else {
        None
    }
}

/// `initiate` on a bundle whose public keys passed the input check.
///
/// Without a one-time prekey, DH4 is the zero block `ZERO_DH_KEY`.
fn initiate_checked<
    C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
    const KEM_PK: usize, const KEM_SK: usize, const KEM_CT: usize,
>(
    ik_a_secret:    &PqxdhDhKey,
    ek_a_secret:    &PqxdhDhKey,
    bundle:         &PqxdhPreKeyBundle<KEM_PK>,
    kem_randomness: &PqxdhKemSs,
    use_opk:        bool,
) -> (PqxdhSessionKey, PqxdhInitMessage<KEM_CT>, bool, bool) {
    let spk_sig_valid  = C::verify(&bundle.ik, &bundle.spk, &bundle.spk_sig);
    let pqpk_sig_valid = C::verify(&bundle.ik,
                                   &C::kem_pk_encode(&bundle.pqpk),
                                   &bundle.pqpk_sig);

    let ik_a_pub = C::dh_pub(ik_a_secret);
    let ek_a_pub = C::dh_pub(ek_a_secret);

    let dh1 = C::dh(ik_a_secret, &bundle.spk);
    let dh2 = C::dh(ek_a_secret, &bundle.ik);
    let dh3 = C::dh(ek_a_secret, &bundle.spk);
    let dh4 = if use_opk { C::dh(ek_a_secret, &bundle.opk) } else { ZERO_DH_KEY };

    let (kem_ct, kem_ss) = C::kem_encaps(&bundle.pqpk, kem_randomness);
    let sk = C::kdf(&dh1, &dh2, &dh3, &dh4, &kem_ss);

    let msg = PqxdhInitMessage {
        ik_a: ik_a_pub, ek_a: ek_a_pub, kem_ct,
        opk_id: if use_opk { [0,0,0,1] } else { [0,0,0,0] },
    };
    (sk, msg, spk_sig_valid, pqpk_sig_valid)
}

/// Responder (Bob) processes Alice's PQXDH message.
///
/// Returns `None` when a Diffie-Hellman public key of the message (`ik_a`,
/// `ek_a`) fails the input check `valid_pub`; otherwise `Some(session_key)`
/// of `respond_checked`.
pub fn respond<
    C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
    const KEM_PK: usize, const KEM_SK: usize, const KEM_CT: usize,
>(
    ik_b_secret:  &PqxdhDhKey,
    spk_b_secret: &PqxdhDhKey,
    opk_b_secret: &PqxdhDhKey,
    pqsk_b:       &[u8; KEM_SK],
    msg:          &PqxdhInitMessage<KEM_CT>,
    use_opk:      bool,
) -> Option<PqxdhSessionKey> {
    // Input check of the peer public keys
    if C::valid_pub(&msg.ik_a) && C::valid_pub(&msg.ek_a) {
        Some(respond_checked::<C, KEM_PK, KEM_SK, KEM_CT>(
            ik_b_secret, spk_b_secret, opk_b_secret, pqsk_b, msg, use_opk,
        ))
    } else {
        None
    }
}

/// `respond` on a message whose public keys passed the input check.
///
/// Without a one-time prekey, DH4 is the zero block `ZERO_DH_KEY`.
fn respond_checked<
    C: PqxdhCrypto<KEM_PK, KEM_SK, KEM_CT>,
    const KEM_PK: usize, const KEM_SK: usize, const KEM_CT: usize,
>(
    ik_b_secret:  &PqxdhDhKey,
    spk_b_secret: &PqxdhDhKey,
    opk_b_secret: &PqxdhDhKey,
    pqsk_b:       &[u8; KEM_SK],
    msg:          &PqxdhInitMessage<KEM_CT>,
    use_opk:      bool,
) -> PqxdhSessionKey {
    let dh1 = C::dh(spk_b_secret, &msg.ik_a);
    let dh2 = C::dh(ik_b_secret,  &msg.ek_a);
    let dh3 = C::dh(spk_b_secret, &msg.ek_a);
    let dh4 = if use_opk { C::dh(opk_b_secret, &msg.ek_a) } else { ZERO_DH_KEY };

    let kem_ss = C::kem_decaps(pqsk_b, &msg.kem_ct);
    C::kdf(&dh1, &dh2, &dh3, &dh4, &kem_ss)
}
