// Copyright (c) 2026 CatCrypt Contributors. MIT license.
//! Signal Double Ratchet: hax-extractable protocol logic over a dependency trait.
//!
//! The crate follows The Double Ratchet Algorithm, Revision 4 (2025-11-04), sections 3.1-3.5
//! and 7.2, with the constants of libsignal. The protocol logic (the state of 3.2, the
//! initialization of 3.3, `RatchetEncrypt` of 3.4, `RatchetDecrypt`, `RatchetReceiveKey`,
//! `TrySkippedMessageKeys`, `SkipMessageKeys` and `DHRatchet` of 3.5) is Rust over the
//! [`DoubleRatchetDeps`] trait, which carries the primitives: HMAC-SHA-256, HKDF-SHA-256,
//! X25519 and the message encryption `ENCRYPT`/`DECRYPT` of 7.2. The crate implements no
//! primitive and draws no randomness.
//!
//! Key derivation (7.2, libsignal `RootKey::create_chain` and `ChainKey`):
//!
//! ```text
//! KDF_RK(rk, dh_out) = split64(HKDF-Expand(HKDF-Extract(rk, dh_out), "WhisperRatchet", 64))
//! KDF_CK(ck)         = (HMAC-SHA-256(ck, 0x02), HMAC-SHA-256(ck, 0x01))
//!                      (next chain key, message key)
//! ```
//!
//! The associated data of the message encryption is `CONCAT(AD, header)`: the 64-byte
//! associated data of the key agreement followed by the 40-byte header encoding
//! `dh || pn || n` (big-endian counters), built by [`concat_ad`].
//!
//! The skipped-message-key store `MKSKIPPED` is a fixed set of [`MAX_STORED`] slots inside
//! [`RatchetState`]. [`skip_message_keys`] refuses a jump of more than [`MAX_SKIP`] keys and an
//! insertion into a full store. [`ratchet_decrypt`] is transactional: on every rejection it
//! returns `None`, and the caller keeps the state it passed in (3.5: "changes to the state
//! object are discarded").
//!
//! The new key pair of `DHRatchet` (`GENERATE_DH`) is an argument of [`ratchet_decrypt`] and
//! [`ratchet_receive_key`]. It is used only on a header whose ratchet key is new; the caller
//! sees this as `result.dhs_pk == new_pk`.
//!
//! Every loop of the crate runs over a constant range without `break` or `return`; every
//! exit is an `Option` value.

#![no_std]

pub mod typestate_fsm;

// =========================================================================
// Constants
// =========================================================================

/// Maximum plaintext length in bytes.
pub const MAX_PLAINTEXT_LEN: usize = 256;
/// AES block length in bytes.
pub const BLOCK_LEN: usize = 16;
/// Length of the truncated HMAC-SHA-256 tag of the message encryption (libsignal).
pub const TAG_LEN: usize = 8;
/// Maximum ciphertext length: `MAX_PLAINTEXT_LEN + BLOCK_LEN + TAG_LEN`, the value of
/// [`ct_len`] at [`MAX_PLAINTEXT_LEN`].
pub const MAX_CT_LEN: usize = 280;
/// Length of the associated data of the key agreement: `Encode(IK_A) || Encode(IK_B)`, two
/// 32-byte X25519 public keys.
pub const AD_LEN: usize = 64;
/// Length of the header encoding `dh (32) || pn (u32 BE) || n (u32 BE)`.
pub const HEADER_LEN: usize = 40;
/// Length of `CONCAT(AD, header)`: `AD_LEN + HEADER_LEN`.
pub const FULL_AD_LEN: usize = 104;
/// `MAX_SKIP` of 3.1: the largest number of message keys skipped in one receiving chain by
/// one received message.
pub const MAX_SKIP: u32 = 16;
/// Number of slots of the skipped-message-key store.
pub const MAX_STORED: usize = 32;
/// HKDF info of `KDF_RK`: the bytes of `"WhisperRatchet"` (libsignal).
pub const KDF_RK_INFO: [u8; 14] = [
    0x57, 0x68, 0x69, 0x73, 0x70, 0x65, 0x72, 0x52, 0x61, 0x74, 0x63, 0x68, 0x65, 0x74,
];
/// HMAC input of `KDF_CK` that derives the message key.
pub const MESSAGE_KEY_SEED: [u8; 1] = [0x01];
/// HMAC input of `KDF_CK` that derives the next chain key.
pub const CHAIN_KEY_SEED: [u8; 1] = [0x02];

// =========================================================================
// Dependency trait: the primitives
// =========================================================================

/// The primitives of the double ratchet: HMAC-SHA-256, HKDF-SHA-256, X25519 and the message
/// encryption of 7.2. An implementation backs them by a cryptographic library.
pub trait DoubleRatchetDeps {
    /// HMAC-SHA-256 under a 32-byte key on a one-byte message (`KDF_CK`, 7.2).
    fn hmac_sha256(key: &[u8; 32], msg: &[u8; 1]) -> [u8; 32];
    /// HKDF-SHA-256 Extract with the salt `salt` and the input keying material `ikm`.
    fn hkdf_extract(salt: &[u8; 32], ikm: &[u8; 32]) -> [u8; 32];
    /// HKDF-SHA-256 Expand of 64 bytes under the info string `info` (`KDF_RK`, 7.2).
    fn hkdf_expand_64(prk: &[u8; 32], info: &[u8; 14]) -> [u8; 64];
    /// X25519: `x25519(sk, pk)` is the shared secret of the secret key `sk` and the public
    /// key `pk`.
    fn x25519(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32];
    /// `ENCRYPT(mk, plaintext, ad)` of 7.2 on the first `pt_len <= MAX_PLAINTEXT_LEN` bytes of
    /// `pt`: HKDF-SHA-256 of `mk` with a zero salt and the info `"WhisperMessageKeys"` into an
    /// encryption key (32 bytes), an authentication key (32 bytes) and an IV (16 bytes);
    /// AES-256-CBC with PKCS#7 padding; HMAC-SHA-256 over `ad` followed by the CBC ciphertext,
    /// truncated to `TAG_LEN` bytes and appended. The first `ct_len(pt_len)` bytes of the
    /// result are the ciphertext and the tag.
    fn aead_encrypt(
        mk: &[u8; 32],
        pt: &[u8; MAX_PLAINTEXT_LEN],
        pt_len: usize,
        ad: &[u8; FULL_AD_LEN],
    ) -> [u8; MAX_CT_LEN];
    /// `DECRYPT(mk, ciphertext, ad)` on the first `ct_len` bytes of `ct`: `None` on a failed
    /// tag or padding check, otherwise the plaintext and its length.
    fn aead_decrypt(
        mk: &[u8; 32],
        ct: &[u8; MAX_CT_LEN],
        ct_len: usize,
        ad: &[u8; FULL_AD_LEN],
    ) -> Option<([u8; MAX_PLAINTEXT_LEN], usize)>;
}

/// The ciphertext length of a `pt_len`-byte plaintext: the PKCS#7-padded CBC blocks and the
/// tag.
pub fn ct_len(pt_len: usize) -> usize {
    (pt_len / BLOCK_LEN + 1) * BLOCK_LEN + TAG_LEN
}

// =========================================================================
// Key derivation
// =========================================================================

/// The one-byte HMAC message of the chain-step constant `c`.
pub fn ck_const(c: u8) -> [u8; 1] {
    [c; 1]
}

/// `KDF_CK(ck)`: the next chain key `HMAC-SHA-256(ck, 0x02)` and the message key
/// `HMAC-SHA-256(ck, 0x01)`.
pub fn kdf_ck<D: DoubleRatchetDeps>(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    (D::hmac_sha256(ck, &ck_const(0x02)), D::hmac_sha256(ck, &ck_const(0x01)))
}

/// The two 32-byte halves of a 64-byte block.
pub fn split64(x: &[u8; 64]) -> ([u8; 32], [u8; 32]) {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    for i in 0..32 {
        a[i] = x[i];
        b[i] = x[32 + i];
    }
    (a, b)
}

/// `KDF_RK(rk, dh_out)`: the new root key and the chain key, the halves of 64 bytes of
/// HKDF-SHA-256 with the salt `rk`, the input keying material `dh_out` and the info
/// [`KDF_RK_INFO`].
pub fn kdf_rk<D: DoubleRatchetDeps>(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    split64(&D::hkdf_expand_64(&D::hkdf_extract(rk, dh_out), &KDF_RK_INFO))
}

/// `DH(sk, pk)`: X25519 of the dependency.
pub fn dh<D: DoubleRatchetDeps>(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
    D::x25519(sk, pk)
}

/// Equality of two 32-byte arrays: the OR of the bytewise XORs is zero.
pub fn eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..32 {
        acc = acc | (a[i] ^ b[i]);
    }
    acc == 0
}

// =========================================================================
// Header and associated data
// =========================================================================

/// The message header `HEADER(dh_pair, pn, n)` of 3.1: the sender's current ratchet public
/// key, the length of its previous sending chain and the message number.
#[derive(Clone, Copy)]
pub struct MessageHeader {
    /// The sender's current ratchet public key.
    pub dh: [u8; 32],
    /// The number of messages in the sender's previous sending chain.
    pub pn: u32,
    /// The message number in the sender's current sending chain.
    pub n: u32,
}

/// The byte encoding of a header: `dh || pn || n`, the counters big-endian.
pub fn encode_header(h: &MessageHeader) -> [u8; HEADER_LEN] {
    let mut out = [0u8; HEADER_LEN];
    for i in 0..32 {
        out[i] = h.dh[i];
    }
    out[32] = (h.pn >> 24) as u8;
    out[33] = ((h.pn >> 16) & 0xff) as u8;
    out[34] = ((h.pn >> 8) & 0xff) as u8;
    out[35] = (h.pn & 0xff) as u8;
    out[36] = (h.n >> 24) as u8;
    out[37] = ((h.n >> 16) & 0xff) as u8;
    out[38] = ((h.n >> 8) & 0xff) as u8;
    out[39] = (h.n & 0xff) as u8;
    out
}

/// `CONCAT(AD, header)`: the associated data of the key agreement followed by the header
/// encoding.
pub fn concat_ad(ad: &[u8; AD_LEN], h: &MessageHeader) -> [u8; FULL_AD_LEN] {
    let enc = encode_header(h);
    let mut out = [0u8; FULL_AD_LEN];
    for i in 0..AD_LEN {
        out[i] = ad[i];
    }
    for i in 0..HEADER_LEN {
        out[AD_LEN + i] = enc[i];
    }
    out
}

// =========================================================================
// State and initialization
// =========================================================================

/// The state of one party (3.2).
///
/// The skipped-message-key store `MKSKIPPED` is held as [`MAX_STORED`] slots: slot `i` is
/// occupied iff `sk_used[i]`, and then holds the ratchet public key `sk_dh[i]`, the message
/// number `sk_n[i]` and the message key `sk_mk[i]`. A free slot holds zero bytes and the
/// number zero.
#[derive(Clone, Copy)]
pub struct RatchetState {
    /// `DHs`: the secret key of the party's current ratchet key pair.
    pub dhs_sk: [u8; 32],
    /// `DHs`: the public key of the party's current ratchet key pair.
    pub dhs_pk: [u8; 32],
    /// `DHr`: the peer's current ratchet public key; `None` at the responder before its first
    /// received message.
    pub dhr: Option<[u8; 32]>,
    /// `RK`: the root key.
    pub rk: [u8; 32],
    /// `CKs`: the sending chain key, `None` while the sending chain does not exist.
    pub cks: Option<[u8; 32]>,
    /// `CKr`: the receiving chain key, `None` while the receiving chain does not exist.
    pub ckr: Option<[u8; 32]>,
    /// `Ns`: the number of messages sent in the current sending chain.
    pub ns: u32,
    /// `Nr`: the number of messages received in the current receiving chain.
    pub nr: u32,
    /// `PN`: the number of messages in the previous sending chain.
    pub pn: u32,
    /// Occupancy of the store slots.
    pub sk_used: [bool; MAX_STORED],
    /// Ratchet public key of each store slot.
    pub sk_dh: [[u8; 32]; MAX_STORED],
    /// Message number of each store slot.
    pub sk_n: [u32; MAX_STORED],
    /// Message key of each store slot.
    pub sk_mk: [[u8; 32]; MAX_STORED],
}

/// `RatchetInitAlice(state, SK, bob_dh_public_key)` of 3.3, with the initiator's ratchet key
/// pair `(my_sk, my_pk)` supplied by the caller: `DHr = bob_pk`,
/// `RK, CKs = KDF_RK(SK, DH(DHs, DHr))`, `CKr = None`, the counters zero and the store empty.
pub fn ratchet_init_alice<D: DoubleRatchetDeps>(
    sk: &[u8; 32],
    bob_pk: &[u8; 32],
    my_sk: &[u8; 32],
    my_pk: &[u8; 32],
) -> RatchetState {
    let (rk, cks) = kdf_rk::<D>(sk, &dh::<D>(my_sk, bob_pk));
    RatchetState {
        dhs_sk: *my_sk,
        dhs_pk: *my_pk,
        dhr: Some(*bob_pk),
        rk,
        cks: Some(cks),
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        sk_used: [false; MAX_STORED],
        sk_dh: [[0u8; 32]; MAX_STORED],
        sk_n: [0u32; MAX_STORED],
        sk_mk: [[0u8; 32]; MAX_STORED],
    }
}

/// `RatchetInitBob(state, SK, bob_dh_key_pair)` of 3.3: `DHs = (my_sk, my_pk)`,
/// `DHr = None`, `RK = SK`, `CKs = CKr = None`, the counters zero and the store empty.
pub fn ratchet_init_bob(sk: &[u8; 32], my_sk: &[u8; 32], my_pk: &[u8; 32]) -> RatchetState {
    RatchetState {
        dhs_sk: *my_sk,
        dhs_pk: *my_pk,
        dhr: None,
        rk: *sk,
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        sk_used: [false; MAX_STORED],
        sk_dh: [[0u8; 32]; MAX_STORED],
        sk_n: [0u32; MAX_STORED],
        sk_mk: [[0u8; 32]; MAX_STORED],
    }
}

// =========================================================================
// Encryption
// =========================================================================

/// `RatchetEncrypt(state, plaintext, AD)` of 3.4 on the first `pt_len` bytes of `pt`, with
/// `pt_len <= MAX_PLAINTEXT_LEN`.
///
/// Steps the sending chain, forms `header = HEADER(DHs, PN, Ns)` and encrypts under the
/// message key with the associated data `CONCAT(ad, header)`. Returns the new state, the
/// header, the ciphertext buffer and the ciphertext length `ct_len(pt_len)`. Returns `None`,
/// and derives no key, when the state holds no sending chain key (the responder before its
/// first received message).
pub fn ratchet_encrypt<D: DoubleRatchetDeps>(
    state: &RatchetState,
    pt: &[u8; MAX_PLAINTEXT_LEN],
    pt_len: usize,
    ad: &[u8; AD_LEN],
) -> Option<(RatchetState, MessageHeader, [u8; MAX_CT_LEN], usize)> {
    match state.cks {
        None => None,
        Some(ck) => {
            let (ck1, mk) = kdf_ck::<D>(&ck);
            let header = MessageHeader { dh: state.dhs_pk, pn: state.pn, n: state.ns };
            let ct = D::aead_encrypt(&mk, pt, pt_len, &concat_ad(ad, &header));
            Some((
                RatchetState { cks: Some(ck1), ns: state.ns + 1, ..*state },
                header,
                ct,
                ct_len(pt_len),
            ))
        }
    }
}

// =========================================================================
// Skipped-message-key store
// =========================================================================

/// The first occupied slot holding the ratchet key `dh_pub` and the message number `n`, as
/// `(found, index)`.
fn store_find(s: &RatchetState, dh_pub: &[u8; 32], n: u32) -> (bool, usize) {
    let mut acc: (bool, usize) = (false, 0);
    for i in 0..MAX_STORED {
        let hit = s.sk_used[i] && eq32(&s.sk_dh[i], dh_pub) && s.sk_n[i] == n;
        if !acc.0 && hit {
            acc = (true, i);
        }
    }
    acc
}

/// The message key of slot `i` and the state with that slot cleared (zero bytes, 8.1).
fn store_take(s: &RatchetState, i: usize) -> (RatchetState, [u8; 32]) {
    let mk = s.sk_mk[i];
    let mut t = *s;
    t.sk_used[i] = false;
    t.sk_dh[i] = [0u8; 32];
    t.sk_n[i] = 0;
    t.sk_mk[i] = [0u8; 32];
    (t, mk)
}

/// The state with `(dh_pub, n, mk)` stored in the first free slot; `None` when no slot is
/// free.
fn store_insert(
    s: &RatchetState,
    dh_pub: &[u8; 32],
    n: u32,
    mk: &[u8; 32],
) -> Option<RatchetState> {
    let mut state = *s;
    let mut done = false;
    for i in 0..MAX_STORED {
        if !done && !state.sk_used[i] {
            let mut used = state.sk_used;
            used[i] = true;
            let mut dhs = state.sk_dh;
            dhs[i] = *dh_pub;
            let mut nums = state.sk_n;
            nums[i] = n;
            let mut mks = state.sk_mk;
            mks[i] = *mk;
            state = RatchetState { sk_used: used, sk_dh: dhs, sk_n: nums, sk_mk: mks, ..state };
            done = true;
        }
    }
    if done {
        Some(state)
    } else {
        None
    }
}

/// `TrySkippedMessageKeys(state, header)` of 3.5: the stored message key of
/// `(header.dh, header.n)` and the state with it deleted, or `None` when the store holds no
/// such key.
pub fn try_skipped_message_keys(
    s: &RatchetState,
    h: &MessageHeader,
) -> Option<(RatchetState, [u8; 32])> {
    let (found, i) = store_find(s, &h.dh, h.n);
    if found {
        Some(store_take(s, i))
    } else {
        None
    }
}

/// `SkipMessageKeys(state, until)` of 3.5.
///
/// Returns `None` when `Nr + MAX_SKIP < until` (tested without the overflowing sum) and when
/// the store has no free slot for a skipped key. On a state without a receiving chain it
/// returns the state. Otherwise it steps the receiving chain from `Nr` to `until`, storing the
/// message key of each position under the ratchet key `DHr`. The loop runs `MAX_SKIP` times
/// with the accumulator `(state, chain key, ok)`; an iteration acts only while `ok` and
/// `Nr < until`, so after the bound check it computes the `while` loop of the specification.
pub fn skip_message_keys<D: DoubleRatchetDeps>(
    s: &RatchetState,
    until: u32,
) -> Option<RatchetState> {
    if until > s.nr && until - s.nr > MAX_SKIP {
        None
    } else {
        match s.ckr {
            None => Some(*s),
            Some(ck0) => {
                let dhr = match s.dhr {
                    Some(r) => r,
                    None => [0u8; 32],
                };
                let mut acc: (RatchetState, [u8; 32], bool) = (*s, ck0, true);
                for _i in 0..MAX_SKIP {
                    let (st, ck, ok) = acc;
                    if ok && st.nr < until {
                        let (ck1, mk) = kdf_ck::<D>(&ck);
                        match store_insert(&st, &dhr, st.nr, &mk) {
                            Some(st1) => {
                                acc = (
                                    RatchetState { ckr: Some(ck1), nr: st1.nr + 1, ..st1 },
                                    ck1,
                                    true,
                                );
                            }
                            None => {
                                acc = (st, ck, false);
                            }
                        }
                    }
                }
                let (st, _ck, ok) = acc;
                if ok {
                    Some(st)
                } else {
                    None
                }
            }
        }
    }
}

// =========================================================================
// DH ratchet
// =========================================================================

/// The receiving half of `DHRatchet(state, header)` of 3.5: `PN = Ns`, `Ns = 0`, `Nr = 0`,
/// `DHr = dh_r`, `RK, CKr = KDF_RK(RK, DH(DHs, DHr))`.
pub fn dh_ratchet_recv_half<D: DoubleRatchetDeps>(
    s: &RatchetState,
    dh_r: &[u8; 32],
) -> RatchetState {
    let (rk1, ckr1) = kdf_rk::<D>(&s.rk, &dh::<D>(&s.dhs_sk, dh_r));
    RatchetState { pn: s.ns, ns: 0, nr: 0, dhr: Some(*dh_r), rk: rk1, ckr: Some(ckr1), ..*s }
}

/// The sending half of `DHRatchet(state, header)` of 3.5, with the key pair of
/// `GENERATE_DH()` supplied by the caller: `DHs = (new_sk, new_pk)`,
/// `RK, CKs = KDF_RK(RK, DH(DHs, DHr))`. The identity on a state with `DHr = None`, which the
/// receiving half never produces.
pub fn dh_ratchet_send_half<D: DoubleRatchetDeps>(
    s: &RatchetState,
    new_sk: &[u8; 32],
    new_pk: &[u8; 32],
) -> RatchetState {
    match s.dhr {
        None => *s,
        Some(r) => {
            let (rk2, cks2) = kdf_rk::<D>(&s.rk, &dh::<D>(new_sk, &r));
            RatchetState { dhs_sk: *new_sk, dhs_pk: *new_pk, rk: rk2, cks: Some(cks2), ..*s }
        }
    }
}

/// `DHRatchet(state, header)` of 3.5 at the ratchet key `dh_r`: the receiving half, then the
/// sending half with the key pair `(new_sk, new_pk)`.
pub fn dh_ratchet<D: DoubleRatchetDeps>(
    s: &RatchetState,
    dh_r: &[u8; 32],
    new_sk: &[u8; 32],
    new_pk: &[u8; 32],
) -> RatchetState {
    dh_ratchet_send_half::<D>(&dh_ratchet_recv_half::<D>(s, dh_r), new_sk, new_pk)
}

// =========================================================================
// Decryption
// =========================================================================

/// `RatchetReceiveKey(state, header)` of 3.5: the message key of `header` and the state after
/// its derivation.
///
/// A key in the store is taken and deleted. Otherwise, on a ratchet key other than `DHr`, the
/// keys of the current receiving chain up to `header.pn` are stored and the DH ratchet step
/// runs with the key pair `(new_sk, new_pk)`; then the keys of the receiving chain up to
/// `header.n` are stored and the chain is stepped once. Returns `None` on a jump over
/// [`MAX_SKIP`], on a full store, on a state without a receiving chain after these steps, and
/// on a header with the current ratchet key and `header.n < Nr` whose key is not in the store
/// (a used position).
pub fn ratchet_receive_key<D: DoubleRatchetDeps>(
    s: &RatchetState,
    h: &MessageHeader,
    new_sk: &[u8; 32],
    new_pk: &[u8; 32],
) -> Option<(RatchetState, [u8; 32])> {
    match try_skipped_message_keys(s, h) {
        Some(r) => Some(r),
        None => {
            let is_new = match s.dhr {
                Some(r) => !eq32(&r, &h.dh),
                None => true,
            };
            let s1 = if is_new {
                match skip_message_keys::<D>(s, h.pn) {
                    Some(t) => Some(dh_ratchet::<D>(&t, &h.dh, new_sk, new_pk)),
                    None => None,
                }
            } else if h.n < s.nr {
                None
            } else {
                Some(*s)
            };
            match s1 {
                None => None,
                Some(t1) => match skip_message_keys::<D>(&t1, h.n) {
                    None => None,
                    Some(t2) => match t2.ckr {
                        None => None,
                        Some(ck) => {
                            let (ck1, mk) = kdf_ck::<D>(&ck);
                            Some((RatchetState { ckr: Some(ck1), nr: t2.nr + 1, ..t2 }, mk))
                        }
                    },
                },
            }
        }
    }
}

/// `RatchetDecrypt(state, header, ciphertext, AD)` of 3.5 on the first `ct_len` bytes of
/// `ct`: [`ratchet_receive_key`], then `DECRYPT(mk, ciphertext, CONCAT(ad, header))`.
///
/// Returns the new state, the plaintext buffer and the plaintext length. Returns `None` when
/// either step rejects; the caller then keeps the state it passed in, so a rejected message
/// changes no state.
pub fn ratchet_decrypt<D: DoubleRatchetDeps>(
    s: &RatchetState,
    h: &MessageHeader,
    ct: &[u8; MAX_CT_LEN],
    ct_len: usize,
    ad: &[u8; AD_LEN],
    new_sk: &[u8; 32],
    new_pk: &[u8; 32],
) -> Option<(RatchetState, [u8; MAX_PLAINTEXT_LEN], usize)> {
    match ratchet_receive_key::<D>(s, h, new_sk, new_pk) {
        None => None,
        Some((s1, mk)) => match D::aead_decrypt(&mk, ct, ct_len, &concat_ad(ad, h)) {
            None => None,
            Some((pt, n)) => Some((s1, pt, n)),
        },
    }
}

// =========================================================================
// Unit tests
// =========================================================================

#[cfg(test)]
extern crate self as doubleratchet_hax;

/// The reference dependency of the integration tests, shared with the unit tests.
#[cfg(test)]
#[path = "../tests/common/mod.rs"]
pub(crate) mod test_deps;

#[cfg(test)]
mod tests {
    use super::test_deps::RefDeps;
    use super::*;

    fn empty_state() -> RatchetState {
        ratchet_init_bob(&[0x11; 32], &[0x22; 32], &[0x33; 32])
    }

    #[test]
    fn kdf_ck_deterministic_and_separated() {
        let ck: [u8; 32] = [0xaa; 32];
        let (ck1, mk1) = kdf_ck::<RefDeps>(&ck);
        let (ck2, mk2) = kdf_ck::<RefDeps>(&ck);
        assert_eq!(ck1, ck2, "chain step must be deterministic (CK)");
        assert_eq!(mk1, mk2, "chain step must be deterministic (MK)");
        assert_ne!(ck1, mk1, "chain key and message key must differ");
        assert_ne!(ck1, ck, "new CK must differ from input CK");
        assert_ne!(mk1, ck, "MK must differ from input CK");
    }

    #[test]
    fn ck_const_matches_seeds() {
        assert_eq!(ck_const(0x01), MESSAGE_KEY_SEED);
        assert_eq!(ck_const(0x02), CHAIN_KEY_SEED);
    }

    #[test]
    fn ct_len_at_max_plaintext_is_max_ct_len() {
        assert_eq!(ct_len(MAX_PLAINTEXT_LEN), MAX_CT_LEN);
        assert_eq!(AD_LEN + HEADER_LEN, FULL_AD_LEN);
    }

    #[test]
    fn eq32_is_equality() {
        let a = [0x5a; 32];
        let mut b = a;
        assert!(eq32(&a, &b));
        for i in 0..32 {
            b = a;
            b[i] ^= 0x80;
            assert!(!eq32(&a, &b), "a difference at byte {i} is detected");
        }
    }

    #[test]
    fn store_insert_find_take() {
        let s0 = empty_state();
        let s1 = store_insert(&s0, &[1; 32], 3, &[0xa1; 32]).expect("a free slot");
        let s2 = store_insert(&s1, &[2; 32], 3, &[0xa2; 32]).expect("a free slot");
        assert_eq!(store_find(&s2, &[1; 32], 3), (true, 0));
        assert_eq!(store_find(&s2, &[2; 32], 3), (true, 1));
        assert!(!store_find(&s2, &[1; 32], 4).0, "a different number is not found");
        let (s3, mk) = store_take(&s2, 0);
        assert_eq!(mk, [0xa1; 32]);
        assert!(!s3.sk_used[0]);
        assert_eq!(s3.sk_dh[0], [0u8; 32], "a cleared slot holds zero bytes");
        assert_eq!(s3.sk_mk[0], [0u8; 32], "a cleared slot holds zero bytes");
        assert_eq!(s3.sk_n[0], 0);
        assert!(!store_find(&s3, &[1; 32], 3).0, "a taken key is not found again");
        // The freed slot is the first free slot again.
        let s4 = store_insert(&s3, &[3; 32], 7, &[0xa3; 32]).expect("a free slot");
        assert_eq!(store_find(&s4, &[3; 32], 7), (true, 0));
    }

    #[test]
    fn store_insert_into_full_store_is_refused() {
        let mut s = empty_state();
        for i in 0..MAX_STORED {
            s = store_insert(&s, &[i as u8; 32], i as u32, &[0xc0; 32]).expect("a free slot");
        }
        assert!(s.sk_used.iter().all(|u| *u));
        assert!(store_insert(&s, &[0xff; 32], 0, &[0xc1; 32]).is_none());
    }

    #[test]
    fn skip_message_keys_bound() {
        let mut s = empty_state();
        s.ckr = Some([0x44; 32]);
        s.dhr = Some([0x55; 32]);
        assert!(skip_message_keys::<RefDeps>(&s, MAX_SKIP + 1).is_none());
        let t = skip_message_keys::<RefDeps>(&s, MAX_SKIP).expect("MAX_SKIP keys are stored");
        assert_eq!(t.nr, MAX_SKIP);
        assert_eq!(t.sk_used.iter().filter(|u| **u).count(), MAX_SKIP as usize);
        // The stored keys are the message keys of the chain at positions 0..MAX_SKIP.
        let mut ck = [0x44; 32];
        for j in 0..MAX_SKIP {
            let (ck1, mk) = kdf_ck::<RefDeps>(&ck);
            let (found, i) = store_find(&t, &[0x55; 32], j);
            assert!(found);
            assert_eq!(t.sk_mk[i], mk);
            ck = ck1;
        }
        assert_eq!(t.ckr, Some(ck));
        // A state without a receiving chain is returned unchanged.
        let u = skip_message_keys::<RefDeps>(&empty_state(), 3).expect("no chain");
        assert_eq!(u.nr, 0);
        assert!(u.sk_used.iter().all(|x| !*x));
    }
}
