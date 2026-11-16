#![allow(dead_code)]
//! The reference dependency of the tests: the primitives of the deployed Signal Double
//! Ratchet from independent crates. HMAC-SHA-256 and HKDF-SHA-256 of RustCrypto (`hmac`,
//! `hkdf`, `sha2`), X25519 of `x25519-dalek`, and the message encryption of section 7.2 of the
//! specification with the libsignal constants: HKDF-SHA-256 of the message key with a zero
//! salt and the info `"WhisperMessageKeys"` into an encryption key, an authentication key and
//! an IV; AES-256-CBC with PKCS#7 padding (RustCrypto `aes`, `cbc`); HMAC-SHA-256 over the
//! associated data followed by the CBC ciphertext, truncated to `TAG_LEN` bytes.
//!
//! The module also holds the helpers shared by the test files: key pairs, plaintext buffers,
//! a comparison of all state fields, and a party that drives the ratchet functions.
//!
//! The module is also compiled into the unit tests of the `no_std` library, so it names the
//! items of `std` it uses.
extern crate std;
use std::{format, vec, vec::Vec};

use doubleratchet_hax::{
    ratchet_decrypt, ratchet_encrypt, DoubleRatchetDeps, MessageHeader, RatchetState, AD_LEN,
    BLOCK_LEN, FULL_AD_LEN, MAX_CT_LEN, MAX_PLAINTEXT_LEN, MAX_STORED, TAG_LEN,
};
use aes::Aes256;
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub struct RefDeps;

/// HKDF info of the message-key expansion (libsignal `MessageKeys::derive_keys`).
pub const MESSAGE_KEYS_INFO: &[u8; 18] = b"WhisperMessageKeys";

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// HMAC-SHA-256 of RustCrypto.
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// The encryption key, the authentication key and the IV of a message key.
pub fn message_keys(mk: &[u8; 32]) -> ([u8; 32], [u8; 32], [u8; 16]) {
    let hk = Hkdf::<Sha256>::new(Some(&[0u8; 32][..]), mk);
    let mut okm = [0u8; 80];
    hk.expand(MESSAGE_KEYS_INFO, &mut okm).expect("80 bytes is a valid HKDF length");
    let mut ek = [0u8; 32];
    let mut ak = [0u8; 32];
    let mut iv = [0u8; 16];
    ek.copy_from_slice(&okm[..32]);
    ak.copy_from_slice(&okm[32..64]);
    iv.copy_from_slice(&okm[64..]);
    (ek, ak, iv)
}

/// The full HMAC-SHA-256 tag over `ad || body` under the authentication key.
fn mac_tag(ak: &[u8; 32], ad: &[u8], body: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(ak).expect("any key length");
    mac.update(ad);
    mac.update(body);
    mac.finalize().into_bytes().into()
}

/// `ENCRYPT(mk, pt, ad)` of 7.2: the CBC ciphertext followed by the truncated tag.
pub fn signal_encrypt(mk: &[u8; 32], pt: &[u8], ad: &[u8]) -> Vec<u8> {
    let (ek, ak, iv) = message_keys(mk);
    let mut buf = vec![0u8; (pt.len() / BLOCK_LEN + 1) * BLOCK_LEN];
    buf[..pt.len()].copy_from_slice(pt);
    let body = Aes256CbcEnc::new(&ek.into(), &iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, pt.len())
        .expect("the buffer holds the padding")
        .to_vec();
    let tag = mac_tag(&ak, ad, &body);
    let mut out = body;
    out.extend_from_slice(&tag[..TAG_LEN]);
    out
}

/// `DECRYPT(mk, ct, ad)` of 7.2: `None` on a malformed length, a failed tag or a failed
/// padding check.
pub fn signal_decrypt(mk: &[u8; 32], ct: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
    if ct.len() < BLOCK_LEN + TAG_LEN || (ct.len() - TAG_LEN) % BLOCK_LEN != 0 {
        return None;
    }
    let (ek, ak, iv) = message_keys(mk);
    let body_len = ct.len() - TAG_LEN;
    let tag = mac_tag(&ak, ad, &ct[..body_len]);
    if tag[..TAG_LEN] != ct[body_len..] {
        return None;
    }
    let mut buf = ct[..body_len].to_vec();
    let pt = Aes256CbcDec::new(&ek.into(), &iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .ok()?;
    Some(pt.to_vec())
}

impl DoubleRatchetDeps for RefDeps {
    fn hmac_sha256(key: &[u8; 32], msg: &[u8; 1]) -> [u8; 32] {
        hmac(key, msg)
    }
    fn hkdf_extract(salt: &[u8; 32], ikm: &[u8; 32]) -> [u8; 32] {
        let (prk, _) = Hkdf::<Sha256>::extract(Some(&salt[..]), ikm);
        prk.into()
    }
    fn hkdf_expand_64(prk: &[u8; 32], info: &[u8; 14]) -> [u8; 64] {
        let hk = Hkdf::<Sha256>::from_prk(prk).expect("a 32-byte PRK");
        let mut out = [0u8; 64];
        hk.expand(info, &mut out).expect("64 bytes is a valid HKDF length");
        out
    }
    fn x25519(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
        x25519_dalek::x25519(*sk, *pk)
    }
    fn aead_encrypt(
        mk: &[u8; 32],
        pt: &[u8; MAX_PLAINTEXT_LEN],
        pt_len: usize,
        ad: &[u8; FULL_AD_LEN],
    ) -> [u8; MAX_CT_LEN] {
        let n = pt_len.min(MAX_PLAINTEXT_LEN);
        let ct = signal_encrypt(mk, &pt[..n], ad);
        let mut out = [0u8; MAX_CT_LEN];
        out[..ct.len()].copy_from_slice(&ct);
        out
    }
    fn aead_decrypt(
        mk: &[u8; 32],
        ct: &[u8; MAX_CT_LEN],
        ct_len: usize,
        ad: &[u8; FULL_AD_LEN],
    ) -> Option<([u8; MAX_PLAINTEXT_LEN], usize)> {
        if ct_len > MAX_CT_LEN {
            return None;
        }
        let pt = signal_decrypt(mk, &ct[..ct_len], ad)?;
        if pt.len() > MAX_PLAINTEXT_LEN {
            return None;
        }
        let mut out = [0u8; MAX_PLAINTEXT_LEN];
        out[..pt.len()].copy_from_slice(&pt);
        Some((out, pt.len()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// The X25519 key pair of the secret key `sk`.
pub fn keypair(sk: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    (sk, x25519_dalek::x25519(sk, x25519_dalek::X25519_BASEPOINT_BYTES))
}

/// The key pair of the secret key derived from a tag and an index.
pub fn keypair_of(tag: u8, i: u32) -> ([u8; 32], [u8; 32]) {
    let mut sk = [tag; 32];
    sk[..4].copy_from_slice(&i.to_be_bytes());
    keypair(sk)
}

/// The associated data of the key agreement used by the tests: `IK_A || IK_B`.
pub fn test_ad() -> [u8; AD_LEN] {
    let mut ad = [0u8; AD_LEN];
    ad[..32].copy_from_slice(&keypair([0x0a; 32]).1);
    ad[32..].copy_from_slice(&keypair([0x0b; 32]).1);
    ad
}

/// A plaintext buffer holding `msg` and its length.
pub fn buf(msg: &[u8]) -> ([u8; MAX_PLAINTEXT_LEN], usize) {
    let mut b = [0u8; MAX_PLAINTEXT_LEN];
    b[..msg.len()].copy_from_slice(msg);
    (b, msg.len())
}

/// A distinct plaintext for each pair `(tag, i)`.
pub fn message(tag: u8, i: usize) -> Vec<u8> {
    format!("message {i} of sender {tag}").into_bytes()
}

/// All fields of a state, in a form that compares with `==` and prints with `{:?}`.
pub type StateView = (
    ([u8; 32], [u8; 32], Option<[u8; 32]>, [u8; 32], Option<[u8; 32]>, Option<[u8; 32]>),
    (u32, u32, u32),
    ([bool; MAX_STORED], [[u8; 32]; MAX_STORED], [u32; MAX_STORED], [[u8; 32]; MAX_STORED]),
);

pub fn view(s: &RatchetState) -> StateView {
    (
        (s.dhs_sk, s.dhs_pk, s.dhr, s.rk, s.cks, s.ckr),
        (s.ns, s.nr, s.pn),
        (s.sk_used, s.sk_dh, s.sk_n, s.sk_mk),
    )
}

/// The number of occupied store slots.
pub fn stored(s: &RatchetState) -> usize {
    s.sk_used.iter().filter(|u| **u).count()
}

/// Every free store slot holds zero bytes and the number zero.
pub fn free_slots_are_zero(s: &RatchetState) -> bool {
    (0..MAX_STORED)
        .all(|i| s.sk_used[i] || (s.sk_dh[i] == [0u8; 32] && s.sk_mk[i] == [0u8; 32] && s.sk_n[i] == 0))
}

/// A sent message: the header, the ciphertext buffer, its length and the plaintext.
#[derive(Clone)]
pub struct Sent {
    pub h: MessageHeader,
    pub ct: [u8; MAX_CT_LEN],
    pub len: usize,
    pub pt: Vec<u8>,
}

/// One party: its state, the tag of its key pairs and the index of the next key pair it
/// supplies to `ratchet_decrypt`.
pub struct Party {
    pub st: RatchetState,
    pub tag: u8,
    pub next_kp: u32,
}

impl Party {
    /// The key pair the party supplies to its next `ratchet_decrypt`.
    pub fn next_keypair(&self) -> ([u8; 32], [u8; 32]) {
        keypair_of(self.tag, self.next_kp)
    }

    /// Encrypts `msg` with the test associated data.
    pub fn send(&mut self, msg: &[u8]) -> Sent {
        let (b, n) = buf(msg);
        let (s, h, ct, len) = ratchet_encrypt::<RefDeps>(&self.st, &b, n, &test_ad())
            .expect("the sender holds a sending chain");
        self.st = s;
        Sent { h, ct, len, pt: msg.to_vec() }
    }

    /// Decrypts a message. On success the state advances, and the key pair index advances
    /// exactly when the new state holds the supplied key pair; on rejection the state stays.
    pub fn try_receive(&mut self, m: &Sent) -> Option<Vec<u8>> {
        let (sk, pk) = self.next_keypair();
        match ratchet_decrypt::<RefDeps>(&self.st, &m.h, &m.ct, m.len, &test_ad(), &sk, &pk) {
            Some((s, pt, n)) => {
                if s.dhs_pk == pk {
                    self.next_kp += 1;
                }
                self.st = s;
                Some(pt[..n].to_vec())
            }
            None => None,
        }
    }

    /// Decrypts a message that must be accepted and checks the plaintext.
    pub fn receive(&mut self, m: &Sent) {
        let pt = self.try_receive(m).expect("the message is accepted");
        assert_eq!(pt, m.pt, "the receiver recovers the plaintext");
    }
}

/// The shared secret of the test sessions.
pub const SK: [u8; 32] = [0x10; 32];

/// Alice and Bob after `RatchetInitAlice` and `RatchetInitBob` at the shared secret `SK`.
pub fn alice_and_bob() -> (Party, Party) {
    let (a_sk, a_pk) = keypair_of(0xa0, 0);
    let (b_sk, b_pk) = keypair_of(0xb0, 0);
    let alice = doubleratchet_hax::ratchet_init_alice::<RefDeps>(&SK, &b_pk, &a_sk, &a_pk);
    let bob = doubleratchet_hax::ratchet_init_bob(&SK, &b_sk, &b_pk);
    (Party { st: alice, tag: 0xa0, next_kp: 1 }, Party { st: bob, tag: 0xb0, next_kp: 1 })
}
