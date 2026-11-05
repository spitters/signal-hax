#![allow(dead_code)]
//! A reference dependency for the integration tests: HMAC-SHA-256 and HKDF-SHA-256
//! of RustCrypto, a byte-wise XOR in place of X25519 and the XOR keystream
//! under the message key as encryption.
use doubleratchet_hax::{DoubleRatchetDeps, MAX_PLAINTEXT_LEN};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub struct RefDeps;

pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

fn xor_stream(mk: &[u8; 32], data: &[u8], len: usize) -> [u8; MAX_PLAINTEXT_LEN] {
    let mut out = [0u8; MAX_PLAINTEXT_LEN];
    for i in 0..MAX_PLAINTEXT_LEN {
        if i < len {
            out[i] = data[i] ^ mk[i % 32];
        }
    }
    out
}

impl DoubleRatchetDeps for RefDeps {
    fn hmac_sha256(key: &[u8; 32], msg: &[u8; 32]) -> [u8; 32] {
        hmac(key, msg)
    }
    fn hkdf_extract(salt: &[u8; 32], ikm: &[u8; 32]) -> [u8; 32] {
        hmac(salt, ikm)
    }
    fn hkdf_expand(prk: &[u8; 32], info: &[u8; 32]) -> [u8; 32] {
        let mut m = [0u8; 33];
        m[..32].copy_from_slice(info);
        m[32] = 0x01;
        hmac(prk, &m)
    }
    fn x25519(sk: &[u8; 32], pk: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = sk[i] ^ pk[i];
        }
        out
    }
    fn aead_encrypt(mk: &[u8; 32], pt: &[u8], len: usize, _ad: &[u8; 32])
        -> [u8; MAX_PLAINTEXT_LEN] {
        xor_stream(mk, pt, len)
    }
    fn aead_decrypt(mk: &[u8; 32], ct: &[u8], len: usize, _ad: &[u8; 32])
        -> [u8; MAX_PLAINTEXT_LEN] {
        xor_stream(mk, ct, len)
    }
}

