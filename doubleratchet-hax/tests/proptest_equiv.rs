//! Property-based equivalence tests against RustCrypto.
//!
//! `doubleratchet-hax` calls its primitives through the `DoubleRatchetDeps` trait; these
//! property tests run the crate over the reference dependency of `tests/common` and check, on
//! random inputs, the KDF chain against `hmac::Hmac<Sha256>` at the seeds `0x02` (chain key)
//! and `0x01` (message key), the root KDF against `hkdf::Hkdf<Sha256>` with the info
//! `"WhisperRatchet"`, the domain separation of both, the stored keys of `skip_message_keys`
//! against the iterated chain, and the encrypt/decrypt round trip between two parties.
//!
//! References: FIPS 180-4 (SHA-256), RFC 2104 (HMAC), RFC 5869 (HKDF); Signal, The Double
//! Ratchet Algorithm, Revision 4, section 7.2,
//! <https://signal.org/docs/specifications/doubleratchet/>.

mod common;
use common::{alice_and_bob, view, RefDeps};
use doubleratchet_hax::*;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use proptest::prelude::*;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn rust_hmac(key: &[u8; 32], msg: u8) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).unwrap();
    mac.update(&[msg]);
    mac.finalize().into_bytes().into()
}

proptest! {
    /// `kdf_ck` agrees with `hmac::Hmac<Sha256>`: next chain key at `0x02`, message key at
    /// `0x01`.
    #[test]
    fn prop_kdf_ck_matches_rustcrypto(ck in any::<[u8; 32]>()) {
        let (next, mk) = kdf_ck::<RefDeps>(&ck);
        prop_assert_eq!(next, rust_hmac(&ck, 0x02));
        prop_assert_eq!(mk, rust_hmac(&ck, 0x01));
    }

    /// `kdf_ck` domain separation: the next chain key and the message key differ.
    #[test]
    fn prop_kdf_ck_domain_separation(ck in any::<[u8; 32]>()) {
        let (next, mk) = kdf_ck::<RefDeps>(&ck);
        prop_assert_ne!(next, mk);
    }

    /// `kdf_rk` agrees with 64 bytes of `hkdf::Hkdf<Sha256>` under `"WhisperRatchet"`.
    #[test]
    fn prop_kdf_rk_matches_rustcrypto(rk in any::<[u8; 32]>(), dh in any::<[u8; 32]>()) {
        let mut okm = [0u8; 64];
        Hkdf::<Sha256>::new(Some(&rk[..]), &dh).expand(b"WhisperRatchet", &mut okm).unwrap();
        let (new_rk, new_ck) = kdf_rk::<RefDeps>(&rk, &dh);
        prop_assert_eq!(&new_rk[..], &okm[..32]);
        prop_assert_eq!(&new_ck[..], &okm[32..]);
    }

    /// `kdf_rk` yields distinct root and chain keys.
    #[test]
    fn prop_kdf_rk_domain_separation(rk in any::<[u8; 32]>(), dh in any::<[u8; 32]>()) {
        let (new_rk, new_ck) = kdf_rk::<RefDeps>(&rk, &dh);
        prop_assert_ne!(new_rk, new_ck);
    }

    /// `skip_message_keys` to `until <= MAX_SKIP` stores the message keys of the iterated
    /// chain at positions `0..until` under `DHr`, and its chain key is the iterated one.
    #[test]
    fn prop_skip_stores_iterated_chain(
        ck in any::<[u8; 32]>(),
        dhr in any::<[u8; 32]>(),
        until in 0u32..=MAX_SKIP,
    ) {
        let mut s = ratchet_init_bob(&[0u8; 32], &[1u8; 32], &[2u8; 32]);
        s.ckr = Some(ck);
        s.dhr = Some(dhr);
        let t = skip_message_keys::<RefDeps>(&s, until).expect("within MAX_SKIP");
        let mut c = ck;
        for j in 0..until {
            let (next, mk) = kdf_ck::<RefDeps>(&c);
            let h = MessageHeader { dh: dhr, pn: 0, n: j };
            let (_t2, got) = try_skipped_message_keys(&t, &h).expect("stored");
            prop_assert_eq!(got, mk);
            c = next;
        }
        prop_assert_eq!(t.ckr, Some(c));
        prop_assert_eq!(t.nr, until);
    }

    /// Alice encrypts, Bob decrypts: the plaintext is recovered, and the two counters agree.
    #[test]
    fn prop_encrypt_decrypt_roundtrip(
        msgs in prop::collection::vec(
            prop::collection::vec(any::<u8>(), 0..=MAX_PLAINTEXT_LEN), 1..6),
    ) {
        let (mut alice, mut bob) = alice_and_bob();
        for m in &msgs {
            let sent = alice.send(m);
            prop_assert_eq!(sent.len, ct_len(m.len()));
            let got = bob.try_receive(&sent);
            prop_assert_eq!(got.as_deref(), Some(&m[..]));
        }
        prop_assert_eq!(alice.st.ns, msgs.len() as u32);
        prop_assert_eq!(bob.st.nr, msgs.len() as u32);
    }

    /// A rejected decryption leaves the state unchanged: a random ciphertext under a valid
    /// header is rejected.
    #[test]
    fn prop_random_ciphertext_rejected(
        body in prop::collection::vec(any::<u8>(), MAX_CT_LEN),
        len in 0usize..=MAX_CT_LEN,
    ) {
        let (mut alice, bob) = alice_and_bob();
        let sent = alice.send(b"genuine");
        let mut ct = [0u8; MAX_CT_LEN];
        ct.copy_from_slice(&body);
        let (sk, pk) = bob.next_keypair();
        let before = view(&bob.st);
        let r = ratchet_decrypt::<RefDeps>(&bob.st, &sent.h, &ct, len, &common::test_ad(), &sk, &pk);
        prop_assert!(r.is_none());
        prop_assert_eq!(view(&bob.st), before);
    }
}
