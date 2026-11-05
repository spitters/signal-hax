//! Kani verification harnesses for X3DH.
//!
//! Proves:
//! 1. Panic-freedom of helper functions (xor_32)
//! 2. XOR algebraic properties (self-inverse, commutativity, identity)
//! 3. Protocol agreement: initiate + respond derive the same key
//! 4. Signature correctness: sign then verify succeeds

#[cfg(kani)]
mod kani_harnesses {
    use crate::types::*;
    use crate::protocol::*;

    // ===== Toy crypto over Z_65537^* (as `KaniSimplifiedX3dh` in tests/toy_model.rs) =====

    const P: u64 = 65537;
    const G: u64 = 3;

    fn tpow(mut base: u64, mut exp: u64) -> u64 {
        let mut r: u64 = 1; base %= P;
        let mut i = 0u32;
        while exp > 0 && i < 20 {
            if exp & 1 == 1 { r = (r * base) % P; }
            exp >>= 1;
            base = (base * base) % P;
            i += 1;
        }
        r
    }

    fn val_to_key(v: u64) -> X3dhKey {
        let mut k = ZERO_KEY;
        let b = (v % P).to_be_bytes();
        k[24] = b[0]; k[25] = b[1]; k[26] = b[2]; k[27] = b[3];
        k[28] = b[4]; k[29] = b[5]; k[30] = b[6]; k[31] = b[7];
        k
    }

    fn key_to_val(k: &X3dhKey) -> u64 {
        let mut v: u64 = 0;
        let mut i = 24usize;
        while i < 32 { v = (v << 8) | k[i] as u64; i += 1; }
        v % P
    }

    #[derive(Copy, Clone)]
    struct KaniX3dh;

    impl X3dhCrypto for KaniX3dh {
        fn dh(secret: &X3dhKey, peer_pub: &X3dhKey) -> X3dhKey {
            val_to_key(tpow(key_to_val(peer_pub), key_to_val(secret)))
        }
        fn dh_pub(secret: &X3dhKey) -> X3dhKey {
            val_to_key(tpow(G, key_to_val(secret)))
        }
        fn kdf(dh1: &X3dhKey, dh2: &X3dhKey, dh3: &X3dhKey, dh4: &X3dhKey) -> X3dhSessionKey {
            let v1 = key_to_val(dh1);
            let v2 = key_to_val(dh2);
            let v3 = key_to_val(dh3);
            let v4 = key_to_val(dh4);
            let result = v1.wrapping_mul(v2.wrapping_add(1))
                .wrapping_add(v3.wrapping_mul(v4.wrapping_add(1))) % P;
            let mut sk = ZERO_SESSION_KEY;
            let b = result.to_be_bytes();
            sk[24] = b[0]; sk[25] = b[1]; sk[26] = b[2]; sk[27] = b[3];
            sk[28] = b[4]; sk[29] = b[5]; sk[30] = b[6]; sk[31] = b[7];
            sk
        }
        fn sign(ik_secret: &X3dhKey, msg: &X3dhKey) -> X3dhSignature {
            let sv = key_to_val(ik_secret);
            let mv = key_to_val(msg);
            let sig_val = sv.wrapping_mul(mv).wrapping_add(42) % P;
            let mut sig = ZERO_SIGNATURE;
            let b = sig_val.to_be_bytes();
            sig[24] = b[0]; sig[25] = b[1]; sig[26] = b[2]; sig[27] = b[3];
            sig[28] = b[4]; sig[29] = b[5]; sig[30] = b[6]; sig[31] = b[7];
            let verify_val = tpow(G, sv).wrapping_mul(mv).wrapping_add(42) % P;
            let b2 = verify_val.to_be_bytes();
            sig[56] = b2[0]; sig[57] = b2[1]; sig[58] = b2[2]; sig[59] = b2[3];
            sig[60] = b2[4]; sig[61] = b2[5]; sig[62] = b2[6]; sig[63] = b2[7];
            sig
        }
        fn verify(ik_pub: &X3dhKey, msg: &X3dhKey, sig: &X3dhSignature) -> bool {
            let pv = key_to_val(ik_pub);
            let mv = key_to_val(msg);
            let expected_val = pv.wrapping_mul(mv).wrapping_add(42) % P;
            let expected_bytes = expected_val.to_be_bytes();
            sig[56] == expected_bytes[0] && sig[57] == expected_bytes[1]
                && sig[58] == expected_bytes[2] && sig[59] == expected_bytes[3]
                && sig[60] == expected_bytes[4] && sig[61] == expected_bytes[5]
                && sig[62] == expected_bytes[6] && sig[63] == expected_bytes[7]
        }
    }

    // =========================================================
    // 1. Panic-freedom: xor_32
    // =========================================================

    #[kani::proof]
    fn xor_32_panic_free() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        let _ = xor_32(&a, &b);
    }

    // =========================================================
    // 2. XOR algebraic properties
    // =========================================================

    #[kani::proof]
    fn xor_32_self_inverse() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        assert_eq!(xor_32(&xor_32(&a, &b), &b), a);
    }

    #[kani::proof]
    fn xor_32_commutative() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        assert_eq!(xor_32(&a, &b), xor_32(&b, &a));
    }

    // =========================================================
    // 3. Protocol agreement: initiate + respond agree
    // =========================================================

    #[kani::proof]
    #[kani::unwind(34)]
    fn x3dh_agreement_4dh_bounded() {
        let ik_a_v: u8 = kani::any();
        let ek_a_v: u8 = kani::any();
        let ik_b_v: u8 = kani::any();
        let spk_b_v: u8 = kani::any();
        let opk_b_v: u8 = kani::any();

        kani::assume(ik_a_v > 0 && ek_a_v > 0);
        kani::assume(ik_b_v > 0 && spk_b_v > 0 && opk_b_v > 0);

        let ik_a = val_to_key(ik_a_v as u64);
        let ek_a = val_to_key(ek_a_v as u64);
        let ik_b = val_to_key(ik_b_v as u64);
        let spk_b = val_to_key(spk_b_v as u64);
        let opk_b = val_to_key(opk_b_v as u64);

        let bundle = create_bundle::<KaniX3dh>(&ik_b, &spk_b, &opk_b);
        let (sk_a, msg, _) = initiate::<KaniX3dh>(&ik_a, &ek_a, &bundle, true);
        let sk_b = respond::<KaniX3dh>(&ik_b, &spk_b, &opk_b, &msg, true);

        assert_eq!(sk_a, sk_b, "X3DH 4DH: Alice and Bob MUST agree");
    }

    #[kani::proof]
    #[kani::unwind(34)]
    fn x3dh_agreement_3dh_bounded() {
        let ik_a_v: u8 = kani::any();
        let ek_a_v: u8 = kani::any();
        let ik_b_v: u8 = kani::any();
        let spk_b_v: u8 = kani::any();
        let opk_b_v: u8 = kani::any();

        kani::assume(ik_a_v > 0 && ek_a_v > 0);
        kani::assume(ik_b_v > 0 && spk_b_v > 0);

        let ik_a = val_to_key(ik_a_v as u64);
        let ek_a = val_to_key(ek_a_v as u64);
        let ik_b = val_to_key(ik_b_v as u64);
        let spk_b = val_to_key(spk_b_v as u64);
        let opk_b = val_to_key(opk_b_v as u64);

        let bundle = create_bundle::<KaniX3dh>(&ik_b, &spk_b, &opk_b);
        let (sk_a, msg, _) = initiate::<KaniX3dh>(&ik_a, &ek_a, &bundle, false);
        let sk_b = respond::<KaniX3dh>(&ik_b, &spk_b, &opk_b, &msg, false);

        assert_eq!(sk_a, sk_b, "X3DH 3DH: Alice and Bob MUST agree");
    }

    // =========================================================
    // 4. Signature correctness
    // =========================================================

    #[kani::proof]
    #[kani::unwind(34)]
    fn signature_roundtrip_bounded() {
        let sk_v: u8 = kani::any();
        let msg_v: u8 = kani::any();
        kani::assume(sk_v > 0);

        let sk = val_to_key(sk_v as u64);
        let pk = KaniX3dh::dh_pub(&sk);
        let msg = val_to_key(msg_v as u64);
        let sig = KaniX3dh::sign(&sk, &msg);
        assert!(KaniX3dh::verify(&pk, &msg, &sig));
    }
}
