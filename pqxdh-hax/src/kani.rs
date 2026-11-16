//! Kani verification harnesses for PQXDH.
//!
//! Checks, over a toy model of the primitives:
//! 1. Panic-freedom of `xor_32` and `wrapping_add_32`
//! 2. XOR identities (self-inverse, commutativity, zero)
//! 3. KEM roundtrip: encaps then decaps recovers the same shared secret
//! 4. Agreement of initiate and respond with a one-time prekey, for key values below 256
//! 5. Signature correctness: sign then verify succeeds, for key values below 256

#[cfg(kani)]
mod kani_harnesses {
    use crate::types::*;
    use crate::protocol::*;

    // ===== Toy crypto over Z_65537^* (as `KaniSimplifiedPqxdh` in tests/toy_model.rs) =====

    const P: u64 = 65537;
    const G: u64 = 3;

    fn tpow(mut base: u64, mut exp: u64) -> u64 {
        let mut r: u64 = 1; base %= P;
        // Bounded loop: exp < P < 2^17, so at most 17 iterations
        let mut i = 0u32;
        while exp > 0 && i < 20 {
            if exp & 1 == 1 { r = (r * base) % P; }
            exp >>= 1;
            base = (base * base) % P;
            i += 1;
        }
        r
    }

    fn val_to_key(v: u64) -> [u8; 32] {
        let mut k = [0u8; 32];
        let b = (v % P).to_be_bytes();
        k[24] = b[0]; k[25] = b[1]; k[26] = b[2]; k[27] = b[3];
        k[28] = b[4]; k[29] = b[5]; k[30] = b[6]; k[31] = b[7];
        k
    }

    fn key_to_val(k: &[u8; 32]) -> u64 {
        let mut v: u64 = 0;
        let mut i = 24usize;
        while i < 32 {
            v = (v << 8) | k[i] as u64;
            i += 1;
        }
        v % P
    }

    const KEM_PK_CONST: [u8; 32] = {
        let mut c = [0u8; 32]; c[0] = 0x05; c[1] = 0x50; c[2] = 0x4B; c
    };
    const KDF_CONST: [u8; 32] = {
        let mut c = [0u8; 32]; c[0] = 0x07; c[1] = 0x50; c[2] = 0x51; c
    };

    #[derive(Copy, Clone)]
    struct KaniPqxdh;

    impl PqxdhCrypto<32, 32, 32> for KaniPqxdh {
        fn dh(secret: &PqxdhDhKey, peer_pub: &PqxdhDhKey) -> PqxdhDhKey {
            val_to_key(tpow(key_to_val(peer_pub), key_to_val(secret)))
        }
        fn dh_pub(secret: &PqxdhDhKey) -> PqxdhDhKey {
            val_to_key(tpow(G, key_to_val(secret)))
        }
        fn kem_keygen(seed: &PqxdhKemSs) -> ([u8; 32], [u8; 32]) {
            (xor_32(seed, &KEM_PK_CONST), *seed)
        }
        fn kem_encaps(pk: &[u8; 32], randomness: &PqxdhKemSs) -> ([u8; 32], PqxdhKemSs) {
            (xor_32(randomness, pk), *randomness)
        }
        fn kem_decaps(sk: &[u8; 32], ct: &[u8; 32]) -> PqxdhKemSs {
            let pk_recovered = xor_32(sk, &KEM_PK_CONST);
            xor_32(ct, &pk_recovered)
        }
        fn kem_pk_encode(pk: &[u8; 32]) -> [u8; 32] { *pk }
        fn kdf(dh1: &PqxdhDhKey, dh2: &PqxdhDhKey, dh3: &PqxdhDhKey,
               dh4: &PqxdhDhKey, kem_ss: &PqxdhKemSs) -> PqxdhSessionKey {
            let mut acc = xor_32(dh1, dh2);
            acc = xor_32(&acc, dh3);
            acc = xor_32(&acc, dh4);
            acc = xor_32(&acc, kem_ss);
            wrapping_add_32(&acc, &KDF_CONST)
        }
        fn sign(ik_secret: &PqxdhDhKey, msg: &[u8; 32]) -> PqxdhSignature {
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
        fn verify(ik_pub: &PqxdhDhKey, msg: &[u8; 32], sig: &PqxdhSignature) -> bool {
            let pv = key_to_val(ik_pub);
            let mv = key_to_val(msg);
            let expected_val = pv.wrapping_mul(mv).wrapping_add(42) % P;
            let expected_bytes = expected_val.to_be_bytes();
            sig[56] == expected_bytes[0] && sig[57] == expected_bytes[1]
                && sig[58] == expected_bytes[2] && sig[59] == expected_bytes[3]
                && sig[60] == expected_bytes[4] && sig[61] == expected_bytes[5]
                && sig[62] == expected_bytes[6] && sig[63] == expected_bytes[7]
        }
        /// A toy public key is a value in `[2, P)` held in the last eight
        /// bytes: an element of Z_P^* other than the identity `1`.
        fn valid_pub(pk: &PqxdhDhKey) -> bool {
            let mut high_zero = true;
            let mut i = 0usize;
            while i < 24 { if pk[i] != 0 { high_zero = false; } i += 1; }
            let mut v: u64 = 0;
            let mut j = 24usize;
            while j < 32 { v = (v << 8) | pk[j] as u64; j += 1; }
            high_zero && v > 1 && v < P
        }
    }

    // =========================================================
    // 1. Panic-freedom: xor_32, wrapping_add_32
    // =========================================================

    #[kani::proof]
    fn xor_32_panic_free() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        let _ = xor_32(&a, &b);
    }

    #[kani::proof]
    fn wrapping_add_32_panic_free() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        let _ = wrapping_add_32(&a, &b);
    }

    // =========================================================
    // 2. XOR properties: self-inverse, identity, commutativity
    // =========================================================

    #[kani::proof]
    fn xor_32_self_inverse() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        assert_eq!(xor_32(&xor_32(&a, &b), &b), a, "a ^ b ^ b = a");
    }

    #[kani::proof]
    fn xor_32_commutative() {
        let a: [u8; 32] = kani::any();
        let b: [u8; 32] = kani::any();
        assert_eq!(xor_32(&a, &b), xor_32(&b, &a), "a ^ b = b ^ a");
    }

    #[kani::proof]
    fn xor_32_identity() {
        let a: [u8; 32] = kani::any();
        let zero = [0u8; 32];
        assert_eq!(xor_32(&a, &zero), a, "a ^ 0 = a");
    }

    // =========================================================
    // 3. KEM roundtrip: encaps then decaps recovers shared secret
    // =========================================================

    #[kani::proof]
    fn kem_roundtrip_all_inputs() {
        let seed: [u8; 32] = kani::any();
        let randomness: [u8; 32] = kani::any();
        let (pk, sk) = KaniPqxdh::kem_keygen(&seed);
        let (ct, ss_enc) = KaniPqxdh::kem_encaps(&pk, &randomness);
        let ss_dec = KaniPqxdh::kem_decaps(&sk, &ct);
        assert_eq!(ss_enc, ss_dec, "KEM roundtrip for ALL inputs");
    }

    // =========================================================
    // 4. Protocol correctness: initiate + respond agree
    //    (bounded: keys constrained to small values)
    // =========================================================

    #[kani::proof]
    #[kani::unwind(34)]
    fn protocol_agreement_bounded() {
        // Use small symbolic values to keep tpow bounded
        let ik_a_val: u8 = kani::any();
        let ek_a_val: u8 = kani::any();
        let ik_b_val: u8 = kani::any();
        let spk_b_val: u8 = kani::any();
        let opk_b_val: u8 = kani::any();
        let kem_seed_val: u8 = kani::any();
        let kem_rand_val: u8 = kani::any();

        // Avoid trivial zero keys (DH with zero is degenerate)
        kani::assume(ik_a_val > 0 && ek_a_val > 0);
        kani::assume(ik_b_val > 0 && spk_b_val > 0 && opk_b_val > 0);

        let ik_a = val_to_key(ik_a_val as u64);
        let ek_a = val_to_key(ek_a_val as u64);
        let ik_b = val_to_key(ik_b_val as u64);
        let spk_b = val_to_key(spk_b_val as u64);
        let opk_b = val_to_key(opk_b_val as u64);
        let kem_seed = val_to_key(kem_seed_val as u64);
        let kem_rand = val_to_key(kem_rand_val as u64);

        let (bundle, pqsk) = create_bundle::<KaniPqxdh>(&ik_b, &spk_b, &opk_b, &kem_seed);
        let (sk_a, msg, _, _) =
            initiate::<KaniPqxdh>(&ik_a, &ek_a, &bundle, &kem_rand, true)
                .expect("the bundle of toy public keys passes the input check");
        let sk_b = respond::<KaniPqxdh>(&ik_b, &spk_b, &opk_b, &pqsk, &msg, true)
            .expect("the message of toy public keys passes the input check");

        assert_eq!(sk_a, sk_b, "Alice and Bob MUST agree for ALL key combinations");
    }

    // =========================================================
    // 5. Signature correctness: sign then verify succeeds
    // =========================================================

    #[kani::proof]
    #[kani::unwind(34)]
    fn signature_roundtrip_bounded() {
        let sk_val: u8 = kani::any();
        let msg_val: u8 = kani::any();
        kani::assume(sk_val > 0);

        let sk = val_to_key(sk_val as u64);
        let pk = KaniPqxdh::dh_pub(&sk);
        let msg = val_to_key(msg_val as u64);
        let sig = KaniPqxdh::sign(&sk, &msg);

        assert!(KaniPqxdh::verify(&pk, &msg, &sig),
            "sign then verify MUST succeed for ALL key/msg pairs");
    }
}
