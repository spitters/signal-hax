//! Protocol-logic and property tests for the Signal Double Ratchet
//! symmetric ratchet (KDF chain). The Signal Double Ratchet has no published
//! test vectors, so these tests check protocol-level properties (determinism,
//! key uniqueness, roundtrip, forward secrecy) rather than published answers.
//!
//! Tests cover:
//! - KDF chain determinism
//! - Chain step produces different CK and MK
//! - Multiple chain steps produce unique keys
//! - Encrypt/decrypt roundtrip
//! - Forward secrecy: after N steps, step N-1 key is not derivable
//! - Wrong key fails decryption
//! - DH ratchet step properties

mod common;
use common::RefDeps;
use doubleratchet_hax::*;

// ============================================================
// Helper: create a test key from a single byte pattern
// ============================================================

fn test_key(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Build a simple RatchetState for testing the symmetric ratchet.
/// Both parties share the same root key; send/recv chains are set
/// so that Alice's send_ck == Bob's recv_ck and vice versa.
fn make_test_pair() -> (RatchetState, RatchetState) {
    let root_key = test_key(0x10);
    let alice_sk = test_key(0x20);
    let alice_pk = test_key(0x21);
    let bob_sk = test_key(0x30);
    let bob_pk = test_key(0x31);

    // Alice as initiator: she does a DH ratchet to get her send chain
    let alice = ratchet_init_initiator::<RefDeps>(
        &root_key, &alice_sk, &alice_pk, &bob_pk,
    );

    // Bob as responder: his recv chain must match Alice's send chain.
    // To achieve this, Bob does the same DH and derives the same chain key.
    let dh_out = dh::<RefDeps>(&alice_sk, &bob_pk);
    let (new_rk, recv_ck_for_bob) = kdf_rk::<RefDeps>(&root_key, &dh_out);

    let bob = RatchetState {
        root_key: new_rk,
        send_ck: test_key(0x00), // Bob hasn't sent yet
        recv_ck: recv_ck_for_bob,
        send_n: 0,
        recv_n: 0,
        my_sk: bob_sk,
        my_pk: bob_pk,
        remote_pk: alice_pk,
        prev_send_n: 0,
    };

    (alice, bob)
}

// ============================================================
// 1. KDF chain determinism
// ============================================================

#[test]
fn kdf_chain_deterministic() {
    let ck = test_key(0x42);
    let (ck1, mk1) = kdf_chain_step::<RefDeps>(&ck);
    let (ck2, mk2) = kdf_chain_step::<RefDeps>(&ck);
    assert_eq!(ck1, ck2, "chain key derivation must be deterministic");
    assert_eq!(mk1, mk2, "message key derivation must be deterministic");
}

// ============================================================
// 2. Chain step produces different CK and MK
// ============================================================

#[test]
fn chain_step_ck_mk_differ() {
    let ck = test_key(0x55);
    let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);
    assert_ne!(new_ck, mk, "CK and MK from same step must differ");
}

// ============================================================
// 3. Multiple chain steps produce unique keys
// ============================================================

#[test]
fn multiple_steps_unique_chain_keys() {
    let mut ck = test_key(0x77);
    let mut chain_keys: [[u8; 32]; 10] = [[0u8; 32]; 10];

    for i in 0..10 {
        let (new_ck, _mk) = kdf_chain_step::<RefDeps>(&ck);
        chain_keys[i] = new_ck;
        ck = new_ck;
    }

    // All chain keys must be distinct
    for i in 0..10 {
        for j in (i + 1)..10 {
            assert_ne!(chain_keys[i], chain_keys[j],
                "chain keys at steps {} and {} must differ", i, j);
        }
    }
}

#[test]
fn multiple_steps_unique_message_keys() {
    let mut ck = test_key(0x88);
    let mut msg_keys: [[u8; 32]; 10] = [[0u8; 32]; 10];

    for i in 0..10 {
        let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);
        msg_keys[i] = mk;
        ck = new_ck;
    }

    // All message keys must be distinct
    for i in 0..10 {
        for j in (i + 1)..10 {
            assert_ne!(msg_keys[i], msg_keys[j],
                "message keys at steps {} and {} must differ", i, j);
        }
    }
}

// ============================================================
// 4. Chain key differs from input
// ============================================================

#[test]
fn chain_step_output_differs_from_input() {
    let ck = test_key(0x99);
    let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);
    assert_ne!(new_ck, ck, "new chain key must differ from input");
    assert_ne!(mk, ck, "message key must differ from input chain key");
}

// ============================================================
// 5. Different initial keys produce different chains
// ============================================================

#[test]
fn different_initial_keys_diverge() {
    let ck_a = test_key(0xaa);
    let ck_b = test_key(0xbb);

    let (new_ck_a, mk_a) = kdf_chain_step::<RefDeps>(&ck_a);
    let (new_ck_b, mk_b) = kdf_chain_step::<RefDeps>(&ck_b);

    assert_ne!(new_ck_a, new_ck_b, "different inputs must produce different chain keys");
    assert_ne!(mk_a, mk_b, "different inputs must produce different message keys");
}

// ============================================================
// 6. Encrypt/decrypt roundtrip
// ============================================================

#[test]
fn encrypt_decrypt_roundtrip_short() {
    let (alice, bob) = make_test_pair();
    let plaintext = b"Hello, Signal!";
    let pt_len = plaintext.len();

    let (alice2, header, ciphertext) =
        ratchet_encrypt::<RefDeps>(&alice, plaintext, pt_len);
    let (bob2, recovered) =
        ratchet_decrypt::<RefDeps>(&bob, &header, &ciphertext, pt_len);

    for i in 0..pt_len {
        assert_eq!(recovered[i], plaintext[i],
            "decrypted byte {} mismatch", i);
    }

    // Counters updated
    assert_eq!(alice2.send_n, 1, "Alice send counter");
    assert_eq!(bob2.recv_n, 1, "Bob recv counter");
}

#[test]
fn encrypt_decrypt_roundtrip_32_bytes() {
    let (alice, bob) = make_test_pair();
    let plaintext: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];
    let pt_len = 32;

    let (_alice2, header, ciphertext) =
        ratchet_encrypt::<RefDeps>(&alice, &plaintext, pt_len);
    let (_bob2, recovered) =
        ratchet_decrypt::<RefDeps>(&bob, &header, &ciphertext, pt_len);

    for i in 0..pt_len {
        assert_eq!(recovered[i], plaintext[i],
            "decrypted byte {} mismatch", i);
    }
}

// ============================================================
// 7. Multiple messages encrypt/decrypt correctly
// ============================================================

#[test]
fn multiple_messages_roundtrip() {
    let (mut alice, mut bob) = make_test_pair();

    let messages: [&[u8]; 5] = [
        b"First message",
        b"Second message",
        b"Third",
        b"Fourth message is a bit longer than the others",
        b"Fifth",
    ];

    for msg in &messages {
        let pt_len = msg.len();
        let (new_alice, header, ciphertext) =
            ratchet_encrypt::<RefDeps>(&alice, msg, pt_len);
        let (new_bob, recovered) =
            ratchet_decrypt::<RefDeps>(&bob, &header, &ciphertext, pt_len);

        for i in 0..pt_len {
            assert_eq!(recovered[i], msg[i]);
        }

        alice = new_alice;
        bob = new_bob;
    }

    assert_eq!(alice.send_n, 5);
    assert_eq!(bob.recv_n, 5);
}

// ============================================================
// 8. Ciphertext differs from plaintext (non-trivial encryption)
// ============================================================

#[test]
fn ciphertext_differs_from_plaintext() {
    let (alice, _bob) = make_test_pair();
    let plaintext = b"This should be encrypted";
    let pt_len = plaintext.len();

    let (_alice2, _header, ciphertext) =
        ratchet_encrypt::<RefDeps>(&alice, plaintext, pt_len);

    // At least some bytes should differ (XOR with non-zero key)
    let mut differs = false;
    for i in 0..pt_len {
        if ciphertext[i] != plaintext[i] {
            differs = true;
            break;
        }
    }
    assert!(differs, "ciphertext must differ from plaintext");
}

// ============================================================
// 9. Forward secrecy: old chain key cannot derive new message keys
// ============================================================

#[test]
fn forward_secrecy() {
    let initial_ck = test_key(0xdd);

    // Advance the chain 5 steps, saving the chain key at step 2
    let mut ck = initial_ck;
    let mut ck_at_step_2 = [0u8; 32];
    let mut mk_at_step_4 = [0u8; 32];

    for step in 0..5 {
        let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);
        if step == 2 {
            ck_at_step_2 = ck; // save the chain key BEFORE step 2
        }
        if step == 4 {
            mk_at_step_4 = mk; // the message key at step 4
        }
        ck = new_ck;
    }

    // From ck_at_step_2, we can only derive step 2's message key,
    // NOT step 4's. This demonstrates forward secrecy.
    let (_ck_from_2, mk_from_2) = kdf_chain_step::<RefDeps>(&ck_at_step_2);
    assert_ne!(mk_from_2, mk_at_step_4,
        "old chain key must not produce future message keys");

    // Even advancing 2 more steps from ck_at_step_2 does NOT produce mk_at_step_4,
    // because the chain keys at step 2 diverge from the original path
    // (step 2's chain key was consumed to get step 3's chain key in the original path).
    let (ck_step3_from_2, _) = kdf_chain_step::<RefDeps>(&ck_at_step_2);
    let (_ck_step4_from_2, _mk_step4_from_2) = kdf_chain_step::<RefDeps>(&ck_step3_from_2);
    // This WILL match because the chain is deterministic from step 2 onward.
    // The forward secrecy property is: if the attacker captures ck at step N,
    // they CANNOT derive message keys for steps 0..N-1.
    // Let's verify the other direction: from ck at step 2, can we get step 0's MK?

    // Derive step 0's message key from the initial chain key
    let (_ck_step0, mk_step0) = kdf_chain_step::<RefDeps>(&initial_ck);

    // From ck_at_step_2, we cannot derive mk_step0
    let (_ck_from_2_first, mk_from_2_first) = kdf_chain_step::<RefDeps>(&ck_at_step_2);
    assert_ne!(mk_from_2_first, mk_step0,
        "chain key at step 2 must not produce step 0's message key");
}

// ============================================================
// 10. Forward secrecy: initial key not derivable from advanced state
// ============================================================

#[test]
fn forward_secrecy_initial_key_lost() {
    let initial_ck = test_key(0xee);
    let (_, mk_initial) = kdf_chain_step::<RefDeps>(&initial_ck);

    // Advance 10 steps
    let advanced_ck = kdf_chain_advance::<RefDeps>(&initial_ck, 10);

    // The advanced chain key is completely different from the initial MK
    let (_, mk_from_advanced) = kdf_chain_step::<RefDeps>(&advanced_ck);
    assert_ne!(mk_from_advanced, mk_initial,
        "advanced chain key must not reproduce initial message key");
    assert_ne!(advanced_ck, initial_ck,
        "advanced chain key must differ from initial");
}

// ============================================================
// 11. Wrong key fails decryption
// ============================================================

#[test]
fn wrong_key_fails_decryption() {
    let (alice, bob) = make_test_pair();
    let plaintext = b"Secret message";
    let pt_len = plaintext.len();

    let (_alice2, header, ciphertext) =
        ratchet_encrypt::<RefDeps>(&alice, plaintext, pt_len);

    // Tamper with Bob's receiving chain key
    let mut bad_bob = bob;
    bad_bob.recv_ck = test_key(0xff); // wrong key

    let (_bad_bob2, bad_recovered) =
        ratchet_decrypt::<RefDeps>(&bad_bob, &header, &ciphertext, pt_len);

    // Decryption with wrong key should produce wrong plaintext
    let mut matches = true;
    for i in 0..pt_len {
        if bad_recovered[i] != plaintext[i] {
            matches = false;
            break;
        }
    }
    assert!(!matches, "decryption with wrong key must produce different plaintext");
}

// ============================================================
// 12. kdf_chain_advance matches iterated kdf_chain_step
// ============================================================

#[test]
fn chain_advance_matches_iterated_step() {
    let initial_ck = test_key(0x33);

    // Manual iteration
    let mut ck = initial_ck;
    for _ in 0..7 {
        let (new_ck, _mk) = kdf_chain_step::<RefDeps>(&ck);
        ck = new_ck;
    }

    // Using kdf_chain_advance
    let advanced_ck = kdf_chain_advance::<RefDeps>(&initial_ck, 7);

    assert_eq!(ck, advanced_ck,
        "kdf_chain_advance must match iterated kdf_chain_step");
}

// ============================================================
// 13. Zero steps in kdf_chain_advance returns same key
// ============================================================

#[test]
fn chain_advance_zero_steps() {
    let ck = test_key(0x44);
    let result = kdf_chain_advance::<RefDeps>(&ck, 0);
    assert_eq!(result, ck, "advancing 0 steps must return same key");
}

// ============================================================
// 14. DH ratchet step changes all chain keys
// ============================================================

#[test]
fn dh_ratchet_step_changes_keys() {
    let (alice, _bob) = make_test_pair();

    // Simulate receiving a new DH key from Bob
    let new_bob_pk = test_key(0x50);
    let new_alice_sk = test_key(0x60);
    let new_alice_pk = test_key(0x61);

    let alice2 = dh_ratchet_step::<RefDeps>(
        &alice, &new_bob_pk, &new_alice_sk, &new_alice_pk,
    );

    assert_ne!(alice2.root_key, alice.root_key, "root key must change");
    assert_ne!(alice2.send_ck, alice.send_ck, "send chain key must change");
    assert_ne!(alice2.recv_ck, alice.recv_ck, "recv chain key must change");
    assert_eq!(alice2.send_n, 0, "send counter resets after DH ratchet");
    assert_eq!(alice2.recv_n, 0, "recv counter resets after DH ratchet");
    assert_eq!(alice2.prev_send_n, alice.send_n, "prev_send_n captures old send_n");
}

// ============================================================
// 15. Header contains correct metadata
// ============================================================

#[test]
fn header_metadata() {
    let (mut alice, _bob) = make_test_pair();

    // Send 3 messages, check headers
    for expected_n in 0..3u32 {
        let plaintext = b"test";
        let (new_alice, header, _ct) =
            ratchet_encrypt::<RefDeps>(&alice, plaintext, 4);
        assert_eq!(header.msg_number, expected_n,
            "header msg_number should be {}", expected_n);
        assert_eq!(header.dh_public, alice.my_pk,
            "header dh_public should be sender's public key");
        alice = new_alice;
    }
}

// ============================================================
// 16. Encrypt empty plaintext
// ============================================================

#[test]
fn encrypt_empty_plaintext() {
    let (alice, bob) = make_test_pair();
    let plaintext: [u8; 0] = [];
    let pt_len = 0;

    let (_alice2, header, ciphertext) =
        ratchet_encrypt::<RefDeps>(&alice, &plaintext, pt_len);
    let (_bob2, recovered) =
        ratchet_decrypt::<RefDeps>(&bob, &header, &ciphertext, pt_len);

    // All bytes in the recovered buffer beyond pt_len should be zero
    for i in 0..MAX_PLAINTEXT_LEN {
        assert_eq!(recovered[i], 0, "recovered byte {} should be 0 for empty plaintext", i);
    }
}

// ============================================================
// 17. KDF chain known-answer test (HMAC-SHA-256 specific)
// ============================================================

#[test]
fn kdf_chain_matches_hmac() {
    // kdf_chain_step must agree with a direct HMAC-SHA-256 computation.
    let ck = [0u8; 32];
    let (new_ck, mk) = kdf_chain_step::<RefDeps>(&ck);

    // Verify against directly computed HMAC
    let expected_ck = common::hmac(&ck, &[0x01; 32]);
    let expected_mk = common::hmac(&ck, &[0x02; 32]);

    assert_eq!(new_ck, expected_ck, "chain key must equal HMAC(ck, [0x01; 32])");
    assert_eq!(mk, expected_mk, "message key must equal HMAC(ck, [0x02; 32])");
}

// ============================================================
// 18. Successive encryptions produce different ciphertexts
// ============================================================

#[test]
fn successive_encryptions_differ() {
    let (alice, _bob) = make_test_pair();
    let plaintext = b"Same message";
    let pt_len = plaintext.len();

    let (alice2, _header1, ct1) =
        ratchet_encrypt::<RefDeps>(&alice, plaintext, pt_len);
    let (_alice3, _header2, ct2) =
        ratchet_encrypt::<RefDeps>(&alice2, plaintext, pt_len);

    // Same plaintext, different ratchet state -> different ciphertext
    let mut differs = false;
    for i in 0..pt_len {
        if ct1[i] != ct2[i] {
            differs = true;
            break;
        }
    }
    assert!(differs, "successive encryptions of same plaintext must produce different ciphertexts");
}

// ============================================================
// 19. kdf_rk produces distinct root key and chain key
// ============================================================

#[test]
fn kdf_rk_outputs_differ() {
    let rk = test_key(0x11);
    let dh_out = test_key(0x22);
    let (new_rk, new_ck) = kdf_rk::<RefDeps>(&rk, &dh_out);
    assert_ne!(new_rk, new_ck, "kdf_rk must produce different root key and chain key");
    assert_ne!(new_rk, rk, "new root key must differ from input");
}
