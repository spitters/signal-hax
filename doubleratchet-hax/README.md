# doubleratchet-hax

Hax-extractable Rust implementation of the protocol logic of Signal's Double Ratchet over a
dependency trait. The state, the initialization, `RatchetEncrypt`, `RatchetDecrypt` with
`RatchetReceiveKey`, the skipped-message-key store and the DH ratchet step on receipt are
Rust; the primitives (HMAC-SHA-256, HKDF-SHA-256, X25519 and the message encryption) are calls
to the `DoubleRatchetDeps` trait. The crate implements no primitive and draws no randomness.
The library is `no_std`.

## Spec reference

Signal, *The Double Ratchet Algorithm*, Revision 4, 2025-11-04, sections 3.1-3.5 and 7.2.
<https://signal.org/docs/specifications/doubleratchet/>

The constants follow libsignal (`rust/protocol/src/ratchet/keys.rs`): `KDF_RK` expands 64
bytes under the info `"WhisperRatchet"`, `KDF_CK` uses the seeds `0x01` (message key) and
`0x02` (chain key), and the message encryption expands the message key under
`"WhisperMessageKeys"` and appends an 8-byte tag.

Underlying primitives: HMAC (RFC 2104), HKDF (RFC 5869), X25519 (RFC 7748), AES-256 (FIPS 197)
in CBC mode with PKCS#7 padding.

## Interface

| Item | Specification |
| --- | --- |
| `DoubleRatchetDeps::{hmac_sha256, hkdf_extract, hkdf_expand_64, x25519}` | the primitives of `KDF_CK`, `KDF_RK` and `DH` (3.1, 7.2) |
| `DoubleRatchetDeps::aead_encrypt`, `aead_decrypt` | `ENCRYPT`, `DECRYPT` (3.1, 7.2); decryption returns `None` on a failed tag or padding check |
| `kdf_ck`, `kdf_rk`, `dh`, `ct_len` | `KDF_CK`, `KDF_RK`, `DH`; `ct_len(pt_len)` is the ciphertext length of a plaintext length |
| `MessageHeader`, `encode_header`, `concat_ad` | `HEADER(dh, pn, n)` and `CONCAT(AD, header)`: the 64-byte AD of the key agreement followed by `dh \|\| pn \|\| n` (big-endian) |
| `RatchetState` | the state of 3.2 with Signal's field names (`dhs_sk`, `dhs_pk`, `dhr`, `rk`, `cks`, `ckr`, `ns`, `nr`, `pn`) and `MKSKIPPED` as `MAX_STORED` slots |
| `ratchet_init_alice`, `ratchet_init_bob` | `RatchetInitAlice`, `RatchetInitBob` (3.3) |
| `ratchet_encrypt` | `RatchetEncrypt` (3.4) |
| `try_skipped_message_keys`, `skip_message_keys` | `TrySkippedMessageKeys`, `SkipMessageKeys` (3.5) |
| `dh_ratchet_recv_half`, `dh_ratchet_send_half`, `dh_ratchet` | `DHRatchet` (3.5) and its two halves |
| `ratchet_receive_key`, `ratchet_decrypt` | `RatchetReceiveKey`, `RatchetDecrypt` (3.5) |

`ratchet_decrypt` is transactional: on every rejection (a failed AEAD check, a jump over
`MAX_SKIP`, a full store, a used position, a state without a receiving chain) it returns
`None`, and the caller keeps the state it passed in. The key pair of `GENERATE_DH` for the DH
ratchet step is an argument of `ratchet_decrypt`; it enters the state exactly when the header
carries a new ratchet key, which the caller sees as `result.dhs_pk == new_pk`.

The parameters of the crate are `MAX_SKIP = 16`, `MAX_STORED = 32`, `AD_LEN = 64` (two 32-byte
X25519 identity keys; libsignal's `Encode` adds a type byte to each), `TAG_LEN = 8` and
`MAX_PLAINTEXT_LEN = 256`. libsignal uses `MAX_FORWARD_JUMPS = 25000` and
`MAX_MESSAGE_KEYS = 2000`.

The typestate wrapper of `src/typestate_fsm.rs` holds a `RatchetState` and a step counter.
`Uninitialized::establish_alice` and `establish_bob` call the two init functions,
`Session::send` calls `ratchet_encrypt`, and `Session::receive` calls `ratchet_decrypt`; both
transitions return the unchanged session together with `None` on a refusal. Move semantics
make the reuse of a consumed session a compile error (the `compile_fail` doctests).

## Lean extraction

The Lean model used by the CatCrypt proofs is extracted with `cargo hax json --use-ids`
followed by the `haxpipeT` translator of hax-lean. The fields of the class
`DoubleratchetDeps` of the extraction are the primitives of the `DoubleRatchetDeps` trait and
the ghost hook `event`. The extraction and its correspondence to the secure-messaging model of
CatCrypt-core (`CatCryptCore/Crypto/Messaging/DoubleRatchet.lean`) are in
`CatCryptCore/Crypto/Signal/DoubleRatchet/`. As a secure-messaging scheme, `ratchet_encrypt`
encrypts in the current sending epoch, the receiving half of `DHRatchet` receives the peer's
epoch and the sending half opens the party's next epoch; under equations stating that the
dependency's primitives commute with the encoding, these functions simulate the construction
of Alwen, Coretti and Dodis, and the corruption and adaptive-challenge bounds of the model hold
on them. The theorems cover the two halves at separate times; the moment inside
`ratchet_decrypt` between the halves, at which the state holds the new key pair, is outside
their statements.

## Running the tests

```bash
cargo test
```

## What the tests claim

The tests run the crate over the reference dependency `RefDeps` of `tests/common`: HMAC-SHA-256
and HKDF-SHA-256 of RustCrypto, X25519 of `x25519-dalek`, and the message encryption of 7.2
with the libsignal constants on RustCrypto `aes` and `cbc`.

| File | Claim |
| --- | --- |
| `tests/reference_crosscheck.rs` | `kdf_ck` and `kdf_rk` agree byte for byte with RustCrypto HMAC and HKDF at the libsignal constants; the header encoding and `CONCAT(AD, header)` have the stated layout; `ct_len(pt_len)` is the deployed ciphertext length for every `pt_len` in `0..=256`; the ciphertexts of `ratchet_encrypt` equal the 7.2 encryption under an independently recomputed sending chain and associated data. |
| `tests/proptest_equiv.rs` | The same agreements on random inputs; domain separation of both KDFs; the keys stored by `skip_message_keys` are those of the iterated chain; encrypt/decrypt round trip between two parties; a random ciphertext is rejected. |
| `tests/protocol_logic.rs` | Determinism, key uniqueness and forward secrecy of the chain; round trip; rejection under a wrong chain key or AD; the DH ratchet step and its two halves; header contents. |
| `tests/session_setup.rs` | The two setups hold the shared secret at most as the responder's root key; operations before the first receipt are refused; the responder's first decryption performs the DH ratchet step from `DHr = None`; a conversation driven by `ratchet_encrypt` and `ratchet_decrypt` agrees, with the supplied key pair used exactly on a new ratchet key. |
| `tests/out_of_order.rs` | In-chain permutations of up to `MAX_SKIP + 1` messages and messages of the previous chain after the first of the new chain decrypt; a jump over `MAX_SKIP`, directly or through `pn`, and a message needing a slot of a full store are rejected with the state unchanged; a skipped key is used once and its slot is cleared to zero bytes; replays are rejected; random delivery orders over two chains decrypt every message. |
| `tests/authentication.rs` | A change of the header's `dh`, `pn` or `n`, of one AD byte, of one ciphertext or tag byte, or of the ciphertext length is rejected with every state field unchanged, at the first receipt, within a chain and at a new chain; a message is bound to its session. |

## Scope and deviations from the Signal specification

- No header encryption (section 4 of the specification).
- The key pair of `GENERATE_DH` in `DHRatchet` is supplied by the caller of
  `ratchet_decrypt`, since the crate draws no randomness.
- Plaintexts have at most `MAX_PLAINTEXT_LEN = 256` bytes; `ratchet_encrypt` requires
  `pt_len <= MAX_PLAINTEXT_LEN`.
- The tag of the message encryption is the HMAC-SHA-256 output truncated to 8 bytes, as in
  libsignal; 7.2 appends the full output.
- `MKSKIPPED` has `MAX_STORED = 32` slots, and a message whose skipped keys do not fit is
  rejected. libsignal evicts the oldest keys instead.
- Skipped keys are not deleted after a time or a number of later messages; 8.4 of the
  specification places such deletion outside the protocol functions.
- A header with the current ratchet key and a message number below `Nr` whose key is not in
  the store is rejected by `ratchet_receive_key`. The specification derives a key at `Nr` and
  rejects the message at the AEAD check, so both reject the same messages except at an AEAD
  collision.

## Departures from libsignal

The interop tests named below live in a private interop crate that runs this crate against
libsignal v0.105.2. Each test that shows a departure is ignored by default and fails when run.

- Previous-chain counter. libsignal sends `N - 1` as the previous-chain counter and keeps the
  old receiving chain (libsignal v0.105.2, rust/protocol/src/double_ratchet.rs:300). The crate
  sends `N` and drops the old chain at the ratchet step (`src/lib.rs:472`, `:532`), so a late
  last message of an old chain is rejected when the counter is libsignal's. Tests:
  `late_message_of_previous_chain_with_pn_translation`,
  `late_message_of_previous_chain_raw_pn`, `pn_on_the_wire_is_libsignal_previous_counter`.
- Sending chain of the responder. libsignal gives the responder a sending chain at
  initialisation (libsignal v0.105.2, rust/protocol/src/ratchet.rs:106, :169). In the crate
  `CKs` and `CKr` of the responder are `None` until the first receipt (`src/lib.rs:270`,
  `:289`). Test: `responder_sends_first`.
- Skip bound. libsignal accepts forward jumps of up to 25,000 messages (libsignal v0.105.2,
  rust/protocol/src/consts.rs:8). The crate has `MAX_SKIP = 16` and `MAX_STORED = 32`
  (`src/lib.rs:63`, `:65`). Test: `forward_jump_beyond_max_skip`.
- MAC input. libsignal computes the MAC over the sender and receiver identity keys and the
  serialized protobuf message (libsignal v0.105.2, rust/protocol/src/protocol.rs:214-233).
  The test dependency of the crate (`tests/common/mod.rs:58-63`) computes it over the
  associated data, the header and the ciphertext, the form of section 7.2 of the
  specification. Test: `section_7_2_mac_input`.
- libsignal v0.105 mixes the SPQR key into the message keys. The crate does not model it.

## License

MIT. See [`LICENSE`](./LICENSE).
