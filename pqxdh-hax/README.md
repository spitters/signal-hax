# pqxdh-hax

Hax-extractable Rust implementation of Signal's **PQXDH** (Post-Quantum
Extended Diffie-Hellman) key-agreement protocol — X3DH plus a KEM
encapsulation — with cross-library and property-based tests against
`x25519-dalek`, `ml-kem` (ML-KEM-768) and `hkdf` + `sha2`.

The `PqxdhCrypto` trait in [`src/protocol.rs`](./src/protocol.rs) is generic
over the KEM byte sizes (`const KEM_PK`, `KEM_SK`, `KEM_CT`), so the same
protocol code runs with a toy 32-byte KEM (Kani harnesses and unit tests) and
with ML-KEM-768 at `<1184, 2400, 1088>`. ML-KEM-768 is the parameter set that
is tested and that the Lean proofs use. The library is `no_std`.

The trait has an input check `valid_pub` of a peer Diffie-Hellman public key.
`initiate` returns `Option<(PqxdhSessionKey, PqxdhInitMessage<KEM_CT>, bool,
bool)>`: `None` when a key of the bundle that the computation uses (`ik`,
`spk`, and `opk` when `use_opk`) fails the check, and otherwise `Some` of the
computation `initiate_checked`. `respond` returns `Option<PqxdhSessionKey>`:
`None` when `ik_a` or `ek_a` of the message fails the check, and otherwise
`Some` of `respond_checked`. The initiator machine of
[`src/typestate_fsm.rs`](./src/typestate_fsm.rs) (`send_init`, `run_pqxdh`,
`pqxdh_initiate_term`) returns `Option` likewise. The module
[`src/subgroup.rs`](./src/subgroup.rs) (not extracted; the module of
x3dh-hax) implements the check for X25519 as `valid_pub`: membership in the
prime-order subgroup of Curve25519 (`is_subgroup_point`) with the identity
`0` excluded. It rejects twist points, points with a component of order 2, 4
or 8, non-canonical strings and the identity.

## Spec reference

Signal — *The PQXDH Key Agreement Protocol*, September 2023.
<https://signal.org/docs/specifications/pqxdh/>

Underlying primitives:
- **X25519** — RFC 7748
- **ML-KEM-768** — FIPS 203 (NIST, 2024)
- **HKDF-SHA256** — RFC 5869

## Lean extraction

The Lean model used by the CatCrypt proofs is extracted with
`cargo hax json --use-ids` followed by the `haxpipeT` translator of hax-lean.
The operations of `PqxdhCrypto` become fields of the class `PqxdhDeps` of the
extraction, and the KEM arrays become `Array Int`, without the size
parameters. The extraction and its correspondence to the passive PQXDH model
are in CatCrypt-core (`CatCryptCore/Crypto/AKE/PQXDH/`): the extracted
handshake game equals the model's real game mapped by the encoding
(`pqxdh_extracted_eq`), and the key-indistinguishability bound holds on it
(`pqxdh_extracted_advantage_le`). The instance gives `valid_pub` by its
specification, the subgroup check `subgroupCheckU` of the decoded key
(`KeyAgreement/Curve25519DHGroup.lean`) with the encoding of the identity
excluded.

## Running the tests

```bash
cargo test

# Bounded model checking (requires `cargo kani`).
cargo kani
```

## What the tests claim

| File                            | Claim |
| ------------------------------- | ----- |
| `tests/reference_crosscheck.rs` | An ML-KEM-768 instance `PqxdhCrypto<1184, 2400, 1088>` over `ml-kem`, `x25519-dalek` and HKDF-SHA256, with the input check `subgroup::valid_pub`: KEM correctness over several seeds; the KEM adapter agrees byte for byte with the raw `ml-kem` API in both directions; determinism; FIPS 203 sizes; the crate's `create_bundle` / `initiate` / `respond` give both sides the same session key with and without the one-time prekey; a different KEM keypair gives a different session key; `initiate` and `respond` reject the identity, a point of order 4, a twist point and a non-canonical string in every checked position. |
| `tests/toy_model.rs`            | Protocol tests of `create_bundle` / `initiate` / `respond` over `KaniSimplifiedPqxdh`, a toy model with DH in Z/65537*, an XOR-based KEM and arithmetic stand-ins for signature and KDF; rejection of keys outside the toy group and of its identity `1`. |
| `src/subgroup.rs`               | Unit tests of the subgroup predicate and of `valid_pub`: the base point is accepted, the identity is a subgroup point and fails `valid_pub`, points of order 4, twist points and non-canonical strings are rejected. The predicate is compared with curve25519-dalek in `x3dh-hax/tests/subgroup_check.rs`. |
| `tests/cross_lib.rs`            | The PQXDH formula computed directly with x25519-dalek, ML-KEM-768 and HKDF-SHA256 (not through the crate's functions): agreement on fixed DH keys, the KEM contribution changes the key; the RFC 7748 §6.1 X25519 test vector and the RFC 5869 HKDF-SHA256 test cases 1 and 3. |
| `tests/proptest_equiv.rs`       | Over random DH keys and fresh ML-KEM-768 keypairs, computed directly with the primitives: X25519 commutativity; all 4 DH legs agree; 3DH and 4DH session-key agreement; the KEM contribution changes the key; KEM round trip. 256 cases per property. |
| `src/kani.rs`                   | 8 Kani harnesses on a toy model: panic-freedom of two helpers, three XOR identities, KEM round trip for all inputs, protocol agreement and signature round trip for key values below 256. |

## Scope and deviations from the PQXDH specification

- Signatures are treated as a black box by the trait. The ML-KEM-768 instance
  of `reference_crosscheck.rs` uses a key-independent stand-in for which
  sign-then-verify holds; no test checks an XEdDSA signature.
- The signed message of the prekey `PQPK` is `kem_pk_encode(PQPK)`. The
  ML-KEM-768 instance of the tests returns SHA-256(PQPK), whereas the PQXDH
  specification signs EncodeKEM(PQPK) itself.
- Without a one-time prekey, `initiate` and `respond` pass the zero block
  `ZERO_DH_KEY` as DH4 to the trait's `kdf`, and the HKDF instances of the
  tests feed it to the KDF input, so the KDF input is
  `F || DH1 || DH2 || DH3 || 0^32 || SS`. The specification omits DH4 in that
  case (`F || DH1 || DH2 || DH3 || SS`). The security model of the CatCrypt
  proofs always uses the one-time prekey and is not affected.
- `valid_pub` rejects, in every received Diffie-Hellman public key, the
  points outside the prime-order subgroup and the identity `0`. The
  specification states no such check (to our reading of the 2023 text). The
  security model needs the exclusion of the identity: on it every
  Diffie-Hellman value is the identity, so two responder sessions of one
  party with one peer that receive the identity as ephemeral key, and whose
  KEM shared secrets the adversary makes equal, hash equal KDF inputs.
- `initiate` returns the validity of the two prekey signatures as the third
  and fourth components of its result and computes the session key in either
  case. The specification requires the initiator to abort on an invalid
  signature; the caller must check the returned values.
- `opk_id` of the initial message is the constant `[0, 0, 0, 1]` when a
  one-time prekey is used and `[0, 0, 0, 0]` otherwise; it does not identify
  the prekey.
- The KDF of the tests uses the info string `"WhisperText"`.

## Departures from libsignal

The interop tests named below live in a private interop crate that runs this crate against
libsignal v0.105.2. Each test that shows a departure is ignored by default and fails when run.

- Zero DH4 block. Without a one-time prekey libsignal omits DH4 from the KDF input (libsignal
  v0.105.2, rust/protocol/src/pqxdh.rs:220-224, :360-366). The crate passes the block
  `ZERO_DH_KEY` (`src/protocol.rs:161`, `:216`), so the two KDF inputs differ by 32 bytes.
  Tests: `no_opk_with_zero_dh4_omitted`, `no_opk_with_zero_dh4_block`.
- Signed Kyber prekey. libsignal signs the 1569-byte serialized key (libsignal v0.105.2,
  rust/protocol/src/session.rs:225-230). The crate signs a 32-byte encoding of the key
  (`src/protocol.rs:59`, `:151`). Test: `kyber_prekey_signature_verifies`.

## Test vectors

The tests use the X25519 test vector of RFC 7748 (Langley, Hamburg, Turner),
Section 6.1, and the HKDF-SHA256 test cases 1 and 3 of RFC 5869 (Krawczyk,
Eronen), Appendix A.

## License

MIT. See [`LICENSE`](./LICENSE).
