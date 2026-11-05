# x3dh-hax

Hax-extractable Rust implementation of Signal's **X3DH** (Extended Triple
Diffie-Hellman) key-agreement protocol, with cross-library and property-based
tests against `x25519-dalek` and `hkdf` + `sha2`.

The crate is structured as a trait (`X3dhCrypto`) over abstract DH, KDF, and
signature operations, so the protocol logic in [`src/protocol.rs`](./src/protocol.rs)
is parametric and extractable. The library is `no_std`. The Kani harnesses of
[`src/kani.rs`](./src/kani.rs) and the tests of
[`tests/toy_model.rs`](./tests/toy_model.rs) each instantiate the trait with a
toy model over Z/65537*; the property tests back the trait with x25519-dalek
and HKDF-SHA256 to check byte-level agreement with the Signal X3DH formula.

## Spec reference

Signal — *The X3DH Key Agreement Protocol*, November 2016 (revised 2024).
<https://signal.org/docs/specifications/x3dh/>

Underlying primitives:
- **X25519** — RFC 7748
- **HKDF-SHA256** — RFC 5869
- **XEdDSA** (signatures) — <https://signal.org/docs/specifications/xeddsa/>

## Lean extraction

The Lean model used by the CatCrypt proofs is extracted with
`cargo hax json --use-ids` followed by the `haxpipeT` translator of hax-lean.
The operations of `X3dhCrypto` become the fields of the class `X3dhDeps` of
the extraction, over which the extracted protocol functions are stated. The
extraction and its correspondence to the passive X3DH model are in CatCrypt-core
(`CatCryptCore/Crypto/AKE/X3DH/`): the extracted handshake game equals the
model's real game mapped by the encoding (`x3dh_extracted_eq`), and the
key-indistinguishability bound holds on it (`x3dh_extracted_advantage_le`).

## Running the tests

```bash
cargo test

# Bounded model checking (requires `cargo kani`).
cargo kani
```

## What the tests claim

| File                       | Claim |
| -------------------------- | ----- |
| `tests/toy_model.rs`       | Protocol tests of `create_bundle` / `initiate` / `respond` over `KaniSimplifiedX3dh`, a toy model with DH in Z/65537* and arithmetic stand-ins for signature and KDF. |
| `tests/cross_lib.rs`       | The X3DH session-key formula computed directly with x25519-dalek and HKDF-SHA256 (not through the crate's functions): agreement of both sides on fixed keys with and without the one-time prekey, sensitivity to the inputs and to the 0xFF padding, sizes of the crate's key types; the RFC 7748 §6.1 X25519 test vector and the RFC 5869 HKDF-SHA256 test cases 1-3. |
| `tests/proptest_equiv.rs`  | `RealX3dh` (trait instance backed by x25519-dalek and hkdf) run through `initiate` / `respond` produces byte-identical session keys to a direct dalek+hkdf computation, over 256 random inputs per property. |
| `src/kani.rs`              | 6 Kani harnesses: XOR panic-freedom, two XOR identities, 3DH and 4DH agreement and a signature round trip on a toy model over Z/65537*. |

## Scope and deviations from the X3DH specification

- Signatures are treated as a black box by the trait. The proptest suite
  stubs `sign`/`verify` and isolates the DH/KDF equivalence; no test checks
  an XEdDSA signature.
- Without a one-time prekey, `initiate` and `respond` pass a zero block as
  DH4 to the trait's `kdf`, and the HKDF instance of the tests feeds it to the
  KDF input. The X3DH specification omits DH4 in that case.
- `initiate` returns the validity of the signed-prekey signature as the third
  component of its result and computes the session key in either case. The
  specification requires the initiator to abort on an invalid signature; the
  caller must check the returned value.
- `opk_id` of the initial message is the constant `[0, 0, 0, 1]` when a
  one-time prekey is used and `[0, 0, 0, 0]` otherwise; it does not identify
  the prekey.
- The KDF of the tests uses the info string `"WhisperText"`.
- The toy model of `toy_model.rs` and `kani.rs` keeps the Kani state space
  tractable. It is not a cryptographic implementation.

## Test vectors

The tests use the X25519 test vector of RFC 7748 (Langley, Hamburg, Turner),
Section 6.1, and the HKDF-SHA256 test cases 1-3 of RFC 5869 (Krawczyk,
Eronen), Appendix A.

## License

MIT. See [`LICENSE`](./LICENSE).
