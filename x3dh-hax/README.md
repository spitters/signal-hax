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

The trait has two KDF operations, and both take the Diffie-Hellman values
alone, as the specification does. With a one-time prekey `initiate` and
`respond` compute the session key as `kdf(DH1, DH2, DH3, DH4)`; without one,
they compute it as `kdf3(DH1, DH2, DH3)` and compute no DH4
(`SK = KDF(DH1 || DH2 || DH3)`). The padding `F` and the info string are
constants of the instance: the HKDF instance of the property tests feeds
`0xFF*32 || DH1 || DH2 || DH3 [|| DH4]` to HKDF-SHA256 with the info
`"WhisperText"`, as `tests/cross_lib.rs` does.

The trait has an input check `valid_pub` of a peer public key. `initiate`
returns `Option<(X3dhSessionKey, X3dhInitMessage, bool)>`: `None` when a key
of the bundle that the computation uses (`ik`, `spk`, and `opk` when
`use_opk`) fails the check, and otherwise `Some` of the computation
`initiate_checked`. `respond` returns `Option<X3dhSessionKey>`: `None` when
`ik_a` or `ek_a` of the message fails the check, and otherwise `Some` of
`respond_checked`; `BundleReceived::send_init` and `run_signal_handshake`
return `Option` likewise. The module [`src/subgroup.rs`](./src/subgroup.rs)
(not extracted) implements the check for X25519 as `valid_pub`: membership in
the prime-order subgroup of Curve25519 (`is_subgroup_point`) with the identity
excluded. `is_subgroup_point` accepts a string when its number is below
`p = 2^255 - 19` and it is `0` (the identity) or the u-coordinate of a point
`P` of the curve with `[l] P = O`; it rejects twist points, points with a
component of order 2, 4 or 8, and non-canonical strings. `valid_pub` accepts
the strings that `is_subgroup_point` accepts other than `0`.

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
The instance `defaultX3dhDeps` gives `valid_pub` by its specification: the
subgroup check `subgroupCheckU` of the decoded key
(`KeyAgreement/Curve25519DHGroup.lean`), which accepts exactly the encodings of
the points `P` with `l • P = 0`, with the encoding of the identity excluded.
On encoded public keys other than the identity the extracted `initiate` and
`respond` return `Some` of `initiate_checked` and `respond_checked`, and the
key equations are stated for the checked functions. The check of
`subgroup.rs` is compared with curve25519-dalek by `tests/subgroup_check.rs`,
not related to `subgroupCheckU` by a theorem.

## Running the tests

```bash
cargo test

# Bounded model checking (requires `cargo kani`).
cargo kani
```

## What the tests claim

| File                       | Claim |
| -------------------------- | ----- |
| `tests/toy_model.rs`       | Protocol tests of `create_bundle` / `initiate` / `respond` over `KaniSimplifiedX3dh`, a toy model with DH in Z/65537* and arithmetic stand-ins for signature and KDF: agreement, the session key as the KDF of the DH values alone, rejection of keys outside the toy group and of its identity `1`. |
| `tests/cross_lib.rs`       | The X3DH session-key formula computed directly with x25519-dalek and HKDF-SHA256 (not through the crate's functions): agreement of both sides on fixed keys with and without the one-time prekey, sensitivity to the inputs and to the 0xFF padding, sizes of the crate's key types; the RFC 7748 §6.1 X25519 test vector and the RFC 5869 HKDF-SHA256 test cases 1-3. |
| `tests/proptest_equiv.rs`  | `RealX3dh` (trait instance backed by x25519-dalek and hkdf) run through `initiate` / `respond` produces byte-identical session keys to a direct dalek+hkdf computation, over 256 random keys per property; `initiate` and `respond` reject peer keys outside the subgroup and the identity `0`. |
| `tests/subgroup_check.rs`  | The subgroup predicate `subgroup::is_subgroup_point` agrees with curve25519-dalek (`to_edwards`, `is_torsion_free`): it accepts the identity, the multiples of the base point and X25519 public keys, and rejects `s B + T` for `T` of order 2, 4 or 8, the eight torsion points other than `0`, twist points and non-canonical strings; it agrees with the reference predicate on random strings, and `is_on_curve` with the decompression of curve25519-dalek. The input check `subgroup::valid_pub` agrees with the reference predicate with `0` excluded, rejects the identity and accepts X25519 public keys. |
| `src/kani.rs`              | 6 Kani harnesses: XOR panic-freedom, two XOR identities, 3DH and 4DH agreement and a signature round trip on a toy model over Z/65537*. |

## Scope and deviations from the X3DH specification

- Signatures are treated as a black box by the trait. The proptest suite
  stubs `sign`/`verify` and isolates the DH/KDF equivalence; no test checks
  an XEdDSA signature.
- `initiate` returns the validity of the signed-prekey signature as the third
  component of its result and computes the session key in either case. The
  specification requires the initiator to abort on an invalid signature; the
  caller must check the returned value.
- `opk_id` of the initial message is the constant `[0, 0, 0, 1]` when a
  one-time prekey is used and `[0, 0, 0, 0]` otherwise; it does not identify
  the prekey.
- `valid_pub` rejects the identity, the encoding `0`, in every received
  public key. The specification states no such check (to our reading of the
  2016 text). The security model needs it: on the identity every
  Diffie-Hellman value is the identity, so two responder sessions of one
  party with one peer that receive the identity as ephemeral key derive equal
  session keys. With a clamped X25519 scalar, the check excludes the all-zero
  output of RFC 7748 §6.1 for every Diffie-Hellman value computed on a
  received key.
- The toy model of `toy_model.rs` and `kani.rs` keeps the Kani state space
  tractable. It is not a cryptographic implementation.

## Test vectors

The tests use the X25519 test vector of RFC 7748 (Langley, Hamburg, Turner),
Section 6.1, and the HKDF-SHA256 test cases 1-3 of RFC 5869 (Krawczyk,
Eronen), Appendix A.

## License

MIT. See [`LICENSE`](./LICENSE).
