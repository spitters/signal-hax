# signal-hax

Rust implementations of three Signal protocols, written in the subset of Rust that the
[hax](https://github.com/cryspen/hax) toolchain extracts, with every cryptographic primitive
behind a trait:

| Crate | Protocol | Primitive trait |
|---|---|---|
| `x3dh-hax` | X3DH key agreement | `X3dhCrypto`: Diffie–Hellman, public key, KDF, signature |
| `pqxdh-hax` | PQXDH key agreement | `PqxdhCrypto`: the X3DH operations, a KEM, `kem_pk_encode` |
| `doubleratchet-hax` | Double Ratchet | `DoubleRatchetDeps`: HMAC-SHA256, HKDF, X25519, AEAD |

Each crate's README lists what its tests check and where the code departs from the Signal
specification.

## What is proved, and where

The Lean extractions of the crates and the security proofs are in
[CatCrypt-core](https://github.com/spitters/CatCrypt-core):

| Crate | Statement | Lean |
|---|---|---|
| `x3dh-hax` | The extracted handshake (`create_bundle`, `initiate`) is the passive single-session X3DH model mapped by the encoding of keys as byte arrays; its key-indistinguishability advantage is at most four DDH advantages and one KDF advantage of explicit, time-certified reductions. | [`x3dh_extracted_eq`, `x3dh_extracted_advantage_le`](https://github.com/spitters/CatCrypt-core/blob/main/CatCryptCore/Crypto/AKE/X3DH/ExtractedCorrespondence.lean); at the libcrux primitives: [`x3dh_extracted_e2e_secure`](https://github.com/spitters/CatCrypt-core/blob/main/CatCryptCore/Crypto/AKE/X3DH/SurfaceDeps.lean) |
| `pqxdh-hax` | The same for PQXDH: one KEM real-or-random reduction, four DDH reductions and one KDF reduction; the responder derives the initiator's key when the KEM is correct. | [`pqxdh_extracted_eq`, `pqxdh_extracted_advantage_le`, `respond_agree`](https://github.com/spitters/CatCrypt-core/blob/main/CatCryptCore/Crypto/AKE/PQXDH/ExtractedCorrespondence.lean); at the libcrux primitives: [`pqxdh_extracted_e2e_secure`](https://github.com/spitters/CatCrypt-core/blob/main/CatCryptCore/Crypto/AKE/PQXDH/SurfaceDeps.lean) |
| `doubleratchet-hax` | The secure-messaging bound of the Double Ratchet is proved for the model in [`Messaging/DoubleRatchet.lean`](https://github.com/spitters/CatCrypt-core/blob/main/CatCryptCore/Crypto/Messaging/DoubleRatchet.lean); the correspondence of this crate's extraction to that model is not yet published. | — |

The libcrux primitives are opaque constants in the Lean development: no proof unfolds them,
so the statements at the libcrux instance hold for any implementation with those signatures.
The X3DH and PQXDH statements at that instance assume that X25519 commutes on public keys
(`X25519Commutes`).

## Regenerating the extraction

`scripts/extract.sh <crate>` runs `cargo hax json --use-ids` in the crate and translates the
export with `haxpipeT` from [hax-lean](https://github.com/spitters/hax-lean). The toolchain
is pinned in `rust-toolchain.toml` (hax 0.4.2 needs nightly-2025-11-08); `haxpipeT` is built
with `lake build haxpipeT` in hax-lean at the revision named in the script.

## Tests

`cargo test --workspace`. The tests compare the protocol functions against reference
computations with RustCrypto and dalek primitives and against the RFC 7748 and RFC 5869 test
vectors; the Double Ratchet tests use a reference instance of the trait.

## Licence

MIT, see `LICENSE`.
