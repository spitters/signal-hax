# doubleratchet-hax

Hax-extractable Rust implementation of Signal's **Double Ratchet** protocol
logic over a dependency trait. The ratchet state, the chain-key step, the root
step on a new DH output, the message-key derivation and the header handling are
Rust; the primitives (HMAC-SHA-256, HKDF-SHA-256, X25519 and the message
encryption) are calls to the `DoubleRatchetDeps` trait. The crate implements no
primitive. The library is `no_std`.

The session state machine of `src/typestate_fsm.rs` is generic in the
`DoubleRatchetOps` trait (`kdf_ck`, `kdf_rk`, `dh`); `Ops<D>` is that trait at
the crate's KDF chain, root step and DH over a dependency `D`.

## Spec reference

Signal — *The Double Ratchet Algorithm*, 2016.
<https://signal.org/docs/specifications/doubleratchet/>

Underlying primitives:
- **HMAC** — RFC 2104
- **HKDF** — RFC 5869
- **X25519** — RFC 7748

## Lean extraction

The Lean model used by the CatCrypt proofs is extracted with
`cargo hax json --use-ids` followed by the `haxpipeT` translator of hax-lean.
The fields of the class `DoubleratchetDeps` of the extraction are the
primitives of the `DoubleRatchetDeps` trait (`hmac_sha256`, `hkdf_extract`,
`hkdf_expand`, `x25519`, `aead_encrypt`, `aead_decrypt`) and the ghost hooks.
The correspondence of this extraction to the secure-messaging model of
CatCrypt-core (`CatCryptCore/Crypto/Messaging/DoubleRatchet.lean`) is not yet
published.

## Running the tests

```bash
cargo test
```

## What the tests claim

The tests run the crate over the reference dependency `RefDeps` of
`tests/common` (RustCrypto HMAC-SHA-256 and HKDF-SHA-256, a byte-wise XOR in
place of X25519, the XOR keystream under the message key as encryption).

| File                            | Claim |
| ------------------------------- | ----- |
| `tests/reference_crosscheck.rs` | The KDF chain, the chain advance, the root step and the encryption keystream agree byte for byte with an independent recomputation on the `hmac` crate. |
| `tests/proptest_equiv.rs`       | `kdf_ck` agrees with `hmac::Hmac<Sha256>` on random chain keys and constants; KDF chain / root-key domain separation; encrypt/decrypt round trip. |
| `tests/protocol_logic.rs`       | Protocol-level properties of the ratchet state (counters, headers, chain independence). |

The reference dependency's X25519 is a stub (`a XOR b`) and its encryption
ignores the associated data, so no test checks the DH ratchet against X25519,
the authentication of the associated data, or two-party convergence.

## Scope and deviations from the Signal specification

- `kdf_ck` is HMAC-SHA-256 over the 32-byte block `[c; 32]`, with `c = 0x01`
  for the next chain key and `c = 0x02` for the message key. The
  specification and libsignal use the single bytes `0x01` for the message key
  and `0x02` for the chain key.
- `kdf_rk` is one HKDF-Extract followed by two 32-byte HKDF-Expand calls with
  the info blocks `[1; 32]` (root key) and `[2; 32]` (chain key). The
  specification derives 64 bytes in one HKDF call with an
  application-specific info string.
- The associated data of the message encryption is the sender's DH public key
  only. The header fields `msg_number` and `prev_chain_len` are not
  authenticated, and the associated data of the initial key agreement is not
  included.
- Before the first DH ratchet step the chain keys without a value in the
  specification are set to the root key: the receiving chain key of the
  initiator (`ratchet_init_initiator`, `Uninitialized::establish`), and both
  chain keys of the responder (`ratchet_init_responder`).
- The crate keeps no skipped message keys and has no header encryption.
  `ratchet_decrypt` does not perform a DH ratchet step on a new remote key and
  does not check that `header.dh_public` equals the stored remote key;
  `dh_ratchet_step` takes the new DH key pair from the caller.

## License

MIT. See [`LICENSE`](./LICENSE).
