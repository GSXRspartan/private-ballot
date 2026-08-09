# Phase 5 Slice 5A12B transport foundation review

This slice adds an in-process cryptographic transport boundary only. It does
not change `BallotPackageV1`, `ElectionManifestV1`, Triptych, nullifiers, or
the 5A11 `intake_ballot_package_bytes` rule. No live Tor/onion/OHTTP/relay,
socket listener, walletd/indexer/Ootle call, voter wallet, or tTARI exists.
Receiver-secret ownership, HPKE opening, authenticated unpadding, retry
retention, and the local gateway simulator are isolated in the
`transport-gateway` crate; `gui-core` retains public descriptor/envelope
handling and the pre-existing 5A11 intake boundary.

## Dependency evidence

Cargo locked `ed25519-dalek 3.0.0` (BSD-3-Clause) and `hpke 0.14.0`
(MIT/Apache-2.0). HPKE locks `x25519-dalek 3.0.0`, `chacha20poly1305 0.11.0`,
`hkdf 0.13.0`, and `sha2 0.11.0`. `hpke` declares Rust 1.85 MSRV, below the
pinned 1.97.1. Its upstream README documents RFC-vector/KAT coverage; this
slice adds binding, mutation, strict-CBOR, exact-byte, and counter checks.
No security scanner was already installed, so none was added.

## Opus status

| Finding | Status | Slice result |
| --- | --- | --- |
| F1 root | PARTIALLY RESOLVED | Release-pinned root abstraction; production key unprovisioned, online disabled. |
| F2 threshold | RESOLVED (local) | Only accepted unique ballots satisfy the counter gate. |
| F3 close transit | PARTIALLY RESOLVED | Separate coarse cutoff/drain policy specified; no core lifecycle change. |
| F4 equivocation | RESOLVED (local) | Same election/generation conflict fails loudly. |
| F5 retry | PARTIALLY RESOLVED | Commitment-only in-memory mapping; production retention needs configuration. |
| F6 | DEFERRED | No live carrier. |
| F7 clock | PARTIALLY RESOLVED | Coarse cutoff design only; trusted authority undecided. |
| F8 anchoring | DEFERRED | Policy frozen, no Ootle transaction. |
| F9 | DEFERRED | Operational logging review. |
| F10 padding | PARTIALLY RESOLVED | Fixed bounded policy implemented; package-size measurement remains required. |
| F11 | DEFERRED | Relay/Tor operations. |
| F12 DTO | RESOLVED | Voter receipt is a distinct reduced DTO. |

Verdict is conditional on offline validation and independent review.
