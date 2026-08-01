# Phase 3 Ristretto255 substrate

**Date:** 2026-08-01

## Status

Experimental cryptographic substrate only.

This slice does not select or implement a production anonymous-membership
construction.

## Dependency decision

The crypto crate pins:

`curve25519-dalek = 5.0.0`

with default features disabled and only the `zeroize` feature enabled.

The pinned release:

- supports Rust 1.85 and therefore the workspace Rust 1.97 baseline;
- provides the prime-order Ristretto group;
- exposes canonical compressed-point decoding;
- provides constant-time group operations except where APIs are explicitly
  marked variable-time.

## Implemented boundary

`RistrettoPublicKeyV1` accepts exactly 32 bytes and requires:

1. successful `CompressedRistretto` decompression;
2. a non-identity point;
3. byte-for-byte recompression agreement.

The type stores only public compressed bytes.

## Explicitly not implemented

This slice adds no:

- private-key generation or import;
- signer or prover;
- proof verifier;
- ring-signature algorithm;
- hash-to-point function;
- Fiat-Shamir transcript;
- election-scoped key image or nullifier;
- production proof-suite identifier;
- ballot-package format change;
- registry format change;
- claim of anonymity or production security.

The Python LSAG proof of concept remains reference material only and is not
copied.

## Construction status

ADR-0005 still governs construction selection.

The project must not invent an election-scoped key-image formula by modifying
ordinary LSAG without a security argument applicable to the exact scoped
construction.

The event-oriented linkable-ring-signature literature is a research lead, not
yet an implementation selection. A later slice must record the exact named
construction and publication before prover or verifier code begins.

## Upstream references

- curve25519-dalek 5.0.0:
  https://docs.rs/curve25519-dalek/5.0.0/curve25519_dalek/
- canonical compressed Ristretto decoding:
  https://docs.rs/curve25519-dalek/5.0.0/curve25519_dalek/ristretto/struct.CompressedRistretto.html
- event-oriented linkability research lead:
  https://link.springer.com/chapter/10.1007/978-3-540-30556-9_30
