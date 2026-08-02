# Triptych

An experimental Rust implementation of the Triptych zero-knowledge proving system.

## Overview

[Triptych](https://eprint.iacr.org/2020/018) is a zero-knowledge proving system designed to function as a linkable ring signature.
This is a construction that allows a signer to sign a message against a set of arbitrary verification keys.
Successful verification of a signature means that the signer knew the signing key corresponding to one of the verification keys, but does not reveal which.
It also produces a linking tag; if any two verified signatures have the same linking tag, they were produced using the same signing key.
However, it is not possible to determine the signing key associated to a linking tag, nor the corresponding verification key.

Triptych proofs scale nicely, with their size increasingly only logarithmically with the size of the verification key set. Proofs sharing the same verification key set can also be verified efficiently in batches to save time.

More formally, let `G` and `U` be fixed independent generators of the Ristretto group.
Let `N = n**m`, where `n, m > 1` are fixed parameters.
The Triptych proving system protocol is a sigma protocol for the following relation, where `M` is an `N`-vector of group elements:

`{ M, J ; (l, r) : M[l] = r*G, r*J = U }`

It's possible to use the Fiat-Shamir transformation to produce a non-interactive protocol that can additionally bind an arbitrary message into the transcript.
This produces the linkable ring signature.

This library also supports parallel proving functionality.

## Implementation notes

This implementation makes several opinionated choices:
- It uses [Ristretto](https://ristretto.group/) for group operations.
- It uses [Merlin](https://merlin.cool/) for Fiat-Shamir transcript operations.
- It uses [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) for other cryptographic hashing operations.

The implementation keeps dependencies to a minimum, and is `no_std` friendly.

There are several features available.

| Feature | Default? | Description |
| :--- | :---: | :--- |
| `borsh` | | Adds proof serialization and deserialization via [`borsh`](https://crates.io/crates/borsh) |
| `hazmat` | | Adds variable-time prover functionality that should only be used if you absolutely know what you're doing |
| `rand` | ✓ | Adds additional prover functionality that supplies a cryptographically-secure random number generator |
| `serde` | | Adds proof serialization and deserialization via [`serde`](https://crates.io/crates/serde) |
| `std` | ✓ | Adds corresponding dependency features |

The underlying [curve library](https://crates.io/crates/curve25519-dalek) chooses an arithmetic backend based on CPU feature detection.
Using a nightly compiler broadens the backend set, and may provide better performance.
You can examine performance using the benchmarks: either `cargo bench --all-features` or `cargo +nightly bench --all-features`.

Proofs support a custom serialization format designed to be efficient and canonical.
This is used for `borsh` serialization and deserialization, or can be accessed directly.
This functionality has an associated fuzzer that can be run using a nightly compiler: `cargo +nightly fuzz run proofs`.

## Warning

While this implementation is written with security in mind, it is currently **experimental** and not suitable for production use.
