// Copyright (c) 2024, The Tari Project
// SPDX-License-Identifier: BSD-3-Clause

//! # Overview
//!
//! It's possible to extend Triptych proving functionality to the case where each element of an input set if composed of
//! two keys, a verification key and an auxiliary verification key. This enables additional functionality.
//!
//! More formally, let `G`, `G1`, and `U` be fixed independent generators of the Ristretto group.
//! Let `N = n**m`, where `n, m > 1` are fixed parameters.
//! The parallel Triptych proving system protocol is a sigma protocol for the following relation, where `M` and `M1` are
//! both `N`-vectors of group elements:
//!
//! `{ M, M1, offset, J ; (l, r, r1) : M[l] = r*G, M1[l] - offset = r1*G1, r*J = U }`
//!
//! # Example
//!
//! Here's a complete example of how to generate and verify a parallel Triptych proof; see the documentation for
//! additional functionality.
//!
//! ```
//! # #[cfg(feature = "rand")]
//! # {
//! use curve25519_dalek::{RistrettoPoint, Scalar};
//! use rand_core::OsRng;
//! use triptych::{parallel::*, Transcript};
//!
//! let mut rng = OsRng;
//!
//! // Generate parameters
//! const n: u32 = 2;
//! const m: u32 = 3;
//! let params = TriptychParameters::new(n, m).unwrap();
//!
//! // Generate a random witness, which includes the signing key, auxiliary key, and an index where they will appear
//! let witness = TriptychWitness::random(&params, &mut rng);
//!
//! // Select a random offset
//! let offset = Scalar::random(&mut rng) * params.get_G1();
//!
//! // Generate an input set of random verification keys, placing ours at the chosen index
//! let M = (0..params.get_N())
//!     .map(|i| {
//!         if i == witness.get_l() {
//!             witness.compute_verification_key()
//!         } else {
//!             RistrettoPoint::random(&mut rng)
//!         }
//!     })
//!     .collect::<Vec<RistrettoPoint>>();
//! let M1 = (0..params.get_N())
//!     .map(|i| {
//!         if i == witness.get_l() {
//!             // This ensures that `M1[l] - offset = r1 * G1` to satisfy the proving relation
//!             witness.compute_auxiliary_verification_key() + offset
//!         } else {
//!             RistrettoPoint::random(&mut rng)
//!         }
//!     })
//!     .collect::<Vec<RistrettoPoint>>();
//! let input_set = TriptychInputSet::new(&M, &M1).unwrap();
//!
//! // Generate the statement, which includes the verification key vectors and linking tag
//! let J = witness.compute_linking_tag();
//! let statement = TriptychStatement::new(&params, &input_set, &offset, &J).unwrap();
//!
//! // Generate a transcript
//! let mut transcript = Transcript::new(b"Test transcript");
//!
//! // Generate a proof from the witness
//! let proof = TriptychProof::prove(&witness, &statement, &mut transcript.clone()).unwrap();
//!
//! // The proof should verify against the same statement and transcript
//! assert!(proof.verify(&statement, &mut transcript).is_ok());
//! # }
//! ```

/// Public parameters used for generating and verifying Triptych proofs.
pub mod parameters;
pub use parameters::TriptychParameters;
/// Triptych proofs.
pub mod proof;
pub use proof::TriptychProof;
/// Triptych proof statements.
pub mod statement;
pub use statement::{TriptychInputSet, TriptychStatement};
/// Triptych proof transcripts.
pub mod transcript;
/// Triptych proof witnesses.
pub mod witness;
pub use witness::TriptychWitness;
