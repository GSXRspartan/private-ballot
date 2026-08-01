#![forbid(unsafe_code)]

//! Cryptography-agnostic anonymous-membership boundary.
//!
//! Only sealed proof-suite implementations can manufacture successful
//! verification results or authenticated duplicate-detection material.

pub mod test_only_verifier;
mod verification;

pub use verification::{ProofVerifierV1, VerifiedNullifier, VerifiedProofV1};
