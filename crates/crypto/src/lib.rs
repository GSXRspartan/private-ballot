#![forbid(unsafe_code)]

//! Cryptography-agnostic anonymous-membership boundary.
//!
//! Only sealed proof-suite implementations can manufacture successful
//! verification results or authenticated duplicate-detection material.

mod ristretto;
pub mod test_only_verifier;
mod triptych_adapter;
mod verification;

pub use ristretto::{RISTRETTO_COMPRESSED_POINT_BYTES, RistrettoPublicKeyV1};
pub use triptych_adapter::{
    TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES, TARI_TRIPTYCH_PROOF_ENVELOPE_VERSION_V1,
    TariTriptychProofEnvelopeV1,
};
pub use verification::{ProofVerifierV1, VerifiedNullifier, VerifiedProofV1};
