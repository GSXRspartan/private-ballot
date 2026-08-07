//! Structured ballot-intake result.
//!
//! Produced only by
//! [`GuiElectionSessionV1::intake_ballot`](crate::GuiElectionSessionV1::intake_ballot),
//! which delegates all validation to the existing ingestion pipeline.

use tari_cc_private_ballot_protocol::ValidationCode;

/// Coarse intake category for frontend treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum GuiIntakeCategory {
    /// The ballot passed every check and entered the accepted set.
    Accepted,
    /// The first valid ballot for this nullifier already counts.
    Duplicate,
    /// The ballot belongs to a different election (manifest, registry
    /// commitment, or candidate set).
    WrongElection,
    /// The proof is malformed.
    MalformedProof,
    /// The proof suite is not permitted by the production policy.
    UnsupportedSuite,
    /// Any other deterministic validation rejection.
    Invalid,
}

impl GuiIntakeCategory {
    /// Returns the stable machine-readable category code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::Duplicate => "DUPLICATE",
            Self::WrongElection => "WRONG_ELECTION",
            Self::MalformedProof => "MALFORMED_PROOF",
            Self::UnsupportedSuite => "UNSUPPORTED_SUITE",
            Self::Invalid => "INVALID",
        }
    }

    /// Maps an existing protocol validation code onto an intake category.
    #[must_use]
    pub const fn from_validation(code: ValidationCode) -> Self {
        match code {
            ValidationCode::DuplicateNullifier => Self::Duplicate,
            ValidationCode::WrongManifestHash
            | ValidationCode::LifecycleCommitmentMismatch
            | ValidationCode::CandidateSetCommitmentMismatch => Self::WrongElection,
            ValidationCode::MalformedProof => Self::MalformedProof,
            ValidationCode::UnsupportedProofSuite => Self::UnsupportedSuite,
            _ => Self::Invalid,
        }
    }
}

/// The deterministic outcome of ingesting one canonical ballot package.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiBallotIntakeResultV1 {
    /// Whether the ballot entered the accepted set.
    pub accepted: bool,
    /// Stable machine code: `ACCEPTED` or the existing validation code.
    pub code: &'static str,
    /// Coarse category for frontend treatment.
    pub category: GuiIntakeCategory,
    /// Domain-separated digest of the exact canonical package bytes.
    pub package_digest_hex: String,
    /// The contiguous ingest sequence assigned to this submission.
    pub sequence: u64,
    /// The proof-authenticated election-scoped nullifier (lowercase hex).
    ///
    /// Present only after successful proof verification: for an accepted
    /// ballot, and for a duplicate rejection (where the nullifier is already
    /// public through the first accepted ballot). Never present for a ballot
    /// whose proof did not verify.
    pub nullifier_hex: Option<String>,
    /// For a duplicate rejection, the ingest sequence of the first accepted
    /// ballot carrying the same nullifier, when it can be resolved.
    pub duplicate_of_sequence: Option<u64>,
}
