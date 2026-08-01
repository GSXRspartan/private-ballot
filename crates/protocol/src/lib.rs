#![forbid(unsafe_code)]

//! Versioned protocol constants and deterministic validation errors.

use core::fmt;

mod cbor;
mod commitment;
mod hashing;
mod limits;
mod scope;
pub use cbor::{CanonicalCborReader, CanonicalCborWriter};
pub use commitment::{
    BallotPayloadHash, CandidateSetCommitment, ElectionScope, ManifestHash, RegistryCommitment,
};
#[cfg(any(test, debug_assertions))]
pub use hashing::test_only;
pub use hashing::{
    HASH_FRAME_PREFIX, HashDomain, HashProvider, domain_separated_input, hash_domain_separated,
};
pub use limits::{
    MAX_BALLOT_CONFIDENTIALITY_ID_BYTES, MAX_BALLOT_KIND_ID_BYTES,
    MAX_CANDIDATE_DISPLAY_NAME_BYTES, MAX_CANDIDATE_ID_BYTES, MAX_CANDIDATES,
    MAX_CANONICAL_OBJECT_BYTES, MAX_ELECTION_ID_BYTES, MAX_GOVERNANCE_KEY_BYTES,
    MAX_GOVERNANCE_REVISION_BYTES, MAX_NULLIFIER_BYTES, MAX_PROOF_BYTES, MAX_PROOF_STATEMENT_BYTES,
    MAX_PROOF_SUITE_ID_BYTES, MAX_REGISTRY_MEMBERS,
};
pub use scope::derive_election_scope;

/// First protocol version implemented by the workspace.
pub const PROTOCOL_VERSION_V1: u16 = 1;

/// Reserved suite identifier for non-anonymous development plumbing.
pub const TEST_ONLY_SUITE_ID: &str = "TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS";

/// Stable protocol validation categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationCode {
    UnsupportedProtocolVersion,
    WrongManifestHash,
    UnsupportedProofSuite,
    MalformedProof,
    EmptyNullifier,
    DuplicateNullifier,
    InvalidData,
    ProtocolLimitExceeded,
    InvalidCbor,
    NonCanonicalCbor,
    UnexpectedCborType,
    TrailingCborData,
    EmptyElectionId,
    EmptyProofSuiteId,
    EmptyGovernanceSourceRevision,
    EmptyRegistry,
    EmptyGovernanceKey,
    DuplicateGovernanceKey,
    EmptyCandidateSet,
    EmptyCandidateId,
    EmptyCandidateDisplayName,
    DuplicateCandidateId,
    InvalidSelectionLimits,
    SelectionCountOutOfRange,
    DuplicateSelection,
    UnknownCandidateId,
    InvalidLifecycleTransition,
    ElectionNotOpen,
    LifecycleCommitmentMismatch,
}

impl ValidationCode {
    /// Returns the stable machine-readable rejection code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedProtocolVersion => "UNSUPPORTED_PROTOCOL_VERSION",
            Self::WrongManifestHash => "WRONG_MANIFEST_HASH",
            Self::UnsupportedProofSuite => "UNSUPPORTED_PROOF_SUITE",
            Self::MalformedProof => "MALFORMED_PROOF",
            Self::EmptyNullifier => "EMPTY_NULLIFIER",
            Self::DuplicateNullifier => "DUPLICATE_NULLIFIER",
            Self::InvalidData => "INVALID_DATA",
            Self::ProtocolLimitExceeded => "PROTOCOL_LIMIT_EXCEEDED",
            Self::InvalidCbor => "INVALID_CBOR",
            Self::NonCanonicalCbor => "NON_CANONICAL_CBOR",
            Self::UnexpectedCborType => "UNEXPECTED_CBOR_TYPE",
            Self::TrailingCborData => "TRAILING_CBOR_DATA",
            Self::EmptyElectionId => "EMPTY_ELECTION_ID",
            Self::EmptyProofSuiteId => "EMPTY_PROOF_SUITE_ID",
            Self::EmptyGovernanceSourceRevision => "EMPTY_GOVERNANCE_SOURCE_REVISION",
            Self::EmptyRegistry => "EMPTY_REGISTRY",
            Self::EmptyGovernanceKey => "EMPTY_GOVERNANCE_KEY",
            Self::DuplicateGovernanceKey => "DUPLICATE_GOVERNANCE_KEY",
            Self::EmptyCandidateSet => "EMPTY_CANDIDATE_SET",
            Self::EmptyCandidateId => "EMPTY_CANDIDATE_ID",
            Self::EmptyCandidateDisplayName => "EMPTY_CANDIDATE_DISPLAY_NAME",
            Self::DuplicateCandidateId => "DUPLICATE_CANDIDATE_ID",
            Self::InvalidSelectionLimits => "INVALID_SELECTION_LIMITS",
            Self::SelectionCountOutOfRange => "SELECTION_COUNT_OUT_OF_RANGE",
            Self::DuplicateSelection => "DUPLICATE_SELECTION",
            Self::UnknownCandidateId => "UNKNOWN_CANDIDATE_ID",
            Self::InvalidLifecycleTransition => "INVALID_LIFECYCLE_TRANSITION",
            Self::ElectionNotOpen => "ELECTION_NOT_OPEN",
            Self::LifecycleCommitmentMismatch => "LIFECYCLE_COMMITMENT_MISMATCH",
        }
    }
}

/// Deterministic protocol validation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolError {
    code: ValidationCode,
    message: &'static str,
}

impl ProtocolError {
    /// Creates a validation failure.
    #[must_use]
    pub const fn new(code: ValidationCode, message: &'static str) -> Self {
        Self { code, message }
    }

    /// Returns the stable validation category.
    #[must_use]
    pub const fn code(&self) -> ValidationCode {
        self.code
    }

    /// Returns the non-sensitive explanation.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code.as_str(), self.message)
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::{ProtocolError, ValidationCode};

    #[test]
    fn validation_codes_are_stable() {
        let cases = [
            (ValidationCode::MalformedProof, "MALFORMED_PROOF"),
            (ValidationCode::EmptyNullifier, "EMPTY_NULLIFIER"),
            (ValidationCode::DuplicateNullifier, "DUPLICATE_NULLIFIER"),
            (
                ValidationCode::ProtocolLimitExceeded,
                "PROTOCOL_LIMIT_EXCEEDED",
            ),
            (ValidationCode::InvalidCbor, "INVALID_CBOR"),
            (ValidationCode::NonCanonicalCbor, "NON_CANONICAL_CBOR"),
            (ValidationCode::UnexpectedCborType, "UNEXPECTED_CBOR_TYPE"),
            (ValidationCode::TrailingCborData, "TRAILING_CBOR_DATA"),
            (ValidationCode::EmptyElectionId, "EMPTY_ELECTION_ID"),
            (ValidationCode::EmptyProofSuiteId, "EMPTY_PROOF_SUITE_ID"),
            (
                ValidationCode::EmptyGovernanceSourceRevision,
                "EMPTY_GOVERNANCE_SOURCE_REVISION",
            ),
            (ValidationCode::EmptyRegistry, "EMPTY_REGISTRY"),
            (
                ValidationCode::DuplicateGovernanceKey,
                "DUPLICATE_GOVERNANCE_KEY",
            ),
            (
                ValidationCode::DuplicateCandidateId,
                "DUPLICATE_CANDIDATE_ID",
            ),
            (ValidationCode::UnknownCandidateId, "UNKNOWN_CANDIDATE_ID"),
            (
                ValidationCode::InvalidLifecycleTransition,
                "INVALID_LIFECYCLE_TRANSITION",
            ),
            (ValidationCode::ElectionNotOpen, "ELECTION_NOT_OPEN"),
            (
                ValidationCode::LifecycleCommitmentMismatch,
                "LIFECYCLE_COMMITMENT_MISMATCH",
            ),
        ];

        for (code, expected) in cases {
            assert_eq!(code.as_str(), expected);
        }
    }

    #[test]
    fn protocol_error_preserves_code_and_message() {
        let error = ProtocolError::new(ValidationCode::MalformedProof, "test message");

        assert_eq!(error.code(), ValidationCode::MalformedProof);
        assert_eq!(error.message(), "test message");
    }
}

mod proof_statement;
pub use proof_statement::{PROOF_STATEMENT_VERSION_V1, ProofStatementV1, ProofStatementV1Input};
