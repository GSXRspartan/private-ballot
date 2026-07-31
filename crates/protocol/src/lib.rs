#![forbid(unsafe_code)]

//! Versioned protocol constants and deterministic validation errors.

use core::fmt;

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
