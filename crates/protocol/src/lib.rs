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
    DuplicateNullifier,
    InvalidData,
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
            Self::DuplicateNullifier => "DUPLICATE_NULLIFIER",
            Self::InvalidData => "INVALID_DATA",
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
    fn validation_code_is_stable() {
        let error = ProtocolError::new(ValidationCode::MalformedProof, "test message");

        assert_eq!(error.code().as_str(), "MALFORMED_PROOF");
        assert_eq!(error.message(), "test message");
    }
}
