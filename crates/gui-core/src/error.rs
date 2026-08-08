//! Bounded GUI-facing error type with stable machine codes.
//!
//! Every error carries a stable machine code (preserving the existing project
//! `ValidationCode`, config, snapshot, evidence, and lifecycle reconstruction
//! identifiers wherever one exists), a coarse category for frontend styling,
//! an optional static context label naming the artifact or stage, and a
//! bounded static message. No error carries a path, a secret, or raw
//! third-party error text.

use tari_cc_private_ballot_ootle_anchor_app::{ConfigFileError, EvidenceError, SnapshotFileError};
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleReconstructionError;
use tari_cc_private_ballot_protocol::{ProtocolError, ValidationCode};

/// Coarse error category for frontend treatment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
pub enum GuiErrorCategory {
    /// The input artifact or value failed validation.
    InvalidInput,
    /// The format, version, hash algorithm, or proof suite is unsupported.
    UnsupportedFormat,
    /// Two artifacts that must match do not (commitments, manifests, bindings).
    BindingMismatch,
    /// A proof failed verification or is malformed.
    ProofFailure,
    /// A ballot duplicates an already-accepted nullifier.
    DuplicateBallot,
    /// An election lifecycle transition is not permitted in the current state.
    InvalidLifecycleTransition,
    /// An archive failed an integrity, digest, membership, or replay check.
    ArchiveIntegrity,
    /// A filesystem operation failed.
    FileIo,
    /// An anchor config, snapshot, or evidence artifact failed integrity or
    /// semantic validation.
    AnchorArtifactIntegrity,
}

impl GuiErrorCategory {
    /// Returns the stable machine-readable category code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidInput => "INVALID_INPUT",
            Self::UnsupportedFormat => "UNSUPPORTED_FORMAT",
            Self::BindingMismatch => "BINDING_MISMATCH",
            Self::ProofFailure => "PROOF_FAILURE",
            Self::DuplicateBallot => "DUPLICATE_BALLOT",
            Self::InvalidLifecycleTransition => "INVALID_LIFECYCLE_TRANSITION",
            Self::ArchiveIntegrity => "ARCHIVE_INTEGRITY",
            Self::FileIo => "FILE_IO",
            Self::AnchorArtifactIntegrity => "ANCHOR_ARTIFACT_INTEGRITY",
        }
    }
}

/// The single bounded gui-core error type.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiCoreError {
    code: &'static str,
    category: GuiErrorCategory,
    context: Option<&'static str>,
    message: &'static str,
}

impl GuiCoreError {
    /// Creates one bounded error.
    #[must_use]
    pub const fn new(
        code: &'static str,
        category: GuiErrorCategory,
        context: Option<&'static str>,
        message: &'static str,
    ) -> Self {
        Self {
            code,
            category,
            context,
            message,
        }
    }

    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Returns the coarse category.
    #[must_use]
    pub const fn category(&self) -> GuiErrorCategory {
        self.category
    }

    /// Returns the optional static context label (an artifact or stage name).
    #[must_use]
    pub const fn context(&self) -> Option<&'static str> {
        self.context
    }

    /// Returns the bounded, non-sensitive message.
    #[must_use]
    pub const fn message(&self) -> &'static str {
        self.message
    }

    /// Wraps a protocol validation failure, preserving its stable code.
    #[must_use]
    pub fn from_protocol(error: &ProtocolError, context: &'static str) -> Self {
        Self::new(
            error.code().as_str(),
            category_for_validation(error.code()),
            Some(context),
            error.message(),
        )
    }

    /// A required file was not present.
    #[must_use]
    pub const fn file_not_found(context: &'static str) -> Self {
        Self::new(
            "GUI_FILE_NOT_FOUND",
            GuiErrorCategory::FileIo,
            Some(context),
            "a required file was not found",
        )
    }

    /// A filesystem operation failed.
    #[must_use]
    pub const fn io_failure(context: &'static str) -> Self {
        Self::new(
            "GUI_IO_ERROR",
            GuiErrorCategory::FileIo,
            Some(context),
            "a filesystem operation failed",
        )
    }

    /// The recomputed registry commitment differs from the election manifest.
    #[must_use]
    pub const fn registry_commitment_mismatch() -> Self {
        Self::new(
            "GUI_REGISTRY_COMMITMENT_MISMATCH",
            GuiErrorCategory::BindingMismatch,
            Some("registry"),
            "the voter registry commitment does not match the election manifest",
        )
    }

    /// The archive target directory is not usable for a fresh archive.
    #[must_use]
    pub const fn archive_target_not_empty() -> Self {
        Self::new(
            "GUI_ARCHIVE_TARGET_NOT_EMPTY",
            GuiErrorCategory::FileIo,
            Some("archive-directory"),
            "the archive target directory already contains files",
        )
    }

    /// The archive target path exists and is not a directory.
    #[must_use]
    pub const fn archive_target_invalid() -> Self {
        Self::new(
            "GUI_ARCHIVE_TARGET_INVALID",
            GuiErrorCategory::FileIo,
            Some("archive-directory"),
            "the archive target path exists and is not a directory",
        )
    }

    /// An archive content file listed in the catalog is missing on disk.
    #[must_use]
    pub const fn archive_missing_file() -> Self {
        Self::new(
            "GUI_ARCHIVE_MISSING_FILE",
            GuiErrorCategory::ArchiveIntegrity,
            Some("archive-directory"),
            "a file listed in the archive catalog is missing",
        )
    }

    /// A file is present on disk that the archive catalog does not list.
    #[must_use]
    pub const fn archive_unexpected_file() -> Self {
        Self::new(
            "GUI_ARCHIVE_UNEXPECTED_FILE",
            GuiErrorCategory::ArchiveIntegrity,
            Some("archive-directory"),
            "the archive directory contains a file the catalog does not list",
        )
    }

    /// A required well-known election artifact is absent from the catalog.
    #[must_use]
    pub const fn archive_missing_artifact(context: &'static str) -> Self {
        Self::new(
            "GUI_ARCHIVE_MISSING_ARTIFACT",
            GuiErrorCategory::ArchiveIntegrity,
            Some(context),
            "a required election artifact is absent from the archive catalog",
        )
    }

    /// Tally results are sealed until voting has closed.
    ///
    /// Returned by [`crate::session::GuiElectionSessionV1::tally`] when the
    /// election lifecycle is `DRAFT`, `FROZEN`, or `OPEN`. Carries no tally
    /// data and no accepted-option counts.
    #[must_use]
    pub const fn tally_not_available_before_close() -> Self {
        Self::new(
            "GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE",
            GuiErrorCategory::InvalidLifecycleTransition,
            Some("tally"),
            "Tally results are not available until voting is closed.",
        )
    }
}

/// Maps an existing protocol validation code onto a coarse GUI category.
#[must_use]
pub const fn category_for_validation(code: ValidationCode) -> GuiErrorCategory {
    match code {
        ValidationCode::DuplicateNullifier => GuiErrorCategory::DuplicateBallot,
        ValidationCode::MalformedProof => GuiErrorCategory::ProofFailure,
        ValidationCode::WrongManifestHash
        | ValidationCode::CandidateSetCommitmentMismatch
        | ValidationCode::LifecycleCommitmentMismatch
        | ValidationCode::BallotDecisionDigestMismatch => GuiErrorCategory::BindingMismatch,
        ValidationCode::InvalidLifecycleTransition | ValidationCode::ElectionNotOpen => {
            GuiErrorCategory::InvalidLifecycleTransition
        }
        ValidationCode::UnsupportedProtocolVersion
        | ValidationCode::UnsupportedHashAlgorithm
        | ValidationCode::UnsupportedProofSuite => GuiErrorCategory::UnsupportedFormat,
        ValidationCode::ArchiveFileDigestMismatch
        | ValidationCode::ArchiveManifestHashMismatch
        | ValidationCode::InvalidArchiveManifest
        | ValidationCode::EmptyArchiveFileSet
        | ValidationCode::EmptyArchivePath
        | ValidationCode::InvalidArchivePath
        | ValidationCode::DuplicateArchivePath
        | ValidationCode::InvalidIngestSequence
        | ValidationCode::DuplicateBallotDecision
        | ValidationCode::IncompleteVerificationTranscript => GuiErrorCategory::ArchiveIntegrity,
        _ => GuiErrorCategory::InvalidInput,
    }
}

impl From<ConfigFileError> for GuiCoreError {
    fn from(error: ConfigFileError) -> Self {
        let category = match error {
            ConfigFileError::FileNotFound | ConfigFileError::IoFailure => GuiErrorCategory::FileIo,
            ConfigFileError::UnsupportedProtocolVersion
            | ConfigFileError::UnsupportedHashAlgorithm
            | ConfigFileError::UnsupportedNetwork => GuiErrorCategory::UnsupportedFormat,
            ConfigFileError::DigestMismatch | ConfigFileError::NetworkMismatch => {
                GuiErrorCategory::AnchorArtifactIntegrity
            }
            _ => GuiErrorCategory::InvalidInput,
        };
        Self::new(
            error.as_str(),
            category,
            Some("anchor-config"),
            "anchor application config failed validation",
        )
    }
}

impl From<SnapshotFileError> for GuiCoreError {
    fn from(error: SnapshotFileError) -> Self {
        let category = match error {
            SnapshotFileError::FileNotFound | SnapshotFileError::IoFailure => {
                GuiErrorCategory::FileIo
            }
            SnapshotFileError::UnsupportedProtocolVersion
            | SnapshotFileError::UnsupportedHashAlgorithm => GuiErrorCategory::UnsupportedFormat,
            _ => GuiErrorCategory::AnchorArtifactIntegrity,
        };
        Self::new(
            error.as_str(),
            category,
            Some("anchor-snapshot"),
            "anchor lifecycle snapshot failed validation",
        )
    }
}

impl From<EvidenceError> for GuiCoreError {
    fn from(error: EvidenceError) -> Self {
        Self::new(
            error.as_str(),
            GuiErrorCategory::AnchorArtifactIntegrity,
            Some("anchor-evidence"),
            "anchor evidence record failed validation",
        )
    }
}

impl From<LifecycleReconstructionError> for GuiCoreError {
    fn from(error: LifecycleReconstructionError) -> Self {
        Self::new(
            error.as_str(),
            GuiErrorCategory::AnchorArtifactIntegrity,
            Some("anchor-snapshot"),
            "anchor lifecycle snapshot is not semantically consistent",
        )
    }
}

impl core::fmt::Display for GuiCoreError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.context {
            Some(context) => write!(formatter, "{} ({context}): {}", self.code, self.message),
            None => write!(formatter, "{}: {}", self.code, self.message),
        }
    }
}

impl std::error::Error for GuiCoreError {}
