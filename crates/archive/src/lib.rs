#![forbid(unsafe_code)]

//! Metadata-minimized offline archive and replay models.
//!
//! This crate records protocol-relevant submission order and deterministic
//! ballot decisions. It deliberately does not retain voter identity, wallet
//! details, network metadata, client fingerprints, retry history, or
//! high-resolution timestamps.

mod file_entry;
mod replay;

pub use file_entry::{
    ArchiveFileCatalogV1, ArchiveFileDigestV1, ArchiveFileEntryV1, ArchivePathV1,
};
pub use replay::{
    BallotDecisionOutcomeV1, BallotDecisionV1, BallotPackageDigestV1, IngestSequenceV1,
    SubmissionRecordV1, VerificationTranscriptV1,
};

/// First metadata-minimized archive replay-model version.
pub const ARCHIVE_REPLAY_MODEL_VERSION_V1: u16 = 1;
