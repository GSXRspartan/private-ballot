#![forbid(unsafe_code)]

//! Metadata-minimized offline archive and replay models.
//!
//! This crate records protocol-relevant submission order and deterministic
//! ballot decisions. It deliberately does not retain voter identity, wallet
//! details, network metadata, client fingerprints, retry history, or
//! high-resolution timestamps.

mod file_entry;
pub mod instrumentation;
mod manifest;
mod replay;
mod transport_binding;
mod verification_memo;
mod verifier;

pub use instrumentation::{
    ArchiveVerificationCountersSnapshotV1, archive_verification_snapshot,
    reset_archive_verification_counters,
};
pub use verification_memo::{ARCHIVE_VERIFICATION_MEMO_CAPACITY_V1, ArchiveVerificationMemoV1};

pub use file_entry::{
    ArchiveFileCatalogV1, ArchiveFileDigestV1, ArchiveFileEntryV1, ArchivePathV1,
};
pub use manifest::{
    ARCHIVE_FINAL_LIFECYCLE_STATE_FINALIZED_V1, ARCHIVE_MANIFEST_CANONICAL_PATH,
    ARCHIVE_MANIFEST_VERSION_V1, ARCHIVE_MANIFEST_VERSION_V2, ARCHIVE_SIGNATURE_PATH_PREFIX,
    ArchiveHashV1, ArchiveManifestV1,
};
pub use replay::{
    BallotDecisionOutcomeV1, BallotDecisionV1, BallotPackageDigestV1, IngestSequenceV1,
    SubmissionRecordV1, VerificationTranscriptV1,
};
pub use transport_binding::{
    TRANSPORT_ARCHIVE_BINDING_PATH_V1, TRANSPORT_ARCHIVE_BINDING_TYPE_ID_V1,
    TRANSPORT_BATCH_SET_ALGORITHM_ID_V1, TransportArchiveBatchV1, TransportArchiveBindingV1,
};
pub use verifier::{
    ArchiveDirectoryFileCheckV1, ArchiveDirectoryVerificationV1, ArchiveGovernancePinFactV1,
    ArchiveLeadingResultV1, ArchiveTallyCountV1, ArchiveTallySummaryV1, ArchiveVerifierError,
    CANDIDATE_SET_ARCHIVE_PATH, ELECTION_MANIFEST_ARCHIVE_PATH, GOVERNANCE_DOCUMENT_ARCHIVE_PATH,
    MAX_GOVERNANCE_DOCUMENT_BYTES, STAGE_ARCHIVE_HASH, STAGE_ARCHIVE_MANIFEST, STAGE_BALLOT_REPLAY,
    STAGE_CATALOG_FILES, STAGE_ELECTION_ARTIFACTS, STAGE_GOVERNANCE_PIN, STAGE_TRANSPORT_BINDING,
    SUBMISSIONS_ARCHIVE_DIR, VOTER_REGISTRY_ARCHIVE_PATH, verify_archive_directory_v1,
};

/// First metadata-minimized archive replay-model version.
pub const ARCHIVE_REPLAY_MODEL_VERSION_V1: u16 = 1;
