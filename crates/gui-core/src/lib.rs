#![forbid(unsafe_code)]

//! Application-facing facade for the Phase 5 GUI (Slice 5A2).
//!
//! This crate is the typed boundary between a future desktop shell (Tauri
//! commands) and the existing project backend. It composes the public APIs of
//! the protocol, registry, ballot, crypto, verifier, tally, archive, and
//! anchor application crates without reimplementing any of their logic:
//!
//! * canonical election-artifact loading with cross-binding validation
//!   ([`GuiElectionArtifactsV1`]);
//! * an organizer election session composing the existing lifecycle,
//!   acceptance ledger, and verification transcript
//!   ([`GuiElectionSessionV1`]);
//! * a ballot-intake facade over
//!   [`ingest_approval_ballot_package_v1`](tari_cc_private_ballot_verifier::ingest_approval_ballot_package_v1);
//! * a deterministic tally facade over
//!   [`ApprovalTally`](tari_cc_private_ballot_tally::ApprovalTally);
//! * an archive-directory writer and a full offline archive replay verifier
//!   promoted from the composition already proven in the CLI integration
//!   tests;
//! * structured, non-printing inspectors for the anchor application config,
//!   durable lifecycle snapshot, and anchor evidence record.
//!
//! # What this crate never does
//!
//! It holds no voter secret key, no walletd auth secret, no wallet seed, no
//! mnemonic, and no signing material, and its view models contain no
//! secret-bearing fields. It performs no network, walletd, or indexer I/O. It
//! introduces no new canonical format, no new hash provider, no container or
//! bundle format, no credential persistence, and no async runtime. The
//! offline archive remains authoritative; Ootle anchoring remains optional
//! and non-binding.

pub mod archive_verify;
pub mod archive_writer;
pub mod artifacts;
pub mod creation;
pub mod error;
pub mod governance;
mod hex;
pub mod inspect;
pub mod intake;
pub mod participation;
pub mod session;
pub mod summary;
pub mod tally;
pub mod voter_confirmation;

pub use archive_verify::{
    GuiArchiveFileCheckV1, GuiArchiveVerificationV1, verify_archive_directory_v1,
};
pub use archive_writer::{
    GuiArchiveFileSummaryV1, GuiArchiveWriteResultV1, write_archive_directory_v1,
};
pub use artifacts::GuiElectionArtifactsV1;
pub use creation::{
    GuiBallotPresentationType, GuiDraftOptionV1, GuiDraftVoterV1, GuiElectionCreationResultV1,
    GuiElectionDraftPreviewV1, GuiElectionDraftV1, GuiElectionExportFileV1,
    GuiElectionExportResultV1, write_election_artifacts_v1,
};
pub use error::{GuiCoreError, GuiErrorCategory};
pub use governance::{
    GOVERNANCE_DOCUMENT_ARCHIVE_PATH, GOVERNANCE_PIN_PREFIX_BLAKE3, GOVERNANCE_PIN_PREFIX_GIT,
    GuiGovernanceArchivePinFactV1, MAX_GOVERNANCE_DOCUMENT_BYTES,
    compute_governance_document_digest, content_digest_pin_for_bytes, match_governance_document,
    read_governance_document, validate_governance_source_pin, GuiGovernanceDocumentDigestV1,
    GuiGovernanceDocumentStatusV1, GuiGovernanceMatchStatusV1, GuiGovernanceSourcePinV1,
};
pub use inspect::{
    GuiAnchorConfigInspectionV1, GuiAnchorEvidenceInspectionV1, GuiAnchorSnapshotInspectionV1,
    GuiReceiptSnapshotSummaryV1, GuiWalletdSnapshotSummaryV1, inspect_anchor_config_v1,
    inspect_anchor_evidence_v1, inspect_anchor_snapshot_v1,
};
pub use intake::{GuiBallotIntakeResultV1, GuiIntakeCategory};
pub use participation::{
    CoarseParticipationBucket, GuiParticipationSummaryV1, ParticipationVisibility,
    ResultVisibility, SMALL_ELECTORATE_THRESHOLD,
};
pub use session::GuiElectionSessionV1;
pub use summary::{GuiCandidateSummaryV1, GuiElectionSummaryV1};
pub use tally::{GuiLeadingResultV1, GuiTallyCountV1, GuiTallySummaryV1};
pub use voter_confirmation::{
    build_voter_election_confirmation, GuiVoterAdvancedDetailsV1, GuiVoterBoundFieldsV1,
    GuiVoterElectionConfirmationV1, VOTER_NEXT_STAGE_PLACEHOLDER,
};
