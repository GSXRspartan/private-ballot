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
//! It holds no walletd auth secret, wallet seed, mnemonic, or wallet signing
//! material, and its view models contain no secret-bearing fields. Slice 5A9
//! adds a narrow Rust-only, session-only voter governance credential holder;
//! the private scalar is never serialized or returned to TypeScript. It
//! performs no network, walletd, or indexer I/O. Durable credential helpers
//! write only the reviewed encrypted V1 credential-container bytes and do not
//! choose app-data paths or expose frontend commands. The offline archive
//! remains authoritative; Ootle anchoring remains optional and non-binding.

pub mod archive_verify;
pub mod archive_writer;
pub mod artifacts;
pub mod creation;
pub mod error;
pub mod governance;
mod hex;
pub mod inspect;
pub mod intake;
pub mod live_anchor_config;
pub mod participation;
pub mod session;
pub mod summary;
pub mod tally;
pub mod transport;
pub mod transport_anchor;
pub mod voter_confirmation;
pub mod voter_credential;
pub mod voter_credential_container;
pub mod voter_credential_store;
pub mod voter_session;

pub use archive_verify::{
    GuiArchiveFileCheckV1, GuiArchiveVerificationV1, STAGE_TRANSPORT_BINDING,
    verify_archive_directory_v1,
};
pub use archive_writer::{
    GuiArchiveFileSummaryV1, GuiArchiveWriteResultV1, write_archive_directory_v1,
    write_archive_directory_v1_with_transport_binding, write_finalized_archive_v1,
    write_finalized_archive_v1_with_governance_document,
    write_finalized_archive_v1_with_transport_binding,
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
    GuiGovernanceArchivePinFactV1, GuiGovernanceDocumentDigestV1, GuiGovernanceDocumentStatusV1,
    GuiGovernanceMatchStatusV1, GuiGovernanceSourcePinV1, MAX_GOVERNANCE_DOCUMENT_BYTES,
    compute_governance_document_digest, content_digest_pin_for_bytes, match_governance_document,
    read_governance_document, validate_governance_source_pin,
};
pub use inspect::{
    GuiAnchorConfigInspectionV1, GuiAnchorEvidenceInspectionV1, GuiAnchorSnapshotInspectionV1,
    GuiReceiptSnapshotSummaryV1, GuiWalletdSnapshotSummaryV1, inspect_anchor_config_v1,
    inspect_anchor_evidence_v1, inspect_anchor_snapshot_v1,
};
pub use intake::{GuiBallotIntakeResultV1, GuiIntakeCategory};
pub use live_anchor_config::{
    GuiLiveAnchorConfigRequestV1, GuiLiveAnchorConfigResultV1,
    write_live_anchor_config_from_verified_archive_v1,
};
pub use participation::{
    CoarseParticipationBucket, GuiParticipationSummaryV1, ParticipationVisibility,
    ResultVisibility, SMALL_ELECTORATE_THRESHOLD,
};
pub use session::GuiElectionSessionV1;
pub use summary::{GuiCandidateSummaryV1, GuiElectionSummaryV1};
pub use tally::{GuiLeadingResultV1, GuiTallyCountV1, GuiTallySummaryV1};
pub use tari_cc_private_ballot_ballot::ElectionLifecycleStateV1;
pub use transport::{
    BatchPolicyV1, DescriptorConsistencyStoreV1, EnvelopeOpeningMaterialV1, PaddingPolicyV1,
    PrivateBallotEnvelopeV1, RetryStatusV1, TransportAuthorityRootSetV1, TransportAuthorityRootV1,
    TransportDescriptorV1, TransportError, TransportRoutePolicyV1, VoterReceiptStateV1,
    VoterTransportReceiptV1, production_transport_authority_root_v1,
};
pub use transport_anchor::{GuiTransportAnchorVerificationV1, verify_transport_archive_anchor_v1};
pub use voter_confirmation::{
    GuiVoterAdvancedDetailsV1, GuiVoterBoundFieldsV1, GuiVoterElectionConfirmationV1,
    VOTER_NEXT_STAGE_PLACEHOLDER, build_voter_election_confirmation,
};
pub use voter_credential::{
    GOVERNANCE_CREDENTIAL_DURABLE_NOTICE, GOVERNANCE_CREDENTIAL_ENROLLMENT_NOTICE,
    GOVERNANCE_CREDENTIAL_SESSION_NOTICE, GuiVoterCredentialOriginV1, GuiVoterCredentialSessionV1,
    GuiVoterCredentialStatusV1, GuiVoterEligibilityV1, VoterGovernanceCredentialV1,
};
pub use voter_credential_container::{
    VOTER_CREDENTIAL_CONTAINER_V1_AEAD_ID_XCHACHA20_POLY1305, VOTER_CREDENTIAL_CONTAINER_V1_BYTES,
    VOTER_CREDENTIAL_CONTAINER_V1_CIPHERTEXT_AND_TAG_BYTES,
    VOTER_CREDENTIAL_CONTAINER_V1_FORMAT_VERSION, VOTER_CREDENTIAL_CONTAINER_V1_HEADER_BYTES,
    VOTER_CREDENTIAL_CONTAINER_V1_KDF_ID_ARGON2ID, VOTER_CREDENTIAL_CONTAINER_V1_KDF_MEMORY_MIB,
    VOTER_CREDENTIAL_CONTAINER_V1_KDF_PARALLELISM, VOTER_CREDENTIAL_CONTAINER_V1_KDF_TIME_COST,
    VOTER_CREDENTIAL_CONTAINER_V1_MAGIC, VOTER_CREDENTIAL_CONTAINER_V1_NONCE_BYTES,
    VOTER_CREDENTIAL_CONTAINER_V1_PLAINTEXT_BYTES, VOTER_CREDENTIAL_CONTAINER_V1_SALT_BYTES,
    VoterCredentialContainerV1, default_voter_credential_filename_v1,
    export_voter_credential_container_v1, import_voter_credential_container_bytes_v1,
    import_voter_credential_container_v1, read_voter_credential_container_v1,
    write_voter_credential_container_v1,
};
pub use voter_credential_store::{
    GuiSavedVoterCredentialDeleteResultV1, GuiSavedVoterCredentialsV1,
    GuiVoterCredentialBackupResultV1, GuiVoterCredentialFileSummaryV1,
    VOTER_CREDENTIALS_DIRECTORY_NAME, backup_voter_credential_to_path_v1,
    copy_validated_voter_credential_to_default_v1, default_voter_credential_path_v1,
    delete_saved_voter_credential_v1, ensure_voter_credentials_directory_v1,
    file_summary_for_public_key, import_voter_credential_from_path_v1,
    list_saved_voter_credentials_v1, parse_public_governance_key_hex_v1,
    unlock_saved_voter_credential_v1, voter_credentials_directory_v1,
    write_new_durable_voter_credential_v1,
};
pub use voter_session::{
    GuiPreparedBallotExportV1, GuiPreparedBallotStatusV1, GuiPreparedBallotSummaryV1,
    GuiVoterElectionBindingV1, GuiVoterPreparationTokenV1, GuiVoterSelectionStatusV1,
    GuiVoterSessionV1, GuiVoterWorkflowStateV1, GuiVoterWorkflowStatusV1,
    PROOF_GENERATION_DEFERRED_NOTICE, voter_selectable_options,
};
