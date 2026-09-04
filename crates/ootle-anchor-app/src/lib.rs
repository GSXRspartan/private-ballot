//! Application-layer driver, durable snapshot, and anchor evidence for the
//! harmless, non-binding Ootle testnet anchor prototype (Phase 4 Slice 4A10).
//!
//! This crate is the application-layer leaf. It wires the Slice 4A9 real network
//! adapters and the Slice 4A8 lifecycle orchestrator together, maps the Slice
//! 4A8 abstract polling attempts to bounded wall-clock delays, owns the
//! canonical durable encoding of [`AnchorLifecycleRecoverySnapshot`], and
//! produces a canonical, versioned [`AnchorEvidenceRecordV1`] for terminal
//! outcomes.
//!
//! # Non-binding pilot
//!
//! The anchor is *non-binding*: it proves only that a specific commitment was
//! submitted or finalized on the named ledger. It does not prove ballot
//! validity, tally correctness, organizer honesty, voter anonymity, or archive
//! availability. The offline archive and the independent verifier remain
//! authoritative. Binding governance use remains unauthorized.
//!
//! # Safety envelope
//!
//! The crate holds no wallet secret, no ballot, no proof, no nullifier, no
//! registry key, no voter identity, no organizer identity, and no private key.
//! It performs no signing and no direct network I/O of its own; all network
//! access is delegated to the existing Slice 4A9 adapters, which are driven
//! through the existing Slice 4A8 orchestrator.

#![forbid(unsafe_code)]

pub mod backoff;
pub mod cli;
pub mod config;
pub mod create_intent;
pub mod driver;
pub mod evidence;
pub mod executor;
pub mod inspect_snapshot;
pub mod path_guard;
pub mod policy;
pub mod poll_gate;
pub mod publish_lock;
pub mod report;
pub mod signer_backend;
pub mod snapshot_store;
pub mod terminal_index;
pub mod verify_evidence;
pub mod write_config;

pub use backoff::{BackoffError, WallClockBackoff};
pub use config::{
    AnchorAppConfig, AnchorConfigInputProvenanceV1, AnchorLiveApprovalFactsV1, ConfigFileError,
    FEE_COMPONENT_ASSURANCE_VERIFIED, MAX_DECLARED_SEAL_PUBLIC_KEY_BYTES,
    SEAL_PUBLIC_KEY_ASSURANCE_ATTESTED,
};
pub use driver::{
    AnchorAppDriver, DriverError, DriverRunOutcome, DriverSingleStepOutcomeV1, OperatorDecision,
    VerifiedRuntimeArchiveFactsV1,
};
pub use evidence::{
    AnchorEvidenceRecordV1, ArchiveProofInputs, EvidenceError, EvidenceFileError,
    LiveEvidenceApprovalFactsV1, TerminalEvidenceInputs, TerminalIncidentKind,
    write_evidence_atomic,
};
pub use executor::{TokioBlockingExecutor, TokioRuntimeBuildError};
pub use policy::{
    OOTLE_ANCHOR_PUBLISH_MIN_ACCEPTED_BALLOT_FLOOR_V1, WALLETD_AUTH_TOKEN_ENV_VAR_V1,
};
pub use report::MachineReportCode;
pub use signer_backend::{
    AnchorSignerBackendV1, EXTERNAL_WALLETD_BACKEND_V1, MANAGED_ANCHOR_WALLET_BACKEND_V1,
    MANAGED_ANCHOR_WALLET_BLOCKER_V1, MANAGED_ANCHOR_WALLET_ENABLED_V1,
};
pub use snapshot_store::{
    MAX_SNAPSHOT_FILE_BYTES, SNAPSHOT_DOMAIN_LABEL_V1, SNAPSHOT_FRAME_PREFIX_V1,
    SNAPSHOT_HASH_ALGORITHM_ID_V1, SNAPSHOT_RECORD_TYPE_ID_V1, SnapshotFileError, read_snapshot,
    snapshot_digest, write_snapshot_atomic,
};
pub use terminal_index::{
    TerminalAnchorIndexRecordV1, TerminalIndexError, default_terminal_index_root,
    read_terminal_index, terminal_index_path, write_terminal_index,
};
