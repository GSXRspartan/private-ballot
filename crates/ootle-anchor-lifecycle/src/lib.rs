#![forbid(unsafe_code)]

//! Offline anchor lifecycle orchestration (Slice 4A8).
//!
//! This leaf crate composes the Slice 4A6B [`WalletdAnchorCoordinator`] and the
//! Slice 4A7 [`AnchorReceiptCoordinator`] into a single, deterministic,
//! caller-advanced driver for the full anchor lifecycle:
//!
//! `prepare → approve → submit → poll receipt → finalize`
//!
//! It introduces no new external API surface, no pinned Ootle dependency, and no
//! network I/O. It owns and drives the two existing coordinators; it
//! re-implements none of their logic. Every coordinator method is called exactly
//! as designed, forwarding the exact request DTOs
//! ([`WalletdDecisionRequestV1::for_prepared`],
//! [`WalletdSubmitRequestV1::for_approved`],
//! [`AnchorReceiptQueryV1::from_submitted`],
//! [`AnchorReceiptCoordinator::register`]).
//!
//! # What this crate never does
//!
//! It never constructs, alters, signs, or resubmits a transaction; never holds
//! key custody; never contacts walletd, an indexer, or any network; never owns
//! an async runtime or starts a background task; never uses wall-clock timing,
//! sleeping, or randomness; and never reconstructs, rehashes, or mutates an
//! election artifact, anchor record, `ArchiveHashV1`, `ManifestHash`, submitted
//! transaction id, or unsigned-transaction fingerprint. Driving, polling,
//! recovering, or restarting the lifecycle is a pure transformation of
//! already-frozen commitments, so any outcome — including every error, timeout,
//! fee-only, rejected, verification-failure, disagreement, or poll-exhausted
//! unknown — leaves every offline election artifact byte-identical.
//!
//! # Dependency direction (unchanged, extended by one leaf)
//!
//! `Phase 1–3 → anchor → anchor-transport → transaction adapter → walletd
//! adapter → receipt adapter → lifecycle orchestrator`
//!
//! [`WalletdAnchorCoordinator`]: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorCoordinator
//! [`AnchorReceiptCoordinator`]: tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptCoordinator
//! [`WalletdDecisionRequestV1::for_prepared`]: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdDecisionRequestV1::for_prepared
//! [`WalletdSubmitRequestV1::for_approved`]: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdSubmitRequestV1::for_approved
//! [`AnchorReceiptQueryV1::from_submitted`]: tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryV1::from_submitted
//! [`AnchorReceiptCoordinator::register`]: tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptCoordinator::register

mod orchestrator;
mod policy;
mod report;
mod snapshot;
mod state;

pub use orchestrator::{AnchorLifecycleOrchestrator, LifecycleError};
pub use policy::{BackoffSchedule, PollingPolicy};
pub use report::{
    LifecycleReceiptQueryOutcome, LifecycleRecoveryOutcome, LifecycleStepOutcome,
    LifecycleStepReport,
};
pub use snapshot::{AnchorLifecycleRecoverySnapshot, LifecycleReconstructionError};
pub use state::UnifiedAnchorLifecyclePhase;
