//! Unified recovery snapshot (Section E).
//!
//! [`AnchorLifecycleRecoverySnapshot`] *composes* the walletd snapshot(s) and
//! the receipt-query snapshot(s) from the two existing coordinators, plus the
//! unified lifecycle phase and the polling policy's attempts-consumed. It
//! preserves every field a restart needs to resume safely and nothing sensitive.
//!
//! Canonical on-disk encoding is deferred to Slice 4A10; this in-memory,
//! comparable snapshot is sufficient, exactly as Slices 4A6/4A7 deferred.

use tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQuerySnapshotV1;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    SubmittedWalletdAnchorRequestV1, WalletdAnchorSnapshotV1,
};

use crate::policy::PollingPolicy;
use crate::state::UnifiedAnchorLifecyclePhase;

/// An error raised when reconstructing the orchestrator from a snapshot.
///
/// Every variant is a bounded, stable code. No variant carries a secret, a
/// pinned Ootle type, or raw third-party text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleReconstructionError {
    /// The walletd and receipt snapshots disagree on which project request they
    /// describe. A consistent recovery snapshot describes at most one anchor.
    SnapshotRequestMismatch,
    /// The receipt snapshot references a submitted request, but no submitted
    /// request was carried in the snapshot. The orchestrator cannot resume
    /// polling without the cached submitted handle (its constructor is
    /// crate-private to the walletd adapter).
    MissingSubmittedHandle,
    /// The declared lifecycle phase is inconsistent with the contained
    /// walletd snapshots, receipt snapshots, submitted handle, or polling
    /// policy state. A consistent snapshot's phase must be derivable from its
    /// contained state.
    PhaseStateMismatch,
    /// A submitted handle is present but no walletd snapshot describes it, or
    /// the walletd snapshot's submission state does not indicate submission.
    SubmittedHandleWithoutWalletdSnapshot,
    /// The transaction identifier in the submitted handle does not match the
    /// one recorded in the walletd snapshot or the receipt-query snapshot.
    TransactionIdMismatch,
    /// The frozen binding (network, account, anchor digest, payload, maximum
    /// fee, or fingerprint) differs between the walletd snapshot, the submitted
    /// handle, and/or the receipt-query snapshot.
    BindingMismatch,
    /// Duplicate project request identifiers, walletd request identifiers, or
    /// transaction identifiers were found across the snapshots.
    DuplicateIdentifier,
    /// More than one walletd or receipt-query snapshot was present. A single
    /// anchor lifecycle describes at most one of each.
    TooManySnapshots,
    /// The polling policy's consumed attempts exceed the maximum, or the
    /// declared phase requires a non-zero attempt count that is absent.
    PolicyInconsistent,
}

impl LifecycleReconstructionError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SnapshotRequestMismatch => "LIFECYCLE_SNAPSHOT_REQUEST_MISMATCH",
            Self::MissingSubmittedHandle => "LIFECYCLE_MISSING_SUBMITTED_HANDLE",
            Self::PhaseStateMismatch => "LIFECYCLE_PHASE_STATE_MISMATCH",
            Self::SubmittedHandleWithoutWalletdSnapshot => {
                "LIFECYCLE_SUBMITTED_HANDLE_WITHOUT_WALLETD_SNAPSHOT"
            }
            Self::TransactionIdMismatch => "LIFECYCLE_TRANSACTION_ID_MISMATCH",
            Self::BindingMismatch => "LIFECYCLE_BINDING_MISMATCH",
            Self::DuplicateIdentifier => "LIFECYCLE_DUPLICATE_IDENTIFIER",
            Self::TooManySnapshots => "LIFECYCLE_TOO_MANY_SNAPSHOTS",
            Self::PolicyInconsistent => "LIFECYCLE_POLICY_INCONSISTENT",
        }
    }
}

impl core::fmt::Display for LifecycleReconstructionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for LifecycleReconstructionError {}

/// The unified, comparable recovery snapshot for one anchor lifecycle.
///
/// It composes:
/// * the walletd snapshot(s) via
///   [`LocalWalletdAnchorRegistry::snapshots`] / [`WalletdAnchorSnapshotV1`];
/// * the receipt-query snapshot(s) via
///   [`LocalReceiptQueryRegistry::snapshots`] /
///   [`AnchorReceiptQuerySnapshotV1`];
/// * the cached [`SubmittedWalletdAnchorRequestV1`] (needed to resume polling,
///   because its constructor is crate-private to the walletd adapter and cannot
///   be rebuilt from snapshots alone);
/// * the unified lifecycle phase and the polling policy's attempts-consumed.
///
/// It holds no wallet secret, ballot, or archive content. It is deterministic
/// and comparable (`PartialEq`, `Eq`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorLifecycleRecoverySnapshot {
    walletd_snapshots: Vec<WalletdAnchorSnapshotV1>,
    receipt_snapshots: Vec<AnchorReceiptQuerySnapshotV1>,
    submitted: Option<SubmittedWalletdAnchorRequestV1>,
    policy: PollingPolicy,
    phase: UnifiedAnchorLifecyclePhase,
    diagnostic: Option<&'static str>,
}

impl AnchorLifecycleRecoverySnapshot {
    /// Builds a unified recovery snapshot from its composed parts.
    #[must_use]
    pub fn new(
        walletd_snapshots: Vec<WalletdAnchorSnapshotV1>,
        receipt_snapshots: Vec<AnchorReceiptQuerySnapshotV1>,
        submitted: Option<SubmittedWalletdAnchorRequestV1>,
        policy: PollingPolicy,
        phase: UnifiedAnchorLifecyclePhase,
        diagnostic: Option<&'static str>,
    ) -> Self {
        Self {
            walletd_snapshots,
            receipt_snapshots,
            submitted,
            policy,
            phase,
            diagnostic,
        }
    }

    /// Returns the walletd coordinator snapshots.
    #[must_use]
    pub fn walletd_snapshots(&self) -> &[WalletdAnchorSnapshotV1] {
        &self.walletd_snapshots
    }

    /// Returns the receipt-query coordinator snapshots.
    #[must_use]
    pub fn receipt_snapshots(&self) -> &[AnchorReceiptQuerySnapshotV1] {
        &self.receipt_snapshots
    }

    /// Returns the cached submitted request, if the lifecycle reached the
    /// submitted phase.
    #[must_use]
    pub fn submitted(&self) -> Option<&SubmittedWalletdAnchorRequestV1> {
        self.submitted.as_ref()
    }

    /// Returns the polling policy (max attempts + consumed).
    #[must_use]
    pub const fn policy(&self) -> PollingPolicy {
        self.policy
    }

    /// Returns the unified lifecycle phase.
    #[must_use]
    pub const fn phase(&self) -> UnifiedAnchorLifecyclePhase {
        self.phase
    }

    /// Returns the last bounded diagnostic code, if any.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&'static str> {
        self.diagnostic
    }

    // -- Accessors that surface the fields Section E requires to be preserved --
    // These delegate to the composed snapshots so there is one source of truth.

    /// Returns the project request identifier, if a walletd snapshot exists.
    #[must_use]
    pub fn project_request_id(
        &self,
    ) -> Option<&tari_cc_private_ballot_anchor_transport::AnchorRequestId> {
        self.walletd_snapshots
            .first()
            .map(|snapshot| snapshot.project_request_id())
    }

    /// Returns the walletd request identifier, if a walletd snapshot exists.
    #[must_use]
    pub fn walletd_request_id(
        &self,
    ) -> Option<tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdRequestId> {
        self.walletd_snapshots
            .first()
            .map(|snapshot| snapshot.walletd_request_id())
    }

    /// Returns the sealed transaction id, if known.
    #[must_use]
    pub fn transaction_id(
        &self,
    ) -> Option<&tari_cc_private_ballot_anchor_transport::AnchorTransactionId> {
        if let Some(submitted) = &self.submitted {
            return Some(submitted.transaction_id());
        }
        self.walletd_snapshots
            .first()
            .and_then(|snapshot| snapshot.transaction_id())
    }

    /// Returns the bound network, if a walletd snapshot exists.
    #[must_use]
    pub fn network(&self) -> Option<&tari_cc_private_ballot_anchor::OotleNetworkIdV1> {
        self.walletd_snapshots
            .first()
            .map(|snapshot| snapshot.binding().network())
    }

    /// Returns the bound fee account reference, if a walletd snapshot exists.
    #[must_use]
    pub fn account(
        &self,
    ) -> Option<&tari_cc_private_ballot_anchor_transport::AnchorAccountReference> {
        self.walletd_snapshots
            .first()
            .map(|snapshot| snapshot.binding().account())
    }

    /// Returns the bound expected anchor-record digest, if a walletd snapshot
    /// exists.
    #[must_use]
    pub fn anchor_digest(&self) -> Option<tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1> {
        self.walletd_snapshots
            .first()
            .map(|snapshot| snapshot.binding().anchor_digest())
    }

    /// Returns the bound expected anchor log payload, if a walletd snapshot
    /// exists.
    #[must_use]
    pub fn payload(&self) -> Option<&tari_cc_private_ballot_anchor_transport::AnchorLogPayloadV1> {
        self.walletd_snapshots
            .first()
            .map(|snapshot| snapshot.binding().payload())
    }

    /// Returns the bound unsigned-transaction fingerprint, if a walletd
    /// snapshot exists.
    ///
    /// The fingerprint is preserved through the composed walletd snapshot's
    /// binding (see [`WalletdAnchorSnapshotV1::binding`]). It is not re-exposed
    /// as a separate accessor here to avoid naming a type from a crate that is
    /// a dev-only dependency of this orchestrator; callers access it via
    /// `snapshot.walletd_snapshots().first().map(|s| s.binding().fingerprint())`.
    #[must_use]
    pub fn fingerprint_note(&self) -> &'static str {
        "unsigned-transaction fingerprint preserved via walletd snapshot binding"
    }

    /// Returns the attempts consumed from the polling policy.
    #[must_use]
    pub const fn attempts_consumed(&self) -> u32 {
        self.policy.attempts_consumed()
    }
}
