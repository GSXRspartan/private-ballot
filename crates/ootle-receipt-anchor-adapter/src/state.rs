//! Project-owned receipt-query and recovery state (Section I).
//!
//! The state machine records, per submitted request, how far receipt retrieval
//! has progressed and what was last observed, plus enough of the frozen query
//! binding to resume safely after a restart. It stores no wallet secret, no
//! private key, no archive content, and no ballot. Durable on-disk persistence is
//! deliberately deferred; the deterministic [`AnchorReceiptQuerySnapshotV1`] plus
//! `from_snapshots` import is sufficient to prove restart safety offline.
//!
//! A missing receipt is never a permanent failure: [`AnchorReceiptQueryStateV1`]
//! distinguishes not-found, pending, and timeout-unknown — all resumable — from a
//! finalized rejection, which is terminal, and from a verification failure, which
//! flags a finalized-but-unverifiable receipt for review.

use std::collections::BTreeMap;

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorFinalStatusV1, AnchorLogPayloadV1, AnchorRequestId,
    AnchorTransactionId,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdRequestId;

use crate::query::AnchorReceiptQueryV1;

/// The progress of receipt retrieval for one submitted anchor transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorReceiptQueryStateV1 {
    /// Submitted, but no receipt has been queried yet.
    SubmittedNotQueried,
    /// A query returned no receipt or result for the transaction.
    ReceiptNotFound,
    /// A query showed the transaction known but not yet finalized.
    ReceiptPending,
    /// A query could not resolve the state, for example after a timeout.
    ReceiptUnknown,
    /// A finalized receipt showed a full acceptance (the anchor may have landed;
    /// verification decides whether it did).
    ReceiptFinalizedAccept,
    /// A finalized receipt showed only the fee intent committed; the anchor did
    /// not land. Terminal for this transaction.
    ReceiptFinalizedFeeOnly,
    /// A finalized receipt showed a ledger rejection. Terminal.
    ReceiptFinalizedReject,
    /// A finalized full acceptance failed anchor verification (missing, malformed,
    /// wrong-digest, duplicate, or conflicting project anchor log).
    ReceiptVerificationFailed,
}

impl AnchorReceiptQueryStateV1 {
    /// Returns the stable machine-readable state code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SubmittedNotQueried => "SUBMITTED_NOT_QUERIED",
            Self::ReceiptNotFound => "RECEIPT_NOT_FOUND",
            Self::ReceiptPending => "RECEIPT_PENDING",
            Self::ReceiptUnknown => "RECEIPT_UNKNOWN",
            Self::ReceiptFinalizedAccept => "RECEIPT_FINALIZED_ACCEPT",
            Self::ReceiptFinalizedFeeOnly => "RECEIPT_FINALIZED_FEE_ONLY",
            Self::ReceiptFinalizedReject => "RECEIPT_FINALIZED_REJECT",
            Self::ReceiptVerificationFailed => "RECEIPT_VERIFICATION_FAILED",
        }
    }

    /// Returns whether the state is terminal (no further query can change it).
    ///
    /// A finalized fee-only or rejection is terminal; a verified full acceptance
    /// is represented by [`Self::ReceiptFinalizedAccept`] with a recorded
    /// verification success and is also effectively terminal, but not-found,
    /// pending, and unknown are all resumable.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ReceiptFinalizedFeeOnly | Self::ReceiptFinalizedReject
        )
    }
}

/// One stored receipt-query record.
#[derive(Debug, Clone)]
pub(crate) struct ReceiptQueryRecord {
    pub(crate) query: AnchorReceiptQueryV1,
    pub(crate) state: AnchorReceiptQueryStateV1,
    pub(crate) last_final_status: Option<AnchorFinalStatusV1>,
    pub(crate) verified: bool,
    pub(crate) sequence: u64,
    pub(crate) last_diagnostic: Option<&'static str>,
}

/// Deterministic recovery snapshot for one receipt-query record.
///
/// It preserves the frozen query binding, the recorded state, the last observed
/// finalized status, whether the anchor was verified, a deterministic sequence,
/// and the last bounded diagnostic. It is comparable and order-stable and holds
/// nothing sensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceiptQuerySnapshotV1 {
    query: AnchorReceiptQueryV1,
    state: AnchorReceiptQueryStateV1,
    last_final_status: Option<AnchorFinalStatusV1>,
    verified: bool,
    sequence: u64,
    last_diagnostic: Option<&'static str>,
}

impl AnchorReceiptQuerySnapshotV1 {
    /// Builds a recovery snapshot from its parts.
    #[must_use]
    pub fn new(
        query: AnchorReceiptQueryV1,
        state: AnchorReceiptQueryStateV1,
        last_final_status: Option<AnchorFinalStatusV1>,
        verified: bool,
        sequence: u64,
        last_diagnostic: Option<&'static str>,
    ) -> Self {
        Self {
            query,
            state,
            last_final_status,
            verified,
            sequence,
            last_diagnostic,
        }
    }

    /// Returns the frozen query binding.
    #[must_use]
    pub const fn query(&self) -> &AnchorReceiptQueryV1 {
        &self.query
    }

    /// Returns the project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        self.query.project_request_id()
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.query.walletd_request_id()
    }

    /// Returns the sealed transaction identifier.
    #[must_use]
    pub const fn transaction_id(&self) -> &AnchorTransactionId {
        self.query.transaction_id()
    }

    /// Returns the bound network.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        self.query.network()
    }

    /// Returns the bound fee account reference.
    #[must_use]
    pub const fn account(&self) -> &AnchorAccountReference {
        self.query.account()
    }

    /// Returns the bound expected anchor-record digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.query.anchor_digest()
    }

    /// Returns the bound exact expected anchor log payload.
    #[must_use]
    pub const fn payload(&self) -> &AnchorLogPayloadV1 {
        self.query.payload()
    }

    /// Returns the bound unsigned-transaction fingerprint.
    #[must_use]
    pub const fn fingerprint(&self) -> OotleAnchorInspectionFingerprintV1 {
        self.query.fingerprint()
    }

    /// Returns the recorded query state.
    #[must_use]
    pub const fn state(&self) -> AnchorReceiptQueryStateV1 {
        self.state
    }

    /// Returns the last observed finalized status, if any.
    #[must_use]
    pub const fn last_final_status(&self) -> Option<AnchorFinalStatusV1> {
        self.last_final_status
    }

    /// Returns whether the anchor was verified from a finalized full acceptance.
    #[must_use]
    pub const fn verified(&self) -> bool {
        self.verified
    }

    /// Returns the deterministic registration sequence.
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Returns the last bounded diagnostic code, if any.
    #[must_use]
    pub const fn last_diagnostic(&self) -> Option<&'static str> {
        self.last_diagnostic
    }
}

/// In-memory registry of receipt-query state, keyed by project request id.
#[derive(Debug, Default)]
pub struct LocalReceiptQueryRegistry {
    records: BTreeMap<AnchorRequestId, ReceiptQueryRecord>,
    sequence_counter: u64,
}

impl LocalReceiptQueryRegistry {
    /// Creates an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers (or idempotently returns) a submitted, not-yet-queried record.
    ///
    /// If a record already exists for the query's project request id it is left
    /// unchanged, so re-registering after a restart never rewinds progress.
    pub(crate) fn register_submitted(&mut self, query: AnchorReceiptQueryV1) {
        let project_request_id = query.project_request_id().clone();
        if self.records.contains_key(&project_request_id) {
            return;
        }
        let sequence = self.sequence_counter;
        self.sequence_counter = self.sequence_counter.wrapping_add(1);
        self.records.insert(
            project_request_id,
            ReceiptQueryRecord {
                query,
                state: AnchorReceiptQueryStateV1::SubmittedNotQueried,
                last_final_status: None,
                verified: false,
                sequence,
                last_diagnostic: None,
            },
        );
    }

    /// Updates the observed outcome of a stored record.
    pub(crate) fn set_outcome(
        &mut self,
        project_request_id: &AnchorRequestId,
        state: AnchorReceiptQueryStateV1,
        last_final_status: Option<AnchorFinalStatusV1>,
        verified: bool,
        diagnostic: Option<&'static str>,
    ) {
        if let Some(record) = self.records.get_mut(project_request_id) {
            record.state = state;
            if last_final_status.is_some() {
                record.last_final_status = last_final_status;
            }
            record.verified = verified;
            record.last_diagnostic = diagnostic;
        }
    }

    /// Returns the recorded query state for a project request id.
    #[must_use]
    pub fn state(&self, project_request_id: &AnchorRequestId) -> Option<AnchorReceiptQueryStateV1> {
        self.records
            .get(project_request_id)
            .map(|record| record.state)
    }

    /// Returns a recovery snapshot for one stored record.
    #[must_use]
    pub fn snapshot(
        &self,
        project_request_id: &AnchorRequestId,
    ) -> Option<AnchorReceiptQuerySnapshotV1> {
        let record = self.records.get(project_request_id)?;
        Some(AnchorReceiptQuerySnapshotV1::new(
            record.query.clone(),
            record.state,
            record.last_final_status,
            record.verified,
            record.sequence,
            record.last_diagnostic,
        ))
    }

    /// Returns recovery snapshots for every stored record, in request order.
    #[must_use]
    pub fn snapshots(&self) -> Vec<AnchorReceiptQuerySnapshotV1> {
        self.records
            .keys()
            .filter_map(|project_request_id| self.snapshot(project_request_id))
            .collect()
    }

    /// Rebuilds a registry from recovery snapshots, as after a restart.
    ///
    /// The sequence counter is restored to one past the highest imported
    /// sequence, so newly registered records continue deterministically.
    #[must_use]
    pub fn from_snapshots(snapshots: Vec<AnchorReceiptQuerySnapshotV1>) -> Self {
        let mut registry = Self::new();
        let mut highest_sequence: Option<u64> = None;

        for snapshot in snapshots {
            highest_sequence = Some(match highest_sequence {
                Some(current) => current.max(snapshot.sequence()),
                None => snapshot.sequence(),
            });
            registry.records.insert(
                snapshot.project_request_id().clone(),
                ReceiptQueryRecord {
                    query: snapshot.query().clone(),
                    state: snapshot.state(),
                    last_final_status: snapshot.last_final_status(),
                    verified: snapshot.verified(),
                    sequence: snapshot.sequence(),
                    last_diagnostic: snapshot.last_diagnostic(),
                },
            );
        }

        registry.sequence_counter = match highest_sequence {
            Some(highest) => highest.wrapping_add(1),
            None => 0,
        };
        registry
    }
}
