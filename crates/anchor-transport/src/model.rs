//! Project-owned lifecycle DTOs for the offline anchor-transport contract.
//!
//! These types model the confirmed walletd request lifecycle
//! (`create → approve → submit`), the observable finality outcomes, and the
//! independently retrievable receipt — all without importing any Tari Ootle
//! type. No DTO here can carry a private key, mnemonic, ballot, proof,
//! nullifier, registry key, or archive content.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};

use crate::identifiers::{
    AnchorAccountReference, AnchorClientReferenceV1, AnchorRequestId, AnchorTransactionId,
};
use crate::payload::AnchorLogPayloadV1;

/// Opaque maximum-fee ceiling, in the ledger's smallest unit.
///
/// Represented as a plain integer so it needs no Tari Ootle numeric type. It
/// bounds the only value the anchor transaction may spend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorMaxFeeV1(u64);

impl AnchorMaxFeeV1 {
    /// Wraps a maximum-fee ceiling.
    #[must_use]
    pub const fn from_units(value: u64) -> Self {
        Self(value)
    }

    /// Returns the maximum-fee ceiling.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Merged transaction lifecycle state (Section F).
///
/// Variants use the repository's CamelCase convention; `as_str` returns the
/// stable screaming-snake code. `RejectedByApprover` is the walletd approval-gate
/// rejection and is intentionally distinct from `FinalizedReject`, the ledger's
/// rejection of a submitted transaction. There is deliberately no `Signed`
/// state: the confirmed transaction identifier exists only after sealing during
/// submission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorLifecycleState {
    /// A request has been created and is awaiting approval.
    Prepared,
    /// A request has been approved but not yet submitted.
    Approved,
    /// The approver rejected the request; it will never be submitted.
    RejectedByApprover,
    /// The request was sealed and submitted; finality is not yet observed.
    Submitted,
    /// The transaction was fully accepted; the anchor landed.
    FinalizedAccept,
    /// Only the fee intent committed; the anchor did not land.
    FinalizedFeeOnly,
    /// The transaction was rejected by the ledger.
    FinalizedReject,
    /// The observable state is unknown, for example after a submit timeout.
    Unknown,
}

impl AnchorLifecycleState {
    /// Returns the stable machine-readable state code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "PREPARED",
            Self::Approved => "APPROVED",
            Self::RejectedByApprover => "REJECTED_BY_APPROVER",
            Self::Submitted => "SUBMITTED",
            Self::FinalizedAccept => "FINALIZED_ACCEPT",
            Self::FinalizedFeeOnly => "FINALIZED_FEE_ONLY",
            Self::FinalizedReject => "FINALIZED_REJECT",
            Self::Unknown => "UNKNOWN",
        }
    }
}

/// Approval-gate decision status, mirroring walletd's effective request status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorRequestDecisionV1 {
    /// Awaiting an approval decision.
    Pending,
    /// Approved and eligible for submission.
    Approved,
    /// Rejected by the approver.
    Rejected,
    /// The approval window closed before a terminal decision.
    Expired,
}

impl AnchorRequestDecisionV1 {
    /// Returns the stable machine-readable decision code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Expired => "EXPIRED",
        }
    }
}

/// Finalized ledger outcome recorded in a receipt.
///
/// A fee-only acceptance is a first-class, distinct outcome and must never be
/// treated as a successful anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorFinalStatusV1 {
    /// The whole transaction, including the anchor log, committed.
    Accepted,
    /// Only the fee intent committed; the main intent (the anchor) was rejected.
    FeeOnlyAccepted,
    /// The transaction was rejected.
    Rejected,
}

impl AnchorFinalStatusV1 {
    /// Returns the stable machine-readable status code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::FeeOnlyAccepted => "FEE_ONLY_ACCEPTED",
            Self::Rejected => "REJECTED",
        }
    }
}

/// Project-owned log level, mirroring the confirmed Ootle log levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorLogLevelV1 {
    /// Error level.
    Error,
    /// Warning level.
    Warn,
    /// Informational level.
    Info,
    /// Debug level.
    Debug,
}

impl AnchorLogLevelV1 {
    /// Returns the stable machine-readable level code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }
}

/// Which observer produced a receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AnchorReceiptSourceKindV1 {
    /// The controlling wallet daemon reported the receipt.
    #[default]
    Walletd,
    /// An independent indexer reported the receipt.
    IndependentIndexer,
}

impl AnchorReceiptSourceKindV1 {
    /// Returns the stable machine-readable source code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Walletd => "WALLETD",
            Self::IndependentIndexer => "INDEPENDENT_INDEXER",
        }
    }
}

/// One ordered receipt log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorLogEntryV1 {
    level: AnchorLogLevelV1,
    message: String,
}

impl AnchorLogEntryV1 {
    /// Creates one log entry.
    #[must_use]
    pub fn new(level: AnchorLogLevelV1, message: String) -> Self {
        Self { level, message }
    }

    /// Returns the log level.
    #[must_use]
    pub const fn level(&self) -> AnchorLogLevelV1 {
        self.level
    }

    /// Returns the log message text.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Immutable binding shared by preparation, approval, and submission.
///
/// It fixes the network, fee account, and anchor payload so an approval or
/// submission cannot be silently reused for a different anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorBindingV1 {
    network: OotleNetworkIdV1,
    account: AnchorAccountReference,
    payload: AnchorLogPayloadV1,
}

impl AnchorBindingV1 {
    /// Creates a binding over the network, account, and payload.
    #[must_use]
    pub fn new(
        network: OotleNetworkIdV1,
        account: AnchorAccountReference,
        payload: AnchorLogPayloadV1,
    ) -> Self {
        Self {
            network,
            account,
            payload,
        }
    }

    /// Returns the bound network.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the bound account reference.
    #[must_use]
    pub const fn account(&self) -> &AnchorAccountReference {
        &self.account
    }

    /// Returns the bound anchor log payload.
    #[must_use]
    pub const fn payload(&self) -> &AnchorLogPayloadV1 {
        &self.payload
    }

    /// Returns the bound anchor-record digest.
    #[must_use]
    pub fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.payload.digest()
    }
}

/// Input DTO for preparing an anchor transaction request (Section C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorPreparationRequest {
    binding: AnchorBindingV1,
    max_fee: AnchorMaxFeeV1,
    client_reference: Option<AnchorClientReferenceV1>,
}

impl AnchorPreparationRequest {
    /// Creates a preparation request.
    #[must_use]
    pub fn new(
        binding: AnchorBindingV1,
        max_fee: AnchorMaxFeeV1,
        client_reference: Option<AnchorClientReferenceV1>,
    ) -> Self {
        Self {
            binding,
            max_fee,
            client_reference,
        }
    }

    /// Returns the anchor binding.
    #[must_use]
    pub const fn binding(&self) -> &AnchorBindingV1 {
        &self.binding
    }

    /// Returns the maximum-fee ceiling.
    #[must_use]
    pub const fn max_fee(&self) -> AnchorMaxFeeV1 {
        self.max_fee
    }

    /// Returns the optional caller idempotency reference.
    #[must_use]
    pub const fn client_reference(&self) -> Option<&AnchorClientReferenceV1> {
        self.client_reference.as_ref()
    }
}

/// Output DTO for a prepared anchor transaction request (Section C).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedAnchorTransaction {
    request_id: AnchorRequestId,
    binding: AnchorBindingV1,
    max_fee: AnchorMaxFeeV1,
    state: AnchorLifecycleState,
}

impl PreparedAnchorTransaction {
    /// Creates a prepared-transaction result in the `Prepared` state.
    #[must_use]
    pub fn new(
        request_id: AnchorRequestId,
        binding: AnchorBindingV1,
        max_fee: AnchorMaxFeeV1,
    ) -> Self {
        Self {
            request_id,
            binding,
            max_fee,
            state: AnchorLifecycleState::Prepared,
        }
    }

    /// Returns the assigned request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &AnchorRequestId {
        &self.request_id
    }

    /// Returns the bound network, account, and payload.
    #[must_use]
    pub const fn binding(&self) -> &AnchorBindingV1 {
        &self.binding
    }

    /// Returns the anchor log payload.
    #[must_use]
    pub const fn payload(&self) -> &AnchorLogPayloadV1 {
        self.binding.payload()
    }

    /// Returns the bound anchor-record digest.
    #[must_use]
    pub fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.binding.anchor_digest()
    }

    /// Returns the maximum-fee ceiling.
    #[must_use]
    pub const fn max_fee(&self) -> AnchorMaxFeeV1 {
        self.max_fee
    }

    /// Returns the lifecycle state, always `Prepared`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }

    /// Renders a deterministic human-review summary.
    ///
    /// This is what a separately-permissioned approver would read before
    /// approving. It exposes only the network, fee account, anchor digest, fixed
    /// pilot purpose, and fee ceiling — never ballots, proofs, or secrets.
    #[must_use]
    pub fn human_review_summary(&self) -> String {
        format!(
            "anchor-request request_id={} network={} account={} anchor_digest={} purpose={} max_fee={}",
            self.request_id.as_str(),
            self.binding.network().as_str(),
            self.binding.account().as_str(),
            self.payload(),
            tari_cc_private_ballot_anchor::OOTLE_ANCHOR_PURPOSE_ID_V1,
            self.max_fee.value(),
        )
    }
}

/// Output DTO for an approved anchor transaction request (Section D).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedAnchorTransaction {
    request_id: AnchorRequestId,
    binding: AnchorBindingV1,
    state: AnchorLifecycleState,
}

impl ApprovedAnchorTransaction {
    /// Creates an approved-transaction result in the `Approved` state.
    #[must_use]
    pub fn new(request_id: AnchorRequestId, binding: AnchorBindingV1) -> Self {
        Self {
            request_id,
            binding,
            state: AnchorLifecycleState::Approved,
        }
    }

    /// Returns the request identifier this approval binds to.
    #[must_use]
    pub const fn request_id(&self) -> &AnchorRequestId {
        &self.request_id
    }

    /// Returns the bound network, account, and payload.
    #[must_use]
    pub const fn binding(&self) -> &AnchorBindingV1 {
        &self.binding
    }

    /// Returns the bound anchor-record digest.
    #[must_use]
    pub fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.binding.anchor_digest()
    }

    /// Returns the lifecycle state, always `Approved`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }
}

/// Output DTO for a submitted anchor transaction (Section E).
///
/// This carries the sealed transaction identifier but makes no finality claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedAnchorTransaction {
    request_id: AnchorRequestId,
    transaction_id: AnchorTransactionId,
    binding: AnchorBindingV1,
    state: AnchorLifecycleState,
}

impl SubmittedAnchorTransaction {
    /// Creates a submitted-transaction result in the `Submitted` state.
    #[must_use]
    pub fn new(
        request_id: AnchorRequestId,
        transaction_id: AnchorTransactionId,
        binding: AnchorBindingV1,
    ) -> Self {
        Self {
            request_id,
            transaction_id,
            binding,
            state: AnchorLifecycleState::Submitted,
        }
    }

    /// Returns the originating request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &AnchorRequestId {
        &self.request_id
    }

    /// Returns the sealed transaction identifier.
    #[must_use]
    pub const fn transaction_id(&self) -> &AnchorTransactionId {
        &self.transaction_id
    }

    /// Returns the bound network, account, and payload.
    #[must_use]
    pub const fn binding(&self) -> &AnchorBindingV1 {
        &self.binding
    }

    /// Returns the submitted anchor log payload.
    #[must_use]
    pub const fn payload(&self) -> &AnchorLogPayloadV1 {
        self.binding.payload()
    }

    /// Returns the bound anchor-record digest.
    #[must_use]
    pub fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.binding.anchor_digest()
    }

    /// Returns the lifecycle state, always `Submitted`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }
}

/// Independently observable receipt DTO (Section F).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceiptV1 {
    transaction_id: AnchorTransactionId,
    network: OotleNetworkIdV1,
    final_status: AnchorFinalStatusV1,
    logs: Vec<AnchorLogEntryV1>,
    rejection_reason: Option<String>,
    ledger_position: Option<u64>,
    source: AnchorReceiptSourceKindV1,
    // Absent for historical V1 log receipts. Present only when the v0.39.2
    // receipt converter copied bounded event facts for detached verification.
    event_proofs_v2: Vec<crate::event::AnchorEventProofV2>,
}

impl AnchorReceiptV1 {
    /// Creates a receipt DTO.
    #[must_use]
    pub fn new(
        transaction_id: AnchorTransactionId,
        network: OotleNetworkIdV1,
        final_status: AnchorFinalStatusV1,
        logs: Vec<AnchorLogEntryV1>,
        rejection_reason: Option<String>,
        ledger_position: Option<u64>,
        source: AnchorReceiptSourceKindV1,
    ) -> Self {
        Self {
            transaction_id,
            network,
            final_status,
            logs,
            rejection_reason,
            ledger_position,
            source,
            event_proofs_v2: Vec::new(),
        }
    }

    /// Returns the transaction identifier the receipt is for.
    #[must_use]
    pub const fn transaction_id(&self) -> &AnchorTransactionId {
        &self.transaction_id
    }

    /// Returns the network the receipt was observed on.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the finalized status.
    #[must_use]
    pub const fn final_status(&self) -> AnchorFinalStatusV1 {
        self.final_status
    }

    /// Returns the ordered receipt log entries.
    #[must_use]
    pub fn logs(&self) -> &[AnchorLogEntryV1] {
        &self.logs
    }

    /// Returns the optional opaque rejection reason.
    #[must_use]
    pub fn rejection_reason(&self) -> Option<&str> {
        self.rejection_reason.as_deref()
    }

    /// Returns the optional opaque ledger position.
    #[must_use]
    pub const fn ledger_position(&self) -> Option<u64> {
        self.ledger_position
    }

    /// Returns which observer produced the receipt.
    #[must_use]
    pub const fn source(&self) -> AnchorReceiptSourceKindV1 {
        self.source
    }

    /// Adds bounded v0.39.2 event facts while retaining the V1 constructor and
    /// V1 log-reader compatibility for historical archives.
    #[must_use]
    pub fn with_event_proofs_v2(mut self, event_proofs_v2: Vec<crate::event::AnchorEventProofV2>) -> Self {
        self.event_proofs_v2 = event_proofs_v2;
        self
    }

    /// Returns the raw bounded event facts copied from a v0.39.2 receipt.
    #[must_use]
    pub fn event_proofs_v2(&self) -> &[crate::event::AnchorEventProofV2] {
        &self.event_proofs_v2
    }
}

/// Outcome of querying a receipt source (Section F).
///
/// This distinguishes not-found, not-yet-finalized, finalized, and timeout /
/// unknown so callers never mistake absence or delay for a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorQueryOutcomeV1 {
    /// No receipt exists for the transaction yet.
    NotFound,
    /// The transaction exists but has not reached finality.
    NotFinalized,
    /// A finalized receipt was retrieved.
    Finalized(AnchorReceiptV1),
    /// The outcome is unknown, for example after a timeout.
    Unknown,
}

/// Deterministic local recovery snapshot (Section K).
///
/// This preserves only what a restart needs to resume the lifecycle safely. It
/// stores no archive content, ballots, proofs, or wallet secrets. Canonical
/// on-disk encoding is deliberately deferred to a later slice: the exact Ootle
/// identifier encodings are not yet pinned, so a canonical format now would be
/// premature. This DTO is deterministic and comparable, which is sufficient for
/// the offline recovery contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorLifecycleSnapshotV1 {
    request_id: AnchorRequestId,
    binding: AnchorBindingV1,
    lifecycle_state: AnchorLifecycleState,
    transaction_id: Option<AnchorTransactionId>,
    last_receipt_status: Option<AnchorFinalStatusV1>,
}

impl AnchorLifecycleSnapshotV1 {
    /// Creates a recovery snapshot.
    #[must_use]
    pub fn new(
        request_id: AnchorRequestId,
        binding: AnchorBindingV1,
        lifecycle_state: AnchorLifecycleState,
        transaction_id: Option<AnchorTransactionId>,
        last_receipt_status: Option<AnchorFinalStatusV1>,
    ) -> Self {
        Self {
            request_id,
            binding,
            lifecycle_state,
            transaction_id,
            last_receipt_status,
        }
    }

    /// Returns the request identifier.
    #[must_use]
    pub const fn request_id(&self) -> &AnchorRequestId {
        &self.request_id
    }

    /// Returns the bound network, account, and payload.
    #[must_use]
    pub const fn binding(&self) -> &AnchorBindingV1 {
        &self.binding
    }

    /// Returns the bound anchor-record digest.
    #[must_use]
    pub fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.binding.anchor_digest()
    }

    /// Returns the recorded lifecycle state.
    #[must_use]
    pub const fn lifecycle_state(&self) -> AnchorLifecycleState {
        self.lifecycle_state
    }

    /// Returns the sealed transaction identifier, if one is known.
    #[must_use]
    pub const fn transaction_id(&self) -> Option<&AnchorTransactionId> {
        self.transaction_id.as_ref()
    }

    /// Returns the last observed finalized status, if any.
    #[must_use]
    pub const fn last_receipt_status(&self) -> Option<AnchorFinalStatusV1> {
        self.last_receipt_status
    }
}
