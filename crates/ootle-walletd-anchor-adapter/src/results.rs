//! Project-owned lifecycle results (Sections C, D, E, F).
//!
//! These DTOs report only confirmed data. None claims a signature, a transaction
//! identifier, submission, acceptance, or finality: on the confirmed walletd API
//! a transaction identifier exists only after `transaction_requests.submit`
//! (Slice 4A6B), and the approval/rejection responses carry no identifier at all.
//! The account reference and walletd request identifier redact their own `Debug`.

use tari_cc_private_ballot_anchor::OOTLE_ANCHOR_PURPOSE_ID_V1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorLifecycleState, AnchorRequestId, AnchorTransactionId,
};

use crate::binding::WalletdAnchorBindingV1;
use crate::convert::to_lower_hex_32;
use crate::identifiers::WalletdRequestId;

/// A prepared walletd anchor request, in the `Prepared` lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    instruction_count: usize,
    fee_present: bool,
    expires_at: i64,
    state: AnchorLifecycleState,
}

impl PreparedWalletdAnchorRequestV1 {
    /// Assembles a prepared result in the `Prepared` state.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
        instruction_count: usize,
        fee_present: bool,
        expires_at: i64,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            instruction_count,
            fee_present,
            expires_at,
            state: AnchorLifecycleState::Prepared,
        }
    }

    /// Returns whether the frozen transaction carries a `pay_fee` instruction.
    ///
    /// True for a fee-bearing (submittable) request, false for the legacy
    /// fee-less request retained only for the approval-gate reference path.
    #[must_use]
    pub const fn fee_present(&self) -> bool {
        self.fee_present
    }

    /// Returns the deterministic project request identifier.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the number of normal instructions in the frozen transaction.
    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    /// Returns the walletd-reported approval-window expiry (unix seconds).
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the lifecycle state, always `Prepared`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }

    /// Renders a deterministic, bounded human-review summary (Section D).
    ///
    /// It derives entirely from the inspected transaction binding: the fixed
    /// pilot purpose, network, fee account, maximum fee, exact 64-character
    /// anchor digest, exact tagged `EmitLog` payload, and instruction count. It
    /// states explicitly that no transaction identifier exists yet and that no
    /// voter or ballot data is present. It contains no caller-supplied prose.
    #[must_use]
    pub fn human_review_summary(&self) -> String {
        // The fee instruction that will actually be sealed: a fee-bearing request
        // pays exactly `max_fee` from the fee account via `pay_fee_from_component`;
        // a legacy fee-less request carries none.
        let fee_instruction = if self.fee_present {
            "pay_fee_from_component"
        } else {
            "NONE"
        };
        format!(
            "walletd-anchor-request purpose={} network={} fee_account={} max_fee={} \
fee_instruction={} anchor_digest={} emit_log_payload={} instruction_count={} \
transaction_id=NONE_YET voter_or_ballot_data=NONE",
            OOTLE_ANCHOR_PURPOSE_ID_V1,
            self.binding.network().as_str(),
            self.binding.account().as_str(),
            self.binding.max_fee().value(),
            fee_instruction,
            to_lower_hex_32(self.binding.anchor_digest().as_bytes()),
            self.binding.payload().to_encoded_string(),
            self.instruction_count,
        )
    }
}

/// An approved walletd anchor request, in the `Approved` lifecycle state.
///
/// Approval is a gate decision only: it claims no signature bytes, no
/// transaction identifier, no submission, and no finality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    state: AnchorLifecycleState,
}

impl ApprovedWalletdAnchorRequestV1 {
    /// Assembles an approved result in the `Approved` state.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            state: AnchorLifecycleState::Approved,
        }
    }

    /// Returns the project request identifier this approval binds to.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the lifecycle state, always `Approved`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }
}

/// A rejected walletd anchor request, in the `RejectedByApprover` state.
///
/// Rejection is terminal for this adapter: a rejected request can never be
/// approved through the coordinator. It produces no transaction identifier and
/// touches no archive or anchor artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    state: AnchorLifecycleState,
}

impl RejectedWalletdAnchorRequestV1 {
    /// Assembles a rejected result in the `RejectedByApprover` state.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            state: AnchorLifecycleState::RejectedByApprover,
        }
    }

    /// Returns the project request identifier this rejection binds to.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the lifecycle state, always `RejectedByApprover`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }
}

/// A submitted walletd anchor request, in the `Submitted` lifecycle state.
///
/// This is the first result that carries a transaction id, because a transaction
/// id exists only after walletd seals the frozen transaction at submit. It makes
/// no finality claim: the transaction is submitted, not accepted, finalized, or
/// receipt-verified. Retrieving a receipt is a later slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubmittedWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    transaction_id: AnchorTransactionId,
    binding: WalletdAnchorBindingV1,
    state: AnchorLifecycleState,
}

impl SubmittedWalletdAnchorRequestV1 {
    /// Assembles a submitted result in the `Submitted` state.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        transaction_id: AnchorTransactionId,
        binding: WalletdAnchorBindingV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            transaction_id,
            binding,
            state: AnchorLifecycleState::Submitted,
        }
    }

    /// Returns the project request identifier this submission binds to.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the sealed transaction identifier.
    #[must_use]
    pub const fn transaction_id(&self) -> &AnchorTransactionId {
        &self.transaction_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the lifecycle state, always `Submitted`.
    #[must_use]
    pub const fn state(&self) -> AnchorLifecycleState {
        self.state
    }
}

/// The recovery classification of a request whose submit result was lost.
///
/// Derived only from the confirmed walletd effective status observed on a status
/// lookup, never invented. It distinguishes the states that decide whether a
/// controlled retry is safe from the states that are terminal or still in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletdRecoveryStateV1 {
    /// Walletd shows the request submitted; the recovered transaction id is bound.
    Submitted(AnchorTransactionId),
    /// Walletd still shows the request approved: it never sealed, so a controlled
    /// retry is safe.
    NotSubmittedRetryable,
    /// Walletd shows a submit claim in progress: still in flight, never retry.
    SubmissionInProgress,
    /// Walletd shows the request pending an approval decision.
    Pending,
    /// Walletd shows the request rejected by an approver. Terminal.
    RejectedByApprover,
    /// Walletd shows the approval window closed before a terminal decision.
    Expired,
}

impl WalletdRecoveryStateV1 {
    /// Returns the stable machine-readable recovery-state code.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Submitted(_) => "SUBMITTED",
            Self::NotSubmittedRetryable => "NOT_SUBMITTED_RETRYABLE",
            Self::SubmissionInProgress => "SUBMISSION_IN_PROGRESS",
            Self::Pending => "PENDING",
            Self::RejectedByApprover => "REJECTED_BY_APPROVER",
            Self::Expired => "EXPIRED",
        }
    }

    /// Returns the merged lifecycle state this recovery maps to.
    #[must_use]
    pub const fn lifecycle_state(&self) -> AnchorLifecycleState {
        match self {
            Self::Submitted(_) => AnchorLifecycleState::Submitted,
            Self::NotSubmittedRetryable => AnchorLifecycleState::Approved,
            // Still-in-flight and not-yet-decided requests are, observably,
            // unresolved from the caller's perspective.
            Self::SubmissionInProgress | Self::Pending => AnchorLifecycleState::Unknown,
            Self::RejectedByApprover => AnchorLifecycleState::RejectedByApprover,
            Self::Expired => AnchorLifecycleState::Unknown,
        }
    }
}

/// The outcome of recovering a request after a lost submit result (Section F/H).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredWalletdAnchorRequestV1 {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    binding: WalletdAnchorBindingV1,
    state: WalletdRecoveryStateV1,
}

impl RecoveredWalletdAnchorRequestV1 {
    /// Assembles a recovery outcome.
    #[must_use]
    pub(crate) fn new(
        project_request_id: AnchorRequestId,
        walletd_request_id: WalletdRequestId,
        binding: WalletdAnchorBindingV1,
        state: WalletdRecoveryStateV1,
    ) -> Self {
        Self {
            project_request_id,
            walletd_request_id,
            binding,
            state,
        }
    }

    /// Returns the project request identifier this recovery binds to.
    #[must_use]
    pub const fn project_request_id(&self) -> &AnchorRequestId {
        &self.project_request_id
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the frozen project-owned binding.
    #[must_use]
    pub const fn binding(&self) -> &WalletdAnchorBindingV1 {
        &self.binding
    }

    /// Returns the recovery classification.
    #[must_use]
    pub const fn state(&self) -> &WalletdRecoveryStateV1 {
        &self.state
    }

    /// Returns the recovered transaction id, if the request was submitted.
    #[must_use]
    pub const fn transaction_id(&self) -> Option<&AnchorTransactionId> {
        match &self.state {
            WalletdRecoveryStateV1::Submitted(transaction_id) => Some(transaction_id),
            _ => None,
        }
    }
}
