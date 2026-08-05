//! Lifecycle step report and outcome (Section A).
//!
//! Each orchestrator step returns a [`LifecycleStepReport`] recording the
//! unified phase, the last coordinator outcome, the attempts consumed, and a
//! bounded diagnostic. A report never carries a wallet secret, ballot, archive,
//! or pinned Ootle type — only project-owned enums and bounded diagnostic
//! strings.

use crate::policy::PollingPolicy;
use crate::state::UnifiedAnchorLifecyclePhase;

/// The bounded outcome of one orchestrator step.
///
/// It names which coordinator method ran and what it produced, without exposing
/// any internal mutable state or any pinned Ootle type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleStepOutcome {
    /// `prepare_fee_bearing` succeeded and recorded a `Prepared` request.
    Prepared,
    /// `approve` succeeded.
    Approved,
    /// `reject` succeeded; the request is terminal-rejected.
    RejectedByApprover,
    /// `submit` succeeded and sealed a transaction id.
    Submitted,
    /// `recover` ran and returned this walletd recovery classification.
    Recovered(LifecycleRecoveryOutcome),
    /// `advance_one_poll` ran and returned this receipt-query state.
    Polled(LifecycleReceiptQueryOutcome),
    /// `check_agreement` ran and the two sources agreed.
    AgreementOk,
    /// `check_agreement` ran and the two sources disagreed.
    AgreementDisagreed,
    /// The step was a no-op: the lifecycle is already terminal or in a state
    /// where the step has no effect. No coordinator method was called.
    IdempotentNoOp,
    /// The step was blocked by the polling policy: the attempt bound is
    /// exhausted. The lifecycle is resumable as `Unknown`, never a permanent
    /// failure.
    PolicyExhausted,
}

/// The walletd recovery outcome carried in a step report.
///
/// This is a project-owned copy of the walletd recovery classification,
/// surfaced without the full recovered request (which carries a binding the
/// report does not need to repeat). It is derived solely from the walletd
/// coordinator's [`WalletdRecoveryStateV1`].
///
/// [`WalletdRecoveryStateV1`]: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdRecoveryStateV1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleRecoveryOutcome {
    /// Walletd shows the request submitted; the recovered transaction id is
    /// bound.
    Submitted,
    /// Walletd still shows the request approved: it never sealed, so a
    /// controlled retry is safe.
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

impl LifecycleRecoveryOutcome {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submitted => "RECOVERED_SUBMITTED",
            Self::NotSubmittedRetryable => "RECOVERED_NOT_SUBMITTED_RETRYABLE",
            Self::SubmissionInProgress => "RECOVERED_SUBMISSION_IN_PROGRESS",
            Self::Pending => "RECOVERED_PENDING",
            Self::RejectedByApprover => "RECOVERED_REJECTED_BY_APPROVER",
            Self::Expired => "RECOVERED_EXPIRED",
        }
    }
}

/// The receipt-query outcome carried in a step report.
///
/// This is a project-owned copy of the receipt-query state, surfaced without the
/// full report (which carries a receipt the step report does not need to
/// repeat). It is derived solely from the receipt coordinator's
/// [`AnchorReceiptQueryStateV1`].
///
/// [`AnchorReceiptQueryStateV1`]: tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryStateV1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LifecycleReceiptQueryOutcome {
    /// Submitted, but no receipt has been queried yet.
    SubmittedNotQueried,
    /// A query returned no receipt or result for the transaction.
    ReceiptNotFound,
    /// A query showed the transaction known but not yet finalized.
    ReceiptPending,
    /// A query could not resolve the state, for example after a timeout.
    ReceiptUnknown,
    /// A finalized receipt showed a full acceptance and the anchor verified.
    ReceiptFinalizedAccept,
    /// A finalized receipt showed only the fee intent committed. Terminal.
    ReceiptFinalizedFeeOnly,
    /// A finalized receipt showed a ledger rejection. Terminal.
    ReceiptFinalizedReject,
    /// A finalized full acceptance failed anchor verification. Terminal,
    /// non-success.
    ReceiptVerificationFailed,
}

impl LifecycleReceiptQueryOutcome {
    /// Returns the stable machine-readable code.
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
}

/// The report returned from one orchestrator step.
///
/// It records the unified phase, the last coordinator outcome, the attempts
/// consumed and remaining, and a bounded diagnostic. It is comparable and
/// deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleStepReport {
    phase: UnifiedAnchorLifecyclePhase,
    outcome: LifecycleStepOutcome,
    attempts_consumed: u32,
    attempts_remaining: u32,
    diagnostic: Option<&'static str>,
}

impl LifecycleStepReport {
    /// Assembles a step report from its parts.
    #[must_use]
    pub fn new(
        phase: UnifiedAnchorLifecyclePhase,
        outcome: LifecycleStepOutcome,
        policy: PollingPolicy,
        diagnostic: Option<&'static str>,
    ) -> Self {
        Self {
            phase,
            outcome,
            attempts_consumed: policy.attempts_consumed(),
            attempts_remaining: policy.attempts_remaining(),
            diagnostic,
        }
    }

    /// Returns the unified lifecycle phase after this step.
    #[must_use]
    pub const fn phase(&self) -> UnifiedAnchorLifecyclePhase {
        self.phase
    }

    /// Returns the bounded outcome of this step.
    #[must_use]
    pub const fn outcome(&self) -> &LifecycleStepOutcome {
        &self.outcome
    }

    /// Returns the number of polling attempts consumed so far.
    #[must_use]
    pub const fn attempts_consumed(&self) -> u32 {
        self.attempts_consumed
    }

    /// Returns the number of polling attempts remaining within the bound.
    #[must_use]
    pub const fn attempts_remaining(&self) -> u32 {
        self.attempts_remaining
    }

    /// Returns the last bounded diagnostic code, if any.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&'static str> {
        self.diagnostic
    }
}
