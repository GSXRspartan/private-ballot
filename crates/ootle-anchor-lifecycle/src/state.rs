//! Unified lifecycle state (Section C).
//!
//! [`UnifiedAnchorLifecyclePhase`] is the project-owned unified state whose
//! terminal vocabulary is drawn from the existing merged
//! [`AnchorLifecycleState`](tari_cc_private_ballot_anchor_transport::AnchorLifecycleState)
//! — that enum is *not* redefined here. The unified phase extends it with the
//! extra dimensions Sections C/D/G require:
//!
//! * [`NotPrepared`](UnifiedAnchorLifecyclePhase::NotPrepared) — before any
//!   prepare (no `AnchorLifecycleState` variant exists for this; maps to
//!   `None`).
//! * [`PollingInProgress`](UnifiedAnchorLifecyclePhase::PollingInProgress) —
//!   submitted and mid-poll within the attempt bound (maps to
//!   [`Submitted`](tari_cc_private_ballot_anchor_transport::AnchorLifecycleState::Submitted)).
//! * [`FinalizedVerificationFailed`](UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed)
//!   — a finalized full acceptance failed anchor verification. This is a
//!   distinct non-success terminal; it is *never*
//!   [`FinalizedAccept`](tari_cc_private_ballot_anchor_transport::AnchorLifecycleState::FinalizedAccept)
//!   and `is_terminal_success` is always `false` for it.
//! * [`FinalizedDisagreement`](UnifiedAnchorLifecyclePhase::FinalizedDisagreement)
//!   — the walletd/indexer agreement check disagreed. This surfaces the
//!   disagreement as a distinct non-success reporting terminal *without*
//!   mutating the underlying verified artifacts.
//!
//! Every terminal is idempotent: re-driving a terminal phase is a no-op that
//! never rewinds, never resubmits, and never creates a second distinct
//! transaction.

use tari_cc_private_ballot_anchor_transport::AnchorLifecycleState;

/// The unified, project-owned lifecycle phase for one anchor.
///
/// It extends the merged `AnchorLifecycleState` with `NotPrepared`,
/// `PollingInProgress`, `FinalizedVerificationFailed`, and
/// `FinalizedDisagreement`. It maps cleanly onto `AnchorLifecycleState` for
/// reporting via [`to_anchor_lifecycle_state`](Self::to_anchor_lifecycle_state).
/// The mapping is a total function: every phase maps to either `Some(state)` or
/// `None` (only `NotPrepared` maps to `None`).
///
/// A verification failure and a disagreement are *never* mapped to
/// `FinalizedAccept`: they map to `Unknown` (the closest non-success
/// `AnchorLifecycleState` variant) so they can never be reported as success.
/// The precise signal is carried by the distinct variant itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum UnifiedAnchorLifecyclePhase {
    /// No prepare has been issued yet.
    #[default]
    NotPrepared,
    /// A walletd request has been created and is awaiting an approval decision.
    Prepared,
    /// The request has been approved and is awaiting submission.
    Approved,
    /// The approver rejected the request. Terminal.
    RejectedByApprover,
    /// The request was sealed and submitted; finality is not yet observed.
    Submitted,
    /// Submitted and mid-poll: at least one receipt query has been issued and
    /// the attempt bound is not yet exhausted.
    PollingInProgress,
    /// The receipt showed a full acceptance and the anchor verified. Terminal
    /// success.
    FinalizedAccept,
    /// The receipt showed only the fee intent committed; the anchor did not
    /// land. Terminal, non-success.
    FinalizedFeeOnly,
    /// The receipt showed a ledger rejection. Terminal, non-success.
    FinalizedReject,
    /// A finalized full acceptance failed anchor verification (missing,
    /// malformed, wrong-digest, duplicate, or conflicting project anchor log).
    /// Terminal, non-success — never `FinalizedAccept`.
    FinalizedVerificationFailed,
    /// The walletd/indexer agreement check disagreed. Terminal for reporting;
    /// does not mutate the underlying verified artifacts.
    FinalizedDisagreement,
    /// The observable state is unknown (for example after a submit timeout or
    /// poll-exhaustion). Resumable, never a permanent failure.
    Unknown,
}

impl UnifiedAnchorLifecyclePhase {
    /// Returns the stable machine-readable phase code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotPrepared => "NOT_PREPARED",
            Self::Prepared => "PREPARED",
            Self::Approved => "APPROVED",
            Self::RejectedByApprover => "REJECTED_BY_APPROVER",
            Self::Submitted => "SUBMITTED",
            Self::PollingInProgress => "POLLING_IN_PROGRESS",
            Self::FinalizedAccept => "FINALIZED_ACCEPT",
            Self::FinalizedFeeOnly => "FINALIZED_FEE_ONLY",
            Self::FinalizedReject => "FINALIZED_REJECT",
            Self::FinalizedVerificationFailed => "FINALIZED_VERIFICATION_FAILED",
            Self::FinalizedDisagreement => "FINALIZED_DISAGREEMENT",
            Self::Unknown => "UNKNOWN",
        }
    }

    /// Maps the unified phase onto the merged `AnchorLifecycleState` for
    /// reporting.
    ///
    /// Returns `None` only for [`NotPrepared`](Self::NotPrepared). A
    /// verification failure or disagreement maps to
    /// [`Unknown`](AnchorLifecycleState::Unknown) — the closest non-success
    /// variant — so it is never reported as
    /// [`FinalizedAccept`](AnchorLifecycleState::FinalizedAccept).
    #[must_use]
    pub const fn to_anchor_lifecycle_state(self) -> Option<AnchorLifecycleState> {
        match self {
            Self::NotPrepared => None,
            Self::Prepared => Some(AnchorLifecycleState::Prepared),
            Self::Approved => Some(AnchorLifecycleState::Approved),
            Self::RejectedByApprover => Some(AnchorLifecycleState::RejectedByApprover),
            Self::Submitted | Self::PollingInProgress => Some(AnchorLifecycleState::Submitted),
            Self::FinalizedAccept => Some(AnchorLifecycleState::FinalizedAccept),
            Self::FinalizedFeeOnly => Some(AnchorLifecycleState::FinalizedFeeOnly),
            Self::FinalizedReject => Some(AnchorLifecycleState::FinalizedReject),
            Self::FinalizedVerificationFailed | Self::FinalizedDisagreement => {
                Some(AnchorLifecycleState::Unknown)
            }
            Self::Unknown => Some(AnchorLifecycleState::Unknown),
        }
    }

    /// Returns whether the phase is terminal (no further step can change it).
    ///
    /// `Unknown` is *not* terminal: it is resumable (recover or continue
    /// polling within the remaining attempt bound).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::RejectedByApprover
                | Self::FinalizedAccept
                | Self::FinalizedFeeOnly
                | Self::FinalizedReject
                | Self::FinalizedVerificationFailed
                | Self::FinalizedDisagreement
        )
    }

    /// Returns whether the phase is a terminal *success*.
    ///
    /// Only [`FinalizedAccept`](Self::FinalizedAccept) is a terminal success. A
    /// verification failure, disagreement, fee-only, rejection, or unknown is
    /// never a success.
    #[must_use]
    pub const fn is_terminal_success(self) -> bool {
        matches!(self, Self::FinalizedAccept)
    }

    /// Returns whether the phase is resumable (not terminal).
    #[must_use]
    pub const fn is_resumable(self) -> bool {
        !self.is_terminal()
    }
}

#[cfg(test)]
mod tests {
    use super::UnifiedAnchorLifecyclePhase as P;
    use tari_cc_private_ballot_anchor_transport::AnchorLifecycleState as S;

    #[test]
    fn not_prepared_maps_to_none() {
        assert_eq!(P::NotPrepared.to_anchor_lifecycle_state(), None);
    }

    #[test]
    fn prepared_through_submitted_map_cleanly() {
        assert_eq!(P::Prepared.to_anchor_lifecycle_state(), Some(S::Prepared));
        assert_eq!(P::Approved.to_anchor_lifecycle_state(), Some(S::Approved));
        assert_eq!(
            P::RejectedByApprover.to_anchor_lifecycle_state(),
            Some(S::RejectedByApprover)
        );
        assert_eq!(P::Submitted.to_anchor_lifecycle_state(), Some(S::Submitted));
        assert_eq!(
            P::PollingInProgress.to_anchor_lifecycle_state(),
            Some(S::Submitted)
        );
    }

    #[test]
    fn finalized_terminals_map_cleanly() {
        assert_eq!(
            P::FinalizedAccept.to_anchor_lifecycle_state(),
            Some(S::FinalizedAccept)
        );
        assert_eq!(
            P::FinalizedFeeOnly.to_anchor_lifecycle_state(),
            Some(S::FinalizedFeeOnly)
        );
        assert_eq!(
            P::FinalizedReject.to_anchor_lifecycle_state(),
            Some(S::FinalizedReject)
        );
    }

    #[test]
    fn verification_failure_and_disagreement_never_map_to_accept() {
        assert_ne!(
            P::FinalizedVerificationFailed.to_anchor_lifecycle_state(),
            Some(S::FinalizedAccept)
        );
        assert_ne!(
            P::FinalizedDisagreement.to_anchor_lifecycle_state(),
            Some(S::FinalizedAccept)
        );
        assert_eq!(
            P::FinalizedVerificationFailed.to_anchor_lifecycle_state(),
            Some(S::Unknown)
        );
        assert_eq!(
            P::FinalizedDisagreement.to_anchor_lifecycle_state(),
            Some(S::Unknown)
        );
    }

    #[test]
    fn only_finalized_accept_is_terminal_success() {
        assert!(P::FinalizedAccept.is_terminal_success());
        assert!(!P::FinalizedFeeOnly.is_terminal_success());
        assert!(!P::FinalizedReject.is_terminal_success());
        assert!(!P::FinalizedVerificationFailed.is_terminal_success());
        assert!(!P::FinalizedDisagreement.is_terminal_success());
        assert!(!P::Unknown.is_terminal_success());
    }

    #[test]
    fn unknown_is_resumable_not_terminal() {
        assert!(!P::Unknown.is_terminal());
        assert!(P::Unknown.is_resumable());
        assert!(!P::PollingInProgress.is_terminal());
        assert!(P::PollingInProgress.is_resumable());
    }

    #[test]
    fn terminals_are_terminal() {
        assert!(P::RejectedByApprover.is_terminal());
        assert!(P::FinalizedAccept.is_terminal());
        assert!(P::FinalizedFeeOnly.is_terminal());
        assert!(P::FinalizedReject.is_terminal());
        assert!(P::FinalizedVerificationFailed.is_terminal());
        assert!(P::FinalizedDisagreement.is_terminal());
    }
}
