//! Bounded, stable machine report codes for the application driver and binary.
//!
//! Every code is a fixed `&'static str` with no raw third-party error text, no
//! credential leakage, and no secret material. The binary prints these codes
//! alongside the human-review summary so that operators and downstream tooling
//! can match outcomes without parsing prose.

/// Stable machine-readable outcome codes for the anchor application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MachineReportCode {
    /// The request was prepared and is awaiting an approval decision.
    Prepared,
    /// The request was approved by the operator.
    Approved,
    /// The request was rejected by the operator before submission.
    RejectedByApprover,
    /// The request was sealed and submitted.
    Submitted,
    /// A previously-unknown submission state was recovered.
    Recovered,
    /// A receipt poll is in progress.
    Polling,
    /// The anchor was verified as finalized and accepted.
    FinalizedAccept,
    /// The anchor finalized fee-only (the anchor did not land).
    FinalizedFeeOnly,
    /// The anchor was finalized as rejected by the ledger.
    FinalizedReject,
    /// Verification of a finalized receipt failed.
    VerificationFailed,
    /// The walletd and indexer observations disagree.
    Disagreement,
    /// Polling exhausted before finality was observed.
    PollExhaustedUnknown,
    /// The run stopped at a non-terminal, resumable state.
    NotYetFinalized,
    /// Configuration loading or validation failed.
    ConfigurationFailure,
    /// Snapshot reading or writing failed.
    SnapshotFailure,
    /// Evidence construction or writing failed.
    EvidenceFailure,
    /// A transport-level failure occurred while driving the adapters.
    TransportFailure,
}

impl MachineReportCode {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "ANCHOR_APP_PREPARED",
            Self::Approved => "ANCHOR_APP_APPROVED",
            Self::RejectedByApprover => "ANCHOR_APP_REJECTED_BY_APPROVER",
            Self::Submitted => "ANCHOR_APP_SUBMITTED",
            Self::Recovered => "ANCHOR_APP_RECOVERED",
            Self::Polling => "ANCHOR_APP_POLLING",
            Self::FinalizedAccept => "ANCHOR_APP_FINALIZED_ACCEPT",
            Self::FinalizedFeeOnly => "ANCHOR_APP_FINALIZED_FEE_ONLY",
            Self::FinalizedReject => "ANCHOR_APP_FINALIZED_REJECT",
            Self::VerificationFailed => "ANCHOR_APP_VERIFICATION_FAILED",
            Self::Disagreement => "ANCHOR_APP_DISAGREEMENT",
            Self::PollExhaustedUnknown => "ANCHOR_APP_POLL_EXHAUSTED_UNKNOWN",
            Self::NotYetFinalized => "ANCHOR_APP_NOT_YET_FINALIZED",
            Self::ConfigurationFailure => "ANCHOR_APP_CONFIGURATION_FAILURE",
            Self::SnapshotFailure => "ANCHOR_APP_SNAPSHOT_FAILURE",
            Self::EvidenceFailure => "ANCHOR_APP_EVIDENCE_FAILURE",
            Self::TransportFailure => "ANCHOR_APP_TRANSPORT_FAILURE",
        }
    }
}

impl core::fmt::Display for MachineReportCode {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}
