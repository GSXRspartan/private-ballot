//! Project-owned mirror of the walletd effective request status (Sections A, E).
//!
//! [`WalletdEffectiveStatusV1`] mirrors the confirmed wallet-SDK `EffectiveStatus`
//! so the adapter and its offline fake speak a project-owned status vocabulary
//! and no wallet-SDK type appears in this crate's public API. `from_wire` is the
//! single, total mapping a future real client would use to translate the wire
//! status; it is exercised by an offline unit test.

use tari_ootle_wallet_sdk::models::EffectiveStatus;

/// Project-owned view of a walletd transaction request's effective status.
///
/// `Submitting` and `Submitted` are included for faithful mapping only. This
/// prepare/approve slice never drives a request into them, and observing either
/// during preparation or approval is treated as an unsupported/unexpected state
/// by the coordinator rather than a success.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletdEffectiveStatusV1 {
    /// Created, awaiting an approval decision.
    Pending,
    /// Approved by an approver and not yet submitted.
    Approved,
    /// Refused by an approver. Terminal.
    Rejected,
    /// A submitter holds the claim and is sealing/broadcasting.
    Submitting,
    /// Sealed and handed to the transaction service. Terminal.
    Submitted,
    /// The approval window closed before a terminal decision was reached.
    Expired,
}

impl WalletdEffectiveStatusV1 {
    /// Returns the stable machine-readable status code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::Submitting => "SUBMITTING",
            Self::Submitted => "SUBMITTED",
            Self::Expired => "EXPIRED",
        }
    }

    /// Total mapping from the confirmed wallet-SDK wire status.
    ///
    /// A future real client uses this to translate a `TransactionRequestDecisionResponse`
    /// or `TransactionRequestGetResponse` status into the project vocabulary.
    #[must_use]
    pub const fn from_wire(status: EffectiveStatus) -> Self {
        match status {
            EffectiveStatus::Pending => Self::Pending,
            EffectiveStatus::Approved => Self::Approved,
            EffectiveStatus::Rejected => Self::Rejected,
            EffectiveStatus::Submitting => Self::Submitting,
            EffectiveStatus::Submitted => Self::Submitted,
            EffectiveStatus::Expired => Self::Expired,
        }
    }
}
