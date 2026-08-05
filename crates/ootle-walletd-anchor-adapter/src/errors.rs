//! Narrow, project-owned walletd adapter errors (Section H).
//!
//! Every variant is a bounded, self-describing project error. No variant carries
//! a raw walletd/reqwest error value, a private key, a mnemonic, an account
//! reference, or any other secret: diagnostics are fixed strings or the already
//! bounded, project-owned Slice 4A5 construction error. This keeps `Debug` and
//! `Display` safe to log and satisfies "do not expose unbounded third-party
//! error text".

use core::fmt;

use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorAdapterError;

/// Bounded error returned by the pinned walletd prepare/approve adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletdAnchorAdapterError {
    /// The wallet daemon could not be reached at all.
    WalletdUnavailable,
    /// A transport-level failure occurred while talking to walletd.
    TransportFailure,
    /// The walletd response could not be parsed into the expected shape.
    MalformedResponse,
    /// Walletd refused to create the transaction request.
    RequestCreationRejected,
    /// No walletd request matched the supplied identifier.
    RequestNotFound,
    /// Walletd refused the approval decision.
    ApprovalRejected,
    /// The request had already been approved.
    RequestAlreadyApproved,
    /// The request had already been rejected.
    RequestAlreadyRejected,
    /// The approval window had already expired.
    RequestExpired,
    /// A supplied binding field differed from the stored request.
    BindingMismatch,
    /// The bound network did not match the stored request.
    NetworkMismatch,
    /// The bound fee account did not match the stored request.
    AccountMismatch,
    /// The bound anchor payload/digest did not match the stored request.
    PayloadMismatch,
    /// The bound maximum fee did not match the stored request.
    FeeMismatch,
    /// The bound unsigned-transaction fingerprint did not match the stored one.
    FingerprintMismatch,
    /// The bound project and walletd request identifiers did not correspond.
    RequestIdMismatch,
    /// The unsigned transaction failed the re-run Slice 4A5 safety inspection.
    ///
    /// The wrapped value is the already-bounded, project-owned construction
    /// error; it carries no secret and no third-party text.
    UnsafeUnsignedTransaction(OotleAnchorAdapterError),
    /// Walletd reported a status or shape this adapter version does not support.
    UnsupportedWalletdApi {
        /// Fixed, non-secret detail text.
        detail: &'static str,
    },
}

impl WalletdAnchorAdapterError {
    /// Returns a stable machine-readable code for the error category.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::WalletdUnavailable => "WALLETD_UNAVAILABLE",
            Self::TransportFailure => "WALLETD_TRANSPORT_FAILURE",
            Self::MalformedResponse => "WALLETD_MALFORMED_RESPONSE",
            Self::RequestCreationRejected => "WALLETD_REQUEST_CREATION_REJECTED",
            Self::RequestNotFound => "WALLETD_REQUEST_NOT_FOUND",
            Self::ApprovalRejected => "WALLETD_APPROVAL_REJECTED",
            Self::RequestAlreadyApproved => "WALLETD_REQUEST_ALREADY_APPROVED",
            Self::RequestAlreadyRejected => "WALLETD_REQUEST_ALREADY_REJECTED",
            Self::RequestExpired => "WALLETD_REQUEST_EXPIRED",
            Self::BindingMismatch => "WALLETD_BINDING_MISMATCH",
            Self::NetworkMismatch => "WALLETD_NETWORK_MISMATCH",
            Self::AccountMismatch => "WALLETD_ACCOUNT_MISMATCH",
            Self::PayloadMismatch => "WALLETD_PAYLOAD_MISMATCH",
            Self::FeeMismatch => "WALLETD_FEE_MISMATCH",
            Self::FingerprintMismatch => "WALLETD_FINGERPRINT_MISMATCH",
            Self::RequestIdMismatch => "WALLETD_REQUEST_ID_MISMATCH",
            Self::UnsafeUnsignedTransaction(_) => "WALLETD_UNSAFE_UNSIGNED_TRANSACTION",
            Self::UnsupportedWalletdApi { .. } => "WALLETD_UNSUPPORTED_API",
        }
    }
}

impl fmt::Display for WalletdAnchorAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsafeUnsignedTransaction(source) => {
                write!(formatter, "{}: {source}", self.as_str())
            }
            Self::UnsupportedWalletdApi { detail } => {
                write!(formatter, "{}: {detail}", self.as_str())
            }
            other => formatter.write_str(other.as_str()),
        }
    }
}

impl std::error::Error for WalletdAnchorAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::UnsafeUnsignedTransaction(source) => Some(source),
            _ => None,
        }
    }
}
