//! Narrow, project-owned adapter errors (Section G).
//!
//! Every variant is a bounded, self-describing project error. No variant carries
//! a raw third-party error value, a private key, an account reference, or any
//! other secret: diagnostics are fixed strings or already-bounded, non-secret
//! network identifiers. This keeps `Debug` and `Display` safe to log.

use core::fmt;

/// Bounded error returned by the pinned Ootle anchor transaction adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OotleAnchorAdapterError {
    /// The project network identifier is not in the supported testnet mapping.
    ///
    /// The rejected identifier is echoed for diagnostics; it is a bounded,
    /// validated, non-secret network name.
    UnsupportedNetwork {
        /// The exact rejected network identifier text.
        requested: String,
    },
    /// The requested fee configuration is not valid for the chosen architecture.
    InvalidFeeConfiguration {
        /// Fixed, non-secret reason text.
        reason: &'static str,
    },
    /// The anchor log payload could not be converted for transaction use.
    PayloadConversion,
    /// The anchor payload string exceeded the Ootle bounded-string limit.
    BoundedStringConversion,
    /// The pinned transaction builder failed to produce an unsigned transaction.
    TransactionBuilderFailure {
        /// Fixed, non-secret reason text.
        reason: &'static str,
    },
    /// The transaction carried an instruction that is not the single anchor log.
    UnexpectedInstruction {
        /// Fixed, non-secret detail text.
        detail: &'static str,
    },
    /// The transaction carried no project anchor log instruction.
    MissingAnchorInstruction,
    /// The transaction carried the identical anchor log more than once.
    DuplicateAnchorInstruction,
    /// The transaction carried two or more differing project anchor logs.
    ConflictingAnchorInstruction,
    /// The transaction carried a component-call instruction.
    ComponentCallPresent,
    /// The transaction carried a resource-transfer instruction.
    ResourceTransferPresent,
    /// The transaction carried an attached blob.
    ArbitraryBlobAttached,
    /// The transaction carried an unexpected substate input.
    UnexpectedInput,
    /// The transaction carried a fee instruction, which this architecture defers
    /// entirely to walletd preparation.
    UnexpectedFeeInstruction,
    /// An anchor log instruction was present but malformed (bad prefix, length,
    /// separator, uppercase hex, or trailing content).
    MalformedAnchorPayload,
    /// A well-formed anchor log instruction encoded the wrong anchor digest.
    AnchorDigestMismatch,
    /// The transaction's bound network did not match the expected network.
    NetworkBindingMismatch,
    /// The unsigned transaction reported an unsupported schema version.
    UnsupportedTransactionSchema {
        /// The reported, unsupported schema version.
        schema_version: u16,
    },
    /// A structural inspection invariant failed.
    UnsignedInspectionFailure {
        /// Fixed, non-secret reason text.
        reason: &'static str,
    },
    /// The unsigned transaction could not be canonically encoded for the
    /// project-owned inspection fingerprint.
    FingerprintFailure,
}

impl fmt::Display for OotleAnchorAdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedNetwork { requested } => {
                write!(
                    formatter,
                    "unsupported ootle network identifier: {requested}"
                )
            }
            Self::InvalidFeeConfiguration { reason } => {
                write!(formatter, "invalid fee configuration: {reason}")
            }
            Self::PayloadConversion => formatter.write_str("anchor log payload conversion failed"),
            Self::BoundedStringConversion => {
                formatter.write_str("anchor payload exceeded the ootle bounded-string limit")
            }
            Self::TransactionBuilderFailure { reason } => {
                write!(formatter, "transaction builder failure: {reason}")
            }
            Self::UnexpectedInstruction { detail } => {
                write!(formatter, "unexpected instruction: {detail}")
            }
            Self::MissingAnchorInstruction => {
                formatter.write_str("no project anchor log instruction present")
            }
            Self::DuplicateAnchorInstruction => {
                formatter.write_str("duplicate project anchor log instruction present")
            }
            Self::ConflictingAnchorInstruction => {
                formatter.write_str("conflicting project anchor log instructions present")
            }
            Self::ComponentCallPresent => {
                formatter.write_str("unexpected component-call instruction present")
            }
            Self::ResourceTransferPresent => {
                formatter.write_str("unexpected resource-transfer instruction present")
            }
            Self::ArbitraryBlobAttached => formatter.write_str("unexpected blob attached"),
            Self::UnexpectedInput => formatter.write_str("unexpected substate input present"),
            Self::UnexpectedFeeInstruction => {
                formatter.write_str("unexpected fee instruction present")
            }
            Self::MalformedAnchorPayload => {
                formatter.write_str("malformed project anchor log payload")
            }
            Self::AnchorDigestMismatch => {
                formatter.write_str("project anchor log encodes the wrong anchor digest")
            }
            Self::NetworkBindingMismatch => {
                formatter.write_str("unsigned transaction is bound to the wrong network")
            }
            Self::UnsupportedTransactionSchema { schema_version } => {
                write!(
                    formatter,
                    "unsupported unsigned transaction schema version: {schema_version}"
                )
            }
            Self::UnsignedInspectionFailure { reason } => {
                write!(
                    formatter,
                    "unsigned transaction inspection failure: {reason}"
                )
            }
            Self::FingerprintFailure => {
                formatter.write_str("failed to canonically encode the unsigned transaction")
            }
        }
    }
}

impl std::error::Error for OotleAnchorAdapterError {}
