//! Stable, project-owned error categories for the offline anchor-transport
//! contract.
//!
//! Every error enum here is field-free and exposes a stable machine-readable
//! `as_str()` code, mirroring
//! [`tari_cc_private_ballot_protocol::ValidationCode`]. None of these errors
//! carry wallet secrets, ballots, proofs, or archive contents; they name a
//! category only.

/// Declares a field-free error enum with a stable `as_str()` code, `Display`,
/// and `std::error::Error`.
macro_rules! stable_error {
    (
        $(#[$enum_meta:meta])*
        $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => $code:literal
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        impl $name {
            /// Returns the stable machine-readable rejection code.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $code,)+
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl std::error::Error for $name {}
    };
}

stable_error! {
    /// Rejection categories for parsing a canonical anchor log payload.
    AnchorLogPayloadError {
        /// The input string was empty.
        Empty => "ANCHOR_LOG_PAYLOAD_EMPTY",
        /// The input did not begin with the exact version-one prefix.
        WrongPrefix => "ANCHOR_LOG_PAYLOAD_WRONG_PREFIX",
        /// The prefix was not immediately followed by the single colon separator.
        MissingSeparator => "ANCHOR_LOG_PAYLOAD_MISSING_SEPARATOR",
        /// The hexadecimal section was not exactly 64 characters long.
        DigestLength => "ANCHOR_LOG_PAYLOAD_DIGEST_LENGTH",
        /// The hexadecimal section contained a character outside `[0-9a-f]`.
        NonLowercaseHexDigit => "ANCHOR_LOG_PAYLOAD_NON_LOWERCASE_HEX_DIGIT",
    }
}

stable_error! {
    /// Rejection categories for constructing a bounded opaque identifier.
    AnchorIdentifierError {
        /// The identifier was empty.
        Empty => "ANCHOR_IDENTIFIER_EMPTY",
        /// The identifier exceeded the maximum permitted byte length.
        TooLong => "ANCHOR_IDENTIFIER_TOO_LONG",
        /// The identifier contained a control or whitespace character.
        ForbiddenCharacter => "ANCHOR_IDENTIFIER_FORBIDDEN_CHARACTER",
    }
}

stable_error! {
    /// Rejection categories for preparing an anchor transaction request.
    AnchorPreparationError {
        /// A scripted failure was injected by an offline fake.
        InjectedFailure => "ANCHOR_PREPARATION_INJECTED_FAILURE",
        /// A caller idempotency reference was reused with different anchor data.
        ClientReferenceConflict => "ANCHOR_PREPARATION_CLIENT_REFERENCE_CONFLICT",
    }
}

stable_error! {
    /// Rejection categories for the approval boundary.
    AnchorApprovalError {
        /// No stored request matched the supplied request identifier.
        RequestNotFound => "ANCHOR_APPROVAL_REQUEST_NOT_FOUND",
        /// The request had already been approved.
        AlreadyApproved => "ANCHOR_APPROVAL_ALREADY_APPROVED",
        /// The request had already been rejected.
        AlreadyRejected => "ANCHOR_APPROVAL_ALREADY_REJECTED",
        /// The approval window had already expired.
        Expired => "ANCHOR_APPROVAL_EXPIRED",
        /// The bound anchor log payload did not match the stored request.
        PayloadMismatch => "ANCHOR_APPROVAL_PAYLOAD_MISMATCH",
        /// The bound network did not match the stored request.
        NetworkMismatch => "ANCHOR_APPROVAL_NETWORK_MISMATCH",
        /// The bound account reference did not match the stored request.
        AccountMismatch => "ANCHOR_APPROVAL_ACCOUNT_MISMATCH",
        /// A scripted failure was injected by an offline fake.
        InjectedFailure => "ANCHOR_APPROVAL_INJECTED_FAILURE",
    }
}

stable_error! {
    /// Rejection categories for the submission boundary.
    AnchorSubmissionError {
        /// No stored request matched the supplied request identifier.
        RequestNotFound => "ANCHOR_SUBMISSION_REQUEST_NOT_FOUND",
        /// The request had not been approved.
        NotApproved => "ANCHOR_SUBMISSION_NOT_APPROVED",
        /// The request had been rejected by the approver.
        Rejected => "ANCHOR_SUBMISSION_REJECTED",
        /// The approval window had already expired.
        Expired => "ANCHOR_SUBMISSION_EXPIRED",
        /// The bound anchor log payload did not match the stored request.
        PayloadMismatch => "ANCHOR_SUBMISSION_PAYLOAD_MISMATCH",
        /// The bound network did not match the stored request.
        NetworkMismatch => "ANCHOR_SUBMISSION_NETWORK_MISMATCH",
        /// The bound account reference did not match the stored request.
        AccountMismatch => "ANCHOR_SUBMISSION_ACCOUNT_MISMATCH",
        /// The response was lost after sealing; the state is recoverable UNKNOWN.
        Timeout => "ANCHOR_SUBMISSION_TIMEOUT",
    }
}

stable_error! {
    /// Rejection categories for querying a receipt source.
    AnchorReceiptQueryError {
        /// The receipt source could not be reached.
        Unavailable => "ANCHOR_RECEIPT_QUERY_UNAVAILABLE",
    }
}

stable_error! {
    /// Rejection categories for looking up a stored request snapshot.
    AnchorRequestLookupError {
        /// No stored request matched the supplied request identifier.
        NotFound => "ANCHOR_REQUEST_LOOKUP_NOT_FOUND",
    }
}

stable_error! {
    /// Rejection categories for pure receipt/log verification.
    AnchorReceiptVerificationError {
        /// The receipt's transaction identifier did not match the expected one.
        WrongTransaction => "ANCHOR_RECEIPT_WRONG_TRANSACTION",
        /// The receipt's network did not match the expected one.
        WrongNetwork => "ANCHOR_RECEIPT_WRONG_NETWORK",
        /// The receipt is not a full finalized acceptance.
        NotFinalized => "ANCHOR_RECEIPT_NOT_FINALIZED",
        /// Only the fee intent committed; the anchor did not land.
        FeeOnlyAcceptance => "ANCHOR_RECEIPT_FEE_ONLY_ACCEPTANCE",
        /// The transaction was rejected by the ledger.
        RejectedTransaction => "ANCHOR_RECEIPT_REJECTED_TRANSACTION",
        /// No project anchor log was present.
        MissingAnchorLog => "ANCHOR_RECEIPT_MISSING_ANCHOR_LOG",
        /// A project-shaped anchor log failed strict parsing.
        MalformedAnchorLog => "ANCHOR_RECEIPT_MALFORMED_ANCHOR_LOG",
        /// The parsed anchor digest did not match the expected digest.
        WrongAnchorDigest => "ANCHOR_RECEIPT_WRONG_ANCHOR_DIGEST",
        /// More than one identical project anchor log was present.
        DuplicateAnchorLogs => "ANCHOR_RECEIPT_DUPLICATE_ANCHOR_LOGS",
        /// More than one differing project anchor log was present.
        ConflictingAnchorLogs => "ANCHOR_RECEIPT_CONFLICTING_ANCHOR_LOGS",
        /// No v0.39.2 anchor event was present in the finalized receipt.
        MissingAnchorEvent => "ANCHOR_RECEIPT_MISSING_ANCHOR_EVENT",
        /// An event named the anchor template ABI but came from another template.
        WrongEventTemplate => "ANCHOR_RECEIPT_WRONG_EVENT_TEMPLATE",
        /// An event from the pinned template had a different stored topic.
        WrongEventTopic => "ANCHOR_RECEIPT_WRONG_EVENT_TOPIC",
        /// An anchor event carried no value or a non-canonical digest value.
        MalformedAnchorEvent => "ANCHOR_RECEIPT_MALFORMED_ANCHOR_EVENT",
        /// An anchor event carried metadata in addition to the sole digest key.
        UnexpectedEventMetadata => "ANCHOR_RECEIPT_UNEXPECTED_EVENT_METADATA",
        /// More than one candidate anchor event appeared in the receipt.
        DuplicateAnchorEvents => "ANCHOR_RECEIPT_DUPLICATE_ANCHOR_EVENTS",
    }
}

stable_error! {
    /// Rejection categories for comparing two receipt observations.
    AnchorObservationAgreementError {
        /// The two observations named different transaction identifiers.
        TransactionIdMismatch => "ANCHOR_AGREEMENT_TRANSACTION_ID_MISMATCH",
        /// The two observations named different networks.
        NetworkMismatch => "ANCHOR_AGREEMENT_NETWORK_MISMATCH",
        /// The two observations reported different final statuses.
        FinalStatusMismatch => "ANCHOR_AGREEMENT_FINAL_STATUS_MISMATCH",
        /// One observation was fee-only while the other was a full acceptance.
        FeeOnlyVersusFullMismatch => "ANCHOR_AGREEMENT_FEE_ONLY_VERSUS_FULL_MISMATCH",
        /// One observation carried a project anchor log and the other did not.
        AnchorLogPresenceMismatch => "ANCHOR_AGREEMENT_ANCHOR_LOG_PRESENCE_MISMATCH",
        /// The two observations carried different anchor digests.
        AnchorDigestMismatch => "ANCHOR_AGREEMENT_ANCHOR_DIGEST_MISMATCH",
        /// The ordered log sequences were not identical.
        LogSequenceMismatch => "ANCHOR_AGREEMENT_LOG_SEQUENCE_MISMATCH",
        /// A project-shaped anchor log failed strict parsing.
        MalformedAnchorLog => "ANCHOR_AGREEMENT_MALFORMED_ANCHOR_LOG",
    }
}
