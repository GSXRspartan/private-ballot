//! Stable, project-owned, bounded error categories for the receipt-retrieval
//! contract.
//!
//! Every error enum here is field-free (or carries only a fixed static detail)
//! and exposes a stable machine-readable `as_str()` code, mirroring the
//! anchor-transport convention. None of these errors carry wallet secrets,
//! private keys, ballots, proofs, archive contents, or unbounded third-party
//! text; they name a category only.

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
    /// Rejection categories for converting a project transaction identifier into
    /// the pinned Ootle transaction identifier (Section B) and for deriving the
    /// receipt substate address (Section C).
    ReceiptIdentifierError {
        /// The project transaction identifier was empty.
        Empty => "RECEIPT_ID_EMPTY",
        /// The identifier was not exactly 64 hexadecimal characters (32 bytes).
        WrongLength => "RECEIPT_ID_WRONG_LENGTH",
        /// The identifier contained an uppercase or non-hexadecimal character.
        ///
        /// The confirmed sealed-id canonicalization always emits lowercase hex,
        /// so an uppercase or otherwise non-`[0-9a-f]` character is rejected
        /// rather than silently canonicalized.
        NonLowercaseHexDigit => "RECEIPT_ID_NON_LOWERCASE_HEX_DIGIT",
    }
}

stable_error! {
    /// Rejection categories for converting a pinned Ootle receipt into the
    /// project receipt DTO (Section E).
    ReceiptConversionError {
        /// The receipt carried more log entries than the bounded maximum.
        TooManyLogs => "RECEIPT_CONVERSION_TOO_MANY_LOGS",
        /// A receipt log message exceeded the bounded maximum byte length.
        LogMessageTooLong => "RECEIPT_CONVERSION_LOG_MESSAGE_TOO_LONG",
        /// The receipt's bounded rejection/diagnostic text exceeded the maximum.
        DiagnosticTooLong => "RECEIPT_CONVERSION_DIAGNOSTIC_TOO_LONG",
    }
}

stable_error! {
    /// Bounded transport categories a receipt-source query can fail with
    /// (Section D). These name a transport condition only; none is a finality
    /// claim and none is a permanent failure of the anchor itself.
    IndexerReceiptTransportError {
        /// The indexer could not be reached at all.
        Unavailable => "INDEXER_RECEIPT_UNAVAILABLE",
        /// The query timed out; the observable state is now unknown.
        Timeout => "INDEXER_RECEIPT_TIMEOUT",
        /// The indexer response could not be parsed into the expected shape.
        MalformedResponse => "INDEXER_RECEIPT_MALFORMED_RESPONSE",
        /// The indexer reported a schema or version this adapter does not support.
        UnsupportedApi => "INDEXER_RECEIPT_UNSUPPORTED_API",
    }
}

stable_error! {
    /// Rejection categories for building or revalidating a receipt query against
    /// the submitted walletd binding (Section A).
    ReceiptQueryBindingError {
        /// The query's transaction identifier did not match the submitted one.
        TransactionIdMismatch => "RECEIPT_QUERY_TRANSACTION_ID_MISMATCH",
        /// The query's walletd request identifier did not match the submitted one.
        WalletdRequestIdMismatch => "RECEIPT_QUERY_WALLETD_REQUEST_ID_MISMATCH",
        /// The query's project request identifier did not match the submitted one.
        ProjectRequestIdMismatch => "RECEIPT_QUERY_PROJECT_REQUEST_ID_MISMATCH",
        /// The query's network did not match the submitted binding.
        NetworkMismatch => "RECEIPT_QUERY_NETWORK_MISMATCH",
        /// The query's anchor digest did not match the submitted binding.
        AnchorDigestMismatch => "RECEIPT_QUERY_ANCHOR_DIGEST_MISMATCH",
        /// The query's anchor log payload did not match the submitted binding.
        PayloadMismatch => "RECEIPT_QUERY_PAYLOAD_MISMATCH",
        /// The query's unsigned-transaction fingerprint did not match the binding.
        FingerprintMismatch => "RECEIPT_QUERY_FINGERPRINT_MISMATCH",
        /// The v0.39.2 template identity did not match the submitted binding.
        TemplateMismatch => "RECEIPT_QUERY_TEMPLATE_MISMATCH",
        /// The frozen v0.39.2 epoch binding did not match the submitted binding.
        EpochMismatch => "RECEIPT_QUERY_EPOCH_MISMATCH",
    }
}
