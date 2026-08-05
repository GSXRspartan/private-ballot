//! Transaction-identifier conversion (Section B) and pinned receipt conversion
//! (Section E).
//!
//! These are the only places in the crate that name a pinned Tari Ootle type,
//! mirroring how the construction adapter names the unsigned transaction and the
//! walletd adapter names the walletd wire request. Everything else is expressed
//! in project-owned DTOs.
//!
//! # Transaction-identifier representation
//!
//! There is exactly one project transaction-identifier representation:
//! [`AnchorTransactionId`], a bounded lowercase-hexadecimal string. Slice 4A6B's
//! [`canonicalize_transaction_id`] produces it from a sealed Ootle
//! [`TransactionId`] as exactly 64 lowercase hexadecimal characters. This module
//! adds only the exact inverse ([`transaction_id_to_ootle`]) so the identifier
//! can be turned back into the 32-byte Ootle id needed to address a receipt; it
//! deliberately does not invent a second encoding.
//!
//! [`TransactionId`]: tari_ootle_transaction::TransactionId
//! [`canonicalize_transaction_id`]: tari_cc_private_ballot_ootle_walletd_anchor_adapter::canonicalize_transaction_id

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorFinalStatusV1, AnchorLogEntryV1, AnchorLogLevelV1, AnchorReceiptSourceKindV1,
    AnchorReceiptV1, AnchorTransactionId,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::canonicalize_transaction_id;
use tari_engine_types::logs::LogEntry;
use tari_engine_types::transaction_receipt::{FinalizeOutcome, TransactionReceipt};
use tari_indexer_client::types::GetTransactionReceiptResponse;
use tari_ootle_transaction::TransactionId;
use tari_template_lib_types::LogLevel;

use crate::errors::{ReceiptConversionError, ReceiptIdentifierError};

/// Exact number of lowercase hexadecimal characters in a project transaction id.
pub const TRANSACTION_ID_HEX_LEN: usize = 64;

/// Maximum number of log entries copied out of a single receipt.
///
/// A well-formed anchor transaction commits one anchor `EmitLog` plus a small
/// number of engine/fee logs. This ceiling bounds the copied diagnostics so a
/// hostile or malformed receipt cannot force an unbounded allocation.
pub const MAX_RECEIPT_LOG_ENTRIES: usize = 256;

/// Maximum UTF-8 byte length of a single copied receipt log message.
///
/// Comfortably larger than the fixed 103-byte anchor payload, but still bounded.
pub const MAX_RECEIPT_LOG_MESSAGE_BYTES: usize = 4096;

/// Converts a sealed pinned Ootle [`TransactionId`] into the project identifier.
///
/// This delegates to the Slice 4A6B canonicalization so both adapters agree on a
/// single representation. It is total and deterministic.
#[must_use]
pub fn transaction_id_from_ootle(id: &TransactionId) -> AnchorTransactionId {
    canonicalize_transaction_id(id)
}

/// Converts a project [`AnchorTransactionId`] back into the pinned Ootle
/// [`TransactionId`] (Section B).
///
/// The parse is strict: exactly 64 characters, each a lowercase hexadecimal
/// digit, decoding to exactly 32 bytes. It rejects an empty string, any other
/// length, uppercase hex, non-hex characters, embedded whitespace, and any
/// prefix. The project identifier is already whitespace-free and control-free by
/// construction, so only length and the lowercase-hex alphabet are re-checked.
///
/// Round trip: `transaction_id_to_ootle(&transaction_id_from_ootle(&id)) == id`.
///
/// # Errors
///
/// Returns a [`ReceiptIdentifierError`] describing the first violated rule.
pub fn transaction_id_to_ootle(
    transaction_id: &AnchorTransactionId,
) -> Result<TransactionId, ReceiptIdentifierError> {
    let text = transaction_id.as_str();
    if text.is_empty() {
        return Err(ReceiptIdentifierError::Empty);
    }

    let bytes = text.as_bytes();
    if bytes.len() != TRANSACTION_ID_HEX_LEN {
        return Err(ReceiptIdentifierError::WrongLength);
    }

    let mut decoded = [0_u8; 32];
    for (byte, pair) in decoded.iter_mut().zip(bytes.chunks_exact(2)) {
        let high = lower_hex_value(pair[0]).ok_or(ReceiptIdentifierError::NonLowercaseHexDigit)?;
        let low = lower_hex_value(pair[1]).ok_or(ReceiptIdentifierError::NonLowercaseHexDigit)?;
        *byte = (high << 4) | low;
    }

    Ok(TransactionId::new(decoded))
}

/// Maps one lowercase hexadecimal byte to its value, rejecting anything else
/// (including uppercase `A`–`F`).
const fn lower_hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Maps the pinned receipt log level into the project log level.
const fn map_log_level(level: LogLevel) -> AnchorLogLevelV1 {
    match level {
        LogLevel::Error => AnchorLogLevelV1::Error,
        LogLevel::Warn => AnchorLogLevelV1::Warn,
        LogLevel::Info => AnchorLogLevelV1::Info,
        LogLevel::Debug => AnchorLogLevelV1::Debug,
    }
}

/// Maps the pinned finalize outcome into the project finalized status.
///
/// The persisted receipt substate exists only for a committed transaction, so
/// its outcome is either a full commit or a fee-intent-only commit; there is no
/// receipt-substate representation of a fully rejected transaction. A fee-only
/// commit maps to the distinct [`AnchorFinalStatusV1::FeeOnlyAccepted`], never to
/// a full acceptance.
const fn map_finalize_outcome(outcome: FinalizeOutcome) -> AnchorFinalStatusV1 {
    match outcome {
        FinalizeOutcome::Commit => AnchorFinalStatusV1::Accepted,
        FinalizeOutcome::FeeIntentCommit => AnchorFinalStatusV1::FeeOnlyAccepted,
    }
}

/// Copies a single pinned receipt log entry into a bounded project log entry.
fn convert_log_entry(entry: &LogEntry) -> Result<AnchorLogEntryV1, ReceiptConversionError> {
    // Use the raw message field, never the `Display` (which prepends the level):
    // the anchor payload must be preserved byte-for-byte for strict parsing.
    if entry.message.len() > MAX_RECEIPT_LOG_MESSAGE_BYTES {
        return Err(ReceiptConversionError::LogMessageTooLong);
    }
    Ok(AnchorLogEntryV1::new(
        map_log_level(entry.level),
        entry.message.clone(),
    ))
}

/// Converts a persisted pinned Ootle [`TransactionReceipt`] into the project
/// receipt DTO (Section E).
///
/// Only confirmed fields are mapped: the finalized status (from the outcome), the
/// ordered logs (preserving order and exact UTF-8 message contents), and the
/// epoch as the opaque ledger position. The transaction identifier and network
/// are supplied by the caller (the persisted receipt is addressed by, not a
/// carrier of, the transaction id, and carries no network field), and the source
/// is recorded as the independent indexer. No organizer identity, block
/// timestamp, archive validity, or tally validity is invented, and no acceptance
/// is claimed beyond what the outcome states. Oversized log content is rejected
/// before any project DTO is created.
///
/// # Errors
///
/// Returns a [`ReceiptConversionError`] if the receipt carries more logs than
/// [`MAX_RECEIPT_LOG_ENTRIES`] or any log message exceeds
/// [`MAX_RECEIPT_LOG_MESSAGE_BYTES`].
pub fn convert_transaction_receipt(
    receipt: &TransactionReceipt,
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> Result<AnchorReceiptV1, ReceiptConversionError> {
    let logs = receipt.logs();
    if logs.len() > MAX_RECEIPT_LOG_ENTRIES {
        return Err(ReceiptConversionError::TooManyLogs);
    }

    let mut converted_logs = Vec::with_capacity(logs.len());
    for entry in logs {
        converted_logs.push(convert_log_entry(entry)?);
    }

    Ok(AnchorReceiptV1::new(
        transaction_id.clone(),
        network.clone(),
        map_finalize_outcome(*receipt.outcome()),
        converted_logs,
        // A committed receipt carries no rejection reason; its outcome already
        // states full versus fee-only. No third-party diagnostic is copied.
        None,
        Some(receipt.epoch().as_u64()),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    ))
}

/// Converts a confirmed indexer [`GetTransactionReceiptResponse`] into the
/// project receipt DTO (Section E).
///
/// This is the seam that names the indexer's own receipt-response wire type: a
/// future real client forwards the response of
/// `IndexerRestApiClient::get_transaction_receipt` here verbatim. It simply
/// converts the wrapped [`TransactionReceipt`].
///
/// # Errors
///
/// Propagates any [`ReceiptConversionError`] from
/// [`convert_transaction_receipt`].
pub fn convert_receipt_response(
    response: &GetTransactionReceiptResponse,
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> Result<AnchorReceiptV1, ReceiptConversionError> {
    convert_transaction_receipt(&response.receipt, transaction_id, network)
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_RECEIPT_LOG_ENTRIES, MAX_RECEIPT_LOG_MESSAGE_BYTES, convert_transaction_receipt,
        transaction_id_from_ootle, transaction_id_to_ootle,
    };
    use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
    use tari_cc_private_ballot_anchor_transport::{
        AnchorFinalStatusV1, AnchorLogLevelV1, AnchorReceiptSourceKindV1, AnchorTransactionId,
    };
    use tari_engine_types::Epoch;
    use tari_engine_types::fees::FeeReceipt;
    use tari_engine_types::logs::LogEntry;
    use tari_engine_types::transaction_receipt::{
        DiffSummary, FinalizeOutcome, TransactionReceipt,
    };
    use tari_ootle_transaction::TransactionId;
    use tari_template_lib_types::LogLevel;

    fn transaction_id(text: &str) -> AnchorTransactionId {
        match AnchorTransactionId::new(text.to_owned()) {
            Ok(id) => id,
            Err(_error) => panic!("test transaction id must be valid"),
        }
    }

    fn network() -> OotleNetworkIdV1 {
        match OotleNetworkIdV1::new("esmeralda".to_owned()) {
            Ok(id) => id,
            Err(_error) => panic!("test network must be valid"),
        }
    }

    fn make_receipt(
        outcome: FinalizeOutcome,
        logs: Vec<LogEntry>,
        epoch: u64,
    ) -> TransactionReceipt {
        TransactionReceipt {
            outcome,
            diff_summary: DiffSummary::default(),
            fee_withdrawals: Box::default(),
            events: Box::default(),
            logs: logs.into_boxed_slice(),
            fee_receipt: FeeReceipt::default(),
            epoch: Epoch(epoch),
        }
    }

    #[test]
    fn transaction_id_round_trips_through_ootle() {
        let ootle = TransactionId::new([0xab; 32]);
        let project = transaction_id_from_ootle(&ootle);
        assert_eq!(project.as_str().len(), 64);
        assert!(
            project
                .as_str()
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );

        let Ok(back) = transaction_id_to_ootle(&project) else {
            panic!("canonical id must convert back");
        };
        assert_eq!(back, ootle);
    }

    #[test]
    fn transaction_id_known_answer_vector() {
        // 0x00..1f increasing bytes -> the exact 64-hex lowercase string.
        let mut bytes = [0_u8; 32];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let project = transaction_id_from_ootle(&TransactionId::new(bytes));
        assert_eq!(
            project.as_str(),
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
        let Ok(back) = transaction_id_to_ootle(&project) else {
            panic!("known-answer id must convert back");
        };
        assert_eq!(back.into_array(), bytes);
    }

    #[test]
    fn uppercase_transaction_id_is_rejected() {
        let upper = transaction_id(&"AB".repeat(32));
        assert!(transaction_id_to_ootle(&upper).is_err());
    }

    #[test]
    fn wrong_length_transaction_id_is_rejected() {
        let short = transaction_id("aa01ffbc");
        assert!(transaction_id_to_ootle(&short).is_err());
        let long = transaction_id(&"ab".repeat(33));
        assert!(transaction_id_to_ootle(&long).is_err());
    }

    #[test]
    fn non_hex_transaction_id_is_rejected() {
        let non_hex = transaction_id(&"zz".repeat(32));
        assert!(transaction_id_to_ootle(&non_hex).is_err());
    }

    #[test]
    fn commit_receipt_maps_to_full_acceptance_preserving_ordered_logs() {
        let id = transaction_id(&"11".repeat(32));
        let logs = vec![
            LogEntry::new(LogLevel::Info, "first".to_owned()),
            LogEntry::new(LogLevel::Warn, "second".to_owned()),
            LogEntry::new(LogLevel::Error, "third".to_owned()),
            LogEntry::new(LogLevel::Debug, "fourth".to_owned()),
        ];
        let receipt = make_receipt(FinalizeOutcome::Commit, logs, 42);

        let Ok(converted) = convert_transaction_receipt(&receipt, &id, &network()) else {
            panic!("commit receipt must convert");
        };

        assert_eq!(converted.final_status(), AnchorFinalStatusV1::Accepted);
        assert_eq!(
            converted.source(),
            AnchorReceiptSourceKindV1::IndependentIndexer
        );
        assert_eq!(converted.ledger_position(), Some(42));
        assert_eq!(converted.transaction_id(), &id);
        assert_eq!(converted.network(), &network());

        let observed: Vec<(AnchorLogLevelV1, &str)> = converted
            .logs()
            .iter()
            .map(|entry| (entry.level(), entry.message()))
            .collect();
        assert_eq!(
            observed,
            vec![
                (AnchorLogLevelV1::Info, "first"),
                (AnchorLogLevelV1::Warn, "second"),
                (AnchorLogLevelV1::Error, "third"),
                (AnchorLogLevelV1::Debug, "fourth"),
            ]
        );
    }

    #[test]
    fn fee_intent_commit_maps_to_fee_only_never_full() {
        let id = transaction_id(&"22".repeat(32));
        let receipt = make_receipt(FinalizeOutcome::FeeIntentCommit, Vec::new(), 1);

        let Ok(converted) = convert_transaction_receipt(&receipt, &id, &network()) else {
            panic!("fee-only receipt must convert");
        };
        assert_eq!(
            converted.final_status(),
            AnchorFinalStatusV1::FeeOnlyAccepted
        );
        assert_ne!(converted.final_status(), AnchorFinalStatusV1::Accepted);
    }

    #[test]
    fn oversized_log_message_is_rejected_before_dto() {
        let id = transaction_id(&"33".repeat(32));
        let oversized = "x".repeat(MAX_RECEIPT_LOG_MESSAGE_BYTES + 1);
        let receipt = make_receipt(
            FinalizeOutcome::Commit,
            vec![LogEntry::new(LogLevel::Info, oversized)],
            1,
        );
        assert!(convert_transaction_receipt(&receipt, &id, &network()).is_err());
    }

    #[test]
    fn too_many_logs_is_rejected_before_dto() {
        let id = transaction_id(&"44".repeat(32));
        let logs = (0..=MAX_RECEIPT_LOG_ENTRIES)
            .map(|_| LogEntry::new(LogLevel::Info, "log".to_owned()))
            .collect::<Vec<_>>();
        let receipt = make_receipt(FinalizeOutcome::Commit, logs, 1);
        assert!(convert_transaction_receipt(&receipt, &id, &network()).is_err());
    }

    #[test]
    fn exact_max_logs_is_accepted() {
        let id = transaction_id(&"55".repeat(32));
        let logs = (0..MAX_RECEIPT_LOG_ENTRIES)
            .map(|_| LogEntry::new(LogLevel::Info, "log".to_owned()))
            .collect::<Vec<_>>();
        let receipt = make_receipt(FinalizeOutcome::Commit, logs, 1);
        let Ok(converted) = convert_transaction_receipt(&receipt, &id, &network()) else {
            panic!("exact-max receipt must convert");
        };
        assert_eq!(converted.logs().len(), MAX_RECEIPT_LOG_ENTRIES);
    }
}
