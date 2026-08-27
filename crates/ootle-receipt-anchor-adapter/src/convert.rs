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
    AnchorEventProofV2, AnchorFinalStatusV1, AnchorReceiptSourceKindV1, AnchorReceiptV1,
    AnchorTransactionId,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::canonicalize_transaction_id;
use tari_engine_types::transaction_receipt::{FinalizeOutcome, TransactionReceipt};
use tari_indexer_client::types::GetTransactionReceiptResponse;
use tari_ootle_transaction::TransactionId;

use crate::errors::{ReceiptConversionError, ReceiptIdentifierError};

/// Exact number of lowercase hexadecimal characters in a project transaction id.
pub const TRANSACTION_ID_HEX_LEN: usize = 64;

/// Maximum number of receipt events (v0.39.2) — or historical V1 log entries —
/// copied out of a single receipt.
///
/// A well-formed anchor transaction emits exactly one anchor event plus a small
/// number of engine/fee events. This ceiling bounds the copied facts so a
/// hostile or malformed receipt cannot force an unbounded allocation.
pub const MAX_RECEIPT_LOG_ENTRIES: usize = 256;

/// Maximum UTF-8 byte length of a single copied historical V1 receipt log
/// message. Retained for reading historical V1 log-based evidence; v0.39.2
/// event metadata is bounded separately by `AnchorEventProofV2`.
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

/// Converts a persisted pinned Ootle [`TransactionReceipt`] into the project
/// receipt DTO (Section E).
///
/// Only confirmed fields are mapped: the finalized status (from the outcome), the
/// bounded receipt events (preserving template address, topic, every metadata
/// field, event index, intent commitment, and epoch), and the epoch as the
/// opaque ledger position. The transaction identifier and network
/// are supplied by the caller (the persisted receipt is addressed by, not a
/// carrier of, the transaction id, and carries no network field), and the source
/// is recorded as the independent indexer. No organizer identity, block
/// timestamp, archive validity, or tally validity is invented, and no acceptance
/// is claimed beyond what the outcome states. Oversized log content is rejected
/// before any project DTO is created.
///
/// # Errors
///
/// Returns a [`ReceiptConversionError`] if the receipt carries more events
/// than [`MAX_RECEIPT_LOG_ENTRIES`] or its bounded event facts cannot be copied.
pub fn convert_transaction_receipt(
    receipt: &TransactionReceipt,
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> Result<AnchorReceiptV1, ReceiptConversionError> {
    let events = receipt.events();
    if events.len() > MAX_RECEIPT_LOG_ENTRIES {
        return Err(ReceiptConversionError::TooManyLogs);
    }

    let mut event_proofs = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let metadata = event.payload().clone().into_iter().collect();
        let event_index = u16::try_from(index).map_err(|_| ReceiptConversionError::TooManyLogs)?;
        // Render the canonical `template_<64 hex>` address string. The pinned
        // `TemplateAddress` is a bare `Hash32` whose `Display` is only the 64 hex
        // characters, so the `template_` prefix is added here to match the exact
        // address string the configured `AnchorTemplateBindingV1` (and the
        // verifier) carry. Storing the bare hex would make every legitimate
        // receipt fail event verification with a spurious wrong-template error.
        let proof = AnchorEventProofV2::new(
            format!("template_{}", event.template_address()),
            event.topic().to_owned(),
            metadata,
            event_index,
            receipt.epoch().as_u64(),
            receipt.intent_commitment().into_array(),
        )
        .map_err(|_| ReceiptConversionError::DiagnosticTooLong)?;
        event_proofs.push(proof);
    }

    Ok(AnchorReceiptV1::new(
        transaction_id.clone(),
        network.clone(),
        map_finalize_outcome(*receipt.outcome()),
        // V1 log data is intentionally empty for a v0.39.2 receipt. A new
        // lifecycle queries `event_proofs_v2`; historical V1 evidence remains
        // readable through the unchanged log field.
        Vec::new(),
        // A committed receipt carries no rejection reason; its outcome already
        // states full versus fee-only. No third-party diagnostic is copied.
        None,
        Some(receipt.epoch().as_u64()),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
    .with_event_proofs_v2(event_proofs))
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
        MAX_RECEIPT_LOG_ENTRIES, convert_transaction_receipt, transaction_id_from_ootle,
        transaction_id_to_ootle,
    };
    use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
    use tari_cc_private_ballot_anchor_transport::{
        AnchorFinalStatusV1, AnchorReceiptSourceKindV1, AnchorTransactionId,
    };
    use tari_engine_types::Epoch;
    use tari_engine_types::events::Event;
    use tari_engine_types::fees::FeeReceipt;
    use tari_engine_types::transaction_receipt::{
        DiffSummary, FinalizeOutcome, TransactionReceipt,
    };
    use tari_ootle_transaction::TransactionId;
    use tari_template_lib_types::{Metadata, TemplateAddress};

    const ANCHOR_TOPIC: &str = "tari_private_ballot_anchor.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1";

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

    fn template_address() -> TemplateAddress {
        match TemplateAddress::from_hex(&"11".repeat(32)) {
            Ok(address) => address,
            Err(_error) => panic!("test template address must parse"),
        }
    }

    /// Builds a v0.39.2 anchor event carrying the sole digest metadata key.
    fn anchor_event(digest_hex: &str) -> Event {
        let metadata: Metadata = [("anchor_digest", digest_hex)].into_iter().collect();
        Event::new(None, template_address(), ANCHOR_TOPIC.to_owned(), metadata)
    }

    fn make_receipt(
        outcome: FinalizeOutcome,
        events: Vec<Event>,
        epoch: u64,
    ) -> TransactionReceipt {
        TransactionReceipt {
            outcome,
            diff_summary: DiffSummary::default(),
            fee_withdrawals: Box::default(),
            events: events.into_boxed_slice(),
            fee_receipt: FeeReceipt::default(),
            epoch: Epoch(epoch),
            intent_commitment: Default::default(),
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
    fn commit_receipt_maps_to_full_acceptance_and_copies_the_anchor_event() {
        let id = transaction_id(&"11".repeat(32));
        let digest_hex = "22".repeat(32);
        let receipt = make_receipt(FinalizeOutcome::Commit, vec![anchor_event(&digest_hex)], 42);

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

        // V1 log data is empty for a v0.39.2 receipt; the event facts land in the
        // detached event-proof channel instead.
        assert!(converted.logs().is_empty());
        let proofs = converted.event_proofs_v2();
        assert_eq!(proofs.len(), 1);
        let proof = &proofs[0];
        // The template address is copied in canonical `template_<64 hex>` form so
        // it matches the configured template binding exactly (regression guard:
        // the bare `Hash32` display would silently fail event verification).
        assert_eq!(
            proof.template_address(),
            format!("template_{}", "11".repeat(32))
        );
        assert_eq!(proof.topic(), ANCHOR_TOPIC);
        assert_eq!(proof.event_index(), 0);
        assert_eq!(proof.receipt_epoch(), 42);
        assert_eq!(
            proof.metadata(),
            &[("anchor_digest".to_owned(), digest_hex.clone())]
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
        assert!(converted.event_proofs_v2().is_empty());
    }

    #[test]
    fn too_many_events_is_rejected_before_dto() {
        let id = transaction_id(&"44".repeat(32));
        let events = (0..=MAX_RECEIPT_LOG_ENTRIES)
            .map(|_| anchor_event(&"22".repeat(32)))
            .collect::<Vec<_>>();
        let receipt = make_receipt(FinalizeOutcome::Commit, events, 1);
        assert!(convert_transaction_receipt(&receipt, &id, &network()).is_err());
    }

    #[test]
    fn exact_max_events_is_accepted() {
        let id = transaction_id(&"55".repeat(32));
        let events = (0..MAX_RECEIPT_LOG_ENTRIES)
            .map(|_| anchor_event(&"22".repeat(32)))
            .collect::<Vec<_>>();
        let receipt = make_receipt(FinalizeOutcome::Commit, events, 1);
        let Ok(converted) = convert_transaction_receipt(&receipt, &id, &network()) else {
            panic!("exact-max receipt must convert");
        };
        assert_eq!(converted.event_proofs_v2().len(), MAX_RECEIPT_LOG_ENTRIES);
    }
}
