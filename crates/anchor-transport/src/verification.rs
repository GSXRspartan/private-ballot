//! Pure receipt/log verification for a finalized anchor transaction (Section G).
//!
//! Verification is a pure function of the expected transaction identifier,
//! expected network, expected anchor payload, and the observed receipt. It
//! accepts only a full finalized acceptance carrying exactly one strictly
//! parseable project anchor log whose digest matches the expected digest.
//! Unrelated non-project logs may coexist and log order does not affect the
//! result.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};

use crate::errors::AnchorReceiptVerificationError;
use crate::identifiers::AnchorTransactionId;
use crate::model::{
    AnchorFinalStatusV1, AnchorQueryOutcomeV1, AnchorReceiptSourceKindV1, AnchorReceiptV1,
};
use crate::event::{ANCHOR_EVENT_DIGEST_KEY_V1, AnchorTemplateBindingV1};
use crate::payload::{ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1, AnchorLogPayloadV1};

/// Verified, bound anchor evidence produced by a successful verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAnchorEvidenceV1 {
    transaction_id: AnchorTransactionId,
    network: OotleNetworkIdV1,
    anchor_digest: OotleAnchorRecordHashV1,
    ledger_position: Option<u64>,
    source: AnchorReceiptSourceKindV1,
}

impl VerifiedAnchorEvidenceV1 {
    /// Returns the verified transaction identifier.
    #[must_use]
    pub const fn transaction_id(&self) -> &AnchorTransactionId {
        &self.transaction_id
    }

    /// Returns the verified network.
    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the verified anchor-record digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }

    /// Returns the opaque ledger position, if the source reported one.
    #[must_use]
    pub const fn ledger_position(&self) -> Option<u64> {
        self.ledger_position
    }

    /// Returns which observer produced the verified receipt.
    #[must_use]
    pub const fn source(&self) -> AnchorReceiptSourceKindV1 {
        self.source
    }
}

/// Verifies a finalized receipt against the expected anchor binding.
///
/// The rules, in order: the transaction identifier matches; the network
/// matches; the status is a full finalized acceptance (fee-only and rejected
/// are refused); exactly one strictly parseable project anchor log is present;
/// and its digest matches the expected digest. A project anchor log is a log
/// whose whole message begins with the exact candidate prefix and then parses
/// strictly — a message merely containing the prefix as an interior substring
/// is ignored as unrelated.
pub fn verify_anchor_receipt(
    expected_transaction: &AnchorTransactionId,
    expected_network: &OotleNetworkIdV1,
    expected_payload: &AnchorLogPayloadV1,
    receipt: &AnchorReceiptV1,
) -> Result<VerifiedAnchorEvidenceV1, AnchorReceiptVerificationError> {
    if receipt.transaction_id() != expected_transaction {
        return Err(AnchorReceiptVerificationError::WrongTransaction);
    }

    if receipt.network() != expected_network {
        return Err(AnchorReceiptVerificationError::WrongNetwork);
    }

    match receipt.final_status() {
        AnchorFinalStatusV1::Accepted => {}
        AnchorFinalStatusV1::FeeOnlyAccepted => {
            return Err(AnchorReceiptVerificationError::FeeOnlyAcceptance);
        }
        AnchorFinalStatusV1::Rejected => {
            return Err(AnchorReceiptVerificationError::RejectedTransaction);
        }
    }

    let parsed = parse_project_anchor_logs(receipt)?;

    match parsed.as_slice() {
        [] => Err(AnchorReceiptVerificationError::MissingAnchorLog),
        [single] => {
            if single.digest() != expected_payload.digest() {
                return Err(AnchorReceiptVerificationError::WrongAnchorDigest);
            }

            Ok(VerifiedAnchorEvidenceV1 {
                transaction_id: receipt.transaction_id().clone(),
                network: receipt.network().clone(),
                anchor_digest: single.digest(),
                ledger_position: receipt.ledger_position(),
                source: receipt.source(),
            })
        }
        [first, rest @ ..] => {
            if rest.iter().all(|payload| payload == first) {
                Err(AnchorReceiptVerificationError::DuplicateAnchorLogs)
            } else {
                Err(AnchorReceiptVerificationError::ConflictingAnchorLogs)
            }
        }
    }
}

/// Verifies a query outcome, refusing not-found, not-finalized, and unknown.
///
/// This is the outer entry point used after querying a receipt source: a
/// finalized receipt is verified as usual, and every non-finalized outcome is
/// rejected as `NotFinalized`.
pub fn verify_query_outcome(
    expected_transaction: &AnchorTransactionId,
    expected_network: &OotleNetworkIdV1,
    expected_payload: &AnchorLogPayloadV1,
    outcome: &AnchorQueryOutcomeV1,
) -> Result<VerifiedAnchorEvidenceV1, AnchorReceiptVerificationError> {
    match outcome {
        AnchorQueryOutcomeV1::Finalized(receipt) => verify_anchor_receipt(
            expected_transaction,
            expected_network,
            expected_payload,
            receipt,
        ),
        AnchorQueryOutcomeV1::NotFound
        | AnchorQueryOutcomeV1::NotFinalized
        | AnchorQueryOutcomeV1::Unknown => Err(AnchorReceiptVerificationError::NotFinalized),
    }
}

/// Verifies the v0.39.2 receipt-event proof path.
///
/// A receipt is authoritative only when it is addressed by the known
/// transaction id, reports a full finalized commit, and contains exactly one
/// event from the pinned template with the pinned full topic and the one
/// permitted metadata key. Historical V1 receipts continue through
/// [`verify_anchor_receipt`]; this path never treats indexer event search as
/// proof of absence.
pub fn verify_v39_event_receipt(
    expected_transaction: &AnchorTransactionId,
    expected_network: &OotleNetworkIdV1,
    expected_template: &AnchorTemplateBindingV1,
    expected_payload: &crate::event::AnchorEventPayloadV2,
    receipt: &AnchorReceiptV1,
) -> Result<VerifiedAnchorEvidenceV1, AnchorReceiptVerificationError> {
    if receipt.transaction_id() != expected_transaction {
        return Err(AnchorReceiptVerificationError::WrongTransaction);
    }
    if receipt.network() != expected_network {
        return Err(AnchorReceiptVerificationError::WrongNetwork);
    }
    match receipt.final_status() {
        AnchorFinalStatusV1::Accepted => {}
        AnchorFinalStatusV1::FeeOnlyAccepted => {
            return Err(AnchorReceiptVerificationError::FeeOnlyAcceptance);
        }
        AnchorFinalStatusV1::Rejected => {
            return Err(AnchorReceiptVerificationError::RejectedTransaction);
        }
    }

    let mut candidates = Vec::new();
    for event in receipt.event_proofs_v2() {
        let has_digest_key = event
            .metadata()
            .iter()
            .any(|(key, _)| key == ANCHOR_EVENT_DIGEST_KEY_V1);
        if event.template_address() == expected_template.template_address()
            && event.topic() != expected_template.full_event_topic()
        {
            return Err(AnchorReceiptVerificationError::WrongEventTopic);
        }
        if event.topic() == expected_template.full_event_topic()
            && event.template_address() != expected_template.template_address()
        {
            return Err(AnchorReceiptVerificationError::WrongEventTemplate);
        }
        if event.topic() == expected_template.full_event_topic() || has_digest_key {
            candidates.push(event);
        }
    }

    let [event] = candidates.as_slice() else {
        return if candidates.is_empty() {
            Err(AnchorReceiptVerificationError::MissingAnchorEvent)
        } else {
            Err(AnchorReceiptVerificationError::DuplicateAnchorEvents)
        };
    };
    if event.template_address() != expected_template.template_address() {
        return Err(AnchorReceiptVerificationError::WrongEventTemplate);
    }
    if event.topic() != expected_template.full_event_topic() {
        return Err(AnchorReceiptVerificationError::WrongEventTopic);
    }
    let [(key, digest)] = event.metadata() else {
        return Err(AnchorReceiptVerificationError::UnexpectedEventMetadata);
    };
    if key != ANCHOR_EVENT_DIGEST_KEY_V1 {
        return Err(AnchorReceiptVerificationError::MalformedAnchorEvent);
    }
    if digest != &expected_payload.digest_hex() {
        return Err(AnchorReceiptVerificationError::WrongAnchorDigest);
    }
    Ok(VerifiedAnchorEvidenceV1 {
        transaction_id: receipt.transaction_id().clone(),
        network: receipt.network().clone(),
        anchor_digest: expected_payload.digest(),
        ledger_position: receipt.ledger_position(),
        source: receipt.source(),
    })
}

/// Collects and strictly parses every project anchor log in a receipt.
///
/// A log whose whole message begins with the candidate prefix but fails strict
/// parsing is a malformed project log and is reported as such (fail closed).
fn parse_project_anchor_logs(
    receipt: &AnchorReceiptV1,
) -> Result<Vec<AnchorLogPayloadV1>, AnchorReceiptVerificationError> {
    let mut parsed = Vec::new();

    for entry in receipt.logs() {
        if !entry
            .message()
            .starts_with(ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1)
        {
            continue;
        }

        let payload = AnchorLogPayloadV1::parse(entry.message())
            .map_err(|_| AnchorReceiptVerificationError::MalformedAnchorLog)?;
        parsed.push(payload);
    }

    Ok(parsed)
}
