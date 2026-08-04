//! Cross-observation agreement between a walletd receipt and an independent
//! indexer receipt (Section H).
//!
//! # Chosen log-equality rule
//!
//! This module requires **strict ordered equality of the full log sequences**
//! of the two observations. Slice 4A3 confirmed that walletd's `FinalizeResult`
//! logs and the indexer's persisted `TransactionReceipt` logs both derive from
//! the same consensus-committed engine log vector, so two honest observations of
//! the same finalized transaction must present byte-identical, identically
//! ordered logs. Allowing auxiliary logs to differ would weaken that guarantee
//! for no confirmed reason, so unrelated logs must match too.

use crate::errors::AnchorObservationAgreementError;
use crate::model::{AnchorFinalStatusV1, AnchorReceiptV1};
use crate::payload::{ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1, AnchorLogPayloadV1};

/// Compares a walletd observation and an independent indexer observation.
///
/// The two observations must agree on the transaction identifier, network, and
/// final status, must either both carry a project anchor log or both not, must
/// carry the same anchor digest when present, and must have identical ordered
/// log sequences. A fee-only versus full-acceptance disagreement is reported
/// distinctly from any other status disagreement.
pub fn compare_receipt_observations(
    walletd: &AnchorReceiptV1,
    indexer: &AnchorReceiptV1,
) -> Result<(), AnchorObservationAgreementError> {
    if walletd.transaction_id() != indexer.transaction_id() {
        return Err(AnchorObservationAgreementError::TransactionIdMismatch);
    }

    if walletd.network() != indexer.network() {
        return Err(AnchorObservationAgreementError::NetworkMismatch);
    }

    if walletd.final_status() != indexer.final_status() {
        return Err(final_status_disagreement(
            walletd.final_status(),
            indexer.final_status(),
        ));
    }

    let walletd_logs = collect_project_anchor_logs(walletd)?;
    let indexer_logs = collect_project_anchor_logs(indexer)?;

    if walletd_logs.is_empty() != indexer_logs.is_empty() {
        return Err(AnchorObservationAgreementError::AnchorLogPresenceMismatch);
    }

    if walletd_logs != indexer_logs {
        return Err(AnchorObservationAgreementError::AnchorDigestMismatch);
    }

    if walletd.logs() != indexer.logs() {
        return Err(AnchorObservationAgreementError::LogSequenceMismatch);
    }

    Ok(())
}

/// Classifies a final-status disagreement, distinguishing fee-only versus full.
const fn final_status_disagreement(
    walletd: AnchorFinalStatusV1,
    indexer: AnchorFinalStatusV1,
) -> AnchorObservationAgreementError {
    match (walletd, indexer) {
        (AnchorFinalStatusV1::Accepted, AnchorFinalStatusV1::FeeOnlyAccepted)
        | (AnchorFinalStatusV1::FeeOnlyAccepted, AnchorFinalStatusV1::Accepted) => {
            AnchorObservationAgreementError::FeeOnlyVersusFullMismatch
        }
        _ => AnchorObservationAgreementError::FinalStatusMismatch,
    }
}

/// Collects and strictly parses every project anchor log in a receipt.
fn collect_project_anchor_logs(
    receipt: &AnchorReceiptV1,
) -> Result<Vec<AnchorLogPayloadV1>, AnchorObservationAgreementError> {
    let mut parsed = Vec::new();

    for entry in receipt.logs() {
        if !entry
            .message()
            .starts_with(ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1)
        {
            continue;
        }

        let payload = AnchorLogPayloadV1::parse(entry.message())
            .map_err(|_| AnchorObservationAgreementError::MalformedAnchorLog)?;
        parsed.push(payload);
    }

    Ok(parsed)
}
