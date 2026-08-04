//! Section H — walletd/indexer receipt-observation agreement matrix.

mod common;

use common::{anchor_log, info_log, network};
use tari_cc_private_ballot_anchor_transport::{
    AnchorFinalStatusV1, AnchorLogEntryV1, AnchorObservationAgreementError,
    AnchorReceiptSourceKindV1, AnchorReceiptV1, AnchorTransactionId, compare_receipt_observations,
};

fn transaction(value: &str) -> AnchorTransactionId {
    match AnchorTransactionId::new(value.to_owned()) {
        Ok(identifier) => identifier,
        Err(_) => panic!("transaction identifier must be valid"),
    }
}

fn observation(
    transaction_value: &str,
    network_value: &str,
    status: AnchorFinalStatusV1,
    logs: Vec<AnchorLogEntryV1>,
    source: AnchorReceiptSourceKindV1,
) -> AnchorReceiptV1 {
    AnchorReceiptV1::new(
        transaction(transaction_value),
        network(network_value),
        status,
        logs,
        None,
        Some(7),
        source,
    )
}

fn accepted_walletd(logs: Vec<AnchorLogEntryV1>) -> AnchorReceiptV1 {
    observation(
        "tx-1",
        "esmeralda",
        AnchorFinalStatusV1::Accepted,
        logs,
        AnchorReceiptSourceKindV1::Walletd,
    )
}

fn accepted_indexer(logs: Vec<AnchorLogEntryV1>) -> AnchorReceiptV1 {
    observation(
        "tx-1",
        "esmeralda",
        AnchorFinalStatusV1::Accepted,
        logs,
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
}

#[test]
fn identical_observations_agree() {
    let logs = || vec![info_log("executed"), anchor_log(0x22)];

    assert_eq!(
        compare_receipt_observations(&accepted_walletd(logs()), &accepted_indexer(logs())),
        Ok(())
    );
}

#[test]
fn transaction_id_mismatch_is_rejected() {
    let walletd = accepted_walletd(vec![anchor_log(0x22)]);
    let indexer = observation(
        "tx-2",
        "esmeralda",
        AnchorFinalStatusV1::Accepted,
        vec![anchor_log(0x22)],
        AnchorReceiptSourceKindV1::IndependentIndexer,
    );

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::TransactionIdMismatch)
    );
}

#[test]
fn network_mismatch_is_rejected() {
    let walletd = accepted_walletd(vec![anchor_log(0x22)]);
    let indexer = observation(
        "tx-1",
        "igor",
        AnchorFinalStatusV1::Accepted,
        vec![anchor_log(0x22)],
        AnchorReceiptSourceKindV1::IndependentIndexer,
    );

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::NetworkMismatch)
    );
}

#[test]
fn accepted_versus_rejected_is_a_final_status_mismatch() {
    let walletd = accepted_walletd(vec![anchor_log(0x22)]);
    let indexer = observation(
        "tx-1",
        "esmeralda",
        AnchorFinalStatusV1::Rejected,
        Vec::new(),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    );

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::FinalStatusMismatch)
    );
}

#[test]
fn fee_only_versus_full_is_distinguished() {
    let walletd = accepted_walletd(vec![anchor_log(0x22)]);
    let indexer = observation(
        "tx-1",
        "esmeralda",
        AnchorFinalStatusV1::FeeOnlyAccepted,
        vec![info_log("fee only")],
        AnchorReceiptSourceKindV1::IndependentIndexer,
    );

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::FeeOnlyVersusFullMismatch)
    );
}

#[test]
fn anchor_log_presence_mismatch_is_rejected() {
    let walletd = accepted_walletd(vec![info_log("executed"), anchor_log(0x22)]);
    let indexer = accepted_indexer(vec![info_log("executed")]);

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::AnchorLogPresenceMismatch)
    );
}

#[test]
fn different_anchor_digests_are_rejected() {
    let walletd = accepted_walletd(vec![anchor_log(0x22)]);
    let indexer = accepted_indexer(vec![anchor_log(0x33)]);

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::AnchorDigestMismatch)
    );
}

#[test]
fn differing_unrelated_logs_break_ordered_equality() {
    let walletd = accepted_walletd(vec![info_log("executed"), anchor_log(0x22)]);
    let indexer = accepted_indexer(vec![info_log("different"), anchor_log(0x22)]);

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::LogSequenceMismatch)
    );
}

#[test]
fn malformed_anchor_log_is_rejected() {
    use tari_cc_private_ballot_anchor_transport::{ANCHOR_LOG_PAYLOAD_PREFIX_V1, AnchorLogLevelV1};

    let malformed = AnchorLogEntryV1::new(
        AnchorLogLevelV1::Info,
        format!("{ANCHOR_LOG_PAYLOAD_PREFIX_V1}:{}", "AA".repeat(32)),
    );
    let walletd = accepted_walletd(vec![malformed]);
    let indexer = accepted_indexer(vec![anchor_log(0x22)]);

    assert_eq!(
        compare_receipt_observations(&walletd, &indexer),
        Err(AnchorObservationAgreementError::MalformedAnchorLog)
    );
}
