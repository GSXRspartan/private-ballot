//! Section G — pure receipt/log verification matrix.

mod common;

use common::{anchor_log, info_log, network, payload};
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_LOG_PAYLOAD_PREFIX_V1, AnchorFinalStatusV1, AnchorLogEntryV1, AnchorLogLevelV1,
    AnchorQueryOutcomeV1, AnchorReceiptSourceKindV1, AnchorReceiptV1,
    AnchorReceiptVerificationError, AnchorTransactionId, verify_anchor_receipt,
    verify_query_outcome,
};

fn transaction() -> AnchorTransactionId {
    match AnchorTransactionId::new("tx-anchor-0001".to_owned()) {
        Ok(identifier) => identifier,
        Err(_) => panic!("transaction identifier must be valid"),
    }
}

fn receipt(
    status: AnchorFinalStatusV1,
    logs: Vec<AnchorLogEntryV1>,
    source: AnchorReceiptSourceKindV1,
) -> AnchorReceiptV1 {
    AnchorReceiptV1::new(
        transaction(),
        network("esmeralda"),
        status,
        logs,
        None,
        Some(7),
        source,
    )
}

#[test]
fn accepts_full_acceptance_with_single_anchor_log_and_unrelated_logs() {
    let logs = vec![
        info_log("transaction executed"),
        anchor_log(0x22),
        info_log("fee paid"),
    ];
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        logs,
        AnchorReceiptSourceKindV1::Walletd,
    );

    let Ok(evidence) = verify_anchor_receipt(
        &transaction(),
        &network("esmeralda"),
        &payload(0x22),
        &receipt,
    ) else {
        panic!("valid receipt must verify");
    };

    assert_eq!(evidence.transaction_id(), &transaction());
    assert_eq!(evidence.anchor_digest(), payload(0x22).digest());
    assert_eq!(evidence.ledger_position(), Some(7));
    assert_eq!(evidence.source(), AnchorReceiptSourceKindV1::Walletd);
}

#[test]
fn log_order_does_not_affect_acceptance() {
    let forward = vec![info_log("a"), anchor_log(0x22), info_log("b")];
    let reversed = vec![info_log("b"), anchor_log(0x22), info_log("a")];

    let first = verify_anchor_receipt(
        &transaction(),
        &network("esmeralda"),
        &payload(0x22),
        &receipt(
            AnchorFinalStatusV1::Accepted,
            forward,
            AnchorReceiptSourceKindV1::Walletd,
        ),
    );
    let second = verify_anchor_receipt(
        &transaction(),
        &network("esmeralda"),
        &payload(0x22),
        &receipt(
            AnchorFinalStatusV1::Accepted,
            reversed,
            AnchorReceiptSourceKindV1::Walletd,
        ),
    );

    assert!(first.is_ok());
    assert_eq!(first, second);
}

#[test]
fn rejects_wrong_transaction_and_network() {
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![anchor_log(0x22)],
        AnchorReceiptSourceKindV1::Walletd,
    );

    let Ok(other_transaction) = AnchorTransactionId::new("tx-other".to_owned()) else {
        panic!("identifier must be valid");
    };

    assert_eq!(
        verify_anchor_receipt(
            &other_transaction,
            &network("esmeralda"),
            &payload(0x22),
            &receipt
        ),
        Err(AnchorReceiptVerificationError::WrongTransaction)
    );
    assert_eq!(
        verify_anchor_receipt(&transaction(), &network("igor"), &payload(0x22), &receipt),
        Err(AnchorReceiptVerificationError::WrongNetwork)
    );
}

#[test]
fn rejects_fee_only_and_rejected_statuses() {
    let fee_only = receipt(
        AnchorFinalStatusV1::FeeOnlyAccepted,
        vec![info_log("fee committed")],
        AnchorReceiptSourceKindV1::Walletd,
    );
    let rejected = receipt(
        AnchorFinalStatusV1::Rejected,
        Vec::new(),
        AnchorReceiptSourceKindV1::Walletd,
    );

    assert_eq!(
        verify_anchor_receipt(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &fee_only
        ),
        Err(AnchorReceiptVerificationError::FeeOnlyAcceptance)
    );
    assert_eq!(
        verify_anchor_receipt(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &rejected
        ),
        Err(AnchorReceiptVerificationError::RejectedTransaction)
    );
}

#[test]
fn rejects_missing_anchor_log_even_with_substring_prefix() {
    // A message that merely contains the prefix as an interior substring is not
    // a project anchor log and must be ignored.
    let interior = AnchorLogEntryV1::new(
        AnchorLogLevelV1::Info,
        format!(
            "note before {ANCHOR_LOG_PAYLOAD_PREFIX_V1}:{}",
            "22".repeat(32)
        ),
    );
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![info_log("unrelated"), interior],
        AnchorReceiptSourceKindV1::Walletd,
    );

    assert_eq!(
        verify_anchor_receipt(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &receipt
        ),
        Err(AnchorReceiptVerificationError::MissingAnchorLog)
    );
}

#[test]
fn rejects_malformed_project_anchor_log() {
    // Whole message begins with the candidate prefix but the hex is uppercase.
    let malformed = AnchorLogEntryV1::new(
        AnchorLogLevelV1::Info,
        format!("{ANCHOR_LOG_PAYLOAD_PREFIX_V1}:{}", "AA".repeat(32)),
    );
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![malformed],
        AnchorReceiptSourceKindV1::Walletd,
    );

    assert_eq!(
        verify_anchor_receipt(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &receipt
        ),
        Err(AnchorReceiptVerificationError::MalformedAnchorLog)
    );
}

#[test]
fn rejects_wrong_anchor_digest() {
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![anchor_log(0x33)],
        AnchorReceiptSourceKindV1::Walletd,
    );

    assert_eq!(
        verify_anchor_receipt(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &receipt
        ),
        Err(AnchorReceiptVerificationError::WrongAnchorDigest)
    );
}

#[test]
fn rejects_duplicate_identical_anchor_logs() {
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![anchor_log(0x22), anchor_log(0x22)],
        AnchorReceiptSourceKindV1::Walletd,
    );

    assert_eq!(
        verify_anchor_receipt(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &receipt
        ),
        Err(AnchorReceiptVerificationError::DuplicateAnchorLogs)
    );
}

#[test]
fn rejects_conflicting_anchor_logs() {
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![anchor_log(0x22), anchor_log(0x33)],
        AnchorReceiptSourceKindV1::Walletd,
    );

    assert_eq!(
        verify_anchor_receipt(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &receipt
        ),
        Err(AnchorReceiptVerificationError::ConflictingAnchorLogs)
    );
}

#[test]
fn query_outcome_verification_refuses_non_finalized_states() {
    for outcome in [
        AnchorQueryOutcomeV1::NotFound,
        AnchorQueryOutcomeV1::NotFinalized,
        AnchorQueryOutcomeV1::Unknown,
    ] {
        assert_eq!(
            verify_query_outcome(
                &transaction(),
                &network("esmeralda"),
                &payload(0x22),
                &outcome
            ),
            Err(AnchorReceiptVerificationError::NotFinalized)
        );
    }

    let finalized = AnchorQueryOutcomeV1::Finalized(receipt(
        AnchorFinalStatusV1::Accepted,
        vec![anchor_log(0x22)],
        AnchorReceiptSourceKindV1::IndependentIndexer,
    ));
    assert!(
        verify_query_outcome(
            &transaction(),
            &network("esmeralda"),
            &payload(0x22),
            &finalized
        )
        .is_ok()
    );
}
