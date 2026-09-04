//! Section G — pure receipt/log verification matrix.

mod common;

use common::{anchor_log, info_log, network, payload};
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_DIGEST_KEY_V2, ANCHOR_EVENT_ELECTION_ID_KEY_V2, ANCHOR_EVENT_FUNCTION_V2,
    ANCHOR_EVENT_NETWORK_KEY_V2, ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V2,
    ANCHOR_LOG_PAYLOAD_PREFIX_V1, ANCHOR_TEMPLATE_MODULE_V2,
    ANCHOR_TEMPLATE_RECEIPT_TOPIC_PREFIX_V2, AnchorEventPayloadV3, AnchorEventProofV2,
    AnchorFinalStatusV1, AnchorLogEntryV1, AnchorLogLevelV1, AnchorQueryOutcomeV1,
    AnchorReceiptSourceKindV1, AnchorReceiptV1, AnchorReceiptVerificationError,
    AnchorTemplateBindingV2, AnchorTransactionId, verify_anchor_receipt, verify_query_outcome,
    verify_v2_event_receipt,
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

fn v2_template() -> AnchorTemplateBindingV2 {
    AnchorTemplateBindingV2::new(
        format!("template_{}", "88".repeat(32)),
        ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
        [0x88; 32],
    )
    .expect("V2 template")
}

/// A representative readable public summary — the corrected V2 template puts
/// exactly this UTF-8 string on-chain as the `public_summary` metadata value.
/// The `election_id` is a plain canonical identifier (like the preserved
/// "500-votertest-01" fixture) — NOT lowercase hex — so this test regression
/// covers a real-world election name shape.
const SAMPLE_PUBLIC_SUMMARY: &str = "{\"schema\":\"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2\",\"version\":2,\"network\":\"esmeralda\",\"election_id\":\"500-votertest-01\",\"question\":\"Which test option should win?\",\"eligible_voters\":10,\"accepted_ballots\":8,\"rejected_ballots\":2,\"results\":[{\"label\":\"A\",\"machine_id\":\"01\",\"votes\":4},{\"label\":\"B\",\"machine_id\":\"02\",\"votes\":4}]}";

fn v2_payload() -> AnchorEventPayloadV3 {
    AnchorEventPayloadV3::new(
        [0x99; 32],
        "esmeralda".to_owned(),
        "500-votertest-01".to_owned(),
        SAMPLE_PUBLIC_SUMMARY.to_owned(),
    )
    .expect("V2 payload")
}

fn v2_event(payload: &AnchorEventPayloadV3) -> AnchorEventProofV2 {
    let template = v2_template();
    AnchorEventProofV2::new(
        template.template_address().to_owned(),
        template.canonical_receipt_event_topic(),
        vec![
            (ANCHOR_EVENT_DIGEST_KEY_V2.to_owned(), payload.digest_hex()),
            (
                ANCHOR_EVENT_NETWORK_KEY_V2.to_owned(),
                payload.network().to_owned(),
            ),
            (
                ANCHOR_EVENT_ELECTION_ID_KEY_V2.to_owned(),
                payload.election_id().to_owned(),
            ),
            (
                ANCHOR_EVENT_PUBLIC_SUMMARY_KEY_V2.to_owned(),
                payload.public_summary().to_owned(),
            ),
        ],
        0,
        1,
        [0; 32],
    )
    .expect("event")
}

#[test]
fn v2_event_requires_exact_topic_and_all_four_fields() {
    let payload = v2_payload();
    let valid = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![],
        AnchorReceiptSourceKindV1::Walletd,
    )
    .with_event_proofs_v2(vec![v2_event(&payload)]);
    assert!(
        verify_v2_event_receipt(
            &transaction(),
            &network("esmeralda"),
            &v2_template(),
            &payload,
            &valid,
        )
        .is_ok()
    );

    let mut wrong_summary = v2_event(&payload);
    let mut metadata = wrong_summary.metadata().to_vec();
    // Tamper the public_summary bytes. Even a one-character difference must
    // fail because the receipt verifier compares the exact on-chain value
    // against the expected canonical summary the caller re-derived off-chain.
    metadata[3].1 = metadata[3]
        .1
        .replace("Which test option", "Which TAMPERED option");
    wrong_summary = AnchorEventProofV2::new(
        wrong_summary.template_address().to_owned(),
        wrong_summary.topic().to_owned(),
        metadata,
        wrong_summary.event_index(),
        wrong_summary.receipt_epoch(),
        *wrong_summary.intent_commitment(),
    )
    .expect("tampered event");
    let receipt = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![],
        AnchorReceiptSourceKindV1::Walletd,
    )
    .with_event_proofs_v2(vec![wrong_summary]);
    assert!(
        verify_v2_event_receipt(
            &transaction(),
            &network("esmeralda"),
            &v2_template(),
            &payload,
            &receipt
        )
        .is_err()
    );
}

#[test]
fn v2_receipt_uses_ootle_template_name_topic_not_snake_module_topic() {
    let payload = v2_payload();
    let valid = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![],
        AnchorReceiptSourceKindV1::Walletd,
    )
    .with_event_proofs_v2(vec![v2_event(&payload)]);
    assert!(
        verify_v2_event_receipt(
            &transaction(),
            &network("esmeralda"),
            &v2_template(),
            &payload,
            &valid,
        )
        .is_ok()
    );

    let old_snake_topic = format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}");
    let old_topic_event = AnchorEventProofV2::new(
        v2_template().template_address().to_owned(),
        old_snake_topic,
        v2_event(&payload).metadata().to_vec(),
        0,
        1,
        [0; 32],
    )
    .expect("old-topic event");
    let wrong = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![],
        AnchorReceiptSourceKindV1::Walletd,
    )
    .with_event_proofs_v2(vec![old_topic_event]);
    assert_eq!(
        verify_v2_event_receipt(
            &transaction(),
            &network("esmeralda"),
            &v2_template(),
            &payload,
            &wrong,
        )
        .err(),
        Some(AnchorReceiptVerificationError::WrongEventTopic)
    );
    assert_eq!(
        v2_template().canonical_receipt_event_topic(),
        format!("{ANCHOR_TEMPLATE_RECEIPT_TOPIC_PREFIX_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}")
    );
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

#[test]
fn v2_each_of_the_four_event_fields_must_match() {
    // Exhaustively mutate each of the four V2 metadata values independently and
    // require verification to fail. The digest carries its own dedicated error;
    // the other three surface as MalformedAnchorEvent.
    let payload = v2_payload();
    let base = v2_event(&payload);
    let tampered_summary = payload
        .public_summary()
        .replace("Which test option", "Which TAMPERED option");
    let cases: [(usize, String, AnchorReceiptVerificationError); 4] = [
        (
            0,
            "00".repeat(32),
            AnchorReceiptVerificationError::WrongAnchorDigest,
        ),
        (
            1,
            "igor".to_owned(),
            AnchorReceiptVerificationError::MalformedAnchorEvent,
        ),
        (
            2,
            "dead".to_owned(),
            AnchorReceiptVerificationError::MalformedAnchorEvent,
        ),
        (
            3,
            tampered_summary,
            AnchorReceiptVerificationError::MalformedAnchorEvent,
        ),
    ];
    for (index, bad_value, expected_error) in cases {
        let mut metadata = base.metadata().to_vec();
        // Guard: the replacement genuinely differs from the authentic value.
        assert_ne!(
            metadata[index].1, bad_value,
            "field {index} replacement must differ"
        );
        metadata[index].1 = bad_value;
        let tampered = AnchorEventProofV2::new(
            base.template_address().to_owned(),
            base.topic().to_owned(),
            metadata,
            base.event_index(),
            base.receipt_epoch(),
            *base.intent_commitment(),
        )
        .expect("tampered event constructs");
        let receipt = receipt(
            AnchorFinalStatusV1::Accepted,
            vec![],
            AnchorReceiptSourceKindV1::Walletd,
        )
        .with_event_proofs_v2(vec![tampered]);
        assert_eq!(
            verify_v2_event_receipt(
                &transaction(),
                &network("esmeralda"),
                &v2_template(),
                &payload,
                &receipt,
            )
            .err(),
            Some(expected_error),
            "mutating V2 field index {index} must fail verification",
        );
    }

    // Control: the untouched event still verifies, proving the failures above are
    // caused only by the single mutated field.
    let valid = receipt(
        AnchorFinalStatusV1::Accepted,
        vec![],
        AnchorReceiptSourceKindV1::Walletd,
    )
    .with_event_proofs_v2(vec![v2_event(&payload)]);
    assert!(
        verify_v2_event_receipt(
            &transaction(),
            &network("esmeralda"),
            &v2_template(),
            &payload,
            &valid,
        )
        .is_ok()
    );
}
