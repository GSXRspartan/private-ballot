//! Deterministic project-owned receipt builders for the offline fake and the
//! test suites (Section J).
//!
//! These construct [`AnchorReceiptV1`] values in every scenario the contract must
//! cover — full acceptance, fee-only, rejection, missing/malformed/wrong/
//! duplicate/conflicting/unrelated anchor logs — using only the anchor-transport
//! public API. They name no pinned Ootle type and perform no I/O. A `walletd_`
//! variant produces the same observation recorded with the walletd source, for
//! cross-source agreement scenarios.

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_DIGEST_KEY_V1, ANCHOR_EVENT_TOPIC_SUFFIX_V1, ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1,
    AnchorEventPayloadV2, AnchorEventProofV2, AnchorFinalStatusV1, AnchorLogEntryV1,
    AnchorLogLevelV1, AnchorLogPayloadV1, AnchorReceiptSourceKindV1, AnchorReceiptV1,
    AnchorTransactionId,
};

/// Deterministic opaque ledger position reported for a finalized fake receipt.
pub const FAKE_LEDGER_POSITION: u64 = 7;

/// The canonical scenario event-template deployment address (`template_<64 hex>`).
///
/// This is a deterministic *test fixture*, not a network constant: it stands in
/// for the address of the one immutable event template published on whichever
/// network a scenario names. A test that verifies these receipts must configure
/// the same address in its template binding, exactly as a real operator pins the
/// per-network deployment address.
pub const SCENARIO_TEMPLATE_ADDRESS: &str =
    "template_1111111111111111111111111111111111111111111111111111111111111111";

/// The scenario event-template module name (shared template-contract constant).
pub const SCENARIO_TEMPLATE_MODULE: &str = "tari_private_ballot_anchor";

/// The full stored event topic the scenario anchor events carry.
fn scenario_event_topic() -> String {
    format!("{SCENARIO_TEMPLATE_MODULE}.{ANCHOR_EVENT_TOPIC_SUFFIX_V1}")
}

/// Builds one bounded anchor event proof for `payload` at `event_index`, carrying
/// exactly the sole `anchor_digest` metadata key, bound to the canonical scenario
/// template deployment. This mirrors what the v0.39.2 receipt converter copies
/// out of a real finalized receipt.
fn anchor_event_proof(payload: &AnchorLogPayloadV1, event_index: u16) -> AnchorEventProofV2 {
    let digest_hex = AnchorEventPayloadV2::from_digest(payload.digest()).digest_hex();
    match AnchorEventProofV2::new(
        SCENARIO_TEMPLATE_ADDRESS.to_owned(),
        scenario_event_topic(),
        vec![(ANCHOR_EVENT_DIGEST_KEY_V1.to_owned(), digest_hex)],
        event_index,
        FAKE_LEDGER_POSITION,
        [0_u8; 32],
    ) {
        Ok(proof) => proof,
        // The inputs are fixed valid fixtures, so this is unreachable in practice.
        Err(_error) => panic!("scenario anchor event proof must be valid"),
    }
}

/// Builds a receipt from explicit parts (the general constructor).
#[must_use]
pub fn receipt(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    final_status: AnchorFinalStatusV1,
    logs: Vec<AnchorLogEntryV1>,
    rejection_reason: Option<String>,
    ledger_position: Option<u64>,
    source: AnchorReceiptSourceKindV1,
) -> AnchorReceiptV1 {
    AnchorReceiptV1::new(
        transaction_id.clone(),
        network.clone(),
        final_status,
        logs,
        rejection_reason,
        ledger_position,
        source,
    )
}

/// The ordered logs of a full acceptance carrying exactly one anchor log.
fn accepted_logs(payload: &AnchorLogPayloadV1) -> Vec<AnchorLogEntryV1> {
    vec![
        AnchorLogEntryV1::new(AnchorLogLevelV1::Info, "transaction executed".to_owned()),
        AnchorLogEntryV1::new(AnchorLogLevelV1::Info, payload.to_encoded_string()),
    ]
}

/// A full acceptance carrying exactly one valid anchor log (indexer source).
#[must_use]
pub fn accepted_receipt(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    payload: &AnchorLogPayloadV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        accepted_logs(payload),
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
    .with_event_proofs_v2(vec![anchor_event_proof(payload, 0)])
}

/// A full acceptance carrying exactly one valid anchor log (walletd source).
#[must_use]
pub fn walletd_accepted_receipt(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    payload: &AnchorLogPayloadV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        accepted_logs(payload),
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::Walletd,
    )
    .with_event_proofs_v2(vec![anchor_event_proof(payload, 0)])
}

/// A v0.39.2-faithful full acceptance: **no** receipt logs (the receipt `logs`
/// field was removed in v0.39.2) and exactly one anchor event.
///
/// Unlike [`accepted_receipt`] (which also carries historical V1 logs so the
/// log-based cross-source agreement path can exercise it), this is exactly what
/// a real indexer returns for a v0.39.2 anchor, so it round-trips through the
/// wire `TransactionReceipt` byte-for-byte.
#[must_use]
pub fn accepted_event_receipt(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    payload: &AnchorLogPayloadV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        Vec::new(),
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
    .with_event_proofs_v2(vec![anchor_event_proof(payload, 0)])
}

/// A fee-only acceptance (no anchor log): the anchor did not land.
#[must_use]
pub fn fee_only_receipt(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::FeeOnlyAccepted,
        vec![AnchorLogEntryV1::new(
            AnchorLogLevelV1::Warn,
            "fee intent committed; main intent rejected".to_owned(),
        )],
        Some("main intent rejected after fee".to_owned()),
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
}

/// A ledger rejection: no anchor, no logs, a bounded reason.
#[must_use]
pub fn rejected_receipt(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Rejected,
        Vec::new(),
        Some("execution failure".to_owned()),
        None,
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
}

/// A full acceptance with unrelated logs but no anchor log.
#[must_use]
pub fn accepted_missing_anchor_log(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        vec![
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, "transaction executed".to_owned()),
            AnchorLogEntryV1::new(AnchorLogLevelV1::Debug, "unrelated diagnostic".to_owned()),
        ],
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
}

/// A full acceptance whose single anchor log encodes a different digest.
#[must_use]
pub fn accepted_wrong_anchor_log(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    wrong_payload: &AnchorLogPayloadV1,
) -> AnchorReceiptV1 {
    accepted_receipt(transaction_id, network, wrong_payload)
}

/// A full acceptance carrying two identical anchor logs.
#[must_use]
pub fn accepted_duplicate_anchor_logs(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    payload: &AnchorLogPayloadV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        vec![
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, payload.to_encoded_string()),
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, payload.to_encoded_string()),
        ],
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
    // Two identical anchor events: the v0.39.2 verifier rejects any receipt with
    // more than one candidate anchor event.
    .with_event_proofs_v2(vec![
        anchor_event_proof(payload, 0),
        anchor_event_proof(payload, 1),
    ])
}

/// A full acceptance carrying two differing anchor logs.
#[must_use]
pub fn accepted_conflicting_anchor_logs(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    payload_a: &AnchorLogPayloadV1,
    payload_b: &AnchorLogPayloadV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        vec![
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, payload_a.to_encoded_string()),
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, payload_b.to_encoded_string()),
        ],
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
    // Two differing anchor events: still more than one candidate, so rejected.
    .with_event_proofs_v2(vec![
        anchor_event_proof(payload_a, 0),
        anchor_event_proof(payload_b, 1),
    ])
}

/// A full acceptance carrying the valid anchor log plus unrelated logs.
#[must_use]
pub fn accepted_with_unrelated_logs(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
    payload: &AnchorLogPayloadV1,
) -> AnchorReceiptV1 {
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        vec![
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, "transaction executed".to_owned()),
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, payload.to_encoded_string()),
            AnchorLogEntryV1::new(
                AnchorLogLevelV1::Debug,
                "post-anchor bookkeeping".to_owned(),
            ),
        ],
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
    // Exactly one anchor event alongside unrelated diagnostics still verifies.
    .with_event_proofs_v2(vec![anchor_event_proof(payload, 0)])
}

/// A full acceptance whose anchor-shaped log begins with the candidate prefix but
/// fails strict parsing (a malformed project log).
#[must_use]
pub fn accepted_malformed_anchor_log(
    transaction_id: &AnchorTransactionId,
    network: &OotleNetworkIdV1,
) -> AnchorReceiptV1 {
    // The candidate prefix followed by a too-short, non-hex remainder: it is
    // recognised as a project anchor log but cannot parse.
    let malformed = format!("{ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1}not-hex");
    receipt(
        transaction_id,
        network,
        AnchorFinalStatusV1::Accepted,
        vec![AnchorLogEntryV1::new(AnchorLogLevelV1::Info, malformed)],
        None,
        Some(FAKE_LEDGER_POSITION),
        AnchorReceiptSourceKindV1::IndependentIndexer,
    )
}
