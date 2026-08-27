//! The deterministic fake and the real Ootle construction adapter agree on every
//! project-boundary value.
//!
//! Parity is asserted only over project-owned values: anchor digest, network,
//! account, fee policy, and client reference, plus the shared invariants that
//! neither side claims a transaction identifier before submission and neither
//! claims finality. The fake's post-submission transaction identifier is
//! fake-only and is deliberately never compared to the unsigned Ootle
//! transaction.

mod common;

use common::{binding, client_reference, epoch_binding, template_binding};
use tari_cc_private_ballot_anchor_transport::{
    AnchorLifecycleState, AnchorMaxFeeV1, AnchorPreparationRequest, AnchorTransactionRequestStore,
    DeterministicAnchorFake,
};
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorTransactionBuildRequestV1, build_unsigned_anchor_transaction,
};
use tari_ootle_transaction::Instruction;

#[test]
fn fake_and_real_adapter_agree_on_every_project_boundary_value() {
    let preparation = AnchorPreparationRequest::new(
        binding("esmeralda", "fee-account", 0x22),
        AnchorMaxFeeV1::from_units(4_242),
        Some(client_reference("parity-1")),
    );
    let adapter_request =
        OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
            preparation.clone(),
            template_binding(),
            epoch_binding(),
        );

    // Deterministic fake path.
    let mut fake = DeterministicAnchorFake::new();
    let Ok(prepared) = fake.create_request(&preparation) else {
        panic!("fake preparation must succeed");
    };

    // Real pinned Ootle construction path.
    let Ok(result) = build_unsigned_anchor_transaction(&adapter_request) else {
        panic!("real construction must succeed");
    };
    let evidence = result.evidence();
    let preparation_dto = result.walletd_preparation();

    // Anchor digest parity: the fake, the real evidence, and the v0.39.2 event
    // payload all commit to the exact same aggregate anchor digest.
    assert_eq!(prepared.anchor_digest(), evidence.anchor_digest());
    assert_eq!(evidence.event_payload().digest(), prepared.anchor_digest());
    assert_eq!(
        prepared.payload().digest(),
        evidence.event_payload().digest()
    );

    // The real transaction is exactly one `publish_anchor` CallFunction.
    match result.unsigned_transaction().instructions() {
        [Instruction::CallFunction { function, .. }] => {
            assert_eq!(&**function, "publish_anchor");
        }
        other => panic!("expected exactly one CallFunction, got {}", other.len()),
    }

    // Network parity.
    assert_eq!(
        prepared.binding().network().as_str(),
        evidence.network().as_str()
    );

    // Account reference parity.
    assert_eq!(
        prepared.binding().account().as_str(),
        evidence.account().as_str()
    );

    // Fee policy parity at the project boundary.
    assert_eq!(prepared.max_fee().value(), preparation_dto.max_fee().value());
    assert_eq!(preparation_dto.max_fee().value(), 4_242);

    // Client reference parity.
    match preparation_dto.client_reference() {
        Some(reference) => assert_eq!(reference.as_str(), "parity-1"),
        None => panic!("client reference must be preserved on the real path"),
    }

    // Neither side claims a transaction identifier before submission: the fake's
    // prepared snapshot has none, and the real evidence has no such field.
    assert_eq!(prepared.state(), AnchorLifecycleState::Prepared);
    let Ok(snapshot) = fake.get_request(prepared.request_id()) else {
        panic!("prepared request must be retrievable");
    };
    assert!(
        snapshot.transaction_id().is_none(),
        "no transaction id before submission"
    );
    assert_eq!(snapshot.last_receipt_status(), None, "no finality claim");
}

#[test]
fn fake_idempotency_reference_matches_the_preserved_real_reference() {
    // The same client reference is honoured on both paths: the fake returns the
    // same request on re-preparation, and the real path preserves the reference.
    let preparation = AnchorPreparationRequest::new(
        binding("igor", "treasury", 0x77),
        AnchorMaxFeeV1::from_units(10),
        Some(client_reference("idem-9")),
    );

    let mut fake = DeterministicAnchorFake::new();
    let Ok(first) = fake.create_request(&preparation) else {
        panic!("first preparation must succeed");
    };
    let Ok(second) = fake.create_request(&preparation) else {
        panic!("idempotent re-preparation must succeed");
    };
    assert_eq!(
        first.request_id(),
        second.request_id(),
        "fake honours the client reference"
    );

    let Ok(result) = build_unsigned_anchor_transaction(
        &OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
            preparation,
            template_binding(),
            epoch_binding(),
        ),
    ) else {
        panic!("real construction must succeed");
    };
    match result.walletd_preparation().client_reference() {
        Some(reference) => assert_eq!(reference.as_str(), "idem-9"),
        None => panic!("real path must preserve the client reference"),
    }
}
