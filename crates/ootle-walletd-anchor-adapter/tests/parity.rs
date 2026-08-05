//! Real / fake request-conversion parity (Section J).
//!
//! Proves the confirmed walletd wire request built by the conversion and the
//! request captured by the offline fake agree on every project-relevant field:
//! the exact `EmitLog` payload, network, fee account, maximum fee, instruction
//! count, anchor digest, and unsigned-transaction fingerprint — and that neither
//! carries a transaction identifier or any finality state.

mod common;

use common::{build_request, seal_signer, valid_build_result};
use tari_cc_private_ballot_anchor_transport::AnchorLifecycleState;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorInspectionExpectationV1, inspect_unsigned_anchor_transaction,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, WalletdAnchorCoordinator, WalletdEffectiveStatusV1,
    build_walletd_create_request,
};

fn esmeralda_expectation() -> AnchorInspectionExpectationV1 {
    match AnchorInspectionExpectationV1::for_request(&build_request(
        "esmeralda",
        "fee-account",
        0x22,
        1_000,
        None,
    )) {
        Ok(expectation) => expectation,
        Err(_error) => panic!("expectation must build"),
    }
}

#[test]
fn conversion_and_fake_capture_agree_on_every_field() {
    let build = valid_build_result();

    // "Real" conversion: the exact confirmed walletd create-transaction-request.
    let Ok(real) = build_walletd_create_request(&build, seal_signer(), None) else {
        panic!("conversion must succeed");
    };

    // "Fake" path: the same conversion, captured by the offline client.
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare(&mut client, &build, seal_signer(), None) else {
        panic!("prepare must succeed");
    };
    let Some(captured) = client.last_captured_create() else {
        panic!("a create request must be captured");
    };

    // Bindings and fingerprints agree, and match the Slice 4A5 evidence.
    assert_eq!(real.binding(), captured.binding());
    assert_eq!(real.fingerprint(), build.evidence().fingerprint());
    assert_eq!(captured.fingerprint(), build.evidence().fingerprint());

    // Fee account and maximum fee are preserved from the build result.
    assert_eq!(
        real.binding().account(),
        build.walletd_preparation().fee_account()
    );
    assert_eq!(
        real.binding().max_fee(),
        build.walletd_preparation().max_fee()
    );
    assert_eq!(
        real.binding().network(),
        build.walletd_preparation().network()
    );

    // The wire transaction inspects to exactly one anchor EmitLog with the exact
    // payload, the expected network, the expected digest, and the same
    // fingerprint — proving the frozen transaction is the Slice 4A5 transaction.
    let Ok(evidence) = inspect_unsigned_anchor_transaction(
        &real.wire_request().transaction,
        &esmeralda_expectation(),
    ) else {
        panic!("wire transaction must inspect");
    };
    assert_eq!(evidence.instruction_count(), 1);
    assert_eq!(evidence.anchor_log_payload(), &common::payload(0x22));
    assert_eq!(evidence.anchor_digest(), common::digest(0x22));
    assert_eq!(evidence.fingerprint(), build.evidence().fingerprint());

    // No transaction identifier and no finality: prepared stays Prepared and the
    // wallet daemon reports the request as merely pending.
    assert_eq!(prepared.state(), AnchorLifecycleState::Prepared);
    assert_eq!(
        client.status_of(prepared.walletd_request_id()),
        Some(WalletdEffectiveStatusV1::Pending)
    );
}
