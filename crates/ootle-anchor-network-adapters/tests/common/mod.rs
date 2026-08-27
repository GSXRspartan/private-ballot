//! Shared test helpers for the network-adapter offline test suites.
//!
//! Each test binary includes this module; not every binary uses every helper or
//! the imports a helper needs, so unused-helper/import warnings are allowed.

#![allow(dead_code, unused_imports)]

use core::str::FromStr;
use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorBindingV1, AnchorEpochBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1,
    AnchorPreparationRequest, AnchorTemplateBindingV1, AnchorTransactionId,
};
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorTransactionBuildRequestV1, build_fee_bearing_anchor_transaction,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryV1;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::receipt_scenarios::{
    SCENARIO_TEMPLATE_ADDRESS, SCENARIO_TEMPLATE_MODULE,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, SubmittedWalletdAnchorRequestV1, WalletdAnchorCoordinator,
    WalletdCreateAnchorRequestV1, WalletdDecisionRequestV1, WalletdFeeComponentRef,
    WalletdSealSignerRef, WalletdSubmitRequestV1, build_fee_bearing_walletd_create_request,
};
use tari_template_lib_types::ComponentAddress;

use tari_cc_private_ballot_ootle_anchor_network_adapters::{IndexerEndpoint, WalletdEndpoint};

pub fn network() -> OotleNetworkIdV1 {
    OotleNetworkIdV1::new("esmeralda".to_owned())
        .unwrap_or_else(|e| panic!("test network must be valid: {e:?}"))
}

pub fn account() -> AnchorAccountReference {
    AnchorAccountReference::new("fee-account".to_owned())
        .unwrap_or_else(|e| panic!("test account must be valid: {e:?}"))
}

pub fn digest(byte: u8) -> OotleAnchorRecordHashV1 {
    OotleAnchorRecordHashV1::new([byte; 32])
}

pub fn payload(byte: u8) -> AnchorLogPayloadV1 {
    AnchorLogPayloadV1::from_digest(digest(byte))
}

pub fn max_fee() -> AnchorMaxFeeV1 {
    AnchorMaxFeeV1::from_units(1_000)
}

pub fn template_binding() -> AnchorTemplateBindingV1 {
    let topic = format!("{SCENARIO_TEMPLATE_MODULE}.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1");
    AnchorTemplateBindingV1::new(
        SCENARIO_TEMPLATE_ADDRESS.to_owned(),
        SCENARIO_TEMPLATE_MODULE.to_owned(),
        "publish_anchor".to_owned(),
        topic,
        [0x33; 32],
    )
    .unwrap_or_else(|e| panic!("test template binding must be valid: {e:?}"))
}

pub fn epoch_binding() -> AnchorEpochBindingV1 {
    AnchorEpochBindingV1::from_observed_epoch(100, 12)
        .unwrap_or_else(|e| panic!("test epoch binding must be valid: {e:?}"))
}

pub fn build_request() -> OotleAnchorTransactionBuildRequestV1 {
    let binding = AnchorBindingV1::new(network(), account(), payload(0x22));
    let preparation = AnchorPreparationRequest::new(binding, max_fee(), None);
    OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
        preparation,
        template_binding(),
        epoch_binding(),
    )
}

pub fn fee_component_address() -> ComponentAddress {
    ComponentAddress::from_str(
        "component_1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap_or_else(|e| panic!("fee component address must be valid: {e:?}"))
}

pub fn fee_component() -> WalletdFeeComponentRef {
    WalletdFeeComponentRef::parse(
        "component_1111111111111111111111111111111111111111111111111111111111111111",
    )
    .unwrap_or_else(|e| panic!("fee component must be valid: {e:?}"))
}

pub fn seal_signer() -> WalletdSealSignerRef {
    WalletdSealSignerRef::AccountKey { index: 0 }
}

pub fn build_result() -> tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorBuildResultV1 {
    build_fee_bearing_anchor_transaction(&build_request(), fee_component_address())
        .unwrap_or_else(|e| panic!("build must succeed: {e:?}"))
}

pub fn walletd_create_request() -> WalletdCreateAnchorRequestV1 {
    build_fee_bearing_walletd_create_request(
        &build_result(),
        fee_component_address(),
        seal_signer(),
        None,
    )
    .unwrap_or_else(|e| panic!("walletd create request must be valid: {e:?}"))
}

pub fn walletd_endpoint() -> WalletdEndpoint {
    WalletdEndpoint::parse("http://127.0.0.1:12009")
        .unwrap_or_else(|e| panic!("test walletd endpoint must be valid: {e:?}"))
}

pub fn indexer_endpoint() -> IndexerEndpoint {
    IndexerEndpoint::parse("http://127.0.0.1:12500")
        .unwrap_or_else(|e| panic!("test indexer endpoint must be valid: {e:?}"))
}

pub fn transaction_id(byte: u8) -> AnchorTransactionId {
    let hex: String = (0..32).map(|_| format!("{byte:02x}")).collect();
    AnchorTransactionId::new(hex)
        .unwrap_or_else(|e| panic!("test transaction id must be valid: {e:?}"))
}

/// Drives the fake walletd client through the coordinator to produce a
/// genuine `SubmittedWalletdAnchorRequestV1`. This is the only way to
/// construct one outside the 4A6 crate (its constructor is `pub(crate)`).
pub fn submitted_request() -> SubmittedWalletdAnchorRequestV1 {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let prepared = coordinator
        .prepare_fee_bearing(
            &mut client,
            &build_request(),
            &fee_component(),
            seal_signer(),
            None,
        )
        .unwrap_or_else(|e| panic!("prepare must succeed: {e:?}"));
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let approved = coordinator
        .approve(&mut client, &decision)
        .unwrap_or_else(|e| panic!("approve must succeed: {e:?}"));
    let submit = WalletdSubmitRequestV1::for_approved(&approved);
    coordinator
        .submit(&mut client, &submit)
        .unwrap_or_else(|e| panic!("submit must succeed: {e:?}"))
}

pub fn receipt_query() -> AnchorReceiptQueryV1 {
    let submitted = submitted_request();
    AnchorReceiptQueryV1::from_submitted(&submitted)
}

/// Convenience alias for `receipt_query()` — the transaction ID argument is
/// ignored because the query's transaction ID is determined by the fake
/// walletd's deterministic submit. The scripted transport returns the same
/// response regardless of the address, so the specific ID does not affect
/// the outcome of archive-independence tests.
pub fn receipt_query_for_tx(_tx_id: &AnchorTransactionId) -> AnchorReceiptQueryV1 {
    receipt_query()
}
