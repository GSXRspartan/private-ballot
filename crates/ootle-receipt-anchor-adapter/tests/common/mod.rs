//! Shared deterministic constructors for the receipt-adapter test suite.
//!
//! Each integration-test binary includes this module; not every binary uses
//! every helper, so unused-helper warnings are allowed here (matching the
//! Slice 4A5/4A6 test convention). Every helper is offline and deterministic and
//! drives the real Slice 4A6B walletd flow to obtain a genuine
//! [`SubmittedWalletdAnchorRequestV1`] — the only way to construct one.

#![allow(dead_code)]

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorBindingV1, AnchorEpochBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1,
    AnchorPreparationRequest, AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::receipt_scenarios::{
    SCENARIO_TEMPLATE_ADDRESS, SCENARIO_TEMPLATE_MODULE,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryV1;
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, SubmittedWalletdAnchorRequestV1, WalletdAnchorCoordinator,
    WalletdDecisionRequestV1, WalletdFeeComponentRef, WalletdSealSignerRef, WalletdSubmitRequestV1,
};

/// The digest byte used by the canonical submitted request.
pub const CANONICAL_DIGEST_BYTE: u8 = 0x22;

/// Builds a valid bounded network identifier or panics.
#[must_use]
pub fn network(value: &str) -> OotleNetworkIdV1 {
    match OotleNetworkIdV1::new(value.to_owned()) {
        Ok(identifier) => identifier,
        Err(_error) => panic!("test network identifier must be valid"),
    }
}

/// The canonical Esmeralda testnet network identifier.
#[must_use]
pub fn canonical_network() -> OotleNetworkIdV1 {
    network("esmeralda")
}

/// Builds a valid bounded account reference or panics.
#[must_use]
pub fn account(value: &str) -> AnchorAccountReference {
    match AnchorAccountReference::new(value.to_owned()) {
        Ok(reference) => reference,
        Err(_error) => panic!("test account reference must be valid"),
    }
}

/// Builds a 32-byte anchor-record digest with a repeated byte.
#[must_use]
pub fn digest(byte: u8) -> OotleAnchorRecordHashV1 {
    OotleAnchorRecordHashV1::new([byte; 32])
}

/// Builds a canonical anchor log payload for a repeated-byte digest.
#[must_use]
pub fn payload(byte: u8) -> AnchorLogPayloadV1 {
    AnchorLogPayloadV1::from_digest(digest(byte))
}

/// The canonical anchor log payload of the submitted request.
#[must_use]
pub fn canonical_payload() -> AnchorLogPayloadV1 {
    payload(CANONICAL_DIGEST_BYTE)
}

/// A deterministic seal-signer reference (account key, index 0).
#[must_use]
pub fn seal_signer() -> WalletdSealSignerRef {
    WalletdSealSignerRef::AccountKey { index: 0 }
}

/// A deterministic, valid resolved fee account component address.
#[must_use]
pub fn fee_component() -> WalletdFeeComponentRef {
    match WalletdFeeComponentRef::parse(&format!("component_{}", "11".repeat(32))) {
        Ok(reference) => reference,
        Err(_error) => panic!("test fee component address must be valid"),
    }
}

/// A valid pinned event-template deployment identity for tests.
///
/// It reuses the exact scenario deployment address/module so the queries built
/// here verify against the anchor events the scenario receipts carry.
#[must_use]
pub fn template_binding() -> AnchorTemplateBindingV1 {
    let topic = format!("{SCENARIO_TEMPLATE_MODULE}.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1");
    match AnchorTemplateBindingV1::new(
        SCENARIO_TEMPLATE_ADDRESS.to_owned(),
        SCENARIO_TEMPLATE_MODULE.to_owned(),
        "publish_anchor".to_owned(),
        topic,
        [0x33; 32],
    ) {
        Ok(binding) => binding,
        Err(_error) => panic!("test template binding must be valid"),
    }
}

/// A valid observed/max epoch binding for tests (observed 100, delta 12).
#[must_use]
pub fn epoch_binding() -> AnchorEpochBindingV1 {
    match AnchorEpochBindingV1::from_observed_epoch(100, 12) {
        Ok(binding) => binding,
        Err(_error) => panic!("test epoch binding must be valid"),
    }
}

/// Builds a v0.39.2 build request (with template + epoch binding) from its parts.
#[must_use]
pub fn build_request(
    network_value: &str,
    account_value: &str,
    digest_byte: u8,
    max_fee: u64,
) -> OotleAnchorTransactionBuildRequestV1 {
    let binding = AnchorBindingV1::new(
        network(network_value),
        account(account_value),
        payload(digest_byte),
    );
    let preparation =
        AnchorPreparationRequest::new(binding, AnchorMaxFeeV1::from_units(max_fee), None);
    OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
        preparation,
        template_binding(),
        epoch_binding(),
    )
}

/// Drives the real fee-bearing prepare -> approve -> submit flow to obtain a
/// genuine submitted request for the given parameters.
#[must_use]
pub fn submit(
    network_value: &str,
    account_value: &str,
    digest_byte: u8,
) -> SubmittedWalletdAnchorRequestV1 {
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let request = build_request(network_value, account_value, digest_byte, 1_000);
    let Ok(prepared) = coordinator.prepare_fee_bearing(
        &mut client,
        &request,
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("fee-bearing prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(approved) = coordinator.approve(&mut client, &decision) else {
        panic!("approve must succeed");
    };
    let submit_request = WalletdSubmitRequestV1::for_approved(&approved);
    let Ok(submitted) = coordinator.submit(&mut client, &submit_request) else {
        panic!("submit must succeed");
    };
    submitted
}

/// Drives the real fee-bearing prepare -> approve -> submit flow for a specific
/// anchor log payload (used to bind a submitted request to a real anchor-record
/// digest).
#[must_use]
pub fn submit_payload(anchor_payload: AnchorLogPayloadV1) -> SubmittedWalletdAnchorRequestV1 {
    let binding = AnchorBindingV1::new(canonical_network(), account("fee-account"), anchor_payload);
    let request = OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
        AnchorPreparationRequest::new(binding, AnchorMaxFeeV1::from_units(1_000), None),
        template_binding(),
        epoch_binding(),
    );
    let mut client = FakeWalletdAnchorClient::new();
    let mut coordinator = WalletdAnchorCoordinator::new();
    let Ok(prepared) = coordinator.prepare_fee_bearing(
        &mut client,
        &request,
        &fee_component(),
        seal_signer(),
        None,
    ) else {
        panic!("fee-bearing prepare must succeed");
    };
    let decision = WalletdDecisionRequestV1::for_prepared(&prepared);
    let Ok(approved) = coordinator.approve(&mut client, &decision) else {
        panic!("approve must succeed");
    };
    let submit_request = WalletdSubmitRequestV1::for_approved(&approved);
    let Ok(submitted) = coordinator.submit(&mut client, &submit_request) else {
        panic!("submit must succeed");
    };
    submitted
}

/// The canonical submitted request on Esmeralda with account `fee-account` and
/// digest byte [`CANONICAL_DIGEST_BYTE`].
#[must_use]
pub fn canonical_submitted() -> SubmittedWalletdAnchorRequestV1 {
    submit("esmeralda", "fee-account", CANONICAL_DIGEST_BYTE)
}

/// The receipt query bound to a submitted request.
#[must_use]
pub fn query_of(submitted: &SubmittedWalletdAnchorRequestV1) -> AnchorReceiptQueryV1 {
    AnchorReceiptQueryV1::from_submitted(submitted)
}
