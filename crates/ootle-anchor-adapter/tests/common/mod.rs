//! Shared deterministic constructors for the adapter test suite.
//!
//! Each integration-test binary includes this module; not every binary uses
//! every helper, so unused-helper warnings are allowed here (matching the
//! anchor-transport test convention).
#![allow(dead_code)]

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorBindingV1, AnchorClientReferenceV1, AnchorEpochBindingV1,
    AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationRequest, AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1;

/// Builds a valid bounded network identifier or panics.
pub fn network(value: &str) -> OotleNetworkIdV1 {
    match OotleNetworkIdV1::new(value.to_owned()) {
        Ok(identifier) => identifier,
        Err(_) => panic!("test network identifier must be valid"),
    }
}

/// Builds a valid bounded account reference or panics.
pub fn account(value: &str) -> AnchorAccountReference {
    match AnchorAccountReference::new(value.to_owned()) {
        Ok(reference) => reference,
        Err(_) => panic!("test account reference must be valid"),
    }
}

/// Builds a valid bounded client reference or panics.
pub fn client_reference(value: &str) -> AnchorClientReferenceV1 {
    match AnchorClientReferenceV1::new(value.to_owned()) {
        Ok(reference) => reference,
        Err(_) => panic!("test client reference must be valid"),
    }
}

/// Builds a 32-byte anchor-record digest with a repeated byte.
pub fn digest(byte: u8) -> OotleAnchorRecordHashV1 {
    OotleAnchorRecordHashV1::new([byte; 32])
}

/// Builds a canonical anchor log payload for a repeated-byte digest.
pub fn payload(byte: u8) -> AnchorLogPayloadV1 {
    AnchorLogPayloadV1::from_digest(digest(byte))
}

/// Builds a binding over a network, account, and repeated-byte digest.
pub fn binding(network_value: &str, account_value: &str, digest_byte: u8) -> AnchorBindingV1 {
    AnchorBindingV1::new(
        network(network_value),
        account(account_value),
        payload(digest_byte),
    )
}

/// Builds a legacy (template-less) adapter build request from its parts.
///
/// This deliberately omits the v0.39.2 event-template and epoch binding, so it
/// is only useful for asserting the `MissingEventBinding` fail-closed path; the
/// real construction path requires [`build_request_v2`].
pub fn build_request(
    network_value: &str,
    account_value: &str,
    digest_byte: u8,
    max_fee: u64,
    client: Option<&str>,
) -> OotleAnchorTransactionBuildRequestV1 {
    let preparation = AnchorPreparationRequest::new(
        binding(network_value, account_value, digest_byte),
        AnchorMaxFeeV1::from_units(max_fee),
        client.map(client_reference),
    );
    OotleAnchorTransactionBuildRequestV1::from_preparation_request(preparation)
}

/// A canonical Ootle template address string (`template_<64 hex>`).
///
/// `byte_pair` is a two-character lowercase-hex seed repeated 32 times. This is
/// the exact textual shape a real published template address has, so it
/// round-trips through the same parser the adapter uses in construction and
/// inspection.
pub fn template_address_string(byte_pair: &str) -> String {
    format!("template_{}", byte_pair.repeat(32))
}

/// A valid pinned event-template deployment identity with the given address.
pub fn template_binding_with_address(address: &str) -> AnchorTemplateBindingV1 {
    let module = "tari_private_ballot_anchor";
    let topic = format!("{module}.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1");
    match AnchorTemplateBindingV1::new(
        address.to_owned(),
        module.to_owned(),
        "publish_anchor".to_owned(),
        topic,
        [0x33; 32],
    ) {
        Ok(binding) => binding,
        Err(_) => panic!("test template binding must be valid"),
    }
}

/// The canonical valid template deployment identity used by the happy path.
pub fn template_binding() -> AnchorTemplateBindingV1 {
    template_binding_with_address(&template_address_string("11"))
}

/// A second, distinct valid template deployment identity (a different published
/// address) for wrong-deployment rejection tests.
pub fn other_template_binding() -> AnchorTemplateBindingV1 {
    template_binding_with_address(&template_address_string("aa"))
}

/// A valid observed/max epoch binding for tests (observed 100, delta 12).
pub fn epoch_binding() -> AnchorEpochBindingV1 {
    match AnchorEpochBindingV1::from_observed_epoch(100, 12) {
        Ok(binding) => binding,
        Err(_) => panic!("test epoch binding must be valid"),
    }
}

/// Builds a v0.39.2 adapter build request bound to the canonical template and
/// epoch. This is the request shape the real driver produces.
pub fn build_request_v2(
    network_value: &str,
    account_value: &str,
    digest_byte: u8,
    max_fee: u64,
    client: Option<&str>,
) -> OotleAnchorTransactionBuildRequestV1 {
    let preparation = AnchorPreparationRequest::new(
        binding(network_value, account_value, digest_byte),
        AnchorMaxFeeV1::from_units(max_fee),
        client.map(client_reference),
    );
    OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
        preparation,
        template_binding(),
        epoch_binding(),
    )
}

/// A canonical, valid v0.39.2 build request on the Esmeralda testnet.
pub fn valid_request() -> OotleAnchorTransactionBuildRequestV1 {
    build_request_v2("esmeralda", "fee-account", 0x22, 1_000, None)
}
