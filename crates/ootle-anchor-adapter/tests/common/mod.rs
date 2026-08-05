//! Shared deterministic constructors for the adapter test suite.
//!
//! Each integration-test binary includes this module; not every binary uses
//! every helper, so unused-helper warnings are allowed here (matching the
//! anchor-transport test convention).
#![allow(dead_code)]

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorBindingV1, AnchorClientReferenceV1, AnchorLogPayloadV1,
    AnchorMaxFeeV1, AnchorPreparationRequest,
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

/// Builds an adapter build request from its parts.
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

/// A canonical, valid build request on the Esmeralda testnet.
pub fn valid_request() -> OotleAnchorTransactionBuildRequestV1 {
    build_request("esmeralda", "fee-account", 0x22, 1_000, None)
}
