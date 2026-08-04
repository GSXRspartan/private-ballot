//! Shared deterministic constructors for the anchor-transport test suite.
//!
//! Each integration-test binary includes this module; not every binary uses
//! every helper, so unused-helper warnings are allowed here.
#![allow(dead_code)]

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorBindingV1, AnchorClientReferenceV1, AnchorLogEntryV1,
    AnchorLogLevelV1, AnchorLogPayloadV1, AnchorMaxFeeV1, AnchorPreparationRequest,
};

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

/// Builds a preparation request with a fixed fee ceiling and no client reference.
pub fn preparation(request_binding: AnchorBindingV1) -> AnchorPreparationRequest {
    AnchorPreparationRequest::new(request_binding, AnchorMaxFeeV1::from_units(1_000), None)
}

/// Builds a preparation request carrying a caller idempotency reference.
pub fn preparation_with_reference(
    request_binding: AnchorBindingV1,
    reference: &str,
) -> AnchorPreparationRequest {
    AnchorPreparationRequest::new(
        request_binding,
        AnchorMaxFeeV1::from_units(1_000),
        Some(client_reference(reference)),
    )
}

/// Builds an informational log entry from arbitrary text.
pub fn info_log(message: &str) -> AnchorLogEntryV1 {
    AnchorLogEntryV1::new(AnchorLogLevelV1::Info, message.to_owned())
}

/// Builds a canonical anchor log entry carrying a repeated-byte digest payload.
pub fn anchor_log(byte: u8) -> AnchorLogEntryV1 {
    AnchorLogEntryV1::new(AnchorLogLevelV1::Info, payload(byte).to_encoded_string())
}
