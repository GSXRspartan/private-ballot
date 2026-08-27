//! v0.39.2 inspection rejects every invalid or mutated event-anchor transaction,
//! and no rejection path panics.
//!
//! Each case builds a fresh transaction with the pinned builder carrying exactly
//! one injected anomaly, then asserts the specific rejection. The pinned unsigned
//! type exposes no instruction mutator, so invalid variants are built directly
//! rather than by editing a valid transaction in place.

mod common;

use common::{other_template_binding, template_binding, valid_request};
use tari_cc_private_ballot_anchor_transport::AnchorEventPayloadV2;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorInspectionExpectationV1, OotleAnchorAdapterError, inspect_unsigned_anchor_transaction,
};
use tari_ootle_transaction::{
    Blob, Epoch, Instruction, Network, TransactionBuilder, UnsignedTransaction, args,
};
use tari_template_lib_types::{ComponentAddress, TemplateAddress};

/// The bounded max epoch of the canonical valid request (observed 100 + 12).
const EXPECTED_MAX_EPOCH: u64 = 112;

/// Expectation for the canonical valid request (Esmeralda, digest 0x22).
fn expectation() -> AnchorInspectionExpectationV1 {
    match AnchorInspectionExpectationV1::for_request(&valid_request()) {
        Ok(expectation) => expectation,
        Err(_) => panic!("expectation must build"),
    }
}

/// The exact lowercase-hex digest string the valid request commits to (0x22).
fn valid_digest_hex() -> String {
    AnchorEventPayloadV2::from_digest(common::digest(0x22)).digest_hex()
}

/// The pinned `TemplateAddress` matching `template_binding()`'s address.
fn expected_address() -> TemplateAddress {
    match TemplateAddress::from_hex(&"11".repeat(32)) {
        Ok(address) => address,
        Err(_) => panic!("expected template address must parse"),
    }
}

/// A different pinned `TemplateAddress` matching `other_template_binding()`.
fn other_address() -> TemplateAddress {
    match TemplateAddress::from_hex(&"aa".repeat(32)) {
        Ok(address) => address,
        Err(_) => panic!("other template address must parse"),
    }
}

/// A fresh main-intent builder bound to the expected Esmeralda network and the
/// expected bounded max epoch.
fn esmeralda_builder() -> TransactionBuilder {
    TransactionBuilder::new(Network::Esmeralda, Epoch::from(EXPECTED_MAX_EPOCH))
}

/// The valid `publish_anchor` call for digest 0x22.
fn valid_call() -> Instruction {
    match esmeralda_builder()
        .call_function(expected_address(), "publish_anchor", args![valid_digest_hex()])
        .build_unsigned()
        .instructions()
        .first()
        .cloned()
    {
        Some(instruction) => instruction,
        None => panic!("valid call must build"),
    }
}

fn inspect(unsigned: &UnsignedTransaction) -> Result<(), OotleAnchorAdapterError> {
    inspect_unsigned_anchor_transaction(unsigned, &expectation()).map(|_evidence| ())
}

#[test]
fn valid_transaction_passes_inspection() {
    let unsigned = esmeralda_builder()
        .call_function(expected_address(), "publish_anchor", args![valid_digest_hex()])
        .build_unsigned();
    match inspect_unsigned_anchor_transaction(&unsigned, &expectation()) {
        Ok(evidence) => {
            assert_eq!(evidence.instruction_count(), 1);
            assert_eq!(evidence.anchor_instruction_index(), 0);
            assert_eq!(evidence.template_binding(), &template_binding());
        }
        Err(error) => panic!("valid transaction must pass, got {error:?}"),
    }
}

#[test]
fn wrong_network_is_rejected() {
    let unsigned = TransactionBuilder::new(Network::Igor, Epoch::from(EXPECTED_MAX_EPOCH))
        .call_function(expected_address(), "publish_anchor", args![valid_digest_hex()])
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::NetworkBindingMismatch)
    );
}

#[test]
fn wrong_max_epoch_is_rejected() {
    let unsigned = TransactionBuilder::new(Network::Esmeralda, Epoch::from(EXPECTED_MAX_EPOCH + 1))
        .call_function(expected_address(), "publish_anchor", args![valid_digest_hex()])
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::MaxEpochBindingMismatch)
    );
}

#[test]
fn wrong_template_address_is_rejected() {
    // A call to a different published template (e.g. one from another network's
    // deployment) is rejected even though the function and digest are correct.
    assert_ne!(template_binding().template_address(), other_template_binding().template_address());
    let unsigned = esmeralda_builder()
        .call_function(other_address(), "publish_anchor", args![valid_digest_hex()])
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::TemplateCallMismatch)
    );
}

#[test]
fn wrong_function_is_rejected() {
    let unsigned = esmeralda_builder()
        .call_function(expected_address(), "publish_something_else", args![valid_digest_hex()])
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::TemplateCallMismatch)
    );
}

#[test]
fn wrong_digest_argument_is_rejected() {
    let wrong_digest_hex = "99".repeat(32);
    let unsigned = esmeralda_builder()
        .call_function(expected_address(), "publish_anchor", args![wrong_digest_hex])
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::TemplateCallMismatch)
    );
}

#[test]
fn call_method_instead_of_call_function_is_rejected() {
    // A `CallMethod` (component method) rather than a `CallFunction` is not the
    // anchor template call.
    let unsigned = esmeralda_builder()
        .call_method(
            ComponentAddress::from_array([7u8; 32]),
            "publish_anchor",
            args![valid_digest_hex()],
        )
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::TemplateCallMismatch)
    );
}

#[test]
fn extra_instruction_alongside_the_anchor_call_is_rejected() {
    let unsigned = esmeralda_builder()
        .add_instruction(valid_call())
        .add_instruction(Instruction::DropAllProofsInWorkspace)
        .build_unsigned();
    assert!(matches!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::UnexpectedInstruction { .. })
    ));
}

#[test]
fn duplicate_anchor_call_is_rejected() {
    let unsigned = esmeralda_builder()
        .add_instruction(valid_call())
        .add_instruction(valid_call())
        .build_unsigned();
    assert!(matches!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::UnexpectedInstruction { .. })
    ));
}

#[test]
fn zero_instructions_is_rejected() {
    let unsigned = esmeralda_builder().build_unsigned();
    assert!(matches!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::UnexpectedInstruction { .. })
    ));
}

#[test]
fn anchor_call_plus_arbitrary_blob_is_rejected() {
    let unsigned = esmeralda_builder()
        .add_instruction(valid_call())
        .add_blob("attachment", Blob::new(vec![1u8, 2, 3, 4]))
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::ArbitraryBlobAttached)
    );
}
