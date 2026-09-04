//! The pinned inspection safety gate re-run before creating a request is live.
//!
//! `build_walletd_create_request` re-inspects the unsigned transaction with
//! `inspect_unsigned_anchor_transaction` before assembling the wire request, and
//! maps any rejection to `WalletdAnchorAdapterError::UnsafeUnsignedTransaction`.
//! The pinned build result exposes no public mutator, so an unsafe transaction
//! cannot reach this crate through the public API; this test proves the exact
//! gate function the conversion calls rejects a mutated transaction (here a
//! duplicate anchor call) and that a valid transaction passes.

mod common;

use common::build_request;
use tari_cc_private_ballot_anchor_transport::AnchorEventPayloadV2;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorInspectionExpectationV1, OotleAnchorAdapterError, build_unsigned_anchor_transaction,
    inspect_unsigned_anchor_transaction,
};
use tari_ootle_transaction::{Epoch, Instruction, Network, TransactionBuilder, args};
use tari_template_lib_types::TemplateAddress;

/// The bounded max epoch the canonical request commits to (observed 100 + 12).
const EXPECTED_MAX_EPOCH: u64 = 112;

fn expectation() -> AnchorInspectionExpectationV1 {
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

/// A `publish_anchor` call matching the canonical template + digest.
fn publish_anchor_call() -> Instruction {
    let Ok(address) = TemplateAddress::from_hex(&"11".repeat(32)) else {
        panic!("template address must parse");
    };
    let digest_hex = AnchorEventPayloadV2::from_digest(common::digest(0x22)).digest_hex();
    match TransactionBuilder::new(Network::Esmeralda, Epoch::from(EXPECTED_MAX_EPOCH))
        .call_function(address, "publish_anchor", args![digest_hex])
        .build_unsigned()
        .instructions()
        .first()
        .cloned()
    {
        Some(instruction) => instruction,
        None => panic!("anchor call must build"),
    }
}

#[test]
fn duplicate_anchor_call_is_rejected_by_the_gate() {
    let call = publish_anchor_call();
    let unsigned = TransactionBuilder::new(Network::Esmeralda, Epoch::from(EXPECTED_MAX_EPOCH))
        .add_instruction(call.clone())
        .add_instruction(call)
        .build_unsigned();

    assert!(matches!(
        inspect_unsigned_anchor_transaction(&unsigned, &expectation()).map(|_evidence| ()),
        Err(OotleAnchorAdapterError::UnexpectedInstruction { .. })
    ));
}

#[test]
fn valid_anchor_transaction_passes_the_gate() {
    let Ok(build) = build_unsigned_anchor_transaction(&build_request(
        "esmeralda",
        "fee-account",
        0x22,
        1_000,
        None,
    )) else {
        panic!("valid build must succeed");
    };

    match inspect_unsigned_anchor_transaction(build.unsigned_transaction(), &expectation()) {
        Ok(evidence) => assert_eq!(evidence.instruction_count(), 1),
        Err(error) => panic!("valid transaction must pass, got {error:?}"),
    }
}
