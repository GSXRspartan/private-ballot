//! The Slice 4A5 safety gate re-run before creating a request is live (Section K).
//!
//! `build_walletd_create_request` re-inspects the unsigned transaction with the
//! Slice 4A5 `inspect_unsigned_anchor_transaction` before assembling the wire
//! request, and maps any rejection to
//! `WalletdAnchorAdapterError::UnsafeUnsignedTransaction`. The pinned build result
//! exposes no public mutator, so an unsafe transaction cannot reach this crate
//! through the public API; this test proves the exact gate function the
//! conversion calls rejects a mutated transaction (here a duplicate anchor log),
//! and that a valid transaction passes. The full mutation matrix is proven by the
//! Slice 4A5 inspection suite, which this slice regression-runs.

mod common;

use common::build_request;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorInspectionExpectationV1, OotleAnchorAdapterError, build_anchor_emit_log,
    inspect_unsigned_anchor_transaction,
};
use tari_ootle_transaction::{Network, TransactionBuilder};

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

#[test]
fn duplicate_anchor_log_is_rejected_by_the_gate() {
    let Ok(anchor) = build_anchor_emit_log(&common::payload(0x22)) else {
        panic!("anchor instruction must build");
    };
    let unsigned = TransactionBuilder::new(Network::Esmeralda)
        .add_instruction(anchor.clone())
        .add_instruction(anchor)
        .build_unsigned();

    assert_eq!(
        inspect_unsigned_anchor_transaction(&unsigned, &expectation()).map(|_evidence| ()),
        Err(OotleAnchorAdapterError::DuplicateAnchorInstruction)
    );
}

#[test]
fn valid_anchor_transaction_passes_the_gate() {
    let Ok(anchor) = build_anchor_emit_log(&common::payload(0x22)) else {
        panic!("anchor instruction must build");
    };
    let unsigned = TransactionBuilder::new(Network::Esmeralda)
        .add_instruction(anchor)
        .build_unsigned();

    match inspect_unsigned_anchor_transaction(&unsigned, &expectation()) {
        Ok(evidence) => assert_eq!(evidence.instruction_count(), 1),
        Err(error) => panic!("valid transaction must pass, got {error:?}"),
    }
}
