//! Fee-bearing v0.39.2 construction and inspection.
//!
//! The fee-bearing path adds exactly one `pay_fee_from_component` fee instruction
//! to the frozen transaction so the confirmed `transaction_requests.submit` path —
//! which seals verbatim and injects no fee — can produce a valid transaction. The
//! normal instruction list is still exactly one anchor `CallFunction`, and the
//! fee instruction touches only the configured fee account.

mod common;

use common::{build_request_v2, valid_request};
use tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorInspectionExpectationV1, OotleAnchorAdapterError, build_fee_bearing_anchor_transaction,
    build_unsigned_anchor_transaction, inspect_fee_bearing_anchor_transaction,
    inspect_unsigned_anchor_transaction,
};
use tari_template_lib_types::ComponentAddress;

/// A deterministic, valid fee account component address.
fn fee_component() -> ComponentAddress {
    match ComponentAddress::from_hex(&"11".repeat(32)) {
        Ok(address) => address,
        Err(_error) => panic!("test fee component must be valid"),
    }
}

/// A distinct valid fee account component address.
fn other_fee_component() -> ComponentAddress {
    match ComponentAddress::from_hex(&"33".repeat(32)) {
        Ok(address) => address,
        Err(_error) => panic!("test fee component must be valid"),
    }
}

/// Builds the inspection expectation for a v0.39.2 request (template + epoch).
fn expectation_for(
    request: &tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1,
) -> AnchorInspectionExpectationV1 {
    match AnchorInspectionExpectationV1::for_request(request) {
        Ok(expectation) => expectation,
        Err(error) => panic!("expectation must build, got {error:?}"),
    }
}

#[test]
fn fee_bearing_build_has_one_emit_log_one_pay_fee_and_no_inputs() {
    let request = valid_request();
    let Ok(result) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("fee-bearing build must succeed");
    };

    let unsigned = result.unsigned_transaction();
    assert_eq!(unsigned.instructions().len(), 1, "one anchor CallFunction");
    assert_eq!(unsigned.fee_instructions().len(), 1, "one pay_fee");
    assert!(unsigned.inputs().is_empty(), "no inputs (no auto-fill)");
    assert!(unsigned.blobs().is_empty(), "no blobs");

    let evidence = result.evidence();
    assert!(evidence.fee_instructions_present());
    assert_eq!(evidence.instruction_count(), 1);
    assert_eq!(evidence.input_count(), 0);
}

#[test]
fn fee_bearing_inspection_accepts_its_own_build() {
    let request = valid_request();
    let Ok(result) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("build must succeed");
    };
    let evidence = inspect_fee_bearing_anchor_transaction(
        result.unsigned_transaction(),
        &expectation_for(&request),
        fee_component(),
        request.max_fee(),
    );
    let Ok(evidence) = evidence else {
        panic!("fee-bearing inspection must accept its own build");
    };
    assert_eq!(evidence.fingerprint(), result.evidence().fingerprint());
}

#[test]
fn fee_less_inspection_rejects_a_fee_bearing_transaction() {
    let request = valid_request();
    let Ok(result) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("build must succeed");
    };
    // The Slice 4A5 fee-less inspector still forbids any fee instruction.
    assert_eq!(
        inspect_unsigned_anchor_transaction(
            result.unsigned_transaction(),
            &expectation_for(&request)
        ),
        Err(OotleAnchorAdapterError::UnexpectedFeeInstruction)
    );
}

#[test]
fn fee_bearing_inspection_rejects_a_fee_less_transaction() {
    let request = valid_request();
    let Ok(fee_less) = build_unsigned_anchor_transaction(&request) else {
        panic!("fee-less build must succeed");
    };
    assert_eq!(
        inspect_fee_bearing_anchor_transaction(
            fee_less.unsigned_transaction(),
            &expectation_for(&request),
            fee_component(),
            request.max_fee(),
        ),
        Err(OotleAnchorAdapterError::MissingFeeInstruction)
    );
}

#[test]
fn fee_bearing_inspection_rejects_wrong_fee_account() {
    let request = valid_request();
    let Ok(result) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("build must succeed");
    };
    assert_eq!(
        inspect_fee_bearing_anchor_transaction(
            result.unsigned_transaction(),
            &expectation_for(&request),
            other_fee_component(),
            request.max_fee(),
        ),
        Err(OotleAnchorAdapterError::FeeAccountMismatch)
    );
}

#[test]
fn fee_bearing_inspection_rejects_wrong_max_fee() {
    let request = valid_request();
    let Ok(result) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("build must succeed");
    };
    assert_eq!(
        inspect_fee_bearing_anchor_transaction(
            result.unsigned_transaction(),
            &expectation_for(&request),
            fee_component(),
            AnchorMaxFeeV1::from_units(9_999),
        ),
        Err(OotleAnchorAdapterError::FeeAmountMismatch)
    );
}

#[test]
fn fee_account_change_changes_the_fingerprint() {
    let request = valid_request();
    let Ok(a) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("build must succeed");
    };
    let Ok(b) = build_fee_bearing_anchor_transaction(&request, other_fee_component()) else {
        panic!("build must succeed");
    };
    assert_ne!(a.evidence().fingerprint(), b.evidence().fingerprint());
}

#[test]
fn fee_amount_change_changes_the_fingerprint() {
    let low = build_request_v2("esmeralda", "fee-account", 0x22, 1_000, None);
    let high = build_request_v2("esmeralda", "fee-account", 0x22, 2_000, None);
    let Ok(a) = build_fee_bearing_anchor_transaction(&low, fee_component()) else {
        panic!("build must succeed");
    };
    let Ok(b) = build_fee_bearing_anchor_transaction(&high, fee_component()) else {
        panic!("build must succeed");
    };
    assert_ne!(a.evidence().fingerprint(), b.evidence().fingerprint());
}

#[test]
fn fee_bearing_build_is_deterministic() {
    let request = valid_request();
    let Ok(a) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("build must succeed");
    };
    let Ok(b) = build_fee_bearing_anchor_transaction(&request, fee_component()) else {
        panic!("build must succeed");
    };
    assert_eq!(a.evidence().fingerprint(), b.evidence().fingerprint());
}
