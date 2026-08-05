//! Sections F/J and Section M(8,9,10,15,16,17) — inspection rejects every
//! invalid or mutated transaction, and no rejection path panics.
//!
//! Each case constructs a fresh, independently-built transaction with exactly one
//! injected anomaly and asserts the specific rejection. The pinned unsigned type
//! exposes no public instruction mutator, so invalid variants are built directly
//! with the pinned builder rather than by editing a valid transaction in place.

mod common;

use common::{payload, valid_request};
use tari_cc_private_ballot_anchor_transport::ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorInspectionExpectationV1, OotleAnchorAdapterError, build_anchor_emit_log,
    inspect_unsigned_anchor_transaction,
};
use tari_ootle_transaction::args::WorkspaceOffsetId;
use tari_ootle_transaction::{Blob, Instruction, Network, TransactionBuilder, UnsignedTransaction};
use tari_template_lib_types::{ComponentAddress, LogLevel, MaxString};

/// Expectation for the canonical valid request (Esmeralda, digest 0x22).
fn expectation() -> AnchorInspectionExpectationV1 {
    match AnchorInspectionExpectationV1::for_request(&valid_request()) {
        Ok(expectation) => expectation,
        Err(_) => panic!("expectation must build"),
    }
}

/// The valid anchor EmitLog instruction for digest 0x22.
fn valid_anchor() -> Instruction {
    match build_anchor_emit_log(&payload(0x22)) {
        Ok(instruction) => instruction,
        Err(_) => panic!("valid anchor instruction must build"),
    }
}

/// An EmitLog carrying arbitrary text (used for unrelated / malformed logs).
fn raw_emit_log(text: &str) -> Instruction {
    match MaxString::try_from(text.to_owned()) {
        Ok(message) => Instruction::EmitLog {
            level: LogLevel::Info,
            message,
        },
        Err(_) => panic!("test message must fit the bound"),
    }
}

/// A fresh main-intent builder bound to the expected Esmeralda network.
fn esmeralda_builder() -> TransactionBuilder {
    TransactionBuilder::new(Network::Esmeralda)
}

fn inspect(unsigned: &UnsignedTransaction) -> Result<(), OotleAnchorAdapterError> {
    inspect_unsigned_anchor_transaction(unsigned, &expectation()).map(|_evidence| ())
}

#[test]
fn valid_transaction_passes_inspection() {
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .build_unsigned();
    match inspect_unsigned_anchor_transaction(&unsigned, &expectation()) {
        Ok(evidence) => {
            assert_eq!(evidence.instruction_count(), 1);
            assert_eq!(evidence.anchor_instruction_index(), 0);
        }
        Err(error) => panic!("valid transaction must pass, got {error:?}"),
    }
}

#[test]
fn wrong_network_is_rejected() {
    let unsigned = TransactionBuilder::new(Network::Igor)
        .add_instruction(valid_anchor())
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::NetworkBindingMismatch)
    );
}

#[test]
fn missing_emit_log_is_rejected() {
    let unsigned = esmeralda_builder().build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::MissingAnchorInstruction)
    );
}

#[test]
fn duplicate_identical_anchor_logs_are_rejected() {
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .add_instruction(valid_anchor())
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::DuplicateAnchorInstruction)
    );
}

#[test]
fn conflicting_anchor_logs_are_rejected() {
    let other_anchor = match build_anchor_emit_log(&payload(0x23)) {
        Ok(instruction) => instruction,
        Err(_) => panic!("second anchor must build"),
    };
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .add_instruction(other_anchor)
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::ConflictingAnchorInstruction)
    );
}

#[test]
fn malformed_anchor_prefix_is_rejected() {
    let malformed = format!("{ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1}{}", "z".repeat(64));
    let unsigned = esmeralda_builder()
        .add_instruction(raw_emit_log(&malformed))
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::MalformedAnchorPayload)
    );
}

#[test]
fn uppercase_digest_is_rejected() {
    let uppercase = format!(
        "{ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1}{}",
        "AB".repeat(32)
    );
    let unsigned = esmeralda_builder()
        .add_instruction(raw_emit_log(&uppercase))
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::MalformedAnchorPayload)
    );
}

#[test]
fn wrong_digest_is_rejected() {
    // A well-formed anchor log for a different digest.
    let wrong = match build_anchor_emit_log(&payload(0x99)) {
        Ok(instruction) => instruction,
        Err(_) => panic!("wrong-digest anchor must build"),
    };
    let unsigned = esmeralda_builder().add_instruction(wrong).build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::AnchorDigestMismatch)
    );
}

#[test]
fn unrelated_log_only_is_rejected() {
    let unsigned = esmeralda_builder()
        .add_instruction(raw_emit_log("routine execution log"))
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::MissingAnchorInstruction)
    );
}

#[test]
fn anchor_log_plus_component_call_is_rejected() {
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .call_method(ComponentAddress::from_array([7u8; 32]), "noop", vec![])
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::ComponentCallPresent)
    );
}

#[test]
fn anchor_log_plus_resource_transfer_is_rejected() {
    // Built directly rather than via `take_from_bucket`, whose builder helper
    // eagerly resolves a workspace bucket key that a standalone test has not
    // created.
    let take_from_bucket = Instruction::TakeFromBucket {
        input_bucket: WorkspaceOffsetId::new(0),
        amount: 1u64.into(),
        output_bucket: 1u16,
    };
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .add_instruction(take_from_bucket)
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::ResourceTransferPresent)
    );
}

#[test]
fn anchor_log_plus_arbitrary_blob_is_rejected() {
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .add_blob("attachment", Blob::new(vec![1u8, 2, 3, 4]))
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::ArbitraryBlobAttached)
    );
}

#[test]
fn unexpected_fee_instruction_is_rejected() {
    // Any populated fee-instruction list is rejected, because this architecture
    // defers all fee instructions to walletd. The specific fee instruction is
    // immaterial, so a simple log stands in without needing a resolved bucket.
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .add_fee_instruction(raw_emit_log("fee note"))
        .build_unsigned();
    assert_eq!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::UnexpectedFeeInstruction)
    );
}

#[test]
fn anchor_log_plus_extra_instruction_is_rejected() {
    // A generic non-call, non-transfer extra instruction alongside the anchor.
    let unsigned = esmeralda_builder()
        .add_instruction(valid_anchor())
        .add_instruction(Instruction::DropAllProofsInWorkspace)
        .build_unsigned();
    assert!(matches!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::UnexpectedInstruction { .. })
    ));
}

#[test]
fn altered_ordering_with_anchor_not_first_is_rejected() {
    // Ordering is security-relevant: the anchor must be the sole instruction, so
    // a prelude instruction before it is rejected rather than tolerated.
    let unsigned = esmeralda_builder()
        .add_instruction(raw_emit_log("prelude"))
        .add_instruction(valid_anchor())
        .build_unsigned();
    assert!(matches!(
        inspect(&unsigned),
        Err(OotleAnchorAdapterError::UnexpectedInstruction { .. })
    ));
}
