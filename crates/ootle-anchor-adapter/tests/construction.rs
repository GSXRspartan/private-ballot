//! v0.39.2 event-anchor construction and inspection evidence.
//!
//! Construction now emits exactly one `CallFunction` to the pinned stateless
//! event template (never the removed `EmitLog`). The build result is always
//! internally consistent because construction runs the same pure inspection used
//! to reject invalid transactions.

mod common;

use common::{build_request, epoch_binding, template_binding, valid_request};
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V2, ANCHOR_TEMPLATE_MODULE_V2,
    AnchorEventPayloadV3, AnchorTemplateBindingV2,
};
use tari_cc_private_ballot_ootle_anchor_adapter::{
    AnchorTransactionConstructor, OotleAnchorAdapterError, OotleAnchorBuildResultV1,
    PinnedOotleAnchorTransactionConstructor, build_unsigned_anchor_transaction,
    build_v2_anchor_call_function,
};
use tari_ootle_transaction::{Instruction, Network, UnsignedTransaction};

/// Asserts the sole instruction is the pinned `publish_anchor` call.
fn assert_sole_publish_anchor_call(unsigned: &UnsignedTransaction) {
    match unsigned.instructions() {
        [Instruction::CallFunction { function, .. }] => {
            assert_eq!(
                &**function, "publish_anchor",
                "anchor call must invoke publish_anchor"
            );
        }
        other => panic!(
            "expected exactly one CallFunction, got {} instructions",
            other.len()
        ),
    }
}

fn build(request_digest: u8) -> OotleAnchorBuildResultV1 {
    match build_unsigned_anchor_transaction(&common::build_request_v2(
        "esmeralda",
        "fee-account",
        request_digest,
        1_000,
        None,
    )) {
        Ok(result) => result,
        Err(error) => panic!("construction must succeed, got {error:?}"),
    }
}

#[test]
fn construction_yields_exactly_one_call_function_at_index_zero() {
    let result = build(0x22);
    let unsigned = result.unsigned_transaction();

    assert_eq!(unsigned.instructions().len(), 1);
    assert_sole_publish_anchor_call(unsigned);

    let evidence = result.evidence();
    assert_eq!(evidence.instruction_count(), 1);
    assert_eq!(evidence.anchor_instruction_index(), 0);
}

#[test]
fn fee_less_construction_has_no_fees_inputs_or_blobs() {
    let result = build(0x22);
    let unsigned = result.unsigned_transaction();

    assert!(
        unsigned.fee_instructions().is_empty(),
        "no fee instructions"
    );
    assert!(unsigned.inputs().is_empty(), "no inputs");
    assert!(unsigned.blobs().is_empty(), "no blobs");

    let evidence = result.evidence();
    assert!(!evidence.fee_instructions_present());
    assert_eq!(evidence.input_count(), 0);
    assert_eq!(evidence.blob_count(), 0);
}

#[test]
fn evidence_binds_network_digest_template_epoch_and_schema() {
    let result = build(0x22);
    let evidence = result.evidence();

    assert_eq!(evidence.network().as_str(), "esmeralda");
    assert_eq!(evidence.ootle_network_byte(), Network::Esmeralda.as_byte());
    assert_eq!(evidence.account().as_str(), "fee-account");
    assert_eq!(evidence.anchor_digest(), common::digest(0x22));
    assert_eq!(evidence.event_payload().digest(), common::digest(0x22));
    assert_eq!(evidence.template_binding(), &template_binding());
    assert_eq!(evidence.epoch_binding(), epoch_binding());
    assert_eq!(evidence.unsigned_schema_version(), 1);
    assert_eq!(
        evidence.unsigned_schema_version(),
        result.unsigned_transaction().schema_version()
    );
    // The transaction is frozen against the bounded max epoch, not wall clock.
    assert_eq!(
        result.unsigned_transaction().max_epoch().as_u64(),
        epoch_binding().max_epoch()
    );
}

#[test]
fn walletd_preparation_preserves_fee_account_max_fee_template_and_epoch() {
    let request = common::build_request_v2("esmeralda", "treasury", 0x33, 7_777, Some("client-1"));
    let Ok(result) = build_unsigned_anchor_transaction(&request) else {
        panic!("construction must succeed");
    };
    let preparation = result.walletd_preparation();

    assert_eq!(preparation.network().as_str(), "esmeralda");
    assert_eq!(preparation.fee_account().as_str(), "treasury");
    assert_eq!(preparation.max_fee().value(), 7_777);
    assert_eq!(preparation.anchor_digest(), common::digest(0x33));
    assert_eq!(preparation.template_binding(), &template_binding());
    assert_eq!(preparation.epoch_binding(), epoch_binding());
    match preparation.client_reference() {
        Some(reference) => assert_eq!(reference.as_str(), "client-1"),
        None => panic!("client reference must be preserved"),
    }
}

#[test]
fn repeated_construction_is_deterministic() {
    let first = build(0x44);
    let second = build(0x44);

    assert_eq!(
        first.evidence().fingerprint().as_bytes(),
        second.evidence().fingerprint().as_bytes()
    );
    assert_eq!(first.evidence(), second.evidence());

    // A different digest yields a different fingerprint.
    let other = build(0x45);
    assert_ne!(
        first.evidence().fingerprint().as_bytes(),
        other.evidence().fingerprint().as_bytes()
    );
}

#[test]
fn constructor_trait_matches_the_free_function() {
    let request = valid_request();
    let constructor = PinnedOotleAnchorTransactionConstructor;

    let Ok(via_trait) = constructor.construct(&request) else {
        panic!("trait construction must succeed");
    };
    let Ok(via_function) = build_unsigned_anchor_transaction(&request) else {
        panic!("function construction must succeed");
    };

    assert_eq!(via_trait.evidence(), via_function.evidence());
}

#[test]
fn legacy_request_without_event_binding_is_fail_closed() {
    // A request built through the legacy (template-less) constructor can never
    // construct a v0.39.2 transaction: the immutable template deployment identity
    // and bounded epoch window are mandatory.
    let legacy = build_request("esmeralda", "fee-account", 0x22, 1_000, None);
    assert_eq!(
        build_unsigned_anchor_transaction(&legacy).err(),
        Some(OotleAnchorAdapterError::MissingEventBinding)
    );
}

#[test]
fn v2_instruction_uses_the_four_string_template_abi() {
    let template = AnchorTemplateBindingV2::new(
        format!("template_{}", "77".repeat(32)),
        ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
        [0x77; 32],
    )
    .expect("valid V2 binding");
    // A representative readable canonical public summary. The corrected V2
    // template puts this exact string on-chain as the `public_summary` value,
    // so a real preparation carries the readable election result verbatim.
    // Regression: use a realistic canonical election id text (matching the
    // preserved "500-votertest-01" fixture) — NOT lowercase hex — to prove
    // the V2 ABI passes the exact archive-frozen string through byte-for-byte.
    let public_summary = "{\"schema\":\"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_PUBLIC_V2\",\
        \"version\":2,\"network\":\"esmeralda\",\"election_id\":\"500-votertest-01\",\
        \"question\":\"Which test option should win?\",\"eligible_voters\":10,\
        \"accepted_ballots\":8,\"rejected_ballots\":2,\"results\":[]}";
    let payload = AnchorEventPayloadV3::new(
        [0x55; 32],
        "esmeralda".to_owned(),
        "500-votertest-01".to_owned(),
        public_summary.to_owned(),
    )
    .expect("valid V2 payload");
    let instruction = build_v2_anchor_call_function(&template, &payload).expect("instruction");
    match instruction {
        Instruction::CallFunction { function, args, .. } => {
            assert_eq!(&*function, ANCHOR_EVENT_FUNCTION_V2);
            assert_eq!(args.len(), 4);
        }
        _ => panic!("V2 must use CallFunction"),
    }
}
