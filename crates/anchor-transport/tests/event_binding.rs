//! v0.39.2 event-template identity, epoch-window, and event-proof validation.
//!
//! These cover the project-owned half of the event contract: the immutable
//! deployment identity a network-specific template publication is pinned to, the
//! bounded transaction-expiry window, and the detached event-proof bounds. The
//! network itself stays runtime data — nothing here hard-codes a network.

use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V1, ANCHOR_EVENT_FUNCTION_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V1,
    ANCHOR_EVENT_TOPIC_SUFFIX_V2, ANCHOR_TEMPLATE_MODULE_V2,
    ANCHOR_TEMPLATE_RECEIPT_TOPIC_PREFIX_V2, AnchorEpochBindingV1, AnchorEventBindingError,
    AnchorEventProofV2, AnchorTemplateBindingV1, AnchorTemplateBindingV2,
    MAX_ANCHOR_EVENT_METADATA_BYTES_V2, MAX_ANCHOR_EVENT_METADATA_FIELDS_V2,
    OOTLE_MAX_EPOCH_WINDOW_V1,
};

const MODULE: &str = "tari_private_ballot_anchor";

fn address() -> String {
    format!("template_{}", "11".repeat(32))
}

fn topic() -> String {
    format!("{MODULE}.{ANCHOR_EVENT_TOPIC_SUFFIX_V1}")
}

fn binding(
    address: &str,
    module: &str,
    function: &str,
    topic: &str,
) -> Result<AnchorTemplateBindingV1, AnchorEventBindingError> {
    AnchorTemplateBindingV1::new(
        address.to_owned(),
        module.to_owned(),
        function.to_owned(),
        topic.to_owned(),
        [0x33; 32],
    )
}

#[test]
fn valid_template_binding_is_accepted_and_readable() {
    let binding = binding(&address(), MODULE, ANCHOR_EVENT_FUNCTION_V1, &topic())
        .unwrap_or_else(|error| panic!("valid binding must be accepted: {error}"));
    assert_eq!(binding.template_address(), address());
    assert_eq!(binding.module(), MODULE);
    assert_eq!(binding.function(), "publish_anchor");
    assert_eq!(binding.full_event_topic(), topic());
    assert_eq!(binding.artifact_digest(), &[0x33; 32]);
}

#[test]
fn wrong_function_is_rejected() {
    assert_eq!(
        binding(&address(), MODULE, "publish_something_else", &topic()),
        Err(AnchorEventBindingError::InvalidFunction)
    );
}

#[test]
fn topic_not_derived_from_module_is_rejected() {
    // The runtime prefixes a custom topic with the active module, so the stored
    // topic must be exactly `<module>.<suffix>`; anything else is rejected.
    let mismatched = format!("other_module.{ANCHOR_EVENT_TOPIC_SUFFIX_V1}");
    assert_eq!(
        binding(&address(), MODULE, ANCHOR_EVENT_FUNCTION_V1, &mismatched),
        Err(AnchorEventBindingError::InvalidEventTopic)
    );
    let bare_suffix = ANCHOR_EVENT_TOPIC_SUFFIX_V1.to_owned();
    assert_eq!(
        binding(&address(), MODULE, ANCHOR_EVENT_FUNCTION_V1, &bare_suffix),
        Err(AnchorEventBindingError::InvalidEventTopic)
    );
}

#[test]
fn malformed_template_address_is_rejected() {
    // Missing the required `template_` prefix.
    assert_eq!(
        binding(&"11".repeat(32), MODULE, ANCHOR_EVENT_FUNCTION_V1, &topic()),
        Err(AnchorEventBindingError::InvalidTemplateAddress)
    );
    // Embedded whitespace.
    assert_eq!(
        binding(
            &format!("template_ {}", "11".repeat(31)),
            MODULE,
            ANCHOR_EVENT_FUNCTION_V1,
            &topic()
        ),
        Err(AnchorEventBindingError::InvalidTemplateAddress)
    );
}

#[test]
fn empty_or_non_identifier_module_is_rejected() {
    assert_eq!(
        binding(&address(), "", ANCHOR_EVENT_FUNCTION_V1, &topic()),
        Err(AnchorEventBindingError::InvalidModule)
    );
    // A module with a `.` would also break the derived-topic contract, but the
    // module character check fires first.
    let dotted = "bad.module";
    assert_eq!(
        binding(&address(), dotted, ANCHOR_EVENT_FUNCTION_V1, &topic()),
        Err(AnchorEventBindingError::InvalidModule)
    );
}

#[test]
fn epoch_binding_derives_and_round_trips() {
    let observed = 1_000_u64;
    let delta = 12_u64;
    let epoch = AnchorEpochBindingV1::from_observed_epoch(observed, delta)
        .unwrap_or_else(|error| panic!("valid epoch must derive: {error}"));
    assert_eq!(epoch.observed_epoch(), observed);
    assert_eq!(epoch.max_epoch(), observed + delta);

    // Recreating from persisted (observed, max) validates the same window.
    let restored = AnchorEpochBindingV1::new(observed, observed + delta)
        .unwrap_or_else(|error| panic!("persisted epoch must restore: {error}"));
    assert_eq!(restored, epoch);
}

#[test]
fn zero_and_over_window_epochs_are_rejected() {
    assert_eq!(
        AnchorEpochBindingV1::from_observed_epoch(1_000, 0),
        Err(AnchorEventBindingError::InvalidEpochWindow)
    );
    assert_eq!(
        AnchorEpochBindingV1::from_observed_epoch(1_000, OOTLE_MAX_EPOCH_WINDOW_V1 + 1),
        Err(AnchorEventBindingError::InvalidEpochWindow)
    );
    // A persisted binding whose max precedes its observed epoch is rejected.
    assert_eq!(
        AnchorEpochBindingV1::new(1_000, 999),
        Err(AnchorEventBindingError::InvalidEpochWindow)
    );
    // The exact window bound is accepted.
    assert!(AnchorEpochBindingV1::from_observed_epoch(1_000, OOTLE_MAX_EPOCH_WINDOW_V1).is_ok());
}

#[test]
fn event_proof_enforces_bounded_metadata() {
    let ok = AnchorEventProofV2::new(
        address(),
        topic(),
        vec![("anchor_digest".to_owned(), "22".repeat(32))],
        0,
        1_000,
        [0_u8; 32],
    );
    assert!(ok.is_ok());

    // Too many metadata fields.
    let too_many = (0..=MAX_ANCHOR_EVENT_METADATA_FIELDS_V2)
        .map(|index| (format!("k{index}"), "v".to_owned()))
        .collect::<Vec<_>>();
    assert!(AnchorEventProofV2::new(address(), topic(), too_many, 0, 1_000, [0_u8; 32]).is_err());

    // An oversized metadata value.
    let oversized = vec![(
        "anchor_digest".to_owned(),
        "a".repeat(MAX_ANCHOR_EVENT_METADATA_BYTES_V2 + 1),
    )];
    assert!(AnchorEventProofV2::new(address(), topic(), oversized, 0, 1_000, [0_u8; 32]).is_err());

    // Empty template address or topic is rejected.
    assert!(
        AnchorEventProofV2::new(String::new(), topic(), Vec::new(), 0, 1_000, [0_u8; 32]).is_err()
    );
    assert!(
        AnchorEventProofV2::new(address(), String::new(), Vec::new(), 0, 1_000, [0_u8; 32])
            .is_err()
    );
}

#[test]
fn v2_template_binding_accepts_only_the_v2_abi() {
    let valid = AnchorTemplateBindingV2::new(
        address(),
        ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
        [0x44; 32],
    );
    assert!(valid.is_ok());
    let valid = valid.expect("valid V2 binding");
    assert_eq!(
        valid.canonical_receipt_event_topic(),
        format!("{ANCHOR_TEMPLATE_RECEIPT_TOPIC_PREFIX_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}")
    );
    assert_eq!(
        AnchorTemplateBindingV2::new(
            address(),
            MODULE.to_owned(),
            ANCHOR_EVENT_FUNCTION_V2.to_owned(),
            format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
            [0x44; 32],
        ),
        Err(AnchorEventBindingError::InvalidModule)
    );
    assert_eq!(
        AnchorTemplateBindingV2::new(
            address(),
            ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
            ANCHOR_EVENT_FUNCTION_V1.to_owned(),
            format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
            [0x44; 32],
        ),
        Err(AnchorEventBindingError::InvalidFunction)
    );
    assert_eq!(
        AnchorTemplateBindingV2::new(
            address(),
            ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
            ANCHOR_EVENT_FUNCTION_V2.to_owned(),
            format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V1}"),
            [0x44; 32],
        ),
        Err(AnchorEventBindingError::InvalidEventTopic)
    );
}
