//! V2 public anchor payload build + offline verify tests (Tasks F, I, J).

#![allow(clippy::expect_used)]

mod common;

use std::path::PathBuf;

use tari_cc_private_ballot_anchor::OotleAnchorPublicPayloadV2;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V2, ANCHOR_EVENT_TOPIC_SUFFIX_V2, ANCHOR_TEMPLATE_MODULE_V2,
    AnchorTemplateBindingV2,
};
use tari_cc_private_ballot_archive::{TransportArchiveBatchV1, TransportArchiveBindingV1};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, GuiLiveAnchorV2RequestV1, GuiV2AnchorPublishPreparationRequestV1,
    build_v2_public_payload_from_verified_archive_v1,
    prepare_v2_anchor_publish_from_verified_evidence_v1,
    verify_v2_public_payload_against_archive_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

const V2_ARTIFACT_DIGEST: &str = "5555555555555555555555555555555555555555555555555555555555555555";

fn finalized_bound_archive(dir: &TestDir) -> PathBuf {
    let session = finalized_session();
    let target = dir.join("archive");
    tari_cc_private_ballot_gui_core::write_finalized_archive_v1_with_transport_binding(
        &session,
        &target,
        &live_transport_binding(&session),
    )
    .expect("finalized bound archive must write");
    target
}

fn finalized_session() -> GuiElectionSessionV1 {
    let mut session = open_session();
    for package in [
        triptych_package_bytes(0, &[b"candidate-a"]),
        triptych_package_bytes(1, &[b"candidate-b"]),
        triptych_package_bytes(2, &[b"candidate-a"]),
    ] {
        session.intake_ballot(&package).expect("intake");
    }
    session.close().expect("close");
    session.mark_verified().expect("verify");
    session.finalize().expect("finalize");
    session
}

fn live_transport_binding(session: &GuiElectionSessionV1) -> TransportArchiveBindingV1 {
    TransportArchiveBindingV1::new(
        session
            .artifacts()
            .manifest()
            .election_id()
            .as_bytes()
            .to_vec(),
        session.artifacts().manifest_hash(),
        [8; 32],
        4,
        vec![TransportArchiveBatchV1::new(
            1,
            [1; 32],
            session.transcript().accepted_count() as u64,
            false,
        )],
    )
    .expect("binding")
}

fn v2_request(archive: &std::path::Path) -> GuiLiveAnchorV2RequestV1 {
    GuiLiveAnchorV2RequestV1 {
        archive_directory: archive.to_string_lossy().into_owned(),
        network: "esmeralda".to_owned(),
        template_address: format!("template_{}", "44".repeat(32)),
        template_module: "tari_private_ballot_anchor_v2".to_owned(),
        template_function: "publish_anchor_v2".to_owned(),
        template_event_topic:
            "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2".to_owned(),
        template_artifact_digest_hex: V2_ARTIFACT_DIGEST.to_owned(),
    }
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex"))
        .collect()
}

#[test]
fn builds_public_payload_from_verified_archive() {
    let dir = TestDir::new("v2-build");
    let archive = finalized_bound_archive(&dir);
    let result = build_v2_public_payload_from_verified_archive_v1(&v2_request(&archive))
        .expect("V2 build must succeed");

    assert_eq!(result.accepted_ballot_count, 3);
    assert_eq!(result.network, "esmeralda");
    assert!(result.eligible_voter_count >= 3);
    assert!(!result.tally.is_empty());
    assert_eq!(result.v2_anchor_digest_hex.len(), 64);
    assert!(result.archive_finalized);
    assert_eq!(result.template_module, "tari_private_ballot_anchor_v2");
    // The readable canonical public summary must contain the fields an
    // independent observer needs to display the election result on-chain.
    assert!(result.public_summary_json.contains("\"question\":\""));
    assert!(result.public_summary_json.contains("\"results\":["));
    assert!(
        result
            .public_summary_json
            .contains("\"accepted_ballots\":3")
    );
    // Both encodings describe the same bytes.
    assert_eq!(
        decode_hex(&result.payload_hex),
        result.public_summary_json.as_bytes(),
    );
}

#[test]
fn built_payload_verifies_against_the_archive() {
    let dir = TestDir::new("v2-verify");
    let archive = finalized_bound_archive(&dir);
    let built =
        build_v2_public_payload_from_verified_archive_v1(&v2_request(&archive)).expect("build");
    let payload_bytes = decode_hex(&built.payload_hex);

    let verified = verify_v2_public_payload_against_archive_v1(
        &archive,
        &payload_bytes,
        &built.v2_anchor_digest_hex,
    )
    .expect("detached payload must verify");
    assert_eq!(verified.v2_anchor_digest_hex, built.v2_anchor_digest_hex);
    assert_eq!(verified.public_summary_json, built.public_summary_json);
}

#[test]
fn wrong_expected_digest_is_rejected() {
    let dir = TestDir::new("v2-baddigest");
    let archive = finalized_bound_archive(&dir);
    let built =
        build_v2_public_payload_from_verified_archive_v1(&v2_request(&archive)).expect("build");
    let payload_bytes = decode_hex(&built.payload_hex);

    let error =
        verify_v2_public_payload_against_archive_v1(&archive, &payload_bytes, &"00".repeat(32))
            .expect_err("wrong digest must fail");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_DIGEST_MISMATCH");
}

#[test]
fn tampered_question_fails_digest() {
    let dir = TestDir::new("v2-tamper-q");
    let archive = finalized_bound_archive(&dir);
    let built =
        build_v2_public_payload_from_verified_archive_v1(&v2_request(&archive)).expect("build");
    let payload_bytes = decode_hex(&built.payload_hex);

    // Tamper: decode, change the question, re-encode canonically, but keep the
    // OLD digest so the digest check catches the change.
    let mut payload =
        OotleAnchorPublicPayloadV2::from_canonical_json_bytes(&payload_bytes).expect("decode");
    payload.ballot_question = "A tampered question".to_owned();
    let tampered = payload.to_canonical_json_bytes().expect("re-encode");

    let error = verify_v2_public_payload_against_archive_v1(
        &archive,
        &tampered,
        &built.v2_anchor_digest_hex,
    )
    .expect_err("tampered payload must fail");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_DIGEST_MISMATCH");
}

#[test]
fn tampered_tally_with_matching_digest_fails_archive_replay() {
    let dir = TestDir::new("v2-tamper-tally");
    let archive = finalized_bound_archive(&dir);
    let built =
        build_v2_public_payload_from_verified_archive_v1(&v2_request(&archive)).expect("build");
    let payload_bytes = decode_hex(&built.payload_hex);

    // Tamper the tally AND recompute a matching digest, so only the independent
    // archive replay can catch it.
    let mut payload =
        OotleAnchorPublicPayloadV2::from_canonical_json_bytes(&payload_bytes).expect("decode");
    if let Some(first) = payload.tally.first_mut() {
        first.count += 1;
    }
    let tampered = payload.to_canonical_json_bytes().expect("re-encode");
    let matching_digest = payload
        .canonical_digest(&tari_cc_private_ballot_protocol::Blake3HashProviderV1)
        .expect("digest");
    let matching_digest_hex: String = matching_digest.iter().map(|b| format!("{b:02x}")).collect();

    let error =
        verify_v2_public_payload_against_archive_v1(&archive, &tampered, &matching_digest_hex)
            .expect_err("tally tamper must fail archive replay");
    assert_eq!(error.code(), "GUI_ANCHOR_V2_ARCHIVE_MISMATCH");
}

#[test]
fn verified_v2_evidence_prepares_exactly_four_template_arguments() {
    let dir = TestDir::new("v2-prepare");
    let archive = finalized_bound_archive(&dir);
    let built =
        build_v2_public_payload_from_verified_archive_v1(&v2_request(&archive)).expect("build");
    let binding = AnchorTemplateBindingV2::new(
        built.template_address.clone(),
        ANCHOR_TEMPLATE_MODULE_V2.to_owned(),
        ANCHOR_EVENT_FUNCTION_V2.to_owned(),
        format!("{ANCHOR_TEMPLATE_MODULE_V2}.{ANCHOR_EVENT_TOPIC_SUFFIX_V2}"),
        [0x55; 32],
    )
    .expect("binding");
    let prepared = prepare_v2_anchor_publish_from_verified_evidence_v1(
        &GuiV2AnchorPublishPreparationRequestV1 {
            archive_directory: archive.to_string_lossy().into_owned(),
            payload_hex: built.payload_hex.clone(),
            expected_digest_hex: built.v2_anchor_digest_hex.clone(),
        },
        &binding,
    )
    .expect("prepare");
    assert_eq!(prepared.template_function, "publish_anchor_v2");
    assert_eq!(prepared.arguments.len(), 4);
    assert_eq!(prepared.arguments[0], built.v2_anchor_digest_hex);
    assert_eq!(prepared.arguments[1], built.network);
    assert_eq!(prepared.arguments[2], built.election_id);
    // Regression: the canonical election id text (not its hex re-encoding)
    // must be passed through byte-for-byte. Real preserved elections use
    // names like "500-votertest-01"; the test session's synthetic id is a
    // control-free UTF-8 string derived from the frozen manifest.
    assert!(prepared.arguments[2].bytes().all(|byte| byte >= 0x20));
    assert!(!prepared.arguments[2].is_empty());
    // And the on-chain public summary must carry the same election_id verbatim.
    assert!(
        prepared
            .public_summary_json
            .contains(&format!("\"election_id\":\"{}\"", built.election_id))
    );
    assert_eq!(prepared.arguments[3], built.public_summary_json);
    assert_eq!(prepared.public_summary_json, built.public_summary_json);
}
