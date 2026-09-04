//! Field-specific live anchor preflight tests (Task B) and the V1 Prepare
//! contract that shares the same validators (Task E).
//!
//! Every invalid operator field must produce its own stable machine code rather
//! than the historical generic `GUI_LIVE_ANCHOR_OPERATOR_CONFIG_INVALID` funnel,
//! and a failed preflight/Prepare must never write any sidecar file.

#![allow(clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use tari_cc_private_ballot_archive::{TransportArchiveBatchV1, TransportArchiveBindingV1};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, GuiLiveAnchorConfigRequestV1, validate_live_anchor_operator_config_v1,
    write_live_anchor_config_from_verified_archive_v1,
};

use common::{TestDir, open_session, triptych_package_bytes};

const VALID_TEMPLATE_ADDRESS: &str =
    "template_1111111111111111111111111111111111111111111111111111111111111111";
const VALID_ARTIFACT_DIGEST: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

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
        triptych_package_bytes(0, &[b"candidate-c"]),
    ] {
        session
            .intake_ballot(&package)
            .expect("ballot package must intake");
    }
    session.close().expect("session must close");
    session.mark_verified().expect("session must verify");
    session.finalize().expect("session must finalize");
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
    .expect("transport binding must construct")
}

/// A fully valid operator config request whose only variable is the sidecar
/// prefix (so distinct tests never collide on output paths).
fn valid_request(archive_dir: &Path, sidecar_prefix: &Path) -> GuiLiveAnchorConfigRequestV1 {
    GuiLiveAnchorConfigRequestV1 {
        archive_directory: archive_dir.to_string_lossy().into_owned(),
        output_config_path: format!("{}-anchor-config.cbor", sidecar_prefix.display()),
        network: "esmeralda".to_owned(),
        walletd_endpoint: "http://127.0.0.1:5100".to_owned(),
        indexer_endpoint: "https://ootle-indexer-a.tari.com/".to_owned(),
        template_address: VALID_TEMPLATE_ADDRESS.to_owned(),
        template_module: "tari_private_ballot_anchor".to_owned(),
        template_event_topic: "tari_private_ballot_anchor.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1"
            .to_owned(),
        template_artifact_digest_hex: VALID_ARTIFACT_DIGEST.to_owned(),
        max_epoch_delta: 12,
        account_reference: "organizer-fee-account".to_owned(),
        fee_component: "component_70f35a1b4b5bfecaafeaf946e0ffca69cae17869af9fa966fabc9a59e3e2d1d7"
            .to_owned(),
        seal_signer_kind: "account".to_owned(),
        seal_signer_id: "0".to_owned(),
        declared_seal_public_key: "ownerpublickey0123456789abcdef".to_owned(),
        dedicated_organizer_wallet_attested: true,
        max_fee: 1000,
        required_accepted_ballot_floor: 2,
        reduced_anonymity_acknowledged: true,
        snapshot_path: format!("{}-anchor-snapshot.cbor", sidecar_prefix.display()),
        evidence_path: format!("{}-anchor-evidence.cbor", sidecar_prefix.display()),
        backoff_base_secs: 1,
        backoff_cap_secs: 10,
        receipt_query_attempts: 8,
        request_timeout_secs: Some(30),
        ttl_secs: None,
    }
}

fn sidecar_prefix(dir: &TestDir, tag: &str) -> PathBuf {
    dir.join(tag)
}

#[test]
fn preflight_all_fields_green_for_valid_request() {
    let dir = TestDir::new("preflight-valid");
    let archive = finalized_bound_archive(&dir);
    let request = valid_request(&archive, &sidecar_prefix(&dir, "valid"));

    let result = validate_live_anchor_operator_config_v1(&request);

    assert!(
        result.ok,
        "expected all-green preflight, first error: {:?} on {:?}",
        result.first_error_code, result.first_error_field
    );
    // Voter 0 votes twice (candidate-a then candidate-c); the duplicate
    // nullifier is rejected, so exactly two ballots are accepted.
    assert_eq!(result.accepted_ballot_count, Some(2));
    // Fee component, signer id, and declared key are format-valid but need an
    // online wallet check to be definitive.
    assert!(result.any_needs_live_check);
}

#[test]
fn prepare_writes_config_sidecar_for_valid_request() {
    let dir = TestDir::new("prepare-valid");
    let archive = finalized_bound_archive(&dir);
    let request = valid_request(&archive, &sidecar_prefix(&dir, "prep"));
    let config_path = PathBuf::from(&request.output_config_path);

    let result = write_live_anchor_config_from_verified_archive_v1(&request)
        .expect("valid request must prepare");

    assert!(config_path.is_file(), "config sidecar must be written");
    assert_eq!(result.accepted_ballot_count, 2);
    assert_eq!(result.config_path, config_path.to_string_lossy());
}

/// One row of the field-mutation table: mutate a single field of a valid
/// request, and assert both preflight and Prepare surface the same specific
/// code, and that Prepare wrote no sidecar.
struct FieldCase {
    tag: &'static str,
    expected_code: &'static str,
    mutate: fn(&mut GuiLiveAnchorConfigRequestV1),
}

fn field_cases() -> Vec<FieldCase> {
    vec![
        FieldCase {
            tag: "network",
            expected_code: "GUI_LIVE_ANCHOR_NETWORK_INVALID",
            mutate: |r| r.network = "invalid network".to_owned(),
        },
        FieldCase {
            tag: "walletd-invalid",
            expected_code: "GUI_LIVE_ANCHOR_WALLETD_ENDPOINT_INVALID",
            mutate: |r| r.walletd_endpoint = "not a url".to_owned(),
        },
        FieldCase {
            tag: "walletd-not-loopback",
            expected_code: "GUI_LIVE_ANCHOR_WALLETD_ENDPOINT_NOT_LOOPBACK",
            mutate: |r| r.walletd_endpoint = "http://10.0.0.5:5100".to_owned(),
        },
        FieldCase {
            tag: "indexer-invalid",
            expected_code: "GUI_LIVE_ANCHOR_INDEXER_ENDPOINT_INVALID",
            mutate: |r| r.indexer_endpoint = "not a url".to_owned(),
        },
        FieldCase {
            tag: "indexer-mismatch",
            expected_code: "GUI_LIVE_ANCHOR_INDEXER_NETWORK_MISMATCH",
            mutate: |r| r.indexer_endpoint = "https://evil.example.com/".to_owned(),
        },
        FieldCase {
            tag: "account-empty",
            expected_code: "GUI_LIVE_ANCHOR_ACCOUNT_REFERENCE_EMPTY",
            mutate: |r| r.account_reference = String::new(),
        },
        FieldCase {
            tag: "account-whitespace",
            expected_code: "GUI_LIVE_ANCHOR_ACCOUNT_REFERENCE_FORBIDDEN_CHARACTER",
            mutate: |r| r.account_reference = "Tari Private Ballot".to_owned(),
        },
        FieldCase {
            tag: "fee-component",
            expected_code: "GUI_LIVE_ANCHOR_FEE_COMPONENT_INVALID",
            mutate: |r| r.fee_component = "not-a-component".to_owned(),
        },
        FieldCase {
            tag: "seal-kind",
            expected_code: "GUI_LIVE_ANCHOR_SEAL_SIGNER_KIND_INVALID",
            mutate: |r| r.seal_signer_kind = "wizard".to_owned(),
        },
        FieldCase {
            tag: "seal-id",
            expected_code: "GUI_LIVE_ANCHOR_SEAL_SIGNER_ID_INVALID",
            mutate: |r| r.seal_signer_id = "not-a-number".to_owned(),
        },
        FieldCase {
            tag: "seal-key-empty",
            expected_code: "GUI_LIVE_ANCHOR_DECLARED_SEAL_PUBLIC_KEY_EMPTY",
            mutate: |r| r.declared_seal_public_key = String::new(),
        },
        FieldCase {
            tag: "seal-key-whitespace",
            expected_code: "GUI_LIVE_ANCHOR_DECLARED_SEAL_PUBLIC_KEY_WHITESPACE",
            mutate: |r| r.declared_seal_public_key = "owner key with spaces".to_owned(),
        },
        FieldCase {
            tag: "artifact-digest",
            expected_code: "GUI_LIVE_ANCHOR_TEMPLATE_ARTIFACT_DIGEST_INVALID",
            mutate: |r| r.template_artifact_digest_hex = "abc".to_owned(),
        },
        FieldCase {
            tag: "max-fee-zero",
            expected_code: "GUI_LIVE_ANCHOR_MAX_FEE_OUT_OF_POLICY",
            mutate: |r| r.max_fee = 0,
        },
        FieldCase {
            tag: "max-epoch-zero",
            expected_code: "GUI_LIVE_ANCHOR_MAX_EPOCH_DELTA_INVALID",
            mutate: |r| r.max_epoch_delta = 0,
        },
        FieldCase {
            tag: "floor-zero",
            expected_code: "GUI_LIVE_ANCHOR_ACCEPTED_FLOOR_REQUIRED",
            mutate: |r| r.required_accepted_ballot_floor = 0,
        },
        FieldCase {
            tag: "dedicated-wallet",
            expected_code: "GUI_LIVE_ANCHOR_DEDICATED_WALLET_REQUIRED",
            mutate: |r| r.dedicated_organizer_wallet_attested = false,
        },
    ]
}

#[test]
fn each_invalid_field_reports_its_own_preflight_code() {
    let dir = TestDir::new("preflight-fields");
    let archive = finalized_bound_archive(&dir);

    for case in field_cases() {
        let mut request = valid_request(&archive, &sidecar_prefix(&dir, case.tag));
        (case.mutate)(&mut request);
        let result = validate_live_anchor_operator_config_v1(&request);
        assert!(
            !result.ok,
            "case {} unexpectedly passed preflight",
            case.tag
        );
        let failing: Vec<_> = result
            .fields
            .iter()
            .filter(|f| !f.ok)
            .map(|f| f.code.as_str())
            .collect();
        assert!(
            failing.contains(&case.expected_code),
            "case {} expected {} among {:?}",
            case.tag,
            case.expected_code,
            failing
        );
    }
}

#[test]
fn each_invalid_field_fails_prepare_with_same_code_and_no_sidecar() {
    let dir = TestDir::new("prepare-fields");
    let archive = finalized_bound_archive(&dir);

    for case in field_cases() {
        let mut request = valid_request(&archive, &sidecar_prefix(&dir, case.tag));
        (case.mutate)(&mut request);
        let config_path = PathBuf::from(&request.output_config_path);
        let snapshot_path = PathBuf::from(&request.snapshot_path);
        let evidence_path = PathBuf::from(&request.evidence_path);

        let error = write_live_anchor_config_from_verified_archive_v1(&request)
            .expect_err("mutated field must fail Prepare");

        assert_eq!(
            error.code(),
            case.expected_code,
            "case {} Prepare code mismatch: {}",
            case.tag,
            error.message()
        );
        assert!(
            !config_path.exists(),
            "case {} must not write config sidecar",
            case.tag
        );
        assert!(
            !snapshot_path.exists(),
            "case {} must not write snapshot",
            case.tag
        );
        assert!(
            !evidence_path.exists(),
            "case {} must not write evidence",
            case.tag
        );
    }
}

#[test]
fn archive_missing_is_reported_specifically() {
    let dir = TestDir::new("preflight-archive-missing");
    let missing = dir.join("does-not-exist");
    let request = valid_request(&missing, &sidecar_prefix(&dir, "missing"));

    let result = validate_live_anchor_operator_config_v1(&request);

    assert!(!result.ok);
    let archive_field = result
        .fields
        .iter()
        .find(|f| f.field == "archive_directory")
        .expect("archive field present");
    assert_eq!(archive_field.code, "GUI_LIVE_ANCHOR_ARCHIVE_MISSING");
}

#[test]
fn output_inside_archive_is_rejected_by_preflight() {
    let dir = TestDir::new("preflight-output-inside");
    let archive = finalized_bound_archive(&dir);
    let mut request = valid_request(&archive, &sidecar_prefix(&dir, "inside"));
    request.output_config_path = archive
        .join("inside-config.cbor")
        .to_string_lossy()
        .into_owned();

    let result = validate_live_anchor_operator_config_v1(&request);

    assert!(!result.ok);
    let output_field = result
        .fields
        .iter()
        .find(|f| f.field == "output_config_path")
        .expect("output field present");
    assert_eq!(output_field.code, "GUI_LIVE_ANCHOR_OUTPUT_WITHIN_ARCHIVE");
}
