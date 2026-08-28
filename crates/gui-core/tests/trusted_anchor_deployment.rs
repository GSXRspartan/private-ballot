#![allow(clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_EVENT_FUNCTION_V1, ANCHOR_TEMPLATE_MODULE_V1,
};
use tari_cc_private_ballot_gui_core::{
    GuiTrustedOotleDeploymentLockRequestV1, TEMPLATE_ARTIFACT_DIGEST_ALGORITHM_ID_V1,
    TRUSTED_OOTLE_DEPLOYMENT_SCHEMA_V1, inspect_template_wasm_v1, load_trusted_ootle_deployment_v1,
    lock_trusted_ootle_deployment_v1, template_wasm_digest_for_bytes_v1,
    trusted_ootle_deployment_event_topic_v1, trusted_ootle_deployment_path_v1,
    unlock_trusted_ootle_deployment_v1,
};
use tempfile::TempDir;

const VALID_WASM: &[u8] = b"\0asm\x01\0\0\0";

fn write_wasm(dir: &TempDir, filename: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(filename);
    fs::write(&path, bytes).expect("write wasm");
    path
}

fn valid_request(wasm_path: &Path) -> GuiTrustedOotleDeploymentLockRequestV1 {
    GuiTrustedOotleDeploymentLockRequestV1 {
        network: "esmeralda".to_owned(),
        template_address: format!("template_{}", "22".repeat(32)),
        selected_wasm_path: wasm_path.display().to_string(),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = template_wasm_digest_for_bytes_v1(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[test]
fn known_bytes_produce_deterministic_lowercase_blake3_256() {
    let digest = digest_hex(b"abc");
    assert_eq!(
        digest,
        "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
    );
    assert_eq!(digest.len(), 64);
    assert!(
        digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    );
}

#[test]
fn lock_persists_public_deployment_and_round_trips() {
    let dir = TempDir::new().expect("temp dir");
    let wasm_path = write_wasm(&dir, "anchor-template.wasm", VALID_WASM);
    let expected_digest = digest_hex(VALID_WASM);

    let status = lock_trusted_ootle_deployment_v1(dir.path(), &valid_request(&wasm_path))
        .expect("deployment locks");

    assert!(status.locked);
    let deployment = status.deployment.expect("deployment present");
    assert_eq!(deployment.schema, TRUSTED_OOTLE_DEPLOYMENT_SCHEMA_V1);
    assert_eq!(deployment.network, "esmeralda");
    assert_eq!(deployment.template_artifact_digest_hex, expected_digest);
    assert_eq!(deployment.template_module, ANCHOR_TEMPLATE_MODULE_V1);
    assert_eq!(deployment.template_function, ANCHOR_EVENT_FUNCTION_V1);
    assert_eq!(
        deployment.template_event_topic,
        trusted_ootle_deployment_event_topic_v1()
    );

    let loaded = load_trusted_ootle_deployment_v1(dir.path()).expect("deployment loads");
    assert!(loaded.locked);
    assert_eq!(loaded.deployment.expect("loaded deployment"), deployment);
}

#[test]
fn selected_file_digest_is_calculated_in_rust() {
    let dir = TempDir::new().expect("temp dir");
    let wasm_path = write_wasm(&dir, "selected-template.wasm", VALID_WASM);

    let inspected = inspect_template_wasm_v1(&wasm_path).expect("wasm inspects");

    assert_eq!(inspected.display_filename, "selected-template.wasm");
    assert_eq!(inspected.bytes, VALID_WASM.len() as u64);
    assert_eq!(
        inspected.digest_algorithm_id,
        TEMPLATE_ARTIFACT_DIGEST_ALGORITHM_ID_V1
    );
    assert_eq!(inspected.digest_hex, digest_hex(VALID_WASM));
}

#[test]
fn persisted_record_contains_no_secret_or_operator_runtime_fields() {
    let dir = TempDir::new().expect("temp dir");
    let wasm_path = write_wasm(&dir, "anchor-template.wasm", VALID_WASM);
    lock_trusted_ootle_deployment_v1(dir.path(), &valid_request(&wasm_path))
        .expect("deployment locks");
    let bytes = fs::read(trusted_ootle_deployment_path_v1(dir.path())).expect("read record");
    let value: Value = serde_json::from_slice(&bytes).expect("json parses");
    let object = value.as_object().expect("record object");
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();

    assert!(keys.contains(&"network"));
    assert!(keys.contains(&"template_address"));
    assert!(keys.contains(&"template_artifact_digest_hex"));
    assert!(!keys.contains(&"selected_wasm_path"));
    assert!(!keys.contains(&"wasm_path"));
    assert!(!keys.contains(&"path"));
    assert!(!keys.iter().any(|key| {
        key.contains("wallet")
            || key.contains("secret")
            || key.contains("token")
            || key.contains("signer")
            || key.contains("credential")
            || key.contains("mnemonic")
    }));
}

#[test]
fn lock_ignores_manual_digest_bypass_by_recomputing_from_selected_wasm() {
    let dir = TempDir::new().expect("temp dir");
    let wasm_path = write_wasm(&dir, "operator-selected.wasm", VALID_WASM);
    let impossible_manual_digest = "33".repeat(32);

    let status = lock_trusted_ootle_deployment_v1(dir.path(), &valid_request(&wasm_path))
        .expect("deployment locks");
    let deployment = status.deployment.expect("deployment present");

    assert_eq!(
        deployment.template_artifact_digest_hex,
        digest_hex(VALID_WASM)
    );
    assert_ne!(
        deployment.template_artifact_digest_hex,
        impossible_manual_digest
    );
}

#[test]
fn second_lock_requires_explicit_unlock_before_replacement() {
    let dir = TempDir::new().expect("temp dir");
    let wasm_path = write_wasm(&dir, "initial.wasm", VALID_WASM);
    lock_trusted_ootle_deployment_v1(dir.path(), &valid_request(&wasm_path))
        .expect("initial deployment locks");

    let replacement_wasm_path = write_wasm(&dir, "replacement.wasm", b"\0asm\x01\0\0\0abc");
    let mut replacement = valid_request(&replacement_wasm_path);
    replacement.network = "igor".to_owned();
    replacement.template_address = format!("template_{}", "44".repeat(32));
    let error = lock_trusted_ootle_deployment_v1(dir.path(), &replacement)
        .expect_err("replacement requires unlock");
    assert_eq!(error.code(), "GUI_TRUSTED_OOTLE_DEPLOYMENT_LOCKED");

    let unlock_error = unlock_trusted_ootle_deployment_v1(dir.path(), false)
        .expect_err("unlock requires confirmation");
    assert_eq!(
        unlock_error.code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_UNLOCK_NOT_CONFIRMED"
    );
    unlock_trusted_ootle_deployment_v1(dir.path(), true).expect("unlock succeeds");

    let replaced = lock_trusted_ootle_deployment_v1(dir.path(), &replacement)
        .expect("replacement locks after unlock");
    let deployment = replaced.deployment.expect("replacement deployment");
    assert_eq!(deployment.network, "igor");
    assert_eq!(deployment.template_address, replacement.template_address);
    assert_eq!(
        deployment.template_artifact_digest_hex,
        digest_hex(b"\0asm\x01\0\0\0abc")
    );
}

#[test]
fn invalid_public_identity_is_rejected() {
    let dir = TempDir::new().expect("temp dir");
    let wasm_path = write_wasm(&dir, "anchor-template.wasm", VALID_WASM);

    let mut bad_network = valid_request(&wasm_path);
    bad_network.network = "bad network".to_owned();
    assert_eq!(
        lock_trusted_ootle_deployment_v1(dir.path(), &bad_network)
            .expect_err("network rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );

    let mut bad_address = valid_request(&wasm_path);
    bad_address.template_address = "not_template_address".to_owned();
    assert_eq!(
        lock_trusted_ootle_deployment_v1(dir.path(), &bad_address)
            .expect_err("address rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );

    let mut blank_wasm_path = valid_request(&wasm_path);
    blank_wasm_path.selected_wasm_path = " ".to_owned();
    assert_eq!(
        lock_trusted_ootle_deployment_v1(dir.path(), &blank_wasm_path)
            .expect_err("blank wasm path rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );
}

#[test]
fn invalid_wasm_paths_and_bytes_are_rejected() {
    let dir = TempDir::new().expect("temp dir");
    let missing = dir.path().join("missing.wasm");
    assert_eq!(
        inspect_template_wasm_v1(&missing)
            .expect_err("missing wasm rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );

    assert_eq!(
        inspect_template_wasm_v1(dir.path())
            .expect_err("directory rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );

    let empty = write_wasm(&dir, "empty.wasm", b"");
    assert_eq!(
        inspect_template_wasm_v1(&empty)
            .expect_err("empty rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );

    let malformed = write_wasm(&dir, "malformed.wasm", b"not wasm");
    assert_eq!(
        inspect_template_wasm_v1(&malformed)
            .expect_err("malformed rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );
}

#[test]
fn corrupt_or_unsupported_saved_record_fails_closed() {
    let dir = TempDir::new().expect("temp dir");
    let path = trusted_ootle_deployment_path_v1(dir.path());

    fs::write(&path, b"not-json").expect("write corrupt record");
    assert_eq!(
        load_trusted_ootle_deployment_v1(dir.path())
            .expect_err("corrupt record rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );

    fs::write(
        &path,
        br#"{
          "schema":"TARI_CC_PRIVATE_BALLOT_TRUSTED_OOTLE_DEPLOYMENT_V999",
          "network":"esmeralda",
          "template_address":"template_2222222222222222222222222222222222222222222222222222222222222222",
          "template_artifact_digest_hex":"3333333333333333333333333333333333333333333333333333333333333333",
          "template_module":"tari_private_ballot_anchor",
          "template_function":"publish_anchor",
          "template_event_topic":"tari_private_ballot_anchor.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1",
          "locked_at_unix_ms":1
        }"#,
    )
    .expect("write unsupported record");
    assert_eq!(
        load_trusted_ootle_deployment_v1(dir.path())
            .expect_err("unsupported schema rejects")
            .code(),
        "GUI_TRUSTED_OOTLE_DEPLOYMENT_INVALID"
    );
}
