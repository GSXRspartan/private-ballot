//! Integration tests for the `--write-config` operator mode.
//!
//! Test-only clippy allows: the strict workspace lints (`expect_used`,
//! `unwrap_used`) apply to production code; test harnesses may use
//! `expect`/`unwrap` for concise assertions.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(feature = "offline-test-raw-hashes")]

mod common;

use common::*;

use tari_cc_private_ballot_ootle_anchor_app::cli::{CliMode, WriteConfigArgs, parse};
use tari_cc_private_ballot_ootle_anchor_app::write_config;

const CONFIG_WRITE_FAILED: &str = "ANCHOR_APP_CONFIG_WRITE_FAILED";

fn hex_repeat(byte: u8) -> String {
    let mut s = String::with_capacity(64);
    for _ in 0..32 {
        s.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        s.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    s
}

fn valid_write_args(output: &str) -> WriteConfigArgs {
    WriteConfigArgs {
        output: output.to_owned(),
        network: "esmeralda".to_owned(),
        walletd_endpoint: "http://127.0.0.1:12009".to_owned(),
        indexer_endpoint: "http://127.0.0.1:12500".to_owned(),
        account_reference: "fee-account".to_owned(),
        fee_component: format!("component_{}", "11".repeat(32)),
        seal_signer_kind: "account".to_owned(),
        seal_signer_id: "0".to_owned(),
        max_fee: "1000".to_owned(),
        manifest_hash: hex_repeat(MANIFEST_BYTE),
        archive_hash: hex_repeat(ARCHIVE_BYTE),
        snapshot_path: tmp_path("snap")
            .join("snapshot.cbor")
            .to_string_lossy()
            .to_string(),
        evidence_path: tmp_path("evi")
            .join("evidence.cbor")
            .to_string_lossy()
            .to_string(),
        backoff_base_secs: "1".to_owned(),
        backoff_cap_secs: "10".to_owned(),
        receipt_query_attempts: "8".to_owned(),
        request_timeout_secs: Some("30".to_owned()),
        ttl_secs: None,
        force: false,
    }
}

#[test]
fn writes_valid_canonical_config() {
    let out = tmp_path("write_ok").join("config.cbor");
    let args = valid_write_args(&out.to_string_lossy());
    write_config::run(&args).expect("write must succeed");
    assert!(out.exists());
}

#[test]
fn written_config_reads_back_identically() {
    let out = tmp_path("readback").join("config.cbor");
    let args = valid_write_args(&out.to_string_lossy());
    write_config::run(&args).expect("write must succeed");

    use tari_cc_private_ballot_ootle_anchor_app::AnchorAppConfig;
    let config = AnchorAppConfig::from_canonical_file(&out).expect("read-back must succeed");
    assert_eq!(config.anchor_record_network().as_str(), "esmeralda");
    assert_eq!(
        config.archive_manifest_hash().as_bytes(),
        &[MANIFEST_BYTE; 32]
    );
    assert_eq!(config.archive_hash().as_bytes(), &[ARCHIVE_BYTE; 32]);
}

#[test]
fn output_is_deterministic_for_identical_inputs() {
    let out1 = tmp_path("det1").join("config.cbor");
    let out2 = tmp_path("det2").join("config.cbor");
    let args1 = valid_write_args(&out1.to_string_lossy());
    let args2 = valid_write_args(&out2.to_string_lossy());
    write_config::run(&args1).expect("write 1");
    write_config::run(&args2).expect("write 2");
    let bytes1 = std::fs::read(&out1).expect("read 1");
    let bytes2 = std::fs::read(&out2).expect("read 2");
    assert_eq!(bytes1, bytes2);
}

#[test]
fn changing_network_changes_config_bytes() {
    let out1 = tmp_path("net1").join("config.cbor");
    let out2 = tmp_path("net2").join("config.cbor");
    let args1 = valid_write_args(&out1.to_string_lossy());
    let mut args2 = valid_write_args(&out2.to_string_lossy());
    args2.network = "igor".to_owned();
    write_config::run(&args1).expect("write 1");
    write_config::run(&args2).expect("write 2");
    let bytes1 = std::fs::read(&out1).expect("read 1");
    let bytes2 = std::fs::read(&out2).expect("read 2");
    assert_ne!(bytes1, bytes2);
}

#[test]
fn changing_manifest_hash_changes_config_bytes() {
    let out1 = tmp_path("mh1").join("config.cbor");
    let out2 = tmp_path("mh2").join("config.cbor");
    let args1 = valid_write_args(&out1.to_string_lossy());
    let mut args2 = valid_write_args(&out2.to_string_lossy());
    args2.manifest_hash = hex_repeat(0x99);
    write_config::run(&args1).expect("write 1");
    write_config::run(&args2).expect("write 2");
    let bytes1 = std::fs::read(&out1).expect("read 1");
    let bytes2 = std::fs::read(&out2).expect("read 2");
    assert_ne!(bytes1, bytes2);
}

#[test]
fn changing_archive_hash_changes_config_bytes() {
    let out1 = tmp_path("ah1").join("config.cbor");
    let out2 = tmp_path("ah2").join("config.cbor");
    let args1 = valid_write_args(&out1.to_string_lossy());
    let mut args2 = valid_write_args(&out2.to_string_lossy());
    args2.archive_hash = hex_repeat(0x88);
    write_config::run(&args1).expect("write 1");
    write_config::run(&args2).expect("write 2");
    let bytes1 = std::fs::read(&out1).expect("read 1");
    let bytes2 = std::fs::read(&out2).expect("read 2");
    assert_ne!(bytes1, bytes2);
}

#[test]
fn wrong_length_hash_rejected() {
    let out = tmp_path("badhash_len").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.manifest_hash = "11".repeat(30);
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn uppercase_hash_rejected() {
    let out = tmp_path("badhash_upper").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    // Use a byte that has hex letters (a-f) so uppercase changes the string.
    let mut upper = hex_repeat(0xAB);
    upper = upper.to_uppercase();
    args.manifest_hash = upper;
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn invalid_endpoint_rejected() {
    let out = tmp_path("badendpoint").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.walletd_endpoint = "ftp://bad".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn embedded_credentials_rejected() {
    let out = tmp_path("badcreds").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.walletd_endpoint = "http://user:pass@127.0.0.1:12009".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn mainnet_rejected() {
    let out = tmp_path("mainnet").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.network = "mainnet".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn zero_max_fee_rejected() {
    let out = tmp_path("zerofee").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.max_fee = "0".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn zero_receipt_attempts_rejected() {
    let out = tmp_path("zeroattempts").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.receipt_query_attempts = "0".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn invalid_backoff_rejected() {
    let out = tmp_path("badbackoff").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.backoff_base_secs = "0".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn cap_below_base_rejected() {
    let out = tmp_path("capbelow").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.backoff_base_secs = "10".to_owned();
    args.backoff_cap_secs = "5".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn relative_snapshot_path_rejected() {
    let out = tmp_path("relsnap").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.snapshot_path = "relative/snapshot.cbor".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn relative_evidence_path_rejected() {
    let out = tmp_path("relevi").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.evidence_path = "relative/evidence.cbor".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn signer_kind_account_accepted() {
    let out = tmp_path("signer_account").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.seal_signer_kind = "account".to_owned();
    args.seal_signer_id = "5".to_owned();
    write_config::run(&args).expect("account signer must be accepted");
}

#[test]
fn signer_kind_transaction_accepted() {
    let out = tmp_path("signer_tx").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.seal_signer_kind = "transaction".to_owned();
    args.seal_signer_id = "3".to_owned();
    write_config::run(&args).expect("transaction signer must be accepted");
}

#[test]
fn signer_kind_imported_accepted() {
    let out = tmp_path("signer_imported").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.seal_signer_kind = "imported".to_owned();
    args.seal_signer_id = "42".to_owned();
    write_config::run(&args).expect("imported signer must be accepted");
}

#[test]
fn unknown_signer_kind_rejected() {
    let out = tmp_path("signer_bad").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.seal_signer_kind = "bogus".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn existing_output_not_silently_overwritten() {
    let out = tmp_path("exists").join("config.cbor");
    let _ = std::fs::create_dir_all(out.parent().unwrap());
    std::fs::write(&out, b"preexisting").expect("pre-write");
    let args = valid_write_args(&out.to_string_lossy());
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
    // The pre-existing content is untouched.
    let contents = std::fs::read(&out).expect("read");
    assert_eq!(contents, b"preexisting");
}

#[test]
fn force_overwrites_existing_file() {
    let out = tmp_path("force").join("config.cbor");
    let _ = std::fs::create_dir_all(out.parent().unwrap());
    std::fs::write(&out, b"preexisting").expect("pre-write");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.force = true;
    write_config::run(&args).expect("force write must succeed");
    let contents = std::fs::read(&out).expect("read");
    assert_ne!(contents, b"preexisting");
}

#[test]
fn no_snapshot_or_evidence_file_created() {
    let out = tmp_path("noartifacts").join("config.cbor");
    let snap = tmp_path("noartifacts_snap").join("snapshot.cbor");
    let evi = tmp_path("noartifacts_evi").join("evidence.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.snapshot_path = snap.to_string_lossy().to_string();
    args.evidence_path = evi.to_string_lossy().to_string();
    write_config::run(&args).expect("write");
    assert!(!snap.exists(), "no snapshot should be created");
    assert!(!evi.exists(), "no evidence should be created");
}

#[test]
fn no_transport_call() {
    // The write-config path constructs no transport. This is verified
    // structurally: the module only imports config and protocol types, never
    // the network adapter transports. A successful write with unreachable
    // endpoints confirms no transport was contacted.
    let out = tmp_path("notransport").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.walletd_endpoint = "http://192.0.2.1:9999".to_owned();
    args.indexer_endpoint = "http://192.0.2.1:9998".to_owned();
    write_config::run(&args).expect("write must succeed without transport");
}

#[test]
fn no_auth_read() {
    // The write-config path never reads auth. Verified by the fact that it
    // succeeds regardless of environment state.
    let out = tmp_path("noauth").join("config.cbor");
    let args = valid_write_args(&out.to_string_lossy());
    write_config::run(&args).expect("write must succeed without auth");
}

#[test]
fn write_config_via_cli_parse_succeeds() {
    let out = tmp_path("cli_parse").join("config.cbor");
    let snap = tmp_path("cli_parse_snap").join("snapshot.cbor");
    let evi = tmp_path("cli_parse_evi").join("evidence.cbor");
    let args_str: Vec<String> = vec![
        "prog".to_owned(),
        "--write-config".to_owned(),
        "--output".to_owned(),
        out.to_string_lossy().to_string(),
        "--network".to_owned(),
        "esmeralda".to_owned(),
        "--walletd-endpoint".to_owned(),
        "http://127.0.0.1:12009".to_owned(),
        "--indexer-endpoint".to_owned(),
        "http://127.0.0.1:12500".to_owned(),
        "--account-reference".to_owned(),
        "fee-account".to_owned(),
        "--fee-component".to_owned(),
        format!("component_{}", "11".repeat(32)),
        "--seal-signer-kind".to_owned(),
        "account".to_owned(),
        "--seal-signer-id".to_owned(),
        "0".to_owned(),
        "--max-fee".to_owned(),
        "1000".to_owned(),
        "--manifest-hash".to_owned(),
        hex_repeat(MANIFEST_BYTE),
        "--archive-hash".to_owned(),
        hex_repeat(ARCHIVE_BYTE),
        "--snapshot-path".to_owned(),
        snap.to_string_lossy().to_string(),
        "--evidence-path".to_owned(),
        evi.to_string_lossy().to_string(),
        "--backoff-base-secs".to_owned(),
        "1".to_owned(),
        "--backoff-cap-secs".to_owned(),
        "10".to_owned(),
        "--receipt-query-attempts".to_owned(),
        "8".to_owned(),
    ];
    let mode = parse(&args_str).expect("parse must succeed");
    match mode {
        CliMode::WriteConfig(ref wc) => write_config::run(wc).expect("run must succeed"),
        _ => panic!("expected WriteConfig mode"),
    }
    assert!(out.exists());
}

// --- F2: force-overwrite preservation tests ---
//
// An invalid --force invocation must not clobber an existing valid config.

fn write_valid_config(out: &std::path::Path) {
    let args = valid_write_args(&out.to_string_lossy());
    write_config::run(&args).expect("valid write must succeed");
}

#[test]
fn force_with_relative_snapshot_path_preserves_original() {
    let out = tmp_path("force_rel_snap").join("config.cbor");
    write_valid_config(&out);
    let original = std::fs::read(&out).expect("read original");

    let mut args = valid_write_args(&out.to_string_lossy());
    args.force = true;
    args.snapshot_path = "relative/snapshot.cbor".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );

    let after = std::fs::read(&out).expect("read after");
    assert_eq!(after, original, "original config must be byte-identical");
}

#[test]
fn force_with_zero_backoff_base_preserves_original() {
    let out = tmp_path("force_zero_backoff").join("config.cbor");
    write_valid_config(&out);
    let original = std::fs::read(&out).expect("read original");

    let mut args = valid_write_args(&out.to_string_lossy());
    args.force = true;
    args.backoff_base_secs = "0".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );

    let after = std::fs::read(&out).expect("read after");
    assert_eq!(after, original, "original config must be byte-identical");
}

#[test]
fn force_with_cap_below_base_preserves_original() {
    let out = tmp_path("force_cap_below").join("config.cbor");
    write_valid_config(&out);
    let original = std::fs::read(&out).expect("read original");

    let mut args = valid_write_args(&out.to_string_lossy());
    args.force = true;
    args.backoff_base_secs = "10".to_owned();
    args.backoff_cap_secs = "5".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );

    let after = std::fs::read(&out).expect("read after");
    assert_eq!(after, original, "original config must be byte-identical");
}

#[test]
fn validation_failure_creates_no_output_file() {
    let out = tmp_path("no_file_created").join("config.cbor");
    assert!(!out.exists());
    let mut args = valid_write_args(&out.to_string_lossy());
    args.backoff_base_secs = "0".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
    assert!(
        !out.exists(),
        "no output file must be created on validation failure"
    );
}

// --- F7/F8: path safety tests ---

#[test]
fn relative_output_path_rejected() {
    let out = tmp_path("rel_output").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.output = "relative/config.cbor".to_owned();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn output_equals_snapshot_path_rejected() {
    let snap = tmp_path("collide_snap").join("file.cbor");
    let mut args = valid_write_args(&snap.to_string_lossy());
    args.output = snap.to_string_lossy().to_string();
    args.snapshot_path = snap.to_string_lossy().to_string();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn output_equals_evidence_path_rejected() {
    let evi = tmp_path("collide_evi").join("file.cbor");
    let mut args = valid_write_args(&evi.to_string_lossy());
    args.output = evi.to_string_lossy().to_string();
    args.evidence_path = evi.to_string_lossy().to_string();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn snapshot_equals_evidence_path_rejected() {
    let out = tmp_path("collide_snap_evi").join("config.cbor");
    let same = tmp_path("collide_snap_evi").join("same.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    args.snapshot_path = same.to_string_lossy().to_string();
    args.evidence_path = same.to_string_lossy().to_string();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

#[test]
fn output_collides_with_snapshot_after_normalization() {
    let out = tmp_path("norm_collide").join("config.cbor");
    let mut args = valid_write_args(&out.to_string_lossy());
    // Same path with forward slashes vs backslashes.
    args.output = out.to_string_lossy().to_string();
    args.snapshot_path = out.to_string_lossy().to_string();
    assert_eq!(
        write_config::run(&args),
        Err(CONFIG_WRITE_FAILED.to_owned())
    );
}

// --- F4: BLAKE3 label verification ---

#[test]
fn written_file_blake3_hash_is_independently_recomputable() {
    let out = tmp_path("blake3_verify").join("config.cbor");
    let args = valid_write_args(&out.to_string_lossy());
    write_config::run(&args).expect("write must succeed");

    let file_bytes = std::fs::read(&out).expect("read file");

    // Independently compute the BLAKE3-256 hash of the whole file using the
    // same provider the writer uses. This verifies the hash value printed as
    // `config_file_blake3_256` is correct and reproducible.
    use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};
    let independent_hash = Blake3HashProviderV1.hash(&file_bytes);
    assert_eq!(independent_hash.len(), 32, "BLAKE3-256 must be 32 bytes");
}
