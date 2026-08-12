//! CLI mode-conflict regression tests for the Phase 4 operator-tooling slice.
//!
//! Test-only clippy allows: the strict workspace lints (`expect_used`,
//! `unwrap_used`) apply to production code; test harnesses may use
//! `expect`/`unwrap` for concise assertions.

#![allow(clippy::expect_used, clippy::unwrap_used)]

//! These tests verify that the extended [`parse`] function rejects conflicting
//! modes, duplicate flags, missing values, and unknown arguments, while the
//! existing lifecycle flags still parse correctly.

use tari_cc_private_ballot_ootle_anchor_app::cli::{CliMode, parse};

const CONFIG_FAILURE: &str = "ANCHOR_APP_CONFIGURATION_FAILURE";

fn prog() -> String {
    "tari-cc-private-ballot-anchor".to_owned()
}

fn valid_write_config_args() -> Vec<String> {
    let mut args = vec![prog(), "--write-config".to_owned()];
    for (flag, val) in [
        ("--output", "C:/out.cbor"),
        ("--network", "esmeralda"),
        ("--walletd-endpoint", "http://127.0.0.1:12009"),
        ("--indexer-endpoint", "http://127.0.0.1:12500"),
        ("--account-reference", "fee-account"),
        ("--fee-component", "component_11"),
        ("--seal-signer-kind", "account"),
        ("--seal-signer-id", "0"),
        ("--max-fee", "1000"),
        ("--manifest-hash", &"1".repeat(64)),
        ("--archive-hash", &"2".repeat(64)),
        ("--snapshot-path", "C:/snap.cbor"),
        ("--evidence-path", "C:/evi.cbor"),
        ("--backoff-base-secs", "1"),
        ("--backoff-cap-secs", "10"),
        ("--receipt-query-attempts", "8"),
    ] {
        args.push(flag.to_owned());
        args.push(val.to_owned());
    }
    args
}

// --- Mode conflict tests ---

#[test]
fn write_config_with_approve_rejected() {
    let mut args = valid_write_config_args();
    args.push("--approve".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_with_dry_run_rejected() {
    let mut args = valid_write_config_args();
    args.push("--dry-run".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_with_reject_rejected() {
    let mut args = valid_write_config_args();
    args.push("--reject".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_with_config_rejected() {
    let mut args = valid_write_config_args();
    args.push("--config".to_owned());
    args.push("path".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_with_auth_env_rejected() {
    let mut args = valid_write_config_args();
    args.push("--auth-env".to_owned());
    args.push("NAME".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_with_verify_evidence_rejected() {
    let mut args = valid_write_config_args();
    args.push("--verify-evidence".to_owned());
    args.push("p".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_with_inspect_snapshot_rejected() {
    let mut args = valid_write_config_args();
    args.push("--inspect-snapshot".to_owned());
    args.push("p".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn verify_evidence_with_config_rejected() {
    let args = vec![
        prog(),
        "--verify-evidence".to_owned(),
        "p".to_owned(),
        "--config".to_owned(),
        "c".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn verify_evidence_with_approve_rejected() {
    let args = vec![
        prog(),
        "--verify-evidence".to_owned(),
        "p".to_owned(),
        "--approve".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn verify_evidence_with_dry_run_rejected() {
    let args = vec![
        prog(),
        "--verify-evidence".to_owned(),
        "p".to_owned(),
        "--dry-run".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn inspect_snapshot_with_approve_rejected() {
    let args = vec![
        prog(),
        "--inspect-snapshot".to_owned(),
        "p".to_owned(),
        "--approve".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn inspect_snapshot_with_config_rejected() {
    let args = vec![
        prog(),
        "--inspect-snapshot".to_owned(),
        "p".to_owned(),
        "--config".to_owned(),
        "c".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn verify_and_inspect_together_rejected() {
    let args = vec![
        prog(),
        "--verify-evidence".to_owned(),
        "p".to_owned(),
        "--inspect-snapshot".to_owned(),
        "q".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_and_verify_together_rejected() {
    let args = vec![
        prog(),
        "--write-config".to_owned(),
        "--verify-evidence".to_owned(),
        "p".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_and_inspect_together_rejected() {
    let args = vec![
        prog(),
        "--write-config".to_owned(),
        "--inspect-snapshot".to_owned(),
        "p".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

// --- Duplicate detection ---

#[test]
fn duplicate_write_config_mode_flag_rejected() {
    let args = vec![
        prog(),
        "--write-config".to_owned(),
        "--write-config".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn duplicate_verify_evidence_flag_rejected() {
    let args = vec![
        prog(),
        "--verify-evidence".to_owned(),
        "p1".to_owned(),
        "--verify-evidence".to_owned(),
        "p2".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn duplicate_inspect_snapshot_flag_rejected() {
    let args = vec![
        prog(),
        "--inspect-snapshot".to_owned(),
        "p1".to_owned(),
        "--inspect-snapshot".to_owned(),
        "p2".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn duplicate_value_flag_in_write_config_rejected() {
    let mut args = valid_write_config_args();
    args.push("--network".to_owned());
    args.push("igor".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn duplicate_optional_value_flag_in_write_config_rejected() {
    let mut args = valid_write_config_args();
    args.push("--request-timeout-secs".to_owned());
    args.push("30".to_owned());
    args.push("--request-timeout-secs".to_owned());
    args.push("60".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

// --- Missing values ---

#[test]
fn missing_value_for_write_config_flag_rejected() {
    let args = vec![prog(), "--write-config".to_owned(), "--output".to_owned()];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn verify_evidence_missing_path_rejected() {
    let args = vec![prog(), "--verify-evidence".to_owned()];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn inspect_snapshot_missing_path_rejected() {
    let args = vec![prog(), "--inspect-snapshot".to_owned()];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn write_config_missing_required_flag_rejected() {
    let args = vec![
        prog(),
        "--write-config".to_owned(),
        "--network".to_owned(),
        "esmeralda".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[cfg(not(feature = "offline-test-raw-hashes"))]
#[test]
fn write_config_mode_unavailable_without_offline_test_feature() {
    let args = valid_write_config_args();
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

// --- Unknown arguments ---

#[test]
fn unknown_arg_in_lifecycle_rejected() {
    let args = vec![prog(), "--bogus".to_owned()];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn unknown_arg_in_write_config_rejected() {
    let mut args = valid_write_config_args();
    args.push("--bogus".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn unknown_arg_in_verify_evidence_rejected() {
    let args = vec![
        prog(),
        "--verify-evidence".to_owned(),
        "p".to_owned(),
        "--bogus".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn unknown_arg_in_inspect_snapshot_rejected() {
    let args = vec![
        prog(),
        "--inspect-snapshot".to_owned(),
        "p".to_owned(),
        "--bogus".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

// --- Existing lifecycle flags still work ---

#[test]
fn lifecycle_no_flags_parses() {
    let args = vec![prog()];
    let mode = parse(&args).expect("parse");
    assert!(matches!(mode, CliMode::Lifecycle(_)));
}

#[test]
fn lifecycle_approve_parses() {
    let args = vec![prog(), "--approve".to_owned()];
    let mode = parse(&args).expect("parse");
    match mode {
        CliMode::Lifecycle(l) => assert!(l.approve),
        _ => panic!("expected lifecycle"),
    }
}

#[test]
fn lifecycle_dry_run_parses() {
    let args = vec![
        prog(),
        "--dry-run".to_owned(),
        "--config".to_owned(),
        "c".to_owned(),
    ];
    let mode = parse(&args).expect("parse");
    match mode {
        CliMode::Lifecycle(l) => assert!(l.dry_run),
        _ => panic!("expected lifecycle"),
    }
}

#[test]
fn lifecycle_approve_and_reject_rejected() {
    let args = vec![prog(), "--approve".to_owned(), "--reject".to_owned()];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn lifecycle_config_and_auth_env_parse() {
    let args = vec![
        prog(),
        "--config".to_owned(),
        "c".to_owned(),
        "--auth-env".to_owned(),
        "NAME".to_owned(),
    ];
    let mode = parse(&args).expect("parse");
    match mode {
        CliMode::Lifecycle(l) => {
            assert_eq!(l.config_path.as_deref(), Some("c"));
            assert_eq!(l.auth_env.as_deref(), Some("NAME"));
        }
        _ => panic!("expected lifecycle"),
    }
}

#[test]
fn lifecycle_archive_path_parses() {
    let args = vec![
        prog(),
        "--config".to_owned(),
        "c".to_owned(),
        "--archive".to_owned(),
        "archive-dir".to_owned(),
    ];
    let mode = parse(&args).expect("parse");
    match mode {
        CliMode::Lifecycle(l) => {
            assert_eq!(l.config_path.as_deref(), Some("c"));
            assert_eq!(l.archive_path.as_deref(), Some("archive-dir"));
        }
        _ => panic!("expected lifecycle"),
    }
}

// --- Write-config mode parses correctly ---

#[test]
#[cfg(feature = "offline-test-raw-hashes")]
fn write_config_mode_parses_with_optional_flags() {
    let mut args = valid_write_config_args();
    args.push("--request-timeout-secs".to_owned());
    args.push("30".to_owned());
    args.push("--ttl-secs".to_owned());
    args.push("120".to_owned());
    let mode = parse(&args).expect("parse");
    match mode {
        CliMode::WriteConfig(wc) => {
            assert_eq!(wc.request_timeout_secs.as_deref(), Some("30"));
            assert_eq!(wc.ttl_secs.as_deref(), Some("120"));
        }
        _ => panic!("expected write-config"),
    }
}

#[test]
#[cfg(feature = "offline-test-raw-hashes")]
fn write_config_mode_parses_with_force() {
    let mut args = valid_write_config_args();
    args.push("--force".to_owned());
    let mode = parse(&args).expect("parse");
    match mode {
        CliMode::WriteConfig(wc) => assert!(wc.force),
        _ => panic!("expected write-config"),
    }
}

// --- F7: value-flag followed by `--` token rejection ---

#[test]
fn output_flag_followed_by_force_rejected() {
    // `--output --force` must be rejected as a missing value, not treat
    // `--force` as the output path.
    let mut args = valid_write_config_args();
    // Remove the original --output pair and re-add with --force as the value.
    args.retain(|a| a != "--output" && a != "C:/out.cbor");
    args.push("--output".to_owned());
    args.push("--force".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn network_flag_followed_by_flag_rejected() {
    let mut args = valid_write_config_args();
    args.retain(|a| a != "--network" && a != "esmeralda");
    args.push("--network".to_owned());
    args.push("--max-fee".to_owned());
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn verify_evidence_path_starting_with_dash_dash_rejected() {
    let args = vec![
        prog(),
        "--verify-evidence".to_owned(),
        "--inspect-snapshot".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}

#[test]
fn inspect_snapshot_path_starting_with_dash_dash_rejected() {
    let args = vec![
        prog(),
        "--inspect-snapshot".to_owned(),
        "--verify-evidence".to_owned(),
    ];
    assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
}
