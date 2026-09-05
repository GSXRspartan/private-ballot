//! Regression coverage for the load-driver control/validation seams the
//! standalone Load Tester GUI depends on. These tests exercise the shared
//! Rust engine — the GUI is a thin wrapper on top of these functions, so a
//! break here is a break in the GUI too. Every test stays deterministic and
//! never touches Tor or the network.

use std::fs;
use std::io::Write;
use std::path::PathBuf;

use tari_cc_private_ballot_cli::{
    ChoiceDistribution, DISTRIBUTED_LOAD_LARGE_RUN_WARNING_THRESHOLD,
    DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS, LoadDriverConfig, LoadDriverRunControl,
    credential_count, partition_credentials_with_summary, validate_load_driver_config,
    validate_load_driver_inputs,
};

/// The registry ceiling exposed to the GUI must be the same value the
/// crypto layer enforces. If a well-meaning refactor ever forks it, the GUI
/// would silently accept more voters than the on-disk registry can hold.
#[test]
fn registry_ceiling_stays_at_authoritative_4096() {
    assert_eq!(DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS, 4_096);
}

/// The 100-voter large-run warning threshold is presentation guidance; a
/// change here is not automatically wrong, but a silent drift would break
/// the GUI's warning banner. Pin it so a rename has to touch this test.
#[test]
fn large_run_warning_threshold_is_pinned_at_100() {
    assert_eq!(DISTRIBUTED_LOAD_LARGE_RUN_WARNING_THRESHOLD, 100);
}

#[test]
fn credential_count_matches_partition_summary() {
    let scratch = tempfile::tempdir().expect("scratch dir");
    // Write three .tcbcred files and one unrelated .txt file. Only the three
    // credential files should be counted.
    for name in [
        "voter-0001.tcbcred",
        "voter-0002.tcbcred",
        "voter-0003.tcbcred",
    ] {
        let mut file = fs::File::create(scratch.path().join(name)).expect("create tcbcred");
        writeln!(file, "unused-body").expect("write");
    }
    let mut extraneous =
        fs::File::create(scratch.path().join("readme.txt")).expect("create readme");
    writeln!(extraneous, "not a credential").expect("write");

    let counted = credential_count(scratch.path()).expect("count succeeds");
    assert_eq!(counted, 3);
}

#[test]
fn partition_summary_produces_inclusive_range() {
    let scratch = tempfile::tempdir().expect("scratch dir");
    for name in [
        "voter-0001.tcbcred",
        "voter-0002.tcbcred",
        "voter-0003.tcbcred",
        "voter-0004.tcbcred",
        "voter-0005.tcbcred",
    ] {
        let mut file = fs::File::create(scratch.path().join(name)).expect("create tcbcred");
        writeln!(file, "unused-body").expect("write");
    }
    let dest = scratch.path().join("partition");
    let summary = partition_credentials_with_summary(scratch.path(), &dest, 2, 3)
        .expect("partition succeeds");
    assert_eq!(summary.credentials_detected, 5);
    assert_eq!(summary.credentials_copied, 3);
    assert_eq!(summary.first_voter_index, 2);
    assert_eq!(summary.last_voter_index, 4);
    assert_eq!(summary.destination, dest);
    // The three copied files must actually land in the destination.
    let mut names: Vec<String> = fs::read_dir(&dest)
        .expect("read dest")
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![
            "voter-0002.tcbcred",
            "voter-0003.tcbcred",
            "voter-0004.tcbcred",
        ]
    );
}

#[test]
fn parallel_concurrency_is_still_rejected_by_the_load_driver_config() {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let empty = scratch.path().to_path_buf();
    // Concurrency > 1 must remain rejected structurally by the shared config
    // validator. The GUI relies on this, so it never has to enforce the rule
    // twice.
    let base = LoadDriverConfig {
        manifest_path: empty.clone(),
        registry_path: empty.clone(),
        candidate_path: empty.clone(),
        voter_public_bundle_path: empty.clone(),
        credentials_dir: empty.clone(),
        tor_socks: "127.0.0.1:1".parse().expect("loopback"),
        results_path: PathBuf::from("results.json"),
        state_dir: None,
        count: Some(1),
        start_index: 1,
        concurrency: 2,
        choice: ChoiceDistribution::RoundRobin,
        passphrase_env: "TARI_BALLOT_LOAD_PASSPHRASE".to_owned(),
        host_run_id: "host".to_owned(),
    };
    let error = validate_load_driver_config(&base).expect_err("concurrency 2 must be rejected");
    assert!(error.to_lowercase().contains("concurrency"));
}

#[test]
fn validate_load_driver_inputs_rejects_missing_credentials_dir() {
    let scratch = tempfile::tempdir().expect("scratch dir");
    let bogus = scratch.path().join("does-not-exist");
    let config = LoadDriverConfig {
        manifest_path: bogus.clone(),
        registry_path: bogus.clone(),
        candidate_path: bogus.clone(),
        voter_public_bundle_path: bogus.clone(),
        credentials_dir: bogus,
        tor_socks: "127.0.0.1:1".parse().expect("loopback"),
        results_path: scratch.path().join("results.json"),
        state_dir: None,
        count: Some(1),
        start_index: 1,
        concurrency: 1,
        choice: ChoiceDistribution::RoundRobin,
        passphrase_env: "TARI_BALLOT_LOAD_PASSPHRASE".to_owned(),
        host_run_id: "host".to_owned(),
    };
    let error = validate_load_driver_inputs(&config)
        .expect_err("validate must reject missing paths without network activity");
    assert!(error.to_lowercase().contains("does not exist"));
}

#[test]
fn load_driver_run_control_defaults_have_no_hooks() {
    // `Default` for the control struct must produce a genuinely neutral
    // control block: no progress callback, no cancel probe, and incremental
    // persistence disabled. The old `run_load_driver` wrapper depends on this
    // to keep behaving exactly like the pre-seam implementation.
    let control = LoadDriverRunControl::default();
    assert!(control.progress.is_none());
    assert!(control.cancel.is_none());
    assert!(!control.persist_incremental);
}
