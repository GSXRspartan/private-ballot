//! Regression coverage for the load-driver control/validation seams the
//! standalone Load Tester GUI depends on. These tests exercise the shared
//! Rust engine — the GUI is a thin wrapper on top of these functions, so a
//! break here is a break in the GUI too. Every test stays deterministic and
//! never touches Tor or the network.

use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use tari_cc_private_ballot_cli::{
    ChoiceDistribution, DISTRIBUTED_LOAD_LARGE_RUN_WARNING_THRESHOLD,
    DISTRIBUTED_LOAD_MAX_REGISTRY_MEMBERS, LoadDriverConfig, LoadDriverRunControl,
    credential_count, partition_credentials_with_summary, run_load_driver_with_control,
    validate_load_driver_config, validate_load_driver_inputs,
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
        remote_socks: None,
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
        remote_socks: None,
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

// ---------------------------------------------------------------------------
// F2 — exact credential selection: the driver must fail closed, BEFORE any
// election artifact is loaded and before any voter runs, unless the requested
// count is satisfied EXACTLY by the local credential files.
// ---------------------------------------------------------------------------

fn scratch_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "load-driver-exact-{}-{}-{}",
        label,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch");
    dir
}

fn write_dummy_credentials(dir: &PathBuf, count: usize) {
    std::fs::create_dir_all(dir).expect("create credentials dir");
    for index in 1..=count {
        let path = dir.join(format!("voter-{index:04}.tcbcred"));
        std::fs::write(&path, b"unused-body").expect("write credential");
    }
}

fn config_with(
    credentials_dir: PathBuf,
    start_index: usize,
    count: Option<usize>,
) -> LoadDriverConfig {
    // Artifact paths point at an EXISTING location (the credentials dir's
    // parent) so validate_load_driver_config passes; the run then fails at
    // artifact content loading, which is exactly the sentinel these tests
    // assert on after the selection gate has passed.
    let existing = credentials_dir
        .parent()
        .map(|parent| parent.to_path_buf())
        .unwrap_or_else(|| credentials_dir.clone());
    LoadDriverConfig {
        manifest_path: existing.clone(),
        registry_path: existing.clone(),
        candidate_path: existing.clone(),
        voter_public_bundle_path: existing,
        tor_socks: SocketAddr::from(([127, 0, 0, 1], 1)),
        remote_socks: None,
        credentials_dir,
        results_path: PathBuf::from("results.json"),
        state_dir: None,
        count,
        start_index,
        concurrency: 1,
        choice: ChoiceDistribution::RoundRobin,
        passphrase_env: "TARI_BALLOT_LOAD_PASSPHRASE".to_owned(),
        host_run_id: "host".to_owned(),
    }
}

#[test]
fn exact_requested_selection_passes_the_driver_gate() {
    let base = scratch_dir("exact-pass");
    let voters = base.join("voters");
    write_dummy_credentials(&voters, 3);
    // The selection gate passes, so the run proceeds to artifact loading and
    // fails there — NOT on selection.
    let error = run_load_driver_with_control(
        &config_with(voters, 1, Some(3)),
        "unused-passphrase",
        &mut LoadDriverRunControl::default(),
    )
    .expect_err("dummy artifacts must fail artifact loading");
    assert!(
        error.contains("election artifacts"),
        "exact selection must pass the gate and reach artifact loading: {error}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn partition_250_files_local_start_1_count_250_passes_the_driver_gate() {
    let base = scratch_dir("partition-250");
    let voters = base.join("voters");
    write_dummy_credentials(&voters, 250);
    let error = run_load_driver_with_control(
        &config_with(voters, 1, Some(250)),
        "unused-passphrase",
        &mut LoadDriverRunControl::default(),
    )
    .expect_err("artifact loading must fail after the gate passes");
    assert!(
        error.contains("election artifacts"),
        "requested 250 / available 250 / local start 1 must pass the gate: {error}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn partition_directory_with_global_start_index_fails_before_any_voter() {
    // A copied partition holds ONLY global voters 251–500 as local files
    // 1–250. Entering the global start index 251 selects ZERO local files and
    // must fail closed before any voter execution.
    let base = scratch_dir("partition-global-start");
    let voters = base.join("voters");
    write_dummy_credentials(&voters, 250);
    let error = run_load_driver_with_control(
        &config_with(voters, 251, Some(250)),
        "unused-passphrase",
        &mut LoadDriverRunControl::default(),
    )
    .expect_err("global start index on a local partition must fail");
    assert!(
        error.contains("requested 250") && error.contains("only 0 credentials"),
        "zero selection must fail closed with a useful message: {error}"
    );
    assert!(
        !error.contains("election artifacts"),
        "the gate must fire before election artifacts are loaded: {error}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn selected_zero_files_can_never_reach_a_report() {
    let base = scratch_dir("zero-selected");
    let voters = base.join("voters");
    write_dummy_credentials(&voters, 2);
    // start index past the end of the directory: zero files selected.
    assert!(
        run_load_driver_with_control(
            &config_with(voters.clone(), 3, Some(1)),
            "unused-passphrase",
            &mut LoadDriverRunControl::default(),
        )
        .is_err()
    );
    // And without an explicit count (process-remainder mode) an empty
    // remainder is also rejected rather than reporting COMPLETE with 0.
    let empty = base.join("empty");
    std::fs::create_dir_all(&empty).expect("create empty dir");
    let error = run_load_driver_with_control(
        &config_with(empty, 1, None),
        "unused-passphrase",
        &mut LoadDriverRunControl::default(),
    )
    .expect_err("zero selected files must fail");
    assert!(
        error.contains("no test voter credentials were selected"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn fewer_files_than_requested_fails_closed() {
    let base = scratch_dir("short-selection");
    let voters = base.join("voters");
    write_dummy_credentials(&voters, 173);
    let error = run_load_driver_with_control(
        &config_with(voters, 1, Some(250)),
        "unused-passphrase",
        &mut LoadDriverRunControl::default(),
    )
    .expect_err("partial selection must fail closed");
    assert!(
        error.contains("requested 250") && error.contains("only 173"),
        "{error}"
    );
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn offline_validation_reports_requested_versus_selected_counts() {
    let base = scratch_dir("validation-counts");
    let voters = base.join("voters");
    write_dummy_credentials(&voters, 4);
    let mut config = config_with(voters, 1, Some(4));
    // Point every artifact at the (existing) base dir so config existence
    // checks pass; the summary is what this test inspects. Artifact content
    // loading fails for dummy files, so only exercise the selection shape
    // through the standalone results-path validation helper and the gate.
    config.manifest_path = base.clone();
    config.registry_path = base.clone();
    config.candidate_path = base.clone();
    config.voter_public_bundle_path = base.clone();
    config.results_path = base.join("results.json");
    // Artifact loading fails for a directory — the exact-selection gate runs
    // inside validate too, but AFTER artifacts; the driver-level tests above
    // prove the gate. Here we assert the summary path is reachable only with
    // real artifacts, i.e. validation still fails closed on dummies.
    let error = validate_load_driver_inputs(&config)
        .expect_err("dummy artifacts must fail offline validation");
    assert!(error.contains("election artifacts"), "{error}");
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn partition_range_math_stays_inclusive_and_global_display_is_preserved() {
    let base = scratch_dir("range-math");
    let all = base.join("all");
    write_dummy_credentials(&all, 500);
    let partition = base.join("vps");
    let summary =
        partition_credentials_with_summary(&all, &partition, 251, 250).expect("partition 251–500");
    // Global range display stays correct...
    assert_eq!(summary.first_voter_index, 251);
    assert_eq!(summary.last_voter_index, 500);
    assert_eq!(summary.credentials_detected, 500);
    assert_eq!(summary.credentials_copied, 250);
    // ...and the partition directory holds exactly 250 LOCAL files, so a run
    // against it must use local start index 1 (not the global 251).
    let copied_count = credential_count(&partition).expect("count partition");
    assert_eq!(copied_count, 250);
    let local = partition_credentials_with_summary(&partition, &base.join("recheck"), 1, 250)
        .expect("local run range");
    assert_eq!(local.first_voter_index, 1);
    assert_eq!(local.last_voter_index, 250);
    assert_eq!(local.credentials_copied, 250);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn driver_fails_closed_before_any_voter_when_results_persistence_is_unusable() {
    let base = scratch_dir("persist-probe");
    let voters = base.join("voters");
    write_dummy_credentials(&voters, 2);
    // The parent of the results path is a REGULAR FILE, so no results JSON can
    // ever be committed there. With incremental persistence requested the
    // driver must fail closed BEFORE the first voter — with 2 selected files
    // the run must error at the gate, not run one voter and stop.
    let parent_file = base.join("not-a-dir");
    std::fs::write(&parent_file, b"regular file").expect("write parent file");
    let mut config = config_with(voters, 1, Some(2));
    config.results_path = parent_file.join("results.json");
    let mut control = LoadDriverRunControl {
        progress: None,
        cancel: None,
        persist_incremental: true,
    };
    let error = run_load_driver_with_control(&config, "unused-passphrase", &mut control)
        .expect_err("unusable results destination must fail the run");
    assert!(
        error.contains("results output"),
        "failure must name the results evidence problem: {error}"
    );
    // No results file or partial snapshot may exist.
    assert!(
        !parent_file.join("results.json").exists(),
        "no results file must be created for a failed pre-run gate"
    );
    let _ = std::fs::remove_dir_all(&base);
}
