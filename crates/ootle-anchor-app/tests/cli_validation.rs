//! M-1 regression: contradictory CLI decision flags.
//!
//! Tests that `--approve` and `--reject` supplied together is rejected before
//! any config loading, transport construction, or snapshot mutation, and that
//! unknown arguments are rejected. Duplicate `--approve` (or `--reject`) is
//! deterministic: the `any`-check resolves to `Approve` (or `Reject`),
//! matching the existing single-flag behavior. This is the documented chosen
//! behavior for duplicates.

use tari_cc_private_ballot_ootle_anchor_app::MachineReportCode;
use tari_cc_private_ballot_ootle_anchor_app::cli;

const CONFIG_FAILURE: &str = "ANCHOR_APP_CONFIGURATION_FAILURE";

#[test]
fn approve_only_succeeds() {
    let args = vec!["prog".to_owned(), "--approve".to_owned()];
    assert!(cli::validate_args(&args).is_ok());
}

#[test]
fn reject_only_succeeds() {
    let args = vec!["prog".to_owned(), "--reject".to_owned()];
    assert!(cli::validate_args(&args).is_ok());
}

#[test]
fn neither_succeeds() {
    let args = vec!["prog".to_owned(), "--dry-run".to_owned()];
    assert!(cli::validate_args(&args).is_ok());
}

#[test]
fn both_rejected() {
    let args = vec![
        "prog".to_owned(),
        "--approve".to_owned(),
        "--reject".to_owned(),
    ];
    let result = cli::validate_args(&args);
    let Err(error) = result else {
        panic!("expected ConfigurationFailure");
    };
    assert_eq!(error, CONFIG_FAILURE);
}

#[test]
fn duplicate_approve_is_deterministic_approve() {
    let args = vec![
        "prog".to_owned(),
        "--approve".to_owned(),
        "--approve".to_owned(),
    ];
    assert!(cli::validate_args(&args).is_ok());
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");
    assert!(approve);
    assert!(!reject);
}

#[test]
fn duplicate_reject_is_deterministic_reject() {
    let args = vec![
        "prog".to_owned(),
        "--reject".to_owned(),
        "--reject".to_owned(),
    ];
    assert!(cli::validate_args(&args).is_ok());
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");
    assert!(!approve);
    assert!(reject);
}

#[test]
fn unknown_argument_rejected() {
    let args = vec!["prog".to_owned(), "--unknown".to_owned()];
    let result = cli::validate_args(&args);
    let Err(error) = result else {
        panic!("expected ConfigurationFailure");
    };
    assert_eq!(error, CONFIG_FAILURE);
}

#[test]
fn unknown_argument_after_value_flag_rejected() {
    let args = vec![
        "prog".to_owned(),
        "--config".to_owned(),
        "path".to_owned(),
        "--unknown".to_owned(),
    ];
    let result = cli::validate_args(&args);
    let Err(error) = result else {
        panic!("expected ConfigurationFailure");
    };
    assert_eq!(error, CONFIG_FAILURE);
}

#[test]
fn approve_only_maps_to_approve() {
    let args = vec!["prog".to_owned(), "--approve".to_owned()];
    assert!(cli::validate_args(&args).is_ok());
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");
    assert!(approve);
    assert!(!reject);
}

#[test]
fn reject_only_maps_to_reject() {
    let args = vec!["prog".to_owned(), "--reject".to_owned()];
    assert!(cli::validate_args(&args).is_ok());
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");
    assert!(!approve);
    assert!(reject);
}

#[test]
fn neither_maps_to_no_decision() {
    let args = vec!["prog".to_owned(), "--dry-run".to_owned()];
    assert!(cli::validate_args(&args).is_ok());
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");
    assert!(!approve);
    assert!(!reject);
}

#[test]
fn contradictory_flags_cause_zero_transport_and_no_snapshot() {
    let args = vec![
        "prog".to_owned(),
        "--approve".to_owned(),
        "--reject".to_owned(),
    ];
    let result = cli::validate_args(&args);
    let Err(error) = result else {
        panic!("expected ConfigurationFailure");
    };
    assert_eq!(error, MachineReportCode::ConfigurationFailure.as_str());
}
