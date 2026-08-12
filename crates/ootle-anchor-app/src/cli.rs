//! Narrow CLI argument parsing for the anchor application binary (Slice 4A10
//! repair M-1, extended by the Phase 4 operator-tooling slice).
//!
//! This module holds the manual argument parser's validation logic so it can be
//! unit- and integration-tested without invoking the binary. It introduces no
//! CLI framework and performs no I/O.
//!
//! Three explicit operator modes are layered on top of the original lifecycle
//! mode:
//!
//! * `--write-config` — build and persist a canonical [`AnchorAppConfig`];
//! * `--verify-evidence <path>` — decode and verify a canonical evidence file;
//! * `--inspect-snapshot <path>` — decode and verify a canonical snapshot file.
//!
//! Only one mode may be selected at a time. Mode detection and conflict
//! rejection happen before any file or transport activity. The lifecycle mode
//! remains the default when none of the three operator mode flags is supplied.

use crate::report::MachineReportCode;

const CONFIG_FAILURE: &str = "ANCHOR_APP_CONFIGURATION_FAILURE";

/// The parsed CLI mode selected by the operator.
///
/// Produced by [`parse`]. The binary dispatches on this before any config
/// loading, auth loading, runtime construction, transport construction,
/// snapshot read/write, or evidence read/write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliMode {
    /// The original lifecycle mode (prepare / approve / reject / dry-run).
    Lifecycle(LifecycleArgs),
    /// `--write-config` mode: build and persist a canonical config.
    WriteConfig(Box<WriteConfigArgs>),
    /// `--verify-evidence <path>` mode: decode and verify an evidence file.
    VerifyEvidence {
        /// Absolute path to the evidence file.
        path: String,
    },
    /// `--inspect-snapshot <path>` mode: decode and verify a snapshot file.
    InspectSnapshot {
        /// Absolute path to the snapshot file.
        path: String,
    },
}

/// Arguments for the lifecycle mode (unchanged from the original binary).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LifecycleArgs {
    /// `--config <path>` value, if supplied.
    pub config_path: Option<String>,
    /// `--auth-env <name>` value, if supplied.
    pub auth_env: Option<String>,
    /// `--archive <finalized-archive-dir>` value, required for live lifecycle runs.
    pub archive_path: Option<String>,
    /// Whether `--approve` was supplied.
    pub approve: bool,
    /// Whether `--reject` was supplied.
    pub reject: bool,
    /// Whether `--dry-run` was supplied.
    pub dry_run: bool,
}

/// Raw string arguments for `--write-config` mode.
///
/// Value parsing and validation is delegated to the [`crate::write_config`]
/// module, which uses the existing project-owned constructors. The CLI parser
/// only validates argument structure (known flags, no duplicates, no missing
/// values, required flags present).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteConfigArgs {
    /// `--output <absolute-path>` (required).
    pub output: String,
    /// `--network <esmeralda|igor|localnet>` (required).
    pub network: String,
    /// `--walletd-endpoint <url>` (required).
    pub walletd_endpoint: String,
    /// `--indexer-endpoint <url>` (required).
    pub indexer_endpoint: String,
    /// `--account-reference <value>` (required).
    pub account_reference: String,
    /// `--fee-component <component-address>` (required).
    pub fee_component: String,
    /// `--seal-signer-kind <account|transaction|imported>` (required).
    pub seal_signer_kind: String,
    /// `--seal-signer-id <unsigned-integer>` (required).
    pub seal_signer_id: String,
    /// `--max-fee <u64>` (required).
    pub max_fee: String,
    /// `--manifest-hash <64-lowercase-hex>` (required).
    pub manifest_hash: String,
    /// `--archive-hash <64-lowercase-hex>` (required).
    pub archive_hash: String,
    /// `--snapshot-path <absolute-path>` (required).
    pub snapshot_path: String,
    /// `--evidence-path <absolute-path>` (required).
    pub evidence_path: String,
    /// `--backoff-base-secs <u64>` (required).
    pub backoff_base_secs: String,
    /// `--backoff-cap-secs <u64>` (required).
    pub backoff_cap_secs: String,
    /// `--receipt-query-attempts <u32>` (required).
    pub receipt_query_attempts: String,
    /// `--request-timeout-secs <u64>` (optional).
    pub request_timeout_secs: Option<String>,
    /// `--ttl-secs <u64>` (optional).
    pub ttl_secs: Option<String>,
    /// Whether `--force` was supplied (optional).
    pub force: bool,
}

/// Value flags accepted in `--write-config` mode.
#[cfg(feature = "offline-test-raw-hashes")]
const WRITE_CONFIG_VALUE_FLAGS: &[&str] = &[
    "--output",
    "--network",
    "--walletd-endpoint",
    "--indexer-endpoint",
    "--account-reference",
    "--fee-component",
    "--seal-signer-kind",
    "--seal-signer-id",
    "--max-fee",
    "--manifest-hash",
    "--archive-hash",
    "--snapshot-path",
    "--evidence-path",
    "--backoff-base-secs",
    "--backoff-cap-secs",
    "--receipt-query-attempts",
    "--request-timeout-secs",
    "--ttl-secs",
];

/// Required value flags in `--write-config` mode (must each appear exactly
/// once).
#[cfg(feature = "offline-test-raw-hashes")]
const WRITE_CONFIG_REQUIRED_FLAGS: &[&str] = &[
    "--output",
    "--network",
    "--walletd-endpoint",
    "--indexer-endpoint",
    "--account-reference",
    "--fee-component",
    "--seal-signer-kind",
    "--seal-signer-id",
    "--max-fee",
    "--manifest-hash",
    "--archive-hash",
    "--snapshot-path",
    "--evidence-path",
    "--backoff-base-secs",
    "--backoff-cap-secs",
    "--receipt-query-attempts",
];

const MODE_WRITE_CONFIG: &str = "--write-config";
const MODE_VERIFY_EVIDENCE: &str = "--verify-evidence";
const MODE_INSPECT_SNAPSHOT: &str = "--inspect-snapshot";

const LIFECYCLE_VALUE_FLAGS: &[&str] = &["--config", "--auth-env", "--archive"];
const LIFECYCLE_BARE_FLAGS: &[&str] = &["--approve", "--reject", "--dry-run"];

/// Parses the CLI argument set into a [`CliMode`].
///
/// This is the single entry point used by the binary. It performs mode
/// detection, conflict rejection, duplicate detection, and missing-value
/// detection before any file or transport activity.
///
/// # Errors
///
/// Returns the stable `ANCHOR_APP_CONFIGURATION_FAILURE` code string if the
/// argument set is contradictory, contains an unknown flag, has a duplicate
/// value flag, has a duplicate mode flag, has conflicting modes, or is missing
/// a required value.
pub fn parse(args: &[String]) -> Result<CliMode, String> {
    // --- Mode detection (single pass, no I/O) ---
    let write_config_count = args.iter().filter(|a| *a == MODE_WRITE_CONFIG).count();
    let verify_evidence_count = args.iter().filter(|a| *a == MODE_VERIFY_EVIDENCE).count();
    let inspect_snapshot_count = args.iter().filter(|a| *a == MODE_INSPECT_SNAPSHOT).count();

    if write_config_count > 1 || verify_evidence_count > 1 || inspect_snapshot_count > 1 {
        return Err(CONFIG_FAILURE.to_owned());
    }

    let mode_count = (write_config_count > 0) as u8
        + (verify_evidence_count > 0) as u8
        + (inspect_snapshot_count > 0) as u8;

    if mode_count > 1 {
        return Err(CONFIG_FAILURE.to_owned());
    }

    if write_config_count == 1 {
        #[cfg(not(feature = "offline-test-raw-hashes"))]
        {
            return Err(CONFIG_FAILURE.to_owned());
        }
        #[cfg(feature = "offline-test-raw-hashes")]
        return parse_write_config(args);
    }
    if verify_evidence_count == 1 {
        return parse_single_path_mode(args, MODE_VERIFY_EVIDENCE)
            .map(|path| CliMode::VerifyEvidence { path });
    }
    if inspect_snapshot_count == 1 {
        return parse_single_path_mode(args, MODE_INSPECT_SNAPSHOT)
            .map(|path| CliMode::InspectSnapshot { path });
    }

    // --- Lifecycle mode (default) ---
    parse_lifecycle(args)
}

/// Validates the CLI argument set before any config loading or lifecycle
/// advancement.
///
/// Rejects:
/// * `--approve` and `--reject` supplied together (contradictory decision);
/// * any unknown argument (narrow parser hardening, no new framework).
///
/// Duplicate `--approve` (or `--reject`) is deterministic: `any` resolves to
/// `Approve` (or `Reject`), matching the existing single-flag behavior. This
/// is the documented chosen behavior for duplicates.
///
/// # Errors
///
/// Returns the stable `ConfigurationFailure` code string if the argument set
/// is contradictory or contains an unknown flag.
pub fn validate_args(args: &[String]) -> Result<(), String> {
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");

    // Contradictory decision flags: approval must never win merely because it
    // is checked first.
    if approve && reject {
        return Err(MachineReportCode::ConfigurationFailure.as_str().to_owned());
    }

    // Unknown arguments: the parser recognises only the known flags. Value
    // flags consume the following argument as their value, so it is not
    // checked as a bare flag.
    let known_value_flags = LIFECYCLE_VALUE_FLAGS;
    let known_bare_flags = LIFECYCLE_BARE_FLAGS;

    let mut i = 1; // Skip the program name.
    while i < args.len() {
        let arg = &args[i];
        if known_value_flags.contains(&arg.as_str()) {
            // Consume the next argument as the value. If no value follows,
            // find_flag_value will return None and the config check will fail
            // later; here we just skip past the value position.
            i += 2;
        } else if known_bare_flags.contains(&arg.as_str()) {
            i += 1;
        } else {
            return Err(MachineReportCode::ConfigurationFailure.as_str().to_owned());
        }
    }

    Ok(())
}

/// Finds the value following a `--flag value` pair in the argument list.
pub fn find_flag_value(args: &[String], flag: &str) -> Option<String> {
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if arg == flag {
            return iter.next().cloned();
        }
    }
    None
}

// -----------------------------------------------------------------------
// Internal parsers
// -----------------------------------------------------------------------

fn parse_lifecycle(args: &[String]) -> Result<CliMode, String> {
    validate_args(args)?;

    let config_path = find_flag_value(args, "--config");
    let auth_env = find_flag_value(args, "--auth-env");
    let archive_path = find_flag_value(args, "--archive");
    let approve = args.iter().any(|a| a == "--approve");
    let reject = args.iter().any(|a| a == "--reject");
    let dry_run = args.iter().any(|a| a == "--dry-run");

    Ok(CliMode::Lifecycle(LifecycleArgs {
        config_path,
        auth_env,
        archive_path,
        approve,
        reject,
        dry_run,
    }))
}

#[cfg(feature = "offline-test-raw-hashes")]
fn parse_write_config(args: &[String]) -> Result<CliMode, String> {
    let mut values: Vec<(usize, String)> = Vec::new(); // (flag_index, value)
    let mut force = false;

    let mut i = 1; // Skip program name.
    while i < args.len() {
        let arg = &args[i];
        if arg == MODE_WRITE_CONFIG {
            i += 1;
            continue;
        }
        if arg == "--force" {
            force = true;
            i += 1;
            continue;
        }
        if WRITE_CONFIG_VALUE_FLAGS.contains(&arg.as_str()) {
            // Consume the next argument as the value.
            if i + 1 >= args.len() {
                return Err(CONFIG_FAILURE.to_owned());
            }
            let value = &args[i + 1];
            // Reject a value that looks like a flag. This prevents a missing
            // value from being masked by the next flag (e.g. `--output
            // --force` would otherwise treat `--force` as the output path).
            if value.starts_with("--") {
                return Err(CONFIG_FAILURE.to_owned());
            }
            // Detect duplicates: the same value flag appearing more than once.
            if values.iter().any(|(idx, _)| args[*idx] == *arg) {
                return Err(CONFIG_FAILURE.to_owned());
            }
            values.push((i, value.clone()));
            i += 2;
            continue;
        }
        // Unknown flag in write-config mode.
        return Err(CONFIG_FAILURE.to_owned());
    }

    // Extract required and optional values.
    let get = |flag: &str| -> Option<String> {
        values
            .iter()
            .find(|(idx, _)| args[*idx] == flag)
            .map(|(_, v)| v.clone())
    };

    for required in WRITE_CONFIG_REQUIRED_FLAGS {
        if get(required).is_none() {
            return Err(CONFIG_FAILURE.to_owned());
        }
    }

    Ok(CliMode::WriteConfig(Box::new(WriteConfigArgs {
        output: get("--output").unwrap_or_default(),
        network: get("--network").unwrap_or_default(),
        walletd_endpoint: get("--walletd-endpoint").unwrap_or_default(),
        indexer_endpoint: get("--indexer-endpoint").unwrap_or_default(),
        account_reference: get("--account-reference").unwrap_or_default(),
        fee_component: get("--fee-component").unwrap_or_default(),
        seal_signer_kind: get("--seal-signer-kind").unwrap_or_default(),
        seal_signer_id: get("--seal-signer-id").unwrap_or_default(),
        max_fee: get("--max-fee").unwrap_or_default(),
        manifest_hash: get("--manifest-hash").unwrap_or_default(),
        archive_hash: get("--archive-hash").unwrap_or_default(),
        snapshot_path: get("--snapshot-path").unwrap_or_default(),
        evidence_path: get("--evidence-path").unwrap_or_default(),
        backoff_base_secs: get("--backoff-base-secs").unwrap_or_default(),
        backoff_cap_secs: get("--backoff-cap-secs").unwrap_or_default(),
        receipt_query_attempts: get("--receipt-query-attempts").unwrap_or_default(),
        request_timeout_secs: get("--request-timeout-secs"),
        ttl_secs: get("--ttl-secs"),
        force,
    })))
}

fn parse_single_path_mode(args: &[String], mode_flag: &str) -> Result<String, String> {
    let mut path: Option<String> = None;
    let mut i = 1; // Skip program name.
    while i < args.len() {
        let arg = &args[i];
        if arg == mode_flag {
            if i + 1 >= args.len() {
                return Err(CONFIG_FAILURE.to_owned());
            }
            // Reject a path that looks like a flag.
            if args[i + 1].starts_with("--") {
                return Err(CONFIG_FAILURE.to_owned());
            }
            if path.is_some() {
                return Err(CONFIG_FAILURE.to_owned());
            }
            path = Some(args[i + 1].clone());
            i += 2;
            continue;
        }
        // Any other flag is rejected in single-path mode.
        return Err(CONFIG_FAILURE.to_owned());
    }
    path.ok_or_else(|| CONFIG_FAILURE.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prog() -> String {
        "tari-cc-private-ballot-anchor".to_owned()
    }

    #[test]
    fn lifecycle_no_flags_parses() {
        let args = vec![prog()];
        let mode = parse(&args).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert!(matches!(mode, CliMode::Lifecycle(_)));
    }

    #[cfg(feature = "offline-test-raw-hashes")]
    #[test]
    fn write_config_mode_detected() {
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
        let mode = parse(&args).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert!(matches!(mode, CliMode::WriteConfig(_)));
    }

    #[test]
    fn conflicting_modes_rejected() {
        let args = vec![
            prog(),
            "--write-config".to_owned(),
            "--verify-evidence".to_owned(),
            "p".to_owned(),
        ];
        assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
    }

    #[test]
    fn duplicate_write_config_mode_rejected() {
        let args = vec![
            prog(),
            "--write-config".to_owned(),
            "--write-config".to_owned(),
        ];
        assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
    }

    #[test]
    fn write_config_with_approve_rejected() {
        let args = vec![prog(), "--write-config".to_owned(), "--approve".to_owned()];
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
    fn duplicate_value_flag_in_write_config_rejected() {
        let mut args = vec![prog(), "--write-config".to_owned()];
        // Provide all required flags, then duplicate --network.
        let base = [
            ("--output", "C:/o"),
            ("--network", "esmeralda"),
            ("--walletd-endpoint", "http://h:1"),
            ("--indexer-endpoint", "http://h:2"),
            ("--account-reference", "a"),
            ("--fee-component", "component_11"),
            ("--seal-signer-kind", "account"),
            ("--seal-signer-id", "0"),
            ("--max-fee", "1"),
            ("--manifest-hash", &"1".repeat(64)),
            ("--archive-hash", &"2".repeat(64)),
            ("--snapshot-path", "C:/s"),
            ("--evidence-path", "C:/e"),
            ("--backoff-base-secs", "1"),
            ("--backoff-cap-secs", "2"),
            ("--receipt-query-attempts", "8"),
        ];
        for (f, v) in base {
            args.push(f.to_owned());
            args.push(v.to_owned());
        }
        args.push("--network".to_owned());
        args.push("igor".to_owned());
        assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
    }

    #[test]
    fn missing_required_flag_in_write_config_rejected() {
        let args = vec![
            prog(),
            "--write-config".to_owned(),
            "--network".to_owned(),
            "esmeralda".to_owned(),
        ];
        assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
    }

    #[test]
    fn missing_value_at_end_rejected() {
        let args = vec![prog(), "--write-config".to_owned(), "--output".to_owned()];
        assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
    }

    #[test]
    fn verify_evidence_missing_path_rejected() {
        let args = vec![prog(), "--verify-evidence".to_owned()];
        assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
    }

    #[test]
    fn unknown_arg_in_lifecycle_rejected() {
        let args = vec![prog(), "--bogus".to_owned()];
        assert_eq!(parse(&args), Err(CONFIG_FAILURE.to_owned()));
    }
}
