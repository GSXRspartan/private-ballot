//! Narrow CLI argument validation (Slice 4A10 repair M-1).
//!
//! This module holds the manual argument parser's validation logic so it can
//! be unit- and integration-tested without invoking the binary. It introduces
//! no CLI framework and performs no I/O.

use crate::report::MachineReportCode;

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
    let known_value_flags = ["--config", "--auth-env"];
    let known_bare_flags = ["--approve", "--reject", "--dry-run"];

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
