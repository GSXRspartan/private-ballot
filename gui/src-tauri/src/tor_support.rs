//! Shared, feature-gated Tor executable discovery and validation for the
//! controlled managed-Tor test slice (organizer intake + voter submission).
//!
//! The near-one-click UX must not require a normal user to type an absolute
//! `tor.exe` path. This module provides a SMALL, explicit allowlist discovery
//! plus validation of an explicitly user-selected (and previously validated)
//! executable. It deliberately does NOT:
//!
//!   * scan the whole disk,
//!   * resolve `tor` from the process `PATH`,
//!   * download / install / update Tor,
//!   * invoke a shell or construct any command string.
//!
//! Discovery only ever *validates* candidate absolute paths that are either the
//! known validated Windows test installation or a path the user explicitly
//! selected in a native picker. Every resolved executable is re-validated
//! (absolute, real regular file, no symlink/reparse point, no control
//! characters) before it is ever spawned — the resolution here is a convenience,
//! never a trust boundary.

use std::path::{Path, PathBuf};

use crate::CommandError;

/// The SMALL explicit allowlist of well-known Tor executable locations probed
/// during auto-detection. The known validated Windows test installation is the
/// only default entry. New entries must be concrete absolute paths, never
/// directories to scan or PATH-relative names.
///
/// Kept intentionally tiny and Windows-first: this is the reviewed controlled
/// test surface. Portability is preserved structurally (the resolver logic is
/// OS-agnostic) without inventing unverified installation paths on other
/// platforms merely to claim cross-platform support.
pub const TOR_EXECUTABLE_ALLOWLIST_V1: &[&str] = &[r"C:\purr-tools\tor-expert\tor\tor.exe"];

/// Validates a candidate `tor.exe` path: absolute, exists, regular file, not a
/// symlink/reparse point, no control characters. This is the SAME validation
/// applied before any Tor process is spawned; discovery never relaxes it.
pub fn validate_tor_exe(path: &Path) -> Result<(), CommandError> {
    if !path.is_absolute() {
        return Err(CommandError::new(
            "GUI_TOR_EXE_PATH_NOT_ABSOLUTE",
            "INVALID_INPUT",
            "the tor.exe path must be absolute",
        ));
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| {
        CommandError::new("GUI_TOR_EXE_NOT_FOUND", "FILE_IO", "tor.exe was not found")
    })?;
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
    {
        return Err(CommandError::new(
            "GUI_TOR_EXE_NOT_REGULAR",
            "FILE_IO",
            "tor.exe must be a regular file (no symlinks/reparse points)",
        ));
    }
    if path
        .as_os_str()
        .to_string_lossy()
        .chars()
        .any(char::is_control)
    {
        return Err(CommandError::new(
            "GUI_TOR_EXE_PATH_CONTROL_CHAR",
            "INVALID_INPUT",
            "the tor.exe path must not contain control characters",
        ));
    }
    Ok(())
}

/// Resolves the Tor executable for a managed-Tor operation without any shell,
/// PATH resolution, or disk scan.
///
/// Resolution order (fail-closed):
///
///   1. an explicit user-selected / remembered path, if non-empty — it MUST
///      validate, otherwise the error is surfaced (we never silently fall back
///      to the allowlist when the user explicitly chose a path);
///   2. otherwise, the first entry of [`TOR_EXECUTABLE_ALLOWLIST_V1`] that
///      validates.
///
/// Returns `GUI_TOR_EXE_NOT_FOUND` when nothing validates. A found executable
/// is always the caller's to re-validate before spawning.
pub fn resolve_tor_executable(explicit: Option<&str>) -> Result<PathBuf, CommandError> {
    if let Some(raw) = explicit {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            validate_tor_exe(&path)?;
            return Ok(path);
        }
    }
    for candidate in TOR_EXECUTABLE_ALLOWLIST_V1 {
        let path = PathBuf::from(candidate);
        if validate_tor_exe(&path).is_ok() {
            return Ok(path);
        }
    }
    Err(CommandError::new(
        "GUI_TOR_EXE_NOT_FOUND",
        "FILE_IO",
        "no Tor executable was found; select a tor.exe to continue",
    ))
}

#[cfg(windows)]
pub fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    (metadata.file_attributes() & 0x400) != 0
}

#[cfg(not(windows))]
pub fn is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_missing_executable_fails_boundedly() {
        // No explicit path and (in CI) no allowlist hit → a bounded not-found.
        let resolved = resolve_tor_executable(Some("   "));
        // Either the allowlist path exists on this machine (Ok) or it does not
        // (bounded GUI_TOR_EXE_NOT_FOUND). Never a panic, never a shell.
        if let Err(error) = resolved {
            assert_eq!(error.code, "GUI_TOR_EXE_NOT_FOUND");
        }
    }

    #[test]
    fn explicit_relative_path_is_rejected_absolute_required() {
        let error = resolve_tor_executable(Some("tor.exe")).expect_err("relative must reject");
        assert_eq!(error.code, "GUI_TOR_EXE_PATH_NOT_ABSOLUTE");
    }

    #[test]
    fn explicit_nonexistent_absolute_path_reports_not_found_not_allowlist() {
        // An explicitly chosen path that does not exist must surface its own
        // error, never silently fall back to the allowlist.
        #[cfg(windows)]
        let bogus = r"C:\definitely\not\here\tor.exe";
        #[cfg(not(windows))]
        let bogus = "/definitely/not/here/tor";
        let error = resolve_tor_executable(Some(bogus)).expect_err("missing must reject");
        assert_eq!(error.code, "GUI_TOR_EXE_NOT_FOUND");
    }

    #[test]
    fn allowlist_is_small_and_absolute() {
        assert!(TOR_EXECUTABLE_ALLOWLIST_V1.len() <= 4);
        for entry in TOR_EXECUTABLE_ALLOWLIST_V1 {
            assert!(Path::new(entry).is_absolute(), "allowlist entry must be absolute: {entry}");
        }
    }

    #[test]
    fn known_validated_windows_test_install_is_in_allowlist() {
        assert!(
            TOR_EXECUTABLE_ALLOWLIST_V1
                .contains(&r"C:\purr-tools\tor-expert\tor\tor.exe")
        );
    }
}
