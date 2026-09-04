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
/// during auto-detection. Deliberately empty in public source: no developer
/// machine path or unverified default is baked in. Operators must select their
/// installed `tor.exe` explicitly the first time; the selection is remembered
/// in the app's stored config, not here. Any new default entry must be a
/// concrete absolute path deliberately reviewed for public source (never a
/// directory to scan, never a PATH-relative name, never a per-user path).
pub const TOR_EXECUTABLE_ALLOWLIST_V1: &[&str] = &[];

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
    // On Unix, verify the file is marked executable. Windows uses the .exe
    // extension convention for executability; there is no equivalent bit to
    // check. Without this, an operator on Linux could point at a plain data
    // file and only discover the mistake at spawn time.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(CommandError::new(
                "GUI_TOR_EXE_NOT_EXECUTABLE",
                "FILE_IO",
                "the tor executable is not marked executable",
            ));
        }
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
            assert!(
                Path::new(entry).is_absolute(),
                "allowlist entry must be absolute: {entry}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn unix_non_executable_regular_file_is_rejected() {
        use std::io::Write;
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "private-ballot-tor-support-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let file = dir.join("not-an-executable");
        std::fs::File::create(&file)
            .and_then(|mut f| f.write_all(b"#!/bin/false\n"))
            .expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let error = validate_tor_exe(&file).expect_err("must reject non-executable");
        assert_eq!(error.code, "GUI_TOR_EXE_NOT_EXECUTABLE");
        // Cleanup.
        let _ = std::fs::remove_file(&file);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn public_source_has_no_developer_machine_tor_path_in_allowlist() {
        // Public source ships with an empty allowlist: no developer machine
        // path or unverified default is baked into the binary. Operators are
        // asked once to select `tor.exe`; the app then remembers that choice
        // in stored config.
        assert!(
            TOR_EXECUTABLE_ALLOWLIST_V1.is_empty(),
            "public source Tor allowlist must be empty; got {:?}",
            TOR_EXECUTABLE_ALLOWLIST_V1
        );
    }
}
