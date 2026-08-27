//! App-owned durable hand-off inbox for privately-accepted ballot packages.
//!
//! The controlled Tor intake process runs in its own OS process with its own
//! in-memory [`GuiElectionSessionV1`]. A ballot it accepts over Tor therefore
//! never reaches the organizer GUI's authoritative durable election workspace
//! on its own. This module is the smallest safe bridge: the intake process
//! **appends the exact canonical ballot-package bytes** it accepted into an
//! app-owned, election-scoped inbox directory, and the organizer GUI later
//! **ingests** those packages through the SAME
//! [`GuiElectionSessionV1::intake_ballot_package_bytes`] boundary used for a
//! normal offline ballot, then persists the resulting session as a new durable
//! workspace revision.
//!
//! What crosses the inbox is only the canonical ballot-package bytes — the same
//! public data the archive already contains. No network metadata (voter IP, Tor
//! circuit, request time, ingress order), no credential/passphrase/member index,
//! no private proof witness, and no HPKE secret material is ever written here.
//!
//! Duplicate protection is preserved end to end:
//!
//!   * the inbox is **content-addressed** by the ballot-package digest, so an
//!     exact-retry of the same accepted envelope maps to the same file and is a
//!     durable no-op (never a second file);
//!   * ingest runs every package back through the election-scoped first-valid
//!     nullifier ledger, so a *different* ballot re-using the same credential
//!     nullifier is still rejected and never inflates the accepted count.
//!
//! Path safety mirrors [`crate::workspace`]: the inbox root is a fixed
//! backend-controlled directory below the app-data root, the election
//! sub-directory name is derived from the (validated) 64-hex manifest hash, and
//! every directory/file is confirmed to be a real, non-symlink, non-reparse
//! entry before it is read or written. No path component is ever taken from
//! remote (envelope) input.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashDomain, hash_domain_separated};

use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::hex::to_lower_hex;
use crate::session::GuiElectionSessionV1;
use crate::workspace::MAX_BALLOT_PACKAGE_BYTES_V1;

/// Backend-controlled directory name below the app-data root.
pub const PRIVATE_INTAKE_INBOX_DIRECTORY_NAME: &str = "private-intake-inbox";

/// Suffix of one accepted-package file inside an election inbox.
const INBOX_PACKAGE_FILE_SUFFIX: &str = ".package";

/// Length in characters of a canonical lowercase Blake3 digest hex string.
const DIGEST_HEX_BYTES: usize = 64;

/// Maximum accepted-package files considered during one bounded ingest pass.
/// The election-scoped nullifier ledger already caps *accepted* ballots at the
/// registry size; this is a defensive bound on files present in one directory.
pub const MAX_PRIVATE_INTAKE_INBOX_FILES_V1: usize =
    crate::workspace::MAX_WORKSPACE_PACKAGE_COUNT_V1;

/// Public, organizer-safe summary of one durable inbox ingest pass. It reports
/// only non-secret aggregate counts — never plaintext, proof, nullifier,
/// credential, or any client/network identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct GuiPrivateIntakeSyncSummaryV1 {
    /// Total valid accepted-package files discovered in the inbox this pass.
    pub discovered: usize,
    /// Packages that were newly accepted into the session this pass.
    pub newly_accepted: usize,
    /// Packages already accounted for (duplicate election nullifier), including
    /// exact retries and any package already ingested in a previous pass.
    pub duplicates: usize,
    /// Packages the session rejected for any other reason (proof/binding).
    pub rejected: usize,
}

/// Returns the app-owned, election-scoped inbox directory for a manifest hash.
///
/// # Errors
///
/// Returns a bounded error if `manifest_hash_hex` is not a canonical 64-char
/// lowercase hex string (so no remote/arbitrary value can influence the path).
pub fn private_intake_inbox_directory_v1(
    app_data_root: &Path,
    manifest_hash_hex: &str,
) -> Result<PathBuf, GuiCoreError> {
    if manifest_hash_hex.len() != DIGEST_HEX_BYTES
        || !manifest_hash_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GuiCoreError::new(
            "GUI_PRIVATE_INTAKE_INBOX_INVALID_ELECTION",
            GuiErrorCategory::InvalidInput,
            Some("private-intake-inbox"),
            "the election manifest hash is not a canonical lowercase hex digest",
        ));
    }
    Ok(app_data_root
        .join(PRIVATE_INTAKE_INBOX_DIRECTORY_NAME)
        .join(format!("election-{manifest_hash_hex}")))
}

/// Ensures and returns the app-owned inbox directory for one election.
///
/// # Errors
///
/// Returns a bounded error if any component is a symlink/reparse point, is not
/// a directory, or cannot be created.
pub fn ensure_private_intake_inbox_directory_v1(
    app_data_root: &Path,
    manifest_hash_hex: &str,
) -> Result<PathBuf, GuiCoreError> {
    let inbox_root = app_data_root.join(PRIVATE_INTAKE_INBOX_DIRECTORY_NAME);
    ensure_direct_directory(&inbox_root)?;
    let election_dir = private_intake_inbox_directory_v1(app_data_root, manifest_hash_hex)?;
    ensure_direct_directory(&election_dir)?;
    Ok(election_dir)
}

/// Computes the canonical ballot-package digest hex used for content-addressing.
#[must_use]
pub fn ballot_package_digest_hex_v1(package_bytes: &[u8]) -> String {
    let digest = hash_domain_separated(
        &Blake3HashProviderV1,
        HashDomain::BallotPackageV1,
        package_bytes,
    );
    to_lower_hex(&digest)
}

/// Appends one accepted canonical ballot package to an election inbox.
///
/// The file is named by the package digest, so an exact retry of the same
/// accepted envelope maps to the same file: this returns `Ok(false)` (a durable
/// no-op) rather than creating a second file, and `Ok(true)` only when a new
/// file was durably written. The write is atomic (`create_new` + fsync) so a
/// partially written file can never be observed as a valid package.
///
/// Only the exact canonical package bytes are written; no timestamp, ordering,
/// or any network/credential metadata is stored in the file or its name.
///
/// # Errors
///
/// Returns a bounded error if `inbox_dir` is unsafe, the package exceeds the
/// canonical size bound, or the file cannot be written.
pub fn append_accepted_ballot_package_to_inbox_v1(
    inbox_dir: &Path,
    package_bytes: &[u8],
) -> Result<bool, GuiCoreError> {
    if package_bytes.len() > MAX_BALLOT_PACKAGE_BYTES_V1 {
        return Err(GuiCoreError::new(
            "GUI_PRIVATE_INTAKE_INBOX_PACKAGE_TOO_LARGE",
            GuiErrorCategory::InvalidInput,
            Some("private-intake-inbox"),
            "the accepted ballot package exceeds the canonical size limit",
        ));
    }
    ensure_direct_directory(inbox_dir)?;
    let digest_hex = ballot_package_digest_hex_v1(package_bytes);
    let final_path = inbox_dir.join(format!("{digest_hex}{INBOX_PACKAGE_FILE_SUFFIX}"));

    // Content-addressed dedup: if the exact package is already present, this is
    // an idempotent no-op (exact-retry recovery), never a second file.
    match fs::symlink_metadata(&final_path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || metadata_is_reparse_point(&metadata)
                || !metadata.is_file()
            {
                return Err(unsafe_inbox_path());
            }
            verify_existing_inbox_package(&final_path, package_bytes)?;
            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(GuiCoreError::io_failure("private-intake-inbox")),
    }

    let tmp_path = inbox_dir.join(format!("{digest_hex}{INBOX_PACKAGE_FILE_SUFFIX}.tmp"));
    let _ = fs::remove_file(&tmp_path);
    write_create_new_sync(&tmp_path, package_bytes)?;
    match fs::rename(&tmp_path, &final_path) {
        Ok(()) => {
            sync_directory_best_effort(inbox_dir);
            verify_existing_inbox_package(&final_path, package_bytes)?;
            Ok(true)
        }
        // A concurrent writer that won the race already produced the exact file;
        // treat as an idempotent no-op after cleaning up our temp.
        Err(_) if final_path.is_file() => {
            let _ = fs::remove_file(&tmp_path);
            verify_existing_inbox_package(&final_path, package_bytes)?;
            Ok(false)
        }
        Err(_) => {
            let _ = fs::remove_file(&tmp_path);
            Err(GuiCoreError::io_failure("private-intake-inbox"))
        }
    }
}

fn verify_existing_inbox_package(path: &Path, expected_bytes: &[u8]) -> Result<(), GuiCoreError> {
    let existing = read_bounded_package_file(path)?;
    if existing != expected_bytes {
        return Err(GuiCoreError::new(
            "GUI_PRIVATE_INTAKE_INBOX_EXISTING_PACKAGE_MISMATCH",
            GuiErrorCategory::ArchiveIntegrity,
            Some("private-intake-inbox"),
            "an existing private-intake package file does not match the accepted ballot package",
        ));
    }
    Ok(())
}

/// Ingests every accepted-package file in an election inbox into `session`.
///
/// Each package is fed through the SAME
/// [`GuiElectionSessionV1::intake_ballot_package_bytes`] boundary a normal
/// offline ballot uses: full decode, election binding, proof verification, and
/// first-valid-nullifier acceptance. No validation is duplicated here. The pass
/// is idempotent — a package already accepted in a prior pass is rejected as a
/// duplicate nullifier and never re-counted — so it is safe to call repeatedly
/// (e.g. after every voter submission and again on resume).
///
/// The session is NOT persisted here; the caller writes the durable workspace
/// revision through the existing [`crate::workspace`] boundary after a
/// successful ingest, so the accepted Tor ballot survives restart exactly like
/// an offline one.
///
/// # Errors
///
/// Returns a bounded error if the inbox path is unsafe, a file is not a
/// canonical `<digest>.package`, a file's content does not match its digest
/// name, or the session cannot reconcile (only `VERIFIED`/`FINALIZED`, whose
/// results are sealed, refuse; `CLOSED` still drains already-accepted work).
pub fn ingest_private_intake_inbox_into_session_v1(
    inbox_dir: &Path,
    session: &mut GuiElectionSessionV1,
) -> Result<GuiPrivateIntakeSyncSummaryV1, GuiCoreError> {
    // A missing inbox is a valid "nothing to sync yet" state, not an error.
    match fs::symlink_metadata(inbox_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_inbox_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GuiPrivateIntakeSyncSummaryV1::default());
        }
        Err(_) => return Err(GuiCoreError::io_failure("private-intake-inbox")),
    }

    // Collect and sort the package digests for a deterministic ingest order that
    // does not depend on filesystem enumeration order (and therefore leaks no
    // arrival order). Content-addressed names sort lexicographically.
    let mut digests: Vec<String> = Vec::new();
    let mut inspected = 0_usize;
    for entry in
        fs::read_dir(inbox_dir).map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?
    {
        let entry = entry.map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(digest_hex) = parse_inbox_package_filename(&name) else {
            // Ignore unrelated files (e.g. a leftover .tmp); never fail the whole
            // pass on a stray entry.
            continue;
        };
        inspected = inspected.checked_add(1).ok_or_else(too_many_inbox_files)?;
        if inspected > MAX_PRIVATE_INTAKE_INBOX_FILES_V1 {
            return Err(too_many_inbox_files());
        }
        digests.push(digest_hex.to_owned());
    }
    digests.sort();

    let mut summary = GuiPrivateIntakeSyncSummaryV1::default();
    for digest_hex in digests {
        let path = inbox_dir.join(format!("{digest_hex}{INBOX_PACKAGE_FILE_SUFFIX}"));
        let package_bytes = read_bounded_package_file(&path)?;
        // Integrity: the file content MUST hash to the digest in its name. A
        // mismatch means on-disk tampering/corruption; fail closed.
        if ballot_package_digest_hex_v1(&package_bytes) != digest_hex {
            return Err(GuiCoreError::new(
                "GUI_PRIVATE_INTAKE_INBOX_DIGEST_MISMATCH",
                GuiErrorCategory::ArchiveIntegrity,
                Some("private-intake-inbox"),
                "an inbox package file does not match its content-address digest",
            ));
        }
        summary.discovered = summary.discovered.saturating_add(1);
        // Reconciliation entry point: every inbox file was already accepted by
        // the collector (and receipted) while the election was OPEN, so the
        // durable hand-off may drain during CLOSED. Identical validation and
        // ledger semantics; VERIFIED/FINALIZED refuse outright.
        let result = session.reconcile_accepted_package_bytes_from_inbox(&package_bytes)?;
        if result.accepted {
            summary.newly_accepted = summary.newly_accepted.saturating_add(1);
        } else if matches!(result.category, crate::intake::GuiIntakeCategory::Duplicate) {
            summary.duplicates = summary.duplicates.saturating_add(1);
        } else {
            summary.rejected = summary.rejected.saturating_add(1);
        }
    }
    Ok(summary)
}

fn parse_inbox_package_filename(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(INBOX_PACKAGE_FILE_SUFFIX)?;
    if stem.len() != DIGEST_HEX_BYTES
        || !stem
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some(stem)
}

fn read_bounded_package_file(path: &Path) -> Result<Vec<u8>, GuiCoreError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found("private-intake-inbox")
        } else {
            GuiCoreError::io_failure("private-intake-inbox")
        }
    })?;
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(unsafe_inbox_path());
    }
    if metadata.len() > MAX_BALLOT_PACKAGE_BYTES_V1 as u64 {
        return Err(GuiCoreError::new(
            "GUI_PRIVATE_INTAKE_INBOX_PACKAGE_TOO_LARGE",
            GuiErrorCategory::InvalidInput,
            Some("private-intake-inbox"),
            "an inbox package file exceeds the canonical size limit",
        ));
    }
    fs::read(path).map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))
}

pub(crate) fn ensure_direct_directory(path: &Path) -> Result<(), GuiCoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_inbox_path());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?;
            if !metadata.is_dir() || metadata_is_reparse_point(&metadata) {
                return Err(unsafe_inbox_path());
            }
            Ok(())
        }
        Err(_) => Err(GuiCoreError::io_failure("private-intake-inbox")),
    }
}

pub(crate) fn write_create_new_sync(path: &Path, bytes: &[u8]) -> Result<(), GuiCoreError> {
    let mut created = false;
    let result = (|| -> Result<(), GuiCoreError> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?;
        created = true;
        file.write_all(bytes)
            .map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?;
        file.flush()
            .map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure("private-intake-inbox"))?;
        Ok(())
    })();
    if result.is_err() && created {
        let _ = fs::remove_file(path);
    }
    result
}

pub(crate) fn sync_directory_best_effort(path: &Path) {
    if let Ok(file) = File::open(path) {
        let _ = file.sync_all();
    }
}

fn unsafe_inbox_path() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_PRIVATE_INTAKE_INBOX_UNSAFE_PATH",
        GuiErrorCategory::InvalidInput,
        Some("private-intake-inbox"),
        "refusing to use a private-intake inbox entry that is not an app-owned file/directory",
    )
}

fn too_many_inbox_files() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_PRIVATE_INTAKE_INBOX_TOO_MANY_FILES",
        GuiErrorCategory::InvalidInput,
        Some("private-intake-inbox"),
        "the private-intake inbox contains more package files than allowed",
    )
}

#[cfg(windows)]
pub(crate) fn metadata_is_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    // FILE_ATTRIBUTE_REPARSE_POINT (0x400): junctions/mount points that could
    // redirect a read or write outside app-owned storage.
    (metadata.file_attributes() & 0x400) != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}
