//! Full offline archive replay verifier.
//!
//! Promotes the complete archive replay composition proven in the CLI
//! integration tests (`offline_archive_replay_gate`,
//! `real_triptych_offline_archive_replay`) into a public application-facing
//! function. The verifier trusts nothing archived: it re-derives every
//! commitment, re-verifies every file digest, re-runs every proof through the
//! existing ingestion pipeline, reproduces the transcript and tally, and
//! rebuilds the archive manifest for hash comparison.
//!
//! The offline archive is authoritative. This verifier performs no network,
//! walletd, or indexer access and never consults organizer state.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ARCHIVE_SIGNATURE_PATH_PREFIX, ArchiveFileCatalogV1,
    ArchiveFileEntryV1, ArchiveManifestV1, ArchivePathV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, MAX_CANONICAL_OBJECT_BYTES};

use crate::archive_writer::SUBMISSIONS_ARCHIVE_DIR;
use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::GuiCoreError;
use crate::session::GuiElectionSessionV1;
use crate::tally::GuiTallySummaryV1;

/// Verification stage: archive manifest presence, decode, and hash provider.
pub const STAGE_ARCHIVE_MANIFEST: &str = "ARCHIVE_MANIFEST";
/// Verification stage: catalog membership and per-file digest checks.
pub const STAGE_CATALOG_FILES: &str = "CATALOG_FILES";
/// Verification stage: election artifact decode and cross-binding checks.
pub const STAGE_ELECTION_ARTIFACTS: &str = "ELECTION_ARTIFACTS";
/// Verification stage: deterministic ballot replay through proof verification.
pub const STAGE_BALLOT_REPLAY: &str = "BALLOT_REPLAY";
/// Verification stage: archive manifest rebuild and archive-hash comparison.
pub const STAGE_ARCHIVE_HASH: &str = "ARCHIVE_HASH";

/// One hash-covered content file's on-disk check.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiArchiveFileCheckV1 {
    /// Canonical archive-relative path.
    pub path: String,
    /// Whether the file is present on disk.
    pub present: bool,
    /// Whether the recorded digest matches the recomputed digest.
    pub digest_ok: bool,
}

/// The structured result of one full offline archive verification.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiArchiveVerificationV1 {
    /// True only when every stage passed completely.
    pub verified: bool,
    /// The first failing stage, if any.
    pub failure_stage: Option<&'static str>,
    /// The stable machine code of the first failure, if any.
    pub failure_code: Option<String>,
    /// Number of hash-covered content files in the catalog.
    pub file_count: usize,
    /// Per-file presence and digest results in canonical path order.
    pub files: Vec<GuiArchiveFileCheckV1>,
    /// Number of archived ballot packages.
    pub ballot_package_count: usize,
    /// Number of replayed accepted decisions.
    pub accepted_count: usize,
    /// Number of replayed rejected decisions.
    pub rejected_count: usize,
    /// Whether the replayed transcript decides every submission.
    pub transcript_complete: bool,
    /// Recomputed deterministic tally, when replay completed.
    pub tally: Option<GuiTallySummaryV1>,
    /// The archived manifest's own hash, lowercase hex, when decodable.
    pub archive_hash_hex: Option<String>,
    /// The archive hash rebuilt from on-disk files, lowercase hex.
    pub recomputed_archive_hash_hex: Option<String>,
    /// Whether the rebuilt manifest and hash equal the archived ones.
    pub archive_hash_consistent: bool,
    /// The recomputed election manifest hash, lowercase hex.
    pub election_manifest_hash_hex: Option<String>,
}

impl GuiArchiveVerificationV1 {
    fn empty() -> Self {
        Self {
            verified: false,
            failure_stage: None,
            failure_code: None,
            file_count: 0,
            files: Vec::new(),
            ballot_package_count: 0,
            accepted_count: 0,
            rejected_count: 0,
            transcript_complete: false,
            tally: None,
            archive_hash_hex: None,
            recomputed_archive_hash_hex: None,
            archive_hash_consistent: false,
            election_manifest_hash_hex: None,
        }
    }

    fn fail(mut self, stage: &'static str, code: &str) -> Self {
        self.verified = false;
        self.failure_stage = Some(stage);
        self.failure_code = Some(code.to_owned());
        self
    }
}

/// Verifies one complete offline archive directory.
///
/// Runs every gate of the strongest existing offline replay tests in order:
/// archive manifest, catalog membership and digests, election artifact
/// bindings, deterministic ballot replay (proof verification, duplicate
/// handling, transcript reproduction), tally reproduction, and archive-hash
/// rebuild comparison.
///
/// `verified` is true only when every stage passes. Integrity failures are
/// reported in the structured result; only filesystem-level impossibilities
/// (missing or non-directory target, unreadable files) return `Err`.
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] for filesystem-level failures only.
pub fn verify_archive_directory_v1(dir: &Path) -> Result<GuiArchiveVerificationV1, GuiCoreError> {
    let metadata = std::fs::symlink_metadata(dir).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found("archive-directory")
        } else {
            GuiCoreError::io_failure("archive-directory")
        }
    })?;
    if !metadata.is_dir() {
        return Err(GuiCoreError::io_failure("archive-directory"));
    }

    let provider = Blake3HashProviderV1;
    let mut result = GuiArchiveVerificationV1::empty();

    // Stage 1: archive manifest.
    let manifest_path = dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH);
    let manifest_bytes = match read_bounded(&manifest_path) {
        Ok(bytes) => bytes,
        Err(error) if error.code() == "GUI_FILE_NOT_FOUND" => {
            return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, "GUI_ARCHIVE_MISSING_FILE"));
        }
        Err(error) => return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, error.code())),
    };
    let archive_manifest = match ArchiveManifestV1::from_canonical_cbor(&manifest_bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, error.code().as_str()));
        }
    };
    if let Err(error) = archive_manifest.validate_hash_provider(&provider) {
        return Ok(result.fail(STAGE_ARCHIVE_MANIFEST, error.code().as_str()));
    }
    let archive_hash = archive_manifest
        .canonical_hash(&provider)
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;
    result.archive_hash_hex = Some(crate::hex::to_lower_hex(archive_hash.as_bytes()));
    result.file_count = archive_manifest.files().len();

    // Stage 2: catalog membership and per-file digests.
    let disk_files = enumerate_disk_files(dir)?;
    let catalog_paths: BTreeSet<String> = archive_manifest
        .files()
        .entries()
        .iter()
        .map(|entry| entry.path().as_str().to_owned())
        .collect();
    if let Some(_missing) = catalog_paths.difference(&disk_files).next() {
        for entry in archive_manifest.files().entries() {
            result.files.push(GuiArchiveFileCheckV1 {
                path: entry.path().as_str().to_owned(),
                present: disk_files.contains(entry.path().as_str()),
                digest_ok: false,
            });
        }
        return Ok(result.fail(STAGE_CATALOG_FILES, "GUI_ARCHIVE_MISSING_FILE"));
    }
    if disk_files.difference(&catalog_paths).next().is_some() {
        return Ok(result.fail(STAGE_CATALOG_FILES, "GUI_ARCHIVE_UNEXPECTED_FILE"));
    }

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in archive_manifest.files().entries() {
        let path = entry.path().as_str();
        let bytes = read_bounded(&dir.join(path))?;
        let digest_ok = entry.verify_bytes(&provider, &bytes).is_ok();
        result.files.push(GuiArchiveFileCheckV1 {
            path: path.to_owned(),
            present: true,
            digest_ok,
        });
        if !digest_ok {
            return Ok(result.fail(STAGE_CATALOG_FILES, "ARCHIVE_FILE_DIGEST_MISMATCH"));
        }
        files.insert(path.to_owned(), bytes);
    }

    // Stage 3: election artifacts and cross-bindings.
    for path in [
        crate::archive_writer::ELECTION_MANIFEST_ARCHIVE_PATH,
        crate::archive_writer::VOTER_REGISTRY_ARCHIVE_PATH,
        crate::archive_writer::CANDIDATE_SET_ARCHIVE_PATH,
    ] {
        if !catalog_paths.contains(path) {
            return Ok(result.fail(STAGE_ELECTION_ARTIFACTS, "GUI_ARCHIVE_MISSING_ARTIFACT"));
        }
    }
    let artifacts = match GuiElectionArtifactsV1::from_bytes(
        &files[crate::archive_writer::ELECTION_MANIFEST_ARCHIVE_PATH],
        &files[crate::archive_writer::VOTER_REGISTRY_ARCHIVE_PATH],
        &files[crate::archive_writer::CANDIDATE_SET_ARCHIVE_PATH],
    ) {
        Ok(artifacts) => artifacts,
        Err(error) => return Ok(result.fail(STAGE_ELECTION_ARTIFACTS, error.code())),
    };
    result.election_manifest_hash_hex = Some(crate::hex::to_lower_hex(
        artifacts.manifest_hash().as_bytes(),
    ));

    // Stage 4: deterministic ballot replay through the ingestion pipeline.
    let submission_paths: Vec<String> = catalog_paths
        .iter()
        .filter(|path| path.starts_with(&format!("{SUBMISSIONS_ARCHIVE_DIR}/")))
        .cloned()
        .collect();
    result.ballot_package_count = submission_paths.len();

    let mut session = match GuiElectionSessionV1::new(artifacts) {
        Ok(session) => session,
        Err(error) => return Ok(result.fail(STAGE_BALLOT_REPLAY, error.code())),
    };
    if let Err(error) = session.open() {
        return Ok(result.fail(STAGE_BALLOT_REPLAY, error.code()));
    }
    let mut replay_failed: Option<GuiCoreError> = None;
    for path in &submission_paths {
        let bytes = &files[path];
        if let Err(error) = session.intake_ballot(bytes) {
            replay_failed = Some(error);
            break;
        }
    }
    if let Some(error) = replay_failed {
        return Ok(result.fail(STAGE_BALLOT_REPLAY, error.code()));
    }
    if let Err(error) = session.transcript().validate_complete() {
        return Ok(result.fail(STAGE_BALLOT_REPLAY, error.code().as_str()));
    }
    result.transcript_complete = true;
    result.accepted_count = session.transcript().accepted_count();
    result.rejected_count = session.transcript().rejected_count();

    let tally = match session.direct_tally() {
        Ok(tally) => tally,
        Err(error) => return Ok(result.fail(STAGE_BALLOT_REPLAY, error.code())),
    };
    result.tally = Some(crate::tally::summarize_tally(
        &tally,
        session.artifacts().candidates(),
    ));

    // Stage 5: rebuild the archive manifest from disk and compare hashes.
    let rebuilt_entries = files
        .iter()
        .map(|(path, bytes)| {
            let archive_path = ArchivePathV1::new(path.clone())
                .map_err(|error| GuiCoreError::from_protocol(&error, "archive-catalog"))?;
            Ok(ArchiveFileEntryV1::for_bytes(
                archive_path,
                &provider,
                bytes,
            ))
        })
        .collect::<Result<Vec<_>, GuiCoreError>>()?;
    let rebuilt_catalog = ArchiveFileCatalogV1::new(rebuilt_entries)
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-catalog"))?;
    let rebuilt_manifest = ArchiveManifestV1::for_provider(
        session.artifacts().manifest_hash(),
        rebuilt_catalog,
        &provider,
    )
    .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;
    let recomputed_hash = rebuilt_manifest
        .canonical_hash(&provider)
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;
    result.recomputed_archive_hash_hex = Some(crate::hex::to_lower_hex(recomputed_hash.as_bytes()));
    result.archive_hash_consistent =
        rebuilt_manifest == archive_manifest && recomputed_hash == archive_hash;
    if !result.archive_hash_consistent {
        return Ok(result.fail(STAGE_ARCHIVE_HASH, "ARCHIVE_MANIFEST_HASH_MISMATCH"));
    }

    result.verified = true;
    Ok(result)
}

/// Reads one archive file with the protocol object size cap.
fn read_bounded(path: &Path) -> Result<Vec<u8>, GuiCoreError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            GuiCoreError::file_not_found("archive-file")
        } else {
            GuiCoreError::io_failure("archive-file")
        }
    })?;
    if !metadata.is_file() {
        return Err(GuiCoreError::io_failure("archive-file"));
    }
    if metadata.len() > MAX_CANONICAL_OBJECT_BYTES as u64 {
        return Err(GuiCoreError::new(
            "PROTOCOL_LIMIT_EXCEEDED",
            crate::error::GuiErrorCategory::InvalidInput,
            Some("archive-file"),
            "archive file exceeds the protocol object size limit",
        ));
    }
    std::fs::read(path).map_err(|_| GuiCoreError::io_failure("archive-file"))
}

/// Enumerates hash-covered candidate files as canonical archive-relative
/// paths (`/` separators), excluding the archive manifest itself and the
/// detached-signature prefix.
fn enumerate_disk_files(dir: &Path) -> Result<BTreeSet<String>, GuiCoreError> {
    let mut files = BTreeSet::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let entries = std::fs::read_dir(&current)
            .map_err(|_| GuiCoreError::io_failure("archive-directory"))?;
        for entry in entries {
            let entry = entry.map_err(|_| GuiCoreError::io_failure("archive-directory"))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|_| GuiCoreError::io_failure("archive-directory"))?;
            if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let relative = path
                .strip_prefix(dir)
                .map_err(|_| GuiCoreError::io_failure("archive-directory"))?;
            let mut canonical = String::new();
            for (index, component) in relative.components().enumerate() {
                if index > 0 {
                    canonical.push('/');
                }
                let std::path::Component::Normal(part) = component else {
                    return Err(GuiCoreError::io_failure("archive-directory"));
                };
                canonical.push_str(&part.to_string_lossy());
            }
            if canonical == ARCHIVE_MANIFEST_CANONICAL_PATH {
                continue;
            }
            if canonical.starts_with(ARCHIVE_SIGNATURE_PATH_PREFIX) {
                continue;
            }
            files.insert(canonical);
        }
    }
    Ok(files)
}
