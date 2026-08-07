//! Archive-directory writer.
//!
//! Promotes the archive assembly pattern already proven in the CLI
//! integration tests into reusable project code. The writer emits exactly the
//! canonical artifacts the offline replay verifier consumes:
//!
//! * `election-manifest.cbor` — canonical election manifest;
//! * `candidate-set.cbor` — canonical candidate set;
//! * `voter-registry.cbor` — canonical frozen voter registry;
//! * `submissions/NNNNNNNN.cbor` — canonical ballot packages in intake order;
//! * `archive-manifest.cbor` — the archive manifest over the hash-covered
//!   catalog (never a catalog member itself).
//!
//! The verification transcript is *derived* during replay, exactly as the
//! existing protocol intends; it is never serialized. No new archive content
//! is invented.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use tari_cc_private_ballot_archive::{
    ARCHIVE_MANIFEST_CANONICAL_PATH, ArchiveFileCatalogV1, ArchiveFileEntryV1, ArchiveManifestV1,
    ArchivePathV1,
};
use tari_cc_private_ballot_protocol::Blake3HashProviderV1;

use crate::error::GuiCoreError;
use crate::session::GuiElectionSessionV1;

/// Canonical archive path of the election manifest.
pub const ELECTION_MANIFEST_ARCHIVE_PATH: &str = "election-manifest.cbor";
/// Canonical archive path of the candidate set.
pub const CANDIDATE_SET_ARCHIVE_PATH: &str = "candidate-set.cbor";
/// Canonical archive path of the frozen voter registry.
pub const VOTER_REGISTRY_ARCHIVE_PATH: &str = "voter-registry.cbor";
/// Canonical archive directory prefix for ballot packages.
pub const SUBMISSIONS_ARCHIVE_DIR: &str = "submissions";

/// Returns the canonical archive path of the ballot package at `index`.
#[must_use]
pub fn submission_archive_path(index: usize) -> String {
    format!("{SUBMISSIONS_ARCHIVE_DIR}/{index:08}.cbor")
}

/// One written archive content file.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiArchiveFileSummaryV1 {
    /// Canonical archive-relative path.
    pub path: String,
    /// Domain-separated content digest, lowercase hex.
    pub digest_hex: String,
    /// File size in bytes.
    pub bytes: u64,
}

/// The result of writing one archive directory.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct GuiArchiveWriteResultV1 {
    /// The archive directory path.
    pub directory: PathBuf,
    /// The final domain-separated archive hash, lowercase hex.
    pub archive_hash_hex: String,
    /// The election manifest hash the archive binds, lowercase hex.
    pub election_manifest_hash_hex: String,
    /// Hash-covered content files in canonical path order.
    pub files: Vec<GuiArchiveFileSummaryV1>,
    /// The path of the archive manifest file itself (not hash-covered).
    pub archive_manifest_path: String,
}

/// Writes one complete election archive from a session.
///
/// The target directory is created when absent. If it already exists it must
/// be an empty directory: an existing non-directory target or a non-empty
/// directory is rejected, and no file is ever silently overwritten. Each file
/// is written atomically (temporary file, flush, sync, rename).
///
/// # Errors
///
/// Returns a bounded [`GuiCoreError`] on any encoding, catalog, hashing, or
/// filesystem failure.
pub fn write_archive_directory_v1(
    session: &GuiElectionSessionV1,
    target_dir: &Path,
) -> Result<GuiArchiveWriteResultV1, GuiCoreError> {
    prepare_target_directory(target_dir)?;

    let provider = Blake3HashProviderV1;
    let artifacts = session.artifacts();

    let manifest_bytes = artifacts
        .manifest()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "manifest"))?;
    let candidate_bytes = artifacts
        .candidates()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "candidates"))?;
    let registry_bytes = artifacts
        .registry()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "registry"))?;

    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert(ELECTION_MANIFEST_ARCHIVE_PATH.to_owned(), manifest_bytes);
    files.insert(CANDIDATE_SET_ARCHIVE_PATH.to_owned(), candidate_bytes);
    files.insert(VOTER_REGISTRY_ARCHIVE_PATH.to_owned(), registry_bytes);
    for (index, package) in session.packages().iter().enumerate() {
        files.insert(submission_archive_path(index), package.clone());
    }

    let entries = files
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
    let catalog = ArchiveFileCatalogV1::new(entries)
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-catalog"))?;
    let archive_manifest =
        ArchiveManifestV1::for_provider(artifacts.manifest_hash(), catalog, &provider)
            .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;
    let archive_hash = archive_manifest
        .canonical_hash(&provider)
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;
    let archive_manifest_bytes = archive_manifest
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "archive-manifest"))?;

    if !session.packages().is_empty() {
        let submissions_dir = target_dir.join(SUBMISSIONS_ARCHIVE_DIR);
        std::fs::create_dir(&submissions_dir)
            .map_err(|_| GuiCoreError::io_failure("archive-directory"))?;
    }

    for (path, bytes) in &files {
        write_file_atomic(&target_dir.join(path), bytes)?;
    }
    write_file_atomic(
        &target_dir.join(ARCHIVE_MANIFEST_CANONICAL_PATH),
        &archive_manifest_bytes,
    )?;

    let file_summaries = archive_manifest
        .files()
        .entries()
        .iter()
        .map(|entry| GuiArchiveFileSummaryV1 {
            path: entry.path().as_str().to_owned(),
            digest_hex: crate::hex::to_lower_hex(entry.digest().as_bytes()),
            bytes: files
                .get(entry.path().as_str())
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0),
        })
        .collect();

    Ok(GuiArchiveWriteResultV1 {
        directory: target_dir.to_path_buf(),
        archive_hash_hex: crate::hex::to_lower_hex(archive_hash.as_bytes()),
        election_manifest_hash_hex: crate::hex::to_lower_hex(artifacts.manifest_hash().as_bytes()),
        files: file_summaries,
        archive_manifest_path: ARCHIVE_MANIFEST_CANONICAL_PATH.to_owned(),
    })
}

/// Creates the target directory when absent, or requires it to be empty.
fn prepare_target_directory(target_dir: &Path) -> Result<(), GuiCoreError> {
    match std::fs::symlink_metadata(target_dir) {
        Ok(metadata) => {
            if !metadata.is_dir() {
                return Err(GuiCoreError::archive_target_invalid());
            }
            let mut entries = std::fs::read_dir(target_dir)
                .map_err(|_| GuiCoreError::io_failure("archive-directory"))?;
            if entries.next().is_some() {
                return Err(GuiCoreError::archive_target_not_empty());
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(target_dir)
                .map_err(|_| GuiCoreError::io_failure("archive-directory"))
        }
        Err(_) => Err(GuiCoreError::io_failure("archive-directory")),
    }
}

/// Atomically writes one file, refusing to overwrite an existing file.
fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), GuiCoreError> {
    if path.exists() {
        return Err(GuiCoreError::archive_target_not_empty());
    }
    let mut tmp = std::ffi::OsString::from(path.as_os_str());
    tmp.push(".tmp");
    let tmp_path = Path::new(&tmp);
    let cleanup = |p: &Path| {
        let _ = std::fs::remove_file(p);
    };
    let result = (|| -> Result<(), GuiCoreError> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(tmp_path)
            .map_err(|_| GuiCoreError::io_failure("archive-file"))?;
        use std::io::Write;
        file.write_all(bytes)
            .map_err(|_| GuiCoreError::io_failure("archive-file"))?;
        file.flush()
            .map_err(|_| GuiCoreError::io_failure("archive-file"))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure("archive-file"))?;
        drop(file);
        std::fs::rename(tmp_path, path).map_err(|_| GuiCoreError::io_failure("archive-file"))?;
        Ok(())
    })();
    if result.is_err() {
        cleanup(tmp_path);
    }
    result
}
