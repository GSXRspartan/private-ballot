//! Election-scoped terminal-anchor index for the live anchor app.
//!
//! The index is keyed by election manifest hash, not by executable location or
//! operator-selected snapshot/evidence/config paths. A terminal record is a
//! digest-bearing canonical CBOR file that points to the original terminal
//! evidence file and binds its digest.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, Blake3HashProviderV1, CanonicalCborReader,
    CanonicalCborWriter, HashProvider, ManifestHash, ProtocolError, ValidationCode,
};

use crate::evidence::{AnchorEvidenceRecordV1, MAX_EVIDENCE_FILE_BYTES};

/// Maximum encoded terminal-index file size.
pub const MAX_TERMINAL_INDEX_FILE_BYTES: usize = 8_192;

/// Stable terminal-index record type.
pub const TERMINAL_INDEX_RECORD_TYPE_ID_V1: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_TERMINAL_INDEX_V1";

/// Hash-algorithm identifier written into the terminal-index envelope.
pub const TERMINAL_INDEX_HASH_ALGORITHM_ID_V1: &str = BLAKE3_256_HASH_ALGORITHM_ID_V1;

/// Domain-separation frame prefix for terminal-index body digests.
pub const TERMINAL_INDEX_FRAME_PREFIX_V1: &[u8] =
    b"TARI_CC_PRIVATE_BALLOT_OOTLE_TERMINAL_INDEX_FRAME_V1";

/// Domain label for terminal-index body digests.
pub const TERMINAL_INDEX_DOMAIN_LABEL_V1: &str = "tari-cc-private-ballot/ootle-terminal-index/v1";

const ENVELOPE_FIELD_COUNT: usize = 4;
const BODY_FIELD_COUNT: usize = 9;
const MAX_PATH_BYTES: usize = 4_096;
const FINAL_STATUS_ACCEPTED: &str = "ACCEPTED";

/// Bounded terminal-index failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalIndexError {
    /// Filesystem I/O failed.
    IoFailure,
    /// Atomic rename failed.
    AtomicRenameFailure,
    /// The record type/version is unsupported.
    UnsupportedProtocolVersion,
    /// The hash algorithm is unsupported.
    UnsupportedHashAlgorithm,
    /// CBOR was structurally invalid.
    InvalidCbor,
    /// CBOR was not canonical.
    NonCanonicalCbor,
    /// An unexpected CBOR type was encountered.
    UnexpectedCborType,
    /// Trailing CBOR bytes remained.
    TrailingCborData,
    /// File or field size exceeded a bound.
    ProtocolLimitExceeded,
    /// The terminal-index body digest did not match.
    DigestMismatch,
    /// A field value was invalid.
    InvalidData,
    /// The index already records a terminal anchor for this election.
    Conflict,
    /// The evidence referenced by the index could not be read or decoded.
    EvidenceUnavailable,
    /// Referenced evidence does not match the terminal-index binding.
    EvidenceMismatch,
}

impl TerminalIndexError {
    /// Returns the stable machine-readable error code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IoFailure => "TERMINAL_INDEX_IO_FAILURE",
            Self::AtomicRenameFailure => "TERMINAL_INDEX_ATOMIC_RENAME_FAILURE",
            Self::UnsupportedProtocolVersion => "TERMINAL_INDEX_UNSUPPORTED_PROTOCOL_VERSION",
            Self::UnsupportedHashAlgorithm => "TERMINAL_INDEX_UNSUPPORTED_HASH_ALGORITHM",
            Self::InvalidCbor => "TERMINAL_INDEX_INVALID_CBOR",
            Self::NonCanonicalCbor => "TERMINAL_INDEX_NON_CANONICAL_CBOR",
            Self::UnexpectedCborType => "TERMINAL_INDEX_UNEXPECTED_CBOR_TYPE",
            Self::TrailingCborData => "TERMINAL_INDEX_TRAILING_CBOR_DATA",
            Self::ProtocolLimitExceeded => "TERMINAL_INDEX_PROTOCOL_LIMIT_EXCEEDED",
            Self::DigestMismatch => "TERMINAL_INDEX_DIGEST_MISMATCH",
            Self::InvalidData => "TERMINAL_INDEX_INVALID_DATA",
            Self::Conflict => "TERMINAL_INDEX_CONFLICT",
            Self::EvidenceUnavailable => "TERMINAL_INDEX_EVIDENCE_UNAVAILABLE",
            Self::EvidenceMismatch => "TERMINAL_INDEX_EVIDENCE_MISMATCH",
        }
    }
}

impl core::fmt::Display for TerminalIndexError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for TerminalIndexError {}

/// One terminal anchor observed for an election manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalAnchorIndexRecordV1 {
    network: OotleNetworkIdV1,
    manifest_hash: ManifestHash,
    archive_hash: ArchiveHashV1,
    anchor_digest: OotleAnchorRecordHashV1,
    final_status: &'static str,
    evidence_path: PathBuf,
    evidence_digest: [u8; 32],
    transaction_id: Option<AnchorTransactionId>,
    encoded: Vec<u8>,
}

impl TerminalAnchorIndexRecordV1 {
    /// Builds a terminal-index record from an already-created evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalIndexError`] if the evidence path is not absolute or
    /// cannot be encoded canonically.
    pub fn from_evidence(
        evidence: &AnchorEvidenceRecordV1,
        evidence_path: &Path,
    ) -> Result<Self, TerminalIndexError> {
        if !evidence_path.is_absolute() || evidence_path.to_string_lossy().len() > MAX_PATH_BYTES {
            return Err(TerminalIndexError::InvalidData);
        }
        Self::new(
            evidence.network().clone(),
            evidence.manifest_hash(),
            evidence.archive_hash(),
            evidence.anchor_digest(),
            evidence.final_status(),
            evidence_path.to_path_buf(),
            evidence.digest(),
            evidence.transaction_id().cloned(),
        )
    }

    /// Decodes and verifies a canonical terminal-index record.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalIndexError`] if the envelope, digest, or body is not
    /// valid.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, TerminalIndexError> {
        if bytes.len() > MAX_TERMINAL_INDEX_FILE_BYTES {
            return Err(TerminalIndexError::ProtocolLimitExceeded);
        }
        let mut reader = CanonicalCborReader::new(bytes);
        let envelope_len = reader.read_array_len().map_err(from_protocol)?;
        if envelope_len != ENVELOPE_FIELD_COUNT {
            return Err(TerminalIndexError::InvalidData);
        }
        let record_type = reader.read_text_string().map_err(from_protocol)?;
        if record_type != TERMINAL_INDEX_RECORD_TYPE_ID_V1 {
            return Err(TerminalIndexError::UnsupportedProtocolVersion);
        }
        let hash_algorithm = reader.read_text_string().map_err(from_protocol)?;
        if hash_algorithm != TERMINAL_INDEX_HASH_ALGORITHM_ID_V1 {
            return Err(TerminalIndexError::UnsupportedHashAlgorithm);
        }
        let recorded_digest = read_digest(&mut reader)?;
        let body = reader.read_byte_string().map_err(from_protocol)?;
        reader.finish().map_err(from_protocol)?;
        let computed_digest = body_digest(body);
        if recorded_digest != computed_digest {
            return Err(TerminalIndexError::DigestMismatch);
        }
        let mut record = decode_body(body)?;
        let canonical = record.to_canonical_bytes()?;
        if canonical != bytes {
            return Err(TerminalIndexError::NonCanonicalCbor);
        }
        record.encoded = canonical;
        Ok(record)
    }

    /// Returns the manifest hash key.
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// Returns the archive hash.
    #[must_use]
    pub const fn archive_hash(&self) -> ArchiveHashV1 {
        self.archive_hash
    }

    /// Returns the anchor digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }

    /// Returns the final status text.
    #[must_use]
    pub const fn final_status(&self) -> &'static str {
        self.final_status
    }

    /// Returns the evidence path recorded by the first terminal run.
    #[must_use]
    pub fn evidence_path(&self) -> &Path {
        &self.evidence_path
    }

    /// Returns whether this record is a verified accepted terminal.
    #[must_use]
    pub fn is_accepted_for(
        &self,
        network: &OotleNetworkIdV1,
        manifest_hash: ManifestHash,
        archive_hash: ArchiveHashV1,
        anchor_digest: OotleAnchorRecordHashV1,
    ) -> bool {
        self.final_status == FINAL_STATUS_ACCEPTED
            && &self.network == network
            && self.manifest_hash == manifest_hash
            && self.archive_hash == archive_hash
            && self.anchor_digest == anchor_digest
    }

    /// Reads and validates the indexed terminal evidence.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalIndexError`] if the evidence is absent, corrupt, or
    /// does not match this index record.
    pub fn read_bound_evidence(&self) -> Result<AnchorEvidenceRecordV1, TerminalIndexError> {
        let metadata = std::fs::symlink_metadata(&self.evidence_path)
            .map_err(|_| TerminalIndexError::EvidenceUnavailable)?;
        reject_path_indirection(&metadata, TerminalIndexError::EvidenceUnavailable)?;
        if !metadata.is_file() || metadata.len() > MAX_EVIDENCE_FILE_BYTES as u64 {
            return Err(TerminalIndexError::EvidenceUnavailable);
        }
        let bytes = std::fs::read(&self.evidence_path)
            .map_err(|_| TerminalIndexError::EvidenceUnavailable)?;
        let evidence = AnchorEvidenceRecordV1::from_canonical_bytes(&bytes)
            .map_err(|_| TerminalIndexError::EvidenceUnavailable)?;
        if evidence.digest() != self.evidence_digest
            || evidence.network() != &self.network
            || evidence.manifest_hash() != self.manifest_hash
            || evidence.archive_hash() != self.archive_hash
            || evidence.anchor_digest() != self.anchor_digest
            || evidence.final_status() != self.final_status
            || evidence.transaction_id().cloned() != self.transaction_id
        {
            return Err(TerminalIndexError::EvidenceMismatch);
        }
        Ok(evidence)
    }

    /// Returns canonical bytes for this terminal-index record.
    ///
    /// # Errors
    ///
    /// Returns [`TerminalIndexError`] if encoding fails.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, TerminalIndexError> {
        let body = encode_body(self)?;
        let digest = body_digest(&body);
        encode_envelope(&body, &digest)
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        network: OotleNetworkIdV1,
        manifest_hash: ManifestHash,
        archive_hash: ArchiveHashV1,
        anchor_digest: OotleAnchorRecordHashV1,
        final_status: &'static str,
        evidence_path: PathBuf,
        evidence_digest: [u8; 32],
        transaction_id: Option<AnchorTransactionId>,
    ) -> Result<Self, TerminalIndexError> {
        let mut record = Self {
            network,
            manifest_hash,
            archive_hash,
            anchor_digest,
            final_status,
            evidence_path,
            evidence_digest,
            transaction_id,
            encoded: Vec::new(),
        };
        record.encoded = record.to_canonical_bytes()?;
        Ok(record)
    }
}

/// Returns the production terminal-index root used by the standalone app.
///
/// # Errors
///
/// Returns [`TerminalIndexError::IoFailure`] if the per-user application-state
/// base cannot be resolved.
pub fn default_terminal_index_root() -> Result<PathBuf, TerminalIndexError> {
    default_terminal_index_root_for_env(|key| std::env::var_os(key))
}

/// Resolves the default terminal-index root from platform environment inputs.
///
/// This is public only for tests and adversarial path-scope validation. The
/// production path uses [`default_terminal_index_root`] and does not accept a
/// runtime override.
#[doc(hidden)]
pub fn default_terminal_index_root_for_env<F>(get_env: F) -> Result<PathBuf, TerminalIndexError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    stable_anchor_state_root_for_env(get_env).map(|root| root.join("terminal-index-v1"))
}

#[cfg(windows)]
fn stable_anchor_state_root_for_env<F>(mut get_env: F) -> Result<PathBuf, TerminalIndexError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let base = get_env("LOCALAPPDATA")
        .or_else(|| get_env("APPDATA"))
        .ok_or(TerminalIndexError::IoFailure)?;
    let base = PathBuf::from(base);
    if !base.is_absolute() {
        return Err(TerminalIndexError::IoFailure);
    }
    Ok(base.join("Tari Private Ballot").join("anchor-state"))
}

#[cfg(target_os = "macos")]
fn stable_anchor_state_root_for_env<F>(mut get_env: F) -> Result<PathBuf, TerminalIndexError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let home = get_env("HOME").ok_or(TerminalIndexError::IoFailure)?;
    let home = PathBuf::from(home);
    if !home.is_absolute() {
        return Err(TerminalIndexError::IoFailure);
    }
    Ok(home
        .join("Library")
        .join("Application Support")
        .join("Tari Private Ballot")
        .join("anchor-state"))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn stable_anchor_state_root_for_env<F>(mut get_env: F) -> Result<PathBuf, TerminalIndexError>
where
    F: FnMut(&str) -> Option<OsString>,
{
    let base = if let Some(xdg_state_home) = get_env("XDG_STATE_HOME") {
        PathBuf::from(xdg_state_home)
    } else {
        let home = get_env("HOME").ok_or(TerminalIndexError::IoFailure)?;
        PathBuf::from(home).join(".local").join("state")
    };
    if !base.is_absolute() {
        return Err(TerminalIndexError::IoFailure);
    }
    Ok(base.join("tari-private-ballot").join("anchor-state"))
}

/// Reads the manifest-scoped terminal-index record, if present.
///
/// # Errors
///
/// Returns [`TerminalIndexError`] on corruption, tampering, oversized files, or
/// I/O failures other than absence.
pub fn read_terminal_index(
    root: &Path,
    manifest_hash: ManifestHash,
) -> Result<Option<TerminalAnchorIndexRecordV1>, TerminalIndexError> {
    let path = terminal_index_path(root, manifest_hash);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(TerminalIndexError::IoFailure),
    };
    reject_path_indirection(&metadata, TerminalIndexError::InvalidData)?;
    if !metadata.is_file() || metadata.len() > MAX_TERMINAL_INDEX_FILE_BYTES as u64 {
        return Err(TerminalIndexError::ProtocolLimitExceeded);
    }
    let bytes = std::fs::read(&path).map_err(|_| TerminalIndexError::IoFailure)?;
    let record = TerminalAnchorIndexRecordV1::from_canonical_bytes(&bytes)?;
    if record.manifest_hash() != manifest_hash {
        return Err(TerminalIndexError::InvalidData);
    }
    Ok(Some(record))
}

/// Writes a manifest-scoped terminal-index record atomically.
///
/// # Errors
///
/// Returns [`TerminalIndexError::Conflict`] if the election already has a
/// different terminal record.
pub fn write_terminal_index(
    root: &Path,
    record: &TerminalAnchorIndexRecordV1,
) -> Result<(), TerminalIndexError> {
    std::fs::create_dir_all(root).map_err(|_| TerminalIndexError::IoFailure)?;
    let path = terminal_index_path(root, record.manifest_hash());
    if let Some(existing) = read_terminal_index(root, record.manifest_hash())? {
        if existing == *record {
            return Ok(());
        }
        return Err(TerminalIndexError::Conflict);
    }

    let tmp_path = path.with_extension(format!("cbor.tmp.{}", std::process::id()));
    let cleanup = |p: &Path| {
        let _ = std::fs::remove_file(p);
    };
    let result = (|| -> Result<(), TerminalIndexError> {
        let mut file =
            std::fs::File::create(&tmp_path).map_err(|_| TerminalIndexError::IoFailure)?;
        use std::io::Write;
        file.write_all(&record.encoded)
            .map_err(|_| TerminalIndexError::IoFailure)?;
        file.flush().map_err(|_| TerminalIndexError::IoFailure)?;
        file.sync_all().map_err(|_| TerminalIndexError::IoFailure)?;
        drop(file);
        std::fs::rename(&tmp_path, &path).map_err(|_| TerminalIndexError::AtomicRenameFailure)
    })();
    if result.is_err() {
        cleanup(&tmp_path);
    }
    result
}

/// Returns the canonical terminal-index file path for an election manifest.
#[must_use]
pub fn terminal_index_path(root: &Path, manifest_hash: ManifestHash) -> PathBuf {
    root.join(format!(
        "manifest-{}.cbor",
        to_lower_hex(manifest_hash.as_bytes())
    ))
}

fn encode_envelope(body: &[u8], digest: &[u8; 32]) -> Result<Vec<u8>, TerminalIndexError> {
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(ENVELOPE_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(TERMINAL_INDEX_RECORD_TYPE_ID_V1)
        .map_err(from_protocol)?;
    writer
        .write_text_string(TERMINAL_INDEX_HASH_ALGORITHM_ID_V1)
        .map_err(from_protocol)?;
    writer.write_byte_string(digest).map_err(from_protocol)?;
    writer.write_byte_string(body).map_err(from_protocol)?;
    Ok(writer.into_bytes())
}

fn encode_body(record: &TerminalAnchorIndexRecordV1) -> Result<Vec<u8>, TerminalIndexError> {
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(BODY_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(record.network.as_str())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(record.manifest_hash.as_bytes())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(record.archive_hash.as_bytes())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(record.anchor_digest.as_bytes())
        .map_err(from_protocol)?;
    writer
        .write_text_string(record.final_status)
        .map_err(from_protocol)?;
    writer
        .write_text_string(&record.evidence_path.to_string_lossy())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(&record.evidence_digest)
        .map_err(from_protocol)?;
    encode_option_text(
        &mut writer,
        record
            .transaction_id
            .as_ref()
            .map(AnchorTransactionId::as_str),
    )?;
    writer
        .write_text_string(BLAKE3_256_HASH_ALGORITHM_ID_V1)
        .map_err(from_protocol)?;
    Ok(writer.into_bytes())
}

fn decode_body(body: &[u8]) -> Result<TerminalAnchorIndexRecordV1, TerminalIndexError> {
    let mut reader = CanonicalCborReader::new(body);
    let body_len = reader.read_array_len().map_err(from_protocol)?;
    if body_len != BODY_FIELD_COUNT {
        return Err(TerminalIndexError::InvalidData);
    }
    let network =
        OotleNetworkIdV1::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| TerminalIndexError::InvalidData)?;
    let manifest_hash = ManifestHash::new(read_digest(&mut reader)?);
    let archive_hash = ArchiveHashV1::new(read_digest(&mut reader)?);
    let anchor_digest = OotleAnchorRecordHashV1::new(read_digest(&mut reader)?);
    let final_status = final_status_from_str(reader.read_text_string().map_err(from_protocol)?)
        .ok_or(TerminalIndexError::InvalidData)?;
    let evidence_path_text = reader.read_text_string().map_err(from_protocol)?;
    if evidence_path_text.len() > MAX_PATH_BYTES {
        return Err(TerminalIndexError::ProtocolLimitExceeded);
    }
    let evidence_path = PathBuf::from(evidence_path_text);
    if !evidence_path.is_absolute() {
        return Err(TerminalIndexError::InvalidData);
    }
    let evidence_digest = read_digest(&mut reader)?;
    let transaction_id = decode_option_text(&mut reader)?
        .map(AnchorTransactionId::new)
        .transpose()
        .map_err(|_| TerminalIndexError::InvalidData)?;
    let hash_algorithm = reader.read_text_string().map_err(from_protocol)?;
    if hash_algorithm != BLAKE3_256_HASH_ALGORITHM_ID_V1 {
        return Err(TerminalIndexError::UnsupportedHashAlgorithm);
    }
    reader.finish().map_err(from_protocol)?;
    TerminalAnchorIndexRecordV1::new(
        network,
        manifest_hash,
        archive_hash,
        anchor_digest,
        final_status,
        evidence_path,
        evidence_digest,
        transaction_id,
    )
}

fn encode_option_text(
    writer: &mut CanonicalCborWriter,
    value: Option<&str>,
) -> Result<(), TerminalIndexError> {
    match value {
        Some(text) => {
            writer.write_array_len(1).map_err(from_protocol)?;
            writer.write_text_string(text).map_err(from_protocol)?;
        }
        None => {
            writer.write_array_len(0).map_err(from_protocol)?;
        }
    }
    Ok(())
}

fn decode_option_text(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<Option<String>, TerminalIndexError> {
    let len = reader.read_array_len().map_err(from_protocol)?;
    match len {
        0 => Ok(None),
        1 => Ok(Some(
            reader.read_text_string().map_err(from_protocol)?.to_owned(),
        )),
        _ => Err(TerminalIndexError::InvalidData),
    }
}

fn read_digest(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], TerminalIndexError> {
    reader
        .read_byte_string()
        .map_err(from_protocol)?
        .try_into()
        .map_err(|_| TerminalIndexError::InvalidData)
}

fn body_digest(body: &[u8]) -> [u8; 32] {
    Blake3HashProviderV1.hash(&terminal_index_domain_input(body))
}

fn terminal_index_domain_input(body: &[u8]) -> Vec<u8> {
    let label = TERMINAL_INDEX_DOMAIN_LABEL_V1.as_bytes();
    let mut framed =
        Vec::with_capacity(TERMINAL_INDEX_FRAME_PREFIX_V1.len() + 1 + label.len() + 1 + body.len());
    framed.extend_from_slice(TERMINAL_INDEX_FRAME_PREFIX_V1);
    framed.push(0);
    framed.extend_from_slice(label);
    framed.push(0);
    framed.extend_from_slice(body);
    framed
}

fn final_status_from_str(text: &str) -> Option<&'static str> {
    match text {
        "ACCEPTED" => Some("ACCEPTED"),
        "FEE_ONLY_ACCEPTED" => Some("FEE_ONLY_ACCEPTED"),
        "REJECTED" => Some("REJECTED"),
        "VERIFICATION_FAILED" => Some("VERIFICATION_FAILED"),
        "DISAGREEMENT" => Some("DISAGREEMENT"),
        "POLL_EXHAUSTED_UNKNOWN" => Some("POLL_EXHAUSTED_UNKNOWN"),
        "REJECTED_BY_APPROVER" => Some("REJECTED_BY_APPROVER"),
        _ => None,
    }
}

fn from_protocol(error: ProtocolError) -> TerminalIndexError {
    match error.code() {
        ValidationCode::UnsupportedProtocolVersion => {
            TerminalIndexError::UnsupportedProtocolVersion
        }
        ValidationCode::UnsupportedHashAlgorithm => TerminalIndexError::UnsupportedHashAlgorithm,
        ValidationCode::InvalidCbor => TerminalIndexError::InvalidCbor,
        ValidationCode::NonCanonicalCbor => TerminalIndexError::NonCanonicalCbor,
        ValidationCode::UnexpectedCborType => TerminalIndexError::UnexpectedCborType,
        ValidationCode::TrailingCborData => TerminalIndexError::TrailingCborData,
        ValidationCode::ProtocolLimitExceeded => TerminalIndexError::ProtocolLimitExceeded,
        _ => TerminalIndexError::InvalidData,
    }
}

fn reject_path_indirection(
    metadata: &std::fs::Metadata,
    error: TerminalIndexError,
) -> Result<(), TerminalIndexError> {
    if metadata.file_type().is_symlink() || is_windows_reparse_point(metadata) {
        return Err(error);
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn to_lower_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(vars: Vec<(&'static str, &'static str)>) -> impl FnMut(&str) -> Option<OsString> {
        move |key| {
            vars.iter()
                .find(|(name, _value)| *name == key)
                .map(|(_name, value)| OsString::from(value))
        }
    }

    #[cfg(windows)]
    #[test]
    fn default_root_uses_stable_windows_user_app_state() {
        let root = default_terminal_index_root_for_env(env(vec![
            ("LOCALAPPDATA", r"C:\Users\tester\AppData\Local"),
            ("APPDATA", r"C:\Users\tester\AppData\Roaming"),
        ]))
        .expect("root resolves");

        assert_eq!(
            root,
            PathBuf::from(r"C:\Users\tester\AppData\Local")
                .join("Tari Private Ballot")
                .join("anchor-state")
                .join("terminal-index-v1")
        );
    }

    #[cfg(windows)]
    #[test]
    fn default_root_rejects_relative_windows_app_state() {
        assert_eq!(
            default_terminal_index_root_for_env(env(vec![("LOCALAPPDATA", "relative")])),
            Err(TerminalIndexError::IoFailure)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_root_uses_stable_macos_user_app_state() {
        let root = default_terminal_index_root_for_env(env(vec![("HOME", "/Users/tester")]))
            .expect("root resolves");

        assert_eq!(
            root,
            PathBuf::from("/Users/tester")
                .join("Library")
                .join("Application Support")
                .join("Tari Private Ballot")
                .join("anchor-state")
                .join("terminal-index-v1")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_root_rejects_relative_macos_home() {
        assert_eq!(
            default_terminal_index_root_for_env(env(vec![("HOME", "relative")])),
            Err(TerminalIndexError::IoFailure)
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn default_root_uses_stable_unix_user_state() {
        let root =
            default_terminal_index_root_for_env(env(vec![("XDG_STATE_HOME", "/state/tester")]))
                .expect("root resolves");

        assert_eq!(
            root,
            PathBuf::from("/state/tester")
                .join("tari-private-ballot")
                .join("anchor-state")
                .join("terminal-index-v1")
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn default_root_falls_back_to_home_local_state_on_unix() {
        let root = default_terminal_index_root_for_env(env(vec![("HOME", "/home/tester")]))
            .expect("root resolves");

        assert_eq!(
            root,
            PathBuf::from("/home/tester")
                .join(".local")
                .join("state")
                .join("tari-private-ballot")
                .join("anchor-state")
                .join("terminal-index-v1")
        );
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn default_root_rejects_relative_unix_state() {
        assert_eq!(
            default_terminal_index_root_for_env(env(vec![("XDG_STATE_HOME", "relative")])),
            Err(TerminalIndexError::IoFailure)
        );
    }
}
