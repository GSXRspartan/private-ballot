//! Durable, local, defense-in-depth "cast lock" for the voter workflow.
//!
//! A voter may freely reconsider a ballot while it lives only inside the local
//! application. The moment the voter deliberately EXPORTS/RELEASES the ballot
//! package, this installation records an irrevocable local cast for that
//! (election, public credential) pair. After that:
//!
//!   * the choice cannot be changed and no new ballot can be prepared,
//!   * restart / navigation / credential lock-unlock do not clear the lock,
//!   * the normal application offers no "undo cast" path.
//!
//! This is honest UX and local defense-in-depth ONLY. It is NOT the double-vote
//! protection: the organizer's election-scoped nullifier remains the sole
//! cryptographic guarantee that a credential can produce at most one accepted
//! ballot per election, even across machines. This module changes no protocol,
//! nullifier, or tally behavior.
//!
//! The record is keyed by the election manifest hash and a fingerprint of the
//! voter's PUBLIC governance/enrollment key. It stores only non-secret metadata
//! (see [`VoterCastRecordV1`]); it never persists a passphrase, decrypted
//! credential, private scalar, seed, witness, proof randomness, nullifier,
//! plaintext ballot choice, or registry index.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tari_cc_private_ballot_ballot::BallotPackageV1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};
use tempfile::NamedTempFile;

use crate::artifacts::GuiElectionArtifactsV1;
use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::hex::{from_hex, to_lower_hex};
use crate::transport::{
    AuthenticatedTransportReceiptV1, PrivateBallotEnvelopeV1, TransportDescriptorV1,
    VoterReceiptStateV1,
};
use crate::workspace::MAX_BALLOT_PACKAGE_BYTES_V1;

/// Backend-controlled directory name below the Tauri app-data root.
pub const VOTER_CAST_LOCKS_DIRECTORY_NAME: &str = "voter-cast-locks";

const CAST_RECORD_MAGIC_V1: &[u8] = b"TARI_PRIVATE_BALLOT_VOTER_CAST_LOCK_V1";
const CAST_RECORD_VERSION_V1: u32 = 1;
/// Distinct magic for the private-transport (online) release record. Offline
/// records keep the V1 magic/format byte-for-byte; a new kind gets a new magic
/// so the two decoders never overlap and old records decode unchanged.
///
/// V3 adds the mandatory `staged_envelope_digest_hex` binding. The online record
/// is unreleased, so evolving it is safe; an older provisional V2 record (magic
/// `..._RELEASE_LOCK_V2`) no longer matches this magic/version and therefore
/// decodes to `Malformed` and fails closed to `CastPending` — a missing staged
/// digest is never silently defaulted.
const RELEASE_RECORD_MAGIC_V3: &[u8] = b"TARI_PRIVATE_BALLOT_VOTER_RELEASE_LOCK_V3";
const RELEASE_RECORD_VERSION_V3: u32 = 3;
/// Domain separation for the exact staged-envelope byte digest (mirrors the
/// local fingerprint-domain convention in this module).
const STAGED_ENVELOPE_DIGEST_DOMAIN_V1: &[u8] =
    b"tari-cc-private-ballot/voter-release/staged-envelope-digest/v1";
const CAST_RECORD_FILE_SUFFIX: &str = ".castlock";
const MAX_CAST_RECORD_BYTES_V1: u64 = 16 * 1024;
const MAX_CAST_RECORD_FIELD_BYTES: usize = 8 * 1024;
/// Bounded size of a durably staged opaque online submission envelope. The
/// transport padding profile keeps real envelopes far below this; the bound
/// rejects a corrupt/oversized staged artifact on recovery.
pub const MAX_STAGED_RELEASE_ENVELOPE_BYTES: u64 = 1_048_576;
const STAGED_ENVELOPE_FILE_SUFFIX: &str = ".release-envelope";
const RELEASE_RECEIPT_FILE_SUFFIX: &str = ".release-receipt";
const FINGERPRINT_DOMAIN_V1: &[u8] =
    b"tari-cc-private-ballot/voter-cast-lock/public-credential-fingerprint/v1";

/// Public, non-secret local cast state for a (election, credential) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GuiVoterCastLockStateV1 {
    /// No local cast has been recorded: the voter may choose/prepare/change.
    NotCast,
    /// A cast export is durably committed but not yet finalized, OR a present
    /// record could not be safely interpreted. Either way the voter is LOCKED
    /// (fail closed); no different ballot may be prepared.
    CastPending,
    /// The ballot was exported and cast locally. Terminal and irreversible from
    /// the normal application.
    Cast,
}

impl GuiVoterCastLockStateV1 {
    /// Returns the stable SCREAMING_SNAKE_CASE identifier (matches the frontend
    /// DTO mirror).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotCast => "NOT_CAST",
            Self::CastPending => "CAST_PENDING",
            Self::Cast => "CAST",
        }
    }

    /// True when the voter is locked out of choosing/preparing a new ballot.
    #[must_use]
    pub const fn is_locked(self) -> bool {
        matches!(self, Self::CastPending | Self::Cast)
    }
}

/// The persisted cast record. Non-secret metadata only. `temp_path`/`final_path`
/// are narrowly necessary local recovery-path metadata for crash-safe
/// finalization; they are the voter's own chosen export location.
///
/// Encoded with a self-contained length-prefixed binary format (no external
/// serialization dependency), mirroring the durable-workspace convention.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VoterCastRecordV1 {
    election_manifest_hash_hex: String,
    credential_fingerprint_hex: String,
    package_digest_hex: String,
    final_path: String,
    temp_path: String,
    is_cast: bool,
}

impl VoterCastRecordV1 {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(CAST_RECORD_MAGIC_V1);
        out.extend_from_slice(&CAST_RECORD_VERSION_V1.to_le_bytes());
        encode_field(&mut out, &self.election_manifest_hash_hex);
        encode_field(&mut out, &self.credential_fingerprint_hex);
        encode_field(&mut out, &self.package_digest_hex);
        encode_field(&mut out, &self.final_path);
        encode_field(&mut out, &self.temp_path);
        out.push(u8::from(self.is_cast));
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = Cursor { bytes, offset: 0 };
        cursor.expect_bytes(CAST_RECORD_MAGIC_V1)?;
        if cursor.read_u32()? != CAST_RECORD_VERSION_V1 {
            return None;
        }
        let election_manifest_hash_hex = cursor.read_field()?;
        let credential_fingerprint_hex = cursor.read_field()?;
        let package_digest_hex = cursor.read_field()?;
        let final_path = cursor.read_field()?;
        let temp_path = cursor.read_field()?;
        let is_cast = match cursor.read_u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        if !cursor.is_exhausted() {
            return None;
        }
        Some(Self {
            election_manifest_hash_hex,
            credential_fingerprint_hex,
            package_digest_hex,
            final_path,
            temp_path,
            is_cast,
        })
    }
}

/// Durable PENDING/CAST record for a private-transport (online) release.
///
/// It stores only non-secret recovery metadata: the durable path of the EXACT
/// opaque submission envelope staged before the boundary was crossed, a
/// domain-separated digest of those EXACT staged bytes, the signed descriptor
/// fingerprint the envelope is bound to, and the path where an authenticated
/// collector receipt is persisted once received. It never stores a credential
/// private key, passphrase, witness, nullifier, or the plaintext ballot. The
/// staged file itself holds only the already-encrypted opaque HPKE envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OnlineReleaseRecordV3 {
    election_manifest_hash_hex: String,
    credential_fingerprint_hex: String,
    package_digest_hex: String,
    staged_envelope_path: String,
    staged_envelope_digest_hex: String,
    descriptor_fingerprint_hex: String,
    receipt_evidence_path: String,
    is_cast: bool,
}

impl OnlineReleaseRecordV3 {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(384);
        out.extend_from_slice(RELEASE_RECORD_MAGIC_V3);
        out.extend_from_slice(&RELEASE_RECORD_VERSION_V3.to_le_bytes());
        encode_field(&mut out, &self.election_manifest_hash_hex);
        encode_field(&mut out, &self.credential_fingerprint_hex);
        encode_field(&mut out, &self.package_digest_hex);
        encode_field(&mut out, &self.staged_envelope_path);
        encode_field(&mut out, &self.staged_envelope_digest_hex);
        encode_field(&mut out, &self.descriptor_fingerprint_hex);
        encode_field(&mut out, &self.receipt_evidence_path);
        out.push(u8::from(self.is_cast));
        out
    }

    fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = Cursor { bytes, offset: 0 };
        cursor.expect_bytes(RELEASE_RECORD_MAGIC_V3)?;
        if cursor.read_u32()? != RELEASE_RECORD_VERSION_V3 {
            return None;
        }
        let election_manifest_hash_hex = cursor.read_field()?;
        let credential_fingerprint_hex = cursor.read_field()?;
        let package_digest_hex = cursor.read_field()?;
        let staged_envelope_path = cursor.read_field()?;
        let staged_envelope_digest_hex = cursor.read_field()?;
        let descriptor_fingerprint_hex = cursor.read_field()?;
        let receipt_evidence_path = cursor.read_field()?;
        let is_cast = match cursor.read_u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        if !cursor.is_exhausted() {
            return None;
        }
        Some(Self {
            election_manifest_hash_hex,
            credential_fingerprint_hex,
            package_digest_hex,
            staged_envelope_path,
            staged_envelope_digest_hex,
            descriptor_fingerprint_hex,
            receipt_evidence_path,
            is_cast,
        })
    }
}

/// Domain-separated BLAKE3 digest (lowercase hex) of the EXACT staged opaque
/// envelope bytes. This is the primary exact-retry invariant: the retry path
/// recomputes this over the bytes it reads and refuses to transmit anything
/// whose digest does not match the durable record.
#[must_use]
pub fn staged_release_envelope_digest_hex_v1(envelope_bytes: &[u8]) -> String {
    let mut framed =
        Vec::with_capacity(STAGED_ENVELOPE_DIGEST_DOMAIN_V1.len() + envelope_bytes.len());
    framed.extend_from_slice(STAGED_ENVELOPE_DIGEST_DOMAIN_V1);
    framed.extend_from_slice(envelope_bytes);
    to_lower_hex(&Blake3HashProviderV1.hash(&framed))
}

fn encode_field(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    // Field lengths are bounded on decode; encode always fits by construction.
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl Cursor<'_> {
    fn expect_bytes(&mut self, expected: &[u8]) -> Option<()> {
        let end = self.offset.checked_add(expected.len())?;
        if self.bytes.get(self.offset..end)? == expected {
            self.offset = end;
            Some(())
        } else {
            None
        }
    }

    fn read_u32(&mut self) -> Option<u32> {
        let end = self.offset.checked_add(4)?;
        let slice = self.bytes.get(self.offset..end)?;
        self.offset = end;
        Some(u32::from_le_bytes(slice.try_into().ok()?))
    }

    fn read_u8(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.offset)?;
        self.offset = self.offset.checked_add(1)?;
        Some(byte)
    }

    fn read_field(&mut self) -> Option<String> {
        let len = self.read_u32()? as usize;
        if len > MAX_CAST_RECORD_FIELD_BYTES {
            return None;
        }
        let end = self.offset.checked_add(len)?;
        let slice = self.bytes.get(self.offset..end)?;
        self.offset = end;
        String::from_utf8(slice.to_vec()).ok()
    }

    fn is_exhausted(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

/// Returns the app-data cast-locks directory path (not created).
#[must_use]
pub fn voter_cast_locks_directory_v1(app_data_root: &Path) -> PathBuf {
    app_data_root.join(VOTER_CAST_LOCKS_DIRECTORY_NAME)
}

/// Creates or validates the backend cast-locks directory. Rejects a symlink or
/// Windows reparse point.
///
/// # Errors
///
/// Returns a bounded error if the path is unsafe or cannot be created.
pub fn ensure_voter_cast_locks_directory_v1(cast_locks_dir: &Path) -> Result<(), GuiCoreError> {
    match fs::symlink_metadata(cast_locks_dir) {
        Ok(metadata) => {
            reject_path_indirection(&metadata)?;
            if !metadata.is_dir() {
                return Err(unsafe_cast_lock_path());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(cast_locks_dir)
                .map_err(|_| GuiCoreError::io_failure("cast-lock"))?;
            let metadata = fs::symlink_metadata(cast_locks_dir)
                .map_err(|_| GuiCoreError::io_failure("cast-lock"))?;
            reject_path_indirection(&metadata)?;
            if !metadata.is_dir() {
                return Err(unsafe_cast_lock_path());
            }
        }
        Err(_) => return Err(GuiCoreError::io_failure("cast-lock")),
    }
    restrict_directory_permissions(cast_locks_dir)
}

/// Computes a domain-separated BLAKE3 fingerprint of a public governance key,
/// as lowercase hex. Returns `None` if the hex is malformed.
///
/// The fingerprint is a purely local lookup key. Nothing that links elections
/// is exported or published.
#[must_use]
pub fn public_credential_fingerprint_hex_v1(public_key_hex: &str) -> Option<String> {
    let bytes = from_hex(public_key_hex)?;
    if bytes.is_empty() {
        return None;
    }
    let mut framed = Vec::with_capacity(FINGERPRINT_DOMAIN_V1.len() + bytes.len());
    framed.extend_from_slice(FINGERPRINT_DOMAIN_V1);
    framed.extend_from_slice(&bytes);
    Some(to_lower_hex(&Blake3HashProviderV1.hash(&framed)))
}

/// Returns `true` when any cast record file already exists for this pair. Used
/// to fail a fresh export closed before any state is written.
///
/// # Errors
///
/// Returns a bounded error only on an unexpected filesystem failure.
pub fn cast_record_exists_v1(
    cast_locks_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
) -> Result<bool, GuiCoreError> {
    let path = cast_record_path(
        cast_locks_dir,
        credential_fingerprint_hex,
        manifest_hash_hex,
    );
    match fs::symlink_metadata(&path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(GuiCoreError::io_failure("cast-lock")),
    }
}

/// Durably writes a `PENDING` cast record for the pair. Must be called only
/// after the ballot bytes are durably written and verified, and before the
/// final exported file is exposed.
///
/// # Errors
///
/// Returns a bounded error on encoding or filesystem failure.
pub fn write_cast_record_pending_v1(
    cast_locks_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
    package_digest_hex: &str,
    final_path: &Path,
    temp_path: &Path,
) -> Result<(), GuiCoreError> {
    let record = VoterCastRecordV1 {
        election_manifest_hash_hex: manifest_hash_hex.to_owned(),
        credential_fingerprint_hex: credential_fingerprint_hex.to_owned(),
        package_digest_hex: package_digest_hex.to_owned(),
        final_path: final_path.to_string_lossy().into_owned(),
        temp_path: temp_path.to_string_lossy().into_owned(),
        is_cast: false,
    };
    let path = cast_record_path(
        cast_locks_dir,
        credential_fingerprint_hex,
        manifest_hash_hex,
    );
    write_record_atomic(&path, &record)
}

/// Returns the durable staging path for the exact opaque online submission
/// envelope for this (election, credential) pair (not created).
#[must_use]
pub fn staged_release_envelope_path_v1(
    staging_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
) -> PathBuf {
    staging_dir.join(format!(
        "{credential_fingerprint_hex}-{manifest_hash_hex}{STAGED_ENVELOPE_FILE_SUFFIX}"
    ))
}

/// Returns the durable path where an authenticated collector receipt is
/// persisted for this pair (not created).
#[must_use]
pub fn release_receipt_evidence_path_v1(
    staging_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
) -> PathBuf {
    staging_dir.join(format!(
        "{credential_fingerprint_hex}-{manifest_hash_hex}{RELEASE_RECEIPT_FILE_SUFFIX}"
    ))
}

/// Durably stages the EXACT opaque submission envelope bytes before the online
/// release boundary is crossed, syncing the file and its directory entry.
///
/// The staged file holds only the already-encrypted opaque HPKE envelope: no
/// credential secret, passphrase, witness, nullifier, or plaintext ballot.
///
/// # Errors
///
/// Returns a bounded error on an oversized envelope or a filesystem failure.
pub fn stage_release_envelope_v1(
    staged_envelope_path: &Path,
    envelope_bytes: &[u8],
) -> Result<(), GuiCoreError> {
    if envelope_bytes.is_empty() || envelope_bytes.len() as u64 > MAX_STAGED_RELEASE_ENVELOPE_BYTES
    {
        return Err(GuiCoreError::new(
            "GUI_RELEASE_ENVELOPE_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("private-release"),
            "the staged submission envelope is empty or exceeds the bounded size",
        ));
    }
    write_record_bytes_atomic(staged_envelope_path, envelope_bytes)
}

/// Reads back the exact staged opaque envelope for a retry, rejecting a
/// missing, indirected, or oversized file. Retry retransmits these EXACT bytes;
/// it never re-seals or re-randomizes a different envelope.
///
/// # Errors
///
/// Returns a bounded error when the staged artifact is missing or unsafe, so
/// the caller stays `CAST_PENDING` (locked) rather than unlocking.
pub fn read_staged_release_envelope_v1(
    staged_envelope_path: &Path,
) -> Result<Vec<u8>, GuiCoreError> {
    let metadata =
        fs::symlink_metadata(staged_envelope_path).map_err(|_| missing_staged_envelope())?;
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_STAGED_RELEASE_ENVELOPE_BYTES
    {
        return Err(missing_staged_envelope());
    }
    fs::read(staged_envelope_path).map_err(|_| missing_staged_envelope())
}

fn missing_staged_envelope() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_RELEASE_ENVELOPE_UNAVAILABLE",
        GuiErrorCategory::FileIo,
        Some("private-release"),
        "the staged submission could not be read; your ballot remains cast-pending and can be retried",
    )
}

/// Durably persists the authenticated collector receipt bytes so a crash
/// between receiving the receipt and promoting to `CAST` can be recovered by
/// re-verifying the same receipt on restart.
///
/// # Errors
///
/// Returns a bounded error on an oversized receipt or a filesystem failure.
pub fn persist_release_receipt_evidence_v1(
    receipt_evidence_path: &Path,
    receipt_bytes: &[u8],
) -> Result<(), GuiCoreError> {
    if receipt_bytes.is_empty() || receipt_bytes.len() as u64 > MAX_CAST_RECORD_BYTES_V1 {
        return Err(GuiCoreError::new(
            "GUI_RELEASE_RECEIPT_INVALID",
            GuiErrorCategory::InvalidInput,
            Some("private-release"),
            "the authenticated receipt is empty or exceeds the bounded size",
        ));
    }
    write_record_bytes_atomic(receipt_evidence_path, receipt_bytes)
}

fn read_release_receipt_evidence(receipt_evidence_path: &Path) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(receipt_evidence_path).ok()?;
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_CAST_RECORD_BYTES_V1
    {
        return None;
    }
    fs::read(receipt_evidence_path).ok()
}

/// Durably writes a `PENDING` private-transport release record. Must be called
/// only after the exact opaque envelope is durably staged, and strictly before
/// the carrier is invoked (i.e. before any ballot bytes can leave the process).
///
/// # Errors
///
/// Returns a bounded error on a filesystem failure.
#[allow(clippy::too_many_arguments)]
pub fn write_cast_record_pending_private_transport_v1(
    cast_locks_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
    package_digest_hex: &str,
    staged_envelope_path: &Path,
    staged_envelope_digest_hex: &str,
    descriptor_fingerprint_hex: &str,
    receipt_evidence_path: &Path,
) -> Result<(), GuiCoreError> {
    let record = OnlineReleaseRecordV3 {
        election_manifest_hash_hex: manifest_hash_hex.to_owned(),
        credential_fingerprint_hex: credential_fingerprint_hex.to_owned(),
        package_digest_hex: package_digest_hex.to_owned(),
        staged_envelope_path: staged_envelope_path.to_string_lossy().into_owned(),
        staged_envelope_digest_hex: staged_envelope_digest_hex.to_owned(),
        descriptor_fingerprint_hex: descriptor_fingerprint_hex.to_owned(),
        receipt_evidence_path: receipt_evidence_path.to_string_lossy().into_owned(),
        is_cast: false,
    };
    let path = cast_record_path(
        cast_locks_dir,
        credential_fingerprint_hex,
        manifest_hash_hex,
    );
    write_online_record_atomic(&path, &record)
}

/// Non-secret metadata about a durable PENDING online release, for retry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReleaseRetryHandleV1 {
    pub staged_envelope_path: PathBuf,
    pub staged_envelope_digest_hex: String,
    pub descriptor_fingerprint_hex: String,
    pub package_digest_hex: String,
    pub receipt_evidence_path: PathBuf,
}

/// Loads the durable PENDING online release handle for a retry, if and only if
/// a non-terminal (`is_cast == false`) private-transport record exists for this
/// identity. Any other state (absent, malformed, offline, already CAST, or an
/// identity mismatch) yields `None`, and the caller must NOT unlock.
#[must_use]
pub fn load_pending_release_retry_handle_v1(
    cast_locks_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
) -> Option<PendingReleaseRetryHandleV1> {
    let path = cast_record_path(
        cast_locks_dir,
        credential_fingerprint_hex,
        manifest_hash_hex,
    );
    let RecordRead::ValidOnline(record) = read_cast_record(&path) else {
        return None;
    };
    if record.is_cast
        || record.election_manifest_hash_hex != manifest_hash_hex
        || record.credential_fingerprint_hex != credential_fingerprint_hex
    {
        return None;
    }
    Some(PendingReleaseRetryHandleV1 {
        staged_envelope_path: PathBuf::from(record.staged_envelope_path),
        staged_envelope_digest_hex: record.staged_envelope_digest_hex,
        descriptor_fingerprint_hex: record.descriptor_fingerprint_hex,
        package_digest_hex: record.package_digest_hex,
        receipt_evidence_path: PathBuf::from(record.receipt_evidence_path),
    })
}

/// Reads back the staged opaque envelope and verifies it is the EXACT, unaltered
/// artifact bound to this release before any carrier may transmit it:
///
/// 1. bounded read (regular file, no symlink/reparse, size cap);
/// 2. the domain-separated byte digest equals `expected_digest_hex` (the primary
///    exact-retry invariant);
/// 3. the bytes parse as a strictly canonical [`PrivateBallotEnvelopeV1`]
///    (rejects non-canonical / trailing garbage);
/// 4. every public binding the envelope exposes verifies against the current
///    trusted descriptor (manifest/election, descriptor fingerprint,
///    gateway/receiver key id, padding policy, ciphertext length) — defense in
///    depth on top of the byte digest. No HPKE ciphertext is decrypted here.
///
/// Any failure returns a bounded tamper error so the caller keeps the voter
/// `CAST_PENDING` and never transmits altered bytes or reseals a replacement.
///
/// # Errors
///
/// - `GUI_RELEASE_ENVELOPE_UNAVAILABLE` when the staged file is missing/unsafe.
/// - `GUI_RELEASE_ENVELOPE_TAMPERED` when the digest, canonical form, or a public
///   binding does not match the durable release.
pub fn read_and_verify_staged_release_envelope_v1(
    staged_envelope_path: &Path,
    expected_staged_envelope_digest_hex: &str,
    descriptor: &TransportDescriptorV1,
) -> Result<Vec<u8>, GuiCoreError> {
    let bytes = read_staged_release_envelope_v1(staged_envelope_path)?;
    if staged_release_envelope_digest_hex_v1(&bytes) != expected_staged_envelope_digest_hex {
        return Err(tampered_staged_envelope());
    }
    let envelope = PrivateBallotEnvelopeV1::from_canonical_cbor(&bytes)
        .map_err(|_| tampered_staged_envelope())?;
    // Public-binding defense in depth (no decryption): manifest/election,
    // descriptor fingerprint, gateway key id, padding policy, ciphertext length.
    envelope
        .receiver_opening_material(descriptor)
        .map_err(|_| tampered_staged_envelope())?;
    Ok(bytes)
}

fn tampered_staged_envelope() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_RELEASE_ENVELOPE_TAMPERED",
        GuiErrorCategory::BindingMismatch,
        Some("private-release"),
        "the staged submission no longer matches the pending release; it will not be sent and your ballot remains cast-pending",
    )
}

/// Descriptor-authenticated recovery for a private-transport release. Unlike the
/// generic resolver, this has the provisioned, already-trusted descriptor and
/// can promote a PENDING record to `CAST` when a durably persisted receipt
/// re-verifies. Fail-closed: any inability to prove the exact expected receipt
/// keeps the record `CAST_PENDING` (locked), never `NOT_CAST`.
///
/// The caller MUST have established descriptor trust (root-pinned, manifest and
/// election bound) before calling this.
///
/// # Errors
///
/// Returns a bounded error only on an unexpected filesystem failure reading the
/// record.
pub fn resolve_and_recover_private_transport_cast_lock_state_v1(
    cast_locks_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
    descriptor: &TransportDescriptorV1,
) -> Result<GuiVoterCastLockStateV1, GuiCoreError> {
    let path = cast_record_path(
        cast_locks_dir,
        credential_fingerprint_hex,
        manifest_hash_hex,
    );
    match read_cast_record(&path) {
        RecordRead::Absent => Ok(GuiVoterCastLockStateV1::NotCast),
        RecordRead::Malformed => Ok(GuiVoterCastLockStateV1::CastPending),
        // An offline record here is a kind/identity mismatch: fail closed.
        RecordRead::ValidOffline(_) => Ok(GuiVoterCastLockStateV1::CastPending),
        RecordRead::ValidOnline(record) => {
            if record.election_manifest_hash_hex != manifest_hash_hex
                || record.credential_fingerprint_hex != credential_fingerprint_hex
            {
                return Ok(GuiVoterCastLockStateV1::CastPending);
            }
            if record.is_cast {
                return Ok(GuiVoterCastLockStateV1::Cast);
            }
            if promote_online_record_if_receipt_valid(&path, &record, descriptor) {
                Ok(GuiVoterCastLockStateV1::Cast)
            } else {
                Ok(GuiVoterCastLockStateV1::CastPending)
            }
        }
    }
}

/// Returns true iff a durably persisted receipt authenticates the exact
/// expected release and the record was promoted to CAST in place. Fail-closed.
fn promote_online_record_if_receipt_valid(
    path: &Path,
    record: &OnlineReleaseRecordV3,
    descriptor: &TransportDescriptorV1,
) -> bool {
    if !authenticated_receipt_promotes_release(
        record,
        descriptor,
        &PathBuf::from(&record.receipt_evidence_path),
    ) {
        return false;
    }
    let mut promoted = record.clone();
    promoted.is_cast = true;
    write_online_record_atomic(path, &promoted).is_ok()
}

/// Pure-ish check that a persisted receipt authenticates promoting THIS release
/// to CAST: the descriptor fingerprint matches, the receipt parses and verifies
/// against a descriptor receipt key, its authenticated package digest matches
/// the recorded package, and it acknowledges an accepted/received delivery.
/// A rejected/duplicate receipt never promotes to CAST.
fn authenticated_receipt_promotes_release(
    record: &OnlineReleaseRecordV3,
    descriptor: &TransportDescriptorV1,
    receipt_evidence_path: &Path,
) -> bool {
    let Ok(descriptor_fingerprint) = descriptor.fingerprint() else {
        return false;
    };
    if to_lower_hex(&descriptor_fingerprint) != record.descriptor_fingerprint_hex {
        return false;
    }
    let Some(bytes) = read_release_receipt_evidence(receipt_evidence_path) else {
        return false;
    };
    let Ok(receipt) = AuthenticatedTransportReceiptV1::from_canonical_cbor(&bytes) else {
        return false;
    };
    // Bind to the exact descriptor of THIS pending release (defense in depth on
    // top of verify_for_descriptor, which also enforces the fingerprint).
    if to_lower_hex(&receipt.descriptor_fingerprint()) != record.descriptor_fingerprint_hex {
        return false;
    }
    if receipt.verify_for_descriptor(descriptor).is_err() {
        return false;
    }
    if to_lower_hex(&receipt.package_digest()) != record.package_digest_hex {
        return false;
    }
    matches!(
        receipt.receipt().state,
        VoterReceiptStateV1::Accepted | VoterReceiptStateV1::Received
    )
}

/// Promotes an existing record for the pair to the terminal `CAST` state. This
/// is monotonic; it never reopens a cast.
///
/// # Errors
///
/// Returns a bounded error if no readable pending/cast record exists or the
/// filesystem write fails.
pub fn promote_cast_record_to_cast_v1(
    cast_locks_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
) -> Result<(), GuiCoreError> {
    let path = cast_record_path(
        cast_locks_dir,
        credential_fingerprint_hex,
        manifest_hash_hex,
    );
    match read_cast_record(&path) {
        RecordRead::ValidOffline(mut record) => {
            record.is_cast = true;
            write_record_atomic(&path, &record)
        }
        RecordRead::ValidOnline(mut record) => {
            record.is_cast = true;
            write_online_record_atomic(&path, &record)
        }
        RecordRead::Absent | RecordRead::Malformed => Err(GuiCoreError::new(
            "GUI_CAST_LOCK_MISSING",
            GuiErrorCategory::FileIo,
            Some("cast-lock"),
            "no readable cast record was found to promote",
        )),
    }
}

/// Exposes an already-written, verified temp cast file under its final export
/// name WITHOUT ever replacing an existing target. Shared by immediate
/// cast-aware export and pending-cast recovery.
///
/// Uses [`std::fs::hard_link`], which fails atomically (`AlreadyExists`) when
/// the final path already exists rather than replacing it, and — because the
/// temp and final paths are siblings in one directory (one filesystem) —
/// exposes the exact already-synced ballot bytes under the final name. This
/// restores the atomic create-or-fail no-overwrite guarantee the original pure
/// export had via `create_new`, without the temp/rename TOCTOU that a
/// replacing rename would reintroduce.
///
/// On success the containing directory entry is synced and the now-redundant
/// temp link is removed (best effort). On collision or any other filesystem
/// error the temp is left intact and a bounded error is returned, so the caller
/// keeps the durable cast PENDING (locked) and recovery can finalize the SAME
/// ballot later.
///
/// # Errors
///
/// - `GUI_BALLOT_EXPORT_COLLISION` when the final path already exists; the
///   existing file is left byte-for-byte unchanged.
/// - `GUI_BALLOT_EXPORT_FINALIZE_FAILED` for any other filesystem error,
///   including a target filesystem without hard-link support.
pub fn finalize_verified_cast_temp_without_overwrite(
    temp_path: &Path,
    final_path: &Path,
) -> Result<(), GuiCoreError> {
    match fs::hard_link(temp_path, final_path) {
        Ok(()) => {
            if let Some(parent) = final_path.parent() {
                sync_directory_best_effort(parent);
            }
            // The final entry now exposes the ballot bytes; drop the temp link.
            let _ = fs::remove_file(temp_path);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(cast_export_collision())
        }
        Err(_) => Err(GuiCoreError::new(
            "GUI_BALLOT_EXPORT_FINALIZE_FAILED",
            GuiErrorCategory::FileIo,
            Some("export-ballot"),
            "the ballot could not be finalized to the chosen location; it remains cast-pending",
        )),
    }
}

fn cast_export_collision() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_BALLOT_EXPORT_COLLISION",
        GuiErrorCategory::FileIo,
        Some("export-ballot"),
        "For safety, ballot exports never overwrite an existing file. The existing file was left unchanged; your ballot remains locked and cast-pending.",
    )
}

/// Probes that the selected cast-export destination directory supports the
/// no-overwrite hard-link finalization used by the real export path, BEFORE
/// any durable cast state is written.
///
/// This is a preflight: it must run after basic path validation but strictly
/// before [`write_cast_record_pending_v1`]. On an unsupported destination
/// (e.g. a FAT32/exFAT removable drive, or a directory without link
/// permission) it returns a bounded error so the caller leaves the session
/// `NOT_CAST` with no `PENDING` record on disk, and the voter may choose
/// another location.
///
/// The probe never touches the voter's actual `final_path`. It runs TWO
/// distinct phases using uniquely-named throwaway files inside the destination
/// directory (via the `tempfile` crate, which uses OS randomness and
/// auto-removes its files on drop):
///
/// * **Phase A — actual hard-link capability.** Create a probe source, then
///   `hard_link(source, nonexistent_destination)` where the destination does
///   NOT exist. Only a real `Ok(())` (an actual link created) proves the
///   filesystem supports the primitive the real export path needs. An
///   `AlreadyExists` here is an extremely unlikely name collision (or a
///   non-conforming filesystem) and is NEVER treated as capability success.
/// * **Phase B — no-replace behavior.** `hard_link(source, existing_destination)`
///   against a probe-owned destination that already exists must return
///   `AlreadyExists` (never replace). If it unexpectedly succeeds, the
///   filesystem would replace an existing target and the probe fails closed.
///
/// # Errors
///
/// - `GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED` when the destination cannot
///   perform the required no-overwrite hard-link finalization (Phase A failed
///   with `Unsupported`/`PermissionDenied`, or Phase B unexpectedly replaced an
///   existing target).
/// - `GUI_BALLOT_EXPORT_PROBE_FAILED` for an unexpected probe I/O failure or
///   an ambiguous Phase A outcome (e.g. an unlikely probe-name collision).
/// - `GUI_FILE_NOT_FOUND` when the destination directory does not exist.
pub fn probe_cast_export_destination_supports_no_overwrite_v1(
    final_path: &Path,
) -> Result<(), GuiCoreError> {
    let Some(destination_dir) = final_path.parent() else {
        return Err(GuiCoreError::new(
            "GUI_BALLOT_EXPORT_DESTINATION_INVALID",
            GuiErrorCategory::FileIo,
            Some("export-ballot"),
            "the chosen export destination has no directory component",
        ));
    };

    // Probe source: a uniquely-named throwaway file in the destination dir.
    let probe_source = match NamedTempFile::new_in(destination_dir) {
        Ok(file) => file,
        Err(error) => return Err(classify_cast_destination_probe_failure_v1(&error)),
    };

    // Phase A destination: a unique path that does NOT exist at hard_link time.
    // Create a uniquely-named placeholder, capture its path, then drop it so the
    // path is free. `hard_link` itself is the atomic check, so a race that
    // recreates the name is caught by `hard_link` returning `AlreadyExists`,
    // which Phase A treats as a probe failure (never capability success).
    let phase_a_placeholder = match NamedTempFile::new_in(destination_dir) {
        Ok(file) => file,
        Err(error) => return Err(classify_cast_destination_probe_failure_v1(&error)),
    };
    let phase_a_path = phase_a_placeholder.path().to_path_buf();
    drop(phase_a_placeholder);

    // Phase A: actual hard-link creation to a nonexistent destination. Only a
    // real Ok(()) proves capability AND transfers ownership of the created
    // pathname to this probe. The cleanup guard is armed ONLY after Ok(()), so
    // if another process wins the pathname race (causing AlreadyExists), the
    // raced file is NEVER deleted by our cleanup. Before Ok(()), phase_a_path
    // is unowned and must not be touched.
    let _phase_a_guard = probe_phase_a_create_link_v1(probe_source.path(), &phase_a_path)?;

    // Phase B: a separate probe-owned destination that already exists.
    let phase_b_existing = match NamedTempFile::new_in(destination_dir) {
        Ok(file) => file,
        Err(error) => return Err(classify_cast_destination_probe_failure_v1(&error)),
    };
    // hard_link to an existing target must fail with AlreadyExists (no replace).
    let phase_b_result = fs::hard_link(probe_source.path(), phase_b_existing.path());
    classify_cast_destination_probe_phase_b_v1(&phase_b_result)?;
    // phase_b_existing and probe_source auto-remove on drop; _phase_a_guard
    // removes the Phase A link.
    Ok(())
}

/// Pure classification of the Phase A (real hard-link creation) outcome,
/// separable from I/O so the "AlreadyExists on the NEW destination is NOT
/// capability success" guarantee is unit-testable without a fake filesystem.
///
/// * `Ok(())` — a real link was created → capability proven.
/// * `Err(AlreadyExists)` — unlikely name collision or non-conforming FS →
///   probe failure (never success).
/// * `Err(Unsupported)`/`Err(PermissionDenied)` → destination unsupported.
/// * other `Err` → unexpected probe failure.
pub fn classify_cast_destination_probe_phase_a_v1(
    result: &std::io::Result<()>,
) -> Result<(), GuiCoreError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(cast_export_destination_probe_failed())
        }
        Err(error) => Err(classify_cast_destination_probe_failure_v1(error)),
    }
}

/// Pure classification of the Phase B (no-replace) outcome, separable from I/O
/// so the no-overwrite guarantee is unit-testable without a fake filesystem.
///
/// * `Err(AlreadyExists)` — existing target was NOT replaced → success.
/// * `Ok(())` — the filesystem would REPLACE an existing target → fail closed
///   as unsupported (a no-overwrite violation must never be allowed).
/// * other `Err` → unexpected probe failure / unsupported.
pub fn classify_cast_destination_probe_phase_b_v1(
    result: &std::io::Result<()>,
) -> Result<(), GuiCoreError> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Ok(()) => Err(cast_export_destination_unsupported()),
        Err(error) => Err(classify_cast_destination_probe_failure_v1(error)),
    }
}

/// Owns a hard link created by the Phase A probe and removes it on drop
/// (best-effort). Constructed ONLY after [`fs::hard_link`] returns `Ok(())`, so
/// it never owns a pathname this process did not create. Public so the Phase A
/// ownership invariant is deterministically testable without a fake filesystem.
pub struct ProbePhaseALinkGuardV1 {
    path: Option<PathBuf>,
}

impl ProbePhaseALinkGuardV1 {
    /// Returns a guard that will remove `path` on drop. Private — only
    /// [`probe_phase_a_create_link_v1`] constructs this, and only after a
    /// successful `hard_link`.
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }
}

impl Drop for ProbePhaseALinkGuardV1 {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(&path);
        }
    }
}

/// Phase A of the destination capability probe: attempt
/// `hard_link(source, nonexistent_destination)` and require `Ok(())`.
///
/// Only a real `Ok(())` proves the destination filesystem supports the
/// no-overwrite hard-link primitive the real export path needs. On success,
/// returns a [`ProbePhaseALinkGuardV1`] that owns and removes the created link
/// on drop (including panic/unwind). On any `Err` (including `AlreadyExists`
/// from a raced pathname), returns a bounded error WITHOUT touching the
/// destination — a raced unrelated file is never deleted by this probe.
///
/// The cleanup guard is armed ONLY after `Ok(())`. Before that point, the
/// destination pathname may be a raced unrelated file this process did not
/// create, and the ownership rule "no delete without proven creation by this
/// process" forbids removing it.
///
/// Exposed as a separate public helper so the Phase A pathname-race cleanup
/// invariant is deterministically testable without multiprocessing or a fake
/// filesystem: a test can pre-create a sentinel at the destination path and
/// assert Phase A fails and leaves the sentinel byte-for-byte unchanged.
pub fn probe_phase_a_create_link_v1(
    probe_source: &Path,
    phase_a_destination: &Path,
) -> Result<ProbePhaseALinkGuardV1, GuiCoreError> {
    let result = fs::hard_link(probe_source, phase_a_destination);
    classify_cast_destination_probe_phase_a_v1(&result)?;
    // Ok(()): this process created phase_a_destination. Now — and only now —
    // we own it and may clean it up. Before this point, phase_a_destination may
    // be a raced unrelated file and must not be deleted.
    Ok(ProbePhaseALinkGuardV1::new(
        phase_a_destination.to_path_buf(),
    ))
}

/// Maps a destination-probe I/O failure to a bounded user-facing error. Pure
/// (no I/O), so the classification is deterministic and unit-testable with
/// synthetic [`std::io::Error`]s. Public so the cast-export integration tests
/// can prove each error kind maps to the correct user-facing code.
pub fn classify_cast_destination_probe_failure_v1(error: &std::io::Error) -> GuiCoreError {
    match error.kind() {
        std::io::ErrorKind::Unsupported => cast_export_destination_unsupported(),
        std::io::ErrorKind::PermissionDenied => cast_export_destination_unsupported(),
        std::io::ErrorKind::NotFound => GuiCoreError::file_not_found("export-ballot"),
        std::io::ErrorKind::AlreadyExists => cast_export_destination_probe_failed(),
        _ => cast_export_destination_probe_failed(),
    }
}

fn cast_export_destination_unsupported() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_BALLOT_EXPORT_DESTINATION_UNSUPPORTED",
        GuiErrorCategory::FileIo,
        Some("export-ballot"),
        "This location does not support the safe ballot finalization required by Private Ballot. Choose another location, such as a local NTFS folder.",
    )
}

fn cast_export_destination_probe_failed() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_BALLOT_EXPORT_PROBE_FAILED",
        GuiErrorCategory::FileIo,
        Some("export-ballot"),
        "Private Ballot could not verify the chosen location supports safe ballot finalization. Choose another location, such as a local NTFS folder.",
    )
}

/// Resolves the durable cast state for a pair, performing safe, idempotent
/// crash recovery of a `PENDING` record when possible.
///
/// Recovery semantics (fail closed): a present-but-unreadable record, or a
/// pending record whose ballot cannot be safely finalized, resolves to
/// [`GuiVoterCastLockStateV1::CastPending`] (locked) — never `NotCast`.
///
/// # Errors
///
/// Returns a bounded error only on an unexpected filesystem failure while
/// checking for the record.
pub fn resolve_and_recover_cast_lock_state_v1(
    cast_locks_dir: &Path,
    manifest_hash_hex: &str,
    credential_fingerprint_hex: &str,
    artifacts: &GuiElectionArtifactsV1,
) -> Result<GuiVoterCastLockStateV1, GuiCoreError> {
    let path = cast_record_path(
        cast_locks_dir,
        credential_fingerprint_hex,
        manifest_hash_hex,
    );
    match read_cast_record(&path) {
        RecordRead::Absent => Ok(GuiVoterCastLockStateV1::NotCast),
        // Present but not safely interpretable: never unlock.
        RecordRead::Malformed => Ok(GuiVoterCastLockStateV1::CastPending),
        RecordRead::ValidOffline(record) => {
            // Defensive: the record content must match the requested identity.
            if record.election_manifest_hash_hex != manifest_hash_hex
                || record.credential_fingerprint_hex != credential_fingerprint_hex
            {
                return Ok(GuiVoterCastLockStateV1::CastPending);
            }
            if record.is_cast {
                return Ok(GuiVoterCastLockStateV1::Cast);
            }
            Ok(recover_pending_record(&path, &record, artifacts))
        }
        RecordRead::ValidOnline(record) => {
            // A private-transport record cannot be safely finalized here: this
            // generic resolver has no descriptor/root to authenticate a
            // persisted receipt with. Fail closed to CAST_PENDING (locked) for
            // any non-terminal online record; a caller that has the provisioned
            // descriptor uses
            // `resolve_and_recover_private_transport_cast_lock_state_v1` to
            // promote it. A terminal CAST record stays terminal.
            if record.election_manifest_hash_hex != manifest_hash_hex
                || record.credential_fingerprint_hex != credential_fingerprint_hex
            {
                return Ok(GuiVoterCastLockStateV1::CastPending);
            }
            if record.is_cast {
                Ok(GuiVoterCastLockStateV1::Cast)
            } else {
                Ok(GuiVoterCastLockStateV1::CastPending)
            }
        }
    }
}

/// Attempts to finalize a durable `PENDING` record. Idempotent and fail-closed:
/// on any inability to prove the exact expected ballot, the record stays pending
/// (the voter remains locked), never unlocked.
fn recover_pending_record(
    path: &Path,
    record: &VoterCastRecordV1,
    artifacts: &GuiElectionArtifactsV1,
) -> GuiVoterCastLockStateV1 {
    let final_path = Path::new(&record.final_path);
    let temp_path = Path::new(&record.temp_path);

    // Boundary D: the final file already exists. Promote iff its digest matches
    // the recorded ballot. A non-matching final (an unrelated collision) is
    // never overwritten or deleted; the cast stays pending and the temp is
    // preserved for a later retry once that unrelated file is gone.
    if final_path.exists() {
        if package_digest_hex_of_file(final_path, artifacts).as_deref()
            == Some(record.package_digest_hex.as_str())
            && promote_record_in_place(path, record).is_ok()
        {
            // Both names may point at the same ballot after a crash between
            // exposure and temp cleanup; drop the redundant temp link.
            let _ = fs::remove_file(temp_path);
            return GuiVoterCastLockStateV1::Cast;
        }
        return GuiVoterCastLockStateV1::CastPending;
    }

    // Boundary C: the verified temp exists but was not yet exposed as final.
    // Finalize WITHOUT overwriting (hard link, never a replacing rename); if a
    // colliding final appeared meanwhile, this fails and the cast stays pending.
    if temp_path.exists()
        && package_digest_hex_of_file(temp_path, artifacts).as_deref()
            == Some(record.package_digest_hex.as_str())
        && finalize_verified_cast_temp_without_overwrite(temp_path, final_path).is_ok()
        && promote_record_in_place(path, record).is_ok()
    {
        return GuiVoterCastLockStateV1::Cast;
    }

    // Neither file can be safely finalized: stay locked (fail closed).
    GuiVoterCastLockStateV1::CastPending
}

fn promote_record_in_place(path: &Path, record: &VoterCastRecordV1) -> Result<(), GuiCoreError> {
    let mut promoted = record.clone();
    promoted.is_cast = true;
    write_record_atomic(path, &promoted)
}

/// Parses a ballot file and returns its canonical package digest as lowercase
/// hex, or `None` if the file is missing, unsafe, oversized, or not a valid
/// manifest-bound package. No proof-secret material is exposed.
fn package_digest_hex_of_file(path: &Path, artifacts: &GuiElectionArtifactsV1) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
        || metadata.len() > MAX_BALLOT_PACKAGE_BYTES_V1 as u64
    {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let package = BallotPackageV1::from_canonical_cbor(
        &bytes,
        artifacts.candidates(),
        artifacts.manifest().approval_limits(),
    )
    .ok()?;
    package
        .validate_manifest_binding(
            artifacts.manifest_hash(),
            artifacts.manifest().proof_suite_id(),
        )
        .ok()?;
    let digest = package.canonical_hash(&Blake3HashProviderV1).ok()?;
    Some(to_lower_hex(&digest))
}

fn cast_record_path(
    cast_locks_dir: &Path,
    credential_fingerprint_hex: &str,
    manifest_hash_hex: &str,
) -> PathBuf {
    cast_locks_dir.join(format!(
        "{credential_fingerprint_hex}-{manifest_hash_hex}{CAST_RECORD_FILE_SUFFIX}"
    ))
}

enum RecordRead {
    Absent,
    Malformed,
    ValidOffline(VoterCastRecordV1),
    ValidOnline(OnlineReleaseRecordV3),
}

fn read_cast_record(path: &Path) -> RecordRead {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return RecordRead::Absent,
        // An existing-but-unreadable record must fail closed, not unlock.
        Err(_) => return RecordRead::Malformed,
    };
    if metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
        || !metadata.is_file()
        || metadata.len() > MAX_CAST_RECORD_BYTES_V1
    {
        return RecordRead::Malformed;
    }
    let Ok(bytes) = fs::read(path) else {
        return RecordRead::Malformed;
    };
    // Offline (V1) and private-transport (V2) records use distinct magics, so
    // the two decoders never overlap. An old offline record still decodes here
    // byte-for-byte unchanged.
    if let Some(record) = VoterCastRecordV1::decode(&bytes) {
        return RecordRead::ValidOffline(record);
    }
    if let Some(record) = OnlineReleaseRecordV3::decode(&bytes) {
        return RecordRead::ValidOnline(record);
    }
    RecordRead::Malformed
}

fn write_record_atomic(path: &Path, record: &VoterCastRecordV1) -> Result<(), GuiCoreError> {
    write_record_bytes_atomic(path, &record.encode())
}

fn write_online_record_atomic(
    path: &Path,
    record: &OnlineReleaseRecordV3,
) -> Result<(), GuiCoreError> {
    write_record_bytes_atomic(path, &record.encode())
}

fn write_record_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<(), GuiCoreError> {
    let tmp_path = path.with_extension("castlock-tmp");
    let _ = fs::remove_file(&tmp_path);
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|_| GuiCoreError::io_failure("cast-lock"))?;
        file.write_all(bytes)
            .map_err(|_| GuiCoreError::io_failure("cast-lock"))?;
        file.flush()
            .map_err(|_| GuiCoreError::io_failure("cast-lock"))?;
        file.sync_all()
            .map_err(|_| GuiCoreError::io_failure("cast-lock"))?;
    }
    if fs::rename(&tmp_path, path).is_err() {
        let _ = fs::remove_file(&tmp_path);
        return Err(GuiCoreError::io_failure("cast-lock"));
    }
    if let Some(parent) = path.parent() {
        sync_directory_best_effort(parent);
    }
    Ok(())
}

fn sync_directory_best_effort(path: &Path) {
    if let Ok(dir) = fs::File::open(path) {
        let _ = dir.sync_all();
    }
}

fn reject_path_indirection(metadata: &fs::Metadata) -> Result<(), GuiCoreError> {
    if metadata.file_type().is_symlink() || is_windows_reparse_point(metadata) {
        return Err(unsafe_cast_lock_path());
    }
    Ok(())
}

#[cfg(windows)]
fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_windows_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn restrict_directory_permissions(path: &Path) -> Result<(), GuiCoreError> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = fs::metadata(path)
        .map_err(|_| GuiCoreError::io_failure("cast-lock"))?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).map_err(|_| GuiCoreError::io_failure("cast-lock"))
}

#[cfg(not(unix))]
fn restrict_directory_permissions(_path: &Path) -> Result<(), GuiCoreError> {
    Ok(())
}

fn unsafe_cast_lock_path() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_CAST_LOCK_UNSAFE_PATH",
        GuiErrorCategory::FileIo,
        Some("cast-lock"),
        "the cast-lock path is not a safe direct directory",
    )
}
