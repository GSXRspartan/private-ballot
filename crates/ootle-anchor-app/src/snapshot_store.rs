//! Canonical, versioned, digest-bearing durable encoding of
//! [`AnchorLifecycleRecoverySnapshot`] (Slice 4A10).
//!
//! The on-disk envelope is a canonical CBOR definite-length 4-element array:
//!
//! 1. record-type / version text ([`SNAPSHOT_RECORD_TYPE_ID_V1`]);
//! 2. hash-algorithm identifier text ([`SNAPSHOT_HASH_ALGORITHM_ID_V1`]);
//! 3. body digest as exactly 32 bytes;
//! 4. canonical body bytes.
//!
//! The body is a canonical CBOR definite-length 6-element array (see
//! [`encode_body`] / [`decode_body`]). The body digest is a domain-separated
//! BLAKE3 hash using [`SNAPSHOT_FRAME_PREFIX_V1`] and
//! [`SNAPSHOT_DOMAIN_LABEL_V1`], which are deliberately distinct from the
//! protocol, anchor-record, transaction-inspection, and evidence-record frames.
//!
//! # Reconciliation note
//!
//! The protocol crate's canonical CBOR subset ([`CanonicalCborWriter`] /
//! [`CanonicalCborReader`]) has no `null` token. Optional fields are therefore
//! encoded as a definite-length 0-element array (`None`) or 1-element array
//! (`Some(value)`), which is deterministic, canonical, and unambiguous. This
//! deviates from the prose "null" in the slice brief but is forced by the
//! pinned protocol subset; no other CBOR encoder is introduced.

use std::path::Path;

use tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorFinalStatusV1, AnchorLogPayloadV1, AnchorRequestId,
    AnchorTransactionId,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleRecoverySnapshot, PollingPolicy, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    AnchorReceiptQuerySnapshotV1, AnchorReceiptQueryStateV1, AnchorReceiptQueryV1,
    TRANSACTION_ID_HEX_LEN,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    SubmittedWalletdAnchorRequestV1, WalletdAnchorBindingV1, WalletdAnchorSnapshotV1,
    WalletdEffectiveStatusV1, WalletdRequestDecisionV1, WalletdRequestId, WalletdSubmissionStateV1,
};
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, Blake3HashProviderV1, CanonicalCborReader,
    CanonicalCborWriter, HashProvider, ProtocolError, ValidationCode,
};

/// Maximum encoded snapshot file size (envelope + body).
pub const MAX_SNAPSHOT_FILE_BYTES: usize = 65_536;

/// Stable record-type / version identifier for the snapshot envelope.
pub const SNAPSHOT_RECORD_TYPE_ID_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_LIFECYCLE_SNAPSHOT_V1";

/// Hash-algorithm identifier written into the snapshot envelope.
pub const SNAPSHOT_HASH_ALGORITHM_ID_V1: &str = BLAKE3_256_HASH_ALGORITHM_ID_V1;

/// Domain-separation frame prefix for snapshot body digests.
pub const SNAPSHOT_FRAME_PREFIX_V1: &[u8] =
    b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_LIFECYCLE_SNAPSHOT_FRAME_V1";

/// Domain label for snapshot body digests.
pub const SNAPSHOT_DOMAIN_LABEL_V1: &str =
    "tari-cc-private-ballot/ootle-anchor-lifecycle-snapshot/v1";

const ENVELOPE_FIELD_COUNT: usize = 4;
const BODY_FIELD_COUNT: usize = 6;
const WALLETD_SNAPSHOT_FIELD_COUNT: usize = 10;
const BINDING_FIELD_COUNT: usize = 6;
const RECEIPT_SNAPSHOT_FIELD_COUNT: usize = 6;
const QUERY_FIELD_COUNT: usize = 8;
const SUBMITTED_HANDLE_FIELD_COUNT: usize = 4;
const POLICY_FIELD_COUNT: usize = 2;

/// Bounded failure while reading or writing a durable snapshot file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotFileError {
    /// No snapshot file was present at the path.
    FileNotFound,
    /// A filesystem I/O failure occurred.
    IoFailure,
    /// The atomic rename could not complete.
    AtomicRenameFailure,
    /// The record-type / version string was unsupported.
    UnsupportedProtocolVersion,
    /// The hash-algorithm identifier was unsupported.
    UnsupportedHashAlgorithm,
    /// The CBOR was structurally invalid.
    InvalidCbor,
    /// The CBOR used a non-canonical (non-shortest) encoding.
    NonCanonicalCbor,
    /// An unexpected CBOR major type was encountered.
    UnexpectedCborType,
    /// Trailing bytes remained after the decoded value.
    TrailingCborData,
    /// The encoded size exceeded [`MAX_SNAPSHOT_FILE_BYTES`].
    ProtocolLimitExceeded,
    /// A field value was invalid (unknown vocabulary, bad identifier, etc.).
    InvalidData,
    /// The recorded body digest did not match the recomputed digest.
    SnapshotDigestMismatch,
}

impl SnapshotFileError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FileNotFound => "SNAPSHOT_FILE_NOT_FOUND",
            Self::IoFailure => "SNAPSHOT_IO_FAILURE",
            Self::AtomicRenameFailure => "SNAPSHOT_ATOMIC_RENAME_FAILURE",
            Self::UnsupportedProtocolVersion => "SNAPSHOT_UNSUPPORTED_PROTOCOL_VERSION",
            Self::UnsupportedHashAlgorithm => "SNAPSHOT_UNSUPPORTED_HASH_ALGORITHM",
            Self::InvalidCbor => "SNAPSHOT_INVALID_CBOR",
            Self::NonCanonicalCbor => "SNAPSHOT_NON_CANONICAL_CBOR",
            Self::UnexpectedCborType => "SNAPSHOT_UNEXPECTED_CBOR_TYPE",
            Self::TrailingCborData => "SNAPSHOT_TRAILING_CBOR_DATA",
            Self::ProtocolLimitExceeded => "SNAPSHOT_PROTOCOL_LIMIT_EXCEEDED",
            Self::InvalidData => "SNAPSHOT_INVALID_DATA",
            Self::SnapshotDigestMismatch => "SNAPSHOT_DIGEST_MISMATCH",
        }
    }
}

impl core::fmt::Display for SnapshotFileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for SnapshotFileError {}

fn from_protocol(error: ProtocolError) -> SnapshotFileError {
    match error.code() {
        ValidationCode::UnsupportedProtocolVersion => SnapshotFileError::UnsupportedProtocolVersion,
        ValidationCode::UnsupportedHashAlgorithm => SnapshotFileError::UnsupportedHashAlgorithm,
        ValidationCode::InvalidCbor => SnapshotFileError::InvalidCbor,
        ValidationCode::NonCanonicalCbor => SnapshotFileError::NonCanonicalCbor,
        ValidationCode::UnexpectedCborType => SnapshotFileError::UnexpectedCborType,
        ValidationCode::TrailingCborData => SnapshotFileError::TrailingCborData,
        ValidationCode::ProtocolLimitExceeded => SnapshotFileError::ProtocolLimitExceeded,
        _ => SnapshotFileError::InvalidData,
    }
}

fn io_not_found(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::NotFound
}

/// Writes `snapshot` to `path` atomically.
///
/// Bytes are written to `<path>.tmp`, flushed, `sync_all`-ed, and then renamed
/// to `path` on the same filesystem. A failure before the rename leaves the
/// previous target (if any) intact.
///
/// # Errors
///
/// Returns a bounded [`SnapshotFileError`] on any failure; no OS or
/// third-party error text is leaked.
pub fn write_snapshot_atomic(
    path: &Path,
    snapshot: &AnchorLifecycleRecoverySnapshot,
) -> Result<(), SnapshotFileError> {
    let body = encode_body(snapshot)?;
    let envelope = encode_envelope(&body)?;
    if envelope.len() > MAX_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotFileError::ProtocolLimitExceeded);
    }
    let mut tmp = std::ffi::OsString::from(path.as_os_str());
    tmp.push(".tmp");
    let tmp_path = Path::new(&tmp);
    let cleanup = |p: &Path| {
        let _ = std::fs::remove_file(p);
    };
    let result = (|| -> Result<(), SnapshotFileError> {
        let mut file = std::fs::File::create(tmp_path).map_err(|_| SnapshotFileError::IoFailure)?;
        use std::io::Write;
        file.write_all(&envelope)
            .map_err(|_| SnapshotFileError::IoFailure)?;
        file.flush().map_err(|_| SnapshotFileError::IoFailure)?;
        file.sync_all().map_err(|_| SnapshotFileError::IoFailure)?;
        drop(file);
        std::fs::rename(tmp_path, path).map_err(|_| SnapshotFileError::AtomicRenameFailure)
    })();
    if result.is_err() {
        cleanup(tmp_path);
    }
    result
}

/// Reads and decodes a snapshot from `path`.
///
/// # Errors
///
/// Returns a bounded [`SnapshotFileError`] on any failure.
pub fn read_snapshot(path: &Path) -> Result<AnchorLifecycleRecoverySnapshot, SnapshotFileError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if io_not_found(&error) => return Err(SnapshotFileError::FileNotFound),
        Err(_) => return Err(SnapshotFileError::IoFailure),
    };
    if bytes.len() > MAX_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotFileError::ProtocolLimitExceeded);
    }
    decode_envelope(&bytes)
}

/// Computes the canonical body digest of `snapshot` without writing it.
///
/// The application uses this to bind the evidence record to the exact snapshot
/// it persisted.
///
/// # Errors
///
/// Returns a bounded [`SnapshotFileError`] on encoding failure.
pub fn snapshot_digest(
    snapshot: &AnchorLifecycleRecoverySnapshot,
) -> Result<[u8; 32], SnapshotFileError> {
    let body = encode_body(snapshot)?;
    let framed = snapshot_domain_input(&body);
    Ok(Blake3HashProviderV1.hash(&framed))
}

fn encode_envelope(body: &[u8]) -> Result<Vec<u8>, SnapshotFileError> {
    let framed = snapshot_domain_input(body);
    let digest = Blake3HashProviderV1.hash(&framed);
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(ENVELOPE_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(SNAPSHOT_RECORD_TYPE_ID_V1)
        .map_err(from_protocol)?;
    writer
        .write_text_string(SNAPSHOT_HASH_ALGORITHM_ID_V1)
        .map_err(from_protocol)?;
    writer.write_byte_string(&digest).map_err(from_protocol)?;
    writer.write_byte_string(body).map_err(from_protocol)?;
    Ok(writer.into_bytes())
}

fn decode_envelope(bytes: &[u8]) -> Result<AnchorLifecycleRecoverySnapshot, SnapshotFileError> {
    let mut reader = CanonicalCborReader::new(bytes);
    if reader.read_array_len().map_err(from_protocol)? != ENVELOPE_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }
    if reader.read_text_string().map_err(from_protocol)? != SNAPSHOT_RECORD_TYPE_ID_V1 {
        return Err(SnapshotFileError::UnsupportedProtocolVersion);
    }
    if reader.read_text_string().map_err(from_protocol)? != SNAPSHOT_HASH_ALGORITHM_ID_V1 {
        return Err(SnapshotFileError::UnsupportedHashAlgorithm);
    }
    let recorded_digest = read_digest(&mut reader)?;
    let body = reader.read_byte_string().map_err(from_protocol)?;
    reader.finish().map_err(from_protocol)?;
    if body.len() > MAX_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotFileError::ProtocolLimitExceeded);
    }
    let framed = snapshot_domain_input(body);
    let recomputed = Blake3HashProviderV1.hash(&framed);
    if recomputed != recorded_digest {
        return Err(SnapshotFileError::SnapshotDigestMismatch);
    }
    decode_body(body)
}

fn snapshot_domain_input(body: &[u8]) -> Vec<u8> {
    let label = SNAPSHOT_DOMAIN_LABEL_V1.as_bytes();
    let mut framed =
        Vec::with_capacity(SNAPSHOT_FRAME_PREFIX_V1.len() + 1 + label.len() + 1 + body.len());
    framed.extend_from_slice(SNAPSHOT_FRAME_PREFIX_V1);
    framed.push(0);
    framed.extend_from_slice(label);
    framed.push(0);
    framed.extend_from_slice(body);
    framed
}

fn encode_body(snapshot: &AnchorLifecycleRecoverySnapshot) -> Result<Vec<u8>, SnapshotFileError> {
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(BODY_FIELD_COUNT)
        .map_err(from_protocol)?;

    // 1. walletd snapshots
    let walletd = snapshot.walletd_snapshots();
    writer
        .write_array_len(walletd.len())
        .map_err(from_protocol)?;
    for item in walletd {
        encode_walletd_snapshot(&mut writer, item)?;
    }

    // 2. receipt snapshots
    let receipts = snapshot.receipt_snapshots();
    writer
        .write_array_len(receipts.len())
        .map_err(from_protocol)?;
    for item in receipts {
        encode_receipt_snapshot(&mut writer, item)?;
    }

    // 3. optional submitted handle
    match snapshot.submitted() {
        Some(submitted) => {
            writer.write_array_len(1).map_err(from_protocol)?;
            encode_submitted_handle(&mut writer, submitted)?;
        }
        None => {
            writer.write_array_len(0).map_err(from_protocol)?;
        }
    }

    // 4. polling policy
    let policy = snapshot.policy();
    writer
        .write_array_len(POLICY_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer.write_unsigned(u64::from(policy.max_query_attempts()));
    writer.write_unsigned(u64::from(policy.attempts_consumed()));

    // 5. unified phase
    writer
        .write_text_string(snapshot.phase().as_str())
        .map_err(from_protocol)?;

    // 6. optional diagnostic
    encode_option_text(&mut writer, snapshot.diagnostic())?;

    Ok(writer.into_bytes())
}

fn decode_body(body: &[u8]) -> Result<AnchorLifecycleRecoverySnapshot, SnapshotFileError> {
    let mut reader = CanonicalCborReader::new(body);
    if reader.read_array_len().map_err(from_protocol)? != BODY_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }

    // 1. walletd snapshots
    let walletd_count = reader.read_array_len().map_err(from_protocol)?;
    if walletd_count > MAX_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotFileError::ProtocolLimitExceeded);
    }
    let mut walletd_snapshots = Vec::with_capacity(walletd_count);
    for _ in 0..walletd_count {
        walletd_snapshots.push(decode_walletd_snapshot(&mut reader)?);
    }

    // 2. receipt snapshots
    let receipt_count = reader.read_array_len().map_err(from_protocol)?;
    if receipt_count > MAX_SNAPSHOT_FILE_BYTES {
        return Err(SnapshotFileError::ProtocolLimitExceeded);
    }
    let mut receipt_intermediates = Vec::with_capacity(receipt_count);
    for _ in 0..receipt_count {
        receipt_intermediates.push(decode_receipt_snapshot_raw(&mut reader)?);
    }

    // 3. optional submitted handle
    let submitted = decode_option(&mut reader, decode_submitted_handle)?;

    // 4. polling policy
    if reader.read_array_len().map_err(from_protocol)? != POLICY_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }
    let max_query_attempts = read_u32(&mut reader)?;
    let attempts_consumed = read_u32(&mut reader)?;
    let policy = PollingPolicy::from_consumed(max_query_attempts, attempts_consumed);

    // 5. unified phase
    let phase_text = reader.read_text_string().map_err(from_protocol)?;
    let phase = phase_from_str(phase_text).ok_or(SnapshotFileError::InvalidData)?;

    // 6. optional diagnostic
    let diagnostic = decode_option_diagnostic(&mut reader)?;

    reader.finish().map_err(from_protocol)?;

    // Reconstruct receipt snapshots: each requires a submitted handle.
    let mut receipt_snapshots = Vec::with_capacity(receipt_intermediates.len());
    for raw in receipt_intermediates {
        let Some(submitted) = &submitted else {
            return Err(SnapshotFileError::InvalidData);
        };
        let query = AnchorReceiptQueryV1::from_submitted(submitted);
        verify_query_matches_raw(&query, &raw.query_raw)?;
        let query_state =
            query_state_from_str(&raw.query_state).ok_or(SnapshotFileError::InvalidData)?;
        let last_final_status = match raw.last_final_status.as_deref() {
            None => None,
            Some(text) => Some(final_status_from_str(text).ok_or(SnapshotFileError::InvalidData)?),
        };
        let last_diagnostic = match raw.last_diagnostic.as_deref() {
            None => None,
            Some(text) => Some(diagnostic_from_str(text).ok_or(SnapshotFileError::InvalidData)?),
        };
        receipt_snapshots.push(AnchorReceiptQuerySnapshotV1::new(
            query,
            query_state,
            last_final_status,
            raw.verified,
            raw.sequence,
            last_diagnostic,
        ));
    }

    Ok(AnchorLifecycleRecoverySnapshot::new(
        walletd_snapshots,
        receipt_snapshots,
        submitted,
        policy,
        phase,
        diagnostic,
    ))
}

// ---------------------------------------------------------------------------
// Walletd snapshot
// ---------------------------------------------------------------------------

fn encode_walletd_snapshot(
    writer: &mut CanonicalCborWriter,
    snapshot: &WalletdAnchorSnapshotV1,
) -> Result<(), SnapshotFileError> {
    writer
        .write_array_len(WALLETD_SNAPSHOT_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(snapshot.project_request_id().as_str())
        .map_err(from_protocol)?;
    writer.write_unsigned(snapshot.walletd_request_id().value() as u32 as u64);
    encode_binding(writer, snapshot.binding())?;
    writer
        .write_text_string(snapshot.decision().as_str())
        .map_err(from_protocol)?;
    writer
        .write_text_string(snapshot.submission().as_str())
        .map_err(from_protocol)?;
    encode_option_text(writer, snapshot.transaction_id().map(|t| t.as_str()))?;
    encode_option_text(writer, snapshot.last_effective_status().map(|s| s.as_str()))?;
    writer.write_unsigned(u64::from(snapshot.retry_count()));
    writer.write_unsigned(snapshot.sequence());
    encode_option_text(writer, snapshot.last_diagnostic())?;
    Ok(())
}

fn decode_walletd_snapshot(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<WalletdAnchorSnapshotV1, SnapshotFileError> {
    if reader.read_array_len().map_err(from_protocol)? != WALLETD_SNAPSHOT_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }
    let project_request_id =
        AnchorRequestId::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| SnapshotFileError::InvalidData)?;
    let walletd_request_id = WalletdRequestId::from_walletd(read_i32(reader)?);
    let binding = decode_binding(reader)?;
    let decision = decision_from_str(reader.read_text_string().map_err(from_protocol)?)
        .ok_or(SnapshotFileError::InvalidData)?;
    let submission = submission_state_from_str(reader.read_text_string().map_err(from_protocol)?)
        .ok_or(SnapshotFileError::InvalidData)?;
    let transaction_id = decode_option(reader, decode_transaction_id)?;
    let last_effective_status = decode_option(reader, decode_effective_status)?;
    let retry_count = read_u32(reader)?;
    let sequence = reader.read_unsigned().map_err(from_protocol)?;
    let last_diagnostic = decode_option_diagnostic(reader)?;

    Ok(WalletdAnchorSnapshotV1::new(
        project_request_id,
        walletd_request_id,
        binding,
        decision,
        submission,
        transaction_id,
        last_effective_status,
        retry_count,
        sequence,
        last_diagnostic,
    ))
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

fn encode_binding(
    writer: &mut CanonicalCborWriter,
    binding: &WalletdAnchorBindingV1,
) -> Result<(), SnapshotFileError> {
    writer
        .write_array_len(BINDING_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(binding.network().as_str())
        .map_err(from_protocol)?;
    writer
        .write_text_string(binding.account().as_str())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(binding.anchor_digest().as_bytes())
        .map_err(from_protocol)?;
    writer
        .write_text_string(&binding.payload().to_encoded_string())
        .map_err(from_protocol)?;
    writer.write_unsigned(binding.max_fee().value());
    writer
        .write_byte_string(binding.fingerprint().as_bytes())
        .map_err(from_protocol)?;
    Ok(())
}

fn decode_binding(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<WalletdAnchorBindingV1, SnapshotFileError> {
    if reader.read_array_len().map_err(from_protocol)? != BINDING_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }
    let network = tari_cc_private_ballot_anchor::OotleNetworkIdV1::new(
        reader.read_text_string().map_err(from_protocol)?.to_owned(),
    )
    .map_err(|_| SnapshotFileError::InvalidData)?;
    let account =
        AnchorAccountReference::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| SnapshotFileError::InvalidData)?;
    let anchor_digest = OotleAnchorRecordHashV1::new(read_digest(reader)?);
    let payload = AnchorLogPayloadV1::parse(reader.read_text_string().map_err(from_protocol)?)
        .map_err(|_| SnapshotFileError::InvalidData)?;
    let max_fee = tari_cc_private_ballot_anchor_transport::AnchorMaxFeeV1::from_units(
        reader.read_unsigned().map_err(from_protocol)?,
    );
    let fingerprint = OotleAnchorInspectionFingerprintV1::new(read_digest(reader)?);
    Ok(WalletdAnchorBindingV1::new(
        network,
        account,
        anchor_digest,
        payload,
        max_fee,
        fingerprint,
    ))
}

// ---------------------------------------------------------------------------
// Submitted handle
// ---------------------------------------------------------------------------

fn encode_submitted_handle(
    writer: &mut CanonicalCborWriter,
    submitted: &SubmittedWalletdAnchorRequestV1,
) -> Result<(), SnapshotFileError> {
    writer
        .write_array_len(SUBMITTED_HANDLE_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(submitted.project_request_id().as_str())
        .map_err(from_protocol)?;
    writer.write_unsigned(submitted.walletd_request_id().value() as u32 as u64);
    writer
        .write_text_string(submitted.transaction_id().as_str())
        .map_err(from_protocol)?;
    encode_binding(writer, submitted.binding())?;
    Ok(())
}

fn decode_submitted_handle(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<SubmittedWalletdAnchorRequestV1, SnapshotFileError> {
    if reader.read_array_len().map_err(from_protocol)? != SUBMITTED_HANDLE_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }
    let project_request_id =
        AnchorRequestId::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| SnapshotFileError::InvalidData)?;
    let walletd_request_id = WalletdRequestId::from_walletd(read_i32(reader)?);
    let transaction_id = decode_transaction_id(reader)?;
    let binding = decode_binding(reader)?;
    Ok(SubmittedWalletdAnchorRequestV1::new(
        project_request_id,
        walletd_request_id,
        transaction_id,
        binding,
    ))
}

// ---------------------------------------------------------------------------
// Receipt snapshot (raw intermediate + reconstruction)
// ---------------------------------------------------------------------------

struct ReceiptSnapshotRaw {
    query_raw: QueryRaw,
    query_state: String,
    last_final_status: Option<String>,
    verified: bool,
    sequence: u64,
    last_diagnostic: Option<String>,
}

fn encode_receipt_snapshot(
    writer: &mut CanonicalCborWriter,
    snapshot: &AnchorReceiptQuerySnapshotV1,
) -> Result<(), SnapshotFileError> {
    writer
        .write_array_len(RECEIPT_SNAPSHOT_FIELD_COUNT)
        .map_err(from_protocol)?;
    encode_query(writer, snapshot.query())?;
    writer
        .write_text_string(snapshot.state().as_str())
        .map_err(from_protocol)?;
    encode_option_text(writer, snapshot.last_final_status().map(|s| s.as_str()))?;
    writer.write_bool(snapshot.verified());
    writer.write_unsigned(snapshot.sequence());
    encode_option_text(writer, snapshot.last_diagnostic())?;
    Ok(())
}

fn decode_receipt_snapshot_raw(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<ReceiptSnapshotRaw, SnapshotFileError> {
    if reader.read_array_len().map_err(from_protocol)? != RECEIPT_SNAPSHOT_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }
    // The query is fully derivable from the submitted handle, but the brief
    // requires it to be stored for independent verification. Read and verify.
    let query_raw = decode_query_raw(reader)?;
    let query_state = reader.read_text_string().map_err(from_protocol)?.to_owned();
    let last_final_status = decode_option_string(reader)?;
    let verified = reader.read_bool().map_err(from_protocol)?;
    let sequence = reader.read_unsigned().map_err(from_protocol)?;
    let last_diagnostic = decode_option_string(reader)?;
    Ok(ReceiptSnapshotRaw {
        query_raw,
        query_state,
        last_final_status,
        verified,
        sequence,
        last_diagnostic,
    })
}

fn encode_query(
    writer: &mut CanonicalCborWriter,
    query: &AnchorReceiptQueryV1,
) -> Result<(), SnapshotFileError> {
    writer
        .write_array_len(QUERY_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(query.project_request_id().as_str())
        .map_err(from_protocol)?;
    writer.write_unsigned(query.walletd_request_id().value() as u32 as u64);
    writer
        .write_text_string(query.transaction_id().as_str())
        .map_err(from_protocol)?;
    writer
        .write_text_string(query.network().as_str())
        .map_err(from_protocol)?;
    writer
        .write_text_string(query.account().as_str())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(query.anchor_digest().as_bytes())
        .map_err(from_protocol)?;
    writer
        .write_text_string(&query.payload().to_encoded_string())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(query.fingerprint().as_bytes())
        .map_err(from_protocol)?;
    Ok(())
}

struct QueryRaw {
    project_request_id: AnchorRequestId,
    walletd_request_id: WalletdRequestId,
    transaction_id: AnchorTransactionId,
    network: tari_cc_private_ballot_anchor::OotleNetworkIdV1,
    account: AnchorAccountReference,
    anchor_digest: OotleAnchorRecordHashV1,
    payload_text: String,
    fingerprint: OotleAnchorInspectionFingerprintV1,
}

fn decode_query_raw(reader: &mut CanonicalCborReader<'_>) -> Result<QueryRaw, SnapshotFileError> {
    if reader.read_array_len().map_err(from_protocol)? != QUERY_FIELD_COUNT {
        return Err(SnapshotFileError::InvalidCbor);
    }
    let project_request_id =
        AnchorRequestId::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| SnapshotFileError::InvalidData)?;
    let walletd_request_id = WalletdRequestId::from_walletd(read_i32(reader)?);
    let transaction_id = decode_transaction_id(reader)?;
    let network = tari_cc_private_ballot_anchor::OotleNetworkIdV1::new(
        reader.read_text_string().map_err(from_protocol)?.to_owned(),
    )
    .map_err(|_| SnapshotFileError::InvalidData)?;
    let account =
        AnchorAccountReference::new(reader.read_text_string().map_err(from_protocol)?.to_owned())
            .map_err(|_| SnapshotFileError::InvalidData)?;
    let anchor_digest = OotleAnchorRecordHashV1::new(read_digest(reader)?);
    let payload_text = reader.read_text_string().map_err(from_protocol)?.to_owned();
    let fingerprint = OotleAnchorInspectionFingerprintV1::new(read_digest(reader)?);
    Ok(QueryRaw {
        project_request_id,
        walletd_request_id,
        transaction_id,
        network,
        account,
        anchor_digest,
        payload_text,
        fingerprint,
    })
}

fn verify_query_matches_raw(
    query: &AnchorReceiptQueryV1,
    raw: &QueryRaw,
) -> Result<(), SnapshotFileError> {
    if query.project_request_id() != &raw.project_request_id
        || query.walletd_request_id() != raw.walletd_request_id
        || query.transaction_id() != &raw.transaction_id
        || query.network() != &raw.network
        || query.account() != &raw.account
        || query.anchor_digest() != raw.anchor_digest
        || query.fingerprint() != raw.fingerprint
        || query.payload().to_encoded_string() != raw.payload_text
    {
        return Err(SnapshotFileError::InvalidData);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Option helpers (0/1-element array)
// ---------------------------------------------------------------------------

fn encode_option_text(
    writer: &mut CanonicalCborWriter,
    value: Option<&str>,
) -> Result<(), SnapshotFileError> {
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

fn decode_option_string(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<Option<String>, SnapshotFileError> {
    let len = reader.read_array_len().map_err(from_protocol)?;
    match len {
        0 => Ok(None),
        1 => Ok(Some(
            reader.read_text_string().map_err(from_protocol)?.to_owned(),
        )),
        _ => Err(SnapshotFileError::InvalidCbor),
    }
}

fn decode_option_diagnostic(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<Option<&'static str>, SnapshotFileError> {
    let len = reader.read_array_len().map_err(from_protocol)?;
    match len {
        0 => Ok(None),
        1 => {
            let text = reader.read_text_string().map_err(from_protocol)?;
            Ok(Some(
                diagnostic_from_str(text).ok_or(SnapshotFileError::InvalidData)?,
            ))
        }
        _ => Err(SnapshotFileError::InvalidCbor),
    }
}

fn decode_option<T>(
    reader: &mut CanonicalCborReader<'_>,
    read_value: impl Fn(&mut CanonicalCborReader<'_>) -> Result<T, SnapshotFileError>,
) -> Result<Option<T>, SnapshotFileError> {
    let len = reader.read_array_len().map_err(from_protocol)?;
    match len {
        0 => Ok(None),
        1 => Ok(Some(read_value(reader)?)),
        _ => Err(SnapshotFileError::InvalidCbor),
    }
}

fn decode_transaction_id(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<AnchorTransactionId, SnapshotFileError> {
    let text = reader.read_text_string().map_err(from_protocol)?;
    if !is_canonical_transaction_id(text) {
        return Err(SnapshotFileError::InvalidData);
    }
    AnchorTransactionId::new(text.to_owned()).map_err(|_| SnapshotFileError::InvalidData)
}

fn decode_effective_status(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<WalletdEffectiveStatusV1, SnapshotFileError> {
    let text = reader.read_text_string().map_err(from_protocol)?;
    effective_status_from_str(text).ok_or(SnapshotFileError::InvalidData)
}

fn is_canonical_transaction_id(text: &str) -> bool {
    text.len() == TRANSACTION_ID_HEX_LEN
        && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn read_digest(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], SnapshotFileError> {
    <[u8; 32]>::try_from(reader.read_byte_string().map_err(from_protocol)?)
        .map_err(|_| SnapshotFileError::InvalidCbor)
}

fn read_u32(reader: &mut CanonicalCborReader<'_>) -> Result<u32, SnapshotFileError> {
    let value = reader.read_unsigned().map_err(from_protocol)?;
    u32::try_from(value).map_err(|_| SnapshotFileError::InvalidData)
}

fn read_i32(reader: &mut CanonicalCborReader<'_>) -> Result<i32, SnapshotFileError> {
    let value = reader.read_unsigned().map_err(from_protocol)?;
    let raw = u32::try_from(value).map_err(|_| SnapshotFileError::InvalidData)?;
    Ok(raw as i32)
}

// ---------------------------------------------------------------------------
// Closed vocabulary lookup
// ---------------------------------------------------------------------------

fn phase_from_str(text: &str) -> Option<UnifiedAnchorLifecyclePhase> {
    match text {
        "NOT_PREPARED" => Some(UnifiedAnchorLifecyclePhase::NotPrepared),
        "PREPARED" => Some(UnifiedAnchorLifecyclePhase::Prepared),
        "APPROVED" => Some(UnifiedAnchorLifecyclePhase::Approved),
        "REJECTED_BY_APPROVER" => Some(UnifiedAnchorLifecyclePhase::RejectedByApprover),
        "SUBMITTED" => Some(UnifiedAnchorLifecyclePhase::Submitted),
        "POLLING_IN_PROGRESS" => Some(UnifiedAnchorLifecyclePhase::PollingInProgress),
        "FINALIZED_ACCEPT" => Some(UnifiedAnchorLifecyclePhase::FinalizedAccept),
        "FINALIZED_FEE_ONLY" => Some(UnifiedAnchorLifecyclePhase::FinalizedFeeOnly),
        "FINALIZED_REJECT" => Some(UnifiedAnchorLifecyclePhase::FinalizedReject),
        "FINALIZED_VERIFICATION_FAILED" => {
            Some(UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed)
        }
        "FINALIZED_DISAGREEMENT" => Some(UnifiedAnchorLifecyclePhase::FinalizedDisagreement),
        "UNKNOWN" => Some(UnifiedAnchorLifecyclePhase::Unknown),
        _ => None,
    }
}

fn decision_from_str(text: &str) -> Option<WalletdRequestDecisionV1> {
    match text {
        "PREPARED" => Some(WalletdRequestDecisionV1::Prepared),
        "APPROVED" => Some(WalletdRequestDecisionV1::Approved),
        "REJECTED" => Some(WalletdRequestDecisionV1::Rejected),
        "EXPIRED" => Some(WalletdRequestDecisionV1::Expired),
        _ => None,
    }
}

fn submission_state_from_str(text: &str) -> Option<WalletdSubmissionStateV1> {
    match text {
        "NOT_SUBMITTED" => Some(WalletdSubmissionStateV1::NotSubmitted),
        "TIMED_OUT_UNKNOWN" => Some(WalletdSubmissionStateV1::TimedOutUnknown),
        "SUBMITTED" => Some(WalletdSubmissionStateV1::Submitted),
        _ => None,
    }
}

fn effective_status_from_str(text: &str) -> Option<WalletdEffectiveStatusV1> {
    match text {
        "PENDING" => Some(WalletdEffectiveStatusV1::Pending),
        "APPROVED" => Some(WalletdEffectiveStatusV1::Approved),
        "REJECTED" => Some(WalletdEffectiveStatusV1::Rejected),
        "SUBMITTING" => Some(WalletdEffectiveStatusV1::Submitting),
        "SUBMITTED" => Some(WalletdEffectiveStatusV1::Submitted),
        "EXPIRED" => Some(WalletdEffectiveStatusV1::Expired),
        _ => None,
    }
}

fn query_state_from_str(text: &str) -> Option<AnchorReceiptQueryStateV1> {
    match text {
        "SUBMITTED_NOT_QUERIED" => Some(AnchorReceiptQueryStateV1::SubmittedNotQueried),
        "RECEIPT_NOT_FOUND" => Some(AnchorReceiptQueryStateV1::ReceiptNotFound),
        "RECEIPT_PENDING" => Some(AnchorReceiptQueryStateV1::ReceiptPending),
        "RECEIPT_UNKNOWN" => Some(AnchorReceiptQueryStateV1::ReceiptUnknown),
        "RECEIPT_FINALIZED_ACCEPT" => Some(AnchorReceiptQueryStateV1::ReceiptFinalizedAccept),
        "RECEIPT_FINALIZED_FEE_ONLY" => Some(AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly),
        "RECEIPT_FINALIZED_REJECT" => Some(AnchorReceiptQueryStateV1::ReceiptFinalizedReject),
        "RECEIPT_VERIFICATION_FAILED" => Some(AnchorReceiptQueryStateV1::ReceiptVerificationFailed),
        _ => None,
    }
}

fn final_status_from_str(text: &str) -> Option<AnchorFinalStatusV1> {
    match text {
        "ACCEPTED" => Some(AnchorFinalStatusV1::Accepted),
        "FEE_ONLY_ACCEPTED" => Some(AnchorFinalStatusV1::FeeOnlyAccepted),
        "REJECTED" => Some(AnchorFinalStatusV1::Rejected),
        _ => None,
    }
}

/// Returns the matching `&'static str` for a known diagnostic code, or `None`
/// for an unknown value. The diagnostic vocabulary is closed-by-convention: it
/// is the union of the orchestrator's poll-exhausted marker and the bounded
/// `as_str()` codes of the adapter and verification errors that the existing
/// system ever records.
fn diagnostic_from_str(text: &str) -> Option<&'static str> {
    match text {
        "POLL_EXHAUSTED" => Some("POLL_EXHAUSTED"),
        // WalletdAnchorAdapterError
        "WALLETD_UNAVAILABLE" => Some("WALLETD_UNAVAILABLE"),
        "WALLETD_TRANSPORT_FAILURE" => Some("WALLETD_TRANSPORT_FAILURE"),
        "WALLETD_MALFORMED_RESPONSE" => Some("WALLETD_MALFORMED_RESPONSE"),
        "WALLETD_REQUEST_CREATION_REJECTED" => Some("WALLETD_REQUEST_CREATION_REJECTED"),
        "WALLETD_REQUEST_NOT_FOUND" => Some("WALLETD_REQUEST_NOT_FOUND"),
        "WALLETD_APPROVAL_REJECTED" => Some("WALLETD_APPROVAL_REJECTED"),
        "WALLETD_REQUEST_ALREADY_APPROVED" => Some("WALLETD_REQUEST_ALREADY_APPROVED"),
        "WALLETD_REQUEST_ALREADY_REJECTED" => Some("WALLETD_REQUEST_ALREADY_REJECTED"),
        "WALLETD_REQUEST_EXPIRED" => Some("WALLETD_REQUEST_EXPIRED"),
        "WALLETD_BINDING_MISMATCH" => Some("WALLETD_BINDING_MISMATCH"),
        "WALLETD_NETWORK_MISMATCH" => Some("WALLETD_NETWORK_MISMATCH"),
        "WALLETD_ACCOUNT_MISMATCH" => Some("WALLETD_ACCOUNT_MISMATCH"),
        "WALLETD_PAYLOAD_MISMATCH" => Some("WALLETD_PAYLOAD_MISMATCH"),
        "WALLETD_FEE_MISMATCH" => Some("WALLETD_FEE_MISMATCH"),
        "WALLETD_FINGERPRINT_MISMATCH" => Some("WALLETD_FINGERPRINT_MISMATCH"),
        "WALLETD_REQUEST_ID_MISMATCH" => Some("WALLETD_REQUEST_ID_MISMATCH"),
        "WALLETD_UNSAFE_UNSIGNED_TRANSACTION" => Some("WALLETD_UNSAFE_UNSIGNED_TRANSACTION"),
        "WALLETD_UNSUPPORTED_API" => Some("WALLETD_UNSUPPORTED_API"),
        "WALLETD_FEE_COMPONENT_INVALID" => Some("WALLETD_FEE_COMPONENT_INVALID"),
        "WALLETD_REQUEST_NOT_APPROVED" => Some("WALLETD_REQUEST_NOT_APPROVED"),
        "WALLETD_SUBMIT_TIMEOUT" => Some("WALLETD_SUBMIT_TIMEOUT"),
        "WALLETD_MALFORMED_SUBMIT_RESPONSE" => Some("WALLETD_MALFORMED_SUBMIT_RESPONSE"),
        "WALLETD_SUBMITTED_BUT_TRANSACTION_ID_MISSING" => {
            Some("WALLETD_SUBMITTED_BUT_TRANSACTION_ID_MISSING")
        }
        "WALLETD_ALREADY_SUBMITTED" => Some("WALLETD_ALREADY_SUBMITTED"),
        "WALLETD_SUBMISSION_STATE_UNKNOWN" => Some("WALLETD_SUBMISSION_STATE_UNKNOWN"),
        "WALLETD_CONFLICTING_TRANSACTION_ID" => Some("WALLETD_CONFLICTING_TRANSACTION_ID"),
        "WALLETD_STATUS_UNAVAILABLE" => Some("WALLETD_STATUS_UNAVAILABLE"),
        "WALLETD_CALLER_SUPPLIED_TRANSACTION_ID" => Some("WALLETD_CALLER_SUPPLIED_TRANSACTION_ID"),
        // IndexerReceiptTransportError
        "INDEXER_RECEIPT_UNAVAILABLE" => Some("INDEXER_RECEIPT_UNAVAILABLE"),
        "INDEXER_RECEIPT_TIMEOUT" => Some("INDEXER_RECEIPT_TIMEOUT"),
        "INDEXER_RECEIPT_MALFORMED_RESPONSE" => Some("INDEXER_RECEIPT_MALFORMED_RESPONSE"),
        "INDEXER_RECEIPT_UNSUPPORTED_API" => Some("INDEXER_RECEIPT_UNSUPPORTED_API"),
        // ReceiptQueryBindingError
        "RECEIPT_QUERY_TRANSACTION_ID_MISMATCH" => Some("RECEIPT_QUERY_TRANSACTION_ID_MISMATCH"),
        "RECEIPT_QUERY_WALLETD_REQUEST_ID_MISMATCH" => {
            Some("RECEIPT_QUERY_WALLETD_REQUEST_ID_MISMATCH")
        }
        "RECEIPT_QUERY_PROJECT_REQUEST_ID_MISMATCH" => {
            Some("RECEIPT_QUERY_PROJECT_REQUEST_ID_MISMATCH")
        }
        "RECEIPT_QUERY_NETWORK_MISMATCH" => Some("RECEIPT_QUERY_NETWORK_MISMATCH"),
        "RECEIPT_QUERY_ANCHOR_DIGEST_MISMATCH" => Some("RECEIPT_QUERY_ANCHOR_DIGEST_MISMATCH"),
        "RECEIPT_QUERY_PAYLOAD_MISMATCH" => Some("RECEIPT_QUERY_PAYLOAD_MISMATCH"),
        "RECEIPT_QUERY_FINGERPRINT_MISMATCH" => Some("RECEIPT_QUERY_FINGERPRINT_MISMATCH"),
        // ReceiptIdentifierError
        "RECEIPT_ID_EMPTY" => Some("RECEIPT_ID_EMPTY"),
        "RECEIPT_ID_WRONG_LENGTH" => Some("RECEIPT_ID_WRONG_LENGTH"),
        "RECEIPT_ID_NON_LOWERCASE_HEX_DIGIT" => Some("RECEIPT_ID_NON_LOWERCASE_HEX_DIGIT"),
        // AnchorReceiptAgreementError (own variants)
        "RECEIPT_AGREEMENT_WRONG_WALLETD_SOURCE" => Some("RECEIPT_AGREEMENT_WRONG_WALLETD_SOURCE"),
        "RECEIPT_AGREEMENT_WRONG_INDEXER_SOURCE" => Some("RECEIPT_AGREEMENT_WRONG_INDEXER_SOURCE"),
        "RECEIPT_AGREEMENT_EXPECTED_TRANSACTION_MISMATCH" => {
            Some("RECEIPT_AGREEMENT_EXPECTED_TRANSACTION_MISMATCH")
        }
        "RECEIPT_AGREEMENT_EXPECTED_NETWORK_MISMATCH" => {
            Some("RECEIPT_AGREEMENT_EXPECTED_NETWORK_MISMATCH")
        }
        // AnchorObservationAgreementError
        "ANCHOR_AGREEMENT_TRANSACTION_ID_MISMATCH" => {
            Some("ANCHOR_AGREEMENT_TRANSACTION_ID_MISMATCH")
        }
        "ANCHOR_AGREEMENT_NETWORK_MISMATCH" => Some("ANCHOR_AGREEMENT_NETWORK_MISMATCH"),
        "ANCHOR_AGREEMENT_FINAL_STATUS_MISMATCH" => Some("ANCHOR_AGREEMENT_FINAL_STATUS_MISMATCH"),
        "ANCHOR_AGREEMENT_FEE_ONLY_VERSUS_FULL_MISMATCH" => {
            Some("ANCHOR_AGREEMENT_FEE_ONLY_VERSUS_FULL_MISMATCH")
        }
        "ANCHOR_AGREEMENT_ANCHOR_LOG_PRESENCE_MISMATCH" => {
            Some("ANCHOR_AGREEMENT_ANCHOR_LOG_PRESENCE_MISMATCH")
        }
        "ANCHOR_AGREEMENT_ANCHOR_DIGEST_MISMATCH" => {
            Some("ANCHOR_AGREEMENT_ANCHOR_DIGEST_MISMATCH")
        }
        "ANCHOR_AGREEMENT_LOG_SEQUENCE_MISMATCH" => Some("ANCHOR_AGREEMENT_LOG_SEQUENCE_MISMATCH"),
        "ANCHOR_AGREEMENT_MALFORMED_ANCHOR_LOG" => Some("ANCHOR_AGREEMENT_MALFORMED_ANCHOR_LOG"),
        // AnchorReceiptVerificationError
        "ANCHOR_RECEIPT_WRONG_TRANSACTION" => Some("ANCHOR_RECEIPT_WRONG_TRANSACTION"),
        "ANCHOR_RECEIPT_WRONG_NETWORK" => Some("ANCHOR_RECEIPT_WRONG_NETWORK"),
        "ANCHOR_RECEIPT_NOT_FINALIZED" => Some("ANCHOR_RECEIPT_NOT_FINALIZED"),
        "ANCHOR_RECEIPT_FEE_ONLY_ACCEPTANCE" => Some("ANCHOR_RECEIPT_FEE_ONLY_ACCEPTANCE"),
        "ANCHOR_RECEIPT_REJECTED_TRANSACTION" => Some("ANCHOR_RECEIPT_REJECTED_TRANSACTION"),
        "ANCHOR_RECEIPT_MISSING_ANCHOR_LOG" => Some("ANCHOR_RECEIPT_MISSING_ANCHOR_LOG"),
        "ANCHOR_RECEIPT_MALFORMED_ANCHOR_LOG" => Some("ANCHOR_RECEIPT_MALFORMED_ANCHOR_LOG"),
        "ANCHOR_RECEIPT_WRONG_ANCHOR_DIGEST" => Some("ANCHOR_RECEIPT_WRONG_ANCHOR_DIGEST"),
        "ANCHOR_RECEIPT_DUPLICATE_ANCHOR_LOGS" => Some("ANCHOR_RECEIPT_DUPLICATE_ANCHOR_LOGS"),
        "ANCHOR_RECEIPT_CONFLICTING_ANCHOR_LOGS" => Some("ANCHOR_RECEIPT_CONFLICTING_ANCHOR_LOGS"),
        _ => None,
    }
}
