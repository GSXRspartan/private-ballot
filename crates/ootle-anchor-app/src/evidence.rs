//! Canonical, versioned [`AnchorEvidenceRecordV1`] for finalized acceptance and
//! non-success terminal outcomes (Slice 4A10).
//!
//! The evidence envelope is a canonical CBOR definite-length 4-element array:
//!
//! 1. record-type / version text ([`EVIDENCE_RECORD_TYPE_ID_V1`]);
//! 2. hash-algorithm identifier text ([`EVIDENCE_HASH_ALGORITHM_ID_V1`]);
//! 3. body digest as exactly 32 bytes;
//! 4. canonical body bytes.
//!
//! The body is a canonical CBOR definite-length 12-element array (see
//! [`AnchorEvidenceRecordV1::canonical_bytes`]). The body digest is a
//! domain-separated BLAKE3 hash using [`EVIDENCE_FRAME_PREFIX_V1`] and
//! [`EVIDENCE_DOMAIN_LABEL_V1`], distinct from the protocol, anchor-record,
//! transaction-inspection, and snapshot frames.
//!
//! The record holds no ballot, proof, nullifier, registry key, voter identity,
//! organizer identity, tally, archive contents, private key, auth secret, or
//! seal signer. Optional fields use the same 0/1-element array convention as
//! the snapshot (the protocol CBOR subset has no `null`).

use std::borrow::Cow;
use std::path::Path;

use tari_cc_private_ballot_anchor::{
    OOTLE_ANCHOR_PURPOSE_ID_V1, OotleAnchorRecordHashV1, OotleNetworkIdV1,
};
use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;
use tari_cc_private_ballot_archive::ArchiveHashV1;
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::UnifiedAnchorLifecyclePhase;
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::VerifiedIndexerAnchorV1;
use tari_cc_private_ballot_protocol::{
    BLAKE3_256_HASH_ALGORITHM_ID_V1, Blake3HashProviderV1, CanonicalCborReader,
    CanonicalCborWriter, HashProvider, ManifestHash, ProtocolError, ValidationCode,
};

/// Maximum encoded evidence file size (envelope + body).
pub const MAX_EVIDENCE_FILE_BYTES: usize = 8_192;

/// Stable record-type / version identifier for the evidence envelope.
pub const EVIDENCE_RECORD_TYPE_ID_V1: &str = "TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_EVIDENCE_V1";

/// Hash-algorithm identifier written into the evidence envelope.
pub const EVIDENCE_HASH_ALGORITHM_ID_V1: &str = BLAKE3_256_HASH_ALGORITHM_ID_V1;

/// Domain-separation frame prefix for evidence body digests.
pub const EVIDENCE_FRAME_PREFIX_V1: &[u8] =
    b"TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_EVIDENCE_FRAME_V1";

/// Domain label for evidence body digests.
pub const EVIDENCE_DOMAIN_LABEL_V1: &str = "tari-cc-private-ballot/ootle-anchor-evidence/v1";

const ENVELOPE_FIELD_COUNT: usize = 4;
const BODY_FIELD_COUNT: usize = 12;

const FINAL_STATUS_ACCEPTED: &str = "ACCEPTED";
const FINAL_STATUS_FEE_ONLY: &str = "FEE_ONLY_ACCEPTED";
const FINAL_STATUS_REJECTED: &str = "REJECTED";
const FINAL_STATUS_VERIFICATION_FAILED: &str = "VERIFICATION_FAILED";
const FINAL_STATUS_DISAGREEMENT: &str = "DISAGREEMENT";
const FINAL_STATUS_POLL_EXHAUSTED_UNKNOWN: &str = "POLL_EXHAUSTED_UNKNOWN";
const FINAL_STATUS_REJECTED_BY_APPROVER: &str = "REJECTED_BY_APPROVER";

const SOURCE_INDEPENDENT_INDEXER: &str = "INDEPENDENT_INDEXER";
const SOURCE_WALLETD_AND_INDEXER: &str = "WALLETD_AND_INDEXER";
const SOURCE_NONE: &str = "NONE";

/// Public, non-secret archive locator data bundled for evidence construction.
///
/// This type is defined in the application leaf (Slice 4A10) because no
/// lower-level crate bundles these four public locators together; it carries
/// no ballot, no proof, and no archive contents — only the public hashes and
/// the network id that identify which commitment the evidence is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveProofInputs {
    network: OotleNetworkIdV1,
    manifest_hash: ManifestHash,
    archive_hash: ArchiveHashV1,
    anchor_digest: OotleAnchorRecordHashV1,
}

impl ArchiveProofInputs {
    /// Assembles the public archive proof locator bundle.
    #[must_use]
    pub fn new(
        network: OotleNetworkIdV1,
        manifest_hash: ManifestHash,
        archive_hash: ArchiveHashV1,
        anchor_digest: OotleAnchorRecordHashV1,
    ) -> Self {
        Self {
            network,
            manifest_hash,
            archive_hash,
            anchor_digest,
        }
    }

    /// Returns the intended project network identifier.
    #[must_use]
    pub fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Returns the election manifest hash.
    #[must_use]
    pub fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// Returns the archive hash.
    #[must_use]
    pub fn archive_hash(&self) -> ArchiveHashV1 {
        self.archive_hash
    }

    /// Returns the anchor-record digest.
    #[must_use]
    pub fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }
}

/// The kind of terminal incident an evidence record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TerminalIncidentKind {
    /// Verified finalized acceptance from the independent indexer.
    FinalizedAccept,
    /// Finalized fee-only acceptance (the anchor did not land).
    FinalizedFeeOnly,
    /// Finalized rejection by the ledger.
    FinalizedReject,
    /// Verification of a finalized receipt failed.
    VerificationFailed,
    /// The walletd and indexer observations disagree.
    Disagreement,
    /// Polling exhausted before finality was observed.
    PollExhaustedUnknown,
    /// The approver rejected the request before submission.
    RejectedByApprover,
}

impl TerminalIncidentKind {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FinalizedAccept => "EVIDENCE_FINALIZED_ACCEPT",
            Self::FinalizedFeeOnly => "EVIDENCE_FINALIZED_FEE_ONLY",
            Self::FinalizedReject => "EVIDENCE_FINALIZED_REJECT",
            Self::VerificationFailed => "EVIDENCE_VERIFICATION_FAILED",
            Self::Disagreement => "EVIDENCE_DISAGREEMENT",
            Self::PollExhaustedUnknown => "EVIDENCE_POLL_EXHAUSTED_UNKNOWN",
            Self::RejectedByApprover => "EVIDENCE_REJECTED_BY_APPROVER",
        }
    }
}

/// Inputs describing a non-success terminal incident for
/// [`AnchorEvidenceRecordV1::from_terminal_outcome`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TerminalEvidenceInputs {
    /// Finalized fee-only acceptance.
    FeeOnly {
        transaction_id: AnchorTransactionId,
        ledger_position: Option<u64>,
    },
    /// Finalized rejection by the ledger.
    Reject {
        transaction_id: AnchorTransactionId,
        ledger_position: Option<u64>,
    },
    /// A finalized receipt failed anchor-log verification.
    VerificationFailed {
        transaction_id: Option<AnchorTransactionId>,
        ledger_position: Option<u64>,
    },
    /// The walletd and indexer observations disagree.
    Disagreement {
        transaction_id: AnchorTransactionId,
        ledger_position: Option<u64>,
    },
    /// Polling exhausted before finality was observed.
    PollExhaustedUnknown {
        transaction_id: Option<AnchorTransactionId>,
    },
    /// The approver rejected the request before submission.
    RejectedByApprover,
}

impl TerminalEvidenceInputs {
    fn final_status(&self) -> &'static str {
        match self {
            Self::FeeOnly { .. } => FINAL_STATUS_FEE_ONLY,
            Self::Reject { .. } => FINAL_STATUS_REJECTED,
            Self::VerificationFailed { .. } => FINAL_STATUS_VERIFICATION_FAILED,
            Self::Disagreement { .. } => FINAL_STATUS_DISAGREEMENT,
            Self::PollExhaustedUnknown { .. } => FINAL_STATUS_POLL_EXHAUSTED_UNKNOWN,
            Self::RejectedByApprover => FINAL_STATUS_REJECTED_BY_APPROVER,
        }
    }

    fn receipt_source(&self) -> &'static str {
        match self {
            Self::FeeOnly { .. } | Self::Reject { .. } | Self::VerificationFailed { .. } => {
                SOURCE_INDEPENDENT_INDEXER
            }
            Self::Disagreement { .. } => SOURCE_WALLETD_AND_INDEXER,
            Self::PollExhaustedUnknown { .. } | Self::RejectedByApprover => SOURCE_NONE,
        }
    }

    fn phase(&self) -> UnifiedAnchorLifecyclePhase {
        match self {
            Self::FeeOnly { .. } => UnifiedAnchorLifecyclePhase::FinalizedFeeOnly,
            Self::Reject { .. } => UnifiedAnchorLifecyclePhase::FinalizedReject,
            Self::VerificationFailed { .. } => {
                UnifiedAnchorLifecyclePhase::FinalizedVerificationFailed
            }
            Self::Disagreement { .. } => UnifiedAnchorLifecyclePhase::FinalizedDisagreement,
            Self::PollExhaustedUnknown { .. } => UnifiedAnchorLifecyclePhase::Unknown,
            Self::RejectedByApprover => UnifiedAnchorLifecyclePhase::RejectedByApprover,
        }
    }

    fn transaction_id(&self) -> Option<&AnchorTransactionId> {
        match self {
            Self::FeeOnly { transaction_id, .. }
            | Self::Reject { transaction_id, .. }
            | Self::Disagreement { transaction_id, .. } => Some(transaction_id),
            Self::VerificationFailed { transaction_id, .. } => transaction_id.as_ref(),
            Self::PollExhaustedUnknown { transaction_id } => transaction_id.as_ref(),
            Self::RejectedByApprover => None,
        }
    }

    fn ledger_position(&self) -> Option<u64> {
        match self {
            Self::FeeOnly {
                ledger_position, ..
            }
            | Self::Reject {
                ledger_position, ..
            }
            | Self::VerificationFailed {
                ledger_position, ..
            }
            | Self::Disagreement {
                ledger_position, ..
            } => *ledger_position,
            Self::PollExhaustedUnknown { .. } | Self::RejectedByApprover => None,
        }
    }
}

/// Bounded failure while constructing an [`AnchorEvidenceRecordV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceError {
    /// The encoded body exceeded [`MAX_EVIDENCE_FILE_BYTES`].
    ProtocolLimitExceeded,
    /// A field value was invalid.
    InvalidData,
}

impl EvidenceError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProtocolLimitExceeded => "EVIDENCE_PROTOCOL_LIMIT_EXCEEDED",
            Self::InvalidData => "EVIDENCE_INVALID_DATA",
        }
    }
}

impl core::fmt::Display for EvidenceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for EvidenceError {}

/// Bounded failure while reading or writing an evidence file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceFileError {
    /// A filesystem I/O failure occurred.
    IoFailure,
    /// The atomic rename could not complete.
    AtomicRenameFailure,
    /// The encoded size exceeded [`MAX_EVIDENCE_FILE_BYTES`].
    ProtocolLimitExceeded,
}

impl EvidenceFileError {
    /// Returns the stable machine-readable code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IoFailure => "EVIDENCE_FILE_IO_FAILURE",
            Self::AtomicRenameFailure => "EVIDENCE_FILE_ATOMIC_RENAME_FAILURE",
            Self::ProtocolLimitExceeded => "EVIDENCE_FILE_PROTOCOL_LIMIT_EXCEEDED",
        }
    }
}

impl core::fmt::Display for EvidenceFileError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for EvidenceFileError {}

/// A canonical, versioned anchor evidence record.
///
/// The record is constructed from either a verified indexer acceptance
/// ([`AnchorEvidenceRecordV1::from_verified_indexer_accept`]) or a non-success
/// terminal incident ([`AnchorEvidenceRecordV1::from_terminal_outcome`]). It
/// stores its canonical envelope bytes, its body digest, and the public
/// locator fields needed for [`AnchorEvidenceRecordV1::human_review_summary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorEvidenceRecordV1 {
    envelope: Vec<u8>,
    body_digest: [u8; 32],
    network: OotleNetworkIdV1,
    manifest_hash: ManifestHash,
    archive_hash: ArchiveHashV1,
    anchor_digest: OotleAnchorRecordHashV1,
    transaction_id: Option<AnchorTransactionId>,
    final_status: &'static str,
    receipt_source: &'static str,
    phase: UnifiedAnchorLifecyclePhase,
    snapshot_digest: [u8; 32],
}

impl AnchorEvidenceRecordV1 {
    /// Builds the ACCEPTED evidence record from a verified indexer acceptance.
    ///
    /// Only this constructor may produce an `ACCEPTED` evidence record; all
    /// other terminal outcomes are incident records built via
    /// [`AnchorEvidenceRecordV1::from_terminal_outcome`].
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::ProtocolLimitExceeded`] if the canonical
    /// envelope exceeds [`MAX_EVIDENCE_FILE_BYTES`].
    pub fn from_verified_indexer_accept(
        archive: &ArchiveProofInputs,
        verified: &VerifiedIndexerAnchorV1,
        snapshot_digest: &[u8; 32],
        phase: UnifiedAnchorLifecyclePhase,
    ) -> Result<Self, EvidenceError> {
        let evidence = verified.evidence();
        let transaction_id = evidence.transaction_id().clone();
        let ledger_position = evidence.ledger_position();
        Self::assemble(
            archive,
            Some(transaction_id),
            ledger_position,
            FINAL_STATUS_ACCEPTED,
            SOURCE_INDEPENDENT_INDEXER,
            phase,
            *snapshot_digest,
        )
    }

    /// Builds a non-success terminal incident evidence record.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceError::ProtocolLimitExceeded`] if the canonical
    /// envelope exceeds [`MAX_EVIDENCE_FILE_BYTES`].
    pub fn from_terminal_outcome(
        archive: &ArchiveProofInputs,
        terminal: TerminalEvidenceInputs,
        snapshot_digest: &[u8; 32],
    ) -> Result<Self, EvidenceError> {
        let transaction_id = terminal.transaction_id().cloned();
        let ledger_position = terminal.ledger_position();
        let final_status = terminal.final_status();
        let receipt_source = terminal.receipt_source();
        let phase = terminal.phase();
        Self::assemble(
            archive,
            transaction_id,
            ledger_position,
            final_status,
            receipt_source,
            phase,
            *snapshot_digest,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        archive: &ArchiveProofInputs,
        transaction_id: Option<AnchorTransactionId>,
        ledger_position: Option<u64>,
        final_status: &'static str,
        receipt_source: &'static str,
        phase: UnifiedAnchorLifecyclePhase,
        snapshot_digest: [u8; 32],
    ) -> Result<Self, EvidenceError> {
        let body = encode_body(
            archive,
            transaction_id.as_ref().map(|t| t.as_str()),
            ledger_position,
            final_status,
            receipt_source,
            phase,
            &snapshot_digest,
        )?;
        let framed = evidence_domain_input(&body);
        let body_digest = Blake3HashProviderV1.hash(&framed);
        let envelope = encode_envelope(&body, &body_digest)?;
        if envelope.len() > MAX_EVIDENCE_FILE_BYTES {
            return Err(EvidenceError::ProtocolLimitExceeded);
        }
        Ok(Self {
            envelope,
            body_digest,
            network: archive.network().clone(),
            manifest_hash: archive.manifest_hash(),
            archive_hash: archive.archive_hash(),
            anchor_digest: archive.anchor_digest(),
            transaction_id,
            final_status,
            receipt_source,
            phase,
            snapshot_digest,
        })
    }

    /// Returns the canonical envelope bytes of this evidence record.
    #[must_use]
    pub fn canonical_bytes(&self) -> Cow<'_, [u8]> {
        Cow::Borrowed(&self.envelope)
    }

    /// Returns the 32-byte body digest of this evidence record.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.body_digest
    }

    /// Returns the incident kind for this record.
    #[must_use]
    pub fn incident_kind(&self) -> TerminalIncidentKind {
        match self.final_status {
            FINAL_STATUS_ACCEPTED => TerminalIncidentKind::FinalizedAccept,
            FINAL_STATUS_FEE_ONLY => TerminalIncidentKind::FinalizedFeeOnly,
            FINAL_STATUS_REJECTED => TerminalIncidentKind::FinalizedReject,
            FINAL_STATUS_VERIFICATION_FAILED => TerminalIncidentKind::VerificationFailed,
            FINAL_STATUS_DISAGREEMENT => TerminalIncidentKind::Disagreement,
            FINAL_STATUS_POLL_EXHAUSTED_UNKNOWN => TerminalIncidentKind::PollExhaustedUnknown,
            FINAL_STATUS_REJECTED_BY_APPROVER => TerminalIncidentKind::RejectedByApprover,
            _ => TerminalIncidentKind::VerificationFailed,
        }
    }

    /// Returns the lifecycle phase recorded for this evidence.
    #[must_use]
    pub fn phase(&self) -> UnifiedAnchorLifecyclePhase {
        self.phase
    }

    /// Returns the final status vocabulary string.
    #[must_use]
    pub fn final_status(&self) -> &'static str {
        self.final_status
    }

    /// Returns the receipt source vocabulary string.
    #[must_use]
    pub fn receipt_source(&self) -> &'static str {
        self.receipt_source
    }

    /// Returns the bound transaction id, if any.
    #[must_use]
    pub fn transaction_id(&self) -> Option<&AnchorTransactionId> {
        self.transaction_id.as_ref()
    }

    /// Returns the human-review summary.
    ///
    /// The summary states, without caller-supplied prose, the non-binding
    /// nature of the pilot, the authority of the offline archive and the
    /// independent verifier, the narrow scope of the proof, and the explicit
    /// non-claims (ballot validity, tally correctness, organizer honesty,
    /// voter anonymity, archive availability).
    #[must_use]
    pub fn human_review_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str("NON-BINDING PILOT: this anchor evidence is non-binding. ");
        summary.push_str("The offline archive and the independent verifier remain authoritative. ");
        summary.push_str(&format!(
            "This evidence proves only that a specific commitment was submitted or finalized on ledger {}; ",
            self.network.as_str()
        ));
        summary.push_str(&format!(
            "final_status={}, receipt_source={}, phase={}, ",
            self.final_status,
            self.receipt_source,
            self.phase.as_str()
        ));
        summary.push_str(&format!(
            "manifest_hash={}, archive_hash={}, anchor_digest={}, ",
            to_lower_hex(self.manifest_hash.as_bytes()),
            to_lower_hex(self.archive_hash.as_bytes()),
            to_lower_hex(self.anchor_digest.as_bytes()),
        ));
        if let Some(tx) = &self.transaction_id {
            summary.push_str(&format!("transaction_id={}, ", tx.as_str()));
        } else {
            summary.push_str("transaction_id=none, ");
        }
        summary.push_str(&format!(
            "snapshot_digest={}.\n",
            to_lower_hex(&self.snapshot_digest)
        ));
        summary.push_str("It does NOT prove ballot validity, tally correctness, ");
        summary.push_str("organizer honesty, voter anonymity, or archive availability. ");
        summary.push_str("Independent cryptographic and implementation review remains ");
        summary.push_str("required before any binding use.");
        summary
    }

    /// Decodes and verifies a canonical evidence record from its envelope
    /// bytes.
    ///
    /// This is the inverse of [`Self::canonical_bytes`]. It verifies the
    /// envelope record-type, hash-algorithm identifier, and the embedded body
    /// digest **before** trusting any decoded field, and rejects trailing
    /// bytes, wrong versions, wrong hash algorithms, malformed digests, and
    /// altered bodies.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`EvidenceError`] on any failure.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, EvidenceError> {
        if bytes.len() > MAX_EVIDENCE_FILE_BYTES {
            return Err(EvidenceError::ProtocolLimitExceeded);
        }

        let mut reader = CanonicalCborReader::new(bytes);
        if reader.read_array_len().map_err(from_protocol)? != ENVELOPE_FIELD_COUNT {
            return Err(EvidenceError::InvalidData);
        }
        if reader.read_text_string().map_err(from_protocol)? != EVIDENCE_RECORD_TYPE_ID_V1 {
            return Err(EvidenceError::InvalidData);
        }
        if reader.read_text_string().map_err(from_protocol)? != EVIDENCE_HASH_ALGORITHM_ID_V1 {
            return Err(EvidenceError::InvalidData);
        }
        let recorded_digest = read_digest(&mut reader)?;
        let body = reader.read_byte_string().map_err(from_protocol)?;
        reader.finish().map_err(from_protocol)?;

        // Verify the body digest before trusting any decoded field.
        let framed = evidence_domain_input(body);
        let recomputed = Blake3HashProviderV1.hash(&framed);
        if recomputed != recorded_digest {
            return Err(EvidenceError::InvalidData);
        }

        // Decode the 12-element body.
        let mut body_reader = CanonicalCborReader::new(body);
        if body_reader.read_array_len().map_err(from_protocol)? != BODY_FIELD_COUNT {
            return Err(EvidenceError::InvalidData);
        }

        // 1. purpose
        let purpose = body_reader.read_text_string().map_err(from_protocol)?;
        if purpose != OOTLE_ANCHOR_PURPOSE_ID_V1 {
            return Err(EvidenceError::InvalidData);
        }

        // 2. network
        let network = OotleNetworkIdV1::new(
            body_reader
                .read_text_string()
                .map_err(from_protocol)?
                .to_owned(),
        )
        .map_err(|_| EvidenceError::InvalidData)?;

        // 3. manifest hash
        let manifest_hash = ManifestHash::new(read_digest(&mut body_reader)?);

        // 4. archive hash
        let archive_hash = ArchiveHashV1::new(read_digest(&mut body_reader)?);

        // 5. anchor digest
        let anchor_digest = OotleAnchorRecordHashV1::new(read_digest(&mut body_reader)?);

        // 6. optional transaction id
        let transaction_id = decode_option_text_value(&mut body_reader)?
            .map(|text| AnchorTransactionId::new(text).map_err(|_| EvidenceError::InvalidData))
            .transpose()?;

        // 7. optional ledger position (read and consumed from the body but not
        // stored in the struct; it is encoded only during construction).
        let _ledger_position = decode_option_u64_value(&mut body_reader)?;

        // 8. final status
        let final_status_text = body_reader.read_text_string().map_err(from_protocol)?;
        let final_status =
            final_status_from_str(final_status_text).ok_or(EvidenceError::InvalidData)?;

        // 9. receipt source
        let receipt_source_text = body_reader.read_text_string().map_err(from_protocol)?;
        let receipt_source =
            receipt_source_from_str(receipt_source_text).ok_or(EvidenceError::InvalidData)?;

        // 10. lifecycle phase
        let phase_text = body_reader.read_text_string().map_err(from_protocol)?;
        let phase = phase_from_str(phase_text).ok_or(EvidenceError::InvalidData)?;

        // 11. snapshot digest
        let snapshot_digest = read_digest(&mut body_reader)?;

        // 12. evidence digest algorithm
        let algo = body_reader.read_text_string().map_err(from_protocol)?;
        if algo != BLAKE3_256_HASH_ALGORITHM_ID_V1 {
            return Err(EvidenceError::InvalidData);
        }

        body_reader.finish().map_err(from_protocol)?;

        Ok(Self {
            envelope: bytes.to_vec(),
            body_digest: recorded_digest,
            network,
            manifest_hash,
            archive_hash,
            anchor_digest,
            transaction_id,
            final_status,
            receipt_source,
            phase,
            snapshot_digest,
        })
    }
}

/// Writes `record`'s canonical bytes to `path` atomically.
///
/// # Errors
///
/// Returns a bounded [`EvidenceFileError`] on any failure.
pub fn write_evidence_atomic(
    path: &Path,
    record: &AnchorEvidenceRecordV1,
) -> Result<(), EvidenceFileError> {
    let bytes = record.canonical_bytes();
    if bytes.len() > MAX_EVIDENCE_FILE_BYTES {
        return Err(EvidenceFileError::ProtocolLimitExceeded);
    }
    let mut tmp = std::ffi::OsString::from(path.as_os_str());
    tmp.push(".tmp");
    let tmp_path = Path::new(&tmp);
    let cleanup = |p: &Path| {
        let _ = std::fs::remove_file(p);
    };
    let result = (|| -> Result<(), EvidenceFileError> {
        let mut file = std::fs::File::create(tmp_path).map_err(|_| EvidenceFileError::IoFailure)?;
        use std::io::Write;
        file.write_all(&bytes)
            .map_err(|_| EvidenceFileError::IoFailure)?;
        file.flush().map_err(|_| EvidenceFileError::IoFailure)?;
        file.sync_all().map_err(|_| EvidenceFileError::IoFailure)?;
        drop(file);
        std::fs::rename(tmp_path, path).map_err(|_| EvidenceFileError::AtomicRenameFailure)
    })();
    if result.is_err() {
        cleanup(tmp_path);
    }
    result
}

fn encode_envelope(body: &[u8], body_digest: &[u8; 32]) -> Result<Vec<u8>, EvidenceError> {
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(ENVELOPE_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(EVIDENCE_RECORD_TYPE_ID_V1)
        .map_err(from_protocol)?;
    writer
        .write_text_string(EVIDENCE_HASH_ALGORITHM_ID_V1)
        .map_err(from_protocol)?;
    writer
        .write_byte_string(body_digest)
        .map_err(from_protocol)?;
    writer.write_byte_string(body).map_err(from_protocol)?;
    Ok(writer.into_bytes())
}

#[allow(clippy::too_many_arguments)]
fn encode_body(
    archive: &ArchiveProofInputs,
    transaction_id: Option<&str>,
    ledger_position: Option<u64>,
    final_status: &str,
    receipt_source: &str,
    phase: UnifiedAnchorLifecyclePhase,
    snapshot_digest: &[u8; 32],
) -> Result<Vec<u8>, EvidenceError> {
    let mut writer = CanonicalCborWriter::new();
    writer
        .write_array_len(BODY_FIELD_COUNT)
        .map_err(from_protocol)?;
    writer
        .write_text_string(OOTLE_ANCHOR_PURPOSE_ID_V1)
        .map_err(from_protocol)?;
    writer
        .write_text_string(archive.network().as_str())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(archive.manifest_hash().as_bytes())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(archive.archive_hash().as_bytes())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(archive.anchor_digest().as_bytes())
        .map_err(from_protocol)?;
    encode_option_text(&mut writer, transaction_id)?;
    encode_option_u64(&mut writer, ledger_position)?;
    writer
        .write_text_string(final_status)
        .map_err(from_protocol)?;
    writer
        .write_text_string(receipt_source)
        .map_err(from_protocol)?;
    writer
        .write_text_string(phase.as_str())
        .map_err(from_protocol)?;
    writer
        .write_byte_string(snapshot_digest)
        .map_err(from_protocol)?;
    writer
        .write_text_string(BLAKE3_256_HASH_ALGORITHM_ID_V1)
        .map_err(from_protocol)?;
    Ok(writer.into_bytes())
}

fn encode_option_text(
    writer: &mut CanonicalCborWriter,
    value: Option<&str>,
) -> Result<(), EvidenceError> {
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

fn encode_option_u64(
    writer: &mut CanonicalCborWriter,
    value: Option<u64>,
) -> Result<(), EvidenceError> {
    match value {
        Some(value) => {
            writer.write_array_len(1).map_err(from_protocol)?;
            writer.write_unsigned(value);
        }
        None => {
            writer.write_array_len(0).map_err(from_protocol)?;
        }
    }
    Ok(())
}

fn evidence_domain_input(body: &[u8]) -> Vec<u8> {
    let label = EVIDENCE_DOMAIN_LABEL_V1.as_bytes();
    let mut framed =
        Vec::with_capacity(EVIDENCE_FRAME_PREFIX_V1.len() + 1 + label.len() + 1 + body.len());
    framed.extend_from_slice(EVIDENCE_FRAME_PREFIX_V1);
    framed.push(0);
    framed.extend_from_slice(label);
    framed.push(0);
    framed.extend_from_slice(body);
    framed
}

fn from_protocol(error: ProtocolError) -> EvidenceError {
    match error.code() {
        ValidationCode::ProtocolLimitExceeded => EvidenceError::ProtocolLimitExceeded,
        _ => EvidenceError::InvalidData,
    }
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

fn read_digest(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], EvidenceError> {
    <[u8; 32]>::try_from(reader.read_byte_string().map_err(from_protocol)?)
        .map_err(|_| EvidenceError::InvalidData)
}

fn decode_option_text_value(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<Option<String>, EvidenceError> {
    let len = reader.read_array_len().map_err(from_protocol)?;
    match len {
        0 => Ok(None),
        1 => Ok(Some(
            reader.read_text_string().map_err(from_protocol)?.to_owned(),
        )),
        _ => Err(EvidenceError::InvalidData),
    }
}

fn decode_option_u64_value(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<Option<u64>, EvidenceError> {
    let len = reader.read_array_len().map_err(from_protocol)?;
    match len {
        0 => Ok(None),
        1 => Ok(Some(reader.read_unsigned().map_err(from_protocol)?)),
        _ => Err(EvidenceError::InvalidData),
    }
}

fn final_status_from_str(text: &str) -> Option<&'static str> {
    match text {
        "ACCEPTED" => Some(FINAL_STATUS_ACCEPTED),
        "FEE_ONLY_ACCEPTED" => Some(FINAL_STATUS_FEE_ONLY),
        "REJECTED" => Some(FINAL_STATUS_REJECTED),
        "VERIFICATION_FAILED" => Some(FINAL_STATUS_VERIFICATION_FAILED),
        "DISAGREEMENT" => Some(FINAL_STATUS_DISAGREEMENT),
        "POLL_EXHAUSTED_UNKNOWN" => Some(FINAL_STATUS_POLL_EXHAUSTED_UNKNOWN),
        "REJECTED_BY_APPROVER" => Some(FINAL_STATUS_REJECTED_BY_APPROVER),
        _ => None,
    }
}

fn receipt_source_from_str(text: &str) -> Option<&'static str> {
    match text {
        "INDEPENDENT_INDEXER" => Some(SOURCE_INDEPENDENT_INDEXER),
        "WALLETD_AND_INDEXER" => Some(SOURCE_WALLETD_AND_INDEXER),
        "NONE" => Some(SOURCE_NONE),
        _ => None,
    }
}

fn phase_from_str(text: &str) -> Option<UnifiedAnchorLifecyclePhase> {
    use UnifiedAnchorLifecyclePhase::*;
    match text {
        "NOT_PREPARED" => Some(NotPrepared),
        "PREPARED" => Some(Prepared),
        "APPROVED" => Some(Approved),
        "REJECTED_BY_APPROVER" => Some(RejectedByApprover),
        "SUBMITTED" => Some(Submitted),
        "POLLING_IN_PROGRESS" => Some(PollingInProgress),
        "FINALIZED_ACCEPT" => Some(FinalizedAccept),
        "FINALIZED_FEE_ONLY" => Some(FinalizedFeeOnly),
        "FINALIZED_REJECT" => Some(FinalizedReject),
        "FINALIZED_VERIFICATION_FAILED" => Some(FinalizedVerificationFailed),
        "FINALIZED_DISAGREEMENT" => Some(FinalizedDisagreement),
        "UNKNOWN" => Some(Unknown),
        _ => None,
    }
}
