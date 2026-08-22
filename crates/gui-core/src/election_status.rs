//! Authenticated, election-bound lifecycle status statements.
//!
//! The frozen election package (manifest, registry, option set) is immutable,
//! but the lifecycle itself keeps moving forward on the organizer's
//! authoritative workspace: `FROZEN -> OPEN -> CLOSED -> VERIFIED ->
//! FINALIZED`. A voter on an independent computer has no way to learn about
//! those post-freeze transitions from the frozen artifacts alone — and the
//! application must never guess a lifecycle forward (fail closed).
//!
//! This module defines the authenticated bridge: a canonical CBOR statement
//! signed by the SAME release-pinned transport authority root key that signs
//! transport descriptors (no new trust root). A voter verifies it against the
//! exact imported election identity and advances only its local mutable view
//! of the lifecycle, never the frozen commitments themselves.
//!
//! Trust model:
//!
//! * Every statement is bound to one exact election: election id, frozen
//!   manifest hash, AND frozen registry commitment. A statement for any other
//!   election, manifest, or registry fails closed before its signature is
//!   considered.
//! * Verification requires a release-pinned root
//!   ([`TransportAuthorityRootSetV1`]); unknown or revoked roots fail closed.
//! * Monotonicity: every statement carries an organizer-assigned generation.
//!   The voter records the highest accepted generation per election; stale
//!   generations are rejected, equal generations with different content fail
//!   closed, and the local lifecycle can never move backward. An older OPEN
//!   artifact can therefore never roll a CLOSED election back to OPEN.
//!
//! What this module deliberately does NOT do:
//!
//! * It does not mutate any frozen election commitment; only the mutable
//!   lifecycle view advances through the same append-only transitions the
//!   organizer uses.
//! * It carries no voter credential, ballot choice, proof, nullifier, or
//!   anything that could link a voter to a ballot: asking "is this election
//!   open?" exposes only the public lifecycle state of a public election.

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use ed25519_dalek::{Signer, SigningKey};
use tari_cc_private_ballot_ballot::ElectionLifecycleStateV1;
use tari_cc_private_ballot_protocol::{
    CanonicalCborReader, CanonicalCborWriter, HashDomain, ManifestHash, RegistryCommitment,
    domain_separated_input,
};

use crate::error::{GuiCoreError, GuiErrorCategory};
use crate::hex::to_lower_hex;
use crate::private_intake_inbox::{
    ensure_direct_directory, metadata_is_reparse_point, sync_directory_best_effort,
    write_create_new_sync,
};
use crate::session::GuiElectionSessionV1;
use crate::transport::{TransportAuthorityRootSetV1, TransportError};

/// Wire format version of the status statement. Any other version fails closed.
pub const ELECTION_STATUS_STATEMENT_VERSION_V1: u64 = 1;

/// Domain-separated protocol identifier embedded in every statement.
const ELECTION_STATUS_PROTOCOL_ID: &str = "tari-cc-private-ballot/election-status/v1";

/// Bounded canonical size of a serialized statement. Even the largest
/// well-formed statement is far below this; the bound rejects hostile inputs
/// before parsing.
pub const MAX_ELECTION_STATUS_STATEMENT_BYTES: usize = 4 * 1024;

/// Field bounds mirroring the transport descriptor policy.
const MAX_STATUS_ELECTION_ID_BYTES: usize = 128;
const MAX_STATUS_ROOT_KEY_ID_BYTES: usize = 256;
const STATUS_GENERATION_MINIMUM: u64 = 1;

/// Stable state codes. `DRAFT` is intentionally not representable: an
/// organizer never publishes pre-freeze state to voters.
const STATUS_STATE_CODE_FROZEN: u64 = 1;
const STATUS_STATE_CODE_OPEN: u64 = 2;
const STATUS_STATE_CODE_CLOSED: u64 = 3;
const STATUS_STATE_CODE_VERIFIED: u64 = 4;
const STATUS_STATE_CODE_FINALIZED: u64 = 5;

/// Backend-controlled directory name below the app-data root for voter-side
/// durable election-status knowledge.
pub const VOTER_ELECTION_STATUS_DIRECTORY_NAME: &str = "voter-election-status";

/// Length in characters of a canonical lowercase BLAKE3 hex string.
const MANIFEST_HASH_HEX_LEN: usize = 64;

/// Record format id / version for one persisted voter-side status record.
const RECORD_VERSION: u64 = 1;
const RECORD_TYPE_ID: &str = "TARI_CC_PRIVATE_BALLOT_VOTER_ELECTION_STATUS_RECORD_V1";

/// Why an authenticated election-status statement was refused.
///
/// Every variant fails closed: the caller's lifecycle knowledge and session
/// state are left exactly as they were.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElectionStatusErrorV1 {
    /// The bytes are not a canonical version-one status statement.
    MalformedStatement,
    /// The statement declares an unsupported format version.
    UnsupportedVersion,
    /// The statement exceeds the bounded canonical size.
    OversizedStatement,
    /// `DRAFT` can never be published to voters.
    DraftNotSignable,
    /// The selected authority root is unknown or revoked.
    UntrustedRoot,
    /// The signature does not verify under the pinned root.
    InvalidSignature,
    /// The statement belongs to a different election.
    WrongElection,
    /// The statement is bound to a different frozen manifest.
    WrongManifestHash,
    /// The statement is bound to a different frozen registry commitment.
    WrongRegistryCommitment,
    /// A stale artifact replayed an older generation than already-accepted
    /// durable knowledge.
    StaleGeneration,
    /// Two different states were asserted at the same generation.
    ConflictingGeneration,
    /// The statement would move the local lifecycle backward (e.g. OPEN after
    /// CLOSED), or a planned forward advance was refused by the append-only
    /// transition table.
    LifecycleRollbackRejected,
}

impl ElectionStatusErrorV1 {
    /// The stable human-readable refusal reason.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::MalformedStatement => "the election status artifact is not a canonical statement",
            Self::UnsupportedVersion => "the election status artifact uses an unsupported version",
            Self::OversizedStatement => "the election status artifact exceeds the size limit",
            Self::DraftNotSignable => "a draft election cannot be published as election status",
            Self::UntrustedRoot => "the election status signer is not a trusted authority",
            Self::InvalidSignature => "the election status signature is invalid",
            Self::WrongElection => "the election status artifact is for a different election",
            Self::WrongManifestHash => {
                "the election status artifact is bound to a different frozen manifest"
            }
            Self::WrongRegistryCommitment => {
                "the election status artifact is bound to a different frozen registry"
            }
            Self::StaleGeneration => "the election status artifact is older than accepted status",
            Self::ConflictingGeneration => {
                "conflicting election status at the same generation was rejected"
            }
            Self::LifecycleRollbackRejected => {
                "the election status artifact would move the election backward"
            }
        }
    }
}

impl fmt::Display for ElectionStatusErrorV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for ElectionStatusErrorV1 {}

impl From<ElectionStatusErrorV1> for GuiCoreError {
    fn from(error: ElectionStatusErrorV1) -> Self {
        let category = match error {
            ElectionStatusErrorV1::WrongElection
            | ElectionStatusErrorV1::WrongManifestHash
            | ElectionStatusErrorV1::WrongRegistryCommitment => GuiErrorCategory::BindingMismatch,
            ElectionStatusErrorV1::LifecycleRollbackRejected
            | ElectionStatusErrorV1::ConflictingGeneration => {
                GuiErrorCategory::InvalidLifecycleTransition
            }
            _ => GuiErrorCategory::InvalidInput,
        };
        GuiCoreError::new(
            "GUI_ELECTION_STATUS_REJECTED",
            category,
            Some("election-status"),
            error.message(),
        )
    }
}

const fn state_code(state: ElectionLifecycleStateV1) -> Result<u64, ElectionStatusErrorV1> {
    match state {
        ElectionLifecycleStateV1::Frozen => Ok(STATUS_STATE_CODE_FROZEN),
        ElectionLifecycleStateV1::Open => Ok(STATUS_STATE_CODE_OPEN),
        ElectionLifecycleStateV1::Closed => Ok(STATUS_STATE_CODE_CLOSED),
        ElectionLifecycleStateV1::Verified => Ok(STATUS_STATE_CODE_VERIFIED),
        ElectionLifecycleStateV1::Finalized => Ok(STATUS_STATE_CODE_FINALIZED),
        ElectionLifecycleStateV1::Draft => Err(ElectionStatusErrorV1::DraftNotSignable),
    }
}

fn state_from_code(code: u64) -> Result<ElectionLifecycleStateV1, ElectionStatusErrorV1> {
    match code {
        STATUS_STATE_CODE_FROZEN => Ok(ElectionLifecycleStateV1::Frozen),
        STATUS_STATE_CODE_OPEN => Ok(ElectionLifecycleStateV1::Open),
        STATUS_STATE_CODE_CLOSED => Ok(ElectionLifecycleStateV1::Closed),
        STATUS_STATE_CODE_VERIFIED => Ok(ElectionLifecycleStateV1::Verified),
        STATUS_STATE_CODE_FINALIZED => Ok(ElectionLifecycleStateV1::Finalized),
        _ => Err(ElectionStatusErrorV1::MalformedStatement),
    }
}

/// One authenticated, election-bound lifecycle statement.
///
/// Canonical CBOR layout (9 elements):
/// `[version, protocol_id, election_id, manifest_hash(32), registry_commitment(32), state_code, generation, root_key_id, signature(64)]`
///
/// The Ed25519 signature covers the domain-separated unsigned canonical CBOR
/// (the same array without the signature) using the release-pinned transport
/// authority root key — the identical trust root that authenticates transport
/// descriptors. No new trust root is introduced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedElectionStatusStatementV1 {
    election_id: Vec<u8>,
    manifest_hash: ManifestHash,
    registry_commitment: RegistryCommitment,
    state: ElectionLifecycleStateV1,
    generation: u64,
    root_key_id: String,
    signature: [u8; 64],
}

impl AuthenticatedElectionStatusStatementV1 {
    /// Signs one status statement with the transport authority root signing
    /// key. Named for provisioning/organizer use: the private key never lives
    /// on the voter side.
    ///
    /// # Errors
    ///
    /// Returns a bounded error if any field violates its bound or the state is
    /// `DRAFT`.
    #[allow(clippy::too_many_arguments)]
    pub fn sign_for_test_or_ceremony(
        election_id: Vec<u8>,
        manifest_hash: ManifestHash,
        registry_commitment: RegistryCommitment,
        state: ElectionLifecycleStateV1,
        generation: u64,
        root_key_id: String,
        signing_key: &SigningKey,
    ) -> Result<Self, ElectionStatusErrorV1> {
        let mut statement = Self {
            election_id,
            manifest_hash,
            registry_commitment,
            state,
            generation,
            root_key_id,
            signature: [0; 64],
        };
        statement.validate_fields()?;
        statement.signature = signing_key.sign(&statement.signing_message()?).to_bytes();
        Ok(statement)
    }

    fn validate_fields(&self) -> Result<(), ElectionStatusErrorV1> {
        if self.election_id.is_empty()
            || self.election_id.len() > MAX_STATUS_ELECTION_ID_BYTES
            || self.root_key_id.is_empty()
            || self.root_key_id.len() > MAX_STATUS_ROOT_KEY_ID_BYTES
            || self.generation < STATUS_GENERATION_MINIMUM
        {
            return Err(ElectionStatusErrorV1::MalformedStatement);
        }
        state_code(self.state)?;
        Ok(())
    }

    /// The canonical election identifier this statement is bound to.
    #[must_use]
    pub fn election_id(&self) -> &[u8] {
        &self.election_id
    }

    /// The frozen manifest hash this statement is bound to.
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }

    /// The frozen registry commitment this statement is bound to.
    #[must_use]
    pub const fn registry_commitment(&self) -> RegistryCommitment {
        self.registry_commitment
    }

    /// The asserted lifecycle state (`FROZEN`..=`FINALIZED`, never `DRAFT`).
    #[must_use]
    pub const fn state(&self) -> ElectionLifecycleStateV1 {
        self.state
    }

    /// The organizer-assigned monotonic generation of this statement.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// The pinned authority-root selector used to sign this statement.
    #[must_use]
    pub fn root_key_id(&self) -> &str {
        &self.root_key_id
    }

    fn unsigned_canonical_cbor(&self) -> Result<Vec<u8>, ElectionStatusErrorV1> {
        let mut writer = CanonicalCborWriter::new();
        writer
            .write_array_len(8)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer.write_unsigned(ELECTION_STATUS_STATEMENT_VERSION_V1);
        writer
            .write_text_string(ELECTION_STATUS_PROTOCOL_ID)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer
            .write_byte_string(&self.election_id)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer
            .write_byte_string(self.manifest_hash.as_bytes())
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer
            .write_byte_string(self.registry_commitment.as_bytes())
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer.write_unsigned(state_code(self.state)?);
        writer.write_unsigned(self.generation);
        writer
            .write_text_string(&self.root_key_id)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        Ok(writer.into_bytes())
    }

    fn signing_message(&self) -> Result<Vec<u8>, ElectionStatusErrorV1> {
        Ok(domain_separated_input(
            HashDomain::ElectionStatusStatementV1,
            &self.unsigned_canonical_cbor()?,
        ))
    }

    /// Verifies this statement against the pinned authority roots AND the
    /// exact expected election identity. Binding checks run BEFORE signature
    /// processing so a wrong-election artifact is classified truthfully.
    ///
    /// # Errors
    ///
    /// Returns a bounded error on any binding mismatch, untrusted root, or
    /// invalid signature.
    pub fn verify(
        &self,
        roots: &TransportAuthorityRootSetV1,
        expected_election_id: &[u8],
        expected_manifest_hash: ManifestHash,
        expected_registry_commitment: RegistryCommitment,
    ) -> Result<(), ElectionStatusErrorV1> {
        self.validate_fields()?;
        if self.election_id != expected_election_id {
            return Err(ElectionStatusErrorV1::WrongElection);
        }
        if self.manifest_hash != expected_manifest_hash {
            return Err(ElectionStatusErrorV1::WrongManifestHash);
        }
        if self.registry_commitment != expected_registry_commitment {
            return Err(ElectionStatusErrorV1::WrongRegistryCommitment);
        }
        match roots.verify_by_root_id(
            &self.root_key_id,
            &self.signing_message()?,
            &self.signature,
        ) {
            Ok(()) => Ok(()),
            Err(TransportError::CryptoFailure) => Err(ElectionStatusErrorV1::InvalidSignature),
            Err(_) => Err(ElectionStatusErrorV1::UntrustedRoot),
        }
    }

    /// Encodes the full signed statement as canonical CBOR.
    ///
    /// # Errors
    ///
    /// Returns a bounded error if encoding fails or fields violate bounds.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ElectionStatusErrorV1> {
        self.validate_fields()?;
        let mut writer = CanonicalCborWriter::new();
        writer
            .write_array_len(9)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer.write_unsigned(ELECTION_STATUS_STATEMENT_VERSION_V1);
        writer
            .write_text_string(ELECTION_STATUS_PROTOCOL_ID)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer
            .write_byte_string(&self.election_id)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer
            .write_byte_string(self.manifest_hash.as_bytes())
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer
            .write_byte_string(self.registry_commitment.as_bytes())
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer.write_unsigned(state_code(self.state)?);
        writer.write_unsigned(self.generation);
        writer
            .write_text_string(&self.root_key_id)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        writer
            .write_byte_string(&self.signature)
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        Ok(writer.into_bytes())
    }

    /// Strictly decodes a canonical CBOR statement. The decode re-encodes and
    /// byte-compares so only canonical encodings are accepted, and the total
    /// input size is bounded before parsing.
    ///
    /// # Errors
    ///
    /// Returns [`ElectionStatusErrorV1::OversizedStatement`] above the size
    /// bound and [`ElectionStatusErrorV1::UnsupportedVersion`] /
    /// [`ElectionStatusErrorV1::MalformedStatement`] for non-canonical input.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ElectionStatusErrorV1> {
        if bytes.len() > MAX_ELECTION_STATUS_STATEMENT_BYTES {
            return Err(ElectionStatusErrorV1::OversizedStatement);
        }
        let mut reader = CanonicalCborReader::new(bytes);
        let array_len = reader
            .read_array_len()
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        if array_len != 9 {
            return Err(ElectionStatusErrorV1::MalformedStatement);
        }
        let version = reader
            .read_unsigned()
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        if version != ELECTION_STATUS_STATEMENT_VERSION_V1 {
            return Err(ElectionStatusErrorV1::UnsupportedVersion);
        }
        let protocol = reader
            .read_text_string()
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        if protocol != ELECTION_STATUS_PROTOCOL_ID {
            return Err(ElectionStatusErrorV1::MalformedStatement);
        }
        let election_id = reader
            .read_byte_string()
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?
            .to_vec();
        let manifest_hash = ManifestHash::new(read_fixed_32(&mut reader)?);
        let registry_commitment = RegistryCommitment::new(read_fixed_32(&mut reader)?);
        let state = state_from_code(
            reader
                .read_unsigned()
                .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?,
        )?;
        let generation = reader
            .read_unsigned()
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        let root_key_id = reader
            .read_text_string()
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?
            .to_owned();
        let signature = read_fixed_signature(&mut reader)?;
        reader
            .finish()
            .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
        let statement = Self {
            election_id,
            manifest_hash,
            registry_commitment,
            state,
            generation,
            root_key_id,
            signature,
        };
        statement.validate_fields()?;
        if statement.to_canonical_cbor()? != bytes {
            return Err(ElectionStatusErrorV1::MalformedStatement);
        }
        Ok(statement)
    }
}

fn read_fixed_32(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], ElectionStatusErrorV1> {
    let bytes = reader
        .read_byte_string()
        .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
    bytes
        .try_into()
        .map_err(|_| ElectionStatusErrorV1::MalformedStatement)
}

fn read_fixed_signature(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<[u8; 64], ElectionStatusErrorV1> {
    let bytes = reader
        .read_byte_string()
        .map_err(|_| ElectionStatusErrorV1::MalformedStatement)?;
    bytes
        .try_into()
        .map_err(|_| ElectionStatusErrorV1::MalformedStatement)
}

/// Voter-side monotonic knowledge about one election's published lifecycle.
///
/// This is deliberately tiny so the shell can persist it per election and
/// reconstruct it across restarts: restarting must never forget the highest
/// accepted generation, or an old OPEN artifact could roll local knowledge
/// backward after a CLOSED had been accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElectionStatusKnowledgeV1 {
    accepted_generation: Option<u64>,
    accepted_state: Option<ElectionLifecycleStateV1>,
}

impl Default for ElectionStatusKnowledgeV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl ElectionStatusKnowledgeV1 {
    /// Fresh knowledge: nothing accepted yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            accepted_generation: None,
            accepted_state: None,
        }
    }

    /// Reconstructs knowledge from previously accepted values (restart path).
    #[must_use]
    pub const fn from_accepted(state: ElectionLifecycleStateV1, generation: u64) -> Self {
        Self {
            accepted_generation: Some(generation),
            accepted_state: Some(state),
        }
    }

    /// The highest accepted generation, if any.
    #[must_use]
    pub const fn accepted_generation(&self) -> Option<u64> {
        self.accepted_generation
    }

    /// The accepted lifecycle state, if any.
    #[must_use]
    pub const fn accepted_state(&self) -> Option<ElectionLifecycleStateV1> {
        self.accepted_state
    }

    /// Plans whether one ALREADY-AUTHENTICATED statement may be applied.
    ///
    /// Rules (all deterministic; no wall-clock involvement):
    ///
    /// 1. The asserted state may never rank below the session's current state
    ///    — an old OPEN artifact cannot roll a CLOSED session back.
    /// 2. A generation strictly below remembered knowledge is stale and is
    ///    rejected even when its state would be a no-op, so replayed artifacts
    ///    stay loudly rejected instead of silently ignored.
    /// 3. Equal generations must repeat the exact already-accepted content
    ///    (idempotent re-application, e.g. after a fresh session import) or
    ///    they conflict and fail closed.
    ///
    /// Returns the target state the session should reach.
    ///
    /// # Errors
    ///
    /// [`ElectionStatusErrorV1::LifecycleRollbackRejected`],
    /// [`ElectionStatusErrorV1::StaleGeneration`], or
    /// [`ElectionStatusErrorV1::ConflictingGeneration`] — the caller's state
    /// is never mutated in those cases.
    pub fn plan(
        &self,
        statement_state: ElectionLifecycleStateV1,
        statement_generation: u64,
        current_session_state: ElectionLifecycleStateV1,
    ) -> Result<ElectionLifecycleStateV1, ElectionStatusErrorV1> {
        if statement_state < current_session_state {
            return Err(ElectionStatusErrorV1::LifecycleRollbackRejected);
        }
        if let Some(previous_generation) = self.accepted_generation {
            if statement_generation < previous_generation {
                return Err(ElectionStatusErrorV1::StaleGeneration);
            }
            if statement_generation == previous_generation
                && self.accepted_state != Some(statement_state)
            {
                return Err(ElectionStatusErrorV1::ConflictingGeneration);
            }
        }
        Ok(statement_state)
    }

    /// Records one successfully applied statement.
    pub fn record(&mut self, state: ElectionLifecycleStateV1, generation: u64) {
        self.accepted_state = Some(state);
        self.accepted_generation = Some(generation);
    }
}

/// Advances a session's mutable lifecycle FORWARD to `target` by applying the
/// exact single-step transitions in order (the same methods the organizer
/// shell uses). Never moves backward: callers must plan first via
/// [`ElectionStatusKnowledgeV1::plan`]. Frozen commitments inside the session
/// are untouched by construction.
///
/// # Errors
///
/// Returns [`ElectionStatusErrorV1::LifecycleRollbackRejected`] if any
/// transition is refused (an internal inconsistency, since planning already
/// guarantees a forward-only target).
fn advance_session_lifecycle_to_state_v1(
    session: &mut GuiElectionSessionV1,
    target: ElectionLifecycleStateV1,
) -> Result<(), ElectionStatusErrorV1> {
    use ElectionLifecycleStateV1::{Closed, Draft, Finalized, Frozen, Open, Verified};
    while session.lifecycle_state_v1() < target {
        let result = match session.lifecycle_state_v1() {
            Frozen => session.open(),
            Open => session.close(),
            Closed => session.mark_verified(),
            Verified => session.finalize(),
            Draft | Finalized => return Err(ElectionStatusErrorV1::LifecycleRollbackRejected),
        };
        result.map_err(|_| ElectionStatusErrorV1::LifecycleRollbackRejected)?;
    }
    Ok(())
}

/// Outcome of applying one authenticated status statement to a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedElectionStatusV1 {
    /// The session's effective lifecycle after application.
    pub effective_state: ElectionLifecycleStateV1,
    /// Whether the session actually moved forward this time (false for an
    /// idempotent re-application).
    pub advanced: bool,
    /// The accepted statement's generation.
    pub generation: u64,
    /// The accepted statement's asserted state.
    pub asserted_state: ElectionLifecycleStateV1,
}

/// THE single authoritative voter-side application path for authenticated
/// election-status evidence, shared by the offline import and any online
/// retrieval route.
///
/// Order of operations (every failure leaves the session untouched):
///
/// 1. Parse the bounded canonical statement.
/// 2. Verify bindings against THIS session's exact election identity
///    (election id + frozen manifest hash + frozen registry commitment).
/// 3. Verify the signature under a pinned, non-revoked authority root.
/// 4. Plan monotonic application against durable knowledge + current state.
/// 5. Advance the session's mutable lifecycle FORWARD through the append-only
///    transitions (frozen commitments are never touched).
/// 6. Record the accepted generation in knowledge.
///
/// # Errors
///
/// Returns a bounded error and leaves both `knowledge` and `session`
/// unchanged whenever parsing, binding, signature, or monotonicity checks
/// refuse the statement.
pub fn verify_and_apply_election_status_statement_v1(
    statement_bytes: &[u8],
    roots: &TransportAuthorityRootSetV1,
    knowledge: &mut ElectionStatusKnowledgeV1,
    session: &mut GuiElectionSessionV1,
) -> Result<AppliedElectionStatusV1, ElectionStatusErrorV1> {
    let statement = AuthenticatedElectionStatusStatementV1::from_canonical_cbor(statement_bytes)?;
    let artifacts = session.artifacts();
    statement.verify(
        roots,
        artifacts.manifest().election_id().as_bytes(),
        artifacts.manifest_hash(),
        artifacts.registry_commitment(),
    )?;
    let current = session.lifecycle_state_v1();
    let target = knowledge.plan(statement.state(), statement.generation(), current)?;

    if target > current {
        advance_session_lifecycle_to_state_v1(session, target)?;
    }
    knowledge.record(statement.state(), statement.generation());
    Ok(AppliedElectionStatusV1 {
        effective_state: session.lifecycle_state_v1(),
        advanced: target > current,
        generation: statement.generation(),
        asserted_state: statement.state(),
    })
}

/// One persisted voter-side record: the trusted root anchor used at acceptance
/// time plus the raw accepted statement bytes. Persisting the anchor keeps the
/// record self-contained so a restart can re-verify it offline, without any
/// transport bundle being configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistedElectionStatusRecordV1 {
    pub root_key_id: String,
    pub root_public_key: [u8; 32],
    pub statement: AuthenticatedElectionStatusStatementV1,
}

/// Returns the app-owned per-election status record path.
///
/// # Errors
///
/// Returns a bounded error if `manifest_hash_hex` is not a canonical 64-char
/// lowercase hex string (so no arbitrary value can influence the path).
pub fn voter_election_status_record_path_v1(
    status_dir: &Path,
    manifest_hash_hex: &str,
) -> Result<PathBuf, GuiCoreError> {
    validate_manifest_hash_hex(manifest_hash_hex)?;
    Ok(status_dir.join(format!("status-{manifest_hash_hex}.cbor")))
}

/// Ensures the backend-owned voter-election-status directory exists.
///
/// # Errors
///
/// Returns a bounded error if the path exists but is unsafe (symlink/reparse
/// point/non-directory) or cannot be created.
pub fn ensure_voter_election_status_directory_v1(
    app_data_root: &Path,
) -> Result<PathBuf, GuiCoreError> {
    let dir = app_data_root.join(VOTER_ELECTION_STATUS_DIRECTORY_NAME);
    ensure_direct_directory(&dir)?;
    Ok(dir)
}

/// Persists the accepted status record for one election (atomic create-new +
/// fsync + rename). Writing the newest accepted record replaces the previous
/// one via rename, so a crash mid-write can never leave a torn record.
///
/// # Errors
///
/// Returns a bounded error if the directory or file cannot be written safely.
pub fn persist_election_status_record_v1(
    status_dir: &Path,
    manifest_hash_hex: &str,
    record: &PersistedElectionStatusRecordV1,
) -> Result<(), GuiCoreError> {
    validate_manifest_hash_hex(manifest_hash_hex)?;
    ensure_direct_directory(status_dir)?;
    let final_path = voter_election_status_record_path_v1(status_dir, manifest_hash_hex)?;
    let statement_bytes = record
        .statement
        .to_canonical_cbor()
        .map_err(GuiCoreError::from)?;
    let mut writer = CanonicalCborWriter::new();
    let write = |action: Result<(), tari_cc_private_ballot_protocol::ProtocolError>| {
        action.map_err(|_| status_io_error())
    };
    write(writer.write_array_len(5))?;
    writer.write_unsigned(RECORD_VERSION);
    write(writer.write_text_string(RECORD_TYPE_ID))?;
    write(writer.write_byte_string(&record.root_public_key))?;
    write(writer.write_text_string(&record.root_key_id))?;
    write(writer.write_byte_string(&statement_bytes))?;
    let bytes = writer.into_bytes();

    let tmp_path = final_path.with_extension("cbor.tmp");
    let _ = fs::remove_file(&tmp_path);
    write_create_new_sync(&tmp_path, &bytes)?;
    match fs::rename(&tmp_path, &final_path) {
        Ok(()) => {
            sync_directory_best_effort(status_dir);
            Ok(())
        }
        Err(_) => {
            let _ = fs::remove_file(&tmp_path);
            Err(status_io_error())
        }
    }
}

/// Loads and fully re-verifies the persisted status record for one election
/// against the supplied expected election identity.
///
/// The record embeds the root anchor that was trusted when the statement was
/// first accepted, so verification works offline with no bundle configured.
/// A missing record is `Ok(None)`; a present-but-invalid record is an error
/// (fail loud for tampering/corruption rather than silently forgetting
/// lifecycle knowledge).
///
/// # Errors
///
/// Returns a bounded error if the record exists but is malformed, oversized,
/// non-canonical, or its statement/signature/bindings do not verify.
pub fn load_persisted_election_status_v1(
    status_dir: &Path,
    manifest_hash_hex: &str,
    expected_election_id: &[u8],
    expected_manifest_hash: ManifestHash,
    expected_registry_commitment: RegistryCommitment,
) -> Result<Option<PersistedElectionStatusRecordV1>, GuiCoreError> {
    validate_manifest_hash_hex(manifest_hash_hex)?;
    let path = voter_election_status_record_path_v1(status_dir, manifest_hash_hex)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(status_io_error()),
    };
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(status_unsafe_path());
    }
    if metadata.len() > MAX_ELECTION_STATUS_STATEMENT_BYTES as u64 {
        return Err(status_malformed());
    }
    let bytes = fs::read(&path).map_err(|_| status_io_error())?;
    let mut reader = CanonicalCborReader::new(&bytes);
    let array_len = reader.read_array_len().map_err(|_| status_malformed())?;
    if array_len != 5
        || reader.read_unsigned().map_err(|_| status_malformed())? != RECORD_VERSION
        || reader
            .read_text_string()
            .map_err(|_| status_malformed())?
            != RECORD_TYPE_ID
    {
        return Err(status_malformed());
    }
    let root_public_key: [u8; 32] = reader
        .read_byte_string()
        .map_err(|_| status_malformed())?
        .try_into()
        .map_err(|_| status_malformed())?;
    let root_key_id = reader
        .read_text_string()
        .map_err(|_| status_malformed())?
        .to_owned();
    let statement_bytes = reader
        .read_byte_string()
        .map_err(|_| status_malformed())?
        .to_vec();
    reader.finish().map_err(|_| status_malformed())?;

    let statement = AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&statement_bytes)
        .map_err(GuiCoreError::from)?;
    // Re-verify against the persisted anchor AND the expected election
    // identity so a record copied between elections cannot apply anywhere.
    let anchor_roots = anchor_root_set(root_public_key, &root_key_id)?;
    statement
        .verify(
            &anchor_roots,
            expected_election_id,
            expected_manifest_hash,
            expected_registry_commitment,
        )
        .map_err(GuiCoreError::from)?;
    Ok(Some(PersistedElectionStatusRecordV1 {
        root_key_id,
        root_public_key,
        statement,
    }))
}

/// Builds a minimal single-root trust set around a previously persisted anchor
/// public key so restart re-verification needs no bundle configuration.
fn anchor_root_set(
    public_key: [u8; 32],
    key_id: &str,
) -> Result<TransportAuthorityRootSetV1, GuiCoreError> {
    use ed25519_dalek::VerifyingKey;
    VerifyingKey::from_bytes(&public_key).map_err(|_| status_malformed())?;
    Ok(TransportAuthorityRootSetV1::new(
        crate::transport::TransportAuthorityRootV1::Pinned {
            key_id: key_id.to_owned(),
            public_key,
        },
    ))
}

fn validate_manifest_hash_hex(manifest_hash_hex: &str) -> Result<(), GuiCoreError> {
    if manifest_hash_hex.len() != MANIFEST_HASH_HEX_LEN
        || !manifest_hash_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GuiCoreError::new(
            "GUI_ELECTION_STATUS_INVALID_ELECTION",
            GuiErrorCategory::InvalidInput,
            Some("election-status"),
            "the election manifest hash is not a canonical lowercase hex digest",
        ));
    }
    Ok(())
}

fn status_io_error() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_ELECTION_STATUS_IO",
        GuiErrorCategory::FileIo,
        Some("election-status"),
        "an election-status storage operation failed",
    )
}

fn status_unsafe_path() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_ELECTION_STATUS_UNSAFE_PATH",
        GuiErrorCategory::InvalidInput,
        Some("election-status"),
        "refusing to use an election-status entry that is not an app-owned regular file",
    )
}

fn status_malformed() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_ELECTION_STATUS_MALFORMED_RECORD",
        GuiErrorCategory::ArchiveIntegrity,
        Some("election-status"),
        "the persisted election-status record is malformed or fails verification",
    )
}

/// Lowercase-hex helper exposed for the shell layer.
#[must_use]
pub fn manifest_hash_lower_hex_v1(manifest_hash: ManifestHash) -> String {
    to_lower_hex(manifest_hash.as_bytes())
}

/// Stable filename prefix for one per-election organizer issuance record.
const ISSUED_GENERATION_PREFIX: &str = "issued-";
const ISSUED_TYPE_ID: &str = "TARI_CC_PRIVATE_BALLOT_ELECTION_STATUS_ISSUED_V1";

/// Returns the path of the organizer-side durable issuance record for one
/// election inside `status_dir`.
///
/// # Errors
///
/// Returns a bounded error for a non-canonical manifest hash hex.
pub fn issued_status_generation_path_v1(
    status_dir: &Path,
    manifest_hash_hex: &str,
) -> Result<PathBuf, GuiCoreError> {
    validate_manifest_hash_hex(manifest_hash_hex)?;
    Ok(status_dir.join(format!("{ISSUED_GENERATION_PREFIX}{manifest_hash_hex}.cbor")))
}

/// Reads the highest status generation this organizer has ever issued for one
/// election. A missing record means nothing was issued yet (`Ok(0)`).
///
/// The organizer's own lifecycle is append-only and durable, so any strictly
/// increasing generation source is safe; this durable counter makes restarts
/// never reuse a generation, which keeps voter-side conflict detection exact.
///
/// # Errors
///
/// Returns a bounded error if a present record is malformed or unsafe.
pub fn read_issued_status_generation_v1(
    status_dir: &Path,
    manifest_hash_hex: &str,
) -> Result<u64, GuiCoreError> {
    validate_manifest_hash_hex(manifest_hash_hex)?;
    let path = issued_status_generation_path_v1(status_dir, manifest_hash_hex)?;
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(_) => return Err(status_io_error()),
    };
    if !metadata.is_file() || metadata_is_reparse_point(&metadata) {
        return Err(status_unsafe_path());
    }
    let bytes = fs::read(&path).map_err(|_| status_io_error())?;
    let mut reader = CanonicalCborReader::new(&bytes);
    let ok = reader.read_array_len().map_err(|_| status_malformed())? == 3
        && reader.read_unsigned().map_err(|_| status_malformed())? == RECORD_VERSION
        && reader
            .read_text_string()
            .map_err(|_| status_malformed())?
            == ISSUED_TYPE_ID;
    if !ok {
        return Err(status_malformed());
    }
    let generation = reader.read_unsigned().map_err(|_| status_malformed())?;
    reader.finish().map_err(|_| status_malformed())?;
    Ok(generation)
}

/// Write-ahead reserves the NEXT status generation for one election: it
/// persists `current + 1` BEFORE the caller signs anything. A crash between
/// reservation and signing wastes exactly one generation — the safe direction
/// — while signing without reserving can never happen through this API.
///
/// # Errors
///
/// Returns a bounded error if the record cannot be written safely.
pub fn reserve_next_status_generation_v1(
    status_dir: &Path,
    manifest_hash_hex: &str,
) -> Result<u64, GuiCoreError> {
    validate_manifest_hash_hex(manifest_hash_hex)?;
    ensure_direct_directory(status_dir)?;
    let next = read_issued_status_generation_v1(status_dir, manifest_hash_hex)?
        .checked_add(1)
        .ok_or_else(status_malformed)?;
    let path = issued_status_generation_path_v1(status_dir, manifest_hash_hex)?;
    let mut writer = CanonicalCborWriter::new();
    let write = |action: Result<(), tari_cc_private_ballot_protocol::ProtocolError>| {
        action.map_err(|_| status_io_error())
    };
    write(writer.write_array_len(3))?;
    writer.write_unsigned(RECORD_VERSION);
    write(writer.write_text_string(ISSUED_TYPE_ID))?;
    writer.write_unsigned(next);
    let bytes = writer.into_bytes();
    let tmp_path = path.with_extension("cbor.tmp");
    let _ = fs::remove_file(&tmp_path);
    write_create_new_sync(&tmp_path, &bytes)?;
    match fs::rename(&tmp_path, &path) {
        Ok(()) => {
            sync_directory_best_effort(status_dir);
            Ok(next)
        }
        Err(_) => {
            let _ = fs::remove_file(&tmp_path);
            Err(status_io_error())
        }
    }
}

/// Organizer-side AUTHORITATIVE lifecycle fence shared with the private-intake
/// worker.
///
/// The intake worker never decides the lifecycle itself: its own session is
/// opened only as an internal verification substrate, and EVERY admission and
/// status answer must consult this cell instead. The GUI's lifecycle commands
/// (open/close/verify/finalize) publish each committed transition here while
/// intake is running, so a CLOSED election fences the collector immediately and
/// a status query is answered from authoritative truth — never from a stale or
/// self-opened worker session.
#[derive(Clone)]
pub struct AuthoritativeLifecycleFenceV1 {
    inner: std::sync::Arc<std::sync::Mutex<(ElectionLifecycleStateV1, u64)>>,
}

impl AuthoritativeLifecycleFenceV1 {
    /// Creates the fence from the authoritative state observed at intake start,
    /// continuing the organizer's durable issuance generation counter so online
    /// statements never carry generations behind already-exported offline ones.
    ///
    /// The generation is floored at the minimum representable statement
    /// generation (`1`) so a fresh election that never exported an artifact
    /// still produces signable statements.
    #[must_use]
    pub fn new(state: ElectionLifecycleStateV1, initial_generation: u64) -> Self {
        Self {
            inner: std::sync::Arc::new(std::sync::Mutex::new((
                state,
                initial_generation.max(STATUS_GENERATION_MINIMUM),
            ))),
        }
    }

    /// Publishes one committed lifecycle transition. When `explicit_generation`
    /// is `Some` (a durable reservation from the issuance ledger), it is used
    /// verbatim; otherwise the internal monotonic counter advances. Re-setting
    /// an unchanged state is idempotent and keeps the current generation.
    pub fn observe(
        &self,
        state: ElectionLifecycleStateV1,
        explicit_generation: Option<u64>,
    ) {
        let Ok(mut guard) = self.inner.lock() else {
            return;
        };
        if guard.0 == state {
            return;
        }
        guard.0 = state;
        match explicit_generation {
            Some(generation) if generation > guard.1 => guard.1 = generation,
            Some(_) => {}
            None => guard.1 = guard.1.saturating_add(1),
        }
    }

    /// The currently published authoritative state.
    ///
    /// Returns `FROZEN` on a poisoned lock (fail closed: ballots refused).
    #[must_use]
    pub fn state(&self) -> ElectionLifecycleStateV1 {
        self.inner
            .lock()
            .map(|guard| guard.0)
            .unwrap_or(ElectionLifecycleStateV1::Frozen)
    }

    /// Whether ballot admission may proceed (authoritative OPEN only).
    #[must_use]
    pub fn is_open(&self) -> bool {
        matches!(self.state(), ElectionLifecycleStateV1::Open)
    }

    /// The current monotonic observation generation.
    ///
    /// Returns `0` on a poisoned lock; statements signed with generation `0`
    /// are unrepresentable and fail validation, which fails closed.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.inner.lock().map(|guard| guard.1).unwrap_or(0)
    }
}

impl fmt::Debug for AuthoritativeLifecycleFenceV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthoritativeLifecycleFenceV1")
            .field("state", &self.state().as_str())
            .field("generation", &self.generation())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const TEST_ROOT_KEY_ID: &str = "test-status-root";

    #[test]
    fn lifecycle_fence_is_authoritative_and_monotonic() {
        let fence = AuthoritativeLifecycleFenceV1::new(ElectionLifecycleStateV1::Open, 7);
        assert!(fence.is_open());
        assert_eq!(fence.generation(), 7);

        // Idempotent observation keeps the generation stable.
        fence.observe(ElectionLifecycleStateV1::Open, None);
        assert_eq!(fence.generation(), 7);

        // A committed close advances the generation.
        fence.observe(ElectionLifecycleStateV1::Closed, None);
        assert!(!fence.is_open());
        assert_eq!(fence.generation(), 8);

        // An explicit durable reservation above the counter wins...
        fence.observe(ElectionLifecycleStateV1::Verified, Some(12));
        assert_eq!(fence.generation(), 12);

        // ...and a stale reservation below it never moves the counter back.
        fence.observe(ElectionLifecycleStateV1::Finalized, Some(3));
        assert_eq!(fence.generation(), 12);
        assert_eq!(fence.state(), ElectionLifecycleStateV1::Finalized);
    }

    struct RootFixture {
        signing_key: SigningKey,
        roots: TransportAuthorityRootSetV1,
        root_public_key: [u8; 32],
    }

    fn root_fixture() -> RootFixture {
        let signing_key = SigningKey::from_bytes(&[0x42; 32]);
        let root_public_key = signing_key.verifying_key().to_bytes();
        let roots = TransportAuthorityRootSetV1::new(
            crate::transport::TransportAuthorityRootV1::Pinned {
                key_id: TEST_ROOT_KEY_ID.to_owned(),
                public_key: root_public_key,
            },
        );
        RootFixture {
            signing_key,
            roots,
            root_public_key,
        }
    }

    fn election_binding() -> (Vec<u8>, ManifestHash, RegistryCommitment) {
        (
            vec![0x11; 16],
            ManifestHash::new([0x22; 32]),
            RegistryCommitment::new([0x33; 32]),
        )
    }

    fn signed_statement(
        fixture: &RootFixture,
        state: ElectionLifecycleStateV1,
        generation: u64,
    ) -> AuthenticatedElectionStatusStatementV1 {
        let (election_id, manifest_hash, registry_commitment) = election_binding();
        match AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
            election_id,
            manifest_hash,
            registry_commitment,
            state,
            generation,
            TEST_ROOT_KEY_ID.to_owned(),
            &fixture.signing_key,
        ) {
            Ok(statement) => statement,
            Err(error) => panic!("test statement must sign: {error}"),
        }
    }

    fn verify_ok(
        fixture: &RootFixture,
        statement: &AuthenticatedElectionStatusStatementV1,
    ) {
        let (election_id, manifest_hash, registry_commitment) = election_binding();
        if let Err(error) = statement.verify(
            &fixture.roots,
            &election_id,
            manifest_hash,
            registry_commitment,
        ) {
            panic!("matching statement must verify: {error}");
        }
    }

    #[test]
    fn statement_round_trips_through_canonical_cbor() {
        let fixture = root_fixture();
        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Open, 3);
        let bytes = match statement.to_canonical_cbor() {
            Ok(bytes) => bytes,
            Err(error) => panic!("statement must encode: {error}"),
        };
        assert!(bytes.len() <= MAX_ELECTION_STATUS_STATEMENT_BYTES);
        let decoded = match AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&bytes) {
            Ok(decoded) => decoded,
            Err(error) => panic!("statement must decode: {error}"),
        };
        assert_eq!(decoded, statement);
        // The encoding is canonical and deterministic.
        assert_eq!(
            decoded
                .to_canonical_cbor()
                .expect("re-encode must succeed"),
            bytes
        );
    }

    #[test]
    fn matching_statement_verifies_under_pinned_root() {
        let fixture = root_fixture();
        for state in [
            ElectionLifecycleStateV1::Frozen,
            ElectionLifecycleStateV1::Open,
            ElectionLifecycleStateV1::Closed,
            ElectionLifecycleStateV1::Verified,
            ElectionLifecycleStateV1::Finalized,
        ] {
            verify_ok(&fixture, &signed_statement(&fixture, state, 1));
        }
    }

    #[test]
    fn wrong_election_statement_is_rejected_before_signature() {
        let fixture = root_fixture();
        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Open, 2);
        let (_, manifest_hash, registry_commitment) = election_binding();
        let error = match statement.verify(
            &fixture.roots,
            b"a-different-election",
            manifest_hash,
            registry_commitment,
        ) {
            Ok(()) => panic!("wrong election must fail"),
            Err(error) => error,
        };
        assert_eq!(error, ElectionStatusErrorV1::WrongElection);
    }

    #[test]
    fn wrong_manifest_statement_is_rejected() {
        let fixture = root_fixture();
        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Open, 2);
        let (election_id, _, registry_commitment) = election_binding();
        let error = statement
            .verify(
                &fixture.roots,
                &election_id,
                ManifestHash::new([0x99; 32]),
                registry_commitment,
            )
            .expect_err("wrong manifest must fail");
        assert_eq!(error, ElectionStatusErrorV1::WrongManifestHash);
    }

    #[test]
    fn wrong_registry_commitment_statement_is_rejected() {
        let fixture = root_fixture();
        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Open, 2);
        let (election_id, manifest_hash, _) = election_binding();
        let error = statement
            .verify(
                &fixture.roots,
                &election_id,
                manifest_hash,
                RegistryCommitment::new([0x77; 32]),
            )
            .expect_err("wrong registry commitment must fail");
        assert_eq!(error, ElectionStatusErrorV1::WrongRegistryCommitment);
    }

    #[test]
    fn untrusted_root_is_rejected_even_for_a_valid_signature() {
        let fixture = root_fixture();
        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Open, 2);
        // A different pinned root must not accept the same artifact.
        let other_signing_key = SigningKey::from_bytes(&[0x43; 32]);
        let other_roots = TransportAuthorityRootSetV1::new(
            crate::transport::TransportAuthorityRootV1::Pinned {
                key_id: TEST_ROOT_KEY_ID.to_owned(),
                public_key: other_signing_key.verifying_key().to_bytes(),
            },
        );
        let (election_id, manifest_hash, registry_commitment) = election_binding();
        let error = statement
            .verify(
                &other_roots,
                &election_id,
                manifest_hash,
                registry_commitment,
            )
            .expect_err("unrelated trusted root set must not accept");
        assert_eq!(error, ElectionStatusErrorV1::InvalidSignature);

        // An unknown root id fails closed as untrusted.
        let mut forged = statement.clone();
        forged.root_key_id = "unknown-root".to_owned();
        let error = forged
            .verify(
                &fixture.roots,
                &election_id,
                manifest_hash,
                registry_commitment,
            )
            .expect_err("unknown root id must fail closed");
        assert_eq!(error, ElectionStatusErrorV1::UntrustedRoot);
    }

    #[test]
    fn tampered_or_noncanonical_statement_bytes_are_rejected() {
        let fixture = root_fixture();
        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Closed, 4);
        let bytes = statement.to_canonical_cbor().expect("must encode");

        // A flipped SIGNATURE byte still parses (structure + canonicality are
        // intact) but must fail AUTHENTICATION under the pinned root.
        let mut flipped = bytes.clone();
        let last_index = flipped.len() - 1;
        flipped[last_index] ^= 0x01;
        let parsed = AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&flipped)
            .expect("structurally valid tampered statement still parses");
        let (election_id, manifest_hash, registry_commitment) = election_binding();
        assert_eq!(
            parsed
                .verify(
                    &fixture.roots,
                    &election_id,
                    manifest_hash,
                    registry_commitment,
                )
                .expect_err("tampered signature must fail authentication"),
            ElectionStatusErrorV1::InvalidSignature
        );

        // Structural damage is rejected at the parse layer.
        assert!(
            AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&bytes[..bytes.len() - 2])
                .is_err()
        );
        // Appended trailing bytes break strict canonical decoding.
        let mut appended = bytes.clone();
        appended.push(0);
        assert!(AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&appended).is_err());

        // A NON-CANONICAL over-long integer encoding (0x18 0x01 for value 1)
        // must be refused even though a lenient parser could decode it: the
        // re-encode equality check rejects every non-canonical input.
        let mut noncanonical = Vec::new();
        noncanonical.push(0x99); // array(9) in over-long form
        noncanonical.extend_from_slice(&[0x00, 0x09]);
        noncanonical.push(0x18); // uint8 follows
        noncanonical.push(ELECTION_STATUS_STATEMENT_VERSION_V1 as u8);
        noncanonical.extend_from_slice(&bytes[3..]); // remainder after minimal header+version
        assert!(
            AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&noncanonical).is_err()
        );
    }

    #[test]
    fn unsupported_version_and_draft_are_rejected() {
        let fixture = root_fixture();
        let draft_error = match AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
            vec![0x11; 8],
            ManifestHash::new([0x22; 32]),
            RegistryCommitment::new([0x33; 32]),
            ElectionLifecycleStateV1::Draft,
            1,
            TEST_ROOT_KEY_ID.to_owned(),
            &fixture.signing_key,
        ) {
            Ok(_) => panic!("draft must not be signable"),
            Err(error) => error,
        };
        assert_eq!(draft_error, ElectionStatusErrorV1::DraftNotSignable);

        // Hand-encode a well-formed but version-two statement; it must fail
        // closed as unsupported rather than parse.
        use tari_cc_private_ballot_protocol::CanonicalCborWriter;
        let mut writer = CanonicalCborWriter::new();
        writer.write_array_len(9);
        writer.write_unsigned(ELECTION_STATUS_STATEMENT_VERSION_V1 + 1);
        writer
            .write_text_string("tari-cc-private-ballot/election-status/v1")
            .expect("protocol id writes");
        writer.write_byte_string(&[0x11; 16]).expect("id writes");
        writer
            .write_byte_string(&[0x22; 32])
            .expect("manifest writes");
        writer
            .write_byte_string(&[0x33; 32])
            .expect("registry writes");
        writer.write_unsigned(STATUS_STATE_CODE_OPEN);
        writer.write_unsigned(1);
        writer
            .write_text_string(TEST_ROOT_KEY_ID)
            .expect("root id writes");
        writer.write_byte_string(&[0; 64]).expect("sig writes");
        let hostile = writer.into_bytes();
        assert_eq!(
            AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&hostile)
                .expect_err("unsupported version must fail"),
            ElectionStatusErrorV1::UnsupportedVersion
        );

        // An unknown state code is malformed, not a lifecycle value.
        let mut unknown_state = CanonicalCborWriter::new();
        unknown_state.write_array_len(9);
        unknown_state.write_unsigned(ELECTION_STATUS_STATEMENT_VERSION_V1);
        unknown_state
            .write_text_string("tari-cc-private-ballot/election-status/v1")
            .expect("protocol id writes");
        unknown_state
            .write_byte_string(&[0x11; 16])
            .expect("id writes");
        unknown_state
            .write_byte_string(&[0x22; 32])
            .expect("manifest writes");
        unknown_state
            .write_byte_string(&[0x33; 32])
            .expect("registry writes");
        unknown_state.write_unsigned(99);
        unknown_state.write_unsigned(1);
        unknown_state
            .write_text_string(TEST_ROOT_KEY_ID)
            .expect("root id writes");
        unknown_state
            .write_byte_string(&[0; 64])
            .expect("sig writes");
        let hostile = unknown_state.into_bytes();
        assert_eq!(
            AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&hostile)
                .expect_err("unknown state code must fail"),
            ElectionStatusErrorV1::MalformedStatement
        );
    }

    #[test]
    fn zero_generation_and_oversized_inputs_fail_closed() {
        let fixture = root_fixture();
        let zero_generation = AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
            vec![0x11; 8],
            ManifestHash::new([0x22; 32]),
            RegistryCommitment::new([0x33; 32]),
            ElectionLifecycleStateV1::Open,
            0,
            TEST_ROOT_KEY_ID.to_owned(),
            &fixture.signing_key,
        );
        assert_eq!(
            zero_generation.expect_err("generation zero must be refused"),
            ElectionStatusErrorV1::MalformedStatement
        );
        let oversized = vec![0_u8; MAX_ELECTION_STATUS_STATEMENT_BYTES + 1];
        assert_eq!(
            AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&oversized)
                .expect_err("oversized must be refused"),
            ElectionStatusErrorV1::OversizedStatement
        );
    }

    #[test]
    fn planning_accepts_first_authenticated_observation_forward_only() {
        let knowledge = ElectionStatusKnowledgeV1::new();
        let planned = knowledge
            .plan(ElectionLifecycleStateV1::Open, 5, ElectionLifecycleStateV1::Frozen)
            .expect("first OPEN observation plans");
        assert_eq!(planned, ElectionLifecycleStateV1::Open);

        // A CLOSED observation advances straight through OPEN to CLOSED.
        let planned = knowledge
            .plan(
                ElectionLifecycleStateV1::Closed,
                6,
                ElectionLifecycleStateV1::Frozen,
            )
            .expect("first CLOSED observation plans");
        assert_eq!(planned, ElectionLifecycleStateV1::Closed);
    }

    #[test]
    fn planning_never_moves_a_session_backward() {
        let mut knowledge = ElectionStatusKnowledgeV1::new();
        knowledge.record(ElectionLifecycleStateV1::Open, 5);
        // Session already advanced to CLOSED by a later statement.
        let error = knowledge
            .plan(
                ElectionLifecycleStateV1::Open,
                6,
                ElectionLifecycleStateV1::Closed,
            )
            .expect_err("OPEN after CLOSED must be rejected");
        assert_eq!(error, ElectionStatusErrorV1::LifecycleRollbackRejected);

        // Old FROZEN after OPEN is equally rejected regardless of generation.
        let error = knowledge
            .plan(
                ElectionLifecycleStateV1::Frozen,
                99,
                ElectionLifecycleStateV1::Open,
            )
            .expect_err("FROZEN after OPEN must be rejected");
        assert_eq!(error, ElectionStatusErrorV1::LifecycleRollbackRejected);
    }

    #[test]
    fn planning_rejects_stale_generations_loudly() {
        let mut knowledge = ElectionStatusKnowledgeV1::new();
        knowledge.record(ElectionLifecycleStateV1::Closed, 8);
        // A fresh FROZEN session replaying the old artifact must NOT reopen.
        let error = knowledge
            .plan(
                ElectionLifecycleStateV1::Open,
                5,
                ElectionLifecycleStateV1::Frozen,
            )
            .expect_err("stale generation must be rejected");
        assert_eq!(error, ElectionStatusErrorV1::StaleGeneration);
    }

    #[test]
    fn planning_fails_closed_on_equal_generation_conflict() {
        let mut knowledge = ElectionStatusKnowledgeV1::new();
        knowledge.record(ElectionLifecycleStateV1::Open, 7);
        let error = knowledge
            .plan(
                ElectionLifecycleStateV1::Closed,
                7,
                ElectionLifecycleStateV1::Open,
            )
            .expect_err("equal-generation conflict must fail closed");
        assert_eq!(error, ElectionStatusErrorV1::ConflictingGeneration);
    }

    #[test]
    fn planning_treats_identical_equal_generation_as_idempotent() {
        let mut knowledge = ElectionStatusKnowledgeV1::new();
        knowledge.record(ElectionLifecycleStateV1::Open, 7);
        // Same content at the same generation replays idempotently — including
        // onto a freshly imported session that must advance again.
        let planned = knowledge
            .plan(
                ElectionLifecycleStateV1::Open,
                7,
                ElectionLifecycleStateV1::Frozen,
            )
            .expect("identical equal generation is idempotent");
        assert_eq!(planned, ElectionLifecycleStateV1::Open);
    }

    #[test]
    fn status_record_persists_and_reverifies_offline() {
        let fixture = root_fixture();
        let dir = TestDirGuard::new("status-record-roundtrip");
        let (_, manifest_hash, registry_commitment) = election_binding();
        let manifest_hex = manifest_hash_lower_hex_v1(manifest_hash);

        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Open, 9);
        let record = PersistedElectionStatusRecordV1 {
            root_key_id: TEST_ROOT_KEY_ID.to_owned(),
            root_public_key: fixture.root_public_key,
            statement: statement.clone(),
        };
        persist_election_status_record_v1(dir.path(), &manifest_hex, &record)
            .expect("record must persist");

        let loaded = load_persisted_election_status_v1(
            dir.path(),
            &manifest_hex,
            &[0x11; 16],
            manifest_hash,
            registry_commitment,
        )
        .expect("persisted record must reload offline");
        let loaded = loaded.expect("record must exist");
        assert_eq!(loaded.statement, statement);
        assert_eq!(loaded.root_key_id, TEST_ROOT_KEY_ID);
        assert_eq!(loaded.root_public_key, fixture.root_public_key);
    }

    #[test]
    fn status_record_from_another_election_is_refused_at_load() {
        let fixture = root_fixture();
        let dir = TestDirGuard::new("status-record-cross-election");
        let (_, manifest_hash, registry_commitment) = election_binding();

        let statement = signed_statement(&fixture, ElectionLifecycleStateV1::Open, 2);
        let record = PersistedElectionStatusRecordV1 {
            root_key_id: TEST_ROOT_KEY_ID.to_owned(),
            root_public_key: fixture.root_public_key,
            statement,
        };
        persist_election_status_record_v1(dir.path(), &manifest_hash_lower_hex_v1(manifest_hash), &record)
            .expect("record must persist");

        // Loading under a DIFFERENT election identity must fail closed.
        let error = load_persisted_election_status_v1(
            dir.path(),
            &manifest_hash_lower_hex_v1(manifest_hash),
            b"another-election",
            manifest_hash,
            registry_commitment,
        )
        .expect_err("cross-election record must be refused");
        assert_eq!(error.code(), "GUI_ELECTION_STATUS_REJECTED");
    }

    #[test]
    fn missing_status_record_is_none_not_an_error() {
        let dir = TestDirGuard::new("status-record-missing");
        let (_, manifest_hash, registry_commitment) = election_binding();
        let loaded = load_persisted_election_status_v1(
            dir.path(),
            &manifest_hash_lower_hex_v1(manifest_hash),
            &[0x11; 16],
            manifest_hash,
            registry_commitment,
        )
        .expect("missing record must be ok");
        assert!(loaded.is_none());
    }

    #[test]
    fn noncanonical_manifest_hex_is_refused_for_paths() {
        let dir = TestDirGuard::new("status-record-bad-hex");
        let error = voter_election_status_record_path_v1(dir.path(), "NOT_HEX")
            .expect_err("non-canonical hex must be refused");
        assert_eq!(error.code(), "GUI_ELECTION_STATUS_INVALID_ELECTION");

        // Uppercase hex is also refused (path canonicality).
        let uppercase = "A".repeat(64);
        assert!(voter_election_status_record_path_v1(dir.path(), &uppercase).is_err());
    }

    /// Minimal temp-dir guard mirroring the integration-test `TestDir`.
    struct TestDirGuard {
        path: PathBuf,
    }

    impl TestDirGuard {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "election-status-unit-{label}-{}",
                std::process::id()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("unit test dir must create");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

