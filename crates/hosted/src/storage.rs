#![forbid(unsafe_code)]

//! Hosted storage: trait, in-memory test implementation, and SQLite
//! persistent implementation (schema version 4).
//!
//! Stored categories only: public election packages, canonical ballot
//! packages, nullifiers, receipts, election state, eligibility drafts,
//! invitation verifiers (never plaintext secrets), enrolled public keys,
//! frozen registry evidence, and organizer capability verifiers (never
//! plaintext organizer secrets). NEVER stored: voter secret keys, Triptych
//! witnesses, wallet private keys, invitation plaintext secrets, bearer
//! tokens, plaintext organizer capability secrets.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering};

// ── Election records (post-freeze, for voting) ──────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionRecord {
    pub id: String,
    pub manifest_cbor: Vec<u8>,
    pub registry_cbor: Vec<u8>,
    pub candidate_cbor: Vec<u8>,
    pub state: String,
    pub manifest_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotRecord {
    pub election_id: String,
    pub receipt_id: String,
    pub package_cbor: Vec<u8>,
    pub envelope_hash_hex: String,
    pub nullifier: Vec<u8>,
    pub seq: u64,
}

/// Canonical public binding exported by the organizer's verified Desktop
/// transport history before the hosted election is finalized. The hosted
/// service stores the exact canonical bytes and never derives a substitute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedTransportBindingRecord {
    pub election_id: String,
    pub binding_cbor: Vec<u8>,
}

/// Durable record of a Hosted authority response to one Desktop-generated
/// descriptor request. Both canonical artifacts are retained so a retry can
/// return the original response while conflicting reuse of a request ID is
/// rejected without relying on signer determinism.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorIssuanceRecord {
    pub election_id: String,
    pub request_id: [u8; 32],
    pub request_cbor: Vec<u8>,
    pub response_cbor: Vec<u8>,
}

// ── Enrollment draft records ─────────────────────────────────────────────────

/// Draft election configuration stored before the registry is frozen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionDraftRecord {
    pub election_id: String,
    pub candidate_cbor: Vec<u8>,
    pub proof_suite_id: String,
    pub min_approvals: i64,
    pub max_approvals: i64,
    pub allow_abstention: bool,
    pub governance_revision: String,
    /// Required exact V2 manifest question for new Hosted elections.
    pub proposal_question: String,
    pub authorized_slot_count: i64,
    pub external_roster_commitment_hex: Option<String>,
    /// DRAFT | ENROLLMENT_OPEN | REGISTRY_FROZEN
    pub eligibility_state: String,
    pub created_at_ms: i64,
}

/// One organiser-authorised eligibility slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EligibilitySlotRecord {
    pub slot_id: String,
    pub election_id: String,
    pub consumed: bool,
    pub created_at_ms: i64,
}

/// One enrollment invitation (invitation plaintext NEVER stored here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationRecord {
    pub invitation_id: String,
    pub slot_id: String,
    pub election_id: String,
    /// BLAKE3("invitation-verifier-v1\0{election_id}\0{slot_id}\0{secret}")
    pub verifier_hex: String,
    /// ACTIVE | CONSUMED | VOIDED
    pub state: String,
    pub created_at_ms: i64,
}

/// One enrolled public voting credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolledCredentialRecord {
    pub election_id: String,
    pub public_key_hex: String,
    /// Scrubbed to NULL after registry freeze for privacy.
    pub slot_id: Option<String>,
    /// Stored only during ENROLLMENT_OPEN for idempotency; scrubbed at freeze.
    pub invitation_id: Option<String>,
    pub enrolled_at_ms: i64,
}

/// Frozen registry audit evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrozenRegistryRecord {
    pub election_id: String,
    pub registry_cbor_hex: String,
    pub registry_commitment_hex: String,
    pub authorized_slot_count: i64,
    pub enrolled_count: i64,
    pub frozen_at_ms: i64,
    pub external_roster_commitment_hex: Option<String>,
}

/// Election-scoped organizer capability verifier (schema v4).
/// The plaintext organizer secret is NEVER stored; only the
/// domain-separated BLAKE3 verifier bound to the election id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrganizerCredentialRecord {
    pub election_id: String,
    pub organizer_verifier_hex: String,
    pub created_at_ms: i64,
}

// ── Storage errors ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    ElectionExists,
    ElectionNotFound,
    DuplicateReceipt,
    DuplicateNullifier,
    InvalidState,
    DuplicatePublicKey,
    SlotConsumed,
    SlotNotFound,
    InvitationNotFound,
    AlreadyFrozen,
    DescriptorRequestConflict,
    Db,
}

impl StorageError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ElectionExists => "STORAGE_ELECTION_EXISTS",
            Self::ElectionNotFound => "STORAGE_ELECTION_NOT_FOUND",
            Self::DuplicateReceipt => "STORAGE_DUPLICATE_RECEIPT",
            Self::DuplicateNullifier => "STORAGE_DUPLICATE_NULLIFIER",
            Self::InvalidState => "STORAGE_INVALID_STATE",
            Self::DuplicatePublicKey => "STORAGE_DUPLICATE_PUBLIC_KEY",
            Self::SlotConsumed => "STORAGE_SLOT_CONSUMED",
            Self::SlotNotFound => "STORAGE_SLOT_NOT_FOUND",
            Self::InvitationNotFound => "STORAGE_INVITATION_NOT_FOUND",
            Self::AlreadyFrozen => "STORAGE_ALREADY_FROZEN",
            Self::DescriptorRequestConflict => "STORAGE_DESCRIPTOR_REQUEST_CONFLICT",
            Self::Db => "STORAGE_DB_ERROR",
        }
    }
}

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::error::Error for StorageError {}

// ── Storage trait ─────────────────────────────────────────────────────────────

pub trait HostedStorage: Send + Sync {
    // Legacy/compatibility
    fn append_ballot_envelope(&self, election_id: &str, envelope: Vec<u8>);
    fn ballot_envelope_count(&self, election_id: &str) -> usize;

    // Election records (post-freeze voting elections)
    fn put_election(&self, record: ElectionRecord) -> Result<(), StorageError>;
    fn get_election(&self, id: &str) -> Result<Option<ElectionRecord>, StorageError>;
    fn set_election_state(&self, id: &str, from: &str, to: &str) -> Result<bool, StorageError>;
    /// Stores exactly one Desktop-exported canonical binding while the election
    /// is closed. The value becomes part of the finalized archive identity.
    fn put_finalized_transport_binding(
        &self,
        record: FinalizedTransportBindingRecord,
    ) -> Result<(), StorageError>;
    fn get_finalized_transport_binding(
        &self,
        election_id: &str,
    ) -> Result<Option<FinalizedTransportBindingRecord>, StorageError>;
    /// Atomically records a new signed response or returns the earlier one
    /// for an identical canonical request. Reusing an ID with any different
    /// request bytes is a conflict, even across a process restart.
    fn record_descriptor_issuance(
        &self,
        record: DescriptorIssuanceRecord,
    ) -> Result<DescriptorIssuanceRecord, StorageError>;
    /// Returns any single descriptor issuance record for the given election, or
    /// `None` if none exists. The election may have more than one record (from
    /// separate request IDs), but the voter bundle endpoint only needs the most
    /// recent one; this returns the first row found, which is sufficient when
    /// there is exactly one (the common case).
    fn get_any_descriptor_issuance(
        &self,
        election_id: &str,
    ) -> Result<Option<DescriptorIssuanceRecord>, StorageError>;

    // Ballot records
    fn get_ballot_by_receipt(
        &self,
        election_id: &str,
        receipt_id: &str,
    ) -> Result<Option<BallotRecord>, StorageError>;
    fn insert_ballot(&self, record: BallotRecord) -> Result<(), StorageError>;
    fn list_ballots(&self, election_id: &str) -> Result<Vec<BallotRecord>, StorageError>;

    // Draft elections (pre-freeze)
    fn put_election_draft(&self, record: ElectionDraftRecord) -> Result<(), StorageError>;
    fn get_election_draft(&self, id: &str) -> Result<Option<ElectionDraftRecord>, StorageError>;
    fn set_draft_eligibility_state(
        &self,
        id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, StorageError>;

    // Eligibility slots
    fn create_slots(
        &self,
        election_id: &str,
        count: usize,
        now_ms: i64,
    ) -> Result<Vec<String>, StorageError>;
    fn list_slots(&self, election_id: &str) -> Result<Vec<EligibilitySlotRecord>, StorageError>;
    fn mark_slot_consumed(&self, slot_id: &str) -> Result<(), StorageError>;

    // Invitations
    fn insert_invitation(&self, record: InvitationRecord) -> Result<(), StorageError>;
    fn get_active_invitation_for_slot(
        &self,
        slot_id: &str,
    ) -> Result<Option<InvitationRecord>, StorageError>;
    fn get_invitation_by_verifier(
        &self,
        verifier_hex: &str,
    ) -> Result<Option<InvitationRecord>, StorageError>;
    fn set_invitation_state(
        &self,
        invitation_id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, StorageError>;
    fn void_active_slot_invitations(&self, slot_id: &str) -> Result<(), StorageError>;

    // Enrolled credentials
    fn insert_enrolled_credential(
        &self,
        record: EnrolledCredentialRecord,
    ) -> Result<(), StorageError>;
    fn get_enrolled_credential_by_key(
        &self,
        election_id: &str,
        public_key_hex: &str,
    ) -> Result<Option<EnrolledCredentialRecord>, StorageError>;
    fn get_enrolled_credential_by_slot(
        &self,
        election_id: &str,
        slot_id: &str,
    ) -> Result<Option<EnrolledCredentialRecord>, StorageError>;
    fn list_enrolled_credentials(
        &self,
        election_id: &str,
    ) -> Result<Vec<EnrolledCredentialRecord>, StorageError>;
    fn count_enrolled_credentials(&self, election_id: &str) -> Result<i64, StorageError>;
    fn scrub_enrollment_linkage(&self, election_id: &str) -> Result<(), StorageError>;
    /// Atomically validates and consumes an invitation, its slot, and a public credential.
    fn complete_enrollment(
        &self,
        election_id: &str,
        verifier_hex: &str,
        public_key_hex: &str,
        now_ms: i64,
    ) -> Result<EnrollmentCompletion, StorageError>;

    // Frozen registry evidence
    fn put_frozen_registry(&self, record: FrozenRegistryRecord) -> Result<(), StorageError>;
    fn get_frozen_registry(
        &self,
        election_id: &str,
    ) -> Result<Option<FrozenRegistryRecord>, StorageError>;

    // Organizer capability credentials (schema v4)
    fn put_organizer_credential(
        &self,
        record: OrganizerCredentialRecord,
    ) -> Result<(), StorageError>;
    fn get_organizer_credential(
        &self,
        election_id: &str,
    ) -> Result<Option<OrganizerCredentialRecord>, StorageError>;

    // Invitation lookups by election scope
    fn get_invitation_by_id(
        &self,
        invitation_id: &str,
    ) -> Result<Option<InvitationRecord>, StorageError>;
    fn list_invitations(&self, election_id: &str) -> Result<Vec<InvitationRecord>, StorageError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnrollmentCompletion {
    Created(EnrolledCredentialRecord),
    Idempotent(EnrolledCredentialRecord),
    ElectionNotFound,
    InvitationNotFound,
    WrongElection,
    EnrollmentClosed,
    InvitationVoided,
    CredentialConflict,
    EnrollmentRace,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EnrollmentFailpoint {
    None = 0,
    AfterInvitationMutation = 1,
    AfterSlotMutation = 2,
    BeforeCredentialInsertion = 3,
}

// ── In-memory implementation (tests) ─────────────────────────────────────────

#[derive(Debug, Default)]
pub struct InMemoryStorage {
    elections: Mutex<HashMap<String, ElectionRecord>>,
    finalized_transport_bindings: Mutex<HashMap<String, FinalizedTransportBindingRecord>>,
    descriptor_issuances: Mutex<HashMap<(String, [u8; 32]), DescriptorIssuanceRecord>>,
    ballots: Mutex<HashMap<String, Vec<BallotRecord>>>,
    legacy: Mutex<HashMap<String, Vec<Vec<u8>>>>,
    drafts: Mutex<HashMap<String, ElectionDraftRecord>>,
    slots: Mutex<Vec<EligibilitySlotRecord>>,
    invitations: Mutex<Vec<InvitationRecord>>,
    credentials: Mutex<Vec<EnrolledCredentialRecord>>,
    frozen: Mutex<HashMap<String, FrozenRegistryRecord>>,
    organizers: Mutex<HashMap<String, OrganizerCredentialRecord>>,
}

impl InMemoryStorage {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl HostedStorage for InMemoryStorage {
    fn append_ballot_envelope(&self, election_id: &str, envelope: Vec<u8>) {
        let mut g = self.legacy.lock().unwrap_or_else(|e| e.into_inner());
        g.entry(election_id.to_owned()).or_default().push(envelope);
    }

    fn ballot_envelope_count(&self, election_id: &str) -> usize {
        let g = self.legacy.lock().unwrap_or_else(|e| e.into_inner());
        g.get(election_id).map_or(0, Vec::len)
    }

    fn put_election(&self, record: ElectionRecord) -> Result<(), StorageError> {
        let mut g = self.elections.lock().unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&record.id) {
            return Err(StorageError::ElectionExists);
        }
        g.insert(record.id.clone(), record);
        Ok(())
    }

    fn get_election(&self, id: &str) -> Result<Option<ElectionRecord>, StorageError> {
        Ok(self
            .elections
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned())
    }

    fn set_election_state(&self, id: &str, from: &str, to: &str) -> Result<bool, StorageError> {
        let mut g = self.elections.lock().unwrap_or_else(|e| e.into_inner());
        match g.get_mut(id) {
            None => Err(StorageError::ElectionNotFound),
            Some(r) if r.state == from => {
                r.state = to.to_owned();
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    fn put_finalized_transport_binding(
        &self,
        record: FinalizedTransportBindingRecord,
    ) -> Result<(), StorageError> {
        let elections = self.elections.lock().unwrap_or_else(|e| e.into_inner());
        let Some(election) = elections.get(&record.election_id) else {
            return Err(StorageError::ElectionNotFound);
        };
        if election.state != "closed" {
            return Err(StorageError::InvalidState);
        }
        let mut bindings = self
            .finalized_transport_bindings
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if bindings.contains_key(&record.election_id) {
            return Err(StorageError::ElectionExists);
        }
        bindings.insert(record.election_id.clone(), record);
        Ok(())
    }

    fn get_finalized_transport_binding(
        &self,
        election_id: &str,
    ) -> Result<Option<FinalizedTransportBindingRecord>, StorageError> {
        Ok(self
            .finalized_transport_bindings
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(election_id)
            .cloned())
    }

    fn record_descriptor_issuance(
        &self,
        record: DescriptorIssuanceRecord,
    ) -> Result<DescriptorIssuanceRecord, StorageError> {
        let mut issuances = self
            .descriptor_issuances
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = (record.election_id.clone(), record.request_id);
        match issuances.get(&key) {
            Some(existing) if existing.request_cbor == record.request_cbor => Ok(existing.clone()),
            Some(_) => Err(StorageError::DescriptorRequestConflict),
            None => {
                issuances.insert(key, record.clone());
                Ok(record)
            }
        }
    }

    fn get_any_descriptor_issuance(
        &self,
        election_id: &str,
    ) -> Result<Option<DescriptorIssuanceRecord>, StorageError> {
        Ok(self
            .descriptor_issuances
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|((eid, _), _)| eid == election_id)
            .map(|(_, record)| record.clone()))
    }

    fn get_ballot_by_receipt(
        &self,
        election_id: &str,
        receipt_id: &str,
    ) -> Result<Option<BallotRecord>, StorageError> {
        let g = self.ballots.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.get(election_id)
            .and_then(|v| v.iter().find(|b| b.receipt_id == receipt_id).cloned()))
    }

    fn insert_ballot(&self, record: BallotRecord) -> Result<(), StorageError> {
        let mut g = self.ballots.lock().unwrap_or_else(|e| e.into_inner());
        let entry = g.entry(record.election_id.clone()).or_default();
        if entry.iter().any(|b| b.receipt_id == record.receipt_id) {
            return Err(StorageError::DuplicateReceipt);
        }
        if entry.iter().any(|b| b.nullifier == record.nullifier) {
            return Err(StorageError::DuplicateNullifier);
        }
        entry.push(record);
        Ok(())
    }

    fn list_ballots(&self, election_id: &str) -> Result<Vec<BallotRecord>, StorageError> {
        let g = self.ballots.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = g.get(election_id).cloned().unwrap_or_default();
        v.sort_by_key(|b| b.seq);
        Ok(v)
    }

    fn put_election_draft(&self, record: ElectionDraftRecord) -> Result<(), StorageError> {
        let mut g = self.drafts.lock().unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&record.election_id) {
            return Err(StorageError::ElectionExists);
        }
        g.insert(record.election_id.clone(), record);
        Ok(())
    }

    fn get_election_draft(&self, id: &str) -> Result<Option<ElectionDraftRecord>, StorageError> {
        Ok(self
            .drafts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(id)
            .cloned())
    }

    fn set_draft_eligibility_state(
        &self,
        id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, StorageError> {
        let mut g = self.drafts.lock().unwrap_or_else(|e| e.into_inner());
        match g.get_mut(id) {
            None => Err(StorageError::ElectionNotFound),
            Some(r) if r.eligibility_state == from => {
                r.eligibility_state = to.to_owned();
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    fn create_slots(
        &self,
        election_id: &str,
        count: usize,
        now_ms: i64,
    ) -> Result<Vec<String>, StorageError> {
        let mut g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let slot_id = format!("slot-{election_id}-{i}-{now_ms}");
            g.push(EligibilitySlotRecord {
                slot_id: slot_id.clone(),
                election_id: election_id.to_owned(),
                consumed: false,
                created_at_ms: now_ms,
            });
            ids.push(slot_id);
        }
        Ok(ids)
    }

    fn list_slots(&self, election_id: &str) -> Result<Vec<EligibilitySlotRecord>, StorageError> {
        let g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter()
            .filter(|s| s.election_id == election_id)
            .cloned()
            .collect())
    }

    fn mark_slot_consumed(&self, slot_id: &str) -> Result<(), StorageError> {
        let mut g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        match g.iter_mut().find(|s| s.slot_id == slot_id) {
            Some(s) => {
                s.consumed = true;
                Ok(())
            }
            None => Err(StorageError::SlotNotFound),
        }
    }

    fn insert_invitation(&self, record: InvitationRecord) -> Result<(), StorageError> {
        let mut g = self.invitations.lock().unwrap_or_else(|e| e.into_inner());
        if g.iter().any(|i| i.verifier_hex == record.verifier_hex) {
            return Err(StorageError::Db);
        }
        g.push(record);
        Ok(())
    }

    fn get_active_invitation_for_slot(
        &self,
        slot_id: &str,
    ) -> Result<Option<InvitationRecord>, StorageError> {
        let g = self.invitations.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter()
            .find(|i| i.slot_id == slot_id && i.state == "ACTIVE")
            .cloned())
    }

    fn get_invitation_by_verifier(
        &self,
        verifier_hex: &str,
    ) -> Result<Option<InvitationRecord>, StorageError> {
        let g = self.invitations.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter().find(|i| i.verifier_hex == verifier_hex).cloned())
    }

    fn set_invitation_state(
        &self,
        invitation_id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, StorageError> {
        let mut g = self.invitations.lock().unwrap_or_else(|e| e.into_inner());
        match g.iter_mut().find(|i| i.invitation_id == invitation_id) {
            None => Ok(false),
            Some(i) if i.state == from => {
                i.state = to.to_owned();
                Ok(true)
            }
            Some(_) => Ok(false),
        }
    }

    fn void_active_slot_invitations(&self, slot_id: &str) -> Result<(), StorageError> {
        let mut g = self.invitations.lock().unwrap_or_else(|e| e.into_inner());
        for inv in g
            .iter_mut()
            .filter(|i| i.slot_id == slot_id && i.state == "ACTIVE")
        {
            inv.state = "VOIDED".to_owned();
        }
        Ok(())
    }

    fn insert_enrolled_credential(
        &self,
        record: EnrolledCredentialRecord,
    ) -> Result<(), StorageError> {
        let mut g = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        if g.iter().any(|c| {
            c.election_id == record.election_id && c.public_key_hex == record.public_key_hex
        }) {
            return Err(StorageError::DuplicatePublicKey);
        }
        g.push(record);
        Ok(())
    }

    fn get_enrolled_credential_by_key(
        &self,
        election_id: &str,
        public_key_hex: &str,
    ) -> Result<Option<EnrolledCredentialRecord>, StorageError> {
        let g = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter()
            .find(|c| c.election_id == election_id && c.public_key_hex == public_key_hex)
            .cloned())
    }

    fn get_enrolled_credential_by_slot(
        &self,
        election_id: &str,
        slot_id: &str,
    ) -> Result<Option<EnrolledCredentialRecord>, StorageError> {
        let g = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter()
            .find(|c| c.election_id == election_id && c.slot_id.as_deref() == Some(slot_id))
            .cloned())
    }

    fn list_enrolled_credentials(
        &self,
        election_id: &str,
    ) -> Result<Vec<EnrolledCredentialRecord>, StorageError> {
        let g = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter()
            .filter(|c| c.election_id == election_id)
            .cloned()
            .collect())
    }

    fn count_enrolled_credentials(&self, election_id: &str) -> Result<i64, StorageError> {
        let g = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter().filter(|c| c.election_id == election_id).count() as i64)
    }

    fn scrub_enrollment_linkage(&self, election_id: &str) -> Result<(), StorageError> {
        let mut g = self.credentials.lock().unwrap_or_else(|e| e.into_inner());
        for c in g.iter_mut().filter(|c| c.election_id == election_id) {
            c.slot_id = None;
            c.invitation_id = None;
        }
        Ok(())
    }

    fn complete_enrollment(
        &self,
        election_id: &str,
        verifier_hex: &str,
        public_key_hex: &str,
        now_ms: i64,
    ) -> Result<EnrollmentCompletion, StorageError> {
        let draft = self.get_election_draft(election_id)?;
        let Some(draft) = draft else {
            return Ok(EnrollmentCompletion::ElectionNotFound);
        };
        if draft.eligibility_state != "ENROLLMENT_OPEN" {
            return Ok(EnrollmentCompletion::EnrollmentClosed);
        }
        let invitation = match self.get_invitation_by_verifier(verifier_hex)? {
            Some(invitation) => invitation,
            None => return Ok(EnrollmentCompletion::InvitationNotFound),
        };
        if invitation.election_id != election_id {
            return Ok(EnrollmentCompletion::WrongElection);
        }
        if invitation.state == "VOIDED" {
            return Ok(EnrollmentCompletion::InvitationVoided);
        }
        if invitation.state == "CONSUMED" {
            return Ok(
                match self.get_enrolled_credential_by_slot(election_id, &invitation.slot_id)? {
                    Some(credential) if credential.public_key_hex == public_key_hex => {
                        EnrollmentCompletion::Idempotent(credential)
                    }
                    Some(_) => EnrollmentCompletion::CredentialConflict,
                    None => EnrollmentCompletion::EnrollmentClosed,
                },
            );
        }
        if self
            .get_enrolled_credential_by_key(election_id, public_key_hex)?
            .is_some()
        {
            return Ok(EnrollmentCompletion::CredentialConflict);
        }
        let slots = self.list_slots(election_id)?;
        if !slots
            .iter()
            .any(|slot| slot.slot_id == invitation.slot_id && !slot.consumed)
        {
            return Ok(EnrollmentCompletion::EnrollmentRace);
        }
        if !self.set_invitation_state(&invitation.invitation_id, "ACTIVE", "CONSUMED")? {
            return Ok(EnrollmentCompletion::EnrollmentRace);
        }
        self.mark_slot_consumed(&invitation.slot_id)?;
        let credential = EnrolledCredentialRecord {
            election_id: election_id.to_owned(),
            public_key_hex: public_key_hex.to_owned(),
            slot_id: Some(invitation.slot_id),
            invitation_id: Some(invitation.invitation_id),
            enrolled_at_ms: now_ms,
        };
        self.insert_enrolled_credential(credential.clone())?;
        Ok(EnrollmentCompletion::Created(credential))
    }

    fn put_frozen_registry(&self, record: FrozenRegistryRecord) -> Result<(), StorageError> {
        let mut g = self.frozen.lock().unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&record.election_id) {
            return Err(StorageError::AlreadyFrozen);
        }
        g.insert(record.election_id.clone(), record);
        Ok(())
    }

    fn get_frozen_registry(
        &self,
        election_id: &str,
    ) -> Result<Option<FrozenRegistryRecord>, StorageError> {
        Ok(self
            .frozen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(election_id)
            .cloned())
    }

    fn put_organizer_credential(
        &self,
        record: OrganizerCredentialRecord,
    ) -> Result<(), StorageError> {
        let mut g = self.organizers.lock().unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&record.election_id) {
            return Err(StorageError::ElectionExists);
        }
        g.insert(record.election_id.clone(), record);
        Ok(())
    }

    fn get_organizer_credential(
        &self,
        election_id: &str,
    ) -> Result<Option<OrganizerCredentialRecord>, StorageError> {
        Ok(self
            .organizers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(election_id)
            .cloned())
    }

    fn get_invitation_by_id(
        &self,
        invitation_id: &str,
    ) -> Result<Option<InvitationRecord>, StorageError> {
        let g = self.invitations.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter().find(|i| i.invitation_id == invitation_id).cloned())
    }

    fn list_invitations(&self, election_id: &str) -> Result<Vec<InvitationRecord>, StorageError> {
        let g = self.invitations.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.iter()
            .filter(|i| i.election_id == election_id)
            .cloned()
            .collect())
    }
}

// ── SQLite implementation ─────────────────────────────────────────────────────

fn map_rusqlite(e: &rusqlite::Error) -> StorageError {
    let msg = e.to_string();
    if msg.contains("UNIQUE constraint") && msg.contains("ballots.receipt_id") {
        return StorageError::DuplicateReceipt;
    }
    if msg.contains("UNIQUE constraint") && msg.contains("nullifier") {
        return StorageError::DuplicateNullifier;
    }
    if msg.contains("UNIQUE constraint") && msg.contains("elections") {
        return StorageError::ElectionExists;
    }
    if msg.contains("UNIQUE constraint") && msg.contains("election_drafts") {
        return StorageError::ElectionExists;
    }
    if msg.contains("UNIQUE constraint") && msg.contains("enrolled_credentials") {
        return StorageError::DuplicatePublicKey;
    }
    if msg.contains("UNIQUE constraint") && msg.contains("enrollment_invitations") {
        return StorageError::Db;
    }
    if msg.contains("UNIQUE constraint") && msg.contains("frozen_registries") {
        return StorageError::AlreadyFrozen;
    }
    if msg.contains("UNIQUE constraint") && msg.contains("organizer_credentials") {
        return StorageError::ElectionExists;
    }
    StorageError::Db
}

pub struct SqliteStorage {
    conn: Mutex<Connection>,
    #[cfg(test)]
    enrollment_failpoint: AtomicU8,
}
impl std::fmt::Debug for SqliteStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SqliteStorage")
    }
}

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let conn = if path.to_string_lossy() == ":memory:" {
            Connection::open_in_memory().map_err(|_| StorageError::Db)?
        } else {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).map_err(|_| StorageError::Db)?;
                }
            }
            Connection::open(path).map_err(|_| StorageError::Db)?
        };
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|_| StorageError::Db)?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|_| StorageError::Db)?;
        conn.pragma_update(None, "busy_timeout", 5000)
            .map_err(|_| StorageError::Db)?;
        let storage = Self {
            conn: Mutex::new(conn),
            #[cfg(test)]
            enrollment_failpoint: AtomicU8::new(EnrollmentFailpoint::None as u8),
        };
        storage.migrate()?;
        Ok(storage)
    }

    fn migrate(&self) -> Result<(), StorageError> {
        let g = self.conn.lock().unwrap_or_else(|e| e.into_inner());

        // Core tables (idempotent).
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS elections (
                id TEXT PRIMARY KEY,
                manifest_cbor BLOB NOT NULL,
                registry_cbor BLOB NOT NULL,
                candidate_cbor BLOB NOT NULL,
                state TEXT NOT NULL,
                manifest_hash_hex TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS ballots (
                election_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                package_cbor BLOB NOT NULL,
                envelope_hash_hex TEXT NOT NULL,
                nullifier BLOB NOT NULL,
                seq INTEGER NOT NULL,
                PRIMARY KEY (election_id, receipt_id),
                UNIQUE (election_id, nullifier),
                FOREIGN KEY (election_id) REFERENCES elections(id)
             );",
        )
        .map_err(|_| StorageError::Db)?;

        // The binding is supplied by the Desktop organizer after it has
        // recovered its sealed transport history. This service stores the
        // canonical bytes and never attempts to reconstruct them from ballots.
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS finalized_transport_bindings (
                election_id TEXT PRIMARY KEY,
                binding_cbor BLOB NOT NULL,
                FOREIGN KEY (election_id) REFERENCES elections(id)
             );",
        )
        .map_err(|_| StorageError::Db)?;

        // Server-side replay boundary for authority issuance. The request
        // bytes are canonical and exact; the stored response remains stable
        // even if a future external signer is non-deterministic.
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS descriptor_issuances (
                election_id TEXT NOT NULL,
                request_id BLOB NOT NULL,
                request_cbor BLOB NOT NULL,
                response_cbor BLOB NOT NULL,
                PRIMARY KEY (election_id, request_id),
                FOREIGN KEY (election_id) REFERENCES elections(id)
             );",
        )
        .map_err(|_| StorageError::Db)?;

        // Enrollment tables (schema v3, idempotent).
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS election_drafts (
                election_id TEXT PRIMARY KEY,
                candidate_cbor BLOB NOT NULL,
                proof_suite_id TEXT NOT NULL,
                min_approvals INTEGER NOT NULL DEFAULT 1,
                max_approvals INTEGER NOT NULL DEFAULT 1,
                allow_abstention INTEGER NOT NULL DEFAULT 1,
                governance_revision TEXT NOT NULL DEFAULT '',
                proposal_question TEXT NOT NULL DEFAULT '',
                authorized_slot_count INTEGER NOT NULL,
                external_roster_commitment_hex TEXT,
                eligibility_state TEXT NOT NULL DEFAULT 'DRAFT',
                created_at_ms INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS eligibility_slots (
                slot_id TEXT PRIMARY KEY,
                election_id TEXT NOT NULL,
                consumed INTEGER NOT NULL DEFAULT 0,
                created_at_ms INTEGER NOT NULL,
                FOREIGN KEY (election_id) REFERENCES election_drafts(election_id)
             );
             CREATE TABLE IF NOT EXISTS enrollment_invitations (
                invitation_id TEXT PRIMARY KEY,
                slot_id TEXT NOT NULL,
                election_id TEXT NOT NULL,
                verifier_hex TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL DEFAULT 'ACTIVE',
                created_at_ms INTEGER NOT NULL,
                FOREIGN KEY (slot_id) REFERENCES eligibility_slots(slot_id),
                FOREIGN KEY (election_id) REFERENCES election_drafts(election_id)
             );
             CREATE TABLE IF NOT EXISTS enrolled_credentials (
                election_id TEXT NOT NULL,
                public_key_hex TEXT NOT NULL,
                slot_id TEXT,
                invitation_id TEXT,
                enrolled_at_ms INTEGER NOT NULL,
                PRIMARY KEY (election_id, public_key_hex)
             );
             CREATE TABLE IF NOT EXISTS frozen_registries (
                election_id TEXT PRIMARY KEY,
                registry_cbor_hex TEXT NOT NULL,
                registry_commitment_hex TEXT NOT NULL,
                authorized_slot_count INTEGER NOT NULL,
                enrolled_count INTEGER NOT NULL,
                frozen_at_ms INTEGER NOT NULL,
                external_roster_commitment_hex TEXT
             );",
        )
        .map_err(|_| StorageError::Db)?;

        // Organizer capability credentials (schema v4, idempotent, additive).
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS organizer_credentials (
                election_id TEXT PRIMARY KEY,
                organizer_verifier_hex TEXT NOT NULL,
                created_at_ms INTEGER NOT NULL
             );",
        )
        .map_err(|_| StorageError::Db)?;

        let existing: Option<String> = g
            .query_row(
                "SELECT value FROM meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| StorageError::Db)?;

        match existing.as_deref() {
            None => {
                g.execute(
                    "INSERT INTO meta (key, value) VALUES ('schema_version', '7')",
                    [],
                )
                .map_err(|_| StorageError::Db)?;
            }
            Some("2") | Some("3") | Some("4") | Some("5") => {
                // V6 adds only the V2 question field; existing V1 drafts keep
                // their empty marker and therefore retain their V1 identity.
                g.execute_batch(
                    "ALTER TABLE election_drafts ADD COLUMN proposal_question TEXT NOT NULL DEFAULT '';
                     UPDATE meta SET value = '6' WHERE key = 'schema_version';",
                )
                .map_err(|_| StorageError::Db)?;
            }
            Some("6") => {
                g.execute(
                    "UPDATE meta SET value = '7' WHERE key = 'schema_version'",
                    [],
                )
                .map_err(|_| StorageError::Db)?;
            }
            Some("7") => {}
            Some(_) => return Err(StorageError::Db),
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn set_enrollment_failpoint(&self, failpoint: EnrollmentFailpoint) {
        self.enrollment_failpoint
            .store(failpoint as u8, Ordering::SeqCst);
    }

    #[cfg(test)]
    fn enrollment_failpoint_active(&self, failpoint: EnrollmentFailpoint) -> bool {
        self.enrollment_failpoint.load(Ordering::SeqCst) == failpoint as u8
    }
}

impl HostedStorage for SqliteStorage {
    fn append_ballot_envelope(&self, _election_id: &str, _envelope: Vec<u8>) {}
    fn ballot_envelope_count(&self, election_id: &str) -> usize {
        self.list_ballots(election_id).map(|v| v.len()).unwrap_or(0)
    }

    fn put_election(&self, record: ElectionRecord) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "INSERT INTO elections (id, manifest_cbor, registry_cbor, candidate_cbor, state, manifest_hash_hex) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![record.id, record.manifest_cbor, record.registry_cbor, record.candidate_cbor, record.state, record.manifest_hash_hex],
        )
        .map_err(|e| map_rusqlite(&e))?;
        Ok(())
    }

    fn get_election(&self, id: &str) -> Result<Option<ElectionRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT id, manifest_cbor, registry_cbor, candidate_cbor, state, manifest_hash_hex FROM elections WHERE id = ?1",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![id], |r| {
                Ok(ElectionRecord {
                    id: r.get(0)?,
                    manifest_cbor: r.get(1)?,
                    registry_cbor: r.get(2)?,
                    candidate_cbor: r.get(3)?,
                    state: r.get(4)?,
                    manifest_hash_hex: r.get(5)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn set_election_state(&self, id: &str, from: &str, to: &str) -> Result<bool, StorageError> {
        let g = self.lock();
        if g.query_row(
            "SELECT state FROM elections WHERE id = ?1",
            params![id],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| StorageError::Db)?
        .is_none()
        {
            return Err(StorageError::ElectionNotFound);
        }
        let n = g
            .execute(
                "UPDATE elections SET state = ?1 WHERE id = ?2 AND state = ?3",
                params![to, id, from],
            )
            .map_err(|_| StorageError::Db)?;
        Ok(n == 1)
    }

    fn put_finalized_transport_binding(
        &self,
        record: FinalizedTransportBindingRecord,
    ) -> Result<(), StorageError> {
        let g = self.lock();
        let state: Option<String> = g
            .query_row(
                "SELECT state FROM elections WHERE id = ?1",
                params![record.election_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::Db)?;
        match state.as_deref() {
            None => return Err(StorageError::ElectionNotFound),
            Some("closed") => {}
            Some(_) => return Err(StorageError::InvalidState),
        }
        g.execute(
            "INSERT INTO finalized_transport_bindings (election_id, binding_cbor) VALUES (?1, ?2)",
            params![record.election_id, record.binding_cbor],
        )
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(_, _) => StorageError::ElectionExists,
            _ => StorageError::Db,
        })?;
        Ok(())
    }

    fn get_finalized_transport_binding(
        &self,
        election_id: &str,
    ) -> Result<Option<FinalizedTransportBindingRecord>, StorageError> {
        let g = self.lock();
        g.query_row(
            "SELECT election_id, binding_cbor FROM finalized_transport_bindings WHERE election_id = ?1",
            params![election_id],
            |row| {
                Ok(FinalizedTransportBindingRecord {
                    election_id: row.get(0)?,
                    binding_cbor: row.get(1)?,
                })
            },
        )
        .optional()
        .map_err(|_| StorageError::Db)
    }

    fn record_descriptor_issuance(
        &self,
        record: DescriptorIssuanceRecord,
    ) -> Result<DescriptorIssuanceRecord, StorageError> {
        let mut g = self.lock();
        let tx = g.transaction().map_err(|_| StorageError::Db)?;
        let existing = tx
            .query_row(
                "SELECT request_cbor, response_cbor FROM descriptor_issuances WHERE election_id = ?1 AND request_id = ?2",
                params![&record.election_id, record.request_id.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()
            .map_err(|_| StorageError::Db)?;
        let output = match existing {
            Some((request_cbor, response_cbor)) if request_cbor == record.request_cbor => DescriptorIssuanceRecord {
                election_id: record.election_id,
                request_id: record.request_id,
                request_cbor,
                response_cbor,
            },
            Some(_) => return Err(StorageError::DescriptorRequestConflict),
            None => {
                tx.execute(
                    "INSERT INTO descriptor_issuances (election_id, request_id, request_cbor, response_cbor) VALUES (?1, ?2, ?3, ?4)",
                    params![&record.election_id, record.request_id.as_slice(), &record.request_cbor, &record.response_cbor],
                )
                .map_err(|_| StorageError::Db)?;
                record
            }
        };
        tx.commit().map_err(|_| StorageError::Db)?;
        Ok(output)
    }

    fn get_any_descriptor_issuance(
        &self,
        election_id: &str,
    ) -> Result<Option<DescriptorIssuanceRecord>, StorageError> {
        let g = self.lock();
        g.query_row(
            "SELECT election_id, request_id, request_cbor, response_cbor FROM descriptor_issuances WHERE election_id = ?1 LIMIT 1",
            params![election_id],
            |row| {
                let request_id_bytes: Vec<u8> = row.get(1)?;
                let request_id: [u8; 32] = request_id_bytes
                    .try_into()
                    .map_err(|_| rusqlite::Error::InvalidColumnType(1, "request_id".to_owned(), rusqlite::types::Type::Blob))?;
                Ok(DescriptorIssuanceRecord {
                    election_id: row.get(0)?,
                    request_id,
                    request_cbor: row.get(2)?,
                    response_cbor: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|_| StorageError::Db)
    }

    fn get_ballot_by_receipt(
        &self,
        election_id: &str,
        receipt_id: &str,
    ) -> Result<Option<BallotRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, receipt_id, package_cbor, envelope_hash_hex, nullifier, seq FROM ballots WHERE election_id = ?1 AND receipt_id = ?2",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id, receipt_id], |r| {
                Ok(BallotRecord {
                    election_id: r.get(0)?,
                    receipt_id: r.get(1)?,
                    package_cbor: r.get(2)?,
                    envelope_hash_hex: r.get(3)?,
                    nullifier: r.get(4)?,
                    seq: r.get::<_, i64>(5)? as u64,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn insert_ballot(&self, record: BallotRecord) -> Result<(), StorageError> {
        let mut g = self.lock();
        let tx = g.transaction().map_err(|_| StorageError::Db)?;
        tx.execute(
            "INSERT INTO ballots (election_id, receipt_id, package_cbor, envelope_hash_hex, nullifier, seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![record.election_id, record.receipt_id, record.package_cbor, record.envelope_hash_hex, record.nullifier, record.seq as i64],
        )
        .map_err(|e| map_rusqlite(&e))?;
        tx.commit().map_err(|_| StorageError::Db)?;
        Ok(())
    }

    fn list_ballots(&self, election_id: &str) -> Result<Vec<BallotRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, receipt_id, package_cbor, envelope_hash_hex, nullifier, seq FROM ballots WHERE election_id = ?1 ORDER BY seq ASC",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id], |r| {
                Ok(BallotRecord {
                    election_id: r.get(0)?,
                    receipt_id: r.get(1)?,
                    package_cbor: r.get(2)?,
                    envelope_hash_hex: r.get(3)?,
                    nullifier: r.get(4)?,
                    seq: r.get::<_, i64>(5)? as u64,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn put_election_draft(&self, record: ElectionDraftRecord) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "INSERT INTO election_drafts (election_id, candidate_cbor, proof_suite_id, min_approvals, max_approvals, allow_abstention, governance_revision, proposal_question, authorized_slot_count, external_roster_commitment_hex, eligibility_state, created_at_ms) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
            params![
                record.election_id,
                record.candidate_cbor,
                record.proof_suite_id,
                record.min_approvals,
                record.max_approvals,
                record.allow_abstention as i64,
                record.governance_revision,
                record.proposal_question,
                record.authorized_slot_count, record.external_roster_commitment_hex,
                record.eligibility_state, record.created_at_ms,
            ],
        )
        .map_err(|e| map_rusqlite(&e))?;
        Ok(())
    }

    fn get_election_draft(&self, id: &str) -> Result<Option<ElectionDraftRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, candidate_cbor, proof_suite_id, min_approvals, max_approvals, allow_abstention, governance_revision, proposal_question, authorized_slot_count, external_roster_commitment_hex, eligibility_state, created_at_ms FROM election_drafts WHERE election_id = ?1",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![id], |r| {
                Ok(ElectionDraftRecord {
                    election_id: r.get(0)?,
                    candidate_cbor: r.get(1)?,
                    proof_suite_id: r.get(2)?,
                    min_approvals: r.get(3)?,
                    max_approvals: r.get(4)?,
                    allow_abstention: r.get::<_, i64>(5)? != 0,
                    governance_revision: r.get(6)?,
                    proposal_question: r.get(7)?,
                    authorized_slot_count: r.get(8)?,
                    external_roster_commitment_hex: r.get(9)?,
                    eligibility_state: r.get(10)?,
                    created_at_ms: r.get(11)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn set_draft_eligibility_state(
        &self,
        id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, StorageError> {
        let g = self.lock();
        if g.query_row(
            "SELECT eligibility_state FROM election_drafts WHERE election_id = ?1",
            params![id],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(|_| StorageError::Db)?
        .is_none()
        {
            return Err(StorageError::ElectionNotFound);
        }
        let n = g
            .execute(
                "UPDATE election_drafts SET eligibility_state = ?1 WHERE election_id = ?2 AND eligibility_state = ?3",
                params![to, id, from],
            )
            .map_err(|_| StorageError::Db)?;
        Ok(n == 1)
    }

    fn create_slots(
        &self,
        election_id: &str,
        count: usize,
        now_ms: i64,
    ) -> Result<Vec<String>, StorageError> {
        let mut g = self.lock();
        let tx = g.transaction().map_err(|_| StorageError::Db)?;
        let mut ids = Vec::with_capacity(count);
        for _ in 0..count {
            // Generate opaque slot ID using rand
            let slot_id = crate::new_opaque_id();
            tx.execute(
                "INSERT INTO eligibility_slots (slot_id, election_id, consumed, created_at_ms) VALUES (?1, ?2, 0, ?3)",
                params![slot_id, election_id, now_ms],
            )
            .map_err(|_| StorageError::Db)?;
            ids.push(slot_id);
        }
        tx.commit().map_err(|_| StorageError::Db)?;
        Ok(ids)
    }

    fn list_slots(&self, election_id: &str) -> Result<Vec<EligibilitySlotRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT slot_id, election_id, consumed, created_at_ms FROM eligibility_slots WHERE election_id = ?1 ORDER BY created_at_ms ASC",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id], |r| {
                Ok(EligibilitySlotRecord {
                    slot_id: r.get(0)?,
                    election_id: r.get(1)?,
                    consumed: r.get::<_, i64>(2)? != 0,
                    created_at_ms: r.get(3)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn mark_slot_consumed(&self, slot_id: &str) -> Result<(), StorageError> {
        let g = self.lock();
        let n = g
            .execute(
                "UPDATE eligibility_slots SET consumed = 1 WHERE slot_id = ?1",
                params![slot_id],
            )
            .map_err(|_| StorageError::Db)?;
        if n == 0 {
            return Err(StorageError::SlotNotFound);
        }
        Ok(())
    }

    fn insert_invitation(&self, record: InvitationRecord) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "INSERT INTO enrollment_invitations (invitation_id, slot_id, election_id, verifier_hex, state, created_at_ms) VALUES (?1,?2,?3,?4,?5,?6)",
            params![
                record.invitation_id,
                record.slot_id,
                record.election_id,
                record.verifier_hex,
                record.state,
                record.created_at_ms,
            ],
        )
        .map_err(|e| map_rusqlite(&e))?;
        Ok(())
    }

    fn get_active_invitation_for_slot(
        &self,
        slot_id: &str,
    ) -> Result<Option<InvitationRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT invitation_id, slot_id, election_id, verifier_hex, state, created_at_ms FROM enrollment_invitations WHERE slot_id = ?1 AND state = 'ACTIVE'",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![slot_id], |r| {
                Ok(InvitationRecord {
                    invitation_id: r.get(0)?,
                    slot_id: r.get(1)?,
                    election_id: r.get(2)?,
                    verifier_hex: r.get(3)?,
                    state: r.get(4)?,
                    created_at_ms: r.get(5)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn get_invitation_by_verifier(
        &self,
        verifier_hex: &str,
    ) -> Result<Option<InvitationRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT invitation_id, slot_id, election_id, verifier_hex, state, created_at_ms FROM enrollment_invitations WHERE verifier_hex = ?1",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![verifier_hex], |r| {
                Ok(InvitationRecord {
                    invitation_id: r.get(0)?,
                    slot_id: r.get(1)?,
                    election_id: r.get(2)?,
                    verifier_hex: r.get(3)?,
                    state: r.get(4)?,
                    created_at_ms: r.get(5)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn set_invitation_state(
        &self,
        invitation_id: &str,
        from: &str,
        to: &str,
    ) -> Result<bool, StorageError> {
        let g = self.lock();
        let n = g
            .execute(
                "UPDATE enrollment_invitations SET state = ?1 WHERE invitation_id = ?2 AND state = ?3",
                params![to, invitation_id, from],
            )
            .map_err(|_| StorageError::Db)?;
        Ok(n == 1)
    }

    fn void_active_slot_invitations(&self, slot_id: &str) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "UPDATE enrollment_invitations SET state = 'VOIDED' WHERE slot_id = ?1 AND state = 'ACTIVE'",
            params![slot_id],
        )
        .map_err(|_| StorageError::Db)?;
        Ok(())
    }

    fn insert_enrolled_credential(
        &self,
        record: EnrolledCredentialRecord,
    ) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "INSERT INTO enrolled_credentials (election_id, public_key_hex, slot_id, invitation_id, enrolled_at_ms) VALUES (?1,?2,?3,?4,?5)",
            params![
                record.election_id,
                record.public_key_hex,
                record.slot_id,
                record.invitation_id,
                record.enrolled_at_ms,
            ],
        )
        .map_err(|e| map_rusqlite(&e))?;
        Ok(())
    }

    fn get_enrolled_credential_by_key(
        &self,
        election_id: &str,
        public_key_hex: &str,
    ) -> Result<Option<EnrolledCredentialRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, public_key_hex, slot_id, invitation_id, enrolled_at_ms FROM enrolled_credentials WHERE election_id = ?1 AND public_key_hex = ?2",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id, public_key_hex], |r| {
                Ok(EnrolledCredentialRecord {
                    election_id: r.get(0)?,
                    public_key_hex: r.get(1)?,
                    slot_id: r.get(2)?,
                    invitation_id: r.get(3)?,
                    enrolled_at_ms: r.get(4)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn get_enrolled_credential_by_slot(
        &self,
        election_id: &str,
        slot_id: &str,
    ) -> Result<Option<EnrolledCredentialRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, public_key_hex, slot_id, invitation_id, enrolled_at_ms FROM enrolled_credentials WHERE election_id = ?1 AND slot_id = ?2",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id, slot_id], |r| {
                Ok(EnrolledCredentialRecord {
                    election_id: r.get(0)?,
                    public_key_hex: r.get(1)?,
                    slot_id: r.get(2)?,
                    invitation_id: r.get(3)?,
                    enrolled_at_ms: r.get(4)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn list_enrolled_credentials(
        &self,
        election_id: &str,
    ) -> Result<Vec<EnrolledCredentialRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, public_key_hex, slot_id, invitation_id, enrolled_at_ms FROM enrolled_credentials WHERE election_id = ?1 ORDER BY enrolled_at_ms ASC",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id], |r| {
                Ok(EnrolledCredentialRecord {
                    election_id: r.get(0)?,
                    public_key_hex: r.get(1)?,
                    slot_id: r.get(2)?,
                    invitation_id: r.get(3)?,
                    enrolled_at_ms: r.get(4)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn count_enrolled_credentials(&self, election_id: &str) -> Result<i64, StorageError> {
        let g = self.lock();
        let count: i64 = g
            .query_row(
                "SELECT COUNT(*) FROM enrolled_credentials WHERE election_id = ?1",
                params![election_id],
                |r| r.get(0),
            )
            .map_err(|_| StorageError::Db)?;
        Ok(count)
    }

    fn scrub_enrollment_linkage(&self, election_id: &str) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "UPDATE enrolled_credentials SET slot_id = NULL, invitation_id = NULL WHERE election_id = ?1",
            params![election_id],
        )
        .map_err(|_| StorageError::Db)?;
        Ok(())
    }

    fn complete_enrollment(
        &self,
        election_id: &str,
        verifier_hex: &str,
        public_key_hex: &str,
        now_ms: i64,
    ) -> Result<EnrollmentCompletion, StorageError> {
        let mut connection = self.lock();
        // An IMMEDIATE transaction gives this enrollment attempt the writer lock before any
        // validation or mutation, so every early return rolls back and leaves no partial state.
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|_| StorageError::Db)?;
        let state: Option<String> = tx
            .query_row(
                "SELECT eligibility_state FROM election_drafts WHERE election_id = ?1",
                params![election_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| StorageError::Db)?;
        let Some(state) = state else {
            return Ok(EnrollmentCompletion::ElectionNotFound);
        };
        if state != "ENROLLMENT_OPEN" {
            return Ok(EnrollmentCompletion::EnrollmentClosed);
        }
        let invitation: Option<InvitationRecord> = tx.query_row(
            "SELECT invitation_id, slot_id, election_id, verifier_hex, state, created_at_ms FROM enrollment_invitations WHERE verifier_hex = ?1",
            params![verifier_hex], |row| Ok(InvitationRecord { invitation_id: row.get(0)?, slot_id: row.get(1)?, election_id: row.get(2)?, verifier_hex: row.get(3)?, state: row.get(4)?, created_at_ms: row.get(5)? }),
        ).optional().map_err(|_| StorageError::Db)?;
        let invitation = match invitation {
            Some(value) => value,
            None => return Ok(EnrollmentCompletion::InvitationNotFound),
        };
        if invitation.election_id != election_id {
            return Ok(EnrollmentCompletion::WrongElection);
        }
        if invitation.state == "VOIDED" {
            return Ok(EnrollmentCompletion::InvitationVoided);
        }
        let existing_for_slot: Option<EnrolledCredentialRecord> = tx.query_row(
            "SELECT election_id, public_key_hex, slot_id, invitation_id, enrolled_at_ms FROM enrolled_credentials WHERE election_id = ?1 AND slot_id = ?2",
            params![election_id, invitation.slot_id], |row| Ok(EnrolledCredentialRecord { election_id: row.get(0)?, public_key_hex: row.get(1)?, slot_id: row.get(2)?, invitation_id: row.get(3)?, enrolled_at_ms: row.get(4)? }),
        ).optional().map_err(|_| StorageError::Db)?;
        if invitation.state == "CONSUMED" {
            return Ok(match existing_for_slot {
                Some(credential) if credential.public_key_hex == public_key_hex => {
                    EnrollmentCompletion::Idempotent(credential)
                }
                Some(_) => EnrollmentCompletion::CredentialConflict,
                None => EnrollmentCompletion::EnrollmentClosed,
            });
        }
        let key_exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM enrolled_credentials WHERE election_id = ?1 AND public_key_hex = ?2)",
            params![election_id, public_key_hex], |row| row.get(0),
        ).map_err(|_| StorageError::Db)?;
        if key_exists {
            return Ok(EnrollmentCompletion::CredentialConflict);
        }
        let slot_available: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM eligibility_slots WHERE slot_id = ?1 AND election_id = ?2 AND consumed = 0)",
            params![invitation.slot_id, election_id], |row| row.get(0),
        ).map_err(|_| StorageError::Db)?;
        if !slot_available {
            return Ok(EnrollmentCompletion::EnrollmentRace);
        }
        if tx.execute("UPDATE enrollment_invitations SET state = 'CONSUMED' WHERE invitation_id = ?1 AND state = 'ACTIVE'", params![invitation.invitation_id]).map_err(|_| StorageError::Db)? != 1 { return Ok(EnrollmentCompletion::EnrollmentRace); }
        #[cfg(test)]
        if self.enrollment_failpoint_active(EnrollmentFailpoint::AfterInvitationMutation) {
            return Err(StorageError::Db);
        }
        if tx.execute("UPDATE eligibility_slots SET consumed = 1 WHERE slot_id = ?1 AND election_id = ?2 AND consumed = 0", params![invitation.slot_id, election_id]).map_err(|_| StorageError::Db)? != 1 { return Ok(EnrollmentCompletion::EnrollmentRace); }
        #[cfg(test)]
        if self.enrollment_failpoint_active(EnrollmentFailpoint::AfterSlotMutation) {
            return Err(StorageError::Db);
        }
        let credential = EnrolledCredentialRecord {
            election_id: election_id.to_owned(),
            public_key_hex: public_key_hex.to_owned(),
            slot_id: Some(invitation.slot_id),
            invitation_id: Some(invitation.invitation_id),
            enrolled_at_ms: now_ms,
        };
        #[cfg(test)]
        if self.enrollment_failpoint_active(EnrollmentFailpoint::BeforeCredentialInsertion) {
            return Err(StorageError::Db);
        }
        tx.execute("INSERT INTO enrolled_credentials (election_id, public_key_hex, slot_id, invitation_id, enrolled_at_ms) VALUES (?1,?2,?3,?4,?5)", params![credential.election_id, credential.public_key_hex, credential.slot_id, credential.invitation_id, credential.enrolled_at_ms]).map_err(|e| map_rusqlite(&e))?;
        tx.commit().map_err(|_| StorageError::Db)?;
        Ok(EnrollmentCompletion::Created(credential))
    }

    fn put_frozen_registry(&self, record: FrozenRegistryRecord) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "INSERT INTO frozen_registries (election_id, registry_cbor_hex, registry_commitment_hex, authorized_slot_count, enrolled_count, frozen_at_ms, external_roster_commitment_hex) VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                record.election_id,
                record.registry_cbor_hex,
                record.registry_commitment_hex,
                record.authorized_slot_count,
                record.enrolled_count,
                record.frozen_at_ms,
                record.external_roster_commitment_hex,
            ],
        )
        .map_err(|e| map_rusqlite(&e))?;
        Ok(())
    }

    fn get_frozen_registry(
        &self,
        election_id: &str,
    ) -> Result<Option<FrozenRegistryRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, registry_cbor_hex, registry_commitment_hex, authorized_slot_count, enrolled_count, frozen_at_ms, external_roster_commitment_hex FROM frozen_registries WHERE election_id = ?1",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id], |r| {
                Ok(FrozenRegistryRecord {
                    election_id: r.get(0)?,
                    registry_cbor_hex: r.get(1)?,
                    registry_commitment_hex: r.get(2)?,
                    authorized_slot_count: r.get(3)?,
                    enrolled_count: r.get(4)?,
                    frozen_at_ms: r.get(5)?,
                    external_roster_commitment_hex: r.get(6)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn put_organizer_credential(
        &self,
        record: OrganizerCredentialRecord,
    ) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute(
            "INSERT INTO organizer_credentials (election_id, organizer_verifier_hex, created_at_ms) VALUES (?1,?2,?3)",
            params![record.election_id, record.organizer_verifier_hex, record.created_at_ms],
        )
        .map_err(|e| map_rusqlite(&e))?;
        Ok(())
    }

    fn get_organizer_credential(
        &self,
        election_id: &str,
    ) -> Result<Option<OrganizerCredentialRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT election_id, organizer_verifier_hex, created_at_ms FROM organizer_credentials WHERE election_id = ?1",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id], |r| {
                Ok(OrganizerCredentialRecord {
                    election_id: r.get(0)?,
                    organizer_verifier_hex: r.get(1)?,
                    created_at_ms: r.get(2)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn get_invitation_by_id(
        &self,
        invitation_id: &str,
    ) -> Result<Option<InvitationRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT invitation_id, slot_id, election_id, verifier_hex, state, created_at_ms FROM enrollment_invitations WHERE invitation_id = ?1",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![invitation_id], |r| {
                Ok(InvitationRecord {
                    invitation_id: r.get(0)?,
                    slot_id: r.get(1)?,
                    election_id: r.get(2)?,
                    verifier_hex: r.get(3)?,
                    state: r.get(4)?,
                    created_at_ms: r.get(5)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows {
            out = Some(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }

    fn list_invitations(&self, election_id: &str) -> Result<Vec<InvitationRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g
            .prepare(
                "SELECT invitation_id, slot_id, election_id, verifier_hex, state, created_at_ms FROM enrollment_invitations WHERE election_id = ?1 ORDER BY created_at_ms ASC",
            )
            .map_err(|_| StorageError::Db)?;
        let rows = stmt
            .query_map(params![election_id], |r| {
                Ok(InvitationRecord {
                    invitation_id: r.get(0)?,
                    slot_id: r.get(1)?,
                    election_id: r.get(2)?,
                    verifier_hex: r.get(3)?,
                    state: r.get(4)?,
                    created_at_ms: r.get(5)?,
                })
            })
            .map_err(|_| StorageError::Db)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(|_| StorageError::Db)?);
        }
        Ok(out)
    }
}
