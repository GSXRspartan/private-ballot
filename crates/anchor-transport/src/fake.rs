//! Deterministic in-memory fake for the offline anchor-transport contract
//! (Section J).
//!
//! The fake models the project-owned lifecycle contract, not walletd wire
//! syntax. It never uses randomness: fake request and transaction identifiers
//! are derived with the production BLAKE3 provider under fake-specific domain
//! frames that can never collide with a protocol or anchor-record digest. It
//! stores no private keys, rejects illegal transitions, supports scripted
//! failure injection, and produces deterministic recovery snapshots.

use std::collections::BTreeMap;

use tari_cc_private_ballot_anchor::OotleAnchorRecordHashV1;
use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};

use crate::errors::{
    AnchorApprovalError, AnchorPreparationError, AnchorReceiptQueryError, AnchorRequestLookupError,
    AnchorSubmissionError,
};
use crate::identifiers::{AnchorRequestId, AnchorTransactionId};
use crate::model::{
    AnchorBindingV1, AnchorFinalStatusV1, AnchorLifecycleSnapshotV1, AnchorLifecycleState,
    AnchorLogEntryV1, AnchorLogLevelV1, AnchorMaxFeeV1, AnchorPreparationRequest,
    AnchorQueryOutcomeV1, AnchorReceiptSourceKindV1, AnchorReceiptV1, AnchorRequestDecisionV1,
    ApprovedAnchorTransaction, PreparedAnchorTransaction, SubmittedAnchorTransaction,
};
use crate::traits::{
    AnchorReceiptSource, AnchorTransactionApprover, AnchorTransactionRequestStore,
    AnchorTransactionSubmitter,
};

/// Frame domain for deterministic fake request identifiers.
const FAKE_REQUEST_ID_DOMAIN: &[u8] = b"tari-cc-private-ballot/anchor-transport-fake/request-id/v1";

/// Frame domain for deterministic fake transaction identifiers.
const FAKE_TRANSACTION_ID_DOMAIN: &[u8] =
    b"tari-cc-private-ballot/anchor-transport-fake/transaction-id/v1";

/// Deterministic opaque ledger position reported for a finalized fake receipt.
const FAKE_LEDGER_POSITION: u64 = 1;

/// Scripted finality the fake should report once a request has been submitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeFinality {
    /// The transaction exists but has not finalized.
    NotFinalized,
    /// The transaction fully committed, including the anchor log.
    Accepted,
    /// Only the fee intent committed; the anchor did not land.
    FeeOnly,
    /// The transaction was rejected.
    Rejected,
    /// The outcome is unknown, for example after a lost submit response.
    Unknown,
}

/// One stored request record inside the fake.
#[derive(Debug, Clone)]
struct FakeRequestRecord {
    binding: AnchorBindingV1,
    max_fee: AnchorMaxFeeV1,
    decision: AnchorRequestDecisionV1,
    transaction_id: Option<AnchorTransactionId>,
    submitted: bool,
    finality: FakeFinality,
}

/// Deterministic in-memory anchor-transport fake.
#[derive(Debug, Default)]
pub struct DeterministicAnchorFake {
    records: BTreeMap<AnchorRequestId, FakeRequestRecord>,
    client_index: BTreeMap<String, AnchorRequestId>,
    by_transaction: BTreeMap<AnchorTransactionId, AnchorRequestId>,
    create_counter: u64,
    source_kind: AnchorReceiptSourceKindV1,
    pending_create_failure: Option<AnchorPreparationError>,
    pending_approve_failure: Option<AnchorApprovalError>,
    arm_submit_timeout: bool,
    query_unavailable: bool,
}

impl DeterministicAnchorFake {
    /// Creates an empty fake that reports receipts as a wallet daemon.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty fake that reports receipts from the given source kind.
    #[must_use]
    pub fn with_source_kind(source_kind: AnchorReceiptSourceKindV1) -> Self {
        Self {
            source_kind,
            ..Self::default()
        }
    }

    /// Arms a single injected failure for the next `create_request` call.
    pub fn inject_create_failure(&mut self, error: AnchorPreparationError) {
        self.pending_create_failure = Some(error);
    }

    /// Arms a single injected failure for the next `approve` call.
    pub fn inject_approve_failure(&mut self, error: AnchorApprovalError) {
        self.pending_approve_failure = Some(error);
    }

    /// Arms a single submit timeout: the next submit seals but returns a timeout.
    pub fn arm_submit_timeout(&mut self) {
        self.arm_submit_timeout = true;
    }

    /// Controls whether the receipt source is currently reachable.
    pub fn set_query_unavailable(&mut self, unavailable: bool) {
        self.query_unavailable = unavailable;
    }

    /// Sets the scripted finality reported for a submitted request.
    pub fn set_finality(&mut self, request_id: &AnchorRequestId, finality: FakeFinality) {
        if let Some(record) = self.records.get_mut(request_id) {
            record.finality = finality;
        }
    }

    /// Marks a request's approval window as expired.
    pub fn inject_expire(&mut self, request_id: &AnchorRequestId) {
        if let Some(record) = self.records.get_mut(request_id) {
            record.decision = AnchorRequestDecisionV1::Expired;
        }
    }

    /// Returns a recovery snapshot for one stored request.
    #[must_use]
    pub fn snapshot(&self, request_id: &AnchorRequestId) -> Option<AnchorLifecycleSnapshotV1> {
        let record = self.records.get(request_id)?;
        Some(AnchorLifecycleSnapshotV1::new(
            request_id.clone(),
            record.binding.clone(),
            Self::lifecycle_state(record),
            record.transaction_id.clone(),
            Self::last_receipt_status(record),
        ))
    }

    /// Returns recovery snapshots for every stored request, in request order.
    #[must_use]
    pub fn snapshots(&self) -> Vec<AnchorLifecycleSnapshotV1> {
        self.records
            .keys()
            .filter_map(|request_id| self.snapshot(request_id))
            .collect()
    }

    /// Rebuilds a fake from recovery snapshots, as after a restart.
    ///
    /// The maximum fee is not part of a snapshot (it is not retry-safe metadata),
    /// so a restored record reports a zero ceiling; no post-restart operation
    /// depends on it.
    #[must_use]
    pub fn from_snapshots(
        source_kind: AnchorReceiptSourceKindV1,
        snapshots: Vec<AnchorLifecycleSnapshotV1>,
    ) -> Self {
        let mut fake = Self::with_source_kind(source_kind);

        for snapshot in snapshots {
            let (decision, submitted, finality) = reconstruct_state(
                snapshot.lifecycle_state(),
                snapshot.transaction_id().is_some(),
            );

            let record = FakeRequestRecord {
                binding: snapshot.binding().clone(),
                max_fee: AnchorMaxFeeV1::from_units(0),
                decision,
                transaction_id: snapshot.transaction_id().cloned(),
                submitted,
                finality,
            };

            if let Some(transaction_id) = snapshot.transaction_id() {
                fake.by_transaction
                    .insert(transaction_id.clone(), snapshot.request_id().clone());
            }

            fake.records.insert(snapshot.request_id().clone(), record);
        }

        fake
    }

    /// Derives a deterministic fake request identifier.
    fn derive_request_id(disambiguator: &[u8], binding: &AnchorBindingV1) -> AnchorRequestId {
        let provider = Blake3HashProviderV1;
        let mut framed = Vec::new();
        framed.extend_from_slice(FAKE_REQUEST_ID_DOMAIN);
        framed.push(0);
        framed.extend_from_slice(binding.network().as_str().as_bytes());
        framed.push(0);
        framed.extend_from_slice(binding.account().as_str().as_bytes());
        framed.push(0);
        framed.extend_from_slice(binding.anchor_digest().as_bytes());
        framed.push(0);
        framed.extend_from_slice(disambiguator);
        AnchorRequestId::from_trusted_hash(&provider.hash(&framed))
    }

    /// Derives a deterministic fake transaction identifier.
    fn derive_transaction_id(
        request_id: &AnchorRequestId,
        anchor_digest: &OotleAnchorRecordHashV1,
    ) -> AnchorTransactionId {
        let provider = Blake3HashProviderV1;
        let mut framed = Vec::new();
        framed.extend_from_slice(FAKE_TRANSACTION_ID_DOMAIN);
        framed.push(0);
        framed.extend_from_slice(request_id.as_str().as_bytes());
        framed.push(0);
        framed.extend_from_slice(anchor_digest.as_bytes());
        AnchorTransactionId::from_trusted_hash(&provider.hash(&framed))
    }

    /// Builds a prepared-transaction result from a stored record.
    fn prepared_from(
        request_id: &AnchorRequestId,
        record: &FakeRequestRecord,
    ) -> PreparedAnchorTransaction {
        PreparedAnchorTransaction::new(request_id.clone(), record.binding.clone(), record.max_fee)
    }

    /// Derives the merged lifecycle state of a stored record.
    fn lifecycle_state(record: &FakeRequestRecord) -> AnchorLifecycleState {
        match record.decision {
            AnchorRequestDecisionV1::Rejected => AnchorLifecycleState::RejectedByApprover,
            AnchorRequestDecisionV1::Expired => AnchorLifecycleState::Unknown,
            AnchorRequestDecisionV1::Pending => AnchorLifecycleState::Prepared,
            AnchorRequestDecisionV1::Approved => {
                if !record.submitted {
                    return AnchorLifecycleState::Approved;
                }

                match record.finality {
                    FakeFinality::NotFinalized => AnchorLifecycleState::Submitted,
                    FakeFinality::Unknown => AnchorLifecycleState::Unknown,
                    FakeFinality::Accepted => AnchorLifecycleState::FinalizedAccept,
                    FakeFinality::FeeOnly => AnchorLifecycleState::FinalizedFeeOnly,
                    FakeFinality::Rejected => AnchorLifecycleState::FinalizedReject,
                }
            }
        }
    }

    /// Derives the last observed finalized status of a stored record.
    fn last_receipt_status(record: &FakeRequestRecord) -> Option<AnchorFinalStatusV1> {
        if !record.submitted {
            return None;
        }

        match record.finality {
            FakeFinality::Accepted => Some(AnchorFinalStatusV1::Accepted),
            FakeFinality::FeeOnly => Some(AnchorFinalStatusV1::FeeOnlyAccepted),
            FakeFinality::Rejected => Some(AnchorFinalStatusV1::Rejected),
            FakeFinality::NotFinalized | FakeFinality::Unknown => None,
        }
    }

    /// Builds a finalized receipt for a fully accepted transaction.
    fn accepted_receipt(
        &self,
        record: &FakeRequestRecord,
        transaction_id: &AnchorTransactionId,
    ) -> AnchorReceiptV1 {
        let logs = vec![
            AnchorLogEntryV1::new(AnchorLogLevelV1::Info, "transaction executed".to_owned()),
            AnchorLogEntryV1::new(
                AnchorLogLevelV1::Info,
                record.binding.payload().to_encoded_string(),
            ),
        ];

        AnchorReceiptV1::new(
            transaction_id.clone(),
            record.binding.network().clone(),
            AnchorFinalStatusV1::Accepted,
            logs,
            None,
            Some(FAKE_LEDGER_POSITION),
            self.source_kind,
        )
    }

    /// Builds a finalized receipt for a fee-only acceptance (no anchor log).
    fn fee_only_receipt(
        &self,
        record: &FakeRequestRecord,
        transaction_id: &AnchorTransactionId,
    ) -> AnchorReceiptV1 {
        let logs = vec![AnchorLogEntryV1::new(
            AnchorLogLevelV1::Warn,
            "fee intent committed; main intent rejected".to_owned(),
        )];

        AnchorReceiptV1::new(
            transaction_id.clone(),
            record.binding.network().clone(),
            AnchorFinalStatusV1::FeeOnlyAccepted,
            logs,
            Some("main intent rejected after fee".to_owned()),
            Some(FAKE_LEDGER_POSITION),
            self.source_kind,
        )
    }

    /// Builds a finalized receipt for a rejected transaction.
    fn rejected_receipt(
        &self,
        record: &FakeRequestRecord,
        transaction_id: &AnchorTransactionId,
    ) -> AnchorReceiptV1 {
        AnchorReceiptV1::new(
            transaction_id.clone(),
            record.binding.network().clone(),
            AnchorFinalStatusV1::Rejected,
            Vec::new(),
            Some("execution failure".to_owned()),
            None,
            self.source_kind,
        )
    }
}

/// Maps a snapshot lifecycle state back into stored-record fields.
fn reconstruct_state(
    lifecycle_state: AnchorLifecycleState,
    has_transaction: bool,
) -> (AnchorRequestDecisionV1, bool, FakeFinality) {
    match lifecycle_state {
        AnchorLifecycleState::Prepared => (
            AnchorRequestDecisionV1::Pending,
            false,
            FakeFinality::NotFinalized,
        ),
        AnchorLifecycleState::Approved => (
            AnchorRequestDecisionV1::Approved,
            false,
            FakeFinality::NotFinalized,
        ),
        AnchorLifecycleState::RejectedByApprover => (
            AnchorRequestDecisionV1::Rejected,
            false,
            FakeFinality::NotFinalized,
        ),
        AnchorLifecycleState::Submitted => (
            AnchorRequestDecisionV1::Approved,
            true,
            FakeFinality::NotFinalized,
        ),
        AnchorLifecycleState::FinalizedAccept => (
            AnchorRequestDecisionV1::Approved,
            true,
            FakeFinality::Accepted,
        ),
        AnchorLifecycleState::FinalizedFeeOnly => (
            AnchorRequestDecisionV1::Approved,
            true,
            FakeFinality::FeeOnly,
        ),
        AnchorLifecycleState::FinalizedReject => (
            AnchorRequestDecisionV1::Approved,
            true,
            FakeFinality::Rejected,
        ),
        AnchorLifecycleState::Unknown => {
            if has_transaction {
                (
                    AnchorRequestDecisionV1::Approved,
                    true,
                    FakeFinality::Unknown,
                )
            } else {
                (
                    AnchorRequestDecisionV1::Expired,
                    false,
                    FakeFinality::NotFinalized,
                )
            }
        }
    }
}

impl AnchorTransactionRequestStore for DeterministicAnchorFake {
    fn create_request(
        &mut self,
        request: &AnchorPreparationRequest,
    ) -> Result<PreparedAnchorTransaction, AnchorPreparationError> {
        if let Some(error) = self.pending_create_failure.take() {
            return Err(error);
        }

        let existing = request
            .client_reference()
            .and_then(|client_reference| self.client_index.get(client_reference.as_str()).cloned());

        if let Some(existing_id) = existing {
            let Some(record) = self.records.get(&existing_id) else {
                return Err(AnchorPreparationError::ClientReferenceConflict);
            };

            if record.binding != *request.binding() {
                return Err(AnchorPreparationError::ClientReferenceConflict);
            }

            return Ok(Self::prepared_from(&existing_id, record));
        }

        let disambiguator = match request.client_reference() {
            Some(client_reference) => client_reference.as_str().as_bytes().to_vec(),
            None => {
                let counter = self.create_counter;
                self.create_counter = self.create_counter.wrapping_add(1);
                counter.to_le_bytes().to_vec()
            }
        };

        let request_id = Self::derive_request_id(&disambiguator, request.binding());
        let record = FakeRequestRecord {
            binding: request.binding().clone(),
            max_fee: request.max_fee(),
            decision: AnchorRequestDecisionV1::Pending,
            transaction_id: None,
            submitted: false,
            finality: FakeFinality::NotFinalized,
        };

        let prepared = Self::prepared_from(&request_id, &record);

        if let Some(client_reference) = request.client_reference() {
            self.client_index
                .insert(client_reference.as_str().to_owned(), request_id.clone());
        }

        self.records.insert(request_id, record);

        Ok(prepared)
    }

    fn get_request(
        &self,
        request_id: &AnchorRequestId,
    ) -> Result<AnchorLifecycleSnapshotV1, AnchorRequestLookupError> {
        self.snapshot(request_id)
            .ok_or(AnchorRequestLookupError::NotFound)
    }
}

impl AnchorTransactionApprover for DeterministicAnchorFake {
    fn approve(
        &mut self,
        request_id: &AnchorRequestId,
        binding: &AnchorBindingV1,
    ) -> Result<ApprovedAnchorTransaction, AnchorApprovalError> {
        if let Some(error) = self.pending_approve_failure.take() {
            return Err(error);
        }

        let Some(record) = self.records.get_mut(request_id) else {
            return Err(AnchorApprovalError::RequestNotFound);
        };

        if binding.network() != record.binding.network() {
            return Err(AnchorApprovalError::NetworkMismatch);
        }
        if binding.account() != record.binding.account() {
            return Err(AnchorApprovalError::AccountMismatch);
        }
        if binding.payload() != record.binding.payload() {
            return Err(AnchorApprovalError::PayloadMismatch);
        }

        match record.decision {
            AnchorRequestDecisionV1::Approved => Err(AnchorApprovalError::AlreadyApproved),
            AnchorRequestDecisionV1::Rejected => Err(AnchorApprovalError::AlreadyRejected),
            AnchorRequestDecisionV1::Expired => Err(AnchorApprovalError::Expired),
            AnchorRequestDecisionV1::Pending => {
                record.decision = AnchorRequestDecisionV1::Approved;
                Ok(ApprovedAnchorTransaction::new(
                    request_id.clone(),
                    record.binding.clone(),
                ))
            }
        }
    }

    fn reject(&mut self, request_id: &AnchorRequestId) -> Result<(), AnchorApprovalError> {
        let Some(record) = self.records.get_mut(request_id) else {
            return Err(AnchorApprovalError::RequestNotFound);
        };

        match record.decision {
            AnchorRequestDecisionV1::Pending => {
                record.decision = AnchorRequestDecisionV1::Rejected;
                Ok(())
            }
            AnchorRequestDecisionV1::Rejected => Ok(()),
            AnchorRequestDecisionV1::Approved => Err(AnchorApprovalError::AlreadyApproved),
            AnchorRequestDecisionV1::Expired => Err(AnchorApprovalError::Expired),
        }
    }
}

impl AnchorTransactionSubmitter for DeterministicAnchorFake {
    fn submit(
        &mut self,
        request_id: &AnchorRequestId,
        binding: &AnchorBindingV1,
        expected_digest: &OotleAnchorRecordHashV1,
    ) -> Result<SubmittedAnchorTransaction, AnchorSubmissionError> {
        let timeout_armed = self.arm_submit_timeout;

        let (transaction_id, bound) = {
            let Some(record) = self.records.get_mut(request_id) else {
                return Err(AnchorSubmissionError::RequestNotFound);
            };

            if binding.network() != record.binding.network() {
                return Err(AnchorSubmissionError::NetworkMismatch);
            }
            if binding.account() != record.binding.account() {
                return Err(AnchorSubmissionError::AccountMismatch);
            }
            if binding.payload() != record.binding.payload() {
                return Err(AnchorSubmissionError::PayloadMismatch);
            }
            if *expected_digest != record.binding.anchor_digest() {
                return Err(AnchorSubmissionError::PayloadMismatch);
            }

            match record.decision {
                AnchorRequestDecisionV1::Pending => return Err(AnchorSubmissionError::NotApproved),
                AnchorRequestDecisionV1::Rejected => return Err(AnchorSubmissionError::Rejected),
                AnchorRequestDecisionV1::Expired => return Err(AnchorSubmissionError::Expired),
                AnchorRequestDecisionV1::Approved => {}
            }

            let transaction_id =
                Self::derive_transaction_id(request_id, &record.binding.anchor_digest());
            record.transaction_id = Some(transaction_id.clone());
            record.submitted = true;

            if timeout_armed {
                record.finality = FakeFinality::Unknown;
            }

            (transaction_id, record.binding.clone())
        };

        self.by_transaction
            .entry(transaction_id.clone())
            .or_insert_with(|| request_id.clone());

        if timeout_armed {
            self.arm_submit_timeout = false;
            return Err(AnchorSubmissionError::Timeout);
        }

        Ok(SubmittedAnchorTransaction::new(
            request_id.clone(),
            transaction_id,
            bound,
        ))
    }
}

impl AnchorReceiptSource for DeterministicAnchorFake {
    fn query_receipt(
        &self,
        transaction_id: &AnchorTransactionId,
        _expected_network: &OotleNetworkIdV1,
    ) -> Result<AnchorQueryOutcomeV1, AnchorReceiptQueryError> {
        if self.query_unavailable {
            return Err(AnchorReceiptQueryError::Unavailable);
        }

        let Some(request_id) = self.by_transaction.get(transaction_id) else {
            return Ok(AnchorQueryOutcomeV1::NotFound);
        };

        let Some(record) = self.records.get(request_id) else {
            return Ok(AnchorQueryOutcomeV1::NotFound);
        };

        if !record.submitted {
            return Ok(AnchorQueryOutcomeV1::NotFound);
        }

        let outcome = match record.finality {
            FakeFinality::NotFinalized => AnchorQueryOutcomeV1::NotFinalized,
            FakeFinality::Unknown => AnchorQueryOutcomeV1::Unknown,
            FakeFinality::Accepted => {
                AnchorQueryOutcomeV1::Finalized(self.accepted_receipt(record, transaction_id))
            }
            FakeFinality::FeeOnly => {
                AnchorQueryOutcomeV1::Finalized(self.fee_only_receipt(record, transaction_id))
            }
            FakeFinality::Rejected => {
                AnchorQueryOutcomeV1::Finalized(self.rejected_receipt(record, transaction_id))
            }
        };

        Ok(outcome)
    }
}
