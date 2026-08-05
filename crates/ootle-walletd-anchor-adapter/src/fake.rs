//! Deterministic, offline fake of the narrow walletd client (Section I).
//!
//! The fake models the confirmed project-owned lifecycle contract, not walletd
//! wire syntax. It uses no randomness: walletd request identifiers are derived
//! with the production BLAKE3 provider under a fake-specific domain frame plus a
//! per-fake counter, so they are deterministic and can never collide with a
//! protocol digest, anchor-record digest, or inspection fingerprint. It never
//! produces a transaction identifier, never signs or submits, and stores no key
//! material. It exposes call counts and captured requests for assertions, and
//! supports scripted failure injection for every branch this slice must cover.

use std::collections::BTreeMap;

use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};

use crate::client::{
    WalletdAnchorClient, WalletdCreateOutcomeV1, WalletdDecisionCommandV1,
    WalletdDecisionOutcomeV1, WalletdRequestStatusV1, WalletdSubmitCommandV1,
    WalletdSubmitOutcomeV1,
};
use crate::convert::WalletdCreateAnchorRequestV1;
use crate::errors::WalletdAnchorAdapterError;
use crate::identifiers::WalletdRequestId;
use crate::status::WalletdEffectiveStatusV1;

/// Frame domain for deterministic fake walletd request identifiers.
const FAKE_WALLETD_REQUEST_ID_DOMAIN: &[u8] =
    b"tari-cc-private-ballot/ootle-walletd-anchor-adapter-fake/request-id/v1";

/// Frame domain for deterministic fake-only transaction identifiers.
///
/// Distinct from every other domain frame (request id, inspection fingerprint,
/// project request id, and every protocol and anchor-record frame), so a fake
/// transaction id can never be mistaken for, or collide with, a real ledger
/// transaction id or any project digest.
const FAKE_TRANSACTION_ID_DOMAIN: &[u8] =
    b"tari-cc-private-ballot/ootle-walletd-anchor-adapter-fake/transaction-id/v1";

/// Deterministic approval-window expiry the fake reports (unix seconds).
const FAKE_EXPIRES_AT: i64 = 1_900_000_000;

/// One stored request inside the fake (walletd's view).
#[derive(Debug, Clone)]
struct FakeWalletdRecord {
    status: WalletdEffectiveStatusV1,
    fingerprint: OotleAnchorInspectionFingerprintV1,
    transaction_id: Option<AnchorTransactionId>,
}

/// Deterministic in-memory fake of the narrow walletd client boundary.
#[derive(Debug, Default)]
pub struct FakeWalletdAnchorClient {
    records: BTreeMap<i32, FakeWalletdRecord>,
    captured_creates: Vec<WalletdCreateAnchorRequestV1>,
    create_counter: u64,
    create_calls: u64,
    approve_calls: u64,
    reject_calls: u64,
    get_calls: u64,
    submit_calls: u64,
    unavailable: bool,
    pending_create_error: Option<WalletdAnchorAdapterError>,
    pending_approve_error: Option<WalletdAnchorAdapterError>,
    pending_reject_error: Option<WalletdAnchorAdapterError>,
    pending_get_error: Option<WalletdAnchorAdapterError>,
    pending_submit_error: Option<WalletdAnchorAdapterError>,
    submit_timeout_after_processing: bool,
}

impl FakeWalletdAnchorClient {
    /// Creates an empty fake.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes every subsequent call report the wallet daemon as unavailable.
    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.unavailable = unavailable;
    }

    /// Arms a single injected failure for the next create call.
    ///
    /// Use this to script a creation rejection, a transport error, a timeout, an
    /// unavailability, or a malformed response.
    pub fn inject_create_error(&mut self, error: WalletdAnchorAdapterError) {
        self.pending_create_error = Some(error);
    }

    /// Arms a single injected failure for the next approve call.
    pub fn inject_approve_error(&mut self, error: WalletdAnchorAdapterError) {
        self.pending_approve_error = Some(error);
    }

    /// Arms a single injected failure for the next reject call.
    pub fn inject_reject_error(&mut self, error: WalletdAnchorAdapterError) {
        self.pending_reject_error = Some(error);
    }

    /// Arms a single injected failure for the next status read.
    pub fn inject_get_error(&mut self, error: WalletdAnchorAdapterError) {
        self.pending_get_error = Some(error);
    }

    /// Arms a single injected failure for the next submit call.
    ///
    /// The request is left untouched (no sealing), modelling a failure that
    /// occurs before walletd processes the submit — a transport error, an
    /// unavailability, a malformed response, or a timeout before processing.
    pub fn inject_submit_error(&mut self, error: WalletdAnchorAdapterError) {
        self.pending_submit_error = Some(error);
    }

    /// Arms the next submit to process fully (seal + record a transaction id) but
    /// then report a timeout, modelling a submit whose response was lost after
    /// walletd already committed it.
    pub fn inject_submit_timeout_after_processing(&mut self) {
        self.submit_timeout_after_processing = true;
    }

    /// Forces a stored request's recorded transaction id (e.g. to model a
    /// walletd-reported id that conflicts with a locally bound one).
    pub fn force_transaction_id(
        &mut self,
        walletd_request_id: WalletdRequestId,
        transaction_id: Option<AnchorTransactionId>,
    ) {
        if let Some(record) = self.records.get_mut(&walletd_request_id.value()) {
            record.transaction_id = transaction_id;
        }
    }

    /// Returns the number of submit calls made.
    #[must_use]
    pub const fn submit_calls(&self) -> u64 {
        self.submit_calls
    }

    /// Returns the recorded transaction id of a stored request, if any.
    #[must_use]
    pub fn transaction_id_of(
        &self,
        walletd_request_id: WalletdRequestId,
    ) -> Option<AnchorTransactionId> {
        self.records
            .get(&walletd_request_id.value())
            .and_then(|record| record.transaction_id.clone())
    }

    /// Derives a deterministic, fake-only transaction id under a separate domain.
    ///
    /// It never derives from unsigned transaction bytes as if it were a real
    /// sealed id: it is a fake-domain digest of the request's fingerprint and its
    /// walletd request id, deterministic and clearly not a ledger id.
    fn derive_transaction_id(
        fingerprint: &OotleAnchorInspectionFingerprintV1,
        walletd_request_id: i32,
    ) -> AnchorTransactionId {
        let provider = Blake3HashProviderV1;
        let mut framed = Vec::new();
        framed.extend_from_slice(FAKE_TRANSACTION_ID_DOMAIN);
        framed.push(0);
        framed.extend_from_slice(fingerprint.as_bytes());
        framed.push(0);
        framed.extend_from_slice(&walletd_request_id.to_le_bytes());
        let hash = provider.hash(&framed);
        let mut encoded = String::with_capacity(64);
        const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
        for &byte in &hash {
            encoded.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX_DIGITS[usize::from(byte & 0x0f)]));
        }
        match AnchorTransactionId::new(encoded) {
            Ok(transaction_id) => transaction_id,
            Err(_error) => unreachable!("64 lowercase hex characters are always a valid id"),
        }
    }

    /// Forces a stored request's effective status (e.g. to model expiry).
    pub fn force_status(
        &mut self,
        walletd_request_id: WalletdRequestId,
        status: WalletdEffectiveStatusV1,
    ) {
        if let Some(record) = self.records.get_mut(&walletd_request_id.value()) {
            record.status = status;
        }
    }

    /// Returns the number of create calls made.
    #[must_use]
    pub const fn create_calls(&self) -> u64 {
        self.create_calls
    }

    /// Returns the number of approve calls made.
    #[must_use]
    pub const fn approve_calls(&self) -> u64 {
        self.approve_calls
    }

    /// Returns the number of reject calls made.
    #[must_use]
    pub const fn reject_calls(&self) -> u64 {
        self.reject_calls
    }

    /// Returns the number of status reads made.
    #[must_use]
    pub const fn get_calls(&self) -> u64 {
        self.get_calls
    }

    /// Returns the create requests captured verbatim, in call order.
    #[must_use]
    pub fn captured_creates(&self) -> &[WalletdCreateAnchorRequestV1] {
        &self.captured_creates
    }

    /// Returns the most recently captured create request.
    #[must_use]
    pub fn last_captured_create(&self) -> Option<&WalletdCreateAnchorRequestV1> {
        self.captured_creates.last()
    }

    /// Returns the current effective status of a stored request, if any.
    #[must_use]
    pub fn status_of(
        &self,
        walletd_request_id: WalletdRequestId,
    ) -> Option<WalletdEffectiveStatusV1> {
        self.records
            .get(&walletd_request_id.value())
            .map(|record| record.status)
    }

    /// Derives a deterministic, positive, nonzero walletd request identifier.
    fn derive_request_id(&self, command: &WalletdCreateAnchorRequestV1, counter: u64) -> i32 {
        let provider = Blake3HashProviderV1;
        let mut framed = Vec::new();
        framed.extend_from_slice(FAKE_WALLETD_REQUEST_ID_DOMAIN);
        framed.push(0);
        framed.extend_from_slice(command.binding().fingerprint().as_bytes());
        framed.push(0);
        framed.extend_from_slice(&counter.to_le_bytes());
        let hash = provider.hash(&framed);
        let raw = u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]);
        // Shift out the sign bit to stay positive, then avoid zero.
        let positive = (raw >> 1) as i32;
        if positive == 0 { 1 } else { positive }
    }
}

impl WalletdAnchorClient for FakeWalletdAnchorClient {
    fn create_transaction_request(
        &mut self,
        command: &WalletdCreateAnchorRequestV1,
    ) -> Result<WalletdCreateOutcomeV1, WalletdAnchorAdapterError> {
        self.create_calls = self.create_calls.wrapping_add(1);

        if self.unavailable {
            return Err(WalletdAnchorAdapterError::WalletdUnavailable);
        }
        if let Some(error) = self.pending_create_error.take() {
            return Err(error);
        }

        let counter = self.create_counter;
        self.create_counter = self.create_counter.wrapping_add(1);

        let mut request_id_value = self.derive_request_id(command, counter);
        // Preserve determinism while guaranteeing uniqueness on the vanishingly
        // rare derived collision, without any randomness.
        while self.records.contains_key(&request_id_value) {
            request_id_value = request_id_value.wrapping_add(1).max(1);
        }

        self.records.insert(
            request_id_value,
            FakeWalletdRecord {
                status: WalletdEffectiveStatusV1::Pending,
                fingerprint: command.binding().fingerprint(),
                transaction_id: None,
            },
        );
        self.captured_creates.push(command.clone());

        Ok(WalletdCreateOutcomeV1::new(
            WalletdRequestId::from_walletd(request_id_value),
            FAKE_EXPIRES_AT,
        ))
    }

    fn approve_transaction_request(
        &mut self,
        command: &WalletdDecisionCommandV1,
    ) -> Result<WalletdDecisionOutcomeV1, WalletdAnchorAdapterError> {
        self.approve_calls = self.approve_calls.wrapping_add(1);

        if self.unavailable {
            return Err(WalletdAnchorAdapterError::WalletdUnavailable);
        }
        if let Some(error) = self.pending_approve_error.take() {
            return Err(error);
        }

        let walletd_request_id = command.walletd_request_id();
        let Some(record) = self.records.get_mut(&walletd_request_id.value()) else {
            return Err(WalletdAnchorAdapterError::RequestNotFound);
        };

        let status = match record.status {
            WalletdEffectiveStatusV1::Pending | WalletdEffectiveStatusV1::Approved => {
                record.status = WalletdEffectiveStatusV1::Approved;
                WalletdEffectiveStatusV1::Approved
            }
            other => other,
        };

        Ok(WalletdDecisionOutcomeV1::new(walletd_request_id, status))
    }

    fn reject_transaction_request(
        &mut self,
        command: &WalletdDecisionCommandV1,
    ) -> Result<WalletdDecisionOutcomeV1, WalletdAnchorAdapterError> {
        self.reject_calls = self.reject_calls.wrapping_add(1);

        if self.unavailable {
            return Err(WalletdAnchorAdapterError::WalletdUnavailable);
        }
        if let Some(error) = self.pending_reject_error.take() {
            return Err(error);
        }

        let walletd_request_id = command.walletd_request_id();
        let Some(record) = self.records.get_mut(&walletd_request_id.value()) else {
            return Err(WalletdAnchorAdapterError::RequestNotFound);
        };

        let status = match record.status {
            WalletdEffectiveStatusV1::Pending | WalletdEffectiveStatusV1::Rejected => {
                record.status = WalletdEffectiveStatusV1::Rejected;
                WalletdEffectiveStatusV1::Rejected
            }
            other => other,
        };

        Ok(WalletdDecisionOutcomeV1::new(walletd_request_id, status))
    }

    fn get_transaction_request(
        &mut self,
        walletd_request_id: WalletdRequestId,
    ) -> Result<WalletdRequestStatusV1, WalletdAnchorAdapterError> {
        self.get_calls = self.get_calls.wrapping_add(1);

        if self.unavailable {
            return Err(WalletdAnchorAdapterError::WalletdUnavailable);
        }
        if let Some(error) = self.pending_get_error.take() {
            return Err(error);
        }

        let Some(record) = self.records.get(&walletd_request_id.value()) else {
            return Err(WalletdAnchorAdapterError::RequestNotFound);
        };

        Ok(WalletdRequestStatusV1::new(
            walletd_request_id,
            record.status,
            record.transaction_id.clone(),
            Some(record.fingerprint),
        ))
    }

    fn submit_transaction_request(
        &mut self,
        command: &WalletdSubmitCommandV1,
    ) -> Result<WalletdSubmitOutcomeV1, WalletdAnchorAdapterError> {
        self.submit_calls = self.submit_calls.wrapping_add(1);

        if self.unavailable {
            return Err(WalletdAnchorAdapterError::WalletdUnavailable);
        }

        let walletd_request_id = command.walletd_request_id();
        let timeout_after = self.submit_timeout_after_processing;
        let pending_error = self.pending_submit_error.take();

        // A failure before processing leaves the request untouched: nothing is
        // sealed, so recovery will find it still approved.
        if let Some(error) = pending_error {
            return Err(error);
        }

        let fingerprint = match self.records.get(&walletd_request_id.value()) {
            Some(record) => record.fingerprint,
            None => return Err(WalletdAnchorAdapterError::RequestNotFound),
        };

        // The confirmed walletd path only seals an approved request; any other
        // status fails the Approved -> Submitting claim.
        let current = self
            .records
            .get(&walletd_request_id.value())
            .map(|record| record.status);
        match current {
            Some(WalletdEffectiveStatusV1::Approved) => {}
            Some(WalletdEffectiveStatusV1::Submitting | WalletdEffectiveStatusV1::Submitted) => {
                return Err(WalletdAnchorAdapterError::AlreadySubmitted);
            }
            Some(WalletdEffectiveStatusV1::Pending) => {
                return Err(WalletdAnchorAdapterError::RequestNotApproved);
            }
            Some(WalletdEffectiveStatusV1::Rejected) => {
                return Err(WalletdAnchorAdapterError::RequestAlreadyRejected);
            }
            Some(WalletdEffectiveStatusV1::Expired) => {
                return Err(WalletdAnchorAdapterError::RequestExpired);
            }
            None => return Err(WalletdAnchorAdapterError::RequestNotFound),
        }

        // Derive the fake transaction id once and seal the record; a second
        // submit of the same request can never create a second transaction.
        let transaction_id = Self::derive_transaction_id(&fingerprint, walletd_request_id.value());
        if let Some(record) = self.records.get_mut(&walletd_request_id.value()) {
            record.status = WalletdEffectiveStatusV1::Submitted;
            record.transaction_id = Some(transaction_id.clone());
        }

        // Model a submit whose response was lost after walletd already committed:
        // the request is sealed above, but the caller sees a timeout and must
        // recover the id through the status API.
        if timeout_after {
            self.submit_timeout_after_processing = false;
            return Err(WalletdAnchorAdapterError::SubmitTimeout);
        }

        Ok(WalletdSubmitOutcomeV1::new(
            walletd_request_id,
            transaction_id,
        ))
    }
}
