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

use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};

use crate::client::{
    WalletdAnchorClient, WalletdCreateOutcomeV1, WalletdDecisionCommandV1,
    WalletdDecisionOutcomeV1, WalletdRequestStatusV1,
};
use crate::convert::WalletdCreateAnchorRequestV1;
use crate::errors::WalletdAnchorAdapterError;
use crate::identifiers::WalletdRequestId;
use crate::status::WalletdEffectiveStatusV1;

/// Frame domain for deterministic fake walletd request identifiers.
const FAKE_WALLETD_REQUEST_ID_DOMAIN: &[u8] =
    b"tari-cc-private-ballot/ootle-walletd-anchor-adapter-fake/request-id/v1";

/// Deterministic approval-window expiry the fake reports (unix seconds).
const FAKE_EXPIRES_AT: i64 = 1_900_000_000;

/// One stored request inside the fake (walletd's view).
#[derive(Debug, Clone)]
struct FakeWalletdRecord {
    status: WalletdEffectiveStatusV1,
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
    unavailable: bool,
    pending_create_error: Option<WalletdAnchorAdapterError>,
    pending_approve_error: Option<WalletdAnchorAdapterError>,
    pending_reject_error: Option<WalletdAnchorAdapterError>,
    pending_get_error: Option<WalletdAnchorAdapterError>,
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
            false,
        ))
    }
}
