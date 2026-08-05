//! Narrow, project-owned walletd client boundary (Section A).
//!
//! The trait exposes only the four operations this slice needs — create,
//! approve, reject, and an optional status read — in terms of project DTOs, so
//! the full walletd client is not spread through the project and the boundary is
//! trivially fakeable offline.
//!
//! The boundary is deliberately synchronous, matching the Slice 4A4 traits. The
//! confirmed `WalletDaemonClient` methods are `async` and reqwest-backed; a
//! future real adapter bridges async to this synchronous boundary at the
//! application layer (it forwards [`WalletdCreateAnchorRequestV1::wire_request`]
//! and blocks on a caller-provided runtime handle). This slice owns no runtime,
//! starts no background task, and makes no network call.

use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorInspectionFingerprintV1;

use crate::convert::WalletdCreateAnchorRequestV1;
use crate::errors::WalletdAnchorAdapterError;
use crate::identifiers::WalletdRequestId;
use crate::status::WalletdEffectiveStatusV1;

/// Outcome of creating a frozen walletd transaction request.
///
/// Mirrors the confirmed `TransactionRequestCreateResponse` (an opaque request
/// identifier plus an approval-window expiry). A freshly created request is
/// always pending an approval decision and carries no transaction identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletdCreateOutcomeV1 {
    walletd_request_id: WalletdRequestId,
    expires_at: i64,
}

impl WalletdCreateOutcomeV1 {
    /// Builds a create outcome from the confirmed fields.
    #[must_use]
    pub const fn new(walletd_request_id: WalletdRequestId, expires_at: i64) -> Self {
        Self {
            walletd_request_id,
            expires_at,
        }
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the approval-window expiry (unix seconds).
    #[must_use]
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }
}

/// Command naming a stored request for an approve or reject decision.
///
/// Mirrors the confirmed `TransactionRequestDecisionRequest`, which carries only
/// the opaque request identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletdDecisionCommandV1 {
    walletd_request_id: WalletdRequestId,
}

impl WalletdDecisionCommandV1 {
    /// Builds a decision command for one stored request.
    #[must_use]
    pub const fn new(walletd_request_id: WalletdRequestId) -> Self {
        Self { walletd_request_id }
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }
}

/// Outcome of an approve or reject decision.
///
/// Mirrors the confirmed `TransactionRequestDecisionResponse` (the opaque
/// request identifier plus the effective status). It carries no transaction
/// identifier: sealing happens only at submit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletdDecisionOutcomeV1 {
    walletd_request_id: WalletdRequestId,
    status: WalletdEffectiveStatusV1,
}

impl WalletdDecisionOutcomeV1 {
    /// Builds a decision outcome from the confirmed fields.
    #[must_use]
    pub const fn new(
        walletd_request_id: WalletdRequestId,
        status: WalletdEffectiveStatusV1,
    ) -> Self {
        Self {
            walletd_request_id,
            status,
        }
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the effective status walletd reported for the request.
    #[must_use]
    pub const fn status(&self) -> WalletdEffectiveStatusV1 {
        self.status
    }
}

/// Project view of a stored request's status (read + recovery boundary).
///
/// Mirrors the confirmed `TransactionRequestGetResponse`/`TransactionRequestInfo`,
/// narrowed to the fields this slice cares about: the effective status, the
/// sealed transaction id (present only once submitted), and the fingerprint of
/// the frozen transaction walletd still holds. Before submit, `transaction_id` is
/// `None`; observing it `Some` during preparation or approval is unexpected.
///
/// `observed_fingerprint` lets recovery prove the request walletd returned is
/// byte-identical to the one that was prepared: a real client recomputes the
/// Slice 4A5 inspection fingerprint over the returned frozen transaction. A
/// mismatch is a security error, never a recoverable warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletdRequestStatusV1 {
    walletd_request_id: WalletdRequestId,
    status: WalletdEffectiveStatusV1,
    transaction_id: Option<AnchorTransactionId>,
    observed_fingerprint: Option<OotleAnchorInspectionFingerprintV1>,
}

impl WalletdRequestStatusV1 {
    /// Builds a status view from the confirmed fields.
    #[must_use]
    pub const fn new(
        walletd_request_id: WalletdRequestId,
        status: WalletdEffectiveStatusV1,
        transaction_id: Option<AnchorTransactionId>,
        observed_fingerprint: Option<OotleAnchorInspectionFingerprintV1>,
    ) -> Self {
        Self {
            walletd_request_id,
            status,
            transaction_id,
            observed_fingerprint,
        }
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the effective status walletd reported for the request.
    #[must_use]
    pub const fn status(&self) -> WalletdEffectiveStatusV1 {
        self.status
    }

    /// Returns the sealed transaction id, if walletd has recorded one.
    #[must_use]
    pub const fn transaction_id(&self) -> Option<&AnchorTransactionId> {
        self.transaction_id.as_ref()
    }

    /// Returns whether walletd has recorded a sealed transaction identifier.
    #[must_use]
    pub const fn has_transaction_id(&self) -> bool {
        self.transaction_id.is_some()
    }

    /// Returns the fingerprint of the frozen transaction walletd still holds.
    #[must_use]
    pub const fn observed_fingerprint(&self) -> Option<OotleAnchorInspectionFingerprintV1> {
        self.observed_fingerprint
    }
}

/// Command asking walletd to seal and submit an approved request (Section C).
///
/// Mirrors the confirmed `TransactionRequestSubmitRequest`, which carries only the
/// opaque request identifier: the frozen transaction, the seal signer, and the
/// fee it pays were all fixed at creation, so submit adds nothing a caller could
/// alter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletdSubmitCommandV1 {
    walletd_request_id: WalletdRequestId,
}

impl WalletdSubmitCommandV1 {
    /// Builds a submit command for one approved, stored request.
    #[must_use]
    pub const fn new(walletd_request_id: WalletdRequestId) -> Self {
        Self { walletd_request_id }
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }
}

/// Outcome of sealing and submitting an approved request (Section D).
///
/// Mirrors the confirmed `TransactionRequestSubmitResponse`, which carries the
/// sealed transaction id and nothing else. The transaction id exists only because
/// walletd sealed the frozen transaction just now; it makes no finality claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletdSubmitOutcomeV1 {
    walletd_request_id: WalletdRequestId,
    transaction_id: AnchorTransactionId,
}

impl WalletdSubmitOutcomeV1 {
    /// Builds a submit outcome from the confirmed fields.
    #[must_use]
    pub const fn new(
        walletd_request_id: WalletdRequestId,
        transaction_id: AnchorTransactionId,
    ) -> Self {
        Self {
            walletd_request_id,
            transaction_id,
        }
    }

    /// Returns the opaque walletd request identifier.
    #[must_use]
    pub const fn walletd_request_id(&self) -> WalletdRequestId {
        self.walletd_request_id
    }

    /// Returns the sealed transaction id walletd produced.
    #[must_use]
    pub const fn transaction_id(&self) -> &AnchorTransactionId {
        &self.transaction_id
    }
}

/// Narrow, fakeable walletd client boundary for the prepare/approve lifecycle.
///
/// It supports only the operations this slice needs. It never exposes a signed
/// transaction, a transaction identifier, a private key, or a mnemonic, and it
/// never submits. `create` accepts the project-owned command carrying the frozen
/// wire request; a real adapter forwards `command.wire_request()`.
pub trait WalletdAnchorClient {
    /// Creates a frozen transaction request walletd stores verbatim.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on transport failure,
    /// unavailability, a malformed response, or a creation rejection.
    fn create_transaction_request(
        &mut self,
        command: &WalletdCreateAnchorRequestV1,
    ) -> Result<WalletdCreateOutcomeV1, WalletdAnchorAdapterError>;

    /// Approves a stored request through the walletd approval gate.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on transport failure,
    /// unavailability, a malformed response, an unknown request, or a refusal.
    fn approve_transaction_request(
        &mut self,
        command: &WalletdDecisionCommandV1,
    ) -> Result<WalletdDecisionOutcomeV1, WalletdAnchorAdapterError>;

    /// Rejects a stored request through the walletd approval gate.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on transport failure,
    /// unavailability, a malformed response, an unknown request, or a refusal.
    fn reject_transaction_request(
        &mut self,
        command: &WalletdDecisionCommandV1,
    ) -> Result<WalletdDecisionOutcomeV1, WalletdAnchorAdapterError>;

    /// Reads the current status of a stored request (status + recovery).
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on transport failure,
    /// unavailability, a malformed response, or an unknown request.
    fn get_transaction_request(
        &mut self,
        walletd_request_id: WalletdRequestId,
    ) -> Result<WalletdRequestStatusV1, WalletdAnchorAdapterError>;

    /// Seals and submits a previously approved, frozen request.
    ///
    /// The confirmed walletd path claims the request (`Approved -> Submitting`),
    /// seals the frozen transaction verbatim, and returns the sealed transaction
    /// id. A real client forwards only `command.walletd_request_id()`.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on transport failure,
    /// unavailability, a submit timeout, a malformed response, an unknown request,
    /// a request that is not approved, or a request already submitted.
    fn submit_transaction_request(
        &mut self,
        command: &WalletdSubmitCommandV1,
    ) -> Result<WalletdSubmitOutcomeV1, WalletdAnchorAdapterError>;
}
