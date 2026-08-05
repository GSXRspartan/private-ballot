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

/// Project view of a stored request's status (optional read boundary).
///
/// Mirrors the confirmed `TransactionRequestGetResponse`, narrowed to the fields
/// this slice cares about. `has_transaction_id` is always false before submit;
/// observing it true during preparation or approval is an unexpected state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WalletdRequestStatusV1 {
    walletd_request_id: WalletdRequestId,
    status: WalletdEffectiveStatusV1,
    has_transaction_id: bool,
}

impl WalletdRequestStatusV1 {
    /// Builds a status view from the confirmed fields.
    #[must_use]
    pub const fn new(
        walletd_request_id: WalletdRequestId,
        status: WalletdEffectiveStatusV1,
        has_transaction_id: bool,
    ) -> Self {
        Self {
            walletd_request_id,
            status,
            has_transaction_id,
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

    /// Returns whether walletd has recorded a sealed transaction identifier.
    #[must_use]
    pub const fn has_transaction_id(&self) -> bool {
        self.has_transaction_id
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

    /// Reads the current status of a stored request (optional).
    ///
    /// # Errors
    ///
    /// Returns a bounded [`WalletdAnchorAdapterError`] on transport failure,
    /// unavailability, a malformed response, or an unknown request.
    fn get_transaction_request(
        &mut self,
        walletd_request_id: WalletdRequestId,
    ) -> Result<WalletdRequestStatusV1, WalletdAnchorAdapterError>;
}
