//! Real walletd client adapter (Section B).
//!
//! [`WalletdAnchorNetworkAdapter`] implements the narrow
//! [`WalletdAnchorClient`](tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorClient)
//! trait by forwarding project-owned commands to the confirmed
//! [`WalletDaemonClient`](tari_ootle_walletd_client::WalletDaemonClient) through
//! an injectable [`WalletdWireTransport`] seam. The adapter is transport only:
//! it consumes project-owned requests, converts them to pinned walletd wire
//! types, calls only the exact matching walletd methods, and converts responses
//! back into project-owned results. It preserves all request/network/account/
//! digest/payload/fee/fingerprint bindings and exposes no private key, mnemonic,
//! or signing API.
//!
//! # Fingerprint recovery
//!
//! The [`WalletdAnchorClient::get_transaction_request`] method returns an
//! `observed_fingerprint` that the 4A6 coordinator checks against the frozen
//! binding. The fingerprint is a domain-separated BLAKE3 digest of the unsigned
//! transaction's canonical CBOR encoding, computed by the 4A5 inspector. The
//! adapter keeps the same-process cache from creation time as a fast path, and
//! after a restart recomputes the fingerprint from walletd's returned frozen
//! unsigned transaction instead of skipping the comparison.

use std::collections::BTreeMap;

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;
use tari_cc_private_ballot_ootle_anchor_adapter::{
    OotleAnchorBuildResultV1, OotleAnchorInspectionFingerprintV1,
    fingerprint_unsigned_anchor_transaction,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    WalletdAnchorClient, WalletdCreateAnchorRequestV1, WalletdCreateOutcomeV1,
    WalletdDecisionCommandV1, WalletdDecisionOutcomeV1, WalletdEffectiveStatusV1, WalletdRequestId,
    WalletdRequestStatusV1, WalletdSubmitCommandV1, WalletdSubmitOutcomeV1,
    canonicalize_transaction_id,
};
use tari_ootle_transaction::{Network, TransactionBuilder, TransactionId, UnsignedTransaction};
use tari_ootle_wallet_sdk::models::{KeyBranch, KeyId};
use tari_ootle_walletd_client::WalletDaemonClient;
pub use tari_ootle_walletd_client::WalletDaemonClient as PinnedWalletDaemonClient;
pub use tari_ootle_walletd_client::error::WalletDaemonClientError as PinnedWalletDaemonClientError;
pub use tari_ootle_walletd_client::types::{
    AccountInfo, AccountsListRequest, AccountsListResponse, TransactionDetectInputsRequest,
    TransactionDetectInputsResponse, TransactionRequestCreateRequest,
    TransactionRequestCreateResponse, TransactionRequestDecisionRequest,
    TransactionRequestDecisionResponse, TransactionRequestGetRequest,
    TransactionRequestGetResponse, TransactionRequestInfo, TransactionRequestListRequest,
    TransactionRequestListResponse, TransactionRequestSubmitRequest,
    TransactionRequestSubmitResponse, TransactionSubmitDryRunRequest, WalletGetInfoRequest,
    WalletGetInfoResponse,
};
use tari_template_lib_types::ComponentAddress;

use crate::auth::WalletdAuthSecret;
use crate::endpoint::{WalletdEndpoint, ensure_walletd_jsonrpc_path};
use crate::error::{TransportError, TransportErrorCategory};
use crate::executor::{BlockingExecutor, BlockingExecutorError};

/// Synchronous, injectable walletd wire-transport seam.
///
/// The real implementation wraps [`WalletDaemonClient`] and bridges async to
/// sync through a [`BlockingExecutor`]. The test implementation is fully
/// scripted and opens no socket.
pub trait WalletdWireTransport {
    /// Resolves the frozen transaction's dependency inputs without submitting
    /// it. The returned transaction is re-inspected before CREATE.
    fn detect_transaction_inputs(
        &mut self,
        request: &TransactionDetectInputsRequest,
    ) -> Result<TransactionDetectInputsResponse, TransportError>;

    /// Executes an unsigned transaction as a walletd dry run and returns the
    /// minimum fee walletd reports. This does not commit or create a wallet
    /// approval request.
    fn submit_transaction_dry_run_fee(
        &mut self,
        request: &TransactionSubmitDryRunRequest,
    ) -> Result<u64, TransportError>;

    /// Creates a frozen transaction request.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] on transport failure, unavailability,
    /// a malformed response, or a creation rejection.
    fn create_transaction_request(
        &mut self,
        request: &TransactionRequestCreateRequest,
    ) -> Result<TransactionRequestCreateResponse, TransportError>;

    /// Approves a stored request.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] on transport failure, unavailability,
    /// a malformed response, an unknown request, or a refusal.
    fn approve_transaction_request(
        &mut self,
        request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError>;

    /// Rejects a stored request.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] on transport failure, unavailability,
    /// a malformed response, an unknown request, or a refusal.
    fn reject_transaction_request(
        &mut self,
        request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError>;

    /// Reads the current status of a stored request.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] on transport failure, unavailability,
    /// a malformed response, or an unknown request.
    fn get_transaction_request(
        &mut self,
        request: &TransactionRequestGetRequest,
    ) -> Result<TransactionRequestGetResponse, TransportError>;

    /// Seals and submits an approved request.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] on transport failure, unavailability,
    /// a submit timeout, a malformed response, an unknown request, or a request
    /// that is not approved.
    fn submit_transaction_request(
        &mut self,
        request: &TransactionRequestSubmitRequest,
    ) -> Result<TransactionRequestSubmitResponse, TransportError>;
}

/// Real walletd transport wrapping the pinned [`WalletDaemonClient`].
///
/// The constructor is synchronous and opens no connection: it builds a
/// `reqwest::Client` (lazy connection pool) and stores the parsed endpoint URL.
/// The async client methods are bridged to the synchronous
/// [`WalletdWireTransport`] trait through a caller-provided
/// [`BlockingExecutor`].
pub struct RealWalletdTransport<E: BlockingExecutor> {
    client: WalletDaemonClient,
    executor: E,
    request_timeout: Option<core::time::Duration>,
}

impl<E: BlockingExecutor> RealWalletdTransport<E> {
    /// Constructs a real walletd transport.
    ///
    /// The `endpoint` is the operator-configured walletd base URL. It is
    /// normalized to the walletd JSON-RPC route (`/json_rpc`) via
    /// [`ensure_walletd_jsonrpc_path`] before the client connects, so the stored
    /// or displayed config may be a bare `http://127.0.0.1:5100` while every RPC
    /// (Prepare and publish) reaches `.../json_rpc`. The optional `auth` is a
    /// bearer JWT or API key. The optional `request_timeout` bounds every
    /// walletd request at the real network boundary; when `None` the request is
    /// unbounded. The `executor` is provided by the application (e.g. a tokio
    /// `Handle` wrapper). No network connection is opened.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] if the pinned client cannot be
    /// constructed (malformed endpoint URL).
    pub fn new(
        endpoint: &WalletdEndpoint,
        auth: Option<&WalletdAuthSecret>,
        request_timeout: Option<core::time::Duration>,
        executor: E,
    ) -> Result<Self, TransportError> {
        let token = auth.map(WalletdAuthSecret::as_jwt_string);
        let rpc_url = ensure_walletd_jsonrpc_path(endpoint.as_str());
        let client = WalletDaemonClient::connect(&rpc_url, token)
            .map_err(|_error| TransportError::from_category(TransportErrorCategory::Unknown))?;
        Ok(Self {
            client,
            executor,
            request_timeout,
        })
    }

    /// The fully-qualified walletd JSON-RPC URL this transport connects to.
    /// Always normalized to the `/json_rpc` route, regardless of whether the
    /// configured endpoint included the path.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        self.client.endpoint().as_str()
    }
}

/// Maps a bounded-executor outcome into a transport result. An elapsed deadline
/// becomes [`TransportErrorCategory::Timeout`] (state unknown → recover, never
/// blind-resubmit); any other executor failure is `ExecutorUnavailable`.
fn resolve_executor_outcome<T>(
    outcome: Result<
        Result<T, tari_ootle_walletd_client::error::WalletDaemonClientError>,
        BlockingExecutorError,
    >,
) -> Result<T, TransportError> {
    match outcome {
        Ok(result) => result.map_err(|e| TransportError::from_walletd_client(&e)),
        Err(BlockingExecutorError::Elapsed) => Err(TransportError::from_category(
            TransportErrorCategory::Timeout,
        )),
        Err(_) => Err(TransportError::from_category(
            TransportErrorCategory::ExecutorUnavailable,
        )),
    }
}

impl<E: BlockingExecutor> WalletdWireTransport for RealWalletdTransport<E> {
    fn detect_transaction_inputs(
        &mut self,
        request: &TransactionDetectInputsRequest,
    ) -> Result<TransactionDetectInputsResponse, TransportError> {
        let future = self.client.detect_transaction_inputs(request);
        resolve_executor_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }

    fn submit_transaction_dry_run_fee(
        &mut self,
        request: &TransactionSubmitDryRunRequest,
    ) -> Result<u64, TransportError> {
        let future = self.client.submit_transaction_dry_run(request);
        resolve_executor_outcome(self.executor.block_on_bounded(future, self.request_timeout))
            .map(|response| response.required_fees)
    }

    fn create_transaction_request(
        &mut self,
        request: &TransactionRequestCreateRequest,
    ) -> Result<TransactionRequestCreateResponse, TransportError> {
        let future = self.client.create_transaction_request(request);
        resolve_executor_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }

    fn approve_transaction_request(
        &mut self,
        request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError> {
        let future = self.client.approve_transaction_request(request);
        resolve_executor_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }

    fn reject_transaction_request(
        &mut self,
        request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError> {
        let future = self.client.reject_transaction_request(request);
        resolve_executor_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }

    fn get_transaction_request(
        &mut self,
        request: &TransactionRequestGetRequest,
    ) -> Result<TransactionRequestGetResponse, TransportError> {
        let future = self.client.get_transaction_request(request);
        resolve_executor_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }

    fn submit_transaction_request(
        &mut self,
        request: &TransactionRequestSubmitRequest,
    ) -> Result<TransactionRequestSubmitResponse, TransportError> {
        let future = self.client.submit_transaction_request(request);
        resolve_executor_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }
}

/// Scripted walletd response for the offline test harness.
///
/// Carries project-owned types only; the [`ScriptedWalletdTransport`] converts
/// them to pinned wire types internally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedWalletdResponse {
    /// A successful create response.
    Create {
        /// The opaque walletd request identifier.
        request_id: i32,
        /// The approval-window expiry (unix seconds).
        expires_at: i64,
    },
    /// A transport error for create.
    CreateError(TransportError),
    /// A successful approve response.
    Approve {
        request_id: i32,
        status: WalletdEffectiveStatusV1,
    },
    /// A transport error for approve.
    ApproveError(TransportError),
    /// A successful reject response.
    Reject {
        request_id: i32,
        status: WalletdEffectiveStatusV1,
    },
    /// A transport error for reject.
    RejectError(TransportError),
    /// A successful status lookup.
    Get {
        request_id: i32,
        status: WalletdEffectiveStatusV1,
        transaction_id: Option<AnchorTransactionId>,
    },
    /// A transport error for status lookup.
    GetError(TransportError),
    /// A successful dry-run fee estimate.
    DryRun { required_fees: u64 },
    /// A transport error for dry-run fee estimation.
    DryRunError(TransportError),
    /// A successful submit response.
    Submit { transaction_id: AnchorTransactionId },
    /// A transport error for submit.
    SubmitError(TransportError),
}

/// Converts a project-owned effective status to the pinned wire status.
fn status_to_wire(
    status: WalletdEffectiveStatusV1,
) -> tari_ootle_wallet_sdk::models::EffectiveStatus {
    use tari_ootle_wallet_sdk::models::EffectiveStatus;
    match status {
        WalletdEffectiveStatusV1::Pending => EffectiveStatus::Pending,
        WalletdEffectiveStatusV1::Approved => EffectiveStatus::Approved,
        WalletdEffectiveStatusV1::Rejected => EffectiveStatus::Rejected,
        WalletdEffectiveStatusV1::Submitting => EffectiveStatus::Submitting,
        WalletdEffectiveStatusV1::Submitted => EffectiveStatus::Submitted,
        WalletdEffectiveStatusV1::Expired => EffectiveStatus::Expired,
    }
}

/// Constructs a minimal `UnsignedTransaction` for the scripted transport.
///
/// The adapter never reads the `transaction` field from a `get` response (it
/// only reads `request_id`, `status`, and `transaction_id`), so a minimal
/// empty transaction suffices.
fn minimal_unsigned_transaction() -> UnsignedTransaction {
    TransactionBuilder::new(Network::LocalNet, 1_u64.into()).build_unsigned()
}

/// Constructs a `TransactionRequestInfo` from scripted fields.
fn scripted_request_info(
    request_id: i32,
    status: WalletdEffectiveStatusV1,
    transaction_id: Option<TransactionId>,
    transaction: UnsignedTransaction,
) -> TransactionRequestInfo {
    TransactionRequestInfo {
        request_id,
        transaction,
        seal_signer: KeyId::derived(KeyBranch::Account, 0),
        other_signers: Vec::new(),
        requested_by: None,
        status: status_to_wire(status),
        transaction_id,
        value_summary: None,
        expires_at: 0,
        approved_at: None,
        created_at: 0,
    }
}

/// Deterministic, offline scripted walletd transport for the test harness.
///
/// Each method returns the scripted response (or error) and captures the
/// request for endpoint-shape validation. No socket is opened.
#[derive(Debug, Clone)]
pub struct ScriptedWalletdTransport {
    detected_transaction: Option<UnsignedTransaction>,
    captured_detect: Option<TransactionDetectInputsRequest>,
    create_response: ScriptedWalletdResponse,
    approve_response: ScriptedWalletdResponse,
    reject_response: ScriptedWalletdResponse,
    get_response: ScriptedWalletdResponse,
    dry_run_response: ScriptedWalletdResponse,
    submit_response: ScriptedWalletdResponse,
    captured_create: Option<TransactionRequestCreateRequest>,
    captured_approve: Option<TransactionRequestDecisionRequest>,
    captured_reject: Option<TransactionRequestDecisionRequest>,
    captured_get: Option<TransactionRequestGetRequest>,
    captured_dry_run: Option<TransactionSubmitDryRunRequest>,
    captured_submit: Option<TransactionRequestSubmitRequest>,
    get_transaction: Option<UnsignedTransaction>,
    create_calls: u64,
    approve_calls: u64,
    reject_calls: u64,
    get_calls: u64,
    dry_run_calls: u64,
    submit_calls: u64,
    detect_calls: u64,
}

impl Default for ScriptedWalletdTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedWalletdTransport {
    /// Creates a new scripted transport with default not-found responses.
    #[must_use]
    pub fn new() -> Self {
        Self {
            create_response: ScriptedWalletdResponse::CreateError(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            approve_response: ScriptedWalletdResponse::ApproveError(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            reject_response: ScriptedWalletdResponse::RejectError(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            get_response: ScriptedWalletdResponse::GetError(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            dry_run_response: ScriptedWalletdResponse::DryRunError(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            submit_response: ScriptedWalletdResponse::SubmitError(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            detected_transaction: None,
            captured_detect: None,
            captured_create: None,
            captured_approve: None,
            captured_reject: None,
            captured_get: None,
            captured_dry_run: None,
            captured_submit: None,
            get_transaction: None,
            create_calls: 0,
            approve_calls: 0,
            reject_calls: 0,
            get_calls: 0,
            dry_run_calls: 0,
            submit_calls: 0,
            detect_calls: 0,
        }
    }

    /// Sets the scripted response for `create_transaction_request`.
    pub fn set_create_response(&mut self, response: ScriptedWalletdResponse) {
        self.create_response = response;
    }

    /// Sets the scripted response for `approve_transaction_request`.
    pub fn set_approve_response(&mut self, response: ScriptedWalletdResponse) {
        self.approve_response = response;
    }

    /// Sets the scripted response for `reject_transaction_request`.
    pub fn set_reject_response(&mut self, response: ScriptedWalletdResponse) {
        self.reject_response = response;
    }

    /// Sets the scripted response for `get_transaction_request`.
    pub fn set_get_response(&mut self, response: ScriptedWalletdResponse) {
        self.get_response = response;
    }

    /// Sets the scripted response for `submit_transaction_dry_run`.
    pub fn set_dry_run_response(&mut self, response: ScriptedWalletdResponse) {
        self.dry_run_response = response;
    }

    /// Sets the scripted response for `submit_transaction_request`.
    pub fn set_submit_response(&mut self, response: ScriptedWalletdResponse) {
        self.submit_response = response;
    }

    /// Sets the frozen transaction returned by scripted status lookups.
    pub fn set_get_transaction(&mut self, transaction: UnsignedTransaction) {
        self.get_transaction = Some(transaction);
    }

    /// Sets the exact transaction returned by the deterministic input-detect
    /// seam. If omitted, the request transaction is echoed unchanged.
    pub fn set_detected_transaction(&mut self, transaction: UnsignedTransaction) {
        self.detected_transaction = Some(transaction);
    }

    /// Returns the captured input-detection request, if one was sent.
    #[must_use]
    pub fn captured_detect(&self) -> Option<&TransactionDetectInputsRequest> {
        self.captured_detect.as_ref()
    }

    /// Returns the captured create request, if one was sent.
    #[must_use]
    pub fn captured_create(&self) -> Option<&TransactionRequestCreateRequest> {
        self.captured_create.as_ref()
    }

    /// Returns the captured approve request, if one was sent.
    #[must_use]
    pub fn captured_approve(&self) -> Option<&TransactionRequestDecisionRequest> {
        self.captured_approve.as_ref()
    }

    /// Returns the captured reject request, if one was sent.
    #[must_use]
    pub fn captured_reject(&self) -> Option<&TransactionRequestDecisionRequest> {
        self.captured_reject.as_ref()
    }

    /// Returns the captured get request, if one was sent.
    #[must_use]
    pub fn captured_get(&self) -> Option<&TransactionRequestGetRequest> {
        self.captured_get.as_ref()
    }

    /// Returns the captured dry-run request, if one was sent.
    #[must_use]
    pub fn captured_dry_run(&self) -> Option<&TransactionSubmitDryRunRequest> {
        self.captured_dry_run.as_ref()
    }

    /// Returns the captured submit request, if one was sent.
    #[must_use]
    pub fn captured_submit(&self) -> Option<&TransactionRequestSubmitRequest> {
        self.captured_submit.as_ref()
    }

    /// Returns the number of create calls.
    #[must_use]
    pub const fn create_calls(&self) -> u64 {
        self.create_calls
    }

    /// Returns the number of approve calls.
    #[must_use]
    pub const fn approve_calls(&self) -> u64 {
        self.approve_calls
    }

    /// Returns the number of reject calls.
    #[must_use]
    pub const fn reject_calls(&self) -> u64 {
        self.reject_calls
    }

    /// Returns the number of get calls.
    #[must_use]
    pub const fn get_calls(&self) -> u64 {
        self.get_calls
    }

    /// Returns the number of dry-run calls.
    #[must_use]
    pub const fn dry_run_calls(&self) -> u64 {
        self.dry_run_calls
    }

    /// Returns the number of submit calls.
    #[must_use]
    pub const fn submit_calls(&self) -> u64 {
        self.submit_calls
    }

    /// Returns the number of input-detection calls.
    #[must_use]
    pub const fn detect_calls(&self) -> u64 {
        self.detect_calls
    }
}

/// Converts a project-owned `AnchorTransactionId` to a pinned `TransactionId`.
fn transaction_id_to_wire(id: &AnchorTransactionId) -> TransactionId {
    match tari_cc_private_ballot_ootle_receipt_anchor_adapter::transaction_id_to_ootle(id) {
        Ok(ootle_id) => ootle_id,
        Err(_error) => TransactionId::new([0; 32]),
    }
}

impl WalletdWireTransport for ScriptedWalletdTransport {
    fn detect_transaction_inputs(
        &mut self,
        request: &TransactionDetectInputsRequest,
    ) -> Result<TransactionDetectInputsResponse, TransportError> {
        self.detect_calls += 1;
        self.captured_detect = Some(request.clone());
        Ok(TransactionDetectInputsResponse {
            transaction: self
                .detected_transaction
                .clone()
                .unwrap_or_else(|| request.transaction.clone()),
        })
    }

    fn submit_transaction_dry_run_fee(
        &mut self,
        request: &TransactionSubmitDryRunRequest,
    ) -> Result<u64, TransportError> {
        self.dry_run_calls += 1;
        self.captured_dry_run = Some(request.clone());
        match &self.dry_run_response {
            ScriptedWalletdResponse::DryRun { required_fees } => Ok(*required_fees),
            ScriptedWalletdResponse::DryRunError(error) => Err(error.clone()),
            _ => Err(TransportError::from_category(
                TransportErrorCategory::MalformedResponse,
            )),
        }
    }

    fn create_transaction_request(
        &mut self,
        request: &TransactionRequestCreateRequest,
    ) -> Result<TransactionRequestCreateResponse, TransportError> {
        self.create_calls += 1;
        self.captured_create = Some(request.clone());
        match &self.create_response {
            ScriptedWalletdResponse::Create {
                request_id,
                expires_at,
            } => Ok(TransactionRequestCreateResponse {
                request_id: *request_id,
                expires_at: *expires_at,
            }),
            ScriptedWalletdResponse::CreateError(error) => Err(error.clone()),
            _ => Err(TransportError::from_category(
                TransportErrorCategory::MalformedResponse,
            )),
        }
    }

    fn approve_transaction_request(
        &mut self,
        request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError> {
        self.approve_calls += 1;
        self.captured_approve = Some(request.clone());
        match &self.approve_response {
            ScriptedWalletdResponse::Approve { request_id, status } => {
                Ok(TransactionRequestDecisionResponse {
                    request_id: *request_id,
                    status: status_to_wire(*status),
                })
            }
            ScriptedWalletdResponse::ApproveError(error) => Err(error.clone()),
            _ => Err(TransportError::from_category(
                TransportErrorCategory::MalformedResponse,
            )),
        }
    }

    fn reject_transaction_request(
        &mut self,
        request: &TransactionRequestDecisionRequest,
    ) -> Result<TransactionRequestDecisionResponse, TransportError> {
        self.reject_calls += 1;
        self.captured_reject = Some(request.clone());
        match &self.reject_response {
            ScriptedWalletdResponse::Reject { request_id, status } => {
                Ok(TransactionRequestDecisionResponse {
                    request_id: *request_id,
                    status: status_to_wire(*status),
                })
            }
            ScriptedWalletdResponse::RejectError(error) => Err(error.clone()),
            _ => Err(TransportError::from_category(
                TransportErrorCategory::MalformedResponse,
            )),
        }
    }

    fn get_transaction_request(
        &mut self,
        request: &TransactionRequestGetRequest,
    ) -> Result<TransactionRequestGetResponse, TransportError> {
        self.get_calls += 1;
        self.captured_get = Some(request.clone());
        match &self.get_response {
            ScriptedWalletdResponse::Get {
                request_id,
                status,
                transaction_id,
            } => {
                let wire_tx_id = transaction_id.as_ref().map(transaction_id_to_wire);
                let transaction = self
                    .get_transaction
                    .clone()
                    .or_else(|| self.captured_create.as_ref().map(|r| r.transaction.clone()))
                    .unwrap_or_else(minimal_unsigned_transaction);
                Ok(TransactionRequestGetResponse {
                    request: scripted_request_info(*request_id, *status, wire_tx_id, transaction),
                })
            }
            ScriptedWalletdResponse::GetError(error) => Err(error.clone()),
            _ => Err(TransportError::from_category(
                TransportErrorCategory::MalformedResponse,
            )),
        }
    }

    fn submit_transaction_request(
        &mut self,
        request: &TransactionRequestSubmitRequest,
    ) -> Result<TransactionRequestSubmitResponse, TransportError> {
        self.submit_calls += 1;
        self.captured_submit = Some(request.clone());
        match &self.submit_response {
            ScriptedWalletdResponse::Submit { transaction_id } => {
                Ok(TransactionRequestSubmitResponse {
                    transaction_id: transaction_id_to_wire(transaction_id),
                })
            }
            ScriptedWalletdResponse::SubmitError(error) => Err(error.clone()),
            _ => Err(TransportError::from_category(
                TransportErrorCategory::MalformedResponse,
            )),
        }
    }
}

/// Real walletd anchor network adapter implementing
/// [`WalletdAnchorClient`].
///
/// The adapter is generic over a [`WalletdWireTransport`], so the real transport
/// (wrapping `WalletDaemonClient`) and the scripted transport (for offline
/// tests) are interchangeable. It caches the inspection fingerprint at creation
/// time for later `get_transaction_request` calls.
pub struct WalletdAnchorNetworkAdapter<T: WalletdWireTransport> {
    transport: T,
    network: OotleNetworkIdV1,
    fingerprint_cache: BTreeMap<i32, OotleAnchorInspectionFingerprintV1>,
}

impl<T: WalletdWireTransport> WalletdAnchorNetworkAdapter<T> {
    /// Creates a new walletd network adapter bound to the given network.
    ///
    /// The `network` is the explicit project-bound Ootle network; it must agree
    /// with every operation's binding network. The endpoint URL never determines
    /// the network.
    #[must_use]
    pub fn new(transport: T, network: OotleNetworkIdV1) -> Self {
        Self {
            transport,
            network,
            fingerprint_cache: BTreeMap::new(),
        }
    }

    /// Returns a reference to the inner transport.
    #[must_use]
    pub fn transport(&self) -> &T {
        &self.transport
    }

    /// Returns a mutable reference to the inner transport.
    pub fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    /// Returns the bound network.
    #[must_use]
    pub fn network(&self) -> &OotleNetworkIdV1 {
        &self.network
    }

    /// Ensures the binding network matches the adapter's configured network.
    fn ensure_network_matches(
        &self,
        binding_network: &OotleNetworkIdV1,
    ) -> Result<(), tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError>
    {
        use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError;
        if binding_network != &self.network {
            return Err(WalletdAnchorAdapterError::NetworkMismatch);
        }
        Ok(())
    }

    /// Maps a [`TransportError`] to a [`WalletdAnchorAdapterError`].
    fn map_transport_error(
        error: TransportError,
    ) -> tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError {
        use tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError;
        match error.category() {
            TransportErrorCategory::ConnectionRefused | TransportErrorCategory::Unknown => {
                WalletdAnchorAdapterError::WalletdUnavailable
            }
            TransportErrorCategory::Timeout => WalletdAnchorAdapterError::SubmitTimeout,
            TransportErrorCategory::AuthenticationFailure => {
                WalletdAnchorAdapterError::ApprovalRejected
            }
            TransportErrorCategory::HttpStatusError => WalletdAnchorAdapterError::TransportFailure,
            TransportErrorCategory::MalformedResponse => {
                WalletdAnchorAdapterError::MalformedResponse
            }
            TransportErrorCategory::UnsupportedApi => {
                WalletdAnchorAdapterError::UnsupportedWalletdApi {
                    detail: "transport reported unsupported API",
                }
            }
            TransportErrorCategory::NotFound => WalletdAnchorAdapterError::RequestNotFound,
            TransportErrorCategory::ServiceUnavailable => {
                WalletdAnchorAdapterError::WalletdUnavailable
            }
            TransportErrorCategory::TlsFailure => WalletdAnchorAdapterError::TransportFailure,
            TransportErrorCategory::ExecutorUnavailable => {
                WalletdAnchorAdapterError::WalletdUnavailable
            }
            TransportErrorCategory::InsufficientFeesPaid => {
                match error.insufficient_fee_details() {
                    Some((paid, required)) => {
                        WalletdAnchorAdapterError::InsufficientFeesPaid { paid, required }
                    }
                    None => WalletdAnchorAdapterError::TransportFailure,
                }
            }
        }
    }

    /// Obtains walletd's declared input closure and accepts it only after the
    /// exact v0.39.2 function/fee/network/max-epoch inspection succeeds.
    ///
    /// This happens before durable CREATE intent and before walletd's create
    /// endpoint, so an altered response cannot be approved or submitted.
    pub fn detect_anchor_inputs(
        &mut self,
        build_result: &OotleAnchorBuildResultV1,
        fee_component: ComponentAddress,
    ) -> Result<
        OotleAnchorBuildResultV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        self.ensure_network_matches(build_result.walletd_preparation().network())?;
        let request = TransactionDetectInputsRequest {
            transaction: build_result.unsigned_transaction().clone(),
            use_unversioned: true,
        };
        let response = self
            .transport
            .detect_transaction_inputs(&request)
            .map_err(Self::map_transport_error)?;
        build_result
            .with_detected_fee_inputs(response.transaction, fee_component)
            .map_err(
                tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError::UnsafeUnsignedTransaction,
            )
    }

    /// Runs walletd input detection for the separately-versioned V2 anchor
    /// path. The caller must re-inspect the returned transaction with the V2
    /// ABI expectation before creating a request.
    pub fn detect_v2_anchor_inputs(
        &mut self,
        transaction: &UnsignedTransaction,
    ) -> Result<
        UnsignedTransaction,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let request = TransactionDetectInputsRequest {
            transaction: transaction.clone(),
            use_unversioned: true,
        };
        self.transport
            .detect_transaction_inputs(&request)
            .map(|response| response.transaction)
            .map_err(Self::map_transport_error)
    }

    /// Runs walletd's dry-run endpoint for the exact detected V2 transaction
    /// and returns the required fee that walletd computed. The caller rebuilds
    /// and re-detects a fresh transaction with the selected final fee before
    /// creating a human-approved request.
    pub fn estimate_v2_anchor_fee(
        &mut self,
        transaction: &UnsignedTransaction,
        seal_signer: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdSealSignerRef,
    ) -> Result<u64, tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError>
    {
        let wire = TransactionSubmitDryRunRequest {
            transaction: transaction.clone(),
            seal_signer: seal_signer.to_key_id(),
            other_signers: Vec::new(),
            signatures: Vec::new(),
            detect_inputs: false,
            detect_inputs_use_unversioned: true,
            lock_ids: Vec::new(),
        };
        self.transport
            .submit_transaction_dry_run_fee(&wire)
            .map_err(Self::map_transport_error)
    }

    /// Creates a frozen V2 request from an already V2-inspected transaction.
    /// This has no V1 binding or V1 payload fallback.
    pub fn create_v2_anchor_request(
        &mut self,
        transaction: &UnsignedTransaction,
        seal_signer: tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdSealSignerRef,
        ttl_secs: Option<u64>,
    ) -> Result<
        WalletdCreateOutcomeV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let wire = TransactionRequestCreateRequest {
            transaction: transaction.clone(),
            seal_signer: seal_signer.to_key_id(),
            other_signers: Vec::new(),
            signatures: Vec::new(),
            lock_ids: Vec::new(),
            ttl_secs,
        };
        let response = self
            .transport
            .create_transaction_request(&wire)
            .map_err(Self::map_transport_error)?;
        Ok(WalletdCreateOutcomeV1::new(
            WalletdRequestId::from_walletd(response.request_id),
            response.expires_at,
        ))
    }

    /// Explicitly approves the V2 request. It is never called as part of
    /// preparation, preserving the manual wallet approval gate.
    pub fn approve_v2_anchor_request(
        &mut self,
        walletd_request_id: WalletdRequestId,
    ) -> Result<
        WalletdDecisionOutcomeV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let response = self
            .transport
            .approve_transaction_request(&TransactionRequestDecisionRequest {
                request_id: walletd_request_id.value(),
            })
            .map_err(Self::map_transport_error)?;
        Ok(WalletdDecisionOutcomeV1::new(
            WalletdRequestId::from_walletd(response.request_id),
            WalletdEffectiveStatusV1::from_wire(response.status),
        ))
    }

    /// Reads the current walletd status of a V2 request without recomputing a
    /// V1 fingerprint or touching the V1 coordinator.
    ///
    /// The V2 lifecycle uses this only for crash recovery and duplicate-action
    /// prevention: before it approves it confirms the request is still
    /// `Pending`, and before it submits it confirms the request has not already
    /// advanced to `Submitting`/`Submitted` (in which case it adopts the sealed
    /// transaction id instead of resubmitting). Receipt authenticity is proved
    /// separately by the V2 receipt verifier against the locked deployment
    /// binding, so no fingerprint is returned here.
    pub fn get_v2_anchor_request_status(
        &mut self,
        walletd_request_id: WalletdRequestId,
    ) -> Result<
        (WalletdEffectiveStatusV1, Option<AnchorTransactionId>),
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let response = self
            .transport
            .get_transaction_request(&TransactionRequestGetRequest {
                request_id: walletd_request_id.value(),
            })
            .map_err(Self::map_transport_error)?;
        let info = response.request;
        let transaction_id = info
            .transaction_id
            .map(|id| canonicalize_transaction_id(&id));
        Ok((
            WalletdEffectiveStatusV1::from_wire(info.status),
            transaction_id,
        ))
    }

    /// Submits an explicitly approved V2 request and returns only walletd's
    /// sealed transaction identifier.
    pub fn submit_v2_anchor_request(
        &mut self,
        walletd_request_id: WalletdRequestId,
    ) -> Result<
        WalletdSubmitOutcomeV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let response = self
            .transport
            .submit_transaction_request(&TransactionRequestSubmitRequest {
                request_id: walletd_request_id.value(),
            })
            .map_err(Self::map_transport_error)?;
        Ok(WalletdSubmitOutcomeV1::new(
            walletd_request_id,
            canonicalize_transaction_id(&response.transaction_id),
        ))
    }
}

impl<T: WalletdWireTransport> WalletdAnchorClient for WalletdAnchorNetworkAdapter<T> {
    fn create_transaction_request(
        &mut self,
        command: &WalletdCreateAnchorRequestV1,
    ) -> Result<
        WalletdCreateOutcomeV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        self.ensure_network_matches(command.binding().network())?;
        let wire = command.wire_request();
        let response = self
            .transport
            .create_transaction_request(wire)
            .map_err(Self::map_transport_error)?;
        let walletd_request_id = WalletdRequestId::from_walletd(response.request_id);
        self.fingerprint_cache
            .insert(response.request_id, command.fingerprint());
        Ok(WalletdCreateOutcomeV1::new(
            walletd_request_id,
            response.expires_at,
        ))
    }

    fn approve_transaction_request(
        &mut self,
        command: &WalletdDecisionCommandV1,
    ) -> Result<
        WalletdDecisionOutcomeV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let wire = TransactionRequestDecisionRequest {
            request_id: command.walletd_request_id().value(),
        };
        let response = self
            .transport
            .approve_transaction_request(&wire)
            .map_err(Self::map_transport_error)?;
        Ok(WalletdDecisionOutcomeV1::new(
            WalletdRequestId::from_walletd(response.request_id),
            WalletdEffectiveStatusV1::from_wire(response.status),
        ))
    }

    fn reject_transaction_request(
        &mut self,
        command: &WalletdDecisionCommandV1,
    ) -> Result<
        WalletdDecisionOutcomeV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let wire = TransactionRequestDecisionRequest {
            request_id: command.walletd_request_id().value(),
        };
        let response = self
            .transport
            .reject_transaction_request(&wire)
            .map_err(Self::map_transport_error)?;
        Ok(WalletdDecisionOutcomeV1::new(
            WalletdRequestId::from_walletd(response.request_id),
            WalletdEffectiveStatusV1::from_wire(response.status),
        ))
    }

    fn get_transaction_request(
        &mut self,
        walletd_request_id: WalletdRequestId,
    ) -> Result<
        WalletdRequestStatusV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let wire = TransactionRequestGetRequest {
            request_id: walletd_request_id.value(),
        };
        let response = self
            .transport
            .get_transaction_request(&wire)
            .map_err(Self::map_transport_error)?;
        let info = response.request;
        let transaction_id = info
            .transaction_id
            .map(|id| canonicalize_transaction_id(&id));
        let observed_fingerprint = match self.fingerprint_cache.get(&info.request_id).copied() {
            Some(fingerprint) => Some(fingerprint),
            None => Some(
                fingerprint_unsigned_anchor_transaction(&info.transaction).map_err(
                    tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError::UnsafeUnsignedTransaction,
                )?,
            ),
        };
        Ok(WalletdRequestStatusV1::new(
            WalletdRequestId::from_walletd(info.request_id),
            WalletdEffectiveStatusV1::from_wire(info.status),
            transaction_id,
            observed_fingerprint,
        ))
    }

    fn submit_transaction_request(
        &mut self,
        command: &WalletdSubmitCommandV1,
    ) -> Result<
        WalletdSubmitOutcomeV1,
        tari_cc_private_ballot_ootle_walletd_anchor_adapter::WalletdAnchorAdapterError,
    > {
        let wire = TransactionRequestSubmitRequest {
            request_id: command.walletd_request_id().value(),
        };
        let response = self
            .transport
            .submit_transaction_request(&wire)
            .map_err(Self::map_transport_error)?;
        let transaction_id = canonicalize_transaction_id(&response.transaction_id);
        Ok(WalletdSubmitOutcomeV1::new(
            command.walletd_request_id(),
            transaction_id,
        ))
    }
}

#[cfg(test)]
mod real_transport_endpoint_tests {
    use super::RealWalletdTransport;
    use crate::endpoint::WalletdEndpoint;
    use crate::executor::SimpleBlockingExecutor;

    fn transport(raw: &str) -> RealWalletdTransport<SimpleBlockingExecutor> {
        let endpoint = WalletdEndpoint::parse(raw).expect("valid loopback endpoint");
        RealWalletdTransport::new(&endpoint, None, None, SimpleBlockingExecutor)
            .expect("client constructs offline")
    }

    #[test]
    fn bare_config_endpoint_connects_to_jsonrpc_route() {
        // Prepare and publish both go through RealWalletdTransport, so this
        // proves the live path targets /json_rpc even when the stored config is
        // the bare web-UI base.
        assert!(
            transport("http://127.0.0.1:5100")
                .endpoint()
                .ends_with("/json_rpc")
        );
    }

    #[test]
    fn localhost_config_endpoint_connects_to_jsonrpc_route() {
        assert!(
            transport("http://localhost:5100")
                .endpoint()
                .ends_with("/json_rpc")
        );
    }

    #[test]
    fn already_jsonrpc_endpoint_is_not_doubled() {
        let ep = transport("http://127.0.0.1:5100/json_rpc")
            .endpoint()
            .to_owned();
        assert!(ep.ends_with("/json_rpc"), "{ep}");
        assert!(!ep.contains("/json_rpc/json_rpc"), "{ep}");
    }
}
