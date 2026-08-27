//! Real indexer receipt client adapter (Section D).
//!
//! [`IndexerReceiptNetworkAdapter`] implements the narrow
//! [`IndexerAnchorReceiptClient`](tari_cc_private_ballot_ootle_receipt_anchor_adapter::IndexerAnchorReceiptClient)
//! trait by forwarding project-owned receipt queries to the confirmed
//! [`IndexerRestApiClient`](tari_indexer_client::rest_api_client::IndexerRestApiClient)
//! through an injectable [`IndexerReceiptWireTransport`] seam. The adapter
//! composes the two confirmed indexer reads into a single
//! [`IndexerReceiptFetchV1`]:
//!
//! 1. `get_transaction_receipt(address)` — if the receipt exists, convert it
//!    via the 4A7 [`convert_receipt_response`] into an `AnchorReceiptV1` and
//!    return `Finalized(receipt)`.
//! 2. If the receipt is not found (404), `get_transaction_result(request)` —
//!    distinguishes `Pending` from `Rejected`/`Finalized{Abort}` from a total
//!    404 (`NotFound`).
//!
//! Neither the pinned receipt type nor the result type crosses the trait
//! boundary: the seam that names them is [`IndexerReceiptWireTransport`].

use tari_cc_private_ballot_anchor_transport::{
    AnchorFinalStatusV1, AnchorLogLevelV1, AnchorReceiptSourceKindV1, AnchorReceiptV1,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    IndexerAnchorReceiptClient, IndexerReceiptFetchV1, IndexerReceiptTransportError,
    convert_receipt_response, transaction_id_to_ootle,
};
use tari_consensus_types::Decision;
use tari_engine_types::Epoch;
use tari_engine_types::fees::FeeReceipt;
use tari_engine_types::logs::LogEntry;
use tari_engine_types::transaction_receipt::{DiffSummary, FinalizeOutcome, TransactionReceipt};
use tari_indexer_client::rest_api_client::IndexerRestApiClient;
use tari_indexer_client::types::{
    GetTransactionReceiptResponse, GetTransactionResultRequest, GetTransactionResultResponse,
    IndexerTransactionFinalizedResult,
};
use tari_template_lib_types::LogLevel;

use crate::endpoint::IndexerEndpoint;
use crate::error::{TransportError, TransportErrorCategory};
use crate::executor::{BlockingExecutor, BlockingExecutorError};

/// Maximum byte length of a copied rejection reason.
const MAX_REJECTION_REASON_BYTES: usize = 4096;

/// Synchronous, injectable indexer receipt wire-transport seam.
///
/// The real implementation wraps [`IndexerRestApiClient`]; the test
/// implementation is fully scripted and opens no socket.
pub trait IndexerReceiptWireTransport {
    /// Retrieves the persisted receipt substate for a transaction.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] on transport failure or
    /// unavailability. A 404 response is [`TransportError`] with category
    /// [`NotFound`](TransportErrorCategory::NotFound).
    fn get_transaction_receipt(
        &mut self,
        address: tari_template_lib_types::TransactionReceiptAddress,
    ) -> Result<GetTransactionReceiptResponse, TransportError>;

    /// Retrieves the transaction-result summary (pending, finalized, rejected).
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] on transport failure or
    /// unavailability. A 404 response is [`TransportError`] with category
    /// [`NotFound`](TransportErrorCategory::NotFound).
    fn get_transaction_result(
        &mut self,
        request: &GetTransactionResultRequest,
    ) -> Result<GetTransactionResultResponse, TransportError>;
}

/// Real indexer transport wrapping the pinned [`IndexerRestApiClient`].
///
/// The constructor is synchronous and opens no connection. The async client
/// methods are bridged to the synchronous
/// [`IndexerReceiptWireTransport`] trait through a caller-provided
/// [`BlockingExecutor`].
pub struct RealIndexerTransport<E: BlockingExecutor> {
    client: IndexerRestApiClient,
    executor: E,
    request_timeout: Option<core::time::Duration>,
}

impl<E: BlockingExecutor> RealIndexerTransport<E> {
    /// Constructs a real indexer transport.
    ///
    /// The optional `request_timeout` bounds every indexer request at the real
    /// network boundary; when `None` the request is unbounded. No network
    /// connection is opened.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`TransportError`] if the pinned client cannot be
    /// constructed (malformed endpoint URL).
    pub fn new(
        endpoint: &IndexerEndpoint,
        request_timeout: Option<core::time::Duration>,
        executor: E,
    ) -> Result<Self, TransportError> {
        let client = IndexerRestApiClient::connect(endpoint.as_str())
            .map_err(|_error| TransportError::from_category(TransportErrorCategory::Unknown))?;
        Ok(Self {
            client,
            executor,
            request_timeout,
        })
    }
}

/// Maps a bounded-executor outcome into an indexer transport result. An elapsed
/// deadline becomes [`TransportErrorCategory::Timeout`]; any other executor
/// failure is `ExecutorUnavailable`.
fn resolve_indexer_outcome<T>(
    outcome: Result<
        Result<T, tari_indexer_client::error::IndexerRestClientError>,
        BlockingExecutorError,
    >,
) -> Result<T, TransportError> {
    match outcome {
        Ok(result) => result.map_err(|e| TransportError::from_indexer_client(&e)),
        Err(BlockingExecutorError::Elapsed) => Err(TransportError::from_category(
            TransportErrorCategory::Timeout,
        )),
        Err(_) => Err(TransportError::from_category(
            TransportErrorCategory::ExecutorUnavailable,
        )),
    }
}

impl<E: BlockingExecutor> IndexerReceiptWireTransport for RealIndexerTransport<E> {
    fn get_transaction_receipt(
        &mut self,
        address: tari_template_lib_types::TransactionReceiptAddress,
    ) -> Result<GetTransactionReceiptResponse, TransportError> {
        let future = self.client.get_transaction_receipt(address);
        resolve_indexer_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }

    fn get_transaction_result(
        &mut self,
        request: &GetTransactionResultRequest,
    ) -> Result<GetTransactionResultResponse, TransportError> {
        let future = self.client.get_transaction_result(request.clone());
        resolve_indexer_outcome(self.executor.block_on_bounded(future, self.request_timeout))
    }
}

/// Scripted indexer response for the offline test harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptedIndexerResponse {
    /// A finalized receipt was retrieved (accepted or fee-only).
    Finalized(AnchorReceiptV1),
    /// The transaction was rejected (mempool or ledger rejection). The receipt
    /// does not exist; the result API reports `Rejected`.
    Rejected { reason: Option<String> },
    /// The transaction is known but not yet finalized.
    Pending,
    /// No record exists for the transaction.
    NotFound,
    /// A transport error.
    Error(TransportError),
}

/// Converts a project-owned log level to the pinned wire level.
fn log_level_to_wire(level: AnchorLogLevelV1) -> LogLevel {
    match level {
        AnchorLogLevelV1::Error => LogLevel::Error,
        AnchorLogLevelV1::Warn => LogLevel::Warn,
        AnchorLogLevelV1::Info => LogLevel::Info,
        AnchorLogLevelV1::Debug => LogLevel::Debug,
    }
}

/// Constructs a `TransactionReceipt` from a project-owned receipt for the
/// scripted transport.
fn build_transaction_receipt(receipt: &AnchorReceiptV1) -> TransactionReceipt {
    let outcome = match receipt.final_status() {
        AnchorFinalStatusV1::Accepted => FinalizeOutcome::Commit,
        AnchorFinalStatusV1::FeeOnlyAccepted => FinalizeOutcome::FeeIntentCommit,
        AnchorFinalStatusV1::Rejected => FinalizeOutcome::Commit,
    };
    let logs: Vec<LogEntry> = receipt
        .logs()
        .iter()
        .map(|entry| LogEntry::new(log_level_to_wire(entry.level()), entry.message().to_owned()))
        .collect();
    let epoch = receipt.ledger_position().unwrap_or(0);
    TransactionReceipt {
        outcome,
        diff_summary: DiffSummary::default(),
        fee_withdrawals: Box::default(),
        events: Box::default(),
        logs: logs.into_boxed_slice(),
        fee_receipt: FeeReceipt::default(),
        epoch: Epoch(epoch),
    }
}

/// Constructs a deterministic `PrimitiveDateTime` for the scripted transport.
fn fixed_primitive_datetime() -> time::PrimitiveDateTime {
    time::PrimitiveDateTime::new(
        time::Date::from_calendar_date(2026, time::Month::January, 1).unwrap_or(time::Date::MIN),
        time::Time::MIDNIGHT,
    )
}

/// Bounds a rejection reason to the maximum byte length, preserving UTF-8
/// boundaries.
fn bound_rejection_reason(reason: Option<String>) -> Option<String> {
    reason.filter(|r| !r.is_empty()).map(|r| {
        if r.len() <= MAX_REJECTION_REASON_BYTES {
            r
        } else {
            let mut truncated = String::new();
            for c in r.chars() {
                if truncated.len() + c.len_utf8() > MAX_REJECTION_REASON_BYTES {
                    break;
                }
                truncated.push(c);
            }
            truncated
        }
    })
}

/// Deterministic, offline scripted indexer transport for the test harness.
///
/// Stores a single [`ScriptedIndexerResponse`] and maps it to the two-step
/// receipt/result flow. No socket is opened.
#[derive(Debug, Clone)]
pub struct ScriptedIndexerTransport {
    response: ScriptedIndexerResponse,
    captured_receipt_address: Option<tari_template_lib_types::TransactionReceiptAddress>,
    captured_result_request: Option<GetTransactionResultRequest>,
    receipt_calls: u64,
    result_calls: u64,
}

impl Default for ScriptedIndexerTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedIndexerTransport {
    /// Creates a new scripted transport with a default `NotFound` response.
    #[must_use]
    pub fn new() -> Self {
        Self {
            response: ScriptedIndexerResponse::NotFound,
            captured_receipt_address: None,
            captured_result_request: None,
            receipt_calls: 0,
            result_calls: 0,
        }
    }

    /// Sets the scripted response.
    pub fn set_response(&mut self, response: ScriptedIndexerResponse) {
        self.response = response;
    }

    /// Returns the captured receipt-address, if one was sent.
    #[must_use]
    pub fn captured_receipt_address(
        &self,
    ) -> Option<&tari_template_lib_types::TransactionReceiptAddress> {
        self.captured_receipt_address.as_ref()
    }

    /// Returns the captured result-request, if one was sent.
    #[must_use]
    pub fn captured_result_request(&self) -> Option<&GetTransactionResultRequest> {
        self.captured_result_request.as_ref()
    }

    /// Returns the number of receipt-lookup calls.
    #[must_use]
    pub const fn receipt_calls(&self) -> u64 {
        self.receipt_calls
    }

    /// Returns the number of result-lookup calls.
    #[must_use]
    pub const fn result_calls(&self) -> u64 {
        self.result_calls
    }
}

impl IndexerReceiptWireTransport for ScriptedIndexerTransport {
    fn get_transaction_receipt(
        &mut self,
        address: tari_template_lib_types::TransactionReceiptAddress,
    ) -> Result<GetTransactionReceiptResponse, TransportError> {
        self.receipt_calls += 1;
        self.captured_receipt_address = Some(address);
        match &self.response {
            ScriptedIndexerResponse::Finalized(receipt) => Ok(GetTransactionReceiptResponse {
                receipt: build_transaction_receipt(receipt),
            }),
            ScriptedIndexerResponse::Rejected { .. }
            | ScriptedIndexerResponse::Pending
            | ScriptedIndexerResponse::NotFound => Err(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            ScriptedIndexerResponse::Error(error) => Err(error.clone()),
        }
    }

    fn get_transaction_result(
        &mut self,
        request: &GetTransactionResultRequest,
    ) -> Result<GetTransactionResultResponse, TransportError> {
        self.result_calls += 1;
        self.captured_result_request = Some(request.clone());
        match &self.response {
            ScriptedIndexerResponse::Rejected { reason } => Ok(GetTransactionResultResponse {
                result: IndexerTransactionFinalizedResult::Rejected {
                    details: bound_rejection_reason(reason.clone()).unwrap_or_default(),
                    rejected_time: fixed_primitive_datetime(),
                },
            }),
            ScriptedIndexerResponse::Pending => Ok(GetTransactionResultResponse {
                result: IndexerTransactionFinalizedResult::Pending,
            }),
            ScriptedIndexerResponse::NotFound => Err(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            ScriptedIndexerResponse::Finalized(_) => Err(TransportError::from_category(
                TransportErrorCategory::NotFound,
            )),
            ScriptedIndexerResponse::Error(error) => Err(error.clone()),
        }
    }
}

/// Maps a [`TransportError`] to an [`IndexerReceiptTransportError`].
fn map_transport_error(error: TransportError) -> IndexerReceiptTransportError {
    match error.category() {
        TransportErrorCategory::ConnectionRefused
        | TransportErrorCategory::ServiceUnavailable
        | TransportErrorCategory::Unknown
        | TransportErrorCategory::ExecutorUnavailable
        | TransportErrorCategory::TlsFailure
        | TransportErrorCategory::AuthenticationFailure
        | TransportErrorCategory::HttpStatusError => IndexerReceiptTransportError::Unavailable,
        TransportErrorCategory::Timeout => IndexerReceiptTransportError::Timeout,
        TransportErrorCategory::MalformedResponse => {
            IndexerReceiptTransportError::MalformedResponse
        }
        TransportErrorCategory::UnsupportedApi => IndexerReceiptTransportError::UnsupportedApi,
        TransportErrorCategory::NotFound => IndexerReceiptTransportError::Unavailable,
    }
}

/// Real indexer receipt network adapter implementing
/// [`IndexerAnchorReceiptClient`].
///
/// The adapter is generic over an [`IndexerReceiptWireTransport`], so the real
/// transport (wrapping `IndexerRestApiClient`) and the scripted transport (for
/// offline tests) are interchangeable.
pub struct IndexerReceiptNetworkAdapter<T: IndexerReceiptWireTransport> {
    transport: T,
}

impl<T: IndexerReceiptWireTransport> IndexerReceiptNetworkAdapter<T> {
    /// Creates a new indexer receipt network adapter.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self { transport }
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

    /// Constructs a rejected `AnchorReceiptV1` from a transaction-result
    /// `Rejected` or `Finalized{Abort}` variant.
    fn build_rejected_receipt(
        query: &tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryV1,
        reason: Option<String>,
    ) -> AnchorReceiptV1 {
        AnchorReceiptV1::new(
            query.transaction_id().clone(),
            query.network().clone(),
            AnchorFinalStatusV1::Rejected,
            Vec::new(),
            bound_rejection_reason(reason),
            None,
            AnchorReceiptSourceKindV1::IndependentIndexer,
        )
    }
}

impl<T: IndexerReceiptWireTransport> IndexerAnchorReceiptClient
    for IndexerReceiptNetworkAdapter<T>
{
    fn fetch_anchor_receipt(
        &mut self,
        query: &tari_cc_private_ballot_ootle_receipt_anchor_adapter::AnchorReceiptQueryV1,
    ) -> Result<IndexerReceiptFetchV1, IndexerReceiptTransportError> {
        let ootle_id = transaction_id_to_ootle(query.transaction_id())
            .map_err(|_error| IndexerReceiptTransportError::MalformedResponse)?;
        let receipt_address = ootle_id.into_receipt_address();

        match self.transport.get_transaction_receipt(receipt_address) {
            Ok(response) => {
                let receipt =
                    convert_receipt_response(&response, query.transaction_id(), query.network())
                        .map_err(|_error| IndexerReceiptTransportError::MalformedResponse)?;
                Ok(IndexerReceiptFetchV1::Finalized(receipt))
            }
            Err(error) if error.is_not_found() => {
                let result_request = GetTransactionResultRequest {
                    transaction_id: ootle_id,
                };
                match self.transport.get_transaction_result(&result_request) {
                    Ok(result_response) => match result_response.result {
                        IndexerTransactionFinalizedResult::Pending => {
                            Ok(IndexerReceiptFetchV1::Pending)
                        }
                        IndexerTransactionFinalizedResult::Finalized {
                            final_decision: Decision::Commit,
                            ..
                        } => Ok(IndexerReceiptFetchV1::Pending),
                        IndexerTransactionFinalizedResult::Finalized {
                            final_decision: Decision::Abort(_),
                            abort_details,
                            ..
                        } => Ok(IndexerReceiptFetchV1::Finalized(
                            Self::build_rejected_receipt(query, abort_details),
                        )),
                        IndexerTransactionFinalizedResult::Rejected { details, .. } => {
                            Ok(IndexerReceiptFetchV1::Finalized(
                                Self::build_rejected_receipt(query, Some(details)),
                            ))
                        }
                    },
                    Err(error) if error.is_not_found() => Ok(IndexerReceiptFetchV1::NotFound),
                    Err(error) => Err(map_transport_error(error)),
                }
            }
            Err(error) => Err(map_transport_error(error)),
        }
    }
}
