//! Narrow, fakeable indexer receipt-query boundary (Section D).
//!
//! The trait exposes exactly one confirmed operation — retrieve the receipt for
//! a submitted anchor transaction — in terms of project DTOs, so the full indexer
//! client is not spread through the project and the boundary is trivially
//! fakeable offline. It is deliberately synchronous, matching the Slice 4A4/4A6
//! traits: the confirmed
//! [`IndexerRestApiClient`](tari_indexer_client::rest_api_client) methods are
//! `async` and reqwest-backed, and a future real adapter bridges async to this
//! synchronous boundary at the application layer. This slice owns no runtime,
//! starts no background task, and makes no network call — the reqwest `client`
//! feature of `tari_indexer_client` is deliberately disabled.
//!
//! # Mapping the confirmed indexer to the project outcomes
//!
//! The confirmed indexer surfaces two relevant reads (traced from
//! `clients/tari_indexer_client/src/rest_api_client.rs`):
//!
//! * `get_transaction_receipt(TransactionReceiptAddress) -> GetTransactionReceiptResponse`
//!   returns the persisted receipt substate. It exists only for a committed
//!   transaction, and its [`FinalizeOutcome`] distinguishes a full commit from a
//!   fee-intent-only commit. This is the source of a [`Finalized`] outcome
//!   carrying an `Accepted` or `FeeOnlyAccepted` receipt.
//! * `get_transaction_result(GetTransactionResultRequest) -> GetTransactionResultResponse`
//!   returns an `IndexerTransactionFinalizedResult`, whose `Pending`, `Rejected`,
//!   and `Finalized { final_decision, .. }` variants let a real adapter tell a
//!   not-yet-finalized transaction ([`Pending`]) from a ledger/mempool rejection
//!   (a [`Finalized`] outcome carrying a `Rejected` receipt) from an absent
//!   record ([`NotFound`]).
//!
//! A real adapter composes these two confirmed reads into a single
//! [`IndexerReceiptFetchV1`]; the offline fake produces the same project outcomes
//! directly. Neither the pinned receipt type nor the result type crosses this
//! trait: the seam that names them is [`crate::convert`].
//!
//! [`FinalizeOutcome`]: tari_engine_types::transaction_receipt::FinalizeOutcome
//! [`Finalized`]: IndexerReceiptFetchV1::Finalized
//! [`Pending`]: IndexerReceiptFetchV1::Pending
//! [`NotFound`]: IndexerReceiptFetchV1::NotFound

use tari_cc_private_ballot_anchor_transport::AnchorReceiptV1;

use crate::errors::IndexerReceiptTransportError;
use crate::query::AnchorReceiptQueryV1;

/// The bounded, project-owned result of a successful receipt query.
///
/// A `Finalized` outcome carries a fully converted project receipt whose
/// finalized status is one of accepted, fee-only accepted, or rejected. `Pending`
/// and `NotFound` are distinct from each other and from every transport error so
/// a caller never mistakes a not-yet-finalized transaction, an absent record, or
/// a transport failure for one another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexerReceiptFetchV1 {
    /// A finalized receipt (accepted, fee-only, or rejected) was retrieved.
    Finalized(AnchorReceiptV1),
    /// The transaction is known but has not reached finality.
    Pending,
    /// No receipt or result exists for the transaction.
    NotFound,
}

/// Narrow, fakeable indexer receipt-source boundary.
///
/// It supports only the confirmed receipt-retrieval operation, keyed by the
/// fully-bound project query (from which a real adapter derives the receipt
/// substate address). It never exposes a signed transaction, a private key, a
/// mnemonic, or any pinned Ootle type, and it never submits or mutates anything.
pub trait IndexerAnchorReceiptClient {
    /// Retrieves the receipt for the query's submitted transaction.
    ///
    /// # Errors
    ///
    /// Returns a bounded [`IndexerReceiptTransportError`] on unavailability, a
    /// timeout, a malformed response, or an unsupported API/version. A timeout
    /// specifically means the observable state is now unknown, not that the
    /// receipt is absent.
    fn fetch_anchor_receipt(
        &mut self,
        query: &AnchorReceiptQueryV1,
    ) -> Result<IndexerReceiptFetchV1, IndexerReceiptTransportError>;
}
