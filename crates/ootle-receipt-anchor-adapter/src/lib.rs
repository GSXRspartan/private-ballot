#![forbid(unsafe_code)]

//! Pinned Tari Ootle indexer receipt retrieval and anchor verification (offline,
//! Slice 4A7).
//!
//! This leaf crate takes a completed Slice 4A6B
//! [`SubmittedWalletdAnchorRequestV1`] — a submitted anchor transaction with a
//! known transaction id but no finality claim — and performs the independent,
//! read-only step of retrieving the persisted Ootle receipt and verifying that
//! the anchor actually landed:
//!
//! 1. [`AnchorReceiptQueryV1::from_submitted`] builds a fully-bound receipt query
//!    from the submitted request and revalidates it against that binding;
//! 2. [`derive_receipt_address_evidence`] derives the exact persisted receipt
//!    substate address from the transaction id via the confirmed pinned mapping
//!    [`TransactionId::into_receipt_address`], recording typed inspection evidence
//!    that makes no finality claim;
//! 3. [`convert_transaction_receipt`] / [`convert_receipt_response`] convert the
//!    pinned Ootle [`TransactionReceipt`] into the Slice 4A4 project receipt DTO,
//!    preserving ordered logs and exact UTF-8 contents and distinguishing full
//!    acceptance from a distinct fee-only acceptance;
//! 4. [`AnchorReceiptCoordinator::query`] queries the narrow, fakeable indexer
//!    boundary, maps the outcome into the Slice 4A4 query outcome, runs the
//!    **existing** Slice 4A4 [`verify_query_outcome`] verifier, and records the
//!    resulting query/recovery state;
//! 5. [`compare_walletd_and_indexer`] cross-checks a walletd finalize observation
//!    against the independently retrieved indexer receipt using the Slice 4A4
//!    agreement verifier.
//!
//! # What this slice never does
//!
//! It never contacts the network (the reqwest `client` feature of
//! `tari_indexer_client` is disabled, and every test uses the offline
//! [`FakeIndexerReceiptClient`]); never submits, signs, or seals a transaction;
//! never accepts or exposes a private key or mnemonic; never owns an async runtime
//! or starts a background task; never treats submission alone as finality; and
//! never reconstructs, rehashes, or mutates an election artifact, anchor record,
//! `ArchiveHashV1`, submitted transaction id, or unsigned-transaction fingerprint.
//! Retrieving and verifying a receipt is a pure transform of already-frozen
//! commitments, so any outcome — not found, pending, timeout, fee-only, rejected,
//! verification failure, or disagreement — leaves every offline election artifact
//! unchanged.
//!
//! # Confirmed pinned indexer APIs (rev `dd1d731`, v0.39.2)
//!
//! * Receipt retrieval: `IndexerRestApiClient::get_transaction_receipt(TransactionReceiptAddress) -> GetTransactionReceiptResponse { receipt: TransactionReceipt }`
//!   (`clients/tari_indexer_client/src/rest_api_client.rs:260`).
//! * Receipt address: [`TransactionId::into_receipt_address`]
//!   (`crates/transaction/src/transaction_id.rs:73`) — the 32 transaction-id
//!   bytes placed verbatim into the receipt object key.
//! * Full vs fee-only: `TransactionReceipt.outcome: FinalizeOutcome::{Commit, FeeIntentCommit}`
//!   (`crates/engine_types/src/transaction_receipt.rs`).
//! * Pending/rejected (result API): `get_transaction_result -> IndexerTransactionFinalizedResult::{Pending, Finalized{..}, Rejected{..}}`
//!   (`clients/tari_indexer_client/src/types.rs:393`).
//!
//! [`SubmittedWalletdAnchorRequestV1`]: tari_cc_private_ballot_ootle_walletd_anchor_adapter::SubmittedWalletdAnchorRequestV1
//! [`TransactionId::into_receipt_address`]: tari_ootle_transaction::TransactionId::into_receipt_address
//! [`TransactionReceipt`]: tari_engine_types::transaction_receipt::TransactionReceipt
//! [`verify_query_outcome`]: tari_cc_private_ballot_anchor_transport::verify_query_outcome

mod address;
mod client;
mod convert;
mod errors;
mod fake;
mod query;
mod retrieve;
mod scenarios;
mod state;

pub use address::{AnchorReceiptAddressEvidenceV1, derive_receipt_address_evidence};
pub use client::{IndexerAnchorReceiptClient, IndexerReceiptFetchV1};
pub use convert::{
    MAX_RECEIPT_LOG_ENTRIES, MAX_RECEIPT_LOG_MESSAGE_BYTES, TRANSACTION_ID_HEX_LEN,
    convert_receipt_response, convert_transaction_receipt, transaction_id_from_ootle,
    transaction_id_to_ootle,
};
pub use errors::{
    IndexerReceiptTransportError, ReceiptConversionError, ReceiptIdentifierError,
    ReceiptQueryBindingError,
};
pub use fake::{FakeIndexerReceiptClient, FakeReceiptStep};
pub use query::AnchorReceiptQueryV1;
pub use retrieve::{
    AnchorReceiptAgreementError, AnchorReceiptCoordinator, AnchorReceiptQueryReportV1,
    ReceiptRetrievalError, VerifiedIndexerAnchorV1, compare_walletd_and_indexer,
};
pub use state::{
    AnchorReceiptQuerySnapshotV1, AnchorReceiptQueryStateV1, LocalReceiptQueryRegistry,
};

/// Deterministic project-owned receipt builders for the offline fake and tests.
pub mod receipt_scenarios {
    pub use crate::scenarios::{
        FAKE_LEDGER_POSITION, SCENARIO_TEMPLATE_ADDRESS, SCENARIO_TEMPLATE_MODULE,
        accepted_conflicting_anchor_logs, accepted_duplicate_anchor_logs, accepted_event_receipt,
        accepted_malformed_anchor_log, accepted_missing_anchor_log, accepted_receipt,
        accepted_with_unrelated_logs, accepted_wrong_anchor_log, fee_only_receipt, receipt,
        rejected_receipt, walletd_accepted_receipt,
    };
}
