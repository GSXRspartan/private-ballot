//! Deterministic, offline fake indexer receipt client (Section J).
//!
//! The fake models the project-owned receipt-retrieval contract, not indexer wire
//! syntax. It uses no randomness and makes no network call: each transaction id is
//! bound to a scripted sequence of outcomes, consumed deterministically. It never
//! creates or modifies a transaction, never signs, and holds no key material. It
//! exposes the captured query identifiers and call counts for assertions and
//! supports fully scripted sequences (for example a stale result followed by an
//! eventual finalization, or a restart that replays the same script).

use std::collections::BTreeMap;
use std::collections::VecDeque;

use tari_cc_private_ballot_anchor_transport::AnchorTransactionId;

use crate::client::{IndexerAnchorReceiptClient, IndexerReceiptFetchV1};
use crate::errors::IndexerReceiptTransportError;
use crate::query::AnchorReceiptQueryV1;

/// One scripted step the fake returns for a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeReceiptStep {
    /// Return this successful fetch outcome.
    Fetch(IndexerReceiptFetchV1),
    /// Return this transport error.
    Transport(IndexerReceiptTransportError),
}

impl FakeReceiptStep {
    /// A finalized-receipt step.
    #[must_use]
    pub fn finalized(receipt: tari_cc_private_ballot_anchor_transport::AnchorReceiptV1) -> Self {
        Self::Fetch(IndexerReceiptFetchV1::Finalized(receipt))
    }

    /// A pending step.
    #[must_use]
    pub const fn pending() -> Self {
        Self::Fetch(IndexerReceiptFetchV1::Pending)
    }

    /// A not-found step.
    #[must_use]
    pub const fn not_found() -> Self {
        Self::Fetch(IndexerReceiptFetchV1::NotFound)
    }

    /// A transport-error step.
    #[must_use]
    pub const fn transport(error: IndexerReceiptTransportError) -> Self {
        Self::Transport(error)
    }
}

/// Deterministic in-memory fake of the narrow indexer receipt boundary.
#[derive(Debug)]
pub struct FakeIndexerReceiptClient {
    scripts: BTreeMap<AnchorTransactionId, VecDeque<FakeReceiptStep>>,
    default_step: FakeReceiptStep,
    unavailable: bool,
    queried: Vec<AnchorTransactionId>,
    call_count: u64,
}

impl Default for FakeIndexerReceiptClient {
    fn default() -> Self {
        Self {
            scripts: BTreeMap::new(),
            // With no script, a transaction has no receipt yet — the safe default
            // that is never mistaken for a finality claim.
            default_step: FakeReceiptStep::not_found(),
            unavailable: false,
            queried: Vec::new(),
            call_count: 0,
        }
    }
}

impl FakeIndexerReceiptClient {
    /// Creates an empty fake whose default outcome is not-found.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the outcome returned for any transaction with no explicit script.
    pub fn set_default_step(&mut self, step: FakeReceiptStep) {
        self.default_step = step;
    }

    /// Makes every subsequent query report the indexer as unavailable.
    ///
    /// This overrides any script, modelling a total transport outage.
    pub fn set_unavailable(&mut self, unavailable: bool) {
        self.unavailable = unavailable;
    }

    /// Scripts a single repeated outcome for a transaction id.
    ///
    /// Once set, every query for this id returns `step` (the last step of a
    /// one-element sequence repeats).
    pub fn script(&mut self, transaction_id: &AnchorTransactionId, step: FakeReceiptStep) {
        self.scripts
            .insert(transaction_id.clone(), VecDeque::from(vec![step]));
    }

    /// Scripts an ordered sequence of outcomes for a transaction id.
    ///
    /// Each query consumes the next step; the final step repeats once the sequence
    /// is exhausted, so a terminal finalized outcome persists. An empty sequence
    /// falls back to the default step.
    pub fn script_sequence(
        &mut self,
        transaction_id: &AnchorTransactionId,
        steps: Vec<FakeReceiptStep>,
    ) {
        self.scripts
            .insert(transaction_id.clone(), VecDeque::from(steps));
    }

    /// Returns the transaction ids queried so far, in call order.
    #[must_use]
    pub fn queried_transaction_ids(&self) -> &[AnchorTransactionId] {
        &self.queried
    }

    /// Returns the total number of queries made.
    #[must_use]
    pub const fn call_count(&self) -> u64 {
        self.call_count
    }

    /// Returns how many times a specific transaction id was queried.
    #[must_use]
    pub fn query_count_for(&self, transaction_id: &AnchorTransactionId) -> usize {
        self.queried
            .iter()
            .filter(|queried| *queried == transaction_id)
            .count()
    }

    /// Consumes and returns the next scripted step for a transaction id.
    ///
    /// The last step of a sequence repeats, so a terminal outcome is stable.
    fn next_step(&mut self, transaction_id: &AnchorTransactionId) -> FakeReceiptStep {
        match self.scripts.get_mut(transaction_id) {
            Some(sequence) if sequence.len() > 1 => sequence
                .pop_front()
                .unwrap_or_else(|| self.default_step.clone()),
            Some(sequence) => sequence
                .front()
                .cloned()
                .unwrap_or_else(|| self.default_step.clone()),
            None => self.default_step.clone(),
        }
    }
}

impl IndexerAnchorReceiptClient for FakeIndexerReceiptClient {
    fn fetch_anchor_receipt(
        &mut self,
        query: &AnchorReceiptQueryV1,
    ) -> Result<IndexerReceiptFetchV1, IndexerReceiptTransportError> {
        self.call_count = self.call_count.wrapping_add(1);
        self.queried.push(query.transaction_id().clone());

        if self.unavailable {
            return Err(IndexerReceiptTransportError::Unavailable);
        }

        match self.next_step(query.transaction_id()) {
            FakeReceiptStep::Fetch(outcome) => Ok(outcome),
            FakeReceiptStep::Transport(error) => Err(error),
        }
    }
}
