//! Minimal synchronous, project-owned traits for future anchor adapters
//! (Section I).
//!
//! The traits are deliberately synchronous. The offline contract needs no async
//! runtime, and a future real adapter can wrap a blocking implementation behind
//! application-level orchestration. No trait exposes a Tari Ootle type or any
//! private-key material; every parameter and return value is a project DTO.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};

use crate::errors::{
    AnchorApprovalError, AnchorPreparationError, AnchorReceiptQueryError, AnchorRequestLookupError,
    AnchorSubmissionError,
};
use crate::identifiers::{AnchorRequestId, AnchorTransactionId};
use crate::model::{
    AnchorBindingV1, AnchorLifecycleSnapshotV1, AnchorPreparationRequest, AnchorQueryOutcomeV1,
    ApprovedAnchorTransaction, PreparedAnchorTransaction, SubmittedAnchorTransaction,
};

/// Stores anchor transaction requests and exposes recovery snapshots.
pub trait AnchorTransactionRequestStore {
    /// Creates (or idempotently returns) a prepared anchor transaction request.
    fn create_request(
        &mut self,
        request: &AnchorPreparationRequest,
    ) -> Result<PreparedAnchorTransaction, AnchorPreparationError>;

    /// Returns a recovery snapshot for a stored request.
    fn get_request(
        &self,
        request_id: &AnchorRequestId,
    ) -> Result<AnchorLifecycleSnapshotV1, AnchorRequestLookupError>;
}

/// Approves or rejects a stored anchor transaction request.
pub trait AnchorTransactionApprover {
    /// Approves a request after confirming it matches the supplied binding.
    fn approve(
        &mut self,
        request_id: &AnchorRequestId,
        binding: &AnchorBindingV1,
    ) -> Result<ApprovedAnchorTransaction, AnchorApprovalError>;

    /// Rejects a request so it can never be submitted.
    fn reject(&mut self, request_id: &AnchorRequestId) -> Result<(), AnchorApprovalError>;
}

/// Submits an approved anchor transaction request.
pub trait AnchorTransactionSubmitter {
    /// Seals and submits an approved request, returning the transaction id.
    ///
    /// The `expected_digest` guards against submitting an approval for a
    /// different anchor than intended.
    fn submit(
        &mut self,
        request_id: &AnchorRequestId,
        binding: &AnchorBindingV1,
        expected_digest: &OotleAnchorRecordHashV1,
    ) -> Result<SubmittedAnchorTransaction, AnchorSubmissionError>;
}

/// Retrieves a receipt for a submitted anchor transaction.
pub trait AnchorReceiptSource {
    /// Queries the receipt for a transaction on the expected network.
    fn query_receipt(
        &self,
        transaction_id: &AnchorTransactionId,
        expected_network: &OotleNetworkIdV1,
    ) -> Result<AnchorQueryOutcomeV1, AnchorReceiptQueryError>;
}
