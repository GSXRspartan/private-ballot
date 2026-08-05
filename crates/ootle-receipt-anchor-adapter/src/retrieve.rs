//! Receipt retrieval, verification (Section G), and walletd/indexer agreement
//! (Section H).
//!
//! [`AnchorReceiptCoordinator`] revalidates the submitted binding, derives the
//! receipt address evidence, queries the narrow client boundary, maps the outcome
//! into the Slice 4A4 [`AnchorQueryOutcomeV1`], and runs the **existing** Slice
//! 4A4 [`verify_query_outcome`] verifier — it never reimplements anchor parsing
//! or verification. Retrieval is a pure transform of already-frozen commitments,
//! so no query outcome can mutate the archive, anchor record, submitted
//! transaction id, or fingerprint.

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorFinalStatusV1, AnchorLogPayloadV1, AnchorObservationAgreementError, AnchorQueryOutcomeV1,
    AnchorReceiptSourceKindV1, AnchorReceiptV1, AnchorReceiptVerificationError,
    AnchorTransactionId, VerifiedAnchorEvidenceV1, compare_receipt_observations,
    verify_query_outcome,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::SubmittedWalletdAnchorRequestV1;

use crate::address::{AnchorReceiptAddressEvidenceV1, derive_receipt_address_evidence};
use crate::client::{IndexerAnchorReceiptClient, IndexerReceiptFetchV1};
use crate::errors::{ReceiptIdentifierError, ReceiptQueryBindingError};
use crate::query::AnchorReceiptQueryV1;
use crate::state::{
    AnchorReceiptQuerySnapshotV1, AnchorReceiptQueryStateV1, LocalReceiptQueryRegistry,
};

/// A verified, bound anchor observed by the independent indexer (Section G).
///
/// It is produced only by a successful verification of a finalized full
/// acceptance. It wraps the Slice 4A4 [`VerifiedAnchorEvidenceV1`] and adds the
/// exact verified payload, the receipt-address query evidence, and the finalized
/// status. It carries no archive, ballot, or secret data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIndexerAnchorV1 {
    evidence: VerifiedAnchorEvidenceV1,
    payload: AnchorLogPayloadV1,
    address_evidence: AnchorReceiptAddressEvidenceV1,
    final_status: AnchorFinalStatusV1,
}

impl VerifiedIndexerAnchorV1 {
    /// Returns the Slice 4A4 verified anchor evidence.
    #[must_use]
    pub const fn evidence(&self) -> &VerifiedAnchorEvidenceV1 {
        &self.evidence
    }

    /// Returns the exact verified anchor log payload.
    #[must_use]
    pub const fn payload(&self) -> &AnchorLogPayloadV1 {
        &self.payload
    }

    /// Returns the receipt-address query evidence.
    #[must_use]
    pub const fn address_evidence(&self) -> &AnchorReceiptAddressEvidenceV1 {
        &self.address_evidence
    }

    /// Returns the finalized status (always a full acceptance here).
    #[must_use]
    pub const fn final_status(&self) -> AnchorFinalStatusV1 {
        self.final_status
    }

    /// Returns the recorded receipt source (always the independent indexer).
    #[must_use]
    pub const fn source(&self) -> AnchorReceiptSourceKindV1 {
        self.evidence.source()
    }
}

/// The full report of a receipt query (Sections F, G, I).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorReceiptQueryReportV1 {
    state: AnchorReceiptQueryStateV1,
    outcome: AnchorQueryOutcomeV1,
    address_evidence: AnchorReceiptAddressEvidenceV1,
    receipt: Option<AnchorReceiptV1>,
    verified: Option<VerifiedIndexerAnchorV1>,
    final_status: Option<AnchorFinalStatusV1>,
    diagnostic: Option<&'static str>,
}

impl AnchorReceiptQueryReportV1 {
    /// Returns the resulting query state.
    #[must_use]
    pub const fn state(&self) -> AnchorReceiptQueryStateV1 {
        self.state
    }

    /// Returns the mapped Slice 4A4 query outcome.
    #[must_use]
    pub const fn outcome(&self) -> &AnchorQueryOutcomeV1 {
        &self.outcome
    }

    /// Returns the receipt-address query evidence.
    #[must_use]
    pub const fn address_evidence(&self) -> &AnchorReceiptAddressEvidenceV1 {
        &self.address_evidence
    }

    /// Returns the retrieved receipt, if a finalized receipt was observed.
    #[must_use]
    pub const fn receipt(&self) -> Option<&AnchorReceiptV1> {
        self.receipt.as_ref()
    }

    /// Returns the verified anchor, if verification succeeded.
    #[must_use]
    pub const fn verified(&self) -> Option<&VerifiedIndexerAnchorV1> {
        self.verified.as_ref()
    }

    /// Returns the observed finalized status, if the receipt was finalized.
    #[must_use]
    pub const fn final_status(&self) -> Option<AnchorFinalStatusV1> {
        self.final_status
    }

    /// Returns the last bounded diagnostic code, if any.
    #[must_use]
    pub const fn diagnostic(&self) -> Option<&'static str> {
        self.diagnostic
    }

    /// Returns whether the query verified a full, landed anchor.
    #[must_use]
    pub const fn is_verified_success(&self) -> bool {
        self.verified.is_some()
    }
}

/// A hard error that prevents a receipt query from running at all.
///
/// Transport failures and unfavourable outcomes are folded into the report; this
/// enum names only the two conditions that stop a query before it begins: a
/// binding revalidation mismatch and a malformed transaction identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReceiptRetrievalError {
    /// The query did not match the submitted request it was revalidated against.
    Binding(ReceiptQueryBindingError),
    /// The transaction identifier could not be converted to a receipt address.
    Identifier(ReceiptIdentifierError),
}

impl ReceiptRetrievalError {
    /// Returns the stable machine-readable code for the underlying error.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Binding(error) => error.as_str(),
            Self::Identifier(error) => error.as_str(),
        }
    }
}

impl core::fmt::Display for ReceiptRetrievalError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for ReceiptRetrievalError {}

/// Categories a walletd/indexer agreement check can fail with (Section H).
///
/// It extends the Slice 4A4 observation-agreement verifier with the extra
/// binding checks this cross-source comparison requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnchorReceiptAgreementError {
    /// The walletd observation was not recorded with the walletd source.
    WrongWalletdSource,
    /// The indexer observation was not recorded with the indexer source.
    WrongIndexerSource,
    /// An observation named a transaction other than the expected one (for
    /// example an indexer receipt for another transaction).
    ExpectedTransactionMismatch,
    /// An observation named a network other than the expected one.
    ExpectedNetworkMismatch,
    /// The two observations disagreed under the Slice 4A4 agreement verifier.
    Observation(AnchorObservationAgreementError),
}

impl AnchorReceiptAgreementError {
    /// Returns the stable machine-readable code for the disagreement.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WrongWalletdSource => "RECEIPT_AGREEMENT_WRONG_WALLETD_SOURCE",
            Self::WrongIndexerSource => "RECEIPT_AGREEMENT_WRONG_INDEXER_SOURCE",
            Self::ExpectedTransactionMismatch => "RECEIPT_AGREEMENT_EXPECTED_TRANSACTION_MISMATCH",
            Self::ExpectedNetworkMismatch => "RECEIPT_AGREEMENT_EXPECTED_NETWORK_MISMATCH",
            Self::Observation(inner) => inner.as_str(),
        }
    }
}

impl core::fmt::Display for AnchorReceiptAgreementError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for AnchorReceiptAgreementError {}

/// Compares a walletd finalize observation with an independent indexer receipt
/// (Section H).
///
/// It confirms each observation is recorded with the correct source, that both
/// name the expected transaction and network (so an indexer receipt for another
/// transaction is refused), and then defers to the Slice 4A4
/// [`compare_receipt_observations`] for the strict transaction/network/status,
/// project-anchor-log presence, digest, and ordered-log agreement. The stricter
/// existing rule — full ordered log-sequence equality — is retained unchanged.
///
/// # Errors
///
/// Returns the specific [`AnchorReceiptAgreementError`] for the first violated
/// rule.
pub fn compare_walletd_and_indexer(
    expected_transaction: &AnchorTransactionId,
    expected_network: &OotleNetworkIdV1,
    walletd: &AnchorReceiptV1,
    indexer: &AnchorReceiptV1,
) -> Result<(), AnchorReceiptAgreementError> {
    if walletd.source() != AnchorReceiptSourceKindV1::Walletd {
        return Err(AnchorReceiptAgreementError::WrongWalletdSource);
    }
    if indexer.source() != AnchorReceiptSourceKindV1::IndependentIndexer {
        return Err(AnchorReceiptAgreementError::WrongIndexerSource);
    }
    if walletd.transaction_id() != expected_transaction
        || indexer.transaction_id() != expected_transaction
    {
        return Err(AnchorReceiptAgreementError::ExpectedTransactionMismatch);
    }
    if walletd.network() != expected_network || indexer.network() != expected_network {
        return Err(AnchorReceiptAgreementError::ExpectedNetworkMismatch);
    }
    compare_receipt_observations(walletd, indexer).map_err(AnchorReceiptAgreementError::Observation)
}

/// Coordinates receipt retrieval, verification, and recovery state (Sections F,
/// G, I).
#[derive(Debug, Default)]
pub struct AnchorReceiptCoordinator {
    registry: LocalReceiptQueryRegistry,
}

impl AnchorReceiptCoordinator {
    /// Creates a coordinator with an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores a coordinator from recovery snapshots (Section I restart).
    #[must_use]
    pub fn from_snapshots(snapshots: Vec<AnchorReceiptQuerySnapshotV1>) -> Self {
        Self {
            registry: LocalReceiptQueryRegistry::from_snapshots(snapshots),
        }
    }

    /// Returns the underlying registry for snapshot inspection.
    #[must_use]
    pub const fn registry(&self) -> &LocalReceiptQueryRegistry {
        &self.registry
    }

    /// Registers a submitted request so it can be queried later (Section I).
    ///
    /// This records the frozen query binding in the `SubmittedNotQueried` state.
    /// Registration is idempotent: a second registration of the same request
    /// never rewinds progress.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptRetrievalError::Binding`] if the query does not match the
    /// submitted request it is built from.
    pub fn register(
        &mut self,
        query: &AnchorReceiptQueryV1,
        submitted: &SubmittedWalletdAnchorRequestV1,
    ) -> Result<(), ReceiptRetrievalError> {
        query
            .ensure_matches_submitted(submitted)
            .map_err(ReceiptRetrievalError::Binding)?;
        self.registry.register_submitted(query.clone());
        Ok(())
    }

    /// Queries and verifies the receipt for a submitted request (Sections F, G).
    ///
    /// It revalidates the query against the submitted binding, derives the receipt
    /// address evidence, fetches through the narrow client boundary, maps the
    /// outcome into the Slice 4A4 query outcome, runs the Slice 4A4 verifier, and
    /// records the resulting state. Every unfavourable outcome (not found, pending,
    /// timeout, fee-only, rejected, verification failure) is a normal report, not
    /// an error; only a binding mismatch or a malformed identifier is a hard error.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptRetrievalError::Binding`] on a revalidation mismatch or
    /// [`ReceiptRetrievalError::Identifier`] if the transaction id cannot be
    /// converted to a receipt address.
    pub fn query<C: IndexerAnchorReceiptClient>(
        &mut self,
        client: &mut C,
        query: &AnchorReceiptQueryV1,
        submitted: &SubmittedWalletdAnchorRequestV1,
    ) -> Result<AnchorReceiptQueryReportV1, ReceiptRetrievalError> {
        query
            .ensure_matches_submitted(submitted)
            .map_err(ReceiptRetrievalError::Binding)?;

        let address_evidence =
            derive_receipt_address_evidence(query.transaction_id(), query.network())
                .map_err(ReceiptRetrievalError::Identifier)?;

        self.registry.register_submitted(query.clone());

        let report = match client.fetch_anchor_receipt(query) {
            Ok(IndexerReceiptFetchV1::Finalized(receipt)) => {
                self.finalized_report(query, address_evidence, receipt)
            }
            Ok(IndexerReceiptFetchV1::Pending) => AnchorReceiptQueryReportV1 {
                state: AnchorReceiptQueryStateV1::ReceiptPending,
                outcome: AnchorQueryOutcomeV1::NotFinalized,
                address_evidence,
                receipt: None,
                verified: None,
                final_status: None,
                diagnostic: None,
            },
            Ok(IndexerReceiptFetchV1::NotFound) => AnchorReceiptQueryReportV1 {
                state: AnchorReceiptQueryStateV1::ReceiptNotFound,
                outcome: AnchorQueryOutcomeV1::NotFound,
                address_evidence,
                receipt: None,
                verified: None,
                final_status: None,
                diagnostic: None,
            },
            Err(error) => AnchorReceiptQueryReportV1 {
                state: AnchorReceiptQueryStateV1::ReceiptUnknown,
                outcome: AnchorQueryOutcomeV1::Unknown,
                address_evidence,
                receipt: None,
                verified: None,
                final_status: None,
                diagnostic: Some(error.as_str()),
            },
        };

        self.registry.set_outcome(
            query.project_request_id(),
            report.state,
            report.final_status,
            report.is_verified_success(),
            report.diagnostic,
        );

        Ok(report)
    }

    /// Builds the report for a finalized receipt, running the Slice 4A4 verifier.
    fn finalized_report(
        &self,
        query: &AnchorReceiptQueryV1,
        address_evidence: AnchorReceiptAddressEvidenceV1,
        receipt: AnchorReceiptV1,
    ) -> AnchorReceiptQueryReportV1 {
        let final_status = receipt.final_status();
        let outcome = AnchorQueryOutcomeV1::Finalized(receipt.clone());

        match verify_query_outcome(
            query.transaction_id(),
            query.network(),
            query.payload(),
            &outcome,
        ) {
            Ok(evidence) => {
                let verified = VerifiedIndexerAnchorV1 {
                    evidence,
                    payload: *query.payload(),
                    address_evidence: address_evidence.clone(),
                    final_status: AnchorFinalStatusV1::Accepted,
                };
                AnchorReceiptQueryReportV1 {
                    state: AnchorReceiptQueryStateV1::ReceiptFinalizedAccept,
                    outcome,
                    address_evidence,
                    receipt: Some(receipt),
                    verified: Some(verified),
                    final_status: Some(final_status),
                    diagnostic: None,
                }
            }
            Err(AnchorReceiptVerificationError::FeeOnlyAcceptance) => AnchorReceiptQueryReportV1 {
                state: AnchorReceiptQueryStateV1::ReceiptFinalizedFeeOnly,
                outcome,
                address_evidence,
                receipt: Some(receipt),
                verified: None,
                final_status: Some(final_status),
                diagnostic: None,
            },
            Err(AnchorReceiptVerificationError::RejectedTransaction) => {
                AnchorReceiptQueryReportV1 {
                    state: AnchorReceiptQueryStateV1::ReceiptFinalizedReject,
                    outcome,
                    address_evidence,
                    receipt: Some(receipt),
                    verified: None,
                    final_status: Some(final_status),
                    diagnostic: None,
                }
            }
            Err(other) => AnchorReceiptQueryReportV1 {
                state: AnchorReceiptQueryStateV1::ReceiptVerificationFailed,
                outcome,
                address_evidence,
                receipt: Some(receipt),
                verified: None,
                final_status: Some(final_status),
                diagnostic: Some(other.as_str()),
            },
        }
    }
}
