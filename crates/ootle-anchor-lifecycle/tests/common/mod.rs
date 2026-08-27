//! Shared deterministic constructors and the end-to-end fake harness for the
//! lifecycle-orchestrator test suite (Section H).
//!
//! Each integration-test binary includes this module; not every binary uses
//! every helper, so unused-helper warnings are allowed here (matching the
//! Slice 4A6/4A7 test convention). Every helper is offline and deterministic and
//! drives the real coordinators through their public APIs.

#![allow(dead_code)]

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorBindingV1, AnchorEpochBindingV1, AnchorLogPayloadV1, AnchorMaxFeeV1,
    AnchorPreparationRequest, AnchorReceiptV1, AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_ootle_anchor_adapter::OotleAnchorTransactionBuildRequestV1;
use tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::{
    AnchorLifecycleOrchestrator, PollingPolicy, UnifiedAnchorLifecyclePhase,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::receipt_scenarios::{
    SCENARIO_TEMPLATE_ADDRESS, SCENARIO_TEMPLATE_MODULE,
};
use tari_cc_private_ballot_ootle_receipt_anchor_adapter::{
    FakeIndexerReceiptClient, FakeReceiptStep, receipt_scenarios,
};
use tari_cc_private_ballot_ootle_walletd_anchor_adapter::{
    FakeWalletdAnchorClient, WalletdFeeComponentRef, WalletdSealSignerRef,
};

/// The digest byte used by the canonical scenario.
pub const CANONICAL_DIGEST_BYTE: u8 = 0x22;

/// Builds a valid bounded network identifier or panics.
#[must_use]
pub fn network(value: &str) -> OotleNetworkIdV1 {
    match OotleNetworkIdV1::new(value.to_owned()) {
        Ok(identifier) => identifier,
        Err(_error) => panic!("test network identifier must be valid"),
    }
}

/// The canonical Esmeralda testnet network identifier.
#[must_use]
pub fn canonical_network() -> OotleNetworkIdV1 {
    network("esmeralda")
}

/// Builds a valid bounded account reference or panics.
#[must_use]
pub fn account(value: &str) -> AnchorAccountReference {
    match AnchorAccountReference::new(value.to_owned()) {
        Ok(reference) => reference,
        Err(_error) => panic!("test account reference must be valid"),
    }
}

/// Builds a 32-byte anchor-record digest with a repeated byte.
#[must_use]
pub fn digest(byte: u8) -> OotleAnchorRecordHashV1 {
    OotleAnchorRecordHashV1::new([byte; 32])
}

/// Builds a canonical anchor log payload for a repeated-byte digest.
#[must_use]
pub fn payload(byte: u8) -> AnchorLogPayloadV1 {
    AnchorLogPayloadV1::from_digest(digest(byte))
}

/// The canonical anchor log payload of the scenario.
#[must_use]
pub fn canonical_payload() -> AnchorLogPayloadV1 {
    payload(CANONICAL_DIGEST_BYTE)
}

/// A deterministic seal-signer reference (account key, index 0).
#[must_use]
pub fn seal_signer() -> WalletdSealSignerRef {
    WalletdSealSignerRef::AccountKey { index: 0 }
}

/// A deterministic, valid resolved fee account component address.
#[must_use]
pub fn fee_component() -> WalletdFeeComponentRef {
    match WalletdFeeComponentRef::parse(&format!("component_{}", "11".repeat(32))) {
        Ok(reference) => reference,
        Err(_error) => panic!("test fee component address must be valid"),
    }
}

/// The v0.39.2 event-template deployment binding matching the scenario receipts.
#[must_use]
pub fn template_binding() -> AnchorTemplateBindingV1 {
    let topic = format!("{SCENARIO_TEMPLATE_MODULE}.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V1");
    match AnchorTemplateBindingV1::new(
        SCENARIO_TEMPLATE_ADDRESS.to_owned(),
        SCENARIO_TEMPLATE_MODULE.to_owned(),
        "publish_anchor".to_owned(),
        topic,
        [0x33; 32],
    ) {
        Ok(binding) => binding,
        Err(_error) => panic!("test template binding must be valid"),
    }
}

/// A valid observed/max epoch binding for tests (observed 100, delta 12).
#[must_use]
pub fn epoch_binding() -> AnchorEpochBindingV1 {
    match AnchorEpochBindingV1::from_observed_epoch(100, 12) {
        Ok(binding) => binding,
        Err(_error) => panic!("test epoch binding must be valid"),
    }
}

/// Builds a v0.39.2 build request (with template + epoch binding) from its parts.
#[must_use]
pub fn build_request(
    network_value: &str,
    account_value: &str,
    digest_byte: u8,
    max_fee: u64,
) -> OotleAnchorTransactionBuildRequestV1 {
    let binding = AnchorBindingV1::new(
        network(network_value),
        account(account_value),
        payload(digest_byte),
    );
    let preparation =
        AnchorPreparationRequest::new(binding, AnchorMaxFeeV1::from_units(max_fee), None);
    OotleAnchorTransactionBuildRequestV1::from_preparation_request_with_event_binding(
        preparation,
        template_binding(),
        epoch_binding(),
    )
}

/// The canonical build request on Esmeralda with account `fee-account` and
/// digest byte [`CANONICAL_DIGEST_BYTE`].
#[must_use]
pub fn canonical_build_request() -> OotleAnchorTransactionBuildRequestV1 {
    build_request("esmeralda", "fee-account", CANONICAL_DIGEST_BYTE, 1_000)
}

// ----------------------------------------------------------------------
// Section H — Deterministic end-to-end fake harness
// ----------------------------------------------------------------------

/// A deterministic end-to-end scenario harness that scripts both the walletd
/// fake and the indexer receipt fake together.
///
/// It drives the full lifecycle over the real coordinators through the
/// orchestrator, advancing the polling policy through an explicit attempt
/// counter (no wall-clock, no sleeping, no async, no randomness). It exposes
/// captured call counts on both fakes and the attempts consumed.
pub struct LifecycleHarness {
    pub walletd_client: FakeWalletdAnchorClient,
    pub indexer_client: FakeIndexerReceiptClient,
    pub orchestrator: AnchorLifecycleOrchestrator,
}

impl LifecycleHarness {
    /// Creates a harness with a fresh orchestrator and fresh fakes.
    #[must_use]
    pub fn new(max_query_attempts: u32) -> Self {
        Self {
            walletd_client: FakeWalletdAnchorClient::new(),
            indexer_client: FakeIndexerReceiptClient::new(),
            orchestrator: AnchorLifecycleOrchestrator::new(PollingPolicy::new(max_query_attempts)),
        }
    }

    /// Runs prepare → approve → submit, returning the sealed transaction id.
    ///
    /// Panics if any step fails; this is the happy-path prefix shared by every
    /// scenario that starts from a submitted request.
    pub fn prepare_approve_submit(
        &mut self,
    ) -> tari_cc_private_ballot_anchor_transport::AnchorTransactionId {
        self.prepare();
        self.approve();
        self.submit()
    }

    /// Runs prepare, panicking on failure.
    pub fn prepare(&mut self) {
        let request = canonical_build_request();
        let Ok(report) = self.orchestrator.prepare_fee_bearing(
            &mut self.walletd_client,
            &request,
            &fee_component(),
            seal_signer(),
            None,
        ) else {
            panic!("prepare must succeed");
        };
        assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Prepared);
    }

    /// Runs approve, panicking on failure.
    pub fn approve(&mut self) {
        let Ok(report) = self.orchestrator.approve(&mut self.walletd_client) else {
            panic!("approve must succeed");
        };
        assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Approved);
    }

    /// Runs submit, panicking on failure, and returns the sealed transaction
    /// id. Also scripts the indexer fake for the sealed transaction id with a
    /// default not-found step (the caller may override with
    /// `script_receipt`).
    pub fn submit(&mut self) -> tari_cc_private_ballot_anchor_transport::AnchorTransactionId {
        let Ok(report) = self.orchestrator.submit(&mut self.walletd_client) else {
            panic!("submit must succeed");
        };
        assert_eq!(report.phase(), UnifiedAnchorLifecyclePhase::Submitted);
        let submitted = match self.orchestrator.submitted() {
            Some(submitted) => submitted,
            None => panic!("submitted handle must be cached"),
        };
        let tx = submitted.transaction_id().clone();
        self.indexer_client
            .script(&tx, FakeReceiptStep::not_found());
        tx
    }

    /// Scripts a single repeated receipt step for the sealed transaction id.
    pub fn script_receipt(&mut self, step: FakeReceiptStep) {
        if let Some(submitted) = self.orchestrator.submitted() {
            let tx = submitted.transaction_id().clone();
            self.indexer_client.script(&tx, step);
        }
    }

    /// Scripts an ordered sequence of receipt steps for the sealed transaction
    /// id.
    pub fn script_receipt_sequence(&mut self, steps: Vec<FakeReceiptStep>) {
        if let Some(submitted) = self.orchestrator.submitted() {
            let tx = submitted.transaction_id().clone();
            self.indexer_client.script_sequence(&tx, steps);
        }
    }

    /// Advances one poll, returning the report. Panics on hard error.
    pub fn poll_once(
        &mut self,
    ) -> tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleStepReport {
        let Ok(report) = self.orchestrator.advance_one_poll(&mut self.indexer_client) else {
            panic!("poll must not hard-error");
        };
        report
    }

    /// Runs recover, returning the report. Panics on hard error.
    pub fn recover(
        &mut self,
    ) -> tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::LifecycleStepReport {
        let Ok(report) = self.orchestrator.recover(&mut self.walletd_client) else {
            panic!("recover must not hard-error");
        };
        report
    }

    /// Returns the walletd fake's submit call count.
    #[must_use]
    pub fn submit_calls(&self) -> u64 {
        self.walletd_client.submit_calls()
    }

    /// Returns the indexer fake's total query count.
    #[must_use]
    pub fn receipt_queries(&self) -> u64 {
        self.indexer_client.call_count()
    }

    /// Returns the polling attempts consumed by the orchestrator.
    #[must_use]
    pub fn attempts_consumed(&self) -> u32 {
        self.orchestrator.policy().attempts_consumed()
    }

    /// Returns the polling policy.
    #[must_use]
    pub fn policy(
        &self,
    ) -> tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::PollingPolicy {
        self.orchestrator.policy()
    }

    /// Returns the current unified phase.
    #[must_use]
    pub fn phase(&self) -> UnifiedAnchorLifecyclePhase {
        self.orchestrator.phase()
    }

    /// Takes a unified recovery snapshot of the current state.
    #[must_use]
    pub fn snapshot(
        &self,
    ) -> tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleRecoverySnapshot
    {
        self.orchestrator.snapshot()
    }

    /// Restores the orchestrator from a snapshot (restart).
    pub fn restart_from(
        &mut self,
        snapshot: tari_cc_private_ballot_ootle_anchor_lifecycle_orchestrator::AnchorLifecycleRecoverySnapshot,
    ) {
        self.orchestrator = match AnchorLifecycleOrchestrator::from_snapshot(snapshot) {
            Ok(orchestrator) => orchestrator,
            Err(_error) => panic!("snapshot must restore"),
        };
    }
}

/// Type alias for the receipt-builder closures used by matrix tests.
pub type ReceiptBuilder = fn(
    &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
) -> tari_cc_private_ballot_anchor_transport::AnchorReceiptV1;

/// Builds an accepted indexer receipt for the canonical payload.
#[must_use]
pub fn accepted_receipt(
    tx: &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
) -> AnchorReceiptV1 {
    receipt_scenarios::accepted_receipt(tx, &canonical_network(), &canonical_payload())
}

/// Builds a walletd-source accepted receipt for the canonical payload.
#[must_use]
pub fn walletd_accepted_receipt(
    tx: &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
) -> AnchorReceiptV1 {
    receipt_scenarios::walletd_accepted_receipt(tx, &canonical_network(), &canonical_payload())
}

/// Builds a fee-only indexer receipt.
#[must_use]
pub fn fee_only_receipt(
    tx: &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
) -> AnchorReceiptV1 {
    receipt_scenarios::fee_only_receipt(tx, &canonical_network())
}

/// Builds a rejected indexer receipt.
#[must_use]
pub fn rejected_receipt(
    tx: &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
) -> AnchorReceiptV1 {
    receipt_scenarios::rejected_receipt(tx, &canonical_network())
}

/// Builds a full-acceptance receipt with a missing anchor log (verification
/// failure).
#[must_use]
pub fn missing_anchor_log_receipt(
    tx: &tari_cc_private_ballot_anchor_transport::AnchorTransactionId,
) -> AnchorReceiptV1 {
    receipt_scenarios::accepted_missing_anchor_log(tx, &canonical_network())
}
