//! v0.39.2 event-anchor transaction construction and frozen preparation data.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorClientReferenceV1, AnchorEpochBindingV1, AnchorEventPayloadV2,
    AnchorMaxFeeV1, AnchorTemplateBindingV1,
};
use tari_ootle_transaction::{Epoch, TransactionBuilder, UnsignedTransaction};
use tari_template_lib_types::{Amount, ComponentAddress};

use crate::errors::OotleAnchorAdapterError;
use crate::event_instruction::build_anchor_call_function;
use crate::evidence::OotleUnsignedAnchorTransactionEvidenceV1;
use crate::inspect::{
    AnchorInspectionExpectationV1, inspect_detected_fee_bearing_anchor_transaction,
    inspect_fee_bearing_anchor_transaction, inspect_unsigned_anchor_transaction,
};
use crate::network::map_ootle_network;
use crate::request::OotleAnchorTransactionBuildRequestV1;

/// Project-owned, immutable walletd preparation data for a v0.39.2 anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OotleWalletdAnchorPreparationV1 {
    network: OotleNetworkIdV1,
    fee_account: AnchorAccountReference,
    max_fee: AnchorMaxFeeV1,
    client_reference: Option<AnchorClientReferenceV1>,
    anchor_digest: OotleAnchorRecordHashV1,
    event_payload: AnchorEventPayloadV2,
    template_binding: AnchorTemplateBindingV1,
    epoch_binding: AnchorEpochBindingV1,
}

impl OotleWalletdAnchorPreparationV1 {
    #[allow(clippy::too_many_arguments)]
    fn new(
        network: OotleNetworkIdV1,
        fee_account: AnchorAccountReference,
        max_fee: AnchorMaxFeeV1,
        client_reference: Option<AnchorClientReferenceV1>,
        anchor_digest: OotleAnchorRecordHashV1,
        event_payload: AnchorEventPayloadV2,
        template_binding: AnchorTemplateBindingV1,
        epoch_binding: AnchorEpochBindingV1,
    ) -> Self {
        Self {
            network,
            fee_account,
            max_fee,
            client_reference,
            anchor_digest,
            event_payload,
            template_binding,
            epoch_binding,
        }
    }

    #[must_use]
    pub const fn network(&self) -> &OotleNetworkIdV1 { &self.network }
    #[must_use]
    pub const fn fee_account(&self) -> &AnchorAccountReference { &self.fee_account }
    #[must_use]
    pub const fn max_fee(&self) -> AnchorMaxFeeV1 { self.max_fee }
    #[must_use]
    pub const fn client_reference(&self) -> Option<&AnchorClientReferenceV1> { self.client_reference.as_ref() }
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 { self.anchor_digest }
    #[must_use]
    pub const fn event_payload(&self) -> AnchorEventPayloadV2 { self.event_payload }
    #[must_use]
    pub const fn template_binding(&self) -> &AnchorTemplateBindingV1 { &self.template_binding }
    #[must_use]
    pub const fn epoch_binding(&self) -> AnchorEpochBindingV1 { self.epoch_binding }
}

/// The frozen unsigned transaction and its project-owned inspection evidence.
#[derive(Debug, Clone)]
pub struct OotleAnchorBuildResultV1 {
    unsigned_transaction: UnsignedTransaction,
    evidence: OotleUnsignedAnchorTransactionEvidenceV1,
    walletd_preparation: OotleWalletdAnchorPreparationV1,
}

impl OotleAnchorBuildResultV1 {
    #[must_use]
    pub const fn unsigned_transaction(&self) -> &UnsignedTransaction { &self.unsigned_transaction }
    #[must_use]
    pub const fn evidence(&self) -> &OotleUnsignedAnchorTransactionEvidenceV1 { &self.evidence }
    #[must_use]
    pub const fn walletd_preparation(&self) -> &OotleWalletdAnchorPreparationV1 { &self.walletd_preparation }

    /// Replaces the still-input-free construction transaction with walletd's
    /// `detect_transaction_inputs` result after strict reinspection. The
    /// original call/fee/epoch binding is retained; only the bounded declared
    /// dependency closure is permitted to differ.
    pub fn with_detected_fee_inputs(
        &self,
        detected: UnsignedTransaction,
        fee_component: ComponentAddress,
    ) -> Result<Self, OotleAnchorAdapterError> {
        let preparation = self.walletd_preparation();
        let expectation = AnchorInspectionExpectationV1::new(
            preparation.network().clone(),
            map_ootle_network(preparation.network())?,
            preparation.fee_account().clone(),
            preparation.event_payload(),
            preparation.template_binding().clone(),
            preparation.epoch_binding(),
        );
        let evidence = inspect_detected_fee_bearing_anchor_transaction(
            &detected,
            &expectation,
            fee_component,
            preparation.max_fee(),
        )?;
        Ok(Self {
            unsigned_transaction: detected,
            evidence,
            walletd_preparation: preparation.clone(),
        })
    }
}

fn expectation_for(
    request: &OotleAnchorTransactionBuildRequestV1,
) -> Result<AnchorInspectionExpectationV1, OotleAnchorAdapterError> {
    let network = map_ootle_network(request.network())?;
    let template = request
        .template_binding()
        .ok_or(OotleAnchorAdapterError::MissingEventBinding)?
        .clone();
    let epoch = request
        .epoch_binding()
        .ok_or(OotleAnchorAdapterError::MissingEpochBinding)?;
    Ok(AnchorInspectionExpectationV1::new(
        request.network().clone(),
        network,
        request.account().clone(),
        request.event_payload(),
        template,
        epoch,
    ))
}

fn preparation_for(
    request: &OotleAnchorTransactionBuildRequestV1,
) -> Result<OotleWalletdAnchorPreparationV1, OotleAnchorAdapterError> {
    let template = request
        .template_binding()
        .ok_or(OotleAnchorAdapterError::MissingEventBinding)?
        .clone();
    let epoch = request
        .epoch_binding()
        .ok_or(OotleAnchorAdapterError::MissingEpochBinding)?;
    Ok(OotleWalletdAnchorPreparationV1::new(
        request.network().clone(),
        request.account().clone(),
        request.max_fee(),
        request.client_reference().cloned(),
        request.anchor_digest(),
        request.event_payload(),
        template,
        epoch,
    ))
}

/// Builds the fee-less normal transaction for deterministic construction checks.
pub fn build_unsigned_anchor_transaction(
    request: &OotleAnchorTransactionBuildRequestV1,
) -> Result<OotleAnchorBuildResultV1, OotleAnchorAdapterError> {
    let expectation = expectation_for(request)?;
    let instruction = build_anchor_call_function(
        expectation.template_binding(),
        expectation.event_payload(),
    )?;
    let unsigned_transaction = TransactionBuilder::new(
        expectation.ootle_network(),
        Epoch::from(expectation.epoch_binding().max_epoch()),
    )
    .add_instruction(instruction)
    .build_unsigned();
    let evidence = inspect_unsigned_anchor_transaction(&unsigned_transaction, &expectation)?;
    Ok(OotleAnchorBuildResultV1 {
        unsigned_transaction,
        evidence,
        walletd_preparation: preparation_for(request)?,
    })
}

/// Builds the only submit-ready anchor transaction: one fee operation and one
/// `CallFunction` to the pinned stateless event template.
pub fn build_fee_bearing_anchor_transaction(
    request: &OotleAnchorTransactionBuildRequestV1,
    fee_component: ComponentAddress,
) -> Result<OotleAnchorBuildResultV1, OotleAnchorAdapterError> {
    let expectation = expectation_for(request)?;
    let instruction = build_anchor_call_function(
        expectation.template_binding(),
        expectation.event_payload(),
    )?;
    let unsigned_transaction = TransactionBuilder::new(
        expectation.ootle_network(),
        Epoch::from(expectation.epoch_binding().max_epoch()),
    )
    .add_instruction(instruction)
    .pay_fee_from_component(fee_component, Amount::from_u64(request.max_fee().value()))
    .build_unsigned();
    let evidence = inspect_fee_bearing_anchor_transaction(
        &unsigned_transaction,
        &expectation,
        fee_component,
        request.max_fee(),
    )?;
    Ok(OotleAnchorBuildResultV1 {
        unsigned_transaction,
        evidence,
        walletd_preparation: preparation_for(request)?,
    })
}
