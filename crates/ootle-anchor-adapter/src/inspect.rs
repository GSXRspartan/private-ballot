//! Pure v0.39.2 transaction inspection for the event-only anchor contract.

use tari_cc_private_ballot_anchor::{OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    AnchorAccountReference, AnchorEpochBindingV1, AnchorEventPayloadV2, AnchorMaxFeeV1,
    AnchorTemplateBindingV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};
use tari_ootle_transaction::{
    ComponentReference, Epoch, Instruction, Network, TransactionBuilder, UnsignedTransaction, args,
};
use tari_template_lib_types::{Amount, ComponentAddress};

use crate::errors::OotleAnchorAdapterError;
use crate::event_instruction::parse_anchor_template_address;
use crate::evidence::{
    OotleAnchorInspectionFingerprintV1, OotleUnsignedAnchorTransactionEvidenceV1,
};
use crate::network::map_ootle_network;
use crate::request::OotleAnchorTransactionBuildRequestV1;

const SUPPORTED_UNSIGNED_SCHEMA_VERSION: u16 = 1;
const INSPECTION_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"tari-cc-private-ballot/ootle-anchor-adapter/unsigned-inspection-fingerprint/v1";
pub(crate) const PAY_FEE_METHOD_NAME: &str = "pay_fee";

#[derive(Debug, Clone)]
enum FeeExpectation {
    Forbidden,
    Required { component: ComponentAddress, max_fee: AnchorMaxFeeV1 },
}

#[derive(Debug, Clone, Copy)]
enum InputExpectation {
    /// Offline construction has not yet passed through walletd input detection.
    Empty,
    /// Walletd returned a dependency-closed transaction. The closure may be
    /// empty for a protocol/version where the referenced component is resolved
    /// by execution; arbitrary instruction, blob, network, and epoch changes
    /// are still rejected below.
    Detected,
}

/// The complete v0.39.2 transaction binding expected by the pure inspector.
#[derive(Debug, Clone)]
pub struct AnchorInspectionExpectationV1 {
    project_network: OotleNetworkIdV1,
    ootle_network: Network,
    account: AnchorAccountReference,
    event_payload: AnchorEventPayloadV2,
    template_binding: AnchorTemplateBindingV1,
    epoch_binding: AnchorEpochBindingV1,
}

impl AnchorInspectionExpectationV1 {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        project_network: OotleNetworkIdV1,
        ootle_network: Network,
        account: AnchorAccountReference,
        event_payload: AnchorEventPayloadV2,
        template_binding: AnchorTemplateBindingV1,
        epoch_binding: AnchorEpochBindingV1,
    ) -> Self {
        Self {
            project_network,
            ootle_network,
            account,
            event_payload,
            template_binding,
            epoch_binding,
        }
    }

    pub fn for_request(request: &OotleAnchorTransactionBuildRequestV1) -> Result<Self, OotleAnchorAdapterError> {
        Ok(Self::new(
            request.network().clone(),
            map_ootle_network(request.network())?,
            request.account().clone(),
            request.event_payload(),
            request.template_binding().ok_or(OotleAnchorAdapterError::MissingEventBinding)?.clone(),
            request.epoch_binding().ok_or(OotleAnchorAdapterError::MissingEpochBinding)?,
        ))
    }

    #[must_use]
    pub const fn ootle_network(&self) -> Network { self.ootle_network }
    #[must_use]
    pub const fn project_network(&self) -> &OotleNetworkIdV1 { &self.project_network }
    #[must_use]
    pub const fn account(&self) -> &AnchorAccountReference { &self.account }
    #[must_use]
    pub const fn event_payload(&self) -> AnchorEventPayloadV2 { self.event_payload }
    #[must_use]
    pub const fn template_binding(&self) -> &AnchorTemplateBindingV1 { &self.template_binding }
    #[must_use]
    pub const fn epoch_binding(&self) -> AnchorEpochBindingV1 { self.epoch_binding }
}

pub fn fingerprint_unsigned_anchor_transaction(
    unsigned: &UnsignedTransaction,
) -> Result<OotleAnchorInspectionFingerprintV1, OotleAnchorAdapterError> {
    let canonical = minicbor::to_vec(unsigned).map_err(|_| OotleAnchorAdapterError::FingerprintFailure)?;
    let mut framed = Vec::with_capacity(INSPECTION_FINGERPRINT_DOMAIN_V1.len() + 1 + canonical.len());
    framed.extend_from_slice(INSPECTION_FINGERPRINT_DOMAIN_V1);
    framed.push(0);
    framed.extend_from_slice(&canonical);
    Ok(OotleAnchorInspectionFingerprintV1::new(Blake3HashProviderV1.hash(&framed)))
}

pub fn inspect_unsigned_anchor_transaction(
    unsigned: &UnsignedTransaction,
    expectation: &AnchorInspectionExpectationV1,
) -> Result<OotleUnsignedAnchorTransactionEvidenceV1, OotleAnchorAdapterError> {
    inspect_core(unsigned, expectation, &FeeExpectation::Forbidden, InputExpectation::Empty)
}

pub fn inspect_fee_bearing_anchor_transaction(
    unsigned: &UnsignedTransaction,
    expectation: &AnchorInspectionExpectationV1,
    fee_component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
) -> Result<OotleUnsignedAnchorTransactionEvidenceV1, OotleAnchorAdapterError> {
    inspect_core(
        unsigned,
        expectation,
        &FeeExpectation::Required { component: fee_component, max_fee },
        InputExpectation::Empty,
    )
}

/// Re-inspects walletd's `transactions.detect_inputs` response before CREATE.
/// The response may add only its declared dependency closure; the v0.39.2
/// network, bounded max epoch, exact function call, exact fee operation, and
/// absence of blobs remain frozen and are rechecked here.
pub fn inspect_detected_fee_bearing_anchor_transaction(
    unsigned: &UnsignedTransaction,
    expectation: &AnchorInspectionExpectationV1,
    fee_component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
) -> Result<OotleUnsignedAnchorTransactionEvidenceV1, OotleAnchorAdapterError> {
    inspect_core(
        unsigned,
        expectation,
        &FeeExpectation::Required { component: fee_component, max_fee },
        InputExpectation::Detected,
    )
}

fn inspect_core(
    unsigned: &UnsignedTransaction,
    expectation: &AnchorInspectionExpectationV1,
    fee: &FeeExpectation,
    input_expectation: InputExpectation,
) -> Result<OotleUnsignedAnchorTransactionEvidenceV1, OotleAnchorAdapterError> {
    if unsigned.schema_version() != SUPPORTED_UNSIGNED_SCHEMA_VERSION {
        return Err(OotleAnchorAdapterError::UnsupportedTransactionSchema { schema_version: unsigned.schema_version() });
    }
    if unsigned.network() != expectation.ootle_network().as_byte() {
        return Err(OotleAnchorAdapterError::NetworkBindingMismatch);
    }
    if unsigned.max_epoch().as_u64() != expectation.epoch_binding().max_epoch() {
        return Err(OotleAnchorAdapterError::MaxEpochBindingMismatch);
    }
    if !unsigned.blobs().is_empty() {
        return Err(OotleAnchorAdapterError::ArbitraryBlobAttached);
    }
    match input_expectation {
        InputExpectation::Empty if !unsigned.inputs().is_empty() => {
            return Err(OotleAnchorAdapterError::UnexpectedInput);
        }
        InputExpectation::Empty | InputExpectation::Detected => {}
    }

    let fee_instructions_present = validate_fee_instructions(unsigned, fee, expectation.epoch_binding())?;
    let instructions = unsigned.instructions();
    if instructions.len() != 1 {
        return Err(OotleAnchorAdapterError::UnexpectedInstruction { detail: "expected exactly one anchor call" });
    }
    verify_anchor_call(&instructions[0], expectation)?;

    Ok(OotleUnsignedAnchorTransactionEvidenceV1 {
        network: expectation.project_network().clone(),
        ootle_network_byte: expectation.ootle_network().as_byte(),
        account: expectation.account().clone(),
        anchor_digest: expectation.event_payload().digest(),
        event_payload: expectation.event_payload(),
        template_binding: expectation.template_binding().clone(),
        epoch_binding: expectation.epoch_binding(),
        instruction_count: 1,
        anchor_instruction_index: 0,
        fee_instructions_present,
        input_count: unsigned.inputs().len(),
        blob_count: 0,
        unsigned_schema_version: unsigned.schema_version(),
        fingerprint: fingerprint_unsigned_anchor_transaction(unsigned)?,
    })
}

fn verify_anchor_call(
    instruction: &Instruction,
    expectation: &AnchorInspectionExpectationV1,
) -> Result<(), OotleAnchorAdapterError> {
    let Instruction::CallFunction { address, function, args: actual_args } = instruction else {
        return Err(OotleAnchorAdapterError::TemplateCallMismatch);
    };
    let expected_address =
        parse_anchor_template_address(expectation.template_binding().template_address())
            .ok_or(OotleAnchorAdapterError::InvalidTemplateAddress)?;
    if *address != expected_address || &**function != expectation.template_binding().function() {
        return Err(OotleAnchorAdapterError::TemplateCallMismatch);
    }
    let reference = TransactionBuilder::new(
        expectation.ootle_network(),
        Epoch::from(expectation.epoch_binding().max_epoch()),
    )
    .call_function(
        expected_address,
        expectation.template_binding().function(),
        args![expectation.event_payload().digest_hex()],
    )
    .build_unsigned();
    let Some(Instruction::CallFunction { args: expected_args, .. }) = reference.instructions().first() else {
        return Err(OotleAnchorAdapterError::TransactionBuilderFailure { reason: "reference call missing" });
    };
    if actual_args != expected_args {
        return Err(OotleAnchorAdapterError::TemplateCallMismatch);
    }
    Ok(())
}

fn validate_fee_instructions(
    unsigned: &UnsignedTransaction,
    fee: &FeeExpectation,
    epoch: AnchorEpochBindingV1,
) -> Result<bool, OotleAnchorAdapterError> {
    match fee {
        FeeExpectation::Forbidden if unsigned.fee_instructions().is_empty() => Ok(false),
        FeeExpectation::Forbidden => Err(OotleAnchorAdapterError::UnexpectedFeeInstruction),
        FeeExpectation::Required { component, max_fee } => match unsigned.fee_instructions() {
            [] => Err(OotleAnchorAdapterError::MissingFeeInstruction),
            [instruction] => {
                verify_pay_fee_instruction(instruction, unsigned.network(), *component, *max_fee, epoch)?;
                Ok(true)
            }
            _ => Err(OotleAnchorAdapterError::UnexpectedFeeInstruction),
        },
    }
}

fn verify_pay_fee_instruction(
    instruction: &Instruction,
    network: u8,
    component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
    epoch: AnchorEpochBindingV1,
) -> Result<(), OotleAnchorAdapterError> {
    let Instruction::CallMethod { call, method, args: actual_args } = instruction else {
        return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
    };
    if &**method != PAY_FEE_METHOD_NAME {
        return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
    }
    if !matches!(call, ComponentReference::Address(address) if *address == component) {
        return Err(OotleAnchorAdapterError::FeeAccountMismatch);
    }
    let reference = TransactionBuilder::new(network, Epoch::from(epoch.max_epoch()))
        .pay_fee_from_component(component, Amount::from_u64(max_fee.value()))
        .build_unsigned();
    let Some(Instruction::CallMethod { args: expected_args, .. }) = reference.fee_instructions().first() else {
        return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
    };
    if actual_args != expected_args {
        return Err(OotleAnchorAdapterError::FeeAmountMismatch);
    }
    Ok(())
}
