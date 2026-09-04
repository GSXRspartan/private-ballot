//! Exact V2 public-summary transaction construction and reinspection.
//!
//! This is deliberately separate from the V1 event-anchor builder. A V2
//! transaction has a different template binding and six scalar arguments, so
//! neither construction nor walletd input detection can silently use V1.

use tari_cc_private_ballot_anchor::OotleNetworkIdV1;
use tari_cc_private_ballot_anchor_transport::{
    AnchorEventPayloadV3, AnchorMaxFeeV1, AnchorTemplateBindingV2,
};
use tari_ootle_transaction::{
    ComponentReference, Epoch, Instruction, TransactionBuilder, UnsignedTransaction,
};
use tari_template_lib_types::{Amount, ComponentAddress};

use crate::errors::OotleAnchorAdapterError;
use crate::event_instruction::build_v2_anchor_call_function;
use crate::evidence::OotleAnchorInspectionFingerprintV1;
use crate::inspect::{PAY_FEE_METHOD_NAME, fingerprint_unsigned_anchor_transaction};
use crate::network::map_ootle_network;

const SUPPORTED_UNSIGNED_SCHEMA_VERSION: u16 = 1;

/// Builds the fee-bearing V2 transaction after all payload fields have been
/// replayed from detached evidence and the verified archive.
pub fn build_fee_bearing_v2_anchor_transaction(
    network: &OotleNetworkIdV1,
    max_epoch: u64,
    fee_component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
    template: &AnchorTemplateBindingV2,
    payload: &AnchorEventPayloadV3,
) -> Result<UnsignedTransaction, OotleAnchorAdapterError> {
    let transaction = TransactionBuilder::new(map_ootle_network(network)?, Epoch::from(max_epoch))
        .add_instruction(build_v2_anchor_call_function(template, payload)?)
        .pay_fee_from_component(fee_component, Amount::from_u64(max_fee.value()))
        .build_unsigned();
    inspect_fee_bearing_v2_anchor_transaction(
        &transaction,
        network,
        max_epoch,
        fee_component,
        max_fee,
        template,
        payload,
        false,
    )?;
    Ok(transaction)
}

/// Re-inspects a V2 transaction after walletd input detection. Only the
/// declared input closure may differ from the deterministic construction.
pub fn inspect_detected_fee_bearing_v2_anchor_transaction(
    transaction: &UnsignedTransaction,
    network: &OotleNetworkIdV1,
    max_epoch: u64,
    fee_component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
    template: &AnchorTemplateBindingV2,
    payload: &AnchorEventPayloadV3,
) -> Result<OotleAnchorInspectionFingerprintV1, OotleAnchorAdapterError> {
    inspect_fee_bearing_v2_anchor_transaction(
        transaction,
        network,
        max_epoch,
        fee_component,
        max_fee,
        template,
        payload,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn inspect_fee_bearing_v2_anchor_transaction(
    transaction: &UnsignedTransaction,
    network: &OotleNetworkIdV1,
    max_epoch: u64,
    fee_component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
    template: &AnchorTemplateBindingV2,
    payload: &AnchorEventPayloadV3,
    inputs_may_be_detected: bool,
) -> Result<OotleAnchorInspectionFingerprintV1, OotleAnchorAdapterError> {
    if transaction.schema_version() != SUPPORTED_UNSIGNED_SCHEMA_VERSION {
        return Err(OotleAnchorAdapterError::UnsupportedTransactionSchema {
            schema_version: transaction.schema_version(),
        });
    }
    let ootle_network = map_ootle_network(network)?;
    if transaction.network() != ootle_network.as_byte() {
        return Err(OotleAnchorAdapterError::NetworkBindingMismatch);
    }
    if transaction.max_epoch().as_u64() != max_epoch {
        return Err(OotleAnchorAdapterError::MaxEpochBindingMismatch);
    }
    if !transaction.blobs().is_empty() {
        return Err(OotleAnchorAdapterError::ArbitraryBlobAttached);
    }
    if !inputs_may_be_detected && !transaction.inputs().is_empty() {
        return Err(OotleAnchorAdapterError::UnexpectedInput);
    }
    if transaction.instructions().len() != 1 {
        return Err(OotleAnchorAdapterError::UnexpectedInstruction {
            detail: "expected exactly one V2 anchor call",
        });
    }
    let expected_call = build_v2_anchor_call_function(template, payload)?;
    if transaction.instructions().first() != Some(&expected_call) {
        return Err(OotleAnchorAdapterError::TemplateCallMismatch);
    }
    match transaction.fee_instructions() {
        [
            Instruction::CallMethod {
                call,
                method,
                args: actual_args,
            },
        ] if &**method == PAY_FEE_METHOD_NAME
            && matches!(call, ComponentReference::Address(address) if *address == fee_component) =>
        {
            let reference = TransactionBuilder::new(ootle_network, Epoch::from(max_epoch))
                .pay_fee_from_component(fee_component, Amount::from_u64(max_fee.value()))
                .build_unsigned();
            let Some(Instruction::CallMethod {
                args: expected_args,
                ..
            }) = reference.fee_instructions().first()
            else {
                return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
            };
            if actual_args != expected_args {
                return Err(OotleAnchorAdapterError::FeeAmountMismatch);
            }
        }
        [Instruction::CallMethod { .. }] => {
            return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
        }
        [] => return Err(OotleAnchorAdapterError::MissingFeeInstruction),
        _ => return Err(OotleAnchorAdapterError::UnexpectedFeeInstruction),
    }
    fingerprint_unsigned_anchor_transaction(transaction)
}
