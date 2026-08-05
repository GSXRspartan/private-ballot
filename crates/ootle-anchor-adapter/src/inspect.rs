//! Pure inspection and safety validation of a constructed unsigned transaction
//! (Section F).
//!
//! [`inspect_unsigned_anchor_transaction`] takes any pinned [`UnsignedTransaction`]
//! and the expected binding, then proves the transaction is exactly the intended
//! single-anchor-log transaction and nothing else. It is a pure function: it
//! reads the transaction and returns either project-owned evidence or a specific
//! rejection. It is used both to validate freshly constructed transactions and to
//! reject mutated or independently constructed invalid variants.
//!
//! "No signer/key fields are populated" and "no transaction identifier is claimed"
//! are guaranteed by the pinned type itself: an [`UnsignedTransaction`] carries no
//! signature and no identifier — those exist only after sealing, which this slice
//! never performs.

use tari_cc_private_ballot_anchor::{OotleAnchorRecordHashV1, OotleNetworkIdV1};
use tari_cc_private_ballot_anchor_transport::{
    ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1, AnchorAccountReference, AnchorLogPayloadV1,
    AnchorMaxFeeV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashProvider};
use tari_ootle_transaction::{
    ComponentReference, Instruction, Network, TransactionBuilder, UnsignedTransaction,
};
use tari_template_lib_types::{Amount, ComponentAddress};

use crate::errors::OotleAnchorAdapterError;
use crate::evidence::{
    OotleAnchorInspectionFingerprintV1, OotleUnsignedAnchorTransactionEvidenceV1,
};
use crate::network::map_ootle_network;
use crate::request::OotleAnchorTransactionBuildRequestV1;

/// The only supported unsigned transaction schema version.
const SUPPORTED_UNSIGNED_SCHEMA_VERSION: u16 = 1;

/// Unique adapter frame for the unsigned-transaction inspection fingerprint.
///
/// This prefix is distinct from the protocol hash frame and the anchor-record
/// hash frame, so the fingerprint can never collide with a protocol or
/// anchor-record digest.
const INSPECTION_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"tari-cc-private-ballot/ootle-anchor-adapter/unsigned-inspection-fingerprint/v1";

/// The confirmed walletd component method used to pay a transaction fee.
///
/// `pay_fee_from_component(component, max_fee)` on the pinned
/// [`TransactionBuilder`] expands to a fee-list `CallMethod` invoking this method
/// on the fee account component with the maximum fee as its single argument.
pub(crate) const PAY_FEE_METHOD_NAME: &str = "pay_fee";

/// Whether the inspected transaction is expected to carry a fee instruction.
///
/// The fee-less path ([`inspect_unsigned_anchor_transaction`]) forbids any fee
/// instruction, exactly as Slice 4A5 did. The fee-bearing path
/// ([`inspect_fee_bearing_anchor_transaction`]) requires exactly one
/// `pay_fee_from_component` instruction naming the resolved fee account component
/// and locking the exact maximum fee.
#[derive(Debug, Clone)]
enum FeeExpectation {
    /// No fee instruction may be present.
    Forbidden,
    /// Exactly one `pay_fee` instruction from `component` locking `max_fee`.
    Required {
        /// The resolved fee account component address that must pay.
        component: ComponentAddress,
        /// The exact maximum fee the `pay_fee` call must lock.
        max_fee: AnchorMaxFeeV1,
    },
}

/// Verifies the transaction's fee-instruction list against the expectation.
///
/// Returns whether a fee instruction is present on success. Every rejection is a
/// specific, bounded error; nothing here can panic.
fn validate_fee_instructions(
    unsigned: &UnsignedTransaction,
    fee: &FeeExpectation,
) -> Result<bool, OotleAnchorAdapterError> {
    let fee_instructions = unsigned.fee_instructions();
    match fee {
        FeeExpectation::Forbidden => {
            if fee_instructions.is_empty() {
                Ok(false)
            } else {
                Err(OotleAnchorAdapterError::UnexpectedFeeInstruction)
            }
        }
        FeeExpectation::Required { component, max_fee } => match fee_instructions.len() {
            0 => Err(OotleAnchorAdapterError::MissingFeeInstruction),
            1 => {
                verify_pay_fee_instruction(
                    &fee_instructions[0],
                    unsigned.network(),
                    *component,
                    *max_fee,
                )?;
                Ok(true)
            }
            _ => Err(OotleAnchorAdapterError::UnexpectedFeeInstruction),
        },
    }
}

/// Proves a single fee instruction is exactly the canonical `pay_fee` call.
///
/// The expected argument encoding is reproduced by building a throwaway,
/// deterministic transaction with the same pinned builder call, so the amount
/// literal is compared against the exact bytes the builder itself would emit
/// rather than a hand-rolled re-encoding.
fn verify_pay_fee_instruction(
    instruction: &Instruction,
    network_byte: u8,
    component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
) -> Result<(), OotleAnchorAdapterError> {
    let Instruction::CallMethod { call, method, args } = instruction else {
        return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
    };
    if &**method != PAY_FEE_METHOD_NAME {
        return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
    }
    match call {
        ComponentReference::Address(address) if *address == component => {}
        ComponentReference::Address(_) => {
            return Err(OotleAnchorAdapterError::FeeAccountMismatch);
        }
        ComponentReference::Workspace(_) => {
            return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
        }
    }

    // Reproduce the exact canonical fee instruction the builder emits for this
    // component and amount, and compare the argument encoding byte-for-byte.
    let reference = TransactionBuilder::new(network_byte)
        .pay_fee_from_component(component, Amount::from_u64(max_fee.value()))
        .build_unsigned();
    let Some(Instruction::CallMethod {
        args: reference_args,
        ..
    }) = reference.fee_instructions().first()
    else {
        // The pinned builder always produces exactly this shape; treat any other
        // outcome as a malformed reference rather than panicking.
        return Err(OotleAnchorAdapterError::MalformedFeeInstruction);
    };
    if args != reference_args {
        return Err(OotleAnchorAdapterError::FeeAmountMismatch);
    }
    Ok(())
}

/// The exact shape a constructed anchor transaction must match.
#[derive(Debug, Clone)]
pub struct AnchorInspectionExpectationV1 {
    project_network: OotleNetworkIdV1,
    ootle_network: Network,
    account: AnchorAccountReference,
    anchor_digest: OotleAnchorRecordHashV1,
    anchor_payload: AnchorLogPayloadV1,
}

impl AnchorInspectionExpectationV1 {
    /// Builds an expectation from its already-resolved parts.
    #[must_use]
    pub fn new(
        project_network: OotleNetworkIdV1,
        ootle_network: Network,
        account: AnchorAccountReference,
        anchor_digest: OotleAnchorRecordHashV1,
        anchor_payload: AnchorLogPayloadV1,
    ) -> Self {
        Self {
            project_network,
            ootle_network,
            account,
            anchor_digest,
            anchor_payload,
        }
    }

    /// Derives the expectation from an adapter build request.
    ///
    /// # Errors
    ///
    /// Returns [`OotleAnchorAdapterError::UnsupportedNetwork`] if the request's
    /// network identifier is not mappable.
    pub fn for_request(
        request: &OotleAnchorTransactionBuildRequestV1,
    ) -> Result<Self, OotleAnchorAdapterError> {
        let ootle_network = map_ootle_network(request.network())?;
        Ok(Self::new(
            request.network().clone(),
            ootle_network,
            request.account().clone(),
            request.anchor_digest(),
            *request.payload(),
        ))
    }

    /// Returns the expected Ootle network.
    #[must_use]
    pub const fn ootle_network(&self) -> Network {
        self.ootle_network
    }

    /// Returns the expected project network identifier.
    #[must_use]
    pub const fn project_network(&self) -> &OotleNetworkIdV1 {
        &self.project_network
    }

    /// Returns the expected anchor-record digest.
    #[must_use]
    pub const fn anchor_digest(&self) -> OotleAnchorRecordHashV1 {
        self.anchor_digest
    }

    /// Returns the expected anchor log payload.
    #[must_use]
    pub const fn anchor_payload(&self) -> &AnchorLogPayloadV1 {
        &self.anchor_payload
    }
}

/// Returns true for component-invoking instructions.
fn is_component_call(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::CallFunction { .. }
            | Instruction::CallMethod { .. }
            | Instruction::UpdateComponentTemplate { .. }
    )
}

/// Returns true for resource-moving instructions.
fn is_resource_transfer(instruction: &Instruction) -> bool {
    matches!(
        instruction,
        Instruction::StealthTransfer { .. }
            | Instruction::TakeFromBucket { .. }
            | Instruction::PutIntoBucket { .. }
            | Instruction::PayFeeFromBucket { .. }
    )
}

/// Classifies a single, non-matching, candidate-prefixed anchor log.
fn classify_anchor_mismatch(
    text: &str,
    expected_digest: OotleAnchorRecordHashV1,
) -> OotleAnchorAdapterError {
    match AnchorLogPayloadV1::parse(text) {
        // Well-formed but a different digest.
        Ok(parsed) if parsed.digest() != expected_digest => {
            OotleAnchorAdapterError::AnchorDigestMismatch
        }
        // Parsed to the expected digest yet bytes differ: impossible for a
        // fixed-length canonical encoding, treated defensively as malformed.
        Ok(_) => OotleAnchorAdapterError::MalformedAnchorPayload,
        // Bad length, casing, separator, or trailing content.
        Err(_error) => OotleAnchorAdapterError::MalformedAnchorPayload,
    }
}

/// Derives the adapter-owned inspection fingerprint over the canonical CBOR
/// encoding of the unsigned transaction.
fn fingerprint_unsigned(
    unsigned: &UnsignedTransaction,
) -> Result<OotleAnchorInspectionFingerprintV1, OotleAnchorAdapterError> {
    let canonical =
        minicbor::to_vec(unsigned).map_err(|_error| OotleAnchorAdapterError::FingerprintFailure)?;

    let mut framed =
        Vec::with_capacity(INSPECTION_FINGERPRINT_DOMAIN_V1.len() + 1 + canonical.len());
    framed.extend_from_slice(INSPECTION_FINGERPRINT_DOMAIN_V1);
    framed.push(0);
    framed.extend_from_slice(&canonical);

    let provider = Blake3HashProviderV1;
    Ok(OotleAnchorInspectionFingerprintV1::new(
        provider.hash(&framed),
    ))
}

/// Inspects a constructed unsigned transaction against the expected binding.
///
/// On success the transaction is proven to contain exactly one normal
/// instruction — the expected anchor `EmitLog` — bound to the expected network,
/// with no fee instructions, no inputs, no blobs, no component calls, and no
/// resource transfers.
///
/// # Errors
///
/// Returns the specific [`OotleAnchorAdapterError`] for the first violated
/// invariant. Every rejection path is total: no input can cause a panic.
pub fn inspect_unsigned_anchor_transaction(
    unsigned: &UnsignedTransaction,
    expectation: &AnchorInspectionExpectationV1,
) -> Result<OotleUnsignedAnchorTransactionEvidenceV1, OotleAnchorAdapterError> {
    inspect_core(unsigned, expectation, &FeeExpectation::Forbidden)
}

/// Inspects a constructed fee-bearing unsigned transaction (Slice 4A6B).
///
/// Identical to [`inspect_unsigned_anchor_transaction`] except that the fee list
/// must carry exactly one `pay_fee_from_component` instruction naming
/// `fee_component` and locking `max_fee`. The normal instruction list is still
/// proven to contain exactly the one anchor `EmitLog`; the fee instruction lives
/// in the separate fee list and touches only the configured fee account.
///
/// # Errors
///
/// Returns the specific [`OotleAnchorAdapterError`] for the first violated
/// invariant. Every rejection path is total: no input can cause a panic.
pub fn inspect_fee_bearing_anchor_transaction(
    unsigned: &UnsignedTransaction,
    expectation: &AnchorInspectionExpectationV1,
    fee_component: ComponentAddress,
    max_fee: AnchorMaxFeeV1,
) -> Result<OotleUnsignedAnchorTransactionEvidenceV1, OotleAnchorAdapterError> {
    inspect_core(
        unsigned,
        expectation,
        &FeeExpectation::Required {
            component: fee_component,
            max_fee,
        },
    )
}

/// Shared inspection core for the fee-less and fee-bearing paths.
fn inspect_core(
    unsigned: &UnsignedTransaction,
    expectation: &AnchorInspectionExpectationV1,
    fee: &FeeExpectation,
) -> Result<OotleUnsignedAnchorTransactionEvidenceV1, OotleAnchorAdapterError> {
    // Schema version.
    let schema = unsigned.schema_version();
    if schema != SUPPORTED_UNSIGNED_SCHEMA_VERSION {
        return Err(OotleAnchorAdapterError::UnsupportedTransactionSchema {
            schema_version: schema,
        });
    }

    // Network binding.
    if unsigned.network() != expectation.ootle_network().as_byte() {
        return Err(OotleAnchorAdapterError::NetworkBindingMismatch);
    }

    // No attached blobs.
    if !unsigned.blobs().is_empty() {
        return Err(OotleAnchorAdapterError::ArbitraryBlobAttached);
    }

    // No substate inputs (walletd resolves inputs later).
    if !unsigned.inputs().is_empty() {
        return Err(OotleAnchorAdapterError::UnexpectedInput);
    }

    // Fee instructions: forbidden on the fee-less path, exactly one canonical
    // `pay_fee` on the fee-bearing path.
    let fee_instructions_present = validate_fee_instructions(unsigned, fee)?;

    let instructions = unsigned.instructions();

    // Structural rejects with priority: component calls, then resource transfers.
    for instruction in instructions {
        if is_component_call(instruction) {
            return Err(OotleAnchorAdapterError::ComponentCallPresent);
        }
        if is_resource_transfer(instruction) {
            return Err(OotleAnchorAdapterError::ResourceTransferPresent);
        }
    }

    // Partition remaining instructions into anchor-candidate logs and everything
    // else (unrelated logs and any other instruction type).
    let mut anchor_logs: Vec<&str> = Vec::new();
    let mut has_other_instruction = false;
    for instruction in instructions {
        match instruction {
            Instruction::EmitLog { message, .. } => {
                let text: &str = message.as_ref();
                if text.starts_with(ANCHOR_LOG_PAYLOAD_CANDIDATE_PREFIX_V1) {
                    anchor_logs.push(text);
                } else {
                    has_other_instruction = true;
                }
            }
            _other => has_other_instruction = true,
        }
    }

    let expected_text = expectation.anchor_payload().to_encoded_string();

    match anchor_logs.len() {
        0 => return Err(OotleAnchorAdapterError::MissingAnchorInstruction),
        1 => {
            if has_other_instruction {
                return Err(OotleAnchorAdapterError::UnexpectedInstruction {
                    detail: "extra instruction alongside the anchor log",
                });
            }

            let anchor_text = anchor_logs[0];
            if anchor_text.as_bytes() != expected_text.as_bytes() {
                return Err(classify_anchor_mismatch(
                    anchor_text,
                    expectation.anchor_digest(),
                ));
            }
        }
        _ => {
            let first = anchor_logs[0];
            if anchor_logs.iter().all(|text| *text == first) {
                return Err(OotleAnchorAdapterError::DuplicateAnchorInstruction);
            }
            return Err(OotleAnchorAdapterError::ConflictingAnchorInstruction);
        }
    }

    // Exactly one instruction remains: the anchor log with the exact payload.
    let fingerprint = fingerprint_unsigned(unsigned)?;

    Ok(OotleUnsignedAnchorTransactionEvidenceV1 {
        network: expectation.project_network().clone(),
        ootle_network_byte: expectation.ootle_network().as_byte(),
        account: expectation.account.clone(),
        anchor_digest: expectation.anchor_digest(),
        anchor_log_payload: *expectation.anchor_payload(),
        instruction_count: instructions.len(),
        anchor_instruction_index: 0,
        fee_instructions_present,
        input_count: unsigned.inputs().len(),
        blob_count: unsigned.blobs().len(),
        unsigned_schema_version: schema,
        fingerprint,
    })
}
