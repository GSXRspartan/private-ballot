//! Exact v0.39.2 `CallFunction` construction for the stateless anchor template.

use tari_cc_private_ballot_anchor_transport::{
    AnchorEventPayloadV2, AnchorEventPayloadV3, AnchorTemplateBindingV1, AnchorTemplateBindingV2,
};
use tari_ootle_transaction::{Instruction, args};
use tari_template_lib_types::TemplateAddress;

use crate::errors::OotleAnchorAdapterError;

/// Parses a canonical Ootle template address of the form `template_<64 hex>`.
///
/// The stock `parse_template_address` strips the bare prefix `template` (with no
/// separator) and then requires the remainder to be exactly 64 hex characters,
/// so it rejects the canonical underscore-separated address that
/// `SubstateId::from_str`, walletd, and the indexer actually emit. This adapter
/// therefore parses the address exactly the way `SubstateId::from_str` does:
/// split on the first `_`, require the `template` prefix, and hex-decode the
/// 32-byte object key. The address stays runtime data (per network deployment);
/// nothing about the network is hard-coded here.
pub(crate) fn parse_anchor_template_address(address: &str) -> Option<TemplateAddress> {
    let (prefix, hash_hex) = address.split_once('_')?;
    if prefix != "template" {
        return None;
    }
    TemplateAddress::from_hex(hash_hex).ok()
}

/// Builds the only normal instruction permitted in a v0.39.2 anchor transaction.
///
/// The published template address is parsed at this Ootle leaf boundary. The
/// exact digest string is passed as the single literal argument; the full event
/// topic is deliberately not caller-controlled in the transaction because the
/// pinned template derives it deterministically.
pub fn build_anchor_call_function(
    template: &AnchorTemplateBindingV1,
    payload: AnchorEventPayloadV2,
) -> Result<Instruction, OotleAnchorAdapterError> {
    let address = parse_anchor_template_address(template.template_address())
        .ok_or(OotleAnchorAdapterError::InvalidTemplateAddress)?;
    let transaction = tari_ootle_transaction::TransactionBuilder::new(0_u8, 1_u64.into())
        .call_function(address, template.function(), args![payload.digest_hex()])
        .build_unsigned();
    transaction.instructions().first().cloned().ok_or(
        OotleAnchorAdapterError::TransactionBuilderFailure {
            reason: "call-function builder emitted no instruction",
        },
    )
}

/// Builds the V2 four-argument `publish_anchor_v2` call from an already
/// verified detached public payload.
///
/// The four arguments are: the domain-separated anchor digest (hex), the
/// network id, the election id (lowercase hex), and the exact canonical
/// public-summary JSON string. No individual ballot, credential, nullifier,
/// proof, voter, or wallet material enters the transaction.
pub fn build_v2_anchor_call_function(
    template: &AnchorTemplateBindingV2,
    payload: &AnchorEventPayloadV3,
) -> Result<Instruction, OotleAnchorAdapterError> {
    let address = parse_anchor_template_address(template.template_address())
        .ok_or(OotleAnchorAdapterError::InvalidTemplateAddress)?;
    let transaction = tari_ootle_transaction::TransactionBuilder::new(0_u8, 1_u64.into())
        .call_function(
            address,
            template.function(),
            args![
                payload.digest_hex(),
                payload.network().to_owned(),
                payload.election_id().to_owned(),
                payload.public_summary().to_owned(),
            ],
        )
        .build_unsigned();
    transaction.instructions().first().cloned().ok_or(
        OotleAnchorAdapterError::TransactionBuilderFailure {
            reason: "V2 call-function builder emitted no instruction",
        },
    )
}
