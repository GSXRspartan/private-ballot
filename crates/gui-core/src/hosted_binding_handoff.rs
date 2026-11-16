//! Portable, public Desktop ↔ Hosted transport-binding handoff artifacts.
//!
//! The request is downloaded by an authenticated Hosted organizer; the Desktop
//! checks it against its already-loaded organizer election before deriving a
//! response from verified transport history.  Neither artifact contains an
//! organizer credential, a transport private key, or ballot contents.

use serde::{Deserialize, Serialize};

use crate::{GuiCoreError, GuiErrorCategory};

pub const HOSTED_BINDING_REQUEST_SCHEMA_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_HOSTED_BINDING_REQUEST_V1";
pub const DESKTOP_BINDING_HANDOFF_SCHEMA_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_DESKTOP_BINDING_HANDOFF_V1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedBindingRequestV1 {
    pub schema: String,
    pub version: u64,
    pub election_id: String,
    pub manifest_hash_hex: String,
}

impl HostedBindingRequestV1 {
    #[must_use]
    pub fn new(election_id: String, manifest_hash_hex: String) -> Self {
        Self {
            schema: HOSTED_BINDING_REQUEST_SCHEMA_V1.to_owned(),
            version: 1,
            election_id,
            manifest_hash_hex,
        }
    }

    pub fn validate(&self) -> Result<(), GuiCoreError> {
        if self.schema != HOSTED_BINDING_REQUEST_SCHEMA_V1
            || self.version != 1
            || !valid_election_id(&self.election_id)
            || !valid_hex_32(&self.manifest_hash_hex)
        {
            return Err(invalid_handoff());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopBindingHandoffV1 {
    pub schema: String,
    pub version: u64,
    pub election_id: String,
    pub manifest_hash_hex: String,
    pub transport_binding_cbor_hex: String,
    pub transport_descriptor_cbor_hex: String,
}

impl DesktopBindingHandoffV1 {
    #[must_use]
    pub fn new(
        election_id: String,
        manifest_hash_hex: String,
        transport_binding_cbor_hex: String,
        transport_descriptor_cbor_hex: String,
    ) -> Self {
        Self {
            schema: DESKTOP_BINDING_HANDOFF_SCHEMA_V1.to_owned(),
            version: 1,
            election_id,
            manifest_hash_hex,
            transport_binding_cbor_hex,
            transport_descriptor_cbor_hex,
        }
    }

    pub fn validate(&self) -> Result<(), GuiCoreError> {
        if self.schema != DESKTOP_BINDING_HANDOFF_SCHEMA_V1
            || self.version != 1
            || !valid_election_id(&self.election_id)
            || !valid_hex_32(&self.manifest_hash_hex)
            || !valid_even_hex(&self.transport_binding_cbor_hex)
            || !valid_even_hex(&self.transport_descriptor_cbor_hex)
        {
            return Err(invalid_handoff());
        }
        Ok(())
    }
}

fn valid_election_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_hex_32(value: &str) -> bool {
    value.len() == 64 && valid_even_hex(value)
}

fn valid_even_hex(value: &str) -> bool {
    !value.is_empty() && value.len() % 2 == 0 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn invalid_handoff() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_HOSTED_BINDING_HANDOFF_INVALID",
        GuiErrorCategory::InvalidInput,
        Some("hosted-binding-handoff"),
        "the Desktop and Hosted binding handoff is invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_artifacts_require_exact_schema_and_public_identity() {
        let request = HostedBindingRequestV1::new("election-1".to_owned(), "ab".repeat(32));
        assert!(request.validate().is_ok());
        let response = DesktopBindingHandoffV1::new(
            "election-1".to_owned(),
            "ab".repeat(32),
            "80".to_owned(),
            "81".to_owned(),
        );
        assert!(response.validate().is_ok());
        assert!(
            DesktopBindingHandoffV1 {
                election_id: "wrong space".to_owned(),
                ..response
            }
            .validate()
            .is_err()
        );
    }
}
