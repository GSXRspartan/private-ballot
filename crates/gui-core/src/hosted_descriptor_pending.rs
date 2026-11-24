//! Durable Desktop state for one browser-mediated Hosted descriptor request.
//!
//! This record contains only public request material and a local opaque
//! transport-state identifier. The corresponding gateway and receipt private
//! keys are held by the Desktop transport store; neither they nor a Hosted
//! organizer credential can appear in this format.

use tari_cc_private_ballot_protocol::{CanonicalCborReader, CanonicalCborWriter, ManifestHash};

use crate::{
    HostedDescriptorRequestV1, HostedDescriptorResponseV1, TransportAuthorityRootSetV1,
    TransportDescriptorV1, TransportError,
};

pub const HOSTED_DESCRIPTOR_PENDING_STATE_TYPE_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_HOSTED_DESCRIPTOR_PENDING_STATE_V1";
pub const HOSTED_DESCRIPTOR_PENDING_STATE_VERSION_V1: u64 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostedDescriptorPendingStatusV1 {
    Pending,
    Provisioning,
    Completed,
}

impl HostedDescriptorPendingStatusV1 {
    const fn code(self) -> u64 {
        match self {
            Self::Pending => 0,
            Self::Provisioning => 1,
            Self::Completed => 2,
        }
    }

    fn from_code(code: u64) -> Result<Self, TransportError> {
        match code {
            0 => Ok(Self::Pending),
            1 => Ok(Self::Provisioning),
            2 => Ok(Self::Completed),
            _ => Err(TransportError::InvalidDescriptor),
        }
    }
}

/// The local side of the request/response exchange. `transport_state_id` is a
/// random, local-only handle for the separately persisted private keys. It is
/// intentionally not a key and cannot grant authority by itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedDescriptorPendingStateV1 {
    request: HostedDescriptorRequestV1,
    workspace_election_id: Vec<u8>,
    workspace_manifest_hash: ManifestHash,
    transport_state_id: [u8; 32],
    status: HostedDescriptorPendingStatusV1,
    completed_response: Option<HostedDescriptorResponseV1>,
}

impl HostedDescriptorPendingStateV1 {
    pub fn new(
        request: HostedDescriptorRequestV1,
        workspace_election_id: Vec<u8>,
        workspace_manifest_hash: ManifestHash,
        transport_state_id: [u8; 32],
    ) -> Result<Self, TransportError> {
        if workspace_election_id.is_empty()
            || transport_state_id == [0; 32]
            || request.election_id() != workspace_election_id
            || request.manifest_hash() != workspace_manifest_hash
        {
            return Err(TransportError::WrongElection);
        }
        Ok(Self {
            request,
            workspace_election_id,
            workspace_manifest_hash,
            transport_state_id,
            status: HostedDescriptorPendingStatusV1::Pending,
            completed_response: None,
        })
    }

    #[must_use]
    pub fn request(&self) -> &HostedDescriptorRequestV1 {
        &self.request
    }

    #[must_use]
    pub const fn transport_state_id(&self) -> [u8; 32] {
        self.transport_state_id
    }

    #[must_use]
    pub const fn status(&self) -> HostedDescriptorPendingStatusV1 {
        self.status
    }

    #[must_use]
    pub fn completed_descriptor(&self) -> Option<&TransportDescriptorV1> {
        self.completed_response
            .as_ref()
            .map(HostedDescriptorResponseV1::descriptor)
    }

    /// Verifies that local Desktop private-key storage still derives the exact
    /// public transport identity embedded in the request. Call this before
    /// accepting a response or starting an intake.
    pub fn verify_local_transport_identity(
        &self,
        gateway_public_key: [u8; 32],
        receipt_verification_key: [u8; 32],
    ) -> Result<(), TransportError> {
        let draft = self.request.descriptor_draft();
        if draft.gateway_public_key() != gateway_public_key
            || draft.receipt_verification_keys() != [receipt_verification_key]
        {
            return Err(TransportError::WrongGatewayKey);
        }
        Ok(())
    }

    /// Validates a canonical Hosted response against every locally persisted
    /// request/workspace/public-parameter boundary. A valid authority signature
    /// alone is deliberately insufficient.
    pub fn verify_response(
        &self,
        response: &HostedDescriptorResponseV1,
        roots: &TransportAuthorityRootSetV1,
        current_workspace_election_id: &[u8],
        current_workspace_manifest_hash: ManifestHash,
    ) -> Result<TransportDescriptorV1, TransportError> {
        if current_workspace_election_id != self.workspace_election_id
            || current_workspace_manifest_hash != self.workspace_manifest_hash
            || self.request.election_id() != self.workspace_election_id
            || self.request.manifest_hash() != self.workspace_manifest_hash
            || response.request_id() != self.request.request_id()
            || response.network() != self.request.network()
            || response.election_id() != self.workspace_election_id
            || response.manifest_hash() != self.workspace_manifest_hash
            || !response
                .descriptor()
                .same_public_parameters_as(self.request.descriptor_draft())
        {
            return Err(TransportError::WrongElection);
        }
        roots.verify_descriptor(response.descriptor(), self.workspace_manifest_hash)?;
        match &self.completed_response {
            Some(existing) if existing == response => Ok(response.descriptor().clone()),
            Some(_) => Err(TransportError::DescriptorConflict),
            None => Ok(response.descriptor().clone()),
        }
    }

    /// Durable transition written before provisioning begins. A caller must
    /// persist this state atomically before it makes any intake-visible change.
    pub fn begin_provisioning(&self) -> Result<Self, TransportError> {
        if self.status != HostedDescriptorPendingStatusV1::Pending {
            return Err(TransportError::DescriptorConflict);
        }
        let mut output = self.clone();
        output.status = HostedDescriptorPendingStatusV1::Provisioning;
        Ok(output)
    }

    /// Durable final transition after the local intake and issued descriptor
    /// have been persisted. It cannot replace an existing completed response.
    pub fn complete(&self, response: HostedDescriptorResponseV1) -> Result<Self, TransportError> {
        if self.status != HostedDescriptorPendingStatusV1::Provisioning {
            return Err(TransportError::DescriptorConflict);
        }
        let mut output = self.clone();
        output.status = HostedDescriptorPendingStatusV1::Completed;
        output.completed_response = Some(response);
        Ok(output)
    }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, TransportError> {
        let request = self.request.to_canonical_cbor()?;
        let response = match &self.completed_response {
            Some(response) => response.to_canonical_cbor()?,
            None => Vec::new(),
        };
        let mut writer = CanonicalCborWriter::new();
        writer
            .write_array_len(8)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(HOSTED_DESCRIPTOR_PENDING_STATE_VERSION_V1);
        writer
            .write_text_string(HOSTED_DESCRIPTOR_PENDING_STATE_TYPE_V1)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(self.status.code());
        writer
            .write_byte_string(&request)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(&self.workspace_election_id)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(self.workspace_manifest_hash.as_bytes())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(&self.transport_state_id)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(&response)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        Ok(writer.into_bytes())
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TransportError> {
        let mut reader = CanonicalCborReader::new(bytes);
        if reader
            .read_array_len()
            .map_err(|_| TransportError::InvalidDescriptor)?
            != 8
            || reader
                .read_unsigned()
                .map_err(|_| TransportError::InvalidDescriptor)?
                != HOSTED_DESCRIPTOR_PENDING_STATE_VERSION_V1
            || reader
                .read_text_string()
                .map_err(|_| TransportError::InvalidDescriptor)?
                != HOSTED_DESCRIPTOR_PENDING_STATE_TYPE_V1
        {
            return Err(TransportError::InvalidDescriptor);
        }
        let status = HostedDescriptorPendingStatusV1::from_code(
            reader
                .read_unsigned()
                .map_err(|_| TransportError::InvalidDescriptor)?,
        )?;
        let request = HostedDescriptorRequestV1::from_canonical_cbor(
            reader
                .read_byte_string()
                .map_err(|_| TransportError::InvalidDescriptor)?,
        )?;
        let workspace_election_id = reader
            .read_byte_string()
            .map_err(|_| TransportError::InvalidDescriptor)?
            .to_vec();
        let workspace_manifest_hash = ManifestHash::new(read_fixed_32(&mut reader)?);
        let transport_state_id = read_fixed_32(&mut reader)?;
        let response_bytes = reader
            .read_byte_string()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        reader
            .finish()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        let mut output = Self::new(
            request,
            workspace_election_id,
            workspace_manifest_hash,
            transport_state_id,
        )?;
        output.status = status;
        output.completed_response = match status {
            HostedDescriptorPendingStatusV1::Completed => {
                Some(HostedDescriptorResponseV1::from_canonical_cbor(response_bytes)?)
            }
            HostedDescriptorPendingStatusV1::Pending | HostedDescriptorPendingStatusV1::Provisioning
                if response_bytes.is_empty() => None,
            _ => return Err(TransportError::InvalidDescriptor),
        };
        if output.to_canonical_cbor()? != bytes {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(output)
    }
}

fn read_fixed_32(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], TransportError> {
    reader
        .read_byte_string()
        .map_err(|_| TransportError::InvalidDescriptor)?
        .try_into()
        .map_err(|_| TransportError::InvalidDescriptor)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use tari_cc_private_ballot_protocol::ManifestHash;

    use super::*;
    use crate::{
        BatchPolicyV1, PaddingPolicyV1, TransportAuthorityRootV1, TransportRoutePolicyV1,
    };

    fn request() -> (HostedDescriptorRequestV1, SigningKey) {
        let signing = SigningKey::from_bytes(&[41; 32]);
        let descriptor = TransportDescriptorV1::unsigned_for_authority(
            b"pending-election".to_vec(),
            ManifestHash::new([7; 32]),
            1,
            TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["http://desktop-test.invalid".to_owned()],
            Vec::new(),
            [8; 32],
            "desktop-gateway".to_owned(),
            vec![[9; 32]],
            PaddingPolicyV1 {
                id: "test-padding".to_owned(),
                padded_bytes: 2048,
            },
            BatchPolicyV1 {
                id: "test-batch".to_owned(),
                accepted_unique_floor: 1,
            },
            None,
            "hosted-test-root".to_owned(),
        )
        .expect("draft");
        (
            HostedDescriptorRequestV1::new([6; 32], "test".to_owned(), descriptor)
                .expect("request"),
            signing,
        )
    }

    fn signed_response(request: &HostedDescriptorRequestV1, signing: &SigningKey) -> HostedDescriptorResponseV1 {
        let signature = signing
            .sign(
                &request
                    .descriptor_draft()
                    .authority_signing_payload()
                    .expect("payload"),
            )
            .to_bytes();
        HostedDescriptorResponseV1::new(
            request,
            request
                .descriptor_draft()
                .with_authority_signature(signature)
                .expect("signed descriptor"),
        )
        .expect("response")
    }

    #[test]
    fn pending_state_round_trips_and_requires_exact_signed_response() {
        let (request, signing) = request();
        let mut pending = HostedDescriptorPendingStateV1::new(
            request.clone(),
            b"pending-election".to_vec(),
            ManifestHash::new([7; 32]),
            [3; 32],
        )
        .expect("pending");
        let encoded = pending.to_canonical_cbor().expect("encode");
        pending = HostedDescriptorPendingStateV1::from_canonical_cbor(&encoded).expect("decode");
        assert_eq!(pending.status(), HostedDescriptorPendingStatusV1::Pending);
        pending
            .verify_local_transport_identity([8; 32], [9; 32])
            .expect("local keys");
        assert!(pending.verify_local_transport_identity([8; 32], [4; 32]).is_err());

        let response = signed_response(&request, &signing);
        let roots = TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
            key_id: "hosted-test-root".to_owned(),
            public_key: signing.verifying_key().to_bytes(),
        });
        pending
            .verify_response(
                &response,
                &roots,
                b"pending-election",
                ManifestHash::new([7; 32]),
            )
            .expect("exact response");
        assert!(pending
            .verify_response(
                &response,
                &roots,
                b"other-election",
                ManifestHash::new([7; 32]),
            )
            .is_err());
        let provisioning = pending.begin_provisioning().expect("transition");
        let completed = provisioning.complete(response).expect("completion");
        assert_eq!(completed.status(), HostedDescriptorPendingStatusV1::Completed);
        assert!(completed.completed_descriptor().is_some());
        assert!(completed.begin_provisioning().is_err());
        let completed_bytes = completed.to_canonical_cbor().expect("completed cbor");
        assert_eq!(
            HostedDescriptorPendingStateV1::from_canonical_cbor(&completed_bytes)
                .expect("completed decode")
                .completed_descriptor(),
            completed.completed_descriptor()
        );
    }
}
