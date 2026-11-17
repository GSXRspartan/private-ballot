//! Canonical browser-mediated Hosted descriptor issuance artifacts.
//!
//! Neither artifact authenticates an organizer. The Hosted Manage browser
//! supplies its existing capability when it uploads a request; Desktop accepts
//! a response only when it matches a durable outstanding local request.

use tari_cc_private_ballot_protocol::{CanonicalCborReader, CanonicalCborWriter, ManifestHash};

use crate::{TransportDescriptorV1, TransportError};

pub const HOSTED_DESCRIPTOR_REQUEST_TYPE_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_HOSTED_DESCRIPTOR_REQUEST_V1";
pub const HOSTED_DESCRIPTOR_RESPONSE_TYPE_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_HOSTED_DESCRIPTOR_RESPONSE_V1";
pub const HOSTED_DESCRIPTOR_EXCHANGE_VERSION_V1: u64 = 1;
const MAX_NETWORK_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedDescriptorRequestV1 {
    request_id: [u8; 32],
    network: String,
    election_id: Vec<u8>,
    manifest_hash: ManifestHash,
    descriptor_draft: TransportDescriptorV1,
}

impl HostedDescriptorRequestV1 {
    pub fn new(
        request_id: [u8; 32],
        network: String,
        descriptor_draft: TransportDescriptorV1,
    ) -> Result<Self, TransportError> {
        if request_id == [0; 32]
            || network.is_empty()
            || network.len() > MAX_NETWORK_BYTES
            || !descriptor_draft.is_unsigned_authority_draft()
        {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(Self {
            request_id,
            network,
            election_id: descriptor_draft.election_id().to_vec(),
            manifest_hash: descriptor_draft.manifest_hash(),
            descriptor_draft,
        })
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 32] { self.request_id }
    #[must_use]
    pub fn network(&self) -> &str { &self.network }
    #[must_use]
    pub fn election_id(&self) -> &[u8] { &self.election_id }
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash { self.manifest_hash }
    #[must_use]
    pub fn descriptor_draft(&self) -> &TransportDescriptorV1 { &self.descriptor_draft }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, TransportError> {
        let draft = self.descriptor_draft.to_canonical_cbor()?;
        let mut w = CanonicalCborWriter::new();
        w.write_array_len(7).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_unsigned(HOSTED_DESCRIPTOR_EXCHANGE_VERSION_V1);
        w.write_text_string(HOSTED_DESCRIPTOR_REQUEST_TYPE_V1).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(&self.request_id).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_text_string(&self.network).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(&self.election_id).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(self.manifest_hash.as_bytes()).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(&draft).map_err(|_| TransportError::InvalidDescriptor)?;
        Ok(w.into_bytes())
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TransportError> {
        let mut r = CanonicalCborReader::new(bytes);
        if r.read_array_len().map_err(|_| TransportError::InvalidDescriptor)? != 7
            || r.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)? != HOSTED_DESCRIPTOR_EXCHANGE_VERSION_V1
            || r.read_text_string().map_err(|_| TransportError::InvalidDescriptor)? != HOSTED_DESCRIPTOR_REQUEST_TYPE_V1 {
            return Err(TransportError::InvalidDescriptor);
        }
        let request_id = fixed_32(&mut r)?;
        let network = r.read_text_string().map_err(|_| TransportError::InvalidDescriptor)?.to_owned();
        let election_id = r.read_byte_string().map_err(|_| TransportError::InvalidDescriptor)?.to_vec();
        let manifest_hash = ManifestHash::new(fixed_32(&mut r)?);
        let draft = TransportDescriptorV1::from_canonical_cbor(r.read_byte_string().map_err(|_| TransportError::InvalidDescriptor)?)?;
        r.finish().map_err(|_| TransportError::InvalidDescriptor)?;
        let output = Self::new(request_id, network, draft)?;
        if output.election_id != election_id || output.manifest_hash != manifest_hash || output.to_canonical_cbor()? != bytes {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedDescriptorResponseV1 {
    request_id: [u8; 32],
    network: String,
    election_id: Vec<u8>,
    manifest_hash: ManifestHash,
    descriptor: TransportDescriptorV1,
}

impl HostedDescriptorResponseV1 {
    pub fn new(request: &HostedDescriptorRequestV1, descriptor: TransportDescriptorV1) -> Result<Self, TransportError> {
        if descriptor.is_unsigned_authority_draft()
            || descriptor.election_id() != request.election_id
            || descriptor.manifest_hash() != request.manifest_hash
            || !descriptor.same_public_parameters_as(&request.descriptor_draft) {
            return Err(TransportError::WrongElection);
        }
        Ok(Self { request_id: request.request_id, network: request.network.clone(), election_id: request.election_id.clone(), manifest_hash: request.manifest_hash, descriptor })
    }

    #[must_use]
    pub const fn request_id(&self) -> [u8; 32] { self.request_id }
    #[must_use]
    pub fn network(&self) -> &str { &self.network }
    #[must_use]
    pub fn election_id(&self) -> &[u8] { &self.election_id }
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash { self.manifest_hash }
    #[must_use]
    pub fn descriptor(&self) -> &TransportDescriptorV1 { &self.descriptor }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, TransportError> {
        let descriptor = self.descriptor.to_canonical_cbor()?;
        let mut w = CanonicalCborWriter::new();
        w.write_array_len(7).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_unsigned(HOSTED_DESCRIPTOR_EXCHANGE_VERSION_V1);
        w.write_text_string(HOSTED_DESCRIPTOR_RESPONSE_TYPE_V1).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(&self.request_id).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_text_string(&self.network).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(&self.election_id).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(self.manifest_hash.as_bytes()).map_err(|_| TransportError::InvalidDescriptor)?;
        w.write_byte_string(&descriptor).map_err(|_| TransportError::InvalidDescriptor)?;
        Ok(w.into_bytes())
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TransportError> {
        let mut r = CanonicalCborReader::new(bytes);
        if r.read_array_len().map_err(|_| TransportError::InvalidDescriptor)? != 7
            || r.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)? != HOSTED_DESCRIPTOR_EXCHANGE_VERSION_V1
            || r.read_text_string().map_err(|_| TransportError::InvalidDescriptor)? != HOSTED_DESCRIPTOR_RESPONSE_TYPE_V1 {
            return Err(TransportError::InvalidDescriptor);
        }
        let request_id = fixed_32(&mut r)?;
        let network = r.read_text_string().map_err(|_| TransportError::InvalidDescriptor)?.to_owned();
        let election_id = r.read_byte_string().map_err(|_| TransportError::InvalidDescriptor)?.to_vec();
        let manifest_hash = ManifestHash::new(fixed_32(&mut r)?);
        let descriptor = TransportDescriptorV1::from_canonical_cbor(r.read_byte_string().map_err(|_| TransportError::InvalidDescriptor)?)?;
        r.finish().map_err(|_| TransportError::InvalidDescriptor)?;
        if request_id == [0; 32]
            || network.is_empty()
            || network.len() > MAX_NETWORK_BYTES
            || descriptor.is_unsigned_authority_draft()
            || descriptor.election_id() != election_id || descriptor.manifest_hash() != manifest_hash {
            return Err(TransportError::InvalidDescriptor);
        }
        let output = Self { request_id, network, election_id, manifest_hash, descriptor };
        if output.to_canonical_cbor()? != bytes { return Err(TransportError::InvalidDescriptor); }
        Ok(output)
    }
}

fn fixed_32(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], TransportError> {
    reader.read_byte_string().map_err(|_| TransportError::InvalidDescriptor)?
        .try_into().map_err(|_| TransportError::InvalidDescriptor)
}
