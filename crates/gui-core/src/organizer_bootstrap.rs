//! Canonical Hosted-to-Desktop organizer bootstrap artifact.
//!
//! This is deliberately distinct from public election files: only a signature
//! under the configured release authority permits organizer-state creation.

use tari_cc_private_ballot_protocol::{
    CanonicalCborReader, CanonicalCborWriter, MAX_CANONICAL_OBJECT_BYTES,
};

use crate::{GuiCoreError, GuiElectionArtifactsV1, TransportAuthorityRootSetV1};

pub const HOSTED_ORGANIZER_BOOTSTRAP_TYPE_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_HOSTED_ORGANIZER_BOOTSTRAP_V1";
pub const HOSTED_ORGANIZER_BOOTSTRAP_VERSION_V1: u64 = 1;
const SIGNING_DOMAIN: &[u8] = b"tari-cc-private-ballot/hosted-organizer-bootstrap/v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedOrganizerBootstrapV1 {
    authority_key_id: String,
    election_id: Vec<u8>,
    manifest_hash: [u8; 32],
    manifest_cbor: Vec<u8>,
    registry_cbor: Vec<u8>,
    candidate_cbor: Vec<u8>,
    signature: [u8; 64],
}

impl HostedOrganizerBootstrapV1 {
    /// Creates an artifact after the Hosted authority has signed the exact
    /// canonical V2 election payload returned by [`Self::signing_payload`].
    pub fn new_signed(
        authority_key_id: String,
        artifacts: &GuiElectionArtifactsV1,
        signature: [u8; 64],
    ) -> Result<Self, GuiCoreError> {
        let (manifest_cbor, registry_cbor, candidate_cbor) = canonical_artifact_bytes(artifacts)?;
        let manifest = artifacts.manifest();
        if manifest.proposal_question().is_none() || authority_key_id.is_empty() {
            return Err(bootstrap_error());
        }
        Ok(Self {
            authority_key_id,
            election_id: manifest.election_id().as_bytes().to_vec(),
            manifest_hash: *artifacts.manifest_hash().as_bytes(),
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            signature,
        })
    }

    /// Returns the dedicated, domain-separated bytes the authority signs.
    pub fn signing_payload(
        authority_key_id: &str,
        artifacts: &GuiElectionArtifactsV1,
    ) -> Result<Vec<u8>, GuiCoreError> {
        if artifacts.manifest().proposal_question().is_none() || authority_key_id.is_empty() {
            return Err(bootstrap_error());
        }
        let (manifest_cbor, registry_cbor, candidate_cbor) = canonical_artifact_bytes(artifacts)?;
        let mut writer = CanonicalCborWriter::new();
        writer.write_array_len(8).map_err(|_| bootstrap_error())?;
        writer.write_unsigned(HOSTED_ORGANIZER_BOOTSTRAP_VERSION_V1);
        writer
            .write_text_string(HOSTED_ORGANIZER_BOOTSTRAP_TYPE_V1)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_text_string(authority_key_id)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(artifacts.manifest().election_id().as_bytes())
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(artifacts.manifest_hash().as_bytes())
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&manifest_cbor)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&registry_cbor)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&candidate_cbor)
            .map_err(|_| bootstrap_error())?;
        Ok([SIGNING_DOMAIN, &writer.into_bytes()].concat())
    }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, GuiCoreError> {
        let mut writer = CanonicalCborWriter::new();
        writer.write_array_len(9).map_err(|_| bootstrap_error())?;
        writer.write_unsigned(HOSTED_ORGANIZER_BOOTSTRAP_VERSION_V1);
        writer
            .write_text_string(HOSTED_ORGANIZER_BOOTSTRAP_TYPE_V1)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_text_string(&self.authority_key_id)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&self.election_id)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&self.manifest_hash)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&self.manifest_cbor)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&self.registry_cbor)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&self.candidate_cbor)
            .map_err(|_| bootstrap_error())?;
        writer
            .write_byte_string(&self.signature)
            .map_err(|_| bootstrap_error())?;
        Ok(writer.into_bytes())
    }

    /// Strictly decodes one canonical artifact. Re-encoding equality rejects
    /// alternate CBOR encodings and trailing input before verification.
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, GuiCoreError> {
        let max_bootstrap_bytes = MAX_CANONICAL_OBJECT_BYTES
            .saturating_mul(3)
            .saturating_add(2048);
        if bytes.len() > max_bootstrap_bytes {
            return Err(bootstrap_error());
        }
        let mut reader = CanonicalCborReader::new(bytes);
        if reader.read_array_len().map_err(|_| bootstrap_error())? != 9 {
            return Err(bootstrap_error());
        }
        if reader.read_unsigned().map_err(|_| bootstrap_error())?
            != HOSTED_ORGANIZER_BOOTSTRAP_VERSION_V1
            || reader.read_text_string().map_err(|_| bootstrap_error())?
                != HOSTED_ORGANIZER_BOOTSTRAP_TYPE_V1
        {
            return Err(bootstrap_error());
        }
        let authority_key_id = reader
            .read_text_string()
            .map_err(|_| bootstrap_error())?
            .to_owned();
        let election_id = reader
            .read_byte_string()
            .map_err(|_| bootstrap_error())?
            .to_vec();
        let manifest_hash = read_fixed_32(&mut reader)?;
        let manifest_cbor = reader
            .read_byte_string()
            .map_err(|_| bootstrap_error())?
            .to_vec();
        let registry_cbor = reader
            .read_byte_string()
            .map_err(|_| bootstrap_error())?
            .to_vec();
        let candidate_cbor = reader
            .read_byte_string()
            .map_err(|_| bootstrap_error())?
            .to_vec();
        let signature = read_fixed_64(&mut reader)?;
        reader.finish().map_err(|_| bootstrap_error())?;
        let output = Self {
            authority_key_id,
            election_id,
            manifest_hash,
            manifest_cbor,
            registry_cbor,
            candidate_cbor,
            signature,
        };
        if output.to_canonical_cbor()? != bytes {
            return Err(bootstrap_error());
        }
        Ok(output)
    }

    /// Verifies both the exact embedded V2 election and its authority
    /// signature before returning usable public election artifacts.
    pub fn verify(
        &self,
        roots: &TransportAuthorityRootSetV1,
    ) -> Result<GuiElectionArtifactsV1, GuiCoreError> {
        let artifacts = GuiElectionArtifactsV1::from_bytes(
            &self.manifest_cbor,
            &self.registry_cbor,
            &self.candidate_cbor,
        )?;
        if artifacts.manifest().proposal_question().is_none()
            || artifacts.manifest().election_id().as_bytes() != self.election_id.as_slice()
            || artifacts.manifest_hash().as_bytes() != self.manifest_hash.as_slice()
        {
            return Err(bootstrap_error());
        }
        let payload = Self::signing_payload(&self.authority_key_id, &artifacts)?;
        roots
            .verify_by_root_id(&self.authority_key_id, &payload, &self.signature)
            .map_err(|_| bootstrap_error())?;
        Ok(artifacts)
    }
}

fn canonical_artifact_bytes(
    artifacts: &GuiElectionArtifactsV1,
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), GuiCoreError> {
    let manifest = artifacts
        .manifest()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "organizer-bootstrap"))?;
    let registry = artifacts
        .registry()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "organizer-bootstrap"))?;
    let candidates = artifacts
        .candidates()
        .to_canonical_cbor()
        .map_err(|error| GuiCoreError::from_protocol(&error, "organizer-bootstrap"))?;
    Ok((manifest, registry, candidates))
}

fn read_fixed_32(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 32], GuiCoreError> {
    reader
        .read_byte_string()
        .map_err(|_| bootstrap_error())?
        .try_into()
        .map_err(|_| bootstrap_error())
}

fn read_fixed_64(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; 64], GuiCoreError> {
    reader
        .read_byte_string()
        .map_err(|_| bootstrap_error())?
        .try_into()
        .map_err(|_| bootstrap_error())
}

const fn bootstrap_error() -> GuiCoreError {
    GuiCoreError::new(
        "GUI_ORGANIZER_BOOTSTRAP_INVALID",
        crate::GuiErrorCategory::InvalidInput,
        Some("organizer-bootstrap"),
        "the organizer bootstrap artifact is invalid or not trusted",
    )
}
