//! Local-only private-transport foundation.
//!
//! This module never opens a socket. It authenticates a separately canonical
//! descriptor, encrypts exact canonical ballot-package bytes with the fixed
//! RFC 9180 suite, and hands recovered bytes to the existing 5A11 intake
//! boundary. Production online transport remains disabled until a release
//! provisions a pinned authority public key.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborReader, CanonicalCborWriter, HashDomain, ManifestHash,
    domain_separated_input, hash_domain_separated,
};

const DESCRIPTOR_VERSION: u64 = 1;
const ENVELOPE_VERSION: u64 = 1;
const PROTOCOL_ID: &str = "tari-cc-private-ballot/private-transport/v1";
const HPKE_SUITE_ID: &str = "DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/ChaCha20Poly1305";
const MAX_ENDPOINTS: usize = 8;
const MAX_ENDPOINT_BYTES: usize = 512;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_ENVELOPE_BYTES: usize = 1_048_576;
const HPKE_INFO: &[u8] = b"tari-cc-private-ballot/private-ballot-envelope/v1";

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

/// Bounded transport failures deliberately omit proof, nullifier, and intake details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    InvalidDescriptor,
    UntrustedRoot,
    DescriptorConflict,
    UnsupportedRoute,
    InvalidEnvelope,
    WrongElection,
    WrongDescriptor,
    WrongGatewayKey,
    CryptoFailure,
    OversizedPayload,
    Unavailable,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidDescriptor => "invalid transport descriptor",
            Self::UntrustedRoot => "transport authority root is not configured or trusted",
            Self::DescriptorConflict => "conflicting transport descriptor generation",
            Self::UnsupportedRoute => "transport route is not permitted",
            Self::InvalidEnvelope => "invalid transport request",
            Self::WrongElection => "transport request is for a different election",
            Self::WrongDescriptor => "transport request does not match the active descriptor",
            Self::WrongGatewayKey => "transport gateway key is not available",
            Self::CryptoFailure => "transport request could not be authenticated",
            Self::OversizedPayload => "ballot package exceeds the configured padding size",
            Self::Unavailable => "private transport is unavailable; use offline export or retry",
        };
        f.write_str(message)
    }
}

impl std::error::Error for TransportError {}

/// Release/bootstrap authority for transport configuration, not voter eligibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportAuthorityRootV1 {
    /// Production application state before the release ceremony provisions a public pin.
    ProductionNotProvisioned { key_id: String },
    /// A release-pinned public Ed25519 verification key.
    Pinned {
        key_id: String,
        public_key: [u8; 32],
    },
}

impl TransportAuthorityRootV1 {
    #[must_use]
    pub fn key_id(&self) -> &str {
        match self {
            Self::ProductionNotProvisioned { key_id } | Self::Pinned { key_id, .. } => key_id,
        }
    }

    fn verifying_key(&self) -> Result<VerifyingKey, TransportError> {
        let Self::Pinned { public_key, .. } = self else {
            return Err(TransportError::UntrustedRoot);
        };
        VerifyingKey::from_bytes(public_key).map_err(|_| TransportError::UntrustedRoot)
    }
}

/// Release-pinned root lifecycle. Descriptors select an already-known root by
/// ID; they can never install a new root. Historical roots remain verification
/// only, while revoked IDs are rejected before signature processing.
#[derive(Debug, Clone)]
pub struct TransportAuthorityRootSetV1 {
    current: TransportAuthorityRootV1,
    historical: BTreeMap<String, TransportAuthorityRootV1>,
    revoked: BTreeSet<String>,
}

impl TransportAuthorityRootSetV1 {
    #[must_use]
    pub fn new(current: TransportAuthorityRootV1) -> Self {
        Self {
            current,
            historical: BTreeMap::new(),
            revoked: BTreeSet::new(),
        }
    }

    pub fn add_historical_root(
        &mut self,
        root: TransportAuthorityRootV1,
    ) -> Result<(), TransportError> {
        if root.key_id() == self.current.key_id() || self.historical.contains_key(root.key_id()) {
            return Err(TransportError::InvalidDescriptor);
        }
        self.historical.insert(root.key_id().to_owned(), root);
        Ok(())
    }

    pub fn revoke_root_id(&mut self, key_id: String) {
        self.revoked.insert(key_id);
    }

    #[must_use]
    pub fn current_root_id(&self) -> &str {
        self.current.key_id()
    }

    pub fn verify_descriptor(
        &self,
        descriptor: &TransportDescriptorV1,
        expected_manifest: ManifestHash,
    ) -> Result<(), TransportError> {
        let root_id = descriptor.root_key_id();
        if self.revoked.contains(root_id) {
            return Err(TransportError::UntrustedRoot);
        }
        let root = if root_id == self.current.key_id() {
            &self.current
        } else {
            self.historical
                .get(root_id)
                .ok_or(TransportError::UntrustedRoot)?
        };
        descriptor.verify(root, expected_manifest)
    }

    /// Verifies a descriptor against an already configured root and records
    /// its generation/fingerprint consistency. The descriptor is never a
    /// source of trust: root lookup, revocation, signature verification, and
    /// manifest binding all happen before its route, endpoints, or gateway
    /// key may be used.
    pub fn verify_and_accept_descriptor(
        &self,
        descriptor: &TransportDescriptorV1,
        expected_manifest: ManifestHash,
        consistency: &mut DescriptorConsistencyStoreV1,
    ) -> Result<[u8; 32], TransportError> {
        let root_id = descriptor.root_key_id();
        if self.revoked.contains(root_id) {
            return Err(TransportError::UntrustedRoot);
        }
        let root = if root_id == self.current.key_id() {
            &self.current
        } else {
            self.historical
                .get(root_id)
                .ok_or(TransportError::UntrustedRoot)?
        };
        descriptor.verify(root, expected_manifest)?;
        consistency.accept(descriptor, root, expected_manifest)
    }
}

/// Explicit release state: no production transport authority has been provisioned.
#[must_use]
pub fn production_transport_authority_root_v1() -> TransportAuthorityRootV1 {
    TransportAuthorityRootV1::ProductionNotProvisioned {
        key_id: "PRODUCTION_TRANSPORT_ROOT_NOT_YET_PROVISIONED".to_owned(),
    }
}

/// Permitted future carrier; none opens a connection in this slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportRoutePolicyV1 {
    OfflineOnly,
    ManagedTorOrOffline,
    RelayOrOffline,
}

impl TransportRoutePolicyV1 {
    const fn code(self) -> u64 {
        match self {
            Self::OfflineOnly => 0,
            Self::ManagedTorOrOffline => 1,
            Self::RelayOrOffline => 2,
        }
    }

    fn from_code(code: u64) -> Result<Self, TransportError> {
        match code {
            0 => Ok(Self::OfflineOnly),
            1 => Ok(Self::ManagedTorOrOffline),
            2 => Ok(Self::RelayOrOffline),
            _ => Err(TransportError::InvalidDescriptor),
        }
    }
}

/// Fixed pre-encryption padding profile. It reduces package-size leakage only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddingPolicyV1 {
    pub id: String,
    pub padded_bytes: usize,
}

/// Batch policy counts only distinct accepted valid ballots toward its threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchPolicyV1 {
    pub id: String,
    pub accepted_unique_floor: u64,
}

/// Unsigned fields of the separately canonical transport descriptor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportDescriptorV1 {
    election_id: Vec<u8>,
    manifest_hash: ManifestHash,
    generation: u64,
    route: TransportRoutePolicyV1,
    onion_endpoints: Vec<String>,
    relay_endpoints: Vec<String>,
    gateway_public_key: [u8; 32],
    gateway_key_id: String,
    receipt_verification_keys: Vec<[u8; 32]>,
    padding: PaddingPolicyV1,
    batch: BatchPolicyV1,
    validity_end_epoch: Option<u64>,
    root_key_id: String,
    signature: [u8; 64],
}

impl TransportDescriptorV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn sign_for_test_or_ceremony(
        election_id: Vec<u8>,
        manifest_hash: ManifestHash,
        generation: u64,
        route: TransportRoutePolicyV1,
        onion_endpoints: Vec<String>,
        relay_endpoints: Vec<String>,
        gateway_public_key: [u8; 32],
        gateway_key_id: String,
        receipt_verification_keys: Vec<[u8; 32]>,
        padding: PaddingPolicyV1,
        batch: BatchPolicyV1,
        validity_end_epoch: Option<u64>,
        root_key_id: String,
        signing_key: &SigningKey,
    ) -> Result<Self, TransportError> {
        let mut descriptor = Self {
            election_id,
            manifest_hash,
            generation,
            route,
            onion_endpoints,
            relay_endpoints,
            gateway_public_key,
            gateway_key_id,
            receipt_verification_keys,
            padding,
            batch,
            validity_end_epoch,
            root_key_id,
            signature: [0; 64],
        };
        descriptor.validate_fields()?;
        descriptor.signature = signing_key.sign(&descriptor.signing_message()?).to_bytes();
        Ok(descriptor)
    }

    #[must_use]
    pub fn manifest_hash(&self) -> ManifestHash {
        self.manifest_hash
    }
    /// Canonical election identifier bound by this descriptor.
    #[must_use]
    pub fn election_id(&self) -> &[u8] {
        &self.election_id
    }
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation
    }
    #[must_use]
    pub fn gateway_public_key(&self) -> [u8; 32] {
        self.gateway_public_key
    }
    #[must_use]
    pub fn gateway_key_id(&self) -> &str {
        &self.gateway_key_id
    }
    /// Authority root selector, used only to look up a release-pinned root.
    #[must_use]
    pub fn root_key_id(&self) -> &str {
        &self.root_key_id
    }
    #[must_use]
    pub fn padding(&self) -> &PaddingPolicyV1 {
        &self.padding
    }
    #[must_use]
    pub fn batch(&self) -> &BatchPolicyV1 {
        &self.batch
    }
    #[must_use]
    pub fn route(&self) -> TransportRoutePolicyV1 {
        self.route
    }
    /// Public keys authorized by this signed descriptor to verify receipts.
    /// They are distinct from voter, Triptych, wallet, and Ootle keys.
    #[must_use]
    pub fn receipt_verification_keys(&self) -> &[[u8; 32]] {
        &self.receipt_verification_keys
    }
    /// The only compiled HPKE suite; no runtime suite negotiation is permitted.
    #[must_use]
    pub const fn hpke_suite_id(&self) -> &'static str {
        HPKE_SUITE_ID
    }

    pub fn verify(
        &self,
        root: &TransportAuthorityRootV1,
        expected_manifest: ManifestHash,
    ) -> Result<(), TransportError> {
        self.validate_fields()?;
        if self.manifest_hash != expected_manifest || self.root_key_id != root.key_id() {
            return Err(TransportError::WrongElection);
        }
        let key = root.verifying_key()?;
        let signature = Signature::from_bytes(&self.signature);
        key.verify_strict(&self.signing_message()?, &signature)
            .map_err(|_| TransportError::UntrustedRoot)
    }

    pub fn fingerprint(&self) -> Result<[u8; 32], TransportError> {
        Ok(hash_domain_separated(
            &Blake3HashProviderV1,
            HashDomain::TransportDescriptorV1,
            &self.to_canonical_cbor()?,
        ))
    }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, TransportError> {
        let mut writer = CanonicalCborWriter::new();
        self.write(&mut writer, true)?;
        Ok(writer.into_bytes())
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TransportError> {
        let mut reader = CanonicalCborReader::new(bytes);
        if reader
            .read_array_len()
            .map_err(|_| TransportError::InvalidDescriptor)?
            != 17
        {
            return Err(TransportError::InvalidDescriptor);
        }
        let version = reader
            .read_unsigned()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        let protocol = reader
            .read_text_string()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        if version != DESCRIPTOR_VERSION || protocol != PROTOCOL_ID {
            return Err(TransportError::InvalidDescriptor);
        }
        let election_id = reader
            .read_byte_string()
            .map_err(|_| TransportError::InvalidDescriptor)?
            .to_vec();
        let manifest_hash = ManifestHash::new(read_fixed(&mut reader)?);
        let generation = reader
            .read_unsigned()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        let route = TransportRoutePolicyV1::from_code(
            reader
                .read_unsigned()
                .map_err(|_| TransportError::InvalidDescriptor)?,
        )?;
        let onion_endpoints = read_text_vec(&mut reader)?;
        let relay_endpoints = read_text_vec(&mut reader)?;
        let gateway_public_key = read_fixed(&mut reader)?;
        let gateway_key_id = reader
            .read_text_string()
            .map_err(|_| TransportError::InvalidDescriptor)?
            .to_owned();
        let receipt_verification_keys = read_key_vec(&mut reader)?;
        let padding = PaddingPolicyV1 {
            id: reader
                .read_text_string()
                .map_err(|_| TransportError::InvalidDescriptor)?
                .to_owned(),
            padded_bytes: usize::try_from(
                reader
                    .read_unsigned()
                    .map_err(|_| TransportError::InvalidDescriptor)?,
            )
            .map_err(|_| TransportError::InvalidDescriptor)?,
        };
        let batch = BatchPolicyV1 {
            id: reader
                .read_text_string()
                .map_err(|_| TransportError::InvalidDescriptor)?
                .to_owned(),
            accepted_unique_floor: reader
                .read_unsigned()
                .map_err(|_| TransportError::InvalidDescriptor)?,
        };
        let validity = reader
            .read_unsigned()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        let suite = reader
            .read_text_string()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        if suite != HPKE_SUITE_ID {
            return Err(TransportError::InvalidDescriptor);
        }
        let root_key_id = reader
            .read_text_string()
            .map_err(|_| TransportError::InvalidDescriptor)?
            .to_owned();
        let signature = read_fixed(&mut reader)?;
        reader
            .finish()
            .map_err(|_| TransportError::InvalidDescriptor)?;
        let descriptor = Self {
            election_id,
            manifest_hash,
            generation,
            route,
            onion_endpoints,
            relay_endpoints,
            gateway_public_key,
            gateway_key_id,
            receipt_verification_keys,
            padding,
            batch,
            validity_end_epoch: (validity != 0).then_some(validity),
            root_key_id,
            signature,
        };
        descriptor.validate_fields()?;
        if descriptor.to_canonical_cbor()? != bytes {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(descriptor)
    }

    fn signing_message(&self) -> Result<Vec<u8>, TransportError> {
        Ok(domain_separated_input(
            HashDomain::TransportDescriptorV1,
            &self.unsigned_canonical_cbor()?,
        ))
    }
    fn unsigned_canonical_cbor(&self) -> Result<Vec<u8>, TransportError> {
        let mut writer = CanonicalCborWriter::new();
        self.write(&mut writer, false)?;
        Ok(writer.into_bytes())
    }
    fn write(
        &self,
        writer: &mut CanonicalCborWriter,
        include_signature: bool,
    ) -> Result<(), TransportError> {
        self.validate_fields()?;
        writer
            .write_array_len(if include_signature { 17 } else { 16 })
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(DESCRIPTOR_VERSION);
        writer
            .write_text_string(PROTOCOL_ID)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(&self.election_id)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(self.manifest_hash.as_bytes())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(self.generation);
        writer.write_unsigned(self.route.code());
        write_text_vec(writer, &self.onion_endpoints)?;
        write_text_vec(writer, &self.relay_endpoints)?;
        writer
            .write_byte_string(&self.gateway_public_key)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_text_string(&self.gateway_key_id)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_array_len(self.receipt_verification_keys.len())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        for key in &self.receipt_verification_keys {
            writer
                .write_byte_string(key)
                .map_err(|_| TransportError::InvalidDescriptor)?;
        }
        writer
            .write_text_string(&self.padding.id)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(self.padding.padded_bytes as u64);
        writer
            .write_text_string(&self.batch.id)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(self.batch.accepted_unique_floor);
        writer.write_unsigned(self.validity_end_epoch.unwrap_or(0));
        writer
            .write_text_string(HPKE_SUITE_ID)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_text_string(&self.root_key_id)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        if include_signature {
            writer
                .write_byte_string(&self.signature)
                .map_err(|_| TransportError::InvalidDescriptor)?;
        }
        Ok(())
    }
    fn validate_fields(&self) -> Result<(), TransportError> {
        if self.election_id.is_empty()
            || self.election_id.len() > 128
            || self.gateway_key_id.is_empty()
            || self.gateway_key_id.len() > MAX_KEY_ID_BYTES
            || self.root_key_id.is_empty()
            || self.root_key_id.len() > MAX_KEY_ID_BYTES
            || self.padding.id.is_empty()
            || self.batch.id.is_empty()
            || self.padding.padded_bytes < 4
            || self.padding.padded_bytes > MAX_ENVELOPE_BYTES
            || self.receipt_verification_keys.len() > MAX_ENDPOINTS
        {
            return Err(TransportError::InvalidDescriptor);
        }
        if self.onion_endpoints.len() > MAX_ENDPOINTS
            || self.relay_endpoints.len() > MAX_ENDPOINTS
            || self
                .onion_endpoints
                .iter()
                .chain(&self.relay_endpoints)
                .any(|v| v.is_empty() || v.len() > MAX_ENDPOINT_BYTES)
        {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(())
    }
}

/// First-authenticated-load pinning plus same-generation conflict detection.
#[derive(Debug, Default)]
pub struct DescriptorConsistencyStoreV1 {
    active: BTreeMap<(Vec<u8>, u64), [u8; 32]>,
}
impl DescriptorConsistencyStoreV1 {
    pub fn accept(
        &mut self,
        descriptor: &TransportDescriptorV1,
        root: &TransportAuthorityRootV1,
        manifest: ManifestHash,
    ) -> Result<[u8; 32], TransportError> {
        descriptor.verify(root, manifest)?;
        let fingerprint = descriptor.fingerprint()?;
        let key = (descriptor.election_id.clone(), descriptor.generation);
        if let Some(existing) = self.active.get(&key) {
            if existing != &fingerprint {
                return Err(TransportError::DescriptorConflict);
            }
        } else {
            self.active.insert(key, fingerprint);
        }
        Ok(fingerprint)
    }
}

/// RFC 9180 Base-mode ciphertext carrying a fixed-size padded ballot package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateBallotEnvelopeV1 {
    manifest_hash: ManifestHash,
    descriptor_fingerprint: [u8; 32],
    gateway_key_id: String,
    padding_policy_id: String,
    encapsulated_key: [u8; 32],
    ciphertext: Vec<u8>,
}
impl PrivateBallotEnvelopeV1 {
    pub fn seal(
        descriptor: &TransportDescriptorV1,
        ballot_bytes: &[u8],
    ) -> Result<Self, TransportError> {
        if ballot_bytes
            .len()
            .checked_add(4)
            .is_none_or(|n| n > descriptor.padding.padded_bytes)
        {
            return Err(TransportError::OversizedPayload);
        }
        let mut padded = vec![0_u8; descriptor.padding.padded_bytes];
        padded[..4].copy_from_slice(&(ballot_bytes.len() as u32).to_be_bytes());
        padded[4..4 + ballot_bytes.len()].copy_from_slice(ballot_bytes);
        let public_key = <Kem as KemTrait>::PublicKey::from_bytes(&descriptor.gateway_public_key)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        let fingerprint = descriptor.fingerprint()?;
        let aad = envelope_aad(
            descriptor.manifest_hash,
            fingerprint,
            &descriptor.gateway_key_id,
            &descriptor.padding.id,
        )?;
        let (encapped, mut ctx) =
            hpke::setup_sender::<Aead, Kdf, Kem>(&OpModeS::Base, &public_key, HPKE_INFO)
                .map_err(|_| TransportError::CryptoFailure)?;
        let ciphertext = ctx
            .seal(&padded, &aad)
            .map_err(|_| TransportError::CryptoFailure)?;
        if ciphertext.len() > MAX_ENVELOPE_BYTES {
            return Err(TransportError::OversizedPayload);
        }
        let mut encapsulated_key = [0; 32];
        encapsulated_key.copy_from_slice(encapped.to_bytes().as_slice());
        Ok(Self {
            manifest_hash: descriptor.manifest_hash,
            descriptor_fingerprint: fingerprint,
            gateway_key_id: descriptor.gateway_key_id.clone(),
            padding_policy_id: descriptor.padding.id.clone(),
            encapsulated_key,
            ciphertext,
        })
    }
    /// Returns public ciphertext and authenticated bindings for a gateway receiver.
    /// Receiver secret material and HPKE opening live in `transport-gateway`.
    pub fn receiver_opening_material(
        &self,
        descriptor: &TransportDescriptorV1,
    ) -> Result<EnvelopeOpeningMaterialV1, TransportError> {
        if self.manifest_hash != descriptor.manifest_hash {
            return Err(TransportError::WrongElection);
        }
        if self.descriptor_fingerprint != descriptor.fingerprint()?
            || self.gateway_key_id != descriptor.gateway_key_id
            || self.padding_policy_id != descriptor.padding.id
        {
            return Err(TransportError::WrongDescriptor);
        }
        if self.ciphertext.len() != descriptor.padding.padded_bytes + 16 {
            return Err(TransportError::InvalidEnvelope);
        }
        let aad = envelope_aad(
            self.manifest_hash,
            self.descriptor_fingerprint,
            &self.gateway_key_id,
            &self.padding_policy_id,
        )?;
        Ok(EnvelopeOpeningMaterialV1 {
            encapsulated_key: self.encapsulated_key,
            ciphertext: self.ciphertext.clone(),
            aad,
            padded_bytes: descriptor.padding.padded_bytes,
        })
    }
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, TransportError> {
        let mut w = CanonicalCborWriter::new();
        w.write_array_len(7)
            .map_err(|_| TransportError::InvalidEnvelope)?;
        w.write_unsigned(ENVELOPE_VERSION);
        w.write_byte_string(self.manifest_hash.as_bytes())
            .map_err(|_| TransportError::InvalidEnvelope)?;
        w.write_byte_string(&self.descriptor_fingerprint)
            .map_err(|_| TransportError::InvalidEnvelope)?;
        w.write_text_string(&self.gateway_key_id)
            .map_err(|_| TransportError::InvalidEnvelope)?;
        w.write_text_string(&self.padding_policy_id)
            .map_err(|_| TransportError::InvalidEnvelope)?;
        w.write_byte_string(&self.encapsulated_key)
            .map_err(|_| TransportError::InvalidEnvelope)?;
        w.write_byte_string(&self.ciphertext)
            .map_err(|_| TransportError::InvalidEnvelope)?;
        Ok(w.into_bytes())
    }
    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(TransportError::OversizedPayload);
        }
        let mut r = CanonicalCborReader::new(bytes);
        if r.read_array_len()
            .map_err(|_| TransportError::InvalidEnvelope)?
            != 7
            || r.read_unsigned()
                .map_err(|_| TransportError::InvalidEnvelope)?
                != ENVELOPE_VERSION
        {
            return Err(TransportError::InvalidEnvelope);
        }
        let manifest_hash = ManifestHash::new(read_fixed(&mut r)?);
        let descriptor_fingerprint = read_fixed(&mut r)?;
        let gateway_key_id = r
            .read_text_string()
            .map_err(|_| TransportError::InvalidEnvelope)?
            .to_owned();
        let padding_policy_id = r
            .read_text_string()
            .map_err(|_| TransportError::InvalidEnvelope)?
            .to_owned();
        let encapsulated_key = read_fixed(&mut r)?;
        let ciphertext = r
            .read_byte_string()
            .map_err(|_| TransportError::InvalidEnvelope)?
            .to_vec();
        r.finish().map_err(|_| TransportError::InvalidEnvelope)?;
        let output = Self {
            manifest_hash,
            descriptor_fingerprint,
            gateway_key_id,
            padding_policy_id,
            encapsulated_key,
            ciphertext,
        };
        if output.gateway_key_id.is_empty()
            || output.padding_policy_id.is_empty()
            || output.to_canonical_cbor()? != bytes
        {
            return Err(TransportError::InvalidEnvelope);
        }
        Ok(output)
    }
}

/// Public envelope data required by the separate secret-bearing gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeOpeningMaterialV1 {
    pub encapsulated_key: [u8; 32],
    pub ciphertext: Vec<u8>,
    pub aad: Vec<u8>,
    pub padded_bytes: usize,
}

/// Wire-safe acknowledgement; organizer intake DTOs never appear here.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VoterTransportReceiptV1 {
    pub state: VoterReceiptStateV1,
    pub retry_status: RetryStatusV1,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum VoterReceiptStateV1 {
    Received,
    Accepted,
    Rejected,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum RetryStatusV1 {
    NewDelivery,
    PreviousDeliveryAccepted,
    PreviousDeliveryRejected,
    GenericDuplicate,
}

fn envelope_aad(
    manifest: ManifestHash,
    fingerprint: [u8; 32],
    key_id: &str,
    policy: &str,
) -> Result<Vec<u8>, TransportError> {
    let mut w = CanonicalCborWriter::new();
    w.write_array_len(6)
        .map_err(|_| TransportError::InvalidEnvelope)?;
    w.write_unsigned(ENVELOPE_VERSION);
    w.write_text_string(PROTOCOL_ID)
        .map_err(|_| TransportError::InvalidEnvelope)?;
    w.write_byte_string(manifest.as_bytes())
        .map_err(|_| TransportError::InvalidEnvelope)?;
    w.write_byte_string(&fingerprint)
        .map_err(|_| TransportError::InvalidEnvelope)?;
    w.write_text_string(key_id)
        .map_err(|_| TransportError::InvalidEnvelope)?;
    w.write_text_string(policy)
        .map_err(|_| TransportError::InvalidEnvelope)?;
    Ok(w.into_bytes())
}
fn read_fixed<const N: usize>(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<[u8; N], TransportError> {
    let bytes = reader
        .read_byte_string()
        .map_err(|_| TransportError::InvalidDescriptor)?;
    bytes
        .try_into()
        .map_err(|_| TransportError::InvalidDescriptor)
}
fn write_text_vec(
    writer: &mut CanonicalCborWriter,
    values: &[String],
) -> Result<(), TransportError> {
    writer
        .write_array_len(values.len())
        .map_err(|_| TransportError::InvalidDescriptor)?;
    for value in values {
        writer
            .write_text_string(value)
            .map_err(|_| TransportError::InvalidDescriptor)?;
    }
    Ok(())
}
fn read_text_vec(reader: &mut CanonicalCborReader<'_>) -> Result<Vec<String>, TransportError> {
    let len = reader
        .read_array_len()
        .map_err(|_| TransportError::InvalidDescriptor)?;
    if len > MAX_ENDPOINTS {
        return Err(TransportError::InvalidDescriptor);
    }
    (0..len)
        .map(|_| {
            reader
                .read_text_string()
                .map(|s| s.to_owned())
                .map_err(|_| TransportError::InvalidDescriptor)
        })
        .collect()
}
fn read_key_vec(reader: &mut CanonicalCborReader<'_>) -> Result<Vec<[u8; 32]>, TransportError> {
    let len = reader
        .read_array_len()
        .map_err(|_| TransportError::InvalidDescriptor)?;
    if len > MAX_ENDPOINTS {
        return Err(TransportError::InvalidDescriptor);
    }
    (0..len).map(|_| read_fixed(reader)).collect()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn authority() -> (SigningKey, TransportAuthorityRootV1) {
        let signing = SigningKey::from_bytes(&[9; 32]);
        let root = TransportAuthorityRootV1::Pinned {
            key_id: "test-root-2026".to_owned(),
            public_key: signing.verifying_key().to_bytes(),
        };
        (signing, root)
    }
    fn descriptor() -> (TransportDescriptorV1, [u8; 32]) {
        let (gateway_private, gateway_public) = Kem::gen_keypair();
        let mut private = [0; 32];
        private.copy_from_slice(gateway_private.to_bytes().as_slice());
        let mut public = [0; 32];
        public.copy_from_slice(gateway_public.to_bytes().as_slice());
        let (signing, _) = authority();
        let descriptor = TransportDescriptorV1::sign_for_test_or_ceremony(
            b"transport-test-election".to_vec(),
            ManifestHash::new([7; 32]),
            1,
            TransportRoutePolicyV1::OfflineOnly,
            Vec::new(),
            Vec::new(),
            public,
            "gateway-2026-1".to_owned(),
            vec![[3; 32]],
            PaddingPolicyV1 {
                id: "fixed-8192".to_owned(),
                padded_bytes: 8192,
            },
            BatchPolicyV1 {
                id: "accepted-100".to_owned(),
                accepted_unique_floor: 100,
            },
            None,
            "test-root-2026".to_owned(),
            &signing,
        )
        .expect("test descriptor signs");
        (descriptor, private)
    }

    #[test]
    fn voter_receipt_states_are_transport_only() {
        fn state_name(state: VoterReceiptStateV1) -> &'static str {
            match state {
                VoterReceiptStateV1::Received => "RECEIVED",
                VoterReceiptStateV1::Accepted => "ACCEPTED",
                VoterReceiptStateV1::Rejected => "REJECTED",
            }
        }

        assert_eq!(state_name(VoterReceiptStateV1::Received), "RECEIVED");
        assert_eq!(state_name(VoterReceiptStateV1::Accepted), "ACCEPTED");
        assert_eq!(state_name(VoterReceiptStateV1::Rejected), "REJECTED");
    }

    #[test]
    fn descriptor_is_canonical_root_authenticated_and_conflict_detected() {
        let (descriptor, _) = descriptor();
        let (_, root) = authority();
        let encoded = descriptor
            .to_canonical_cbor()
            .expect("canonical descriptor");
        let decoded = TransportDescriptorV1::from_canonical_cbor(&encoded).expect("strict decode");
        decoded
            .verify(&root, ManifestHash::new([7; 32]))
            .expect("root verifies");
        assert!(decoded.verify(&root, ManifestHash::new([8; 32])).is_err());
        assert_eq!(decoded.hpke_suite_id(), HPKE_SUITE_ID);
        assert!(
            decoded
                .verify(
                    &production_transport_authority_root_v1(),
                    ManifestHash::new([7; 32])
                )
                .is_err()
        );
        let mut mutated = encoded.clone();
        let last = mutated.len() - 1;
        mutated[last] ^= 1;
        let mutated =
            TransportDescriptorV1::from_canonical_cbor(&mutated).expect("shape still decodes");
        assert!(mutated.verify(&root, ManifestHash::new([7; 32])).is_err());
        let mut store = DescriptorConsistencyStoreV1::default();
        store
            .accept(&decoded, &root, ManifestHash::new([7; 32]))
            .expect("first descriptor pins");
        assert_eq!(
            store
                .accept(&decoded, &root, ManifestHash::new([7; 32]))
                .expect("same descriptor is stable"),
            decoded.fingerprint().expect("fingerprint")
        );
        assert!(
            store
                .accept(&mutated, &root, ManifestHash::new([7; 32]))
                .is_err()
        );
    }

    #[test]
    fn envelope_rejects_mutation_before_gateway_opening() {
        let (descriptor, _) = descriptor();
        let bytes = b"exact canonical ballot package bytes";
        let envelope = PrivateBallotEnvelopeV1::seal(&descriptor, bytes).expect("seal");
        let encoded = envelope.to_canonical_cbor().expect("canonical envelope");
        let decoded =
            PrivateBallotEnvelopeV1::from_canonical_cbor(&encoded).expect("strict envelope decode");
        let mut tampered = decoded.clone();
        tampered.ciphertext[0] ^= 1;
        assert!(tampered.receiver_opening_material(&descriptor).is_ok());
        let mut bad_encapped = decoded.clone();
        bad_encapped.encapsulated_key[0] ^= 1;
        assert!(bad_encapped.receiver_opening_material(&descriptor).is_ok());
        let mut bad_descriptor = descriptor.clone();
        bad_descriptor.padding.id = "other".to_owned();
        assert!(decoded.receiver_opening_material(&bad_descriptor).is_err());
        assert!(PrivateBallotEnvelopeV1::from_canonical_cbor(&[0x87, 1]).is_err());
    }
}
