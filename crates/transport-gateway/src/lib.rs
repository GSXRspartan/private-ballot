//! Local-only receiver boundary for private ballot envelopes.
//!
//! This crate owns HPKE receiver secrets, opens authenticated ciphertext, and
//! passes exact recovered bytes to gui-core's existing 5A11 intake boundary.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use tari_cc_private_ballot_archive::{
    TransportArchiveBatchV1, TransportArchiveBindingV1,
};

use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, GuiIntakeCategory, PrivateBallotEnvelopeV1, RetryStatusV1,
    TransportDescriptorV1, TransportError, VoterReceiptStateV1, VoterTransportReceiptV1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborReader, CanonicalCborWriter, HashDomain, ManifestHash,
    hash_domain_separated,
};
use tari_cc_private_ballot_transport_network::VoterPrivateRouteV1;

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;
const HPKE_INFO: &[u8] = b"tari-cc-private-ballot/private-ballot-envelope/v1";
const DURABLE_STATE_VERSION: u64 = 1;
const DURABLE_STATE_TYPE_ID: &str = "TARI_CC_PRIVATE_BALLOT_TRANSPORT_GATEWAY_STATE_V1";
const MAX_DURABLE_RETRIES: usize = 65_536;
const MAX_DURABLE_BATCHES: usize = 4_096;
const MAX_DURABLE_PENDING: usize = 65_536;

/// Voter-safe result of one explicit private-submission attempt. It omits the
/// descriptor, endpoint, encrypted payload, retry capability, intake
/// sequence, and all gateway internals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateSubmissionResultV1 {
    pub route: VoterPrivateRouteV1,
    pub receipt: VoterTransportReceiptV1,
    pub reduced_anonymity: bool,
}

/// The only carrier operations a submission coordinator may invoke. A
/// carrier receives an already-authenticated opaque envelope; no direct HTTP
/// or fallback operation exists in this interface.
pub trait PrivateSubmissionCarrierV1 {
    fn send_managed_tor(
        &mut self,
        descriptor: &TransportDescriptorV1,
        envelope: &[u8],
    ) -> Result<(), TransportError>;

    fn send_split_trust_relay(
        &mut self,
        descriptor: &TransportDescriptorV1,
        envelope: &[u8],
    ) -> Result<(), TransportError>;
}

/// Rust-side private submission coordinator. Production construction carries
/// an explicitly unprovisioned root and consequently has no online
/// configuration. Test/development construction requires an explicit pinned
/// test root, descriptor, and receiver key.
pub struct PrivateSubmissionCoordinatorV1 {
    roots: tari_cc_private_ballot_gui_core::TransportAuthorityRootSetV1,
    descriptor: Option<TransportDescriptorV1>,
    receiver_key: Option<GatewayReceiverKeyV1>,
    gateway: TransportGatewaySimulatorV1,
    consistency: tari_cc_private_ballot_gui_core::DescriptorConsistencyStoreV1,
    persistence_path: Option<std::path::PathBuf>,
    retry_memory: Option<([u8; 32], [u8; 32])>,
}

impl PrivateSubmissionCoordinatorV1 {
    /// Production default: online routes fail closed until a release pins a
    /// production transport authority root and installs a descriptor.
    #[must_use]
    pub fn production_unprovisioned() -> Self {
        Self {
            roots: tari_cc_private_ballot_gui_core::TransportAuthorityRootSetV1::new(
                tari_cc_private_ballot_gui_core::production_transport_authority_root_v1(),
            ),
            descriptor: None,
            receiver_key: None,
            gateway: TransportGatewaySimulatorV1::default(),
            consistency: tari_cc_private_ballot_gui_core::DescriptorConsistencyStoreV1::default(),
            persistence_path: None,
            retry_memory: None,
        }
    }

    /// Explicit development/test installation. Production code must not call
    /// this constructor with an unreviewed root or a ceremony private key.
    pub fn with_test_configuration(
        root: tari_cc_private_ballot_gui_core::TransportAuthorityRootV1,
        descriptor: TransportDescriptorV1,
        receiver_key: GatewayReceiverKeyV1,
        persistence_path: Option<std::path::PathBuf>,
    ) -> Result<Self, TransportError> {
        let gateway = match persistence_path.as_deref() {
            Some(path) if path.exists() => TransportGatewaySimulatorV1::load_durable_state(path, &descriptor)?,
            _ => TransportGatewaySimulatorV1::default(),
        };
        Ok(Self {
            roots: tari_cc_private_ballot_gui_core::TransportAuthorityRootSetV1::new(root),
            descriptor: Some(descriptor),
            receiver_key: Some(receiver_key),
            gateway,
            consistency: tari_cc_private_ballot_gui_core::DescriptorConsistencyStoreV1::default(),
            persistence_path,
            retry_memory: None,
        })
    }

    /// Online routes are unavailable for an unprovisioned production root;
    /// offline export is intentionally handled by the existing Rust-only
    /// voter export command and never needs descriptor configuration.
    #[must_use]
    pub fn online_configured(&self) -> bool {
        self.descriptor.is_some() && self.receiver_key.is_some()
    }

    /// Seals and sends exact canonical bytes through only the explicitly
    /// selected carrier, then passes the exact HPKE-opened bytes to the 5A11
    /// intake boundary. No frontend acceptance decision is involved.
    pub fn submit(
        &mut self,
        route: VoterPrivateRouteV1,
        ballot_bytes: &[u8],
        session: &mut GuiElectionSessionV1,
        carrier: &mut impl PrivateSubmissionCarrierV1,
    ) -> Result<PrivateSubmissionResultV1, TransportError> {
        if route == VoterPrivateRouteV1::OfflineExport {
            return Err(TransportError::Unavailable);
        }
        let retry_capability = self.retry_capability_for(ballot_bytes);
        let descriptor = self.descriptor.as_ref().ok_or(TransportError::UntrustedRoot)?;
        let receiver_key = self.receiver_key.as_ref().ok_or(TransportError::UntrustedRoot)?;
        self.roots.verify_and_accept_descriptor(
            descriptor,
            session.artifacts().manifest_hash(),
            &mut self.consistency,
        )?;
        if descriptor.election_id() != session.artifacts().manifest().election_id().as_bytes() {
            return Err(TransportError::WrongElection);
        }
        match (route, descriptor.route()) {
            (VoterPrivateRouteV1::ManagedTor, tari_cc_private_ballot_gui_core::TransportRoutePolicyV1::ManagedTorOrOffline)
            | (VoterPrivateRouteV1::SplitTrustRelay, tari_cc_private_ballot_gui_core::TransportRoutePolicyV1::RelayOrOffline) => {}
            _ => return Err(TransportError::UnsupportedRoute),
        }
        let envelope = PrivateBallotEnvelopeV1::seal(descriptor, ballot_bytes)?;
        let encoded = envelope.to_canonical_cbor()?;
        match route {
            VoterPrivateRouteV1::ManagedTor => carrier.send_managed_tor(descriptor, &encoded)?,
            VoterPrivateRouteV1::SplitTrustRelay => carrier.send_split_trust_relay(descriptor, &encoded)?,
            VoterPrivateRouteV1::OfflineExport => return Err(TransportError::Unavailable),
        }
        let receipt = self.gateway.deliver(&encoded, descriptor, receiver_key, retry_capability, session)?;
        self.persist_if_configured(descriptor)?;
        Ok(PrivateSubmissionResultV1 {
            route,
            receipt,
            reduced_anonymity: !self
                .gateway
                .threshold_met(descriptor.batch().accepted_unique_floor),
        })
    }

    fn retry_capability_for(&mut self, ballot_bytes: &[u8]) -> [u8; 32] {
        let digest = hash_domain_separated(&Blake3HashProviderV1, HashDomain::BallotPackageV1, ballot_bytes);
        if let Some((prior_digest, capability)) = self.retry_memory
            && prior_digest == digest
        {
            return capability;
        }
        let capability = new_retry_capability_v1();
        self.retry_memory = Some((digest, capability));
        capability
    }

    fn persist_if_configured(&self, descriptor: &TransportDescriptorV1) -> Result<(), TransportError> {
        if let Some(path) = &self.persistence_path {
            self.gateway.save_durable_state(descriptor, path)?;
        }
        Ok(())
    }
}

/// Admission is the sole cutoff authority for online transport. It deliberately
/// has no voter-clock or arrival-time field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportAdmissionStateV1 {
    Open,
    Closing,
    Closed,
}

/// Serializes close against expensive authenticated delivery. Callers must
/// finish every successful `admit` exactly once; close only calls core `close`
/// after the last admitted request finishes (or the operator aborts its drain).
#[derive(Debug)]
pub struct TransportAdmissionGateV1 {
    state: TransportAdmissionStateV1,
    admitted: u32,
    drain_generation: u64,
}

impl Default for TransportAdmissionGateV1 {
    fn default() -> Self {
        Self {
            state: TransportAdmissionStateV1::Open,
            admitted: 0,
            drain_generation: 0,
        }
    }
}

impl TransportAdmissionGateV1 {
    #[must_use]
    pub const fn state(&self) -> TransportAdmissionStateV1 {
        self.state
    }
    #[must_use]
    pub const fn admitted_in_flight(&self) -> u32 {
        self.admitted
    }
    pub fn admit(&mut self, session: &GuiElectionSessionV1) -> Result<u64, TransportError> {
        if self.state != TransportAdmissionStateV1::Open || session.lifecycle_state() != "OPEN" {
            return Err(TransportError::Unavailable);
        }
        self.admitted = self.admitted.saturating_add(1);
        Ok(self.drain_generation)
    }
    pub fn begin_close(
        &mut self,
        session: &mut GuiElectionSessionV1,
    ) -> Result<(), TransportError> {
        if self.state != TransportAdmissionStateV1::Open {
            return Err(TransportError::Unavailable);
        }
        self.state = TransportAdmissionStateV1::Closing;
        self.close_if_drained(session)
    }
    pub fn finish_admitted(
        &mut self,
        session: &mut GuiElectionSessionV1,
        admission_generation: u64,
    ) -> Result<(), TransportError> {
        if self.state == TransportAdmissionStateV1::Closed
            || admission_generation != self.drain_generation
        {
            return Err(TransportError::Unavailable);
        }
        self.admitted = self
            .admitted
            .checked_sub(1)
            .ok_or(TransportError::Unavailable)?;
        self.close_if_drained(session)
    }
    /// Ends the bounded operator drain. Requests that have not completed must
    /// be returned as unavailable by their carrier and must not call intake.
    pub fn expire_drain(
        &mut self,
        session: &mut GuiElectionSessionV1,
    ) -> Result<(), TransportError> {
        self.drain_generation = self.drain_generation.wrapping_add(1);
        self.admitted = 0;
        self.close_if_drained(session)
    }
    fn close_if_drained(
        &mut self,
        session: &mut GuiElectionSessionV1,
    ) -> Result<(), TransportError> {
        if self.state == TransportAdmissionStateV1::Closing && self.admitted == 0 {
            session.close().map_err(|_| TransportError::Unavailable)?;
            self.state = TransportAdmissionStateV1::Closed;
        }
        Ok(())
    }
}

/// Public, deterministic inclusion material. It contains only a package digest,
/// a root and sibling hashes; it never contains ingress order or timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchInclusionProofV1 {
    pub package_digest: [u8; 32],
    pub root: [u8; 32],
    pub siblings: Vec<([u8; 32], bool)>,
}

impl BatchInclusionProofV1 {
    #[must_use]
    pub fn verify(&self) -> bool {
        let provider = Blake3HashProviderV1;
        let mut current = hash_domain_separated(
            &provider,
            HashDomain::TransportBatchLeafV1,
            &self.package_digest,
        );
        for (sibling, sibling_is_left) in &self.siblings {
            let mut input = Vec::with_capacity(64);
            if *sibling_is_left {
                input.extend_from_slice(sibling);
                input.extend_from_slice(&current);
            } else {
                input.extend_from_slice(&current);
                input.extend_from_slice(sibling);
            }
            current = hash_domain_separated(&provider, HashDomain::TransportBatchNodeV1, &input);
        }
        current == self.root
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedTransportBatchV1 {
    /// Monotonic operator sealing epoch, never ballot ingress order.
    pub batch_id: u64,
    pub root: [u8; 32],
    pub accepted_unique_count: u64,
    pub reduced_anonymity: bool,
    digests: Vec<[u8; 32]>,
}

impl SealedTransportBatchV1 {
    pub fn inclusion_proof(&self, package_digest: [u8; 32]) -> Option<BatchInclusionProofV1> {
        let index = self.digests.binary_search(&package_digest).ok()?;
        let provider = Blake3HashProviderV1;
        let mut layer: Vec<[u8; 32]> = self
            .digests
            .iter()
            .map(|d| hash_domain_separated(&provider, HashDomain::TransportBatchLeafV1, d))
            .collect();
        let mut cursor = index;
        let mut siblings = Vec::new();
        while layer.len() > 1 {
            let sibling_index = if cursor % 2 == 0 {
                (cursor + 1).min(layer.len() - 1)
            } else {
                cursor - 1
            };
            siblings.push((layer[sibling_index], sibling_index < cursor));
            layer = next_merkle_layer(&layer);
            cursor /= 2;
        }
        Some(BatchInclusionProofV1 {
            package_digest,
            root: self.root,
            siblings,
        })
    }
}

/// Descriptor-authorized signature over a minimal, caller-held receipt body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransportReceiptV1 {
    pub receipt: VoterTransportReceiptV1,
    pub package_digest: [u8; 32],
    pub batch_root: Option<[u8; 32]>,
    pub key_id: String,
    pub signature: [u8; 64],
}

impl SignedTransportReceiptV1 {
    pub fn sign(
        receipt: VoterTransportReceiptV1,
        package_digest: [u8; 32],
        batch_root: Option<[u8; 32]>,
        key_id: String,
        key: &SigningKey,
    ) -> Self {
        let mut output = Self {
            receipt,
            package_digest,
            batch_root,
            key_id,
            signature: [0; 64],
        };
        output.signature = key.sign(&output.message()).to_bytes();
        output
    }
    pub fn verify(&self, key: &VerifyingKey) -> Result<(), TransportError> {
        key.verify(&self.message(), &Signature::from_bytes(&self.signature))
            .map_err(|_| TransportError::CryptoFailure)
    }
    pub fn verify_for_descriptor(
        &self,
        descriptor: &TransportDescriptorV1,
    ) -> Result<(), TransportError> {
        for bytes in descriptor.receipt_verification_keys() {
            let key =
                VerifyingKey::from_bytes(bytes).map_err(|_| TransportError::InvalidDescriptor)?;
            if self.verify(&key).is_ok() {
                return Ok(());
            }
        }
        Err(TransportError::CryptoFailure)
    }
    fn message(&self) -> Vec<u8> {
        let mut message = b"tari-cc-private-ballot/transport-receipt/v1\0".to_vec();
        message.push(self.receipt.state as u8);
        message.push(self.receipt.retry_status as u8);
        message.extend_from_slice(&self.package_digest);
        if let Some(root) = self.batch_root {
            message.push(1);
            message.extend_from_slice(&root);
        } else {
            message.push(0);
        }
        message.extend_from_slice(self.key_id.as_bytes());
        message
    }
}

/// Secret-bearing HPKE receiver key, deliberately isolated from gui-core.
pub struct GatewayReceiverKeyV1 {
    receiver_secret_bytes: [u8; 32],
}

impl GatewayReceiverKeyV1 {
    pub fn from_secret_bytes(receiver_secret_bytes: [u8; 32]) -> Result<Self, TransportError> {
        <Kem as KemTrait>::PrivateKey::from_bytes(&receiver_secret_bytes)
            .map_err(|_| TransportError::WrongGatewayKey)?;
        Ok(Self {
            receiver_secret_bytes,
        })
    }
}

/// Opens one authenticated envelope without reserializing its ballot package.
pub fn open_envelope_bytes_v1(
    envelope: &PrivateBallotEnvelopeV1,
    descriptor: &TransportDescriptorV1,
    receiver_key: &GatewayReceiverKeyV1,
) -> Result<Vec<u8>, TransportError> {
    let material = envelope.receiver_opening_material(descriptor)?;
    let receiver_secret =
        <Kem as KemTrait>::PrivateKey::from_bytes(&receiver_key.receiver_secret_bytes)
            .map_err(|_| TransportError::WrongGatewayKey)?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&material.encapsulated_key)
        .map_err(|_| TransportError::InvalidEnvelope)?;
    let mut ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &receiver_secret,
        &encapped,
        HPKE_INFO,
    )
    .map_err(|_| TransportError::CryptoFailure)?;
    let padded = ctx
        .open(&material.ciphertext, &material.aad)
        .map_err(|_| TransportError::CryptoFailure)?;
    unpad_authenticated_payload(&padded, material.padded_bytes)
}

/// In-process collector/gateway simulator. It has no network listener.
#[derive(Default)]
pub struct TransportGatewaySimulatorV1 {
    received_count: u64,
    verified_count: u64,
    accepted_unique_count: u64,
    retries: BTreeMap<[u8; 32], RetryRecordV1>,
    admission: TransportAdmissionGateV1,
    pending_digests: Vec<[u8; 32]>,
    sealed_batches: Vec<SealedTransportBatchV1>,
    next_batch_id: u64,
    retry_retention: RetryRetentionV1,
}

#[derive(Clone)]
struct RetryRecordV1 {
    package_digest: [u8; 32],
    receipt: VoterTransportReceiptV1,
}

/// Lifecycle-scoped retry retention. There are deliberately no voter arrival
/// times in the retention model: entries survive while an election is active
/// and, if configured, through a post-finalization verification grace period.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RetryRetentionV1 {
    #[default]
    ActiveElection,
    VerificationGrace,
    Expired,
}

impl RetryRetentionV1 {
    const fn code(self) -> u64 {
        match self {
            Self::ActiveElection => 0,
            Self::VerificationGrace => 1,
            Self::Expired => 2,
        }
    }

    fn from_code(code: u64) -> Result<Self, TransportError> {
        match code {
            0 => Ok(Self::ActiveElection),
            1 => Ok(Self::VerificationGrace),
            2 => Ok(Self::Expired),
            _ => Err(TransportError::InvalidDescriptor),
        }
    }
}

/// Strict, deterministic persistence for the privacy-safe gateway state.
/// It intentionally serializes commitments rather than retry capabilities and
/// public batch proof material rather than decrypted ballot bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportGatewayDurableStateV1 {
    bytes: Vec<u8>,
}

impl TransportGatewayDurableStateV1 {
    #[must_use]
    pub fn as_canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl TransportGatewaySimulatorV1 {
    #[must_use]
    pub fn admission_state(&self) -> TransportAdmissionStateV1 {
        self.admission.state()
    }
    #[must_use]
    pub fn received_count(&self) -> u64 {
        self.received_count
    }
    #[must_use]
    pub fn verified_count(&self) -> u64 {
        self.verified_count
    }
    #[must_use]
    pub fn accepted_unique_count(&self) -> u64 {
        self.accepted_unique_count
    }
    #[must_use]
    pub fn threshold_met(&self, floor: u64) -> bool {
        self.accepted_unique_count >= floor
    }

    #[must_use]
    pub const fn retry_retention(&self) -> RetryRetentionV1 {
        self.retry_retention
    }

    /// Starts the configured post-finalization grace period without attaching
    /// a voter timestamp to a retry record.
    pub fn begin_retry_verification_grace(&mut self) {
        if self.retry_retention == RetryRetentionV1::ActiveElection {
            self.retry_retention = RetryRetentionV1::VerificationGrace;
        }
    }

    /// Permanently removes retry records at the configured lifecycle boundary.
    /// Sealed public batch proof material is retained for archive verification.
    pub fn expire_retry_retention(&mut self) {
        self.retries.clear();
        self.retry_retention = RetryRetentionV1::Expired;
    }

    /// Produces a strict, deterministic snapshot. It excludes raw retry
    /// capabilities, decrypted ballots, credentials, IP/header data, keys,
    /// ingress sequence, and timestamps by construction.
    pub fn durable_state(
        &self,
        descriptor: &TransportDescriptorV1,
    ) -> Result<TransportGatewayDurableStateV1, TransportError> {
        let descriptor_fingerprint = descriptor.fingerprint()?;
        let mut writer = CanonicalCborWriter::new();
        writer.write_array_len(14).map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(DURABLE_STATE_VERSION);
        writer
            .write_text_string(DURABLE_STATE_TYPE_ID)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(descriptor.election_id())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(descriptor.manifest_hash().as_bytes())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer
            .write_byte_string(&descriptor_fingerprint)
            .map_err(|_| TransportError::InvalidDescriptor)?;
        writer.write_unsigned(descriptor.generation());
        writer.write_unsigned(self.received_count);
        writer.write_unsigned(self.verified_count);
        writer.write_unsigned(self.accepted_unique_count);
        writer.write_unsigned(self.next_batch_id);
        writer.write_unsigned(self.retry_retention.code());
        writer
            .write_array_len(self.retries.len())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        for (commitment, record) in &self.retries {
            writer.write_array_len(3).map_err(|_| TransportError::InvalidDescriptor)?;
            writer
                .write_byte_string(commitment)
                .map_err(|_| TransportError::InvalidDescriptor)?;
            writer
                .write_byte_string(&record.package_digest)
                .map_err(|_| TransportError::InvalidDescriptor)?;
            writer.write_unsigned(receipt_state_code(record.receipt.state));
        }
        let mut pending_digests = self.pending_digests.clone();
        pending_digests.sort_unstable();
        pending_digests.dedup();
        writer
            .write_array_len(pending_digests.len())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        for digest in &pending_digests {
            writer
                .write_byte_string(digest)
                .map_err(|_| TransportError::InvalidDescriptor)?;
        }
        writer
            .write_array_len(self.sealed_batches.len())
            .map_err(|_| TransportError::InvalidDescriptor)?;
        for batch in &self.sealed_batches {
            writer.write_array_len(5).map_err(|_| TransportError::InvalidDescriptor)?;
            writer.write_unsigned(batch.batch_id);
            writer
                .write_byte_string(&batch.root)
                .map_err(|_| TransportError::InvalidDescriptor)?;
            writer.write_unsigned(batch.accepted_unique_count);
            writer.write_bool(batch.reduced_anonymity);
            writer
                .write_array_len(batch.digests.len())
                .map_err(|_| TransportError::InvalidDescriptor)?;
            for digest in &batch.digests {
                writer
                    .write_byte_string(digest)
                    .map_err(|_| TransportError::InvalidDescriptor)?;
            }
        }
        Ok(TransportGatewayDurableStateV1 { bytes: writer.into_bytes() })
    }

    /// Crash-safe replacement write: build and validate canonical state, flush
    /// a newly-created sibling file, then rename it into place.
    pub fn save_durable_state(
        &self,
        descriptor: &TransportDescriptorV1,
        path: &Path,
    ) -> Result<(), TransportError> {
        let state = self.durable_state(descriptor)?;
        let parent = path.parent().ok_or(TransportError::InvalidDescriptor)?;
        std::fs::create_dir_all(parent).map_err(|_| TransportError::Unavailable)?;
        let temporary = path.with_extension("transport-state-v1.tmp");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|_| TransportError::Unavailable)?;
        file.write_all(state.as_canonical_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|_| TransportError::Unavailable)?;
        std::fs::rename(&temporary, path).map_err(|_| TransportError::Unavailable)
    }

    /// Loads only a canonical, descriptor-bound snapshot. A corrupt,
    /// incompatible, or wrong-election file is rejected before any gateway is
    /// returned, so callers must fail closed rather than start with ambiguous
    /// retry or inclusion state.
    pub fn load_durable_state(
        path: &Path,
        descriptor: &TransportDescriptorV1,
    ) -> Result<Self, TransportError> {
        let bytes = std::fs::read(path).map_err(|_| TransportError::Unavailable)?;
        let state = Self::decode_durable_state(&bytes, descriptor)?;
        if state.durable_state(descriptor)?.as_canonical_bytes() != bytes {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(state)
    }

    fn decode_durable_state(bytes: &[u8], descriptor: &TransportDescriptorV1) -> Result<Self, TransportError> {
        let mut reader = CanonicalCborReader::new(bytes);
        if reader.read_array_len().map_err(|_| TransportError::InvalidDescriptor)? != 14
            || reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)? != DURABLE_STATE_VERSION
            || reader.read_text_string().map_err(|_| TransportError::InvalidDescriptor)? != DURABLE_STATE_TYPE_ID
        {
            return Err(TransportError::InvalidDescriptor);
        }
        let election_id = reader.read_byte_string().map_err(|_| TransportError::InvalidDescriptor)?;
        let manifest_hash = ManifestHash::new(read_fixed(&mut reader)?);
        let fingerprint = read_fixed(&mut reader)?;
        let generation = reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?;
        if election_id != descriptor.election_id()
            || manifest_hash != descriptor.manifest_hash()
            || fingerprint != descriptor.fingerprint()?
            || generation != descriptor.generation()
        {
            return Err(TransportError::WrongDescriptor);
        }
        let received_count = reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?;
        let verified_count = reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?;
        let accepted_unique_count = reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?;
        let next_batch_id = reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?;
        let retry_retention = RetryRetentionV1::from_code(
            reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?,
        )?;
        let retry_count = reader.read_array_len().map_err(|_| TransportError::InvalidDescriptor)?;
        if retry_count > MAX_DURABLE_RETRIES {
            return Err(TransportError::InvalidDescriptor);
        }
        let mut retries = BTreeMap::new();
        for _ in 0..retry_count {
            if reader.read_array_len().map_err(|_| TransportError::InvalidDescriptor)? != 3 {
                return Err(TransportError::InvalidDescriptor);
            }
            let commitment = read_fixed(&mut reader)?;
            let package_digest = read_fixed(&mut reader)?;
            let state = receipt_state_from_code(
                reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?,
            )?;
            if retries.insert(
                commitment,
                RetryRecordV1 {
                    package_digest,
                    receipt: VoterTransportReceiptV1 { state, retry_status: RetryStatusV1::NewDelivery },
                },
            ).is_some() {
                return Err(TransportError::InvalidDescriptor);
            }
        }
        if retry_retention == RetryRetentionV1::Expired && !retries.is_empty() {
            return Err(TransportError::InvalidDescriptor);
        }
        let pending_count = reader.read_array_len().map_err(|_| TransportError::InvalidDescriptor)?;
        if pending_count > MAX_DURABLE_PENDING {
            return Err(TransportError::InvalidDescriptor);
        }
        let mut pending_digests = Vec::with_capacity(pending_count);
        for _ in 0..pending_count {
            pending_digests.push(read_fixed(&mut reader)?);
        }
        pending_digests.sort_unstable();
        if pending_digests.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(TransportError::InvalidDescriptor);
        }
        let batch_count = reader.read_array_len().map_err(|_| TransportError::InvalidDescriptor)?;
        if batch_count > MAX_DURABLE_BATCHES {
            return Err(TransportError::InvalidDescriptor);
        }
        let mut sealed_batches = Vec::with_capacity(batch_count);
        for _ in 0..batch_count {
            if reader.read_array_len().map_err(|_| TransportError::InvalidDescriptor)? != 5 {
                return Err(TransportError::InvalidDescriptor);
            }
            let batch_id = reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?;
            let root = read_fixed(&mut reader)?;
            let batch_accepted_unique_count = reader.read_unsigned().map_err(|_| TransportError::InvalidDescriptor)?;
            let reduced_anonymity = reader.read_bool().map_err(|_| TransportError::InvalidDescriptor)?;
            let digest_count = reader.read_array_len().map_err(|_| TransportError::InvalidDescriptor)?;
            if digest_count == 0 || digest_count > MAX_DURABLE_PENDING {
                return Err(TransportError::InvalidDescriptor);
            }
            let mut digests = Vec::with_capacity(digest_count);
            for _ in 0..digest_count {
                digests.push(read_fixed(&mut reader)?);
            }
            if digests.windows(2).any(|pair| pair[0] >= pair[1])
                || batch_accepted_unique_count != digests.len() as u64
            {
                return Err(TransportError::InvalidDescriptor);
            }
            let leaves: Vec<[u8; 32]> = digests
                .iter()
                .map(|digest| hash_domain_separated(&Blake3HashProviderV1, HashDomain::TransportBatchLeafV1, digest))
                .collect();
            if merkle_root(&leaves) != Some(root) {
                return Err(TransportError::InvalidDescriptor);
            }
            sealed_batches.push(SealedTransportBatchV1 {
                batch_id,
                root,
                accepted_unique_count: batch_accepted_unique_count,
                reduced_anonymity,
                digests,
            });
        }
        reader.finish().map_err(|_| TransportError::InvalidDescriptor)?;
        if sealed_batches.windows(2).any(|pair| pair[0].batch_id >= pair[1].batch_id)
            || sealed_batches.last().is_some_and(|batch| next_batch_id <= batch.batch_id)
        {
            return Err(TransportError::InvalidDescriptor);
        }
        let known_accepted = pending_digests.len() as u64
            + sealed_batches.iter().map(|batch| batch.accepted_unique_count).sum::<u64>();
        if accepted_unique_count != known_accepted || verified_count < accepted_unique_count || received_count < verified_count {
            return Err(TransportError::InvalidDescriptor);
        }
        Ok(Self {
            received_count,
            verified_count,
            accepted_unique_count,
            retries,
            admission: TransportAdmissionGateV1::default(),
            pending_digests,
            sealed_batches,
            next_batch_id,
            retry_retention,
        })
    }

    /// Starts the serialized close transition. New deliveries are rejected
    /// immediately; already admitted deliveries may finish until the caller
    /// expires the drain with `expire_close_drain`.
    pub fn begin_close(
        &mut self,
        session: &mut GuiElectionSessionV1,
    ) -> Result<(), TransportError> {
        self.admission.begin_close(session)
    }

    pub fn expire_close_drain(
        &mut self,
        session: &mut GuiElectionSessionV1,
    ) -> Result<(), TransportError> {
        self.admission.expire_drain(session)
    }

    /// Seals all accepted-but-unpublished packages. Digests are sorted before
    /// commitment construction, never by ingress order. A below-floor final
    /// batch remains valid but is explicitly marked reduced anonymity.
    pub fn seal_pending_batch(
        &mut self,
        floor: u64,
        final_close_batch: bool,
    ) -> Option<SealedTransportBatchV1> {
        if self.pending_digests.is_empty()
            || (!final_close_batch && self.pending_digests.len() < floor as usize)
        {
            return None;
        }
        self.pending_digests.sort_unstable();
        self.pending_digests.dedup();
        let digests = std::mem::take(&mut self.pending_digests);
        let leaves: Vec<[u8; 32]> = digests
            .iter()
            .map(|digest| {
                hash_domain_separated(
                    &Blake3HashProviderV1,
                    HashDomain::TransportBatchLeafV1,
                    digest,
                )
            })
            .collect();
        let root = merkle_root(&leaves)?;
        let batch = SealedTransportBatchV1 {
            batch_id: self.next_batch_id,
            root,
            accepted_unique_count: digests.len() as u64,
            reduced_anonymity: digests.len() < floor as usize,
            digests,
        };
        self.next_batch_id = self.next_batch_id.saturating_add(1);
        self.sealed_batches.push(batch.clone());
        Some(batch)
    }

    /// Public deterministic commitment over the set of sealed roots. This does
    /// not claim an Ootle anchor; anchoring is an operator-side later action.
    #[must_use]
    pub fn final_batch_set_commitment(&self) -> Option<[u8; 32]> {
        if self.sealed_batches.is_empty() {
            return None;
        }
        let mut roots: Vec<[u8; 32]> = self.sealed_batches.iter().map(|batch| batch.root).collect();
        roots.sort_unstable();
        Some(hash_domain_separated(
            &Blake3HashProviderV1,
            HashDomain::TransportBatchSetV1,
            &roots.concat(),
        ))
    }

    /// Produces the public archive constituent for every sealed batch. The
    /// caller must archive its canonical bytes before deriving `ArchiveHashV1`.
    pub fn transport_archive_binding(
        &self,
        descriptor: &TransportDescriptorV1,
    ) -> Result<Option<TransportArchiveBindingV1>, TransportError> {
        if self.sealed_batches.is_empty() {
            return Ok(None);
        }
        let descriptor_fingerprint = descriptor.fingerprint()?;
        let batches = self
            .sealed_batches
            .iter()
            .map(|batch| {
                TransportArchiveBatchV1::new(
                    batch.batch_id,
                    batch.root,
                    batch.accepted_unique_count,
                    batch.reduced_anonymity,
                )
            })
            .collect();
        TransportArchiveBindingV1::new(
            descriptor.election_id().to_vec(),
            descriptor.manifest_hash(),
            descriptor_fingerprint,
            descriptor.generation(),
            batches,
        )
        .map(Some)
        .map_err(|_| TransportError::InvalidDescriptor)
    }

    pub fn collect(&mut self, encoded: &[u8]) -> Result<PrivateBallotEnvelopeV1, TransportError> {
        self.received_count = self.received_count.saturating_add(1);
        PrivateBallotEnvelopeV1::from_canonical_cbor(encoded)
    }

    pub fn deliver(
        &mut self,
        encoded: &[u8],
        descriptor: &TransportDescriptorV1,
        receiver_key: &GatewayReceiverKeyV1,
        retry_capability: [u8; 32],
        session: &mut GuiElectionSessionV1,
    ) -> Result<VoterTransportReceiptV1, TransportError> {
        let admission_generation = self.admission.admit(session)?;
        let result =
            self.deliver_admitted(
                encoded,
                descriptor,
                receiver_key,
                retry_capability,
                session,
                admission_generation,
            );
        // Completion is intentionally serialized even when delivery failed;
        // close can then advance without a post-close intake bypass.
        self.admission.finish_admitted(session, admission_generation)?;
        result
    }

    fn deliver_admitted(
        &mut self,
        encoded: &[u8],
        descriptor: &TransportDescriptorV1,
        receiver_key: &GatewayReceiverKeyV1,
        retry_capability: [u8; 32],
        session: &mut GuiElectionSessionV1,
        admission_generation: u64,
    ) -> Result<VoterTransportReceiptV1, TransportError> {
        let envelope = self.collect(encoded)?;
        let bytes = open_envelope_bytes_v1(&envelope, descriptor, receiver_key)?;
        let package_digest =
            hash_domain_separated(&Blake3HashProviderV1, HashDomain::BallotPackageV1, &bytes);
        let capability_commitment = hash_domain_separated(
            &Blake3HashProviderV1,
            HashDomain::TransportRetryCapabilityV1,
            &retry_capability,
        );
        if let Some(prior) = self.retries.get(&capability_commitment) {
            if prior.package_digest != package_digest {
                return Ok(VoterTransportReceiptV1 {
                    state: VoterReceiptStateV1::Rejected,
                    retry_status: RetryStatusV1::GenericDuplicate,
                });
            }
            let mut receipt = prior.receipt.clone();
            receipt.retry_status = match receipt.state {
                VoterReceiptStateV1::Accepted => RetryStatusV1::PreviousDeliveryAccepted,
                _ => RetryStatusV1::PreviousDeliveryRejected,
            };
            return Ok(receipt);
        }

        // A drain expiry invalidates its earlier admission before core intake.
        // This is the final local guard against a generic post-close bypass.
        if self.admission.state() == TransportAdmissionStateV1::Closed
            || admission_generation != self.admission.drain_generation
        {
            return Err(TransportError::Unavailable);
        }
        self.verified_count = self.verified_count.saturating_add(1);
        let result = session
            .intake_ballot_package_bytes(&bytes)
            .map_err(|_| TransportError::Unavailable)?;
        let receipt = if result.accepted {
            self.accepted_unique_count = self.accepted_unique_count.saturating_add(1);
            self.pending_digests.push(package_digest);
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Accepted,
                retry_status: RetryStatusV1::NewDelivery,
            }
        } else if result.category == GuiIntakeCategory::Duplicate {
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Rejected,
                retry_status: RetryStatusV1::GenericDuplicate,
            }
        } else {
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Rejected,
                retry_status: RetryStatusV1::NewDelivery,
            }
        };
        if self.retry_retention != RetryRetentionV1::Expired {
            self.retries.insert(
                capability_commitment,
                RetryRecordV1 {
                    package_digest,
                    receipt: receipt.clone(),
                },
            );
        }
        Ok(receipt)
    }
}

fn merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    let mut layer = leaves.to_vec();
    while layer.len() > 1 {
        layer = next_merkle_layer(&layer);
    }
    layer.first().copied()
}

fn next_merkle_layer(layer: &[[u8; 32]]) -> Vec<[u8; 32]> {
    layer
        .chunks(2)
        .map(|pair| {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut input = Vec::with_capacity(64);
            input.extend_from_slice(&pair[0]);
            input.extend_from_slice(right);
            hash_domain_separated(
                &Blake3HashProviderV1,
                HashDomain::TransportBatchNodeV1,
                &input,
            )
        })
        .collect()
}

fn receipt_state_code(state: VoterReceiptStateV1) -> u64 {
    match state {
        VoterReceiptStateV1::Accepted => 1,
        VoterReceiptStateV1::Rejected => 2,
        // A persisted retry record is always a terminal intake result. The
        // remaining receipt states are intentionally not durable retry data.
        VoterReceiptStateV1::Received | VoterReceiptStateV1::Included | VoterReceiptStateV1::Anchored => 0,
    }
}

fn receipt_state_from_code(code: u64) -> Result<VoterReceiptStateV1, TransportError> {
    match code {
        1 => Ok(VoterReceiptStateV1::Accepted),
        2 => Ok(VoterReceiptStateV1::Rejected),
        _ => Err(TransportError::InvalidDescriptor),
    }
}

fn read_fixed<const N: usize>(
    reader: &mut CanonicalCborReader<'_>,
) -> Result<[u8; N], TransportError> {
    reader
        .read_byte_string()
        .map_err(|_| TransportError::InvalidDescriptor)?
        .try_into()
        .map_err(|_| TransportError::InvalidDescriptor)
}

/// Generates a non-identity retry capability in the gateway client helper.
#[must_use]
pub fn new_retry_capability_v1() -> [u8; 32] {
    let (secret, _) = Kem::gen_keypair();
    let mut capability = [0; 32];
    capability.copy_from_slice(secret.to_bytes().as_slice());
    capability
}

fn unpad_authenticated_payload(padded: &[u8], expected: usize) -> Result<Vec<u8>, TransportError> {
    if padded.len() != expected || padded.len() < 4 {
        return Err(TransportError::InvalidEnvelope);
    }
    let length = u32::from_be_bytes(
        padded[..4]
            .try_into()
            .map_err(|_| TransportError::InvalidEnvelope)?,
    ) as usize;
    if length.checked_add(4).is_none_or(|end| end > padded.len())
        || padded[4 + length..].iter().any(|byte| *byte != 0)
    {
        return Err(TransportError::InvalidEnvelope);
    }
    Ok(padded[4..4 + length].to_vec())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn descriptor() -> TransportDescriptorV1 {
        let signing = SigningKey::from_bytes(&[3; 32]);
        TransportDescriptorV1::sign_for_test_or_ceremony(
            b"durable-state-election".to_vec(),
            ManifestHash::new([4; 32]),
            7,
            tari_cc_private_ballot_gui_core::TransportRoutePolicyV1::ManagedTorOrOffline,
            vec!["http://test.invalid".to_owned()],
            Vec::new(),
            [5; 32],
            "test-gateway".to_owned(),
            vec![[6; 32]],
            tari_cc_private_ballot_gui_core::PaddingPolicyV1 {
                id: "fixed-test-padding".to_owned(),
                padded_bytes: 2048,
            },
            tari_cc_private_ballot_gui_core::BatchPolicyV1 {
                id: "test-batch-policy".to_owned(),
                accepted_unique_floor: 2,
            },
            None,
            "test-root".to_owned(),
            &signing,
        )
        .expect("test descriptor")
    }

    fn persisted_gateway() -> TransportGatewaySimulatorV1 {
        let batch_digest = [8; 32];
        let leaf = hash_domain_separated(
            &Blake3HashProviderV1,
            HashDomain::TransportBatchLeafV1,
            &batch_digest,
        );
        TransportGatewaySimulatorV1 {
            received_count: 2,
            verified_count: 2,
            accepted_unique_count: 2,
            retries: BTreeMap::from([
                (
                    [1; 32],
                    RetryRecordV1 {
                        package_digest: [2; 32],
                        receipt: VoterTransportReceiptV1 {
                            state: VoterReceiptStateV1::Accepted,
                            retry_status: RetryStatusV1::NewDelivery,
                        },
                    },
                ),
                (
                    [3; 32],
                    RetryRecordV1 {
                        package_digest: [4; 32],
                        receipt: VoterTransportReceiptV1 {
                            state: VoterReceiptStateV1::Rejected,
                            retry_status: RetryStatusV1::NewDelivery,
                        },
                    },
                ),
            ]),
            admission: TransportAdmissionGateV1::default(),
            pending_digests: vec![[9; 32]],
            sealed_batches: vec![SealedTransportBatchV1 {
                batch_id: 0,
                root: leaf,
                accepted_unique_count: 1,
                reduced_anonymity: true,
                digests: vec![batch_digest],
            }],
            next_batch_id: 1,
            retry_retention: RetryRetentionV1::ActiveElection,
        }
    }

    fn temp_state_path(label: &str) -> std::path::PathBuf {
        let unique = format!("{label}-{}", std::process::id());
        std::env::temp_dir().join(unique).join("gateway-state.cbor")
    }

    #[test]
    fn odd_leaf_merkle_proofs_are_deterministic_and_verifiable() {
        let mut digests = vec![[3; 32], [1; 32], [2; 32]];
        digests.sort_unstable();
        let leaves: Vec<[u8; 32]> = digests
            .iter()
            .map(|digest| {
                hash_domain_separated(
                    &Blake3HashProviderV1,
                    HashDomain::TransportBatchLeafV1,
                    digest,
                )
            })
            .collect();
        let batch = SealedTransportBatchV1 {
            batch_id: 0,
            root: merkle_root(&leaves).expect("non-empty batch has root"),
            accepted_unique_count: 3,
            reduced_anonymity: true,
            digests: digests.clone(),
        };
        for digest in digests {
            assert!(
                batch
                    .inclusion_proof(digest)
                    .expect("member has proof")
                    .verify()
            );
        }
        assert!(batch.inclusion_proof([9; 32]).is_none());
    }

    #[test]
    fn receipt_signature_detects_mutation() {
        let signing = SigningKey::from_bytes(&[8; 32]);
        let mut receipt = SignedTransportReceiptV1::sign(
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Accepted,
                retry_status: RetryStatusV1::NewDelivery,
            },
            [4; 32],
            None,
            "test-receipt-key".to_owned(),
            &signing,
        );
        receipt
            .verify(&signing.verifying_key())
            .expect("signature verifies");
        receipt.package_digest[0] ^= 1;
        assert!(receipt.verify(&signing.verifying_key()).is_err());
    }

    #[test]
    fn durable_state_reloads_retry_results_and_inclusion_material() {
        let descriptor = descriptor();
        let path = temp_state_path("transport-gateway-durable-reload");
        let gateway = persisted_gateway();
        gateway
            .save_durable_state(&descriptor, &path)
            .expect("durable state writes");
        let restored = TransportGatewaySimulatorV1::load_durable_state(&path, &descriptor)
            .expect("durable state reloads");
        assert_eq!(restored.final_batch_set_commitment(), gateway.final_batch_set_commitment());
        assert!(restored.sealed_batches[0]
            .inclusion_proof([8; 32])
            .expect("proof survives reload")
            .verify());
        assert_eq!(restored.retries[&[1; 32]].receipt.state, VoterReceiptStateV1::Accepted);
        assert_eq!(restored.retries[&[3; 32]].receipt.state, VoterReceiptStateV1::Rejected);
        let bytes = std::fs::read(&path).expect("state readable");
        assert!(!bytes.windows(b"X-Forwarded-For".len()).any(|v| v == b"X-Forwarded-For"));
        assert!(!bytes.windows(b"retry-capability".len()).any(|v| v == b"retry-capability"));
    }

    #[test]
    fn corrupt_or_incompatible_durable_state_fails_closed() {
        let descriptor = descriptor();
        let path = temp_state_path("transport-gateway-durable-corrupt");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("parent creates");
        std::fs::write(&path, [0xff, 0x00]).expect("corruption writes");
        assert!(TransportGatewaySimulatorV1::load_durable_state(&path, &descriptor).is_err());
        persisted_gateway()
            .save_durable_state(&descriptor, &path.with_extension("valid"))
            .expect("valid snapshot writes");
        assert!(TransportGatewaySimulatorV1::load_durable_state(&path.with_extension("valid"), &descriptor)
            .is_ok());
    }

    #[test]
    fn expiry_removes_retry_commitments_but_keeps_public_batches() {
        let descriptor = descriptor();
        let path = temp_state_path("transport-gateway-durable-expiry");
        let mut gateway = persisted_gateway();
        gateway.begin_retry_verification_grace();
        gateway.expire_retry_retention();
        gateway.save_durable_state(&descriptor, &path).expect("expired state writes");
        let restored = TransportGatewaySimulatorV1::load_durable_state(&path, &descriptor)
            .expect("expired state reloads");
        assert_eq!(restored.retry_retention(), RetryRetentionV1::Expired);
        assert!(restored.retries.is_empty());
        assert!(restored.final_batch_set_commitment().is_some());
    }
}
