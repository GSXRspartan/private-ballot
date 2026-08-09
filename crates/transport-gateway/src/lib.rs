//! Local-only receiver boundary for private ballot envelopes.
//!
//! This crate owns HPKE receiver secrets, opens authenticated ciphertext, and
//! passes exact recovered bytes to gui-core's existing 5A11 intake boundary.

use std::collections::BTreeMap;

use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use tari_cc_private_ballot_gui_core::{
    GuiElectionSessionV1, GuiIntakeCategory, PrivateBallotEnvelopeV1, RetryStatusV1,
    TransportDescriptorV1, TransportError, VoterReceiptStateV1, VoterTransportReceiptV1,
};
use tari_cc_private_ballot_protocol::{Blake3HashProviderV1, HashDomain, hash_domain_separated};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;
const HPKE_INFO: &[u8] = b"tari-cc-private-ballot/private-ballot-envelope/v1";

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
}

#[derive(Clone)]
struct RetryRecordV1 {
    package_digest: [u8; 32],
    receipt: VoterTransportReceiptV1,
}

impl TransportGatewaySimulatorV1 {
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

        self.verified_count = self.verified_count.saturating_add(1);
        let result = session
            .intake_ballot_package_bytes(&bytes)
            .map_err(|_| TransportError::Unavailable)?;
        let receipt = if result.accepted {
            self.accepted_unique_count = self.accepted_unique_count.saturating_add(1);
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Accepted,
                retry_status: RetryStatusV1::NewDelivery,
            }
        } else if result.category == GuiIntakeCategory::Duplicate {
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Received,
                retry_status: RetryStatusV1::GenericDuplicate,
            }
        } else {
            VoterTransportReceiptV1 {
                state: VoterReceiptStateV1::Rejected,
                retry_status: RetryStatusV1::NewDelivery,
            }
        };
        self.retries.insert(
            capability_commitment,
            RetryRecordV1 {
                package_digest,
                receipt: receipt.clone(),
            },
        );
        Ok(receipt)
    }
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
