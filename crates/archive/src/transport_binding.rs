//! Canonical public binding from sealed transport batches into an archive.
//!
//! This is an archive constituent, not an Ootle record and not an archive
//! hash. Its exact bytes are later covered by the ordinary archive catalog and
//! `ArchiveHashV1`; the Phase 4 Ootle anchor protocol remains unchanged.

use tari_cc_private_ballot_protocol::{
    CanonicalCborReader, CanonicalCborWriter, HashDomain, ManifestHash,
    MAX_CANONICAL_OBJECT_BYTES, ProtocolError, ValidationCode, hash_domain_separated,
};

/// Canonical archive path for the public transport-to-archive binding.
pub const TRANSPORT_ARCHIVE_BINDING_PATH_V1: &str = "transport/archive-binding-v1.cbor";
/// Stable schema marker for the binding artifact.
pub const TRANSPORT_ARCHIVE_BINDING_TYPE_ID_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_TRANSPORT_ARCHIVE_BINDING_V1";
/// Stable identifier for the frozen transport batch-set calculation.
pub const TRANSPORT_BATCH_SET_ALGORITHM_ID_V1: &str =
    "TARI_CC_PRIVATE_BALLOT_TRANSPORT_BATCH_SET_V1";

const VERSION: u64 = 1;
const FIELD_COUNT: usize = 9;
const BATCH_FIELD_COUNT: usize = 4;
const MAX_BATCHES: usize = 4_096;

/// One sealed public batch commitment. The identifier is an operator sealing
/// epoch, not ingress order or a voter-facing sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportArchiveBatchV1 {
    batch_id: u64,
    root: [u8; 32],
    accepted_unique_count: u64,
    reduced_anonymity: bool,
}

impl TransportArchiveBatchV1 {
    #[must_use]
    pub const fn new(
        batch_id: u64,
        root: [u8; 32],
        accepted_unique_count: u64,
        reduced_anonymity: bool,
    ) -> Self {
        Self { batch_id, root, accepted_unique_count, reduced_anonymity }
    }

    #[must_use]
    pub const fn batch_id(&self) -> u64 { self.batch_id }
    #[must_use]
    pub const fn root(&self) -> [u8; 32] { self.root }
    #[must_use]
    pub const fn accepted_unique_count(&self) -> u64 { self.accepted_unique_count }
    #[must_use]
    pub const fn reduced_anonymity(&self) -> bool { self.reduced_anonymity }
}

/// Version-one public audit binding between one election and its sealed
/// transport batch set. It deliberately contains no ballot, retry capability,
/// ingress timing, relay/source metadata, credential, nullifier, or secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportArchiveBindingV1 {
    election_id: Vec<u8>,
    manifest_hash: ManifestHash,
    descriptor_fingerprint: [u8; 32],
    descriptor_generation: u64,
    batches: Vec<TransportArchiveBatchV1>,
    final_batch_set_commitment: [u8; 32],
}

impl TransportArchiveBindingV1 {
    pub fn new(
        election_id: Vec<u8>,
        manifest_hash: ManifestHash,
        descriptor_fingerprint: [u8; 32],
        descriptor_generation: u64,
        mut batches: Vec<TransportArchiveBatchV1>,
    ) -> Result<Self, ProtocolError> {
        if election_id.is_empty() || election_id.len() > 128 {
            return Err(invalid("transport binding election identity is invalid"));
        }
        if batches.is_empty() || batches.len() > MAX_BATCHES {
            return Err(invalid("transport binding must contain a bounded non-empty batch set"));
        }
        batches.sort_by_key(TransportArchiveBatchV1::batch_id);
        for pair in batches.windows(2) {
            if pair[0].batch_id() == pair[1].batch_id() {
                return Err(invalid("transport binding batch identities must be unique"));
            }
        }
        let final_batch_set_commitment = batch_set_commitment(&batches);
        Ok(Self {
            election_id,
            manifest_hash,
            descriptor_fingerprint,
            descriptor_generation,
            batches,
            final_batch_set_commitment,
        })
    }

    #[must_use]
    pub fn election_id(&self) -> &[u8] { &self.election_id }
    #[must_use]
    pub const fn manifest_hash(&self) -> ManifestHash { self.manifest_hash }
    #[must_use]
    pub const fn descriptor_fingerprint(&self) -> [u8; 32] { self.descriptor_fingerprint }
    #[must_use]
    pub const fn descriptor_generation(&self) -> u64 { self.descriptor_generation }
    #[must_use]
    pub fn batches(&self) -> &[TransportArchiveBatchV1] { &self.batches }
    #[must_use]
    pub const fn final_batch_set_commitment(&self) -> [u8; 32] { self.final_batch_set_commitment }

    /// Verifies the batch identities and the claimed derived batch-root
    /// commitment. `final_batch_set_commitment` is intentionally independent
    /// of archive and Ootle verification; the completed archive's
    /// `ArchiveHashV1` is the authoritative Phase 4 commitment.
    pub fn verify_commitment(&self) -> Result<(), ProtocolError> {
        let rebuilt = Self::new(
            self.election_id.clone(),
            self.manifest_hash,
            self.descriptor_fingerprint,
            self.descriptor_generation,
            self.batches.clone(),
        )?;
        if rebuilt.batches != self.batches
            || rebuilt.final_batch_set_commitment != self.final_batch_set_commitment
        {
            return Err(ProtocolError::new(
                ValidationCode::InvalidData,
                "transport binding batch set does not match its final commitment",
            ));
        }
        Ok(())
    }

    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        self.verify_commitment()?;
        let mut writer = CanonicalCborWriter::new();
        writer.write_array_len(FIELD_COUNT)?;
        writer.write_unsigned(VERSION);
        writer.write_text_string(TRANSPORT_ARCHIVE_BINDING_TYPE_ID_V1)?;
        writer.write_byte_string(&self.election_id)?;
        writer.write_byte_string(self.manifest_hash.as_bytes())?;
        writer.write_byte_string(&self.descriptor_fingerprint)?;
        writer.write_unsigned(self.descriptor_generation);
        writer.write_text_string(TRANSPORT_BATCH_SET_ALGORITHM_ID_V1)?;
        writer.write_array_len(self.batches.len())?;
        for batch in &self.batches {
            writer.write_array_len(BATCH_FIELD_COUNT)?;
            writer.write_unsigned(batch.batch_id());
            writer.write_byte_string(&batch.root())?;
            writer.write_unsigned(batch.accepted_unique_count());
            writer.write_bool(batch.reduced_anonymity());
        }
        writer.write_byte_string(&self.final_batch_set_commitment)?;
        let bytes = writer.into_bytes();
        if bytes.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "transport archive binding exceeds the canonical object limit",
            ));
        }
        Ok(bytes)
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, ProtocolError> {
        if bytes.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "transport archive binding exceeds the canonical object limit",
            ));
        }
        let mut reader = CanonicalCborReader::new(bytes);
        if reader.read_array_len()? != FIELD_COUNT
            || reader.read_unsigned()? != VERSION
            || reader.read_text_string()? != TRANSPORT_ARCHIVE_BINDING_TYPE_ID_V1
        {
            return Err(invalid("invalid transport archive binding header"));
        }
        let election_id = reader.read_byte_string()?.to_vec();
        let manifest_hash = ManifestHash::new(read_fixed(&mut reader)?);
        let descriptor_fingerprint = read_fixed(&mut reader)?;
        let descriptor_generation = reader.read_unsigned()?;
        if reader.read_text_string()? != TRANSPORT_BATCH_SET_ALGORITHM_ID_V1 {
            return Err(invalid("unsupported transport batch-set algorithm"));
        }
        let count = reader.read_array_len()?;
        if count == 0 || count > MAX_BATCHES {
            return Err(invalid("transport binding batch count is invalid"));
        }
        let mut batches = Vec::with_capacity(count);
        for _ in 0..count {
            if reader.read_array_len()? != BATCH_FIELD_COUNT {
                return Err(invalid("transport binding batch has an invalid field count"));
            }
            batches.push(TransportArchiveBatchV1::new(
                reader.read_unsigned()?,
                read_fixed(&mut reader)?,
                reader.read_unsigned()?,
                reader.read_bool()?,
            ));
        }
        let final_batch_set_commitment = read_fixed(&mut reader)?;
        reader.finish()?;
        let output = Self::new(
            election_id,
            manifest_hash,
            descriptor_fingerprint,
            descriptor_generation,
            batches,
        )?;
        if output.final_batch_set_commitment != final_batch_set_commitment
            || output.to_canonical_cbor()? != bytes
        {
            return Err(ProtocolError::new(
                ValidationCode::NonCanonicalCbor,
                "transport archive binding is not canonical or its commitment is invalid",
            ));
        }
        Ok(output)
    }
}

fn batch_set_commitment(batches: &[TransportArchiveBatchV1]) -> [u8; 32] {
    let mut roots: Vec<[u8; 32]> = batches.iter().map(TransportArchiveBatchV1::root).collect();
    roots.sort_unstable();
    hash_domain_separated(
        &tari_cc_private_ballot_protocol::Blake3HashProviderV1,
        HashDomain::TransportBatchSetV1,
        &roots.concat(),
    )
}

fn read_fixed<const N: usize>(reader: &mut CanonicalCborReader<'_>) -> Result<[u8; N], ProtocolError> {
    <[u8; N]>::try_from(reader.read_byte_string()?).map_err(|_| invalid("transport binding digest length is invalid"))
}

fn invalid(message: &'static str) -> ProtocolError {
    ProtocolError::new(ValidationCode::InvalidData, message)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn binding() -> TransportArchiveBindingV1 {
        TransportArchiveBindingV1::new(
            b"election".to_vec(),
            ManifestHash::new([1; 32]),
            [2; 32],
            7,
            vec![
                TransportArchiveBatchV1::new(4, [4; 32], 2, false),
                TransportArchiveBatchV1::new(2, [2; 32], 1, true),
            ],
        ).expect("valid binding")
    }

    #[test]
    fn canonical_round_trip_sorts_by_sealed_batch_identity() {
        let binding = binding();
        assert_eq!(binding.batches()[0].batch_id(), 2);
        let bytes = binding.to_canonical_cbor().expect("canonical encode");
        let decoded = TransportArchiveBindingV1::from_canonical_cbor(&bytes).expect("canonical decode");
        assert_eq!(decoded, binding);
        assert_eq!(decoded.to_canonical_cbor().expect("re-encode"), bytes);
    }

    #[test]
    fn changed_final_commitment_is_rejected() {
        let mut bytes = binding().to_canonical_cbor().expect("canonical encode");
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert!(TransportArchiveBindingV1::from_canonical_cbor(&bytes).is_err());
    }

    #[test]
    fn duplicate_batch_identity_is_rejected() {
        assert!(TransportArchiveBindingV1::new(
            b"election".to_vec(), ManifestHash::new([1; 32]), [2; 32], 1,
            vec![
                TransportArchiveBatchV1::new(1, [3; 32], 1, false),
                TransportArchiveBatchV1::new(1, [4; 32], 1, false),
            ],
        ).is_err());
    }
}
