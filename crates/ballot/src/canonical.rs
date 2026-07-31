//! Canonical candidate and approval-payload serialization.

use tari_cc_private_ballot_protocol::{
    BallotPayloadHash, CandidateSetCommitment, CanonicalCborReader, CanonicalCborWriter,
    HashDomain, HashProvider, MAX_CANDIDATES, MAX_CANONICAL_OBJECT_BYTES, ProtocolError,
    ValidationCode, hash_domain_separated,
};

use crate::{
    ApprovalBallotPayload, ApprovalLimits, CandidateDefinition, CandidateId, CandidateSet,
};

impl CandidateSet {
    /// Encodes candidates in canonical candidate-ID order.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(self.candidates().len())?;

        for candidate in self.candidates() {
            writer.write_array_len(2)?;
            writer.write_byte_string(candidate.id().as_bytes())?;
            writer.write_text_string(candidate.display_name())?;
        }

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical candidate set exceeds the protocol object limit",
            ));
        }

        Ok(encoded)
    }

    /// Strictly decodes one canonically ordered candidate set.
    pub fn from_canonical_cbor(encoded: &[u8]) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded candidate set exceeds the protocol object limit",
            ));
        }

        let mut reader = CanonicalCborReader::new(encoded);
        let candidate_count = reader.read_array_len()?;

        if candidate_count == 0 {
            return Err(ProtocolError::new(
                ValidationCode::EmptyCandidateSet,
                "candidate set must not be empty",
            ));
        }

        if candidate_count > MAX_CANDIDATES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "candidate count exceeds the protocol limit",
            ));
        }

        let mut candidates = Vec::with_capacity(candidate_count);

        for _ in 0..candidate_count {
            if reader.read_array_len()? != 2 {
                return Err(ProtocolError::new(
                    ValidationCode::InvalidCbor,
                    "candidate entry must contain exactly two fields",
                ));
            }

            let id = CandidateId::new(reader.read_byte_string()?.to_vec())?;
            let display_name = reader.read_text_string()?.to_owned();

            candidates.push(CandidateDefinition::new(id, display_name)?);
        }

        reader.finish()?;

        for pair in candidates.windows(2) {
            if pair[0].id() == pair[1].id() {
                return Err(ProtocolError::new(
                    ValidationCode::DuplicateCandidateId,
                    "candidate set contains a duplicate candidate identifier",
                ));
            }

            if pair[0].id() > pair[1].id() {
                return Err(ProtocolError::new(
                    ValidationCode::NonCanonicalCbor,
                    "candidate identifiers are not in canonical order",
                ));
            }
        }

        Self::new(candidates)
    }

    /// Derives the candidate-set commitment from canonical CBOR bytes.
    pub fn canonical_commitment<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<CandidateSetCommitment, ProtocolError> {
        let encoded = self.to_canonical_cbor()?;
        let digest = hash_domain_separated(provider, HashDomain::CandidateSetV1, &encoded);

        Ok(CandidateSetCommitment::new(digest))
    }
}

impl ApprovalBallotPayload {
    /// Encodes selected candidate IDs in canonical order.
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, ProtocolError> {
        let mut writer = CanonicalCborWriter::new();

        writer.write_array_len(self.selections().len())?;

        for candidate_id in self.selections() {
            writer.write_byte_string(candidate_id.as_bytes())?;
        }

        let encoded = writer.into_bytes();

        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "canonical ballot payload exceeds the protocol object limit",
            ));
        }

        Ok(encoded)
    }

    /// Strictly decodes and validates one approval payload.
    pub fn from_canonical_cbor(
        encoded: &[u8],
        candidates: &CandidateSet,
        limits: ApprovalLimits,
    ) -> Result<Self, ProtocolError> {
        if encoded.len() > MAX_CANONICAL_OBJECT_BYTES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "encoded ballot payload exceeds the protocol object limit",
            ));
        }

        let mut reader = CanonicalCborReader::new(encoded);
        let selection_count = reader.read_array_len()?;

        if selection_count > MAX_CANDIDATES {
            return Err(ProtocolError::new(
                ValidationCode::ProtocolLimitExceeded,
                "ballot selection count exceeds the protocol limit",
            ));
        }

        let mut selections = Vec::with_capacity(selection_count);

        for _ in 0..selection_count {
            selections.push(CandidateId::new(reader.read_byte_string()?.to_vec())?);
        }

        reader.finish()?;

        for pair in selections.windows(2) {
            if pair[0] == pair[1] {
                return Err(ProtocolError::new(
                    ValidationCode::DuplicateSelection,
                    "approval ballot contains a duplicate candidate",
                ));
            }

            if pair[0] > pair[1] {
                return Err(ProtocolError::new(
                    ValidationCode::NonCanonicalCbor,
                    "ballot selections are not in canonical order",
                ));
            }
        }

        Self::new(selections, candidates, limits)
    }

    /// Derives a ballot-payload hash from canonical CBOR bytes.
    pub fn canonical_hash<H: HashProvider>(
        &self,
        provider: &H,
    ) -> Result<BallotPayloadHash, ProtocolError> {
        let encoded = self.to_canonical_cbor()?;
        let digest = hash_domain_separated(provider, HashDomain::ApprovalBallotPayloadV1, &encoded);

        Ok(BallotPayloadHash::new(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tari_cc_private_ballot_protocol::{
        CanonicalCborWriter, MAX_CANDIDATE_DISPLAY_NAME_BYTES, MAX_CANDIDATE_ID_BYTES,
        MAX_CANDIDATES, ValidationCode, test_only::TestOnlyDeterministicHasher,
    };

    fn id(bytes: &[u8]) -> CandidateId {
        let Ok(id) = CandidateId::new(bytes.to_vec()) else {
            panic!("test candidate ID must be valid");
        };

        id
    }

    fn candidate(identifier: &[u8], name: &str) -> CandidateDefinition {
        let Ok(candidate) = CandidateDefinition::new(id(identifier), name.to_owned()) else {
            panic!("test candidate must be valid");
        };

        candidate
    }

    fn candidate_set() -> CandidateSet {
        let Ok(candidates) = CandidateSet::new(vec![
            candidate(b"candidate-c", "Candidate C"),
            candidate(b"candidate-a", "Candidate A"),
            candidate(b"candidate-b", "Candidate B"),
        ]) else {
            panic!("test candidate set must be valid");
        };

        candidates
    }

    fn limits(minimum: usize, maximum: usize, allow_abstention: bool) -> ApprovalLimits {
        let Ok(limits) = ApprovalLimits::new(minimum, maximum, allow_abstention) else {
            panic!("test limits must be valid");
        };

        limits
    }

    fn payload(
        candidates: &CandidateSet,
        selections: Vec<CandidateId>,
        approval_limits: ApprovalLimits,
    ) -> ApprovalBallotPayload {
        let Ok(payload) = ApprovalBallotPayload::new(selections, candidates, approval_limits)
        else {
            panic!("test payload must be valid");
        };

        payload
    }

    #[test]
    fn candidate_set_vector_is_exact() {
        let Ok(candidates) = CandidateSet::new(vec![candidate(b"b", "Bee"), candidate(b"a", "A")])
        else {
            panic!("candidate set should be valid");
        };

        let Ok(encoded) = candidates.to_canonical_cbor() else {
            panic!("candidate encoding should succeed");
        };

        assert_eq!(
            encoded,
            vec![
                0x82, 0x82, 0x41, b'a', 0x61, b'A', 0x82, 0x41, b'b', 0x63, b'B', b'e', b'e',
            ]
        );
    }

    #[test]
    fn candidate_set_round_trip_preserves_exact_bytes() {
        let candidates = candidate_set();

        let Ok(encoded) = candidates.to_canonical_cbor() else {
            panic!("candidate encoding should succeed");
        };

        let Ok(decoded) = CandidateSet::from_canonical_cbor(&encoded) else {
            panic!("candidate decoding should succeed");
        };

        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("candidate re-encoding should succeed");
        };

        assert_eq!(decoded, candidates);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn candidate_input_order_does_not_change_commitment() {
        let Ok(first) = CandidateSet::new(vec![candidate(b"a", "A"), candidate(b"b", "B")]) else {
            panic!("first candidate set should be valid");
        };

        let Ok(second) = CandidateSet::new(vec![candidate(b"b", "B"), candidate(b"a", "A")]) else {
            panic!("second candidate set should be valid");
        };

        let provider = TestOnlyDeterministicHasher;

        let Ok(first_commitment) = first.canonical_commitment(&provider) else {
            panic!("first commitment should succeed");
        };

        let Ok(second_commitment) = second.canonical_commitment(&provider) else {
            panic!("second commitment should succeed");
        };

        assert_eq!(first_commitment, second_commitment);
    }

    #[test]
    fn candidate_changes_produce_different_commitments() {
        let Ok(base) = CandidateSet::new(vec![candidate(b"a", "A")]) else {
            panic!("base candidate set should be valid");
        };

        let Ok(changed_name) = CandidateSet::new(vec![candidate(b"a", "Other")]) else {
            panic!("changed-name candidate set should be valid");
        };

        let Ok(changed_id) = CandidateSet::new(vec![candidate(b"b", "A")]) else {
            panic!("changed-ID candidate set should be valid");
        };

        let provider = TestOnlyDeterministicHasher;

        let Ok(base_commitment) = base.canonical_commitment(&provider) else {
            panic!("base commitment should succeed");
        };

        let Ok(name_commitment) = changed_name.canonical_commitment(&provider) else {
            panic!("name commitment should succeed");
        };

        let Ok(id_commitment) = changed_id.canonical_commitment(&provider) else {
            panic!("ID commitment should succeed");
        };

        assert_ne!(base_commitment, name_commitment);
        assert_ne!(base_commitment, id_commitment);
    }

    #[test]
    fn unsorted_encoded_candidates_are_rejected() {
        let encoded = vec![
            0x82, 0x82, 0x41, b'b', 0x61, b'B', 0x82, 0x41, b'a', 0x61, b'A',
        ];

        let result = CandidateSet::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn duplicate_encoded_candidate_id_is_rejected() {
        let encoded = vec![
            0x82, 0x82, 0x41, b'a', 0x61, b'A', 0x82, 0x41, b'a', 0x61, b'B',
        ];

        let result = CandidateSet::from_canonical_cbor(&encoded);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::DuplicateCandidateId
        ));
    }

    #[test]
    fn encoded_candidate_limit_is_enforced_before_allocation() {
        let mut writer = CanonicalCborWriter::new();

        assert!(writer.write_array_len(MAX_CANDIDATES + 1).is_ok());

        let result = CandidateSet::from_canonical_cbor(&writer.into_bytes());

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_candidate_id_is_rejected() {
        let result = CandidateId::new(vec![7_u8; MAX_CANDIDATE_ID_BYTES + 1]);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_candidate_display_name_is_rejected() {
        let result =
            CandidateDefinition::new(id(b"a"), "n".repeat(MAX_CANDIDATE_DISPLAY_NAME_BYTES + 1));

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn oversized_candidate_set_is_rejected() {
        let mut candidates = Vec::with_capacity(MAX_CANDIDATES + 1);

        for index in 0..=MAX_CANDIDATES {
            let Ok(value) = u32::try_from(index) else {
                panic!("candidate index should fit in u32");
            };

            candidates.push(candidate(&value.to_be_bytes(), "Candidate"));
        }

        let result = CandidateSet::new(candidates);

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::ProtocolLimitExceeded
        ));
    }

    #[test]
    fn approval_payload_vector_is_exact() {
        let candidates = candidate_set();
        let payload = payload(
            &candidates,
            vec![id(b"candidate-c"), id(b"candidate-a")],
            limits(1, 2, false),
        );

        let Ok(encoded) = payload.to_canonical_cbor() else {
            panic!("payload encoding should succeed");
        };

        assert_eq!(
            encoded,
            vec![
                0x82, 0x4b, b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e', b'-', b'a', 0x4b,
                b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e', b'-', b'c',
            ]
        );
    }

    #[test]
    fn approval_payload_round_trip_preserves_exact_bytes() {
        let candidates = candidate_set();
        let original = payload(
            &candidates,
            vec![id(b"candidate-b"), id(b"candidate-a")],
            limits(1, 2, true),
        );

        let Ok(encoded) = original.to_canonical_cbor() else {
            panic!("payload encoding should succeed");
        };

        let Ok(decoded) =
            ApprovalBallotPayload::from_canonical_cbor(&encoded, &candidates, limits(1, 2, true))
        else {
            panic!("payload decoding should succeed");
        };

        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("payload re-encoding should succeed");
        };

        assert_eq!(decoded, original);
        assert_eq!(reencoded, encoded);
    }

    #[test]
    fn changed_choices_produce_different_payload_hashes() {
        let candidates = candidate_set();
        let first = payload(&candidates, vec![id(b"candidate-a")], limits(1, 2, false));
        let second = payload(&candidates, vec![id(b"candidate-b")], limits(1, 2, false));

        let provider = TestOnlyDeterministicHasher;

        let Ok(first_hash) = first.canonical_hash(&provider) else {
            panic!("first payload hash should succeed");
        };

        let Ok(second_hash) = second.canonical_hash(&provider) else {
            panic!("second payload hash should succeed");
        };

        assert_ne!(first_hash, second_hash);
    }

    #[test]
    fn unsorted_encoded_selections_are_rejected() {
        let candidates = candidate_set();
        let encoded = vec![
            0x82, 0x4b, b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e', b'-', b'b', 0x4b,
            b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e', b'-', b'a',
        ];

        let result =
            ApprovalBallotPayload::from_canonical_cbor(&encoded, &candidates, limits(1, 2, false));

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::NonCanonicalCbor
        ));
    }

    #[test]
    fn duplicate_encoded_selection_is_rejected() {
        let candidates = candidate_set();
        let encoded = vec![
            0x82, 0x4b, b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e', b'-', b'a', 0x4b,
            b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e', b'-', b'a',
        ];

        let result =
            ApprovalBallotPayload::from_canonical_cbor(&encoded, &candidates, limits(1, 2, false));

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::DuplicateSelection
        ));
    }

    #[test]
    fn unknown_encoded_selection_is_rejected() {
        let candidates = candidate_set();
        let encoded = vec![
            0x81, 0x4b, b'c', b'a', b'n', b'd', b'i', b'd', b'a', b't', b'e', b'-', b'z',
        ];

        let result =
            ApprovalBallotPayload::from_canonical_cbor(&encoded, &candidates, limits(1, 2, false));

        assert!(matches!(
            result,
            Err(error)
                if error.code() == ValidationCode::UnknownCandidateId
        ));
    }
}
