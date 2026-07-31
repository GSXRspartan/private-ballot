//! Deterministic hash framing and domain-separation boundaries.

/// Stable prefix placed before every domain-separated hash input.
pub const HASH_FRAME_PREFIX: &[u8] = b"TARI_CC_PRIVATE_BALLOT_HASH_FRAME_V1";

/// Protocol object domains that must never share an unqualified hash input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashDomain {
    RegistrySnapshotV1,
    CandidateSetV1,
    ElectionManifestV1,
    ApprovalBallotPayloadV1,
    BallotPackageV1,
    ElectionScopeV1,
    ProofStatementV1,
    ArchiveManifestV1,
}

impl HashDomain {
    /// Returns the stable domain-separation label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RegistrySnapshotV1 => "tari-cc-private-ballot/registry-snapshot/v1",
            Self::CandidateSetV1 => "tari-cc-private-ballot/candidate-set/v1",
            Self::ElectionManifestV1 => "tari-cc-private-ballot/election-manifest/v1",
            Self::ApprovalBallotPayloadV1 => "tari-cc-private-ballot/approval-ballot-payload/v1",
            Self::BallotPackageV1 => "tari-cc-private-ballot/ballot-package/v1",
            Self::ElectionScopeV1 => "tari-cc-private-ballot/election-scope/v1",
            Self::ProofStatementV1 => "tari-cc-private-ballot/proof-statement/v1",
            Self::ArchiveManifestV1 => "tari-cc-private-ballot/archive-manifest/v1",
        }
    }
}

/// Hash implementation selected by a versioned protocol suite.
pub trait HashProvider {
    /// Returns the exact algorithm or suite identifier.
    fn algorithm_id(&self) -> &'static str;

    /// Hashes one already framed byte sequence into 32 bytes.
    fn hash(&self, framed_input: &[u8]) -> [u8; 32];
}

/// Creates the exact bytes supplied to a hash provider.
///
/// The frame is:
///
/// `prefix || 0x00 || domain-label || 0x00 || canonical-object-bytes`
#[must_use]
pub fn domain_separated_input(domain: HashDomain, canonical_object_bytes: &[u8]) -> Vec<u8> {
    let label = domain.label().as_bytes();

    let mut framed = Vec::with_capacity(
        HASH_FRAME_PREFIX.len() + 1 + label.len() + 1 + canonical_object_bytes.len(),
    );

    framed.extend_from_slice(HASH_FRAME_PREFIX);
    framed.push(0);
    framed.extend_from_slice(label);
    framed.push(0);
    framed.extend_from_slice(canonical_object_bytes);

    framed
}

/// Hashes canonical object bytes using the selected protocol domain.
#[must_use]
pub fn hash_domain_separated<H: HashProvider>(
    provider: &H,
    domain: HashDomain,
    canonical_object_bytes: &[u8],
) -> [u8; 32] {
    let framed = domain_separated_input(domain, canonical_object_bytes);
    provider.hash(&framed)
}

/// Explicitly non-cryptographic provider for debug and test plumbing.
#[cfg(any(test, debug_assertions))]
pub mod test_only {
    use super::HashProvider;

    /// Stable warning label for the non-cryptographic test provider.
    pub const TEST_ONLY_HASH_ALGORITHM_ID: &str = "TEST_ONLY_DETERMINISTIC_HASH_NOT_CRYPTOGRAPHIC";

    /// Deterministic but non-cryptographic test hasher.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct TestOnlyDeterministicHasher;

    impl HashProvider for TestOnlyDeterministicHasher {
        fn algorithm_id(&self) -> &'static str {
            TEST_ONLY_HASH_ALGORITHM_ID
        }

        fn hash(&self, framed_input: &[u8]) -> [u8; 32] {
            let mut output = [0_u8; 32];
            let mut state = 0x9e37_79b9_7f4a_7c15_u64;

            for (index, byte) in framed_input.iter().copied().enumerate() {
                let lane = index % output.len();
                let shift = (lane % 8) * 8;

                state ^= u64::from(byte)
                    .wrapping_add(index as u64)
                    .rotate_left((index % 64) as u32);

                state = state
                    .rotate_left(13)
                    .wrapping_mul(0x0000_0100_0000_01b3_u64);

                output[lane] = output[lane]
                    .wrapping_add((state >> shift) as u8)
                    .wrapping_add(byte.rotate_left((lane % 8) as u32));
            }

            for (lane, output_byte) in output.iter_mut().enumerate() {
                state ^= (lane as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15_u64);

                state = state
                    .rotate_left(17)
                    .wrapping_mul(0x94d0_49bb_1331_11eb_u64);

                let shift = (lane % 8) * 8;
                *output_byte ^= (state >> shift) as u8;
            }

            output
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::test_only::{TEST_ONLY_HASH_ALGORITHM_ID, TestOnlyDeterministicHasher};
    use super::{
        HASH_FRAME_PREFIX, HashDomain, HashProvider, domain_separated_input, hash_domain_separated,
    };

    #[test]
    fn all_domain_labels_are_unique() {
        let domains = [
            HashDomain::RegistrySnapshotV1,
            HashDomain::CandidateSetV1,
            HashDomain::ElectionManifestV1,
            HashDomain::ApprovalBallotPayloadV1,
            HashDomain::BallotPackageV1,
            HashDomain::ElectionScopeV1,
            HashDomain::ProofStatementV1,
            HashDomain::ArchiveManifestV1,
        ];

        let expected_count = domains.len();
        let labels: BTreeSet<&str> = domains.into_iter().map(HashDomain::label).collect();

        assert_eq!(labels.len(), expected_count);
    }

    #[test]
    fn framed_input_has_stable_boundaries() {
        let framed = domain_separated_input(HashDomain::ElectionManifestV1, &[1_u8, 2_u8, 3_u8]);

        let mut expected = HASH_FRAME_PREFIX.to_vec();
        expected.push(0);
        expected.extend_from_slice(b"tari-cc-private-ballot/election-manifest/v1");
        expected.push(0);
        expected.extend_from_slice(&[1_u8, 2_u8, 3_u8]);

        assert_eq!(framed, expected);
    }

    #[test]
    fn identical_domain_and_bytes_hash_identically() {
        let provider = TestOnlyDeterministicHasher;

        let first =
            hash_domain_separated(&provider, HashDomain::CandidateSetV1, b"canonical-bytes");

        let second =
            hash_domain_separated(&provider, HashDomain::CandidateSetV1, b"canonical-bytes");

        assert_eq!(first, second);
    }

    #[test]
    fn different_domains_produce_different_test_digests() {
        let provider = TestOnlyDeterministicHasher;

        let registry = hash_domain_separated(
            &provider,
            HashDomain::RegistrySnapshotV1,
            b"same-canonical-bytes",
        );

        let candidates = hash_domain_separated(
            &provider,
            HashDomain::CandidateSetV1,
            b"same-canonical-bytes",
        );

        assert_ne!(registry, candidates);
    }

    #[test]
    fn different_payloads_produce_different_test_digests() {
        let provider = TestOnlyDeterministicHasher;

        let first = hash_domain_separated(&provider, HashDomain::BallotPackageV1, b"ballot-a");

        let second = hash_domain_separated(&provider, HashDomain::BallotPackageV1, b"ballot-b");

        assert_ne!(first, second);
    }

    #[test]
    fn test_provider_identifies_itself_as_non_cryptographic() {
        let provider = TestOnlyDeterministicHasher;

        assert_eq!(provider.algorithm_id(), TEST_ONLY_HASH_ALGORITHM_ID);
        assert!(provider.algorithm_id().contains("NOT_CRYPTOGRAPHIC"));
    }
}
