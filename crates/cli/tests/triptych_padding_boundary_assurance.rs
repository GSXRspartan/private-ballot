//! Manual real Tari Triptych padding-boundary assurance suite.
//!
//! The ignored test covers registry sizes 249, 250, 255, 256, and 257 and
//! exercises every real voter position of every size with real Triptych
//! proving and project-owned verification. It deliberately performs no archive
//! replay and no tally work: the subject is cryptographic membership, padding,
//! nullifier, serialization, and signer-position behaviour around the
//! 256-member ring boundary.
//!
//! Padded ring capacity is never hard-coded from a guess. The intended value is
//! planned from the upstream `TriptychParameters` constraints (`n > 1`,
//! `m > 1`, ring size `n**m`) and the observed value is read back out of the
//! canonical Triptych proof bytes produced by the real project prover, whose
//! serialization begins with `n - 1` and `m`. Every proof of every size must
//! agree with the plan.
//!
//! Everything below uses the production BLAKE3 hash provider, the production
//! proof-suite policy reached through the manifest-bound ingestion boundary,
//! and the real Triptych prover and verifier. The forgeable test-only proof
//! verifier is not used anywhere in this file.
//!
//! Passing this suite is functional evidence only. It does not prove the
//! anonymity theorem for the repeated-final-key padding construction.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::time::{Duration, Instant};

use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    ProofVerifierV1, RISTRETTO_COMPRESSED_POINT_BYTES, TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES,
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychProofEnvelopeV1, TariTriptychPrototypeVerifierV1,
    TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, MAX_REGISTRY_MEMBERS, PROTOCOL_VERSION_V1,
    ProofStatementV1, ProtocolError, RegistryCommitment, ValidationCode,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, build_tari_triptych_verifier_from_registry_v1,
    ingest_approval_ballot_package_v1, reconstruct_approval_proof_statement, verify_approval_proof,
};

/// Registry sizes surrounding the 256-member Triptych ring boundary.
const BOUNDARY_REGISTRY_SIZES: [usize; 5] = [249, 250, 255, 256, 257];

/// Number of canonical public keys in the deterministic key fixture.
const FIXTURE_KEY_COUNT: usize = 2_048;

/// Deterministic fixture keys; chunk `index` is the public key of scalar `index + 1`.
const FIXTURE_KEYS: &[u8; FIXTURE_KEY_COUNT * RISTRETTO_COMPRESSED_POINT_BYTES] =
    include_bytes!("fixtures/triptych_large_election_keys_2048.bin");

/// Compressed Ristretto basepoint, which is the public key of fixture scalar one.
const RISTRETTO_BASEPOINT_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] = [
    0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51, 0x5f,
    0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
];

/// Canonical encoding of the Ristretto identity element.
const RISTRETTO_IDENTITY_BYTES: [u8; RISTRETTO_COMPRESSED_POINT_BYTES] =
    [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];

/// Ring base used by the project Triptych statement builder.
const TRIPTYCH_RING_BASE_V1: u32 = 2;

/// Smallest exponent the upstream `TriptychParameters` constructor accepts.
const TRIPTYCH_MINIMUM_EXPONENT_V1: u32 = 2;

/// Serialized size of one Triptych scalar or compressed point.
const TRIPTYCH_SERIALIZED_ELEMENT_BYTES: usize = 32;

/// Leading `n - 1` and `m` little-endian dimensions of a canonical Triptych proof.
const TRIPTYCH_PROOF_DIMENSION_HEADER_BYTES: usize = 8;

/// Fixed serialized Triptych proof elements `A`, `B`, `C`, `D`, `z_A`, `z_C`, `z`.
const TRIPTYCH_PROOF_FIXED_ELEMENTS: usize = 7;

/// Signer interval used for long-run progress output.
const PROGRESS_SIGNER_INTERVAL: usize = 25;

/// Registry size used by the inexpensive planning smoke test.
const SMOKE_REGISTRY_SIZE: usize = 4;

#[test]
#[ignore = "manual real Triptych padding-boundary assurance for 249/250/255/256/257 members"]
fn manual_triptych_padding_boundary_assurance_covers_every_signer_position() {
    let mut evidence = Vec::new();

    for members in BOUNDARY_REGISTRY_SIZES {
        let Some(plan) = plan_triptych_ring_v1(members) else {
            panic!("boundary registry size {members} must have a planned Triptych ring");
        };

        evidence.push(run_boundary_registry_size(plan));
    }

    assert_eq!(evidence.len(), BOUNDARY_REGISTRY_SIZES.len());
    assert_boundary_transitions(&evidence);
}

#[test]
fn boundary_planning_table_and_key_fixture_are_consistent() {
    let expected = [
        (249_usize, 8_u32, 256_u32, 7_usize),
        (250, 8, 256, 6),
        (255, 8, 256, 1),
        (256, 8, 256, 0),
        (257, 9, 512, 255),
    ];

    assert_eq!(expected.len(), BOUNDARY_REGISTRY_SIZES.len());

    for ((members, exponent, capacity, repeats), expected_members) in
        expected.into_iter().zip(BOUNDARY_REGISTRY_SIZES)
    {
        assert_eq!(members, expected_members);
        assert!(members <= MAX_REGISTRY_MEMBERS);
        assert!(members <= FIXTURE_KEY_COUNT);

        let Some(plan) = plan_triptych_ring_v1(members) else {
            panic!("boundary registry size {members} must have a planned Triptych ring");
        };

        assert_eq!(plan.members, members);
        assert_eq!(plan.base, TRIPTYCH_RING_BASE_V1);
        assert_eq!(plan.exponent, exponent);
        assert_eq!(plan.capacity, capacity);
        assert_eq!(plan.padding_repeats(), Some(repeats));
        assert!(plan.exponent >= TRIPTYCH_MINIMUM_EXPONENT_V1);

        let Ok(required) = u32::try_from(members) else {
            panic!("boundary registry size {members} must fit in u32");
        };
        let Some(previous_capacity) = exponent
            .checked_sub(1)
            .and_then(|smaller| TRIPTYCH_RING_BASE_V1.checked_pow(smaller))
        else {
            panic!("previous Triptych capacity for {members} members must be computable");
        };

        assert!(plan.capacity >= required);
        assert!(
            previous_capacity < required,
            "capacity {capacity} for {members} members must be the smallest sufficient ring",
        );
    }

    assert_eq!(
        plan_triptych_ring_v1(249).and_then(|plan| plan.expected_inner_proof_bytes()),
        Some(1_000),
    );
    assert_eq!(
        plan_triptych_ring_v1(257).and_then(|plan| plan.expected_inner_proof_bytes()),
        Some(1_096),
    );

    assert_key_fixture_layout();
    assert_smoke_proof_reports_the_planned_ring();
}

/// Confirms the deterministic fixture provides enough unique, ordered keys.
fn assert_key_fixture_layout() {
    let Some(first) = fixture_public_key(0) else {
        panic!("key fixture must expose its first public key");
    };

    assert_eq!(first, RISTRETTO_BASEPOINT_BYTES);

    let Some(largest) = BOUNDARY_REGISTRY_SIZES.iter().copied().max() else {
        panic!("boundary registry size list must not be empty");
    };

    let members = canonical_boundary_members(largest);

    assert_eq!(members.len(), largest);

    let unique = members
        .iter()
        .map(|member| member.public_key)
        .collect::<BTreeSet<_>>();

    assert_eq!(unique.len(), largest);
    assert!(
        members
            .windows(2)
            .all(|pair| pair[0].public_key < pair[1].public_key),
        "canonical boundary members must be strictly ordered by public key",
    );
    assert!(!unique.contains(&RISTRETTO_IDENTITY_BYTES));
}

/// Proves and verifies two small real proofs to validate the observation path.
///
/// This uses the fixture positions the 257-member case depends on, so a broken
/// scalar-to-public-key association fails here in milliseconds instead of hours.
fn assert_smoke_proof_reports_the_planned_ring() {
    let Some(plan) = plan_triptych_ring_v1(SMOKE_REGISTRY_SIZE) else {
        panic!("smoke registry size must have a planned Triptych ring");
    };

    assert_eq!(plan.capacity, 4);
    assert_eq!(plan.exponent, TRIPTYCH_MINIMUM_EXPONENT_V1);

    let provider = Blake3HashProviderV1;
    let smoke_indices = [0_usize, 1, 255, 256];
    let mut smoke_members = smoke_indices
        .into_iter()
        .map(|index| {
            let Some(public_key) = fixture_public_key(index) else {
                panic!("smoke fixture key {index} must exist");
            };
            let Ok(secret_scalar) = u64::try_from(index + 1) else {
                panic!("smoke fixture scalar must fit in u64");
            };

            BoundaryMemberV1 {
                secret_scalar,
                public_key,
            }
        })
        .collect::<Vec<_>>();

    smoke_members.sort_unstable_by_key(|member| member.public_key);

    let registry = boundary_registry_snapshot(&smoke_members);
    let candidates = boundary_candidate_set();
    let manifest = boundary_manifest(&registry, &candidates, SMOKE_REGISTRY_SIZE, "smoke");
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&registry, &provider) else {
        panic!("smoke registry must construct a Triptych verifier");
    };
    let payload = boundary_payload(&candidates, b"candidate-a");
    let Ok(statement) = reconstruct_approval_proof_statement(&manifest, &payload, &provider) else {
        panic!("smoke proof statement must be reconstructible");
    };

    for scalar in [1_u64, 257] {
        let secret = boundary_secret_key(scalar);
        let Ok(proof) = prove_tari_triptych_prototype_v1(&statement, &verifier, &secret) else {
            panic!("smoke fixture scalar {scalar} must construct a real Triptych proof");
        };
        let Ok(verified) = verify_approval_proof(&manifest, &payload, &proof, &provider, &verifier)
        else {
            panic!("smoke Triptych proof for scalar {scalar} must verify");
        };
        let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(&proof) else {
            panic!("smoke proof envelope must decode");
        };
        let Some(observed) = observed_triptych_ring_v1(envelope.triptych_proof_bytes()) else {
            panic!("smoke proof must expose its Triptych ring dimensions");
        };

        assert_eq!(observed.base, plan.base);
        assert_eq!(observed.exponent, plan.exponent);
        assert_eq!(observed.capacity, plan.capacity);
        assert_eq!(
            Some(envelope.triptych_proof_bytes().len()),
            plan.expected_inner_proof_bytes(),
        );
        assert_eq!(
            verified.nullifier().as_bytes(),
            envelope.linking_tag_bytes().as_slice(),
        );
    }
}

/// Intended Triptych ring configuration for one registry size.
///
/// The upstream `TriptychParameters` constructor requires `n > 1` and `m > 1`
/// and defines the verification-key vector size as `N == n**m`. The project
/// statement builder fixes `n` and selects the smallest sufficient `m`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TriptychRingPlanV1 {
    members: usize,
    base: u32,
    exponent: u32,
    capacity: u32,
}

impl TriptychRingPlanV1 {
    /// Returns how many times the final real key fills the padded ring.
    fn padding_repeats(self) -> Option<usize> {
        usize::try_from(self.capacity)
            .ok()
            .and_then(|capacity| capacity.checked_sub(self.members))
    }

    /// Returns the canonical serialized length of one inner Triptych proof.
    ///
    /// The upstream serializer writes `n - 1` and `m` as little-endian `u32`
    /// values, then `A`, `B`, `C`, `D`, `z_A`, `z_C`, `z`, the `m`-element `X`
    /// and `Y` vectors, and the `m * (n - 1)` matrix `f`.
    fn expected_inner_proof_bytes(self) -> Option<usize> {
        let exponent = usize::try_from(self.exponent).ok()?;
        let base = usize::try_from(self.base).ok()?;
        let matrix = exponent.checked_mul(base.checked_sub(1)?)?;
        let elements = TRIPTYCH_PROOF_FIXED_ELEMENTS
            .checked_add(exponent.checked_mul(2)?)?
            .checked_add(matrix)?;

        TRIPTYCH_PROOF_DIMENSION_HEADER_BYTES
            .checked_add(elements.checked_mul(TRIPTYCH_SERIALIZED_ELEMENT_BYTES)?)
    }
}

/// Triptych ring dimensions read back out of real canonical proof bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ObservedTriptychRingV1 {
    base: u32,
    exponent: u32,
    capacity: u32,
}

/// One deterministic registry member with its known signing scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoundaryMemberV1 {
    secret_scalar: u64,
    public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
}

/// Everything one boundary registry size needs before proving begins.
struct BoundaryFixtureV1 {
    members: Vec<BoundaryMemberV1>,
    registry_keys: Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>,
    registry_commitment: RegistryCommitment,
    candidates: CandidateSet,
    primary_manifest: ElectionManifestV1,
    alternate_manifest: ElectionManifestV1,
    verifier: TariTriptychPrototypeVerifierV1,
    primary_payload: ApprovalBallotPayload,
    alternate_choice_payload: ApprovalBallotPayload,
    primary_statement: ProofStatementV1,
    lifecycle: ElectionLifecycleV1,
}

/// Recorded evidence for one completed boundary registry size.
struct BoundarySizeEvidenceV1 {
    members: usize,
    padded_capacity: u32,
    registry_commitment: RegistryCommitment,
    statement_bytes: Vec<u8>,
    padded_verification_keys: Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>,
}

/// Ordered set of observed lengths for one measured quantity.
#[derive(Debug, Default)]
struct LengthObservationsV1 {
    values: BTreeSet<usize>,
}

impl LengthObservationsV1 {
    fn record(&mut self, value: usize) {
        self.values.insert(value);
    }

    fn minimum(&self) -> Option<usize> {
        self.values.iter().copied().next()
    }

    fn maximum(&self) -> Option<usize> {
        self.values.iter().copied().next_back()
    }

    fn unique_count(&self) -> usize {
        self.values.len()
    }

    /// Returns the single observed length, failing on any position-dependent difference.
    fn single(&self, label: &str, members: usize) -> usize {
        let (Some(minimum), Some(maximum)) = (self.minimum(), self.maximum()) else {
            panic!("{label} must have at least one observation for {members} members");
        };

        assert_eq!(
            minimum, maximum,
            "{label} varied by signer position for {members} members",
        );
        assert_eq!(
            self.unique_count(),
            1,
            "{label} must have exactly one unique length for {members} members",
        );

        minimum
    }
}

/// Plans the smallest upstream-valid Triptych ring that holds `members` keys.
fn plan_triptych_ring_v1(members: usize) -> Option<TriptychRingPlanV1> {
    let required = u32::try_from(members).ok()?;

    if required == 0 {
        return None;
    }

    let mut exponent = TRIPTYCH_MINIMUM_EXPONENT_V1;
    let mut capacity = TRIPTYCH_RING_BASE_V1.checked_pow(exponent)?;

    while capacity < required {
        exponent = exponent.checked_add(1)?;
        capacity = TRIPTYCH_RING_BASE_V1.checked_pow(exponent)?;
    }

    Some(TriptychRingPlanV1 {
        members,
        base: TRIPTYCH_RING_BASE_V1,
        exponent,
        capacity,
    })
}

/// Reads the ring dimensions the real prover wrote into canonical proof bytes.
fn observed_triptych_ring_v1(inner_proof: &[u8]) -> Option<ObservedTriptychRingV1> {
    let header = inner_proof.get(..TRIPTYCH_PROOF_DIMENSION_HEADER_BYTES)?;
    let base_minus_one = u32::from_le_bytes(<[u8; 4]>::try_from(header.get(..4)?).ok()?);
    let exponent = u32::from_le_bytes(<[u8; 4]>::try_from(header.get(4..8)?).ok()?);
    let base = base_minus_one.checked_add(1)?;
    let capacity = base.checked_pow(exponent)?;

    Some(ObservedTriptychRingV1 {
        base,
        exponent,
        capacity,
    })
}

/// Mirrors the documented repeated-final-key padding for evidence comparison only.
///
/// The real padding is performed by the vendored Triptych input-set
/// constructor. This model exists so the suite can compare padded key vectors
/// across boundary sizes; it never feeds a proof or a verification.
fn expected_padded_verification_keys_v1(
    registry_keys: &[[u8; RISTRETTO_COMPRESSED_POINT_BYTES]],
    capacity: u32,
) -> Option<Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>> {
    let capacity = usize::try_from(capacity).ok()?;
    let last = registry_keys.last().copied()?;

    if registry_keys.len() > capacity {
        return None;
    }

    let mut padded = registry_keys.to_vec();
    padded.resize(capacity, last);

    Some(padded)
}

/// Returns fixture public key `index`, whose signing scalar is `index + 1`.
fn fixture_public_key(index: usize) -> Option<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]> {
    let start = index.checked_mul(RISTRETTO_COMPRESSED_POINT_BYTES)?;
    let end = start.checked_add(RISTRETTO_COMPRESSED_POINT_BYTES)?;

    <[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>::try_from(FIXTURE_KEYS.get(start..end)?).ok()
}

/// Builds the deterministic canonical member list for one registry size.
fn canonical_boundary_members(members: usize) -> Vec<BoundaryMemberV1> {
    assert!(members <= FIXTURE_KEY_COUNT);

    let mut list = (0..members)
        .map(|index| {
            let Some(public_key) = fixture_public_key(index) else {
                panic!("fixture key {index} must exist");
            };
            let Ok(secret_scalar) = u64::try_from(index + 1) else {
                panic!("fixture scalar {index} must fit in u64");
            };

            BoundaryMemberV1 {
                secret_scalar,
                public_key,
            }
        })
        .collect::<Vec<_>>();

    list.sort_unstable_by_key(|member| member.public_key);
    list
}

/// Encodes one canonical registry snapshot from ordered members.
fn boundary_registry_snapshot(members: &[BoundaryMemberV1]) -> RegistrySnapshot {
    let keys = members
        .iter()
        .map(|member| member.public_key)
        .collect::<Vec<_>>();

    registry_snapshot_from_keys(&keys)
}

/// Encodes one canonical registry snapshot from ordered compressed keys.
fn registry_snapshot_from_keys(
    keys: &[[u8; RISTRETTO_COMPRESSED_POINT_BYTES]],
) -> RegistrySnapshot {
    let Ok(snapshot) = decode_registry_from_keys(keys) else {
        panic!("canonical boundary registry must decode");
    };

    snapshot
}

/// Encodes and decodes one canonical registry, surfacing the rejection code.
fn decode_registry_from_keys(
    keys: &[[u8; RISTRETTO_COMPRESSED_POINT_BYTES]],
) -> Result<RegistrySnapshot, ProtocolError> {
    let mut writer = CanonicalCborWriter::new();

    writer.write_array_len(keys.len())?;

    for key in keys {
        writer.write_byte_string(key)?;
    }

    RegistrySnapshot::from_canonical_cbor(&writer.into_bytes())
}

/// Returns the fixed two-candidate set used by every boundary election.
fn boundary_candidate_set() -> CandidateSet {
    let Ok(first) = CandidateDefinition::new(
        boundary_candidate_id(b"candidate-a"),
        "Candidate A".to_owned(),
    ) else {
        panic!("first boundary candidate must be valid");
    };
    let Ok(second) = CandidateDefinition::new(
        boundary_candidate_id(b"candidate-b"),
        "Candidate B".to_owned(),
    ) else {
        panic!("second boundary candidate must be valid");
    };
    let Ok(candidates) = CandidateSet::new(vec![first, second]) else {
        panic!("boundary candidate set must be valid");
    };

    candidates
}

fn boundary_candidate_id(bytes: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(bytes.to_vec()) else {
        panic!("boundary candidate identifier must be valid");
    };

    id
}

fn boundary_approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
        panic!("boundary approval limits must be valid");
    };

    limits
}

/// Builds one single-selection approval payload of fixed content length.
fn boundary_payload(candidates: &CandidateSet, selection: &[u8]) -> ApprovalBallotPayload {
    let Ok(payload) = ApprovalBallotPayload::new(
        vec![boundary_candidate_id(selection)],
        candidates,
        boundary_approval_limits(),
    ) else {
        panic!("boundary approval payload must be valid");
    };

    payload
}

/// Builds one frozen manifest bound to the supplied registry snapshot.
fn boundary_manifest(
    registry: &RegistrySnapshot,
    candidates: &CandidateSet,
    members: usize,
    label: &str,
) -> ElectionManifestV1 {
    let provider = Blake3HashProviderV1;

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("boundary registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("boundary candidate-set commitment must be derivable");
    };
    let Ok(election_id) = ElectionId::new(format!("pad-boundary-{members}-{label}").into_bytes())
    else {
        panic!("boundary election identifier must be valid");
    };
    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: boundary_approval_limits(),
        governance_source_revision: format!("pad-boundary-{members}-{label}-revision-1"),
    }) else {
        panic!("boundary manifest must be valid");
    };

    manifest
}

/// Opens one lifecycle frozen against the supplied manifest.
fn boundary_lifecycle(manifest: &ElectionManifestV1) -> ElectionLifecycleV1 {
    let provider = Blake3HashProviderV1;

    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("boundary manifest hash must be derivable");
    };

    let mut lifecycle = ElectionLifecycleV1::new();

    assert!(
        lifecycle
            .freeze(manifest_hash, manifest.registry_commitment())
            .is_ok()
    );
    assert!(lifecycle.open().is_ok());

    lifecycle
}

/// Parses one canonical, nonzero signing scalar.
fn boundary_secret_key(scalar: u64) -> TariTriptychSecretKeyV1 {
    let mut bytes = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];
    bytes[..8].copy_from_slice(&scalar.to_le_bytes());

    let Ok(secret) = TariTriptychSecretKeyV1::from_canonical_bytes(bytes) else {
        panic!("boundary signing scalar {scalar} must be canonical and nonzero");
    };

    secret
}

/// Builds and canonically encodes one ballot package.
fn boundary_package_bytes(
    manifest: &ElectionManifestV1,
    payload: &ApprovalBallotPayload,
    proof: Vec<u8>,
) -> Vec<u8> {
    let provider = Blake3HashProviderV1;

    let Ok(manifest_hash) = manifest.canonical_hash(&provider) else {
        panic!("boundary manifest hash must be derivable");
    };
    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        proof,
        payload: payload.clone(),
    }) else {
        panic!("boundary ballot package must be structurally valid");
    };
    let Ok(encoded) = package.to_canonical_cbor() else {
        panic!("boundary ballot package must encode canonically");
    };

    assert_eq!(package.protocol_version(), PROTOCOL_VERSION_V1);
    assert_eq!(package.manifest_hash(), manifest_hash);
    assert_eq!(package.proof_suite_id(), TARI_TRIPTYCH_PROOF_SUITE_ID_V1);
    assert_eq!(package.payload(), payload);

    encoded
}

/// Assembles every fixture one boundary registry size needs.
fn build_boundary_fixture(plan: TriptychRingPlanV1) -> BoundaryFixtureV1 {
    let provider = Blake3HashProviderV1;
    let members = canonical_boundary_members(plan.members);
    let registry = boundary_registry_snapshot(&members);
    let candidates = boundary_candidate_set();
    let primary_manifest = boundary_manifest(&registry, &candidates, plan.members, "primary");
    let alternate_manifest = boundary_manifest(&registry, &candidates, plan.members, "alternate");

    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("boundary registry commitment must be derivable");
    };
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&registry, &provider) else {
        panic!("boundary registry must construct a Triptych verifier");
    };

    let primary_payload = boundary_payload(&candidates, b"candidate-a");
    let alternate_choice_payload = boundary_payload(&candidates, b"candidate-b");

    let Ok(primary_statement) =
        reconstruct_approval_proof_statement(&primary_manifest, &primary_payload, &provider)
    else {
        panic!("boundary primary proof statement must be reconstructible");
    };

    let registry_keys = members
        .iter()
        .map(|member| member.public_key)
        .collect::<Vec<_>>();

    assert_eq!(registry.len(), plan.members);
    assert_eq!(verifier.registry_keys(), registry_keys.as_slice());
    assert_eq!(verifier.registry_commitment(), registry_commitment);
    assert_eq!(verifier.proof_suite_id(), TARI_TRIPTYCH_PROOF_SUITE_ID_V1);
    assert_eq!(primary_statement.registry_commitment(), registry_commitment);
    assert_eq!(
        primary_statement.proof_suite_id(),
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
    );

    let lifecycle = boundary_lifecycle(&primary_manifest);

    BoundaryFixtureV1 {
        members,
        registry_keys,
        registry_commitment,
        candidates,
        primary_manifest,
        alternate_manifest,
        verifier,
        primary_payload,
        alternate_choice_payload,
        primary_statement,
        lifecycle,
    }
}

/// Runs every real signer position of one boundary registry size.
fn run_boundary_registry_size(plan: TriptychRingPlanV1) -> BoundarySizeEvidenceV1 {
    let provider = Blake3HashProviderV1;
    let fixture = build_boundary_fixture(plan);
    let members = plan.members;

    let Some(padding_repeats) = plan.padding_repeats() else {
        panic!("padding repeat count for {members} members must be computable");
    };
    let Some(padded_verification_keys) =
        expected_padded_verification_keys_v1(&fixture.registry_keys, plan.capacity)
    else {
        panic!("padded verification-key model for {members} members must be computable");
    };

    assert_padded_key_vector(&fixture.registry_keys, &padded_verification_keys, plan);

    println!(
        "[padding-boundary] size={members} begin members={members} padded_capacity={} \
         triptych_base={} triptych_exponent={} padding_repeats={padding_repeats} \
         registry_commitment={} proof_suite={}",
        plan.capacity,
        plan.base,
        plan.exponent,
        hex_lower(fixture.registry_commitment.as_bytes()),
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
    );

    let mut ledger = BallotAcceptanceLedger::new();
    let mut unique_nullifiers = BTreeSet::new();
    let mut previous_nullifier: Option<Vec<u8>> = None;
    let mut inner_proof_lengths = LengthObservationsV1::default();
    let mut envelope_lengths = LengthObservationsV1::default();
    let mut package_lengths = LengthObservationsV1::default();
    let mut reference_prefix: Option<Vec<u8>> = None;
    let mut inspected_packages = Vec::new();
    let mut prove_total = Duration::ZERO;
    let mut verify_total = Duration::ZERO;
    let mut proof_count = 0_usize;
    let mut first_proof = Vec::new();
    let mut final_proof = Vec::new();
    let mut final_alternate_choice_proof = Vec::new();

    let inspection_positions = representative_positions(members);

    for (position, member) in fixture.members.iter().enumerate() {
        let secret = boundary_secret_key(member.secret_scalar);

        let (primary_proof, elapsed) = timed_prove(&fixture, &fixture.primary_statement, &secret);
        prove_total = prove_total.saturating_add(elapsed);
        proof_count += 1;

        let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(&primary_proof) else {
            panic!("signer {position} envelope of {members} members must decode canonically");
        };
        let inner_proof = envelope.triptych_proof_bytes();

        assert_observed_ring(inner_proof, plan, position);
        assert_eq!(
            envelope.to_bytes(),
            primary_proof,
            "signer {position} envelope must re-encode exactly",
        );
        assert_eq!(
            primary_proof.len(),
            inner_proof
                .len()
                .saturating_add(TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES),
        );

        let package_bytes = boundary_package_bytes(
            &fixture.primary_manifest,
            &fixture.primary_payload,
            primary_proof.clone(),
        );

        let accept_started = Instant::now();
        let accepted = ingest_approval_ballot_package_v1(
            &package_bytes,
            &fixture.primary_manifest,
            &fixture.candidates,
            &fixture.lifecycle,
            &mut ledger,
            &provider,
            &fixture.verifier,
        );
        verify_total = verify_total.saturating_add(accept_started.elapsed());

        assert!(
            accepted.is_ok(),
            "signer {position} of {members} members must be accepted once",
        );
        assert_eq!(ledger.len(), position.saturating_add(1));

        let Some(last_accepted) = ledger.accepted_ballots().last() else {
            panic!("signer {position} must appear in the acceptance ledger");
        };
        let nullifier = last_accepted.election_scoped_nullifier().to_vec();

        assert!(!nullifier.is_empty());
        assert_eq!(nullifier.len(), RISTRETTO_COMPRESSED_POINT_BYTES);
        assert_ne!(nullifier.as_slice(), RISTRETTO_IDENTITY_BYTES.as_slice());
        assert_eq!(
            nullifier.as_slice(),
            envelope.linking_tag_bytes().as_slice()
        );
        assert_eq!(last_accepted.payload(), &fixture.primary_payload);

        assert!(
            unique_nullifiers.insert(nullifier.clone()),
            "signer {position} of {members} members repeated an earlier nullifier",
        );

        if let Some(previous) = previous_nullifier.as_ref() {
            assert_ne!(
                previous,
                &nullifier,
                "adjacent signers {position} and {} shared a nullifier",
                position.saturating_sub(1),
            );
        }

        let repeat_nullifier = assert_repeat_ballot_nullifier(
            &fixture,
            &secret,
            &mut prove_total,
            &mut verify_total,
            &mut proof_count,
        );

        assert_eq!(
            repeat_nullifier, nullifier,
            "signer {position} of {members} members changed nullifier on an identical ballot",
        );

        let alternate_choice = alternate_choice_proof(
            &fixture,
            &secret,
            &mut prove_total,
            &mut verify_total,
            &mut proof_count,
        );

        assert_eq!(
            alternate_choice.nullifier, nullifier,
            "signer {position} of {members} members changed nullifier on a different choice",
        );

        let alternate_election_nullifier = assert_alternate_election_nullifier(
            &fixture,
            &secret,
            &mut prove_total,
            &mut verify_total,
            &mut proof_count,
        );

        assert_ne!(
            alternate_election_nullifier, nullifier,
            "signer {position} of {members} members reused a nullifier across elections",
        );

        assert_statement_binding(&fixture, &primary_proof, &mut verify_total, position);

        let Some(split) = package_bytes.len().checked_sub(primary_proof.len()) else {
            panic!("signer {position} package must contain its proof field");
        };
        let Some(prefix) = package_bytes.get(..split) else {
            panic!("signer {position} package prefix must be readable");
        };
        let Some(suffix) = package_bytes.get(split..) else {
            panic!("signer {position} package proof region must be readable");
        };

        assert_eq!(suffix, primary_proof.as_slice());

        match reference_prefix.as_ref() {
            Some(expected) => assert_eq!(
                prefix,
                expected.as_slice(),
                "signer {position} of {members} members changed a project-owned package field",
            ),
            None => reference_prefix = Some(prefix.to_vec()),
        }

        inner_proof_lengths.record(inner_proof.len());
        envelope_lengths.record(primary_proof.len());
        package_lengths.record(package_bytes.len());

        if inspection_positions.contains(&position) {
            inspected_packages.push((position, package_bytes.clone()));
        }

        if position == 0 {
            first_proof = primary_proof.clone();
        }

        if position.saturating_add(1) == members {
            final_proof = primary_proof.clone();
            final_alternate_choice_proof = alternate_choice.proof;
        }

        previous_nullifier = Some(nullifier);

        let completed = position.saturating_add(1);

        if completed % PROGRESS_SIGNER_INTERVAL == 0 {
            println!(
                "[padding-boundary] size={members} progress signer={completed}/{members} \
                 proofs={proof_count} accepted={} prove_ms={} verify_ms={}",
                ledger.len(),
                prove_total.as_millis(),
                verify_total.as_millis(),
            );
        }
    }

    assert_eq!(ledger.len(), members);
    assert_eq!(unique_nullifiers.len(), members);

    let inner_proof_bytes = inner_proof_lengths.single("inner Triptych proof length", members);
    let envelope_bytes = envelope_lengths.single("Triptych envelope length", members);
    let package_bytes = package_lengths.single("canonical ballot-package length", members);

    assert_eq!(
        Some(inner_proof_bytes),
        plan.expected_inner_proof_bytes(),
        "inner proof length for {members} members must match the planned ring",
    );

    assert_package_field_inspection(&inspected_packages, package_bytes, envelope_bytes, members);

    let duplicate_rejection = assert_final_key_duplicate_rejection(
        &fixture,
        &final_alternate_choice_proof,
        &mut ledger,
        members,
    );

    assert_boundary_rejections(&fixture, plan, &first_proof, &final_proof, &mut ledger);

    assert_eq!(ledger.len(), members);

    let Ok(statement_bytes) = fixture.primary_statement.to_canonical_cbor() else {
        panic!("boundary proof statement for {members} members must encode canonically");
    };

    println!(
        "[padding-boundary] size={members} complete members={members} padded_capacity={} \
         proof_count={proof_count} prove_ms_total={} prove_ms_average={} verify_ms_total={} \
         proof_bytes_min={} proof_bytes_max={} envelope_bytes_min={} envelope_bytes_max={} \
         package_bytes_min={} package_bytes_max={} unique_nullifier_count={} \
         duplicate_rejection={}",
        plan.capacity,
        prove_total.as_millis(),
        average_millis_text(prove_total, proof_count),
        verify_total.as_millis(),
        inner_proof_bytes,
        inner_proof_bytes,
        envelope_bytes,
        envelope_bytes,
        package_bytes,
        package_bytes,
        unique_nullifiers.len(),
        duplicate_rejection.as_str(),
    );

    BoundarySizeEvidenceV1 {
        members,
        padded_capacity: plan.capacity,
        registry_commitment: fixture.registry_commitment,
        statement_bytes,
        padded_verification_keys,
    }
}

/// Confirms the modelled padded key vector repeats only the final real key.
fn assert_padded_key_vector(
    registry_keys: &[[u8; RISTRETTO_COMPRESSED_POINT_BYTES]],
    padded: &[[u8; RISTRETTO_COMPRESSED_POINT_BYTES]],
    plan: TriptychRingPlanV1,
) {
    let Ok(capacity) = usize::try_from(plan.capacity) else {
        panic!("planned capacity must fit in usize");
    };
    let Some(last) = registry_keys.last() else {
        panic!("boundary registry must not be empty");
    };
    let Some(real_region) = padded.get(..plan.members) else {
        panic!("padded vector must contain every real key");
    };
    let Some(padding_region) = padded.get(plan.members..) else {
        panic!("padded vector must expose its padding region");
    };

    assert_eq!(padded.len(), capacity);
    assert_eq!(real_region, registry_keys);
    assert!(padding_region.iter().all(|key| key == last));
}

/// Confirms one real proof reports exactly the planned ring dimensions.
fn assert_observed_ring(inner_proof: &[u8], plan: TriptychRingPlanV1, position: usize) {
    let Some(observed) = observed_triptych_ring_v1(inner_proof) else {
        panic!("signer {position} proof must expose its Triptych ring dimensions");
    };

    assert_eq!(
        observed.base, plan.base,
        "signer {position} used an unplanned Triptych base",
    );
    assert_eq!(
        observed.exponent, plan.exponent,
        "signer {position} used an unplanned Triptych exponent",
    );
    assert_eq!(
        observed.capacity, plan.capacity,
        "signer {position} used an unplanned padded ring capacity",
    );
}

/// Proves the identical ballot again and returns the authenticated nullifier.
fn assert_repeat_ballot_nullifier(
    fixture: &BoundaryFixtureV1,
    secret: &TariTriptychSecretKeyV1,
    prove_total: &mut Duration,
    verify_total: &mut Duration,
    proof_count: &mut usize,
) -> Vec<u8> {
    let provider = Blake3HashProviderV1;
    let (proof, elapsed) = timed_prove(fixture, &fixture.primary_statement, secret);
    *prove_total = prove_total.saturating_add(elapsed);
    *proof_count += 1;

    let started = Instant::now();
    let verified = verify_approval_proof(
        &fixture.primary_manifest,
        &fixture.primary_payload,
        &proof,
        &provider,
        &fixture.verifier,
    );
    *verify_total = verify_total.saturating_add(started.elapsed());

    let Ok(verified) = verified else {
        panic!("repeated identical ballot must verify");
    };

    verified.nullifier().as_bytes().to_vec()
}

/// One alternate-choice proof and the nullifier it authenticated.
struct AlternateChoiceProofV1 {
    proof: Vec<u8>,
    nullifier: Vec<u8>,
}

/// Proves a different valid choice in the same election.
fn alternate_choice_proof(
    fixture: &BoundaryFixtureV1,
    secret: &TariTriptychSecretKeyV1,
    prove_total: &mut Duration,
    verify_total: &mut Duration,
    proof_count: &mut usize,
) -> AlternateChoiceProofV1 {
    let provider = Blake3HashProviderV1;
    let Ok(statement) = reconstruct_approval_proof_statement(
        &fixture.primary_manifest,
        &fixture.alternate_choice_payload,
        &provider,
    ) else {
        panic!("alternate-choice proof statement must be reconstructible");
    };

    let (proof, elapsed) = timed_prove(fixture, &statement, secret);
    *prove_total = prove_total.saturating_add(elapsed);
    *proof_count += 1;

    let started = Instant::now();
    let verified = verify_approval_proof(
        &fixture.primary_manifest,
        &fixture.alternate_choice_payload,
        &proof,
        &provider,
        &fixture.verifier,
    );
    *verify_total = verify_total.saturating_add(started.elapsed());

    let Ok(verified) = verified else {
        panic!("alternate-choice ballot must verify");
    };

    AlternateChoiceProofV1 {
        nullifier: verified.nullifier().as_bytes().to_vec(),
        proof,
    }
}

/// Proves the same ballot in a second election and returns its nullifier.
fn assert_alternate_election_nullifier(
    fixture: &BoundaryFixtureV1,
    secret: &TariTriptychSecretKeyV1,
    prove_total: &mut Duration,
    verify_total: &mut Duration,
    proof_count: &mut usize,
) -> Vec<u8> {
    let provider = Blake3HashProviderV1;
    let Ok(statement) = reconstruct_approval_proof_statement(
        &fixture.alternate_manifest,
        &fixture.primary_payload,
        &provider,
    ) else {
        panic!("alternate-election proof statement must be reconstructible");
    };

    let (proof, elapsed) = timed_prove(fixture, &statement, secret);
    *prove_total = prove_total.saturating_add(elapsed);
    *proof_count += 1;

    let started = Instant::now();
    let verified = verify_approval_proof(
        &fixture.alternate_manifest,
        &fixture.primary_payload,
        &proof,
        &provider,
        &fixture.verifier,
    );
    *verify_total = verify_total.saturating_add(started.elapsed());

    let Ok(verified) = verified else {
        panic!("alternate-election ballot must verify");
    };

    verified.nullifier().as_bytes().to_vec()
}

/// Confirms one proof verifies only under its own election statement.
fn assert_statement_binding(
    fixture: &BoundaryFixtureV1,
    primary_proof: &[u8],
    verify_total: &mut Duration,
    position: usize,
) {
    let provider = Blake3HashProviderV1;
    let started = Instant::now();

    let changed_choice = verify_approval_proof(
        &fixture.primary_manifest,
        &fixture.alternate_choice_payload,
        primary_proof,
        &provider,
        &fixture.verifier,
    );
    let changed_election = verify_approval_proof(
        &fixture.alternate_manifest,
        &fixture.primary_payload,
        primary_proof,
        &provider,
        &fixture.verifier,
    );

    *verify_total = verify_total.saturating_add(started.elapsed());

    assert!(
        matches!(changed_choice, Err(error) if error.code() == ValidationCode::MalformedProof),
        "signer {position} proof must not verify against another ballot statement",
    );
    assert!(
        matches!(changed_election, Err(error) if error.code() == ValidationCode::MalformedProof),
        "signer {position} proof must not verify against another election statement",
    );
}

/// Times one real Triptych proof construction.
fn timed_prove(
    fixture: &BoundaryFixtureV1,
    statement: &ProofStatementV1,
    secret: &TariTriptychSecretKeyV1,
) -> (Vec<u8>, Duration) {
    let started = Instant::now();
    let proof = prove_tari_triptych_prototype_v1(statement, &fixture.verifier, secret);
    let elapsed = started.elapsed();

    let Ok(proof) = proof else {
        panic!("registered boundary member must construct a real Triptych proof");
    };

    (proof, elapsed)
}

/// Returns the first, middle, penultimate, and final signer positions.
fn representative_positions(members: usize) -> BTreeSet<usize> {
    let mut positions = BTreeSet::new();

    positions.insert(0);
    positions.insert(members / 2);

    if let Some(final_position) = members.checked_sub(1) {
        positions.insert(final_position);

        if let Some(penultimate) = final_position.checked_sub(1) {
            positions.insert(penultimate);
        }
    }

    positions
}

/// Confirms representative packages share one field layout and one length.
fn assert_package_field_inspection(
    inspected: &[(usize, Vec<u8>)],
    package_bytes: usize,
    envelope_bytes: usize,
    members: usize,
) {
    assert_eq!(
        inspected.len(),
        4,
        "four representative packages must be inspected for {members} members",
    );

    let Some((_, reference)) = inspected.first() else {
        panic!("representative package inspection must have a reference package");
    };
    let Some(split) = package_bytes.checked_sub(envelope_bytes) else {
        panic!("canonical package must contain its proof field");
    };
    let Some(reference_prefix) = reference.get(..split) else {
        panic!("reference package prefix must be readable");
    };

    let mut proof_regions = BTreeSet::new();

    for (position, encoded) in inspected {
        let Some(prefix) = encoded.get(..split) else {
            panic!("package prefix for signer {position} must be readable");
        };
        let Some(proof_region) = encoded.get(split..) else {
            panic!("package proof region for signer {position} must be readable");
        };

        assert_eq!(encoded.len(), package_bytes);
        assert_eq!(
            prefix, reference_prefix,
            "representative signer {position} changed a project-owned package field",
        );
        assert_eq!(proof_region.len(), envelope_bytes);
        assert!(proof_regions.insert(proof_region.to_vec()));
    }

    assert_eq!(proof_regions.len(), inspected.len());

    println!(
        "[padding-boundary] size={members} package_inspection positions={:?} \
         identical_prefix_bytes={split} proof_region_bytes={envelope_bytes} \
         package_bytes={package_bytes} distinct_proof_regions={}",
        inspected
            .iter()
            .map(|(position, _)| *position)
            .collect::<Vec<_>>(),
        proof_regions.len(),
    );
}

/// Confirms a second valid ballot from the final real key is a duplicate.
fn assert_final_key_duplicate_rejection(
    fixture: &BoundaryFixtureV1,
    final_alternate_choice_proof: &[u8],
    ledger: &mut BallotAcceptanceLedger,
    members: usize,
) -> ValidationCode {
    let provider = Blake3HashProviderV1;
    let before = ledger.len();
    let package_bytes = boundary_package_bytes(
        &fixture.primary_manifest,
        &fixture.alternate_choice_payload,
        final_alternate_choice_proof.to_vec(),
    );

    let outcome = ingest_approval_ballot_package_v1(
        &package_bytes,
        &fixture.primary_manifest,
        &fixture.candidates,
        &fixture.lifecycle,
        ledger,
        &provider,
        &fixture.verifier,
    );

    let Err(error) = outcome else {
        panic!("second ballot from the final real key of {members} members must be rejected");
    };

    assert_eq!(error.code(), ValidationCode::DuplicateNullifier);
    assert_eq!(ledger.len(), before);

    error.code()
}

/// Runs the unauthorized and padding-related rejection matrix for one size.
fn assert_boundary_rejections(
    fixture: &BoundaryFixtureV1,
    plan: TriptychRingPlanV1,
    first_proof: &[u8],
    final_proof: &[u8],
    ledger: &mut BallotAcceptanceLedger,
) {
    let before = ledger.len();
    let members = plan.members;

    assert_unregistered_and_invalid_secrets(fixture, members);
    assert_registry_construction_rejections(fixture, members);
    assert_final_key_against_reduced_registry(fixture, members);
    assert_cross_registry_rejections(fixture, plan, final_proof);
    assert_swapped_nullifier_rejection(fixture, first_proof, final_proof, ledger, members);

    assert_eq!(
        ledger.len(),
        before,
        "rejected attempts must not mutate acceptance-ledger state for {members} members",
    );
}

/// Rejects unregistered, zero, and noncanonical signing scalars.
fn assert_unregistered_and_invalid_secrets(fixture: &BoundaryFixtureV1, members: usize) {
    let Ok(unregistered_scalar) = u64::try_from(members + 1) else {
        panic!("unregistered scalar for {members} members must fit in u64");
    };
    let unregistered = boundary_secret_key(unregistered_scalar);
    let outcome = prove_tari_triptych_prototype_v1(
        &fixture.primary_statement,
        &fixture.verifier,
        &unregistered,
    );

    assert!(
        matches!(outcome, Err(error) if error.code() == ValidationCode::InvalidData),
        "an unregistered secret must not construct a proof for {members} members",
    );

    assert!(matches!(
        TariTriptychSecretKeyV1::from_canonical_bytes([0_u8; RISTRETTO_COMPRESSED_POINT_BYTES]),
        Err(error) if error.code() == ValidationCode::InvalidData
    ));
    assert!(matches!(
        TariTriptychSecretKeyV1::from_canonical_bytes([0xff_u8; RISTRETTO_COMPRESSED_POINT_BYTES]),
        Err(error) if error.code() == ValidationCode::InvalidData
    ));
}

/// Rejects duplicate real keys and the identity element in a canonical registry.
fn assert_registry_construction_rejections(fixture: &BoundaryFixtureV1, members: usize) {
    let provider = Blake3HashProviderV1;
    let Some(last) = fixture.registry_keys.last().copied() else {
        panic!("boundary registry must not be empty");
    };

    let mut duplicated = fixture.registry_keys.clone();
    duplicated.push(last);

    assert!(
        matches!(
            decode_registry_from_keys(&duplicated),
            Err(error) if error.code() == ValidationCode::DuplicateGovernanceKey
        ),
        "a duplicate real public key must be rejected for {members} members",
    );

    let mut with_identity = vec![RISTRETTO_IDENTITY_BYTES];
    with_identity.extend_from_slice(&fixture.registry_keys);

    let Ok(identity_registry) = decode_registry_from_keys(&with_identity) else {
        panic!("identity-bearing registry must decode before Triptych validation");
    };

    assert!(
        matches!(
            build_tari_triptych_verifier_from_registry_v1(&identity_registry, &provider),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ),
        "an identity public key must be rejected for {members} members",
    );
}

/// Rejects the final real key when it is used against a registry without it.
fn assert_final_key_against_reduced_registry(fixture: &BoundaryFixtureV1, members: usize) {
    let provider = Blake3HashProviderV1;
    let Some((final_member, reduced_members)) = fixture.members.split_last() else {
        panic!("boundary registry must not be empty");
    };

    let reduced_registry = boundary_registry_snapshot(reduced_members);
    let reduced_manifest = boundary_manifest(
        &reduced_registry,
        &fixture.candidates,
        members,
        "reduced-registry",
    );

    let Ok(reduced_verifier) =
        build_tari_triptych_verifier_from_registry_v1(&reduced_registry, &provider)
    else {
        panic!("reduced boundary registry must construct a Triptych verifier");
    };
    let Ok(reduced_statement) = reconstruct_approval_proof_statement(
        &reduced_manifest,
        &fixture.primary_payload,
        &provider,
    ) else {
        panic!("reduced-registry proof statement must be reconstructible");
    };

    let secret = boundary_secret_key(final_member.secret_scalar);
    let outcome = prove_tari_triptych_prototype_v1(&reduced_statement, &reduced_verifier, &secret);

    assert!(
        matches!(outcome, Err(error) if error.code() == ValidationCode::InvalidData),
        "the final real key of {members} members must not sign against another registry",
    );
}

/// Rejects one valid proof under every neighbouring padded key vector.
fn assert_cross_registry_rejections(
    fixture: &BoundaryFixtureV1,
    plan: TriptychRingPlanV1,
    final_proof: &[u8],
) {
    let provider = Blake3HashProviderV1;
    let members = plan.members;
    let mut cases: Vec<(String, Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>)> = Vec::new();

    for other in BOUNDARY_REGISTRY_SIZES {
        if other == members {
            continue;
        }

        let other_keys = canonical_boundary_members(other)
            .iter()
            .map(|member| member.public_key)
            .collect::<Vec<_>>();

        cases.push((format!("boundary-size-{other}"), other_keys));
    }

    let Some((_, removed)) = fixture.registry_keys.split_first() else {
        panic!("boundary registry must not be empty");
    };

    cases.push(("removed-one-real-member".to_owned(), removed.to_vec()));

    let Some(extra_key) = fixture_public_key(members) else {
        panic!("one additional fixture key must exist for {members} members");
    };
    let mut added = fixture.registry_keys.clone();
    added.push(extra_key);
    added.sort_unstable();

    cases.push(("added-one-real-member".to_owned(), added));

    for (label, keys) in cases {
        let Ok(mismatched_verifier) =
            TariTriptychPrototypeVerifierV1::new(fixture.registry_commitment, keys.clone())
        else {
            panic!("{label} verifier configuration must be structurally valid");
        };

        assert!(
            matches!(
                mismatched_verifier.verify(&fixture.primary_statement, final_proof),
                Err(error) if error.code() == ValidationCode::MalformedProof
            ),
            "{label} must not verify a proof from the {members}-member registry",
        );

        let other_registry = registry_snapshot_from_keys(&keys);
        let Ok(other_verifier) =
            build_tari_triptych_verifier_from_registry_v1(&other_registry, &provider)
        else {
            panic!("{label} registry must construct a Triptych verifier");
        };

        assert_ne!(
            other_verifier.registry_commitment(),
            fixture.registry_commitment
        );
        assert!(
            matches!(
                other_verifier.verify(&fixture.primary_statement, final_proof),
                Err(error) if error.code() == ValidationCode::InvalidData
            ),
            "{label} must reject a foreign registry commitment for {members} members",
        );
    }
}

/// Rejects a valid inner proof paired with another signer's linking tag.
fn assert_swapped_nullifier_rejection(
    fixture: &BoundaryFixtureV1,
    first_proof: &[u8],
    final_proof: &[u8],
    ledger: &mut BallotAcceptanceLedger,
    members: usize,
) {
    let provider = Blake3HashProviderV1;
    let (Ok(first_envelope), Ok(final_envelope)) = (
        TariTriptychProofEnvelopeV1::from_bytes(first_proof),
        TariTriptychProofEnvelopeV1::from_bytes(final_proof),
    ) else {
        panic!("boundary probe envelopes must decode for {members} members");
    };

    assert_ne!(
        first_envelope.linking_tag_bytes(),
        final_envelope.linking_tag_bytes(),
    );

    let Ok(swapped) = TariTriptychProofEnvelopeV1::new(
        *first_envelope.linking_tag_bytes(),
        final_envelope.triptych_proof_bytes().to_vec(),
    ) else {
        panic!("swapped-nullifier envelope must remain structurally encodable");
    };
    let swapped_bytes = swapped.to_bytes();

    assert!(
        matches!(
            fixture.verifier.verify(&fixture.primary_statement, &swapped_bytes),
            Err(error) if error.code() == ValidationCode::MalformedProof
        ),
        "a proof paired with another signer's nullifier must be rejected for {members} members",
    );

    let before = ledger.len();
    let package_bytes = boundary_package_bytes(
        &fixture.primary_manifest,
        &fixture.primary_payload,
        swapped_bytes,
    );
    let outcome = ingest_approval_ballot_package_v1(
        &package_bytes,
        &fixture.primary_manifest,
        &fixture.candidates,
        &fixture.lifecycle,
        ledger,
        &provider,
        &fixture.verifier,
    );

    assert!(
        matches!(outcome, Err(error) if error.code() == ValidationCode::MalformedProof),
        "swapped-nullifier ingestion must be rejected for {members} members",
    );
    assert_eq!(ledger.len(), before);
}

/// Confirms every boundary transition changes commitment, statement, and ring.
fn assert_boundary_transitions(evidence: &[BoundarySizeEvidenceV1]) {
    let commitments = evidence
        .iter()
        .map(|entry| entry.registry_commitment)
        .collect::<BTreeSet<_>>();
    let statements = evidence
        .iter()
        .map(|entry| entry.statement_bytes.clone())
        .collect::<BTreeSet<_>>();
    let padded_vectors = evidence
        .iter()
        .map(|entry| entry.padded_verification_keys.clone())
        .collect::<BTreeSet<_>>();

    assert_eq!(commitments.len(), evidence.len());
    assert_eq!(statements.len(), evidence.len());
    assert_eq!(padded_vectors.len(), evidence.len());

    for pair in evidence.windows(2) {
        let (Some(lower), Some(upper)) = (pair.first(), pair.get(1)) else {
            panic!("boundary transition must compare two recorded sizes");
        };

        assert!(lower.members < upper.members);
        assert_ne!(
            lower.registry_commitment, upper.registry_commitment,
            "transition {} -> {} must change the registry commitment",
            lower.members, upper.members,
        );
        assert_ne!(
            lower.statement_bytes, upper.statement_bytes,
            "transition {} -> {} must change the complete proof statement",
            lower.members, upper.members,
        );
        assert_ne!(
            lower.padded_verification_keys, upper.padded_verification_keys,
            "transition {} -> {} must change the padded verification-key vector",
            lower.members, upper.members,
        );
        assert!(upper.padded_capacity >= lower.padded_capacity);

        println!(
            "[padding-boundary] transition {} -> {} padded_capacity {} -> {} \
             commitment_changed=true statement_changed=true padded_vector_changed=true",
            lower.members, upper.members, lower.padded_capacity, upper.padded_capacity,
        );
    }
}

/// Formats an average duration in milliseconds with microsecond resolution.
fn average_millis_text(total: Duration, count: usize) -> String {
    let Ok(count) = u128::try_from(count) else {
        return "n/a".to_owned();
    };

    if count == 0 {
        return "n/a".to_owned();
    }

    let micros = total.as_micros() / count;

    format!("{}.{:03}", micros / 1_000, micros % 1_000)
}

/// Formats bytes as lowercase hexadecimal for evidence output.
fn hex_lower(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));

    for byte in bytes {
        let Ok(()) = write!(encoded, "{byte:02x}") else {
            return "<hex-encoding-failed>".to_owned();
        };
    }

    encoded
}
