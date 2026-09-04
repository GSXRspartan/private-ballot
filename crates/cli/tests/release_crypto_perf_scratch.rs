//! SCRATCH release crypto performance benchmark (Slice: Production Release Audit).
//!
//! Disposable: generated for the production-release crypto performance audit,
//! archived into PRODUCTION_RELEASE_CRYPTO_PERFORMANCE_AUDIT.md /.csv, then
//! removed. Touches no production source, durable format, protocol, or vendored
//! crypto. Ignored by default; run explicitly under --release.
//!
//!   cargo +1.97.1-x86_64-pc-windows-msvc test -p tari-cc-private-ballot-cli \
//!     --release --test release_crypto_perf_scratch -- --ignored --nocapture
//!
//! It measures, over registry sizes 50/100/500/1000/2048/4096, on the exact
//! production verify path (`verify_approval_proof` and the crypto
//! `verify_batch_v1` override): individual proof verification and batch
//! verification (batch-of-4 and batch-of-16) per-proof cost, plus a runtime
//! curve25519-dalek AVX2 backend probe.

use std::time::Instant;

use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1,
    CandidateDefinition, CandidateId, CandidateSet, ElectionId, ElectionManifestV1,
    ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    ProofBatchInputV1, ProofVerifierV1, RISTRETTO_COMPRESSED_POINT_BYTES,
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychPrototypeVerifierV1, TariTriptychSecretKeyV1,
    prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, PROTOCOL_VERSION_V1, ProofStatementV1, ProtocolError,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    build_tari_triptych_verifier_from_registry_v1, reconstruct_approval_proof_statement,
    verify_approval_proof,
};

const SIZES: [usize; 6] = [50, 100, 500, 1000, 2048, 4096];
const PROOFS_PER_SIZE: usize = 16;

struct Fixture {
    registry: RegistrySnapshot,
    candidates: CandidateSet,
    manifest: ElectionManifestV1,
}

fn approval_limits() -> ApprovalLimits {
    match ApprovalLimits::new(1, 1, false) {
        Ok(limits) => limits,
        Err(_) => panic!("approval limits must be valid"),
    }
}

fn candidate_id(bytes: &[u8]) -> CandidateId {
    match CandidateId::new(bytes.to_vec()) {
        Ok(id) => id,
        Err(_) => panic!("candidate id must be valid"),
    }
}

fn candidate_set() -> CandidateSet {
    let first =
        match CandidateDefinition::new(candidate_id(b"candidate-a"), "Candidate A".to_owned()) {
            Ok(def) => def,
            Err(_) => panic!("candidate a must be valid"),
        };
    let second =
        match CandidateDefinition::new(candidate_id(b"candidate-b"), "Candidate B".to_owned()) {
            Ok(def) => def,
            Err(_) => panic!("candidate b must be valid"),
        };
    match CandidateSet::new(vec![first, second]) {
        Ok(set) => set,
        Err(_) => panic!("candidate set must be valid"),
    }
}

fn scalar_bytes(value: u64) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
    let mut bytes = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    bytes
}

/// Registry of `members` real keys derived from scalars 1..=members, sorted.
fn registry(members: usize) -> RegistrySnapshot {
    let mut keys: Vec<[u8; RISTRETTO_COMPRESSED_POINT_BYTES]> = (1..=members as u64)
        .map(|value| {
            let secret = match TariTriptychSecretKeyV1::from_canonical_bytes(scalar_bytes(value)) {
                Ok(secret) => secret,
                Err(_) => panic!("scratch secret must be canonical"),
            };
            match secret.governance_public_key() {
                Ok(public) => {
                    let mut out = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];
                    out.copy_from_slice(public.as_bytes());
                    out
                }
                Err(_) => panic!("scratch public key must derive"),
            }
        })
        .collect();
    keys.sort_unstable();

    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(keys.len()).is_ok());
    for key in keys {
        assert!(writer.write_byte_string(&key).is_ok());
    }
    match RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) {
        Ok(registry) => registry,
        Err(_) => panic!("scratch registry must decode"),
    }
}

fn fixture(members: usize) -> Fixture {
    let provider = Blake3HashProviderV1;
    let registry = registry(members);
    let candidates = candidate_set();
    let registry_commitment = match registry.canonical_commitment(&provider) {
        Ok(commitment) => commitment,
        Err(_) => panic!("registry commitment must derive"),
    };
    let candidate_set_commitment = match candidates.canonical_commitment(&provider) {
        Ok(commitment) => commitment,
        Err(_) => panic!("candidate commitment must derive"),
    };
    let election_id = match ElectionId::new(format!("release-perf-{members}").into_bytes()) {
        Ok(id) => id,
        Err(_) => panic!("election id must be valid"),
    };
    let manifest = match ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: format!("release-perf-{members}-rev-1"),
    }) {
        Ok(manifest) => manifest,
        Err(_) => panic!("manifest must be valid"),
    };
    Fixture {
        registry,
        candidates,
        manifest,
    }
}

fn payload_a(candidates: &CandidateSet) -> ApprovalBallotPayload {
    match ApprovalBallotPayload::new(
        vec![candidate_id(b"candidate-a")],
        candidates,
        approval_limits(),
    ) {
        Ok(payload) => payload,
        Err(_) => panic!("payload must be valid"),
    }
}

fn make_proof(
    fixture: &Fixture,
    statement: &ProofStatementV1,
    verifier: &TariTriptychPrototypeVerifierV1,
    scalar: u64,
) -> Result<Vec<u8>, ProtocolError> {
    let _ = fixture;
    let secret = TariTriptychSecretKeyV1::from_canonical_bytes(scalar_bytes(scalar))?;
    prove_tari_triptych_prototype_v1(statement, verifier, &secret)
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

#[test]
#[ignore = "manual release crypto performance benchmark"]
fn release_crypto_perf_benchmark() {
    let profile = if cfg!(debug_assertions) {
        "DEBUG"
    } else {
        "RELEASE"
    };
    let avx2 = std::arch::is_x86_feature_detected!("avx2");
    let avx512f = std::arch::is_x86_feature_detected!("avx512f");
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);
    println!("PROBE profile={profile} avx2={avx2} avx512f={avx512f} available_parallelism={cores}");
    println!(
        "CSV_HEADER,size,ring_cap,verify_individual_us,batch4_per_proof_us,batch16_per_proof_us,batch4_amort,batch16_amort"
    );

    let provider = Blake3HashProviderV1;

    for &members in SIZES.iter() {
        let fixture = fixture(members);
        let verifier =
            match build_tari_triptych_verifier_from_registry_v1(&fixture.registry, &provider) {
                Ok(verifier) => verifier,
                Err(_) => panic!("verifier must build"),
            };
        let payload = payload_a(&fixture.candidates);
        let statement =
            match reconstruct_approval_proof_statement(&fixture.manifest, &payload, &provider) {
                Ok(statement) => statement,
                Err(_) => panic!("statement must reconstruct"),
            };

        // Generate PROOFS_PER_SIZE real proofs from distinct registered voters.
        let mut proofs: Vec<Vec<u8>> = Vec::with_capacity(PROOFS_PER_SIZE);
        for scalar in 1..=PROOFS_PER_SIZE as u64 {
            match make_proof(&fixture, &statement, &verifier, scalar) {
                Ok(proof) => proofs.push(proof),
                Err(error) => panic!("proof {scalar} must construct: {error}"),
            }
        }

        // Warm up (backend dispatch, caches) with one verify.
        assert!(
            verify_approval_proof(
                &fixture.manifest,
                &payload,
                &proofs[0],
                &provider,
                &verifier
            )
            .is_ok()
        );

        // Individual verify: median per-proof over all proofs.
        let mut individual = Vec::with_capacity(PROOFS_PER_SIZE);
        for proof in proofs.iter() {
            let start = Instant::now();
            let outcome =
                verify_approval_proof(&fixture.manifest, &payload, proof, &provider, &verifier);
            let elapsed = start.elapsed().as_micros();
            assert!(outcome.is_ok(), "individual verify must accept");
            individual.push(elapsed);
        }
        let verify_individual_us = median(individual);

        // Batch-of-4 (per proof).
        let batch4_inputs: Vec<ProofBatchInputV1<'_>> = proofs[..4]
            .iter()
            .map(|proof| ProofBatchInputV1 {
                statement: &statement,
                proof_bytes: proof.as_slice(),
            })
            .collect();
        let start = Instant::now();
        let batch4 = verifier.verify_batch_v1(&batch4_inputs);
        let batch4_total = start.elapsed().as_micros();
        assert!(batch4.iter().all(|r| r.is_ok()), "batch4 must accept all");
        let batch4_per_proof = batch4_total / 4;

        // Batch-of-16 (per proof).
        let batch16_inputs: Vec<ProofBatchInputV1<'_>> = proofs
            .iter()
            .map(|proof| ProofBatchInputV1 {
                statement: &statement,
                proof_bytes: proof.as_slice(),
            })
            .collect();
        let start = Instant::now();
        let batch16 = verifier.verify_batch_v1(&batch16_inputs);
        let batch16_total = start.elapsed().as_micros();
        assert!(batch16.iter().all(|r| r.is_ok()), "batch16 must accept all");
        let batch16_per_proof = batch16_total / PROOFS_PER_SIZE as u128;

        let ring_cap = members.next_power_of_two();
        let batch4_amort = verify_individual_us as f64 / batch4_per_proof.max(1) as f64;
        let batch16_amort = verify_individual_us as f64 / batch16_per_proof.max(1) as f64;
        println!(
            "CSV_ROW,{members},{ring_cap},{verify_individual_us},{batch4_per_proof},{batch16_per_proof},{batch4_amort:.2},{batch16_amort:.2}"
        );
    }
}
