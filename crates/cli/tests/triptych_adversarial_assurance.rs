//! Bounded adversarial assurance for the project-owned real Triptych path.
//!
//! This target deliberately uses the normal package-to-ledger ingestion API.
//! It is regression evidence, not a proof of mathematical soundness, zero
//! knowledge, or constant-time execution.

use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

use tari_cc_private_ballot_ballot::{
    ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1, BallotPackageV1,
    BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet, ElectionId,
    ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input,
};
use tari_cc_private_ballot_crypto::{
    RISTRETTO_COMPRESSED_POINT_BYTES, TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES,
    TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychProofEnvelopeV1, TariTriptychPrototypeVerifierV1,
    TariTriptychSecretKeyV1, prove_tari_triptych_prototype_v1,
};
use tari_cc_private_ballot_protocol::{
    Blake3HashProviderV1, CanonicalCborWriter, MAX_CANONICAL_OBJECT_BYTES, MAX_PROOF_BYTES,
    ManifestHash, PROTOCOL_VERSION_V1, ProtocolError, ValidationCode,
};
use tari_cc_private_ballot_registry::RegistrySnapshot;
use tari_cc_private_ballot_verifier::{
    BallotAcceptanceLedger, ProductionProofSuitePolicyV1,
    build_tari_triptych_verifier_from_registry_v1, ingest_approval_ballot_package_v1,
    reconstruct_approval_proof_statement,
};

const MUTATION_RING_MEMBERS: usize = 4;
const SERIALIZATION_RING_MEMBERS: usize = 16;
const FIXTURE_KEY_COUNT: usize = 2_048;
const FIXTURE_KEYS: &[u8; FIXTURE_KEY_COUNT * RISTRETTO_COMPRESSED_POINT_BYTES] =
    include_bytes!("fixtures/triptych_large_election_keys_2048.bin");
const OUTER_PREFIX_BYTES: usize = 16;
const PROOF_BODY_BIT_STRIDE: usize = 17;
const DETERMINISTIC_CORPUS_SEED: u64 = 0x3c17_5eed_c0de_2026;
const TIMING_CORPUS_SEED: u64 = 0x3c17_71ae_5eed_2026;
const MANUAL_TIMING_SAMPLES: usize = 12;
const SPECTACULAR_HANG_LIMIT: Duration = Duration::from_secs(30);
const SPECTACULAR_TIMING_RATIO_LIMIT: f64 = 5.0;

#[derive(Clone, Copy)]
struct RegistryMember {
    canonical_index: usize,
    scalar: u64,
    public_key: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
}

struct Fixture {
    candidates: CandidateSet,
    manifest: ElectionManifestV1,
    verifier: TariTriptychPrototypeVerifierV1,
    members: Vec<RegistryMember>,
}

struct MutationCase {
    label: String,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct CorpusStatistics {
    mutation_count: usize,
    rejections: BTreeMap<&'static str, usize>,
    maximum_input_bytes: usize,
    maximum_elapsed: Duration,
}

impl CorpusStatistics {
    fn record(&mut self, input_bytes: usize, elapsed: Duration, code: ValidationCode) {
        self.mutation_count += 1;
        self.maximum_input_bytes = self.maximum_input_bytes.max(input_bytes);
        self.maximum_elapsed = self.maximum_elapsed.max(elapsed);
        *self.rejections.entry(code.as_str()).or_default() += 1;
    }

    fn rejection_summary(&self) -> String {
        let mut summary = String::new();

        for (index, (code, count)) in self.rejections.iter().enumerate() {
            if index > 0 {
                summary.push_str(", ");
            }
            summary.push_str(code);
            summary.push('=');
            summary.push_str(&count.to_string());
        }

        summary
    }
}

#[derive(Clone, Copy)]
struct CborStringLayout {
    header_start: usize,
    data_start: usize,
    data_end: usize,
}

impl CborStringLayout {
    const fn header_len(self) -> usize {
        self.data_start - self.header_start
    }
}

#[derive(Clone, Copy)]
struct PackageLayout {
    payload: CborStringLayout,
    proof: CborStringLayout,
}

#[test]
fn bounded_complete_ingestion_mutation_corpus_rejects_without_ledger_mutation() {
    let fixture = fixture(
        "phase3-3c17-mutation",
        MUTATION_RING_MEMBERS,
        standard_candidates(),
    );
    let baseline = package_for_member(&fixture, 0, b"a");
    let other = package_for_member(&fixture, 1, b"b");
    let baseline_bytes = canonical_package_bytes(&baseline);
    let other_bytes = canonical_package_bytes(&other);
    let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(baseline.proof()) else {
        panic!("valid real Triptych proof envelope must decode");
    };
    let Ok(other_envelope) = TariTriptychProofEnvelopeV1::from_bytes(other.proof()) else {
        panic!("second valid real Triptych proof envelope must decode");
    };
    let Some(layout) = canonical_package_layout(&baseline_bytes) else {
        panic!("valid canonical package layout must be inspectable");
    };
    let inner = envelope.triptych_proof_bytes();
    let mut statistics = CorpusStatistics::default();
    let corpus_started = Instant::now();

    let package_truncations = (0..baseline_bytes.len())
        .map(|boundary| MutationCase {
            label: format!("complete package truncation at {boundary}"),
            bytes: baseline_bytes[..boundary].to_vec(),
        })
        .collect::<Vec<_>>();
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "complete canonical package truncation boundaries",
        &package_truncations,
        &mut statistics,
    );

    let envelope_bytes = envelope.to_bytes();
    let envelope_truncations = (0..envelope_bytes.len())
        .map(|boundary| MutationCase {
            label: format!("proof envelope truncation at {boundary}"),
            bytes: package_bytes_with_proof(&baseline, envelope_bytes[..boundary].to_vec()),
        })
        .collect::<Vec<_>>();
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "Triptych envelope truncation boundaries",
        &envelope_truncations,
        &mut statistics,
    );

    let inner_truncations = (0..inner.len())
        .map(|boundary| MutationCase {
            label: format!("inner Triptych proof truncation at {boundary}"),
            bytes: package_bytes_with_proof(
                &baseline,
                raw_envelope_with_inner(&envelope, inner[..boundary].to_vec()),
            ),
        })
        .collect::<Vec<_>>();
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "inner Triptych proof truncation boundaries",
        &inner_truncations,
        &mut statistics,
    );

    let Ok(other_payload_bytes) = other.payload().to_canonical_cbor() else {
        panic!("second valid payload must encode canonically");
    };
    let outer_suffixes = [
        ("one zero byte", vec![0_u8]),
        ("one nonzero byte", vec![0xa5_u8]),
        (
            "eight deterministic bytes",
            vec![0x10_u8, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87],
        ),
        ("thirty-two deterministic bytes", vec![0x5a_u8; 32]),
        ("another valid envelope", other_envelope.to_bytes()),
        (
            "another valid inner proof",
            other_envelope.triptych_proof_bytes().to_vec(),
        ),
        ("another valid canonical package", other_bytes.clone()),
        (
            "another valid canonical payload",
            other_payload_bytes.clone(),
        ),
    ];
    let outer_suffix_cases = outer_suffixes
        .iter()
        .map(|(label, suffix)| {
            let mut bytes = baseline_bytes.clone();
            bytes.extend_from_slice(suffix);

            MutationCase {
                label: format!("outer appended suffix: {label}"),
                bytes,
            }
        })
        .collect::<Vec<_>>();
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "outer package appended suffixes",
        &outer_suffix_cases,
        &mut statistics,
    );

    let proof_suffix_cases = outer_suffixes
        .iter()
        .map(|(label, suffix)| {
            let mut proof = envelope.to_bytes();
            proof.extend_from_slice(suffix);

            MutationCase {
                label: format!("proof envelope appended suffix: {label}"),
                bytes: package_bytes_with_proof(&baseline, proof),
            }
        })
        .collect::<Vec<_>>();
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "proof-envelope and inner-proof appended suffixes",
        &proof_suffix_cases,
        &mut statistics,
    );

    let bit_flip_cases =
        deterministic_bit_flip_cases(&baseline, &baseline_bytes, &envelope, layout);
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "deterministic outer, envelope, point, scalar, and strided proof bit flips",
        &bit_flip_cases,
        &mut statistics,
    );

    let framing_cases = framing_mutation_cases(&baseline, &baseline_bytes, &envelope, layout);
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "canonical CBOR length, envelope version, point-scalar length, and proof-limit framing",
        &framing_cases,
        &mut statistics,
    );

    let random_cases =
        deterministic_random_cases(baseline_bytes.len(), envelope.to_bytes().len(), inner.len());
    exercise_malformed_category(
        &fixture,
        &baseline_bytes,
        "fixed-seed random-looking bounded byte arrays",
        &random_cases,
        &mut statistics,
    );

    println!(
        "triptych_adversarial_assurance corpus mutations={} rejections={} max_input_bytes={} \
         max_input_ms={} total_ms={}",
        statistics.mutation_count,
        statistics.rejection_summary(),
        statistics.maximum_input_bytes,
        statistics.maximum_elapsed.as_millis(),
        corpus_started.elapsed().as_millis(),
    );
}

#[test]
fn proof_field_and_context_substitutions_reject_through_full_ingestion() {
    let source = fixture(
        "phase3-3c17-source",
        MUTATION_RING_MEMBERS,
        standard_candidates(),
    );
    let source_first = package_for_member(&source, 0, b"a");
    let source_second = package_for_member(&source, 1, b"b");
    let source_first_bytes = canonical_package_bytes(&source_first);
    let source_second_bytes = canonical_package_bytes(&source_second);
    let Ok(source_first_envelope) = TariTriptychProofEnvelopeV1::from_bytes(source_first.proof())
    else {
        panic!("source first envelope must decode");
    };
    let Ok(source_second_envelope) = TariTriptychProofEnvelopeV1::from_bytes(source_second.proof())
    else {
        panic!("source second envelope must decode");
    };
    let mut statistics = CorpusStatistics::default();

    let swapped_linking_tag = envelope_with_parts(
        *source_second_envelope.linking_tag_bytes(),
        source_first_envelope.triptych_proof_bytes().to_vec(),
    );
    let swapped_inner_proof = envelope_with_parts(
        *source_first_envelope.linking_tag_bytes(),
        source_second_envelope.triptych_proof_bytes().to_vec(),
    );
    let same_context_cases = vec![
        MutationCase {
            label: "linking tag from a different valid proof".to_owned(),
            bytes: package_bytes_with_proof(&source_first, swapped_linking_tag),
        },
        MutationCase {
            label: "inner Triptych proof from a different valid proof".to_owned(),
            bytes: package_bytes_with_proof(&source_first, swapped_inner_proof),
        },
        MutationCase {
            label: "entire envelope from a different valid proof".to_owned(),
            bytes: package_bytes_with_proof(&source_first, source_second.proof().to_vec()),
        },
        MutationCase {
            label: "canonical payload from a different valid proof".to_owned(),
            bytes: canonical_package_from_parts(
                source_first.manifest_hash(),
                source_first.proof_suite_id(),
                source_first.proof().to_vec(),
                source_second.payload().clone(),
            ),
        },
        MutationCase {
            label: "proof-suite identifier substitution".to_owned(),
            bytes: canonical_package_from_parts(
                source_first.manifest_hash(),
                "OTHER_PROJECT_SUITE",
                source_first.proof().to_vec(),
                source_first.payload().clone(),
            ),
        },
    ];
    exercise_malformed_category(
        &source,
        &source_first_bytes,
        "same-election valid-proof field substitutions",
        &same_context_cases,
        &mut statistics,
    );

    let target_election = fixture(
        "phase3-3c17-target",
        MUTATION_RING_MEMBERS,
        standard_candidates(),
    );
    let target_election_baseline =
        canonical_package_bytes(&package_for_member(&target_election, 0, b"a"));
    let target_manifest_hash = manifest_hash(&target_election.manifest);
    let target_election_cases = vec![MutationCase {
        label: "source proof and payload under substituted target manifest hash".to_owned(),
        bytes: canonical_package_from_parts(
            target_manifest_hash,
            target_election.manifest.proof_suite_id(),
            source_first.proof().to_vec(),
            source_first.payload().clone(),
        ),
    }];
    exercise_malformed_category(
        &target_election,
        &target_election_baseline,
        "election-manifest and manifest-hash substitution",
        &target_election_cases,
        &mut statistics,
    );

    let target_registry = fixture("phase3-3c17-registry", 5, standard_candidates());
    let target_registry_baseline =
        canonical_package_bytes(&package_for_member(&target_registry, 0, b"a"));
    let target_registry_cases = vec![MutationCase {
        label: "source proof under a different registered-voter context".to_owned(),
        bytes: canonical_package_from_parts(
            manifest_hash(&target_registry.manifest),
            target_registry.manifest.proof_suite_id(),
            source_first.proof().to_vec(),
            source_first.payload().clone(),
        ),
    }];
    exercise_malformed_category(
        &target_registry,
        &target_registry_baseline,
        "registry-context substitution",
        &target_registry_cases,
        &mut statistics,
    );

    let target_candidates = fixture(
        "phase3-3c17-candidates",
        MUTATION_RING_MEMBERS,
        alternate_candidates(),
    );
    let target_candidates_baseline =
        canonical_package_bytes(&package_for_member(&target_candidates, 0, b"a"));
    let target_candidate_cases = vec![MutationCase {
        label: "source proof under a different authoritative candidate set".to_owned(),
        bytes: canonical_package_from_parts(
            manifest_hash(&target_candidates.manifest),
            target_candidates.manifest.proof_suite_id(),
            source_first.proof().to_vec(),
            source_first.payload().clone(),
        ),
    }];
    exercise_malformed_category(
        &target_candidates,
        &target_candidates_baseline,
        "authoritative candidate-set substitution",
        &target_candidate_cases,
        &mut statistics,
    );

    assert_ne!(source_first_bytes, source_second_bytes);
    println!(
        "triptych_adversarial_assurance substitutions mutations={} rejections={}",
        statistics.mutation_count,
        statistics.rejection_summary(),
    );
}

#[test]
fn signer_position_serialization_smoke_has_fixed_project_owned_shape() {
    let fixture = fixture(
        "phase3-3c17-serialization",
        SERIALIZATION_RING_MEMBERS,
        standard_candidates(),
    );
    let positions = representative_positions(fixture.members.len());
    let mut expected_inner_bytes = None;
    let mut expected_envelope_bytes = None;
    let mut expected_package_bytes = None;
    let mut expected_nonproof_prefix: Option<Vec<u8>> = None;
    let mut observed = 0_usize;
    let lifecycle = open_lifecycle(&fixture.manifest);

    for position in positions.iter().copied() {
        for fresh_proof in 0..2 {
            let package = package_for_member(&fixture, position, b"a");
            let package_bytes = canonical_package_bytes(&package);
            let Some(layout) = canonical_package_layout(&package_bytes) else {
                panic!("canonical package layout must remain fixed");
            };
            let Ok(decoded) = BallotPackageV1::from_canonical_cbor(
                &package_bytes,
                &fixture.candidates,
                fixture.manifest.approval_limits(),
            ) else {
                panic!("canonical package parser must recover each signer package");
            };
            let Ok(reencoded) = decoded.to_canonical_cbor() else {
                panic!("decoded signer package must re-encode canonically");
            };
            let Ok(envelope) = TariTriptychProofEnvelopeV1::from_bytes(package.proof()) else {
                panic!("proof envelope parser must recover each signer package");
            };

            assert_eq!(reencoded, package_bytes);
            assert_eq!(envelope.to_bytes(), package.proof());
            assert_eq!(layout.proof.data_end, package_bytes.len());
            assert_eq!(
                layout.proof.data_start,
                layout.payload.data_end + layout.proof.header_len(),
            );
            assert_eq!(package.proof().len(), envelope.to_bytes().len());

            let nonproof_prefix = &package_bytes[..layout.proof.data_start];
            assert_length_and_prefix(
                &mut expected_inner_bytes,
                envelope.triptych_proof_bytes().len(),
                "inner Triptych proof",
            );
            assert_length_and_prefix(
                &mut expected_envelope_bytes,
                envelope.to_bytes().len(),
                "Triptych envelope",
            );
            assert_length_and_prefix(
                &mut expected_package_bytes,
                package_bytes.len(),
                "canonical package",
            );
            match expected_nonproof_prefix {
                Some(ref prefix) => assert_eq!(
                    prefix.as_slice(),
                    nonproof_prefix,
                    "project-owned package fields must not vary by canonical signer position",
                ),
                None => expected_nonproof_prefix = Some(nonproof_prefix.to_vec()),
            }

            assert_eq!(
                fixture.members[position].canonical_index, position,
                "representative position must remain a canonical registry position",
            );
            assert_eq!(
                layout.proof.data_start,
                nonproof_prefix.len(),
                "the inspected prefix must cover exactly every project-owned non-proof field",
            );
            let mut ledger = BallotAcceptanceLedger::new();
            assert!(
                ingest(&fixture, &lifecycle, &mut ledger, &package_bytes).is_ok(),
                "the package parser and complete proof parser must accept each observed shape",
            );
            assert_eq!(ledger.len(), 1);
            observed += 1;
            assert!(fresh_proof < 2);
        }
    }

    println!(
        "triptych_adversarial_assurance serialization ring_members={} positions={} fresh_proofs={} \
         inner_bytes={} envelope_bytes={} package_bytes={} nonproof_prefix_bytes={} fields=5",
        fixture.members.len(),
        positions.len(),
        observed,
        expected_inner_bytes.unwrap_or(0),
        expected_envelope_bytes.unwrap_or(0),
        expected_package_bytes.unwrap_or(0),
        expected_nonproof_prefix.as_ref().map_or(0, Vec::len),
    );
}

#[test]
fn production_randomness_and_hazmat_policy_inventory_is_release_safe() {
    const CRYPTO_CARGO: &str = include_str!("../../crypto/Cargo.toml");
    const CRYPTO_LIB: &str = include_str!("../../crypto/src/lib.rs");
    const PROTOCOL_LIB: &str = include_str!("../../protocol/src/lib.rs");
    const PROVER: &str = include_str!("../../crypto/src/triptych_prover.rs");
    const VENDORED_CARGO: &str = include_str!("../../../third_party/tari-triptych/Cargo.toml");

    assert!(CRYPTO_CARGO.contains(
        "triptych = { path = \"../../third_party/tari-triptych\", default-features = false }"
    ));
    assert!(!CRYPTO_CARGO.contains("hazmat"));
    assert!(VENDORED_CARGO.contains("hazmat = []"));
    assert!(PROVER.contains("use rand_core::OsRng;"));
    assert!(PROVER.contains("TriptychProof::prove_with_rng"));
    assert!(PROVER.contains("&mut OsRng"));
    assert!(!PROVER.contains("prove_vartime"));
    assert!(!PROVER.contains("prove_with_rng_vartime"));
    assert!(!PROVER.contains("println!"));
    assert!(CRYPTO_LIB.contains(
        "#[cfg(any(test, feature = \"test-only-suites\"))]\npub mod test_only_verifier;"
    ));
    assert!(
        PROTOCOL_LIB.contains("#[cfg(any(test, debug_assertions))]\npub use hashing::test_only;")
    );

    let policy = ProductionProofSuitePolicyV1::new();
    assert!(policy.validate(TARI_TRIPTYCH_PROOF_SUITE_ID_V1).is_ok());
    assert!(matches!(
        policy.validate("TEST_ONLY_NOT_ANONYMOUS_NOT_FOR_BINDING_ELECTIONS"),
        Err(error) if error.code() == ValidationCode::UnsupportedProofSuite
    ));

    let secret = secret_key(1);
    assert_eq!(format!("{secret:?}"), "TariTriptychSecretKeyV1([REDACTED])");

    println!(
        "triptych_adversarial_assurance policy normal_prover_rng=OsRng \
         hazmat_feature=disabled_in_project_production_dependency \
         test_only_suite=feature_gated_and_rejected_by_production_policy \
         secret_debug=redacted",
    );
}

#[test]
#[ignore = "manual release-only signer timing smoke; run this target with --release -- --ignored --nocapture"]
fn manual_release_signer_position_timing_smoke() {
    if cfg!(debug_assertions) {
        panic!("run this exploratory timing smoke with cargo test --release");
    }

    let fixture = fixture(
        "phase3-3c17-timing",
        SERIALIZATION_RING_MEMBERS,
        standard_candidates(),
    );
    let positions = representative_positions(fixture.members.len());
    let statement = proof_statement_for(&fixture, b"a");

    for position in &positions {
        let proof = prove_raw_proof(&fixture, &statement, *position);
        assert!(!proof.is_empty());
    }

    let mut samples = BTreeMap::<usize, Vec<Duration>>::new();
    let mut order_rng = DeterministicBytes::new(TIMING_CORPUS_SEED);
    for _ in 0..MANUAL_TIMING_SAMPLES {
        let order = deterministically_shuffle_positions(&positions, &mut order_rng);

        for position in order {
            let started = Instant::now();
            let proof = prove_raw_proof(&fixture, &statement, position);
            let elapsed = started.elapsed();

            assert!(!proof.is_empty());
            samples.entry(position).or_default().push(elapsed);
        }
    }

    let mut summaries = Vec::new();
    for position in positions {
        let Some(position_samples) = samples.get(&position) else {
            panic!("every representative signer must receive timing samples");
        };
        let summary = timing_summary(position, position_samples);

        println!(
            "triptych_adversarial_assurance timing signer_position={} samples={} min_us={:.3} \
             median_us={:.3} mean_us={:.3} max_us={:.3} stddev_us={:.3}",
            summary.position,
            summary.samples,
            summary.minimum_us,
            summary.median_us,
            summary.mean_us,
            summary.maximum_us,
            summary.standard_deviation_us,
        );
        summaries.push(summary);
    }

    let median_ratio = ratio_of_extremes(summaries.iter().map(|summary| summary.median_us));
    let mean_ratio = ratio_of_extremes(summaries.iter().map(|summary| summary.mean_us));
    assert!(
        median_ratio <= SPECTACULAR_TIMING_RATIO_LIMIT
            && mean_ratio <= SPECTACULAR_TIMING_RATIO_LIMIT,
        "a >= {SPECTACULAR_TIMING_RATIO_LIMIT}x signer-position timing difference requires investigation; \
         this smoke does not prove constant-time behavior",
    );
    println!(
        "triptych_adversarial_assurance timing result=pass median_ratio={median_ratio:.3} \
         mean_ratio={mean_ratio:.3} threshold={SPECTACULAR_TIMING_RATIO_LIMIT:.1}x \
         caveat=hardware_os_scheduling_and_background_load_dependent",
    );
}

fn exercise_malformed_category(
    fixture: &Fixture,
    original_bytes: &[u8],
    category: &str,
    cases: &[MutationCase],
    statistics: &mut CorpusStatistics,
) {
    let lifecycle = open_lifecycle(&fixture.manifest);
    let mut ledger = BallotAcceptanceLedger::new();

    for case in cases {
        let started = Instant::now();
        assert_single_structural_interpretation(fixture, &case.bytes, &case.label);

        let result = ingest(fixture, &lifecycle, &mut ledger, &case.bytes);
        let elapsed = started.elapsed();
        let Err(error) = result else {
            panic!(
                "{category}: malformed input unexpectedly accepted: {}",
                case.label
            );
        };
        assert!(
            elapsed <= SPECTACULAR_HANG_LIMIT,
            "{category}: malformed input exceeded the broad {} second smoke limit: {}",
            SPECTACULAR_HANG_LIMIT.as_secs(),
            case.label,
        );

        let repeated = ingest(fixture, &lifecycle, &mut ledger, &case.bytes);
        let Err(repeated_error) = repeated else {
            panic!(
                "{category}: malformed input was accepted on a repeated attempt: {}",
                case.label
            );
        };
        assert_eq!(
            repeated_error.code(),
            error.code(),
            "{category}: validation code changed across repeated ingestion: {}",
            case.label,
        );
        assert!(
            ledger.is_empty(),
            "{category}: rejected input mutated the acceptance ledger: {}",
            case.label,
        );
        statistics.record(case.bytes.len(), elapsed, error.code());
    }

    assert!(
        ledger.is_empty(),
        "{category}: the ledger must remain empty after the malformed corpus",
    );
    assert!(
        ingest(fixture, &lifecycle, &mut ledger, original_bytes).is_ok(),
        "{category}: the original valid package must remain acceptable",
    );
    assert_eq!(ledger.len(), 1);
    assert!(matches!(
        ingest(fixture, &lifecycle, &mut ledger, original_bytes),
        Err(error) if error.code() == ValidationCode::DuplicateNullifier
    ));
    assert_eq!(ledger.len(), 1);
    println!(
        "triptych_adversarial_assurance category={} mutations={} ledger=unchanged_before_baseline",
        category,
        cases.len(),
    );
}

fn assert_single_structural_interpretation(fixture: &Fixture, bytes: &[u8], label: &str) {
    if let Ok(decoded) = BallotPackageV1::from_canonical_cbor(
        bytes,
        &fixture.candidates,
        fixture.manifest.approval_limits(),
    ) {
        let Ok(reencoded) = decoded.to_canonical_cbor() else {
            panic!("{label}: a structurally decoded package must re-encode");
        };
        assert_eq!(
            reencoded, bytes,
            "{label}: accepted structural decoding must have one canonical interpretation",
        );
    }
}

fn deterministic_bit_flip_cases(
    package: &BallotPackageV1,
    package_bytes: &[u8],
    envelope: &TariTriptychProofEnvelopeV1,
    layout: PackageLayout,
) -> Vec<MutationCase> {
    let mut cases = Vec::new();
    let outer_prefix = package_bytes.len().min(OUTER_PREFIX_BYTES);
    for index in 0..outer_prefix {
        for bit in 0..8 {
            let mut bytes = package_bytes.to_vec();
            bytes[index] ^= 1_u8 << bit;
            cases.push(MutationCase {
                label: format!("outer package prefix byte {index} bit {bit}"),
                bytes,
            });
        }
    }

    let envelope_bytes = envelope.to_bytes();
    for index in 0..TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES {
        for bit in 0..8 {
            let mut proof = envelope_bytes.clone();
            proof[index] ^= 1_u8 << bit;
            cases.push(MutationCase {
                label: format!("envelope header or linking tag byte {index} bit {bit}"),
                bytes: package_bytes_with_proof(package, proof),
            });
        }
    }

    let inner = envelope.triptych_proof_bytes();
    let point_range = 8..40;
    let scalar_range = 136..168;
    assert!(
        inner.len() >= scalar_range.end,
        "the bounded real proof fixture must expose representative point and scalar encodings",
    );
    for (label, range) in [
        ("representative encoded point", point_range.clone()),
        ("representative encoded scalar", scalar_range.clone()),
    ] {
        for index in range {
            for bit in 0..8 {
                let mut proof = envelope_bytes.clone();
                let proof_index = TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES + index;
                proof[proof_index] ^= 1_u8 << bit;
                cases.push(MutationCase {
                    label: format!("{label} byte {index} bit {bit}"),
                    bytes: package_bytes_with_proof(package, proof),
                });
            }
        }
    }

    let mut sampled_body_indexes = (0..inner.len())
        .step_by(PROOF_BODY_BIT_STRIDE)
        .filter(|index| !point_range.contains(index) && !scalar_range.contains(index))
        .collect::<Vec<_>>();
    if let Some(last) = inner.len().checked_sub(1)
        && sampled_body_indexes.last().copied() != Some(last)
    {
        sampled_body_indexes.push(last);
    }
    for index in sampled_body_indexes {
        for bit in 0..8 {
            let mut proof = envelope_bytes.clone();
            let proof_index = TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES + index;
            proof[proof_index] ^= 1_u8 << bit;
            cases.push(MutationCase {
                label: format!(
                    "strided remaining proof body byte {index} bit {bit} stride={PROOF_BODY_BIT_STRIDE}"
                ),
                bytes: package_bytes_with_proof(package, proof),
            });
        }
    }

    assert_eq!(layout.proof.data_end, package_bytes.len());
    cases
}

fn framing_mutation_cases(
    package: &BallotPackageV1,
    package_bytes: &[u8],
    envelope: &TariTriptychProofEnvelopeV1,
    layout: PackageLayout,
) -> Vec<MutationCase> {
    let mut cases = Vec::new();
    let proof_length = package.proof().len();
    assert!(
        proof_length > 1,
        "the real proof must have room for shorter and longer declared lengths",
    );
    let Some(shorter) = replace_proof_length(package_bytes, layout.proof, proof_length - 1) else {
        panic!("proof length must fit its existing canonical CBOR width");
    };
    let Some(longer) = replace_proof_length(package_bytes, layout.proof, proof_length + 1) else {
        panic!("proof length must fit its existing canonical CBOR width");
    };
    cases.push(MutationCase {
        label: "declared proof length shorter than content".to_owned(),
        bytes: shorter,
    });
    cases.push(MutationCase {
        label: "declared proof length longer than content".to_owned(),
        bytes: longer,
    });

    assert_eq!(
        layout.proof.header_len(),
        3,
        "the bounded real proof fixture must use a two-byte canonical proof length",
    );
    let Ok(length_u32) = u32::try_from(proof_length) else {
        panic!("bounded real proof length must fit u32");
    };
    let mut noncanonical = package_bytes[..layout.proof.header_start].to_vec();
    noncanonical.push(0x5a);
    noncanonical.extend_from_slice(&length_u32.to_be_bytes());
    noncanonical.extend_from_slice(package.proof());
    cases.push(MutationCase {
        label: "noncanonical widened proof byte-string length".to_owned(),
        bytes: noncanonical,
    });

    let mut unsupported_version = envelope.to_bytes();
    unsupported_version[..2].copy_from_slice(&2_u16.to_le_bytes());
    cases.push(MutationCase {
        label: "unsupported envelope version".to_owned(),
        bytes: package_bytes_with_proof(package, unsupported_version),
    });
    cases.push(MutationCase {
        label: "zero-length proof where the verifier boundary prohibits it".to_owned(),
        bytes: package_bytes_with_proof(package, Vec::new()),
    });

    let inner = envelope.triptych_proof_bytes();
    let mut point_length = inner.to_vec();
    point_length.remove(39);
    cases.push(MutationCase {
        label: "malformed representative point encoding length".to_owned(),
        bytes: package_bytes_with_proof(package, envelope_with_inner(envelope, point_length)),
    });
    let mut scalar_length = inner.to_vec();
    scalar_length.remove(167);
    cases.push(MutationCase {
        label: "malformed representative scalar encoding length".to_owned(),
        bytes: package_bytes_with_proof(package, envelope_with_inner(envelope, scalar_length)),
    });

    cases.push(MutationCase {
        label: "maximum accepted proof length boundary".to_owned(),
        bytes: raw_canonical_package(package, &vec![0_u8; MAX_PROOF_BYTES]),
    });
    cases.push(MutationCase {
        label: "one byte above maximum proof length".to_owned(),
        bytes: raw_canonical_package(package, &vec![0_u8; MAX_PROOF_BYTES + 1]),
    });

    cases
}

fn deterministic_random_cases(
    valid_package_bytes: usize,
    envelope_bytes: usize,
    inner_proof_bytes: usize,
) -> Vec<MutationCase> {
    let mut rng = DeterministicBytes::new(DETERMINISTIC_CORPUS_SEED);
    let Some(just_below_known_valid) = valid_package_bytes.checked_sub(1) else {
        panic!("valid real package size must be nonzero");
    };
    let lengths = [
        ("empty", 0_usize),
        ("one byte", 1),
        (
            "just below known minimum real package",
            just_below_known_valid,
        ),
        ("exact known real package size", valid_package_bytes),
        ("one byte above known real package", valid_package_bytes + 1),
        ("one below envelope size", envelope_bytes - 1),
        ("exact envelope size", envelope_bytes),
        ("one above envelope size", envelope_bytes + 1),
        ("one below inner proof size", inner_proof_bytes - 1),
        ("exact inner proof size", inner_proof_bytes),
        ("one above inner proof size", inner_proof_bytes + 1),
        ("one KiB", 1024),
        ("maximum canonical object size", MAX_CANONICAL_OBJECT_BYTES),
        (
            "one byte above maximum canonical object size",
            MAX_CANONICAL_OBJECT_BYTES + 1,
        ),
    ];

    lengths
        .into_iter()
        .map(|(label, length)| MutationCase {
            label: format!("fixed-seed random-looking array: {label}"),
            bytes: rng.bytes(length),
        })
        .collect()
}

fn fixture(election_id: &str, member_count: usize, candidates: CandidateSet) -> Fixture {
    assert!(
        (1..=SERIALIZATION_RING_MEMBERS).contains(&member_count),
        "this bounded assurance fixture supports a small fixed representative ring",
    );
    let mut members = (1..=member_count)
        .map(|position| {
            let Ok(scalar) = u64::try_from(position) else {
                panic!("small fixture scalar must fit u64");
            };
            let public_key = fixture_public_key(scalar);

            RegistryMember {
                canonical_index: 0,
                scalar,
                public_key,
            }
        })
        .collect::<Vec<_>>();
    members.sort_unstable_by_key(|member| member.public_key);
    for (canonical_index, member) in members.iter_mut().enumerate() {
        member.canonical_index = canonical_index;
    }

    let registry = registry_snapshot(&members);
    let provider = Blake3HashProviderV1;
    let Ok(registry_commitment) = registry.canonical_commitment(&provider) else {
        panic!("representative registry commitment must be derivable");
    };
    let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
        panic!("representative candidate-set commitment must be derivable");
    };
    let Ok(election_id) = ElectionId::new(election_id.as_bytes().to_vec()) else {
        panic!("representative election identifier must be valid");
    };
    let Ok(manifest) = ElectionManifestV1::new(ElectionManifestV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        election_id,
        ballot_kind: BallotKindV1::NonBindingApprovalPilot,
        ballot_confidentiality: BallotConfidentialityV1::Public,
        registry_commitment,
        candidate_set_commitment,
        proof_suite_id: TARI_TRIPTYCH_PROOF_SUITE_ID_V1.to_owned(),
        approval_limits: approval_limits(),
        governance_source_revision: "phase3-3c17".to_owned(),
    }) else {
        panic!("representative real Triptych manifest must be valid");
    };
    let Ok(verifier) = build_tari_triptych_verifier_from_registry_v1(&registry, &provider) else {
        panic!("representative registry must construct a real Triptych verifier");
    };

    Fixture {
        candidates,
        manifest,
        verifier,
        members,
    }
}

fn registry_snapshot(members: &[RegistryMember]) -> RegistrySnapshot {
    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(members.len()).is_ok());
    for member in members {
        assert!(writer.write_byte_string(&member.public_key).is_ok());
    }
    let Ok(snapshot) = RegistrySnapshot::from_canonical_cbor(&writer.into_bytes()) else {
        panic!("canonical representative registry must decode");
    };

    snapshot
}

fn standard_candidates() -> CandidateSet {
    candidate_set(&[
        (b"a", "Candidate A"),
        (b"b", "Candidate B"),
        (b"c", "Candidate C"),
    ])
}

fn alternate_candidates() -> CandidateSet {
    candidate_set(&[(b"a", "Candidate A"), (b"d", "Candidate D")])
}

fn candidate_set(entries: &[(&[u8], &str)]) -> CandidateSet {
    let candidates = entries
        .iter()
        .map(|(id, name)| {
            let Ok(candidate) = CandidateDefinition::new(candidate_id(id), (*name).to_owned())
            else {
                panic!("representative candidate definition must be valid");
            };

            candidate
        })
        .collect::<Vec<_>>();
    let Ok(candidates) = CandidateSet::new(candidates) else {
        panic!("representative candidate set must be valid");
    };

    candidates
}

fn candidate_id(bytes: &[u8]) -> CandidateId {
    let Ok(id) = CandidateId::new(bytes.to_vec()) else {
        panic!("representative candidate identifier must be valid");
    };

    id
}

fn approval_limits() -> ApprovalLimits {
    let Ok(limits) = ApprovalLimits::new(1, 1, false) else {
        panic!("representative approval limits must be valid");
    };

    limits
}

fn approval_payload(candidates: &CandidateSet, selected: &[u8]) -> ApprovalBallotPayload {
    let Ok(payload) =
        ApprovalBallotPayload::new(vec![candidate_id(selected)], candidates, approval_limits())
    else {
        panic!("representative approval payload must be valid");
    };

    payload
}

fn package_for_member(fixture: &Fixture, position: usize, selected: &[u8]) -> BallotPackageV1 {
    let Some(member) = fixture.members.get(position) else {
        panic!("representative signer position must be in the canonical registry");
    };
    let payload = approval_payload(&fixture.candidates, selected);
    let statement = proof_statement_for(fixture, selected);
    let proof = prove_raw_proof(fixture, &statement, member.canonical_index);

    canonical_package_from_parts_value(
        manifest_hash(&fixture.manifest),
        fixture.manifest.proof_suite_id(),
        proof,
        payload,
    )
}

fn proof_statement_for(
    fixture: &Fixture,
    selected: &[u8],
) -> tari_cc_private_ballot_protocol::ProofStatementV1 {
    let provider = Blake3HashProviderV1;
    let payload = approval_payload(&fixture.candidates, selected);
    let Ok(statement) =
        reconstruct_approval_proof_statement(&fixture.manifest, &payload, &provider)
    else {
        panic!("representative approval proof statement must reconstruct");
    };

    statement
}

fn prove_raw_proof(
    fixture: &Fixture,
    statement: &tari_cc_private_ballot_protocol::ProofStatementV1,
    position: usize,
) -> Vec<u8> {
    let Some(member) = fixture.members.get(position) else {
        panic!("representative signer position must be in the canonical registry");
    };
    let secret = secret_key(member.scalar);
    let Ok(proof) = prove_tari_triptych_prototype_v1(statement, &fixture.verifier, &secret) else {
        panic!("registered representative signer must construct a real Triptych proof");
    };

    proof
}

fn secret_key(scalar: u64) -> TariTriptychSecretKeyV1 {
    let mut bytes = [0_u8; RISTRETTO_COMPRESSED_POINT_BYTES];
    bytes[..core::mem::size_of::<u64>()].copy_from_slice(&scalar.to_le_bytes());
    let Ok(secret) = TariTriptychSecretKeyV1::from_canonical_bytes(bytes) else {
        panic!("representative scalar must create a canonical nonzero secret key");
    };

    secret
}

fn fixture_public_key(scalar: u64) -> [u8; RISTRETTO_COMPRESSED_POINT_BYTES] {
    let Some(index) = scalar
        .checked_sub(1)
        .and_then(|value| usize::try_from(value).ok())
    else {
        panic!("representative scalar must map to the deterministic key fixture");
    };
    let Some(start) = index.checked_mul(RISTRETTO_COMPRESSED_POINT_BYTES) else {
        panic!("deterministic key fixture offset must not overflow");
    };
    let Some(end) = start.checked_add(RISTRETTO_COMPRESSED_POINT_BYTES) else {
        panic!("deterministic key fixture end offset must not overflow");
    };
    let Some(bytes) = FIXTURE_KEYS.get(start..end) else {
        panic!("representative scalar must be present in the deterministic key fixture");
    };
    let Ok(public_key) = <[u8; RISTRETTO_COMPRESSED_POINT_BYTES]>::try_from(bytes) else {
        panic!("deterministic key fixture chunk must be exactly one compressed point");
    };

    public_key
}

fn canonical_package_bytes(package: &BallotPackageV1) -> Vec<u8> {
    let Ok(bytes) = package.to_canonical_cbor() else {
        panic!("representative real Triptych package must encode canonically");
    };

    bytes
}

fn package_bytes_with_proof(package: &BallotPackageV1, proof: Vec<u8>) -> Vec<u8> {
    canonical_package_from_parts(
        package.manifest_hash(),
        package.proof_suite_id(),
        proof,
        package.payload().clone(),
    )
}

fn canonical_package_from_parts(
    manifest_hash: ManifestHash,
    proof_suite_id: &str,
    proof: Vec<u8>,
    payload: ApprovalBallotPayload,
) -> Vec<u8> {
    canonical_package_bytes(&canonical_package_from_parts_value(
        manifest_hash,
        proof_suite_id,
        proof,
        payload,
    ))
}

fn canonical_package_from_parts_value(
    manifest_hash: ManifestHash,
    proof_suite_id: &str,
    proof: Vec<u8>,
    payload: ApprovalBallotPayload,
) -> BallotPackageV1 {
    let Ok(package) = BallotPackageV1::new(BallotPackageV1Input {
        protocol_version: PROTOCOL_VERSION_V1,
        manifest_hash,
        proof_suite_id: proof_suite_id.to_owned(),
        proof,
        payload,
    }) else {
        panic!("mutated package transport must remain structurally constructible");
    };

    package
}

fn raw_canonical_package(package: &BallotPackageV1, proof: &[u8]) -> Vec<u8> {
    let Ok(payload_bytes) = package.payload().to_canonical_cbor() else {
        panic!("representative payload must encode for raw framing mutation");
    };
    let mut writer = CanonicalCborWriter::new();
    assert!(writer.write_array_len(5).is_ok());
    writer.write_unsigned(u64::from(package.protocol_version()));
    assert!(
        writer
            .write_byte_string(package.manifest_hash().as_bytes())
            .is_ok()
    );
    assert!(writer.write_text_string(package.proof_suite_id()).is_ok());
    assert!(writer.write_byte_string(&payload_bytes).is_ok());
    assert!(writer.write_byte_string(proof).is_ok());

    writer.into_bytes()
}

fn envelope_with_inner(envelope: &TariTriptychProofEnvelopeV1, inner: Vec<u8>) -> Vec<u8> {
    envelope_with_parts(*envelope.linking_tag_bytes(), inner)
}

fn raw_envelope_with_inner(envelope: &TariTriptychProofEnvelopeV1, inner: Vec<u8>) -> Vec<u8> {
    let mut bytes = envelope.to_bytes()[..TARI_TRIPTYCH_PROOF_ENVELOPE_HEADER_BYTES].to_vec();
    bytes.extend_from_slice(&inner);

    bytes
}

fn envelope_with_parts(
    linking_tag: [u8; RISTRETTO_COMPRESSED_POINT_BYTES],
    inner: Vec<u8>,
) -> Vec<u8> {
    let Ok(envelope) = TariTriptychProofEnvelopeV1::new(linking_tag, inner) else {
        panic!("mutated proof envelope must remain structurally constructible");
    };

    envelope.to_bytes()
}

fn manifest_hash(manifest: &ElectionManifestV1) -> ManifestHash {
    let provider = Blake3HashProviderV1;
    let Ok(hash) = manifest.canonical_hash(&provider) else {
        panic!("representative manifest hash must be derivable");
    };

    hash
}

fn open_lifecycle(manifest: &ElectionManifestV1) -> ElectionLifecycleV1 {
    let mut lifecycle = ElectionLifecycleV1::new();

    assert!(
        lifecycle
            .freeze(manifest_hash(manifest), manifest.registry_commitment())
            .is_ok()
    );
    assert!(lifecycle.open().is_ok());

    lifecycle
}

fn ingest(
    fixture: &Fixture,
    lifecycle: &ElectionLifecycleV1,
    ledger: &mut BallotAcceptanceLedger,
    package_bytes: &[u8],
) -> Result<(), ProtocolError> {
    let provider = Blake3HashProviderV1;

    ingest_approval_ballot_package_v1(
        package_bytes,
        &fixture.manifest,
        &fixture.candidates,
        lifecycle,
        ledger,
        &provider,
        &fixture.verifier,
    )
}

fn canonical_package_layout(bytes: &[u8]) -> Option<PackageLayout> {
    if bytes.first().copied()? != 0x85 {
        return None;
    }
    let mut offset = 1_usize;
    offset = cbor_item_end(bytes, offset)?;
    let (_, manifest) = cbor_string_layout(bytes, offset, 2)?;
    offset = manifest.data_end;
    let (_, suite) = cbor_string_layout(bytes, offset, 3)?;
    offset = suite.data_end;
    let (_, payload) = cbor_string_layout(bytes, offset, 2)?;
    offset = payload.data_end;
    let (_, proof) = cbor_string_layout(bytes, offset, 2)?;
    if proof.data_end != bytes.len() {
        return None;
    }

    Some(PackageLayout { payload, proof })
}

fn cbor_item_end(bytes: &[u8], offset: usize) -> Option<usize> {
    let (major, length, header_len) = cbor_header(bytes, offset)?;
    let content_start = offset.checked_add(header_len)?;

    match major {
        0 => Some(content_start),
        2 | 3 => content_start.checked_add(length),
        _ => None,
    }
}

fn cbor_string_layout(
    bytes: &[u8],
    offset: usize,
    expected_major: u8,
) -> Option<(usize, CborStringLayout)> {
    let (major, length, header_len) = cbor_header(bytes, offset)?;
    if major != expected_major {
        return None;
    }
    let data_start = offset.checked_add(header_len)?;
    let data_end = data_start.checked_add(length)?;
    bytes.get(data_start..data_end)?;

    Some((
        data_end,
        CborStringLayout {
            header_start: offset,
            data_start,
            data_end,
        },
    ))
}

fn cbor_header(bytes: &[u8], offset: usize) -> Option<(u8, usize, usize)> {
    let initial = *bytes.get(offset)?;
    let major = initial >> 5;
    let additional = initial & 0x1f;
    let value = match additional {
        0..=23 => u64::from(additional),
        24 => u64::from(*bytes.get(offset.checked_add(1)?)?),
        25 => {
            let array =
                <[u8; 2]>::try_from(bytes.get(offset.checked_add(1)?..offset.checked_add(3)?)?)
                    .ok()?;

            u64::from(u16::from_be_bytes(array))
        }
        26 => {
            let array =
                <[u8; 4]>::try_from(bytes.get(offset.checked_add(1)?..offset.checked_add(5)?)?)
                    .ok()?;

            u64::from(u32::from_be_bytes(array))
        }
        27 => {
            let array =
                <[u8; 8]>::try_from(bytes.get(offset.checked_add(1)?..offset.checked_add(9)?)?)
                    .ok()?;

            u64::from_be_bytes(array)
        }
        _ => return None,
    };
    let header_len = match additional {
        0..=23 => 1,
        24 => 2,
        25 => 3,
        26 => 5,
        27 => 9,
        _ => return None,
    };
    let length = usize::try_from(value).ok()?;

    Some((major, length, header_len))
}

fn replace_proof_length(
    package_bytes: &[u8],
    proof: CborStringLayout,
    replacement_length: usize,
) -> Option<Vec<u8>> {
    let header = cbor_string_header_with_width(2, replacement_length, proof.header_len())?;
    let mut bytes = package_bytes.to_vec();
    bytes
        .get_mut(proof.header_start..proof.data_start)?
        .copy_from_slice(&header);

    Some(bytes)
}

fn cbor_string_header_with_width(major: u8, length: usize, width: usize) -> Option<Vec<u8>> {
    let length = u64::try_from(length).ok()?;

    match width {
        1 if length <= 23 => Some(vec![(major << 5) | u8::try_from(length).ok()?]),
        2 if (24..=u64::from(u8::MAX)).contains(&length) => {
            Some(vec![(major << 5) | 24, u8::try_from(length).ok()?])
        }
        3 if (u64::from(u8::MAX) + 1..=u64::from(u16::MAX)).contains(&length) => {
            let Ok(length) = u16::try_from(length) else {
                return None;
            };
            let mut header = vec![(major << 5) | 25];
            header.extend_from_slice(&length.to_be_bytes());
            Some(header)
        }
        5 if (u64::from(u16::MAX) + 1..=u64::from(u32::MAX)).contains(&length) => {
            let Ok(length) = u32::try_from(length) else {
                return None;
            };
            let mut header = vec![(major << 5) | 26];
            header.extend_from_slice(&length.to_be_bytes());
            Some(header)
        }
        9 if length > u64::from(u32::MAX) => {
            let mut header = vec![(major << 5) | 27];
            header.extend_from_slice(&length.to_be_bytes());
            Some(header)
        }
        _ => None,
    }
}

fn representative_positions(member_count: usize) -> Vec<usize> {
    let positions = [
        0_usize,
        member_count / 4,
        member_count / 2,
        member_count.saturating_mul(3) / 4,
        member_count.saturating_sub(1),
    ];
    let mut unique = Vec::new();
    for position in positions {
        if !unique.contains(&position) {
            unique.push(position);
        }
    }

    unique
}

fn assert_length_and_prefix(expected: &mut Option<usize>, observed: usize, label: &str) {
    match expected {
        Some(value) => assert_eq!(
            *value, observed,
            "{label} length must not vary by signer position for equal ballot content",
        ),
        None => *expected = Some(observed),
    }
}

struct TimingSummary {
    position: usize,
    samples: usize,
    minimum_us: f64,
    median_us: f64,
    mean_us: f64,
    maximum_us: f64,
    standard_deviation_us: f64,
}

fn timing_summary(position: usize, samples: &[Duration]) -> TimingSummary {
    assert!(!samples.is_empty());
    let mut microseconds = samples
        .iter()
        .map(|duration| duration.as_secs_f64() * 1_000_000.0)
        .collect::<Vec<_>>();
    microseconds.sort_by(f64::total_cmp);
    let sample_count = microseconds.len();
    let mean_us = microseconds.iter().sum::<f64>() / sample_count as f64;
    let median_us = (microseconds[(sample_count - 1) / 2] + microseconds[sample_count / 2]) / 2.0;
    let variance = microseconds
        .iter()
        .map(|value| {
            let difference = *value - mean_us;

            difference * difference
        })
        .sum::<f64>()
        / sample_count as f64;

    TimingSummary {
        position,
        samples: sample_count,
        minimum_us: microseconds[0],
        median_us,
        mean_us,
        maximum_us: microseconds[sample_count - 1],
        standard_deviation_us: variance.sqrt(),
    }
}

fn ratio_of_extremes(values: impl Iterator<Item = f64>) -> f64 {
    let mut minimum = f64::INFINITY;
    let mut maximum = 0.0_f64;
    for value in values {
        minimum = minimum.min(value);
        maximum = maximum.max(value);
    }
    if minimum == 0.0 {
        f64::INFINITY
    } else {
        maximum / minimum
    }
}

fn deterministically_shuffle_positions(
    positions: &[usize],
    rng: &mut DeterministicBytes,
) -> Vec<usize> {
    let mut order = positions.to_vec();
    for index in (1..order.len()).rev() {
        let swap_with = rng.bounded_usize(index + 1);
        order.swap(index, swap_with);
    }

    order
}

struct DeterministicBytes {
    state: u64,
}

impl DeterministicBytes {
    const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state ^= self.state << 13;
        self.state ^= self.state >> 7;
        self.state ^= self.state << 17;

        self.state
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        (0..length)
            .map(|_| self.next_u64().to_le_bytes()[0])
            .collect()
    }

    fn bounded_usize(&mut self, upper_exclusive: usize) -> usize {
        assert!(upper_exclusive > 0);
        let Ok(value) = usize::try_from(self.next_u64()) else {
            return 0;
        };

        value % upper_exclusive
    }
}
