//! Manifest-bound approval-package ingestion for normal application use.

use tari_cc_private_ballot_ballot::{
    BallotPackageEnvelopeV1, CandidateSet, ElectionLifecycleV1, ElectionManifestV1,
};
use tari_cc_private_ballot_crypto::ProofVerifierV1;
use tari_cc_private_ballot_protocol::{HashProvider, ProtocolError, ValidationCode};

use crate::{BallotAcceptanceLedger, ProductionProofSuitePolicyV1, verify_approval_proof};

/// Decodes, binds, verifies, and accepts one canonical approval-ballot package.
///
/// This is the normal application boundary. It decodes package transport fields,
/// checks their binding and the production proof-suite policy, validates the
/// authoritative candidate commitment, then decodes the payload using the
/// manifest's approval limits before proof verification and ledger acceptance.
pub fn ingest_approval_ballot_package_v1<H, V>(
    package_bytes: &[u8],
    manifest: &ElectionManifestV1,
    candidates: &CandidateSet,
    lifecycle: &ElectionLifecycleV1,
    ledger: &mut BallotAcceptanceLedger,
    hash_provider: &H,
    proof_verifier: &V,
) -> Result<(), ProtocolError>
where
    H: HashProvider,
    V: ProofVerifierV1,
{
    let envelope = BallotPackageEnvelopeV1::from_canonical_cbor(package_bytes)?;
    let manifest_hash = manifest.canonical_hash(hash_provider)?;

    envelope.validate_manifest_binding(manifest_hash, manifest.proof_suite_id())?;
    ProductionProofSuitePolicyV1::new().validate(manifest.proof_suite_id())?;

    if candidates.canonical_commitment(hash_provider)? != manifest.candidate_set_commitment() {
        return Err(ProtocolError::new(
            ValidationCode::CandidateSetCommitmentMismatch,
            "authoritative candidate set does not match the election manifest",
        ));
    }

    let package = envelope.into_ballot_package(candidates, manifest.approval_limits())?;
    let verified = verify_approval_proof(
        manifest,
        package.payload(),
        package.proof(),
        hash_provider,
        proof_verifier,
    )?;

    ledger.accept_verified(lifecycle, verified)
}

#[cfg(test)]
mod tests {
    use super::ingest_approval_ballot_package_v1;
    use crate::BallotAcceptanceLedger;
    use tari_cc_private_ballot_ballot::{
        ApprovalBallotPayload, ApprovalLimits, BallotConfidentialityV1, BallotKindV1,
        BallotPackageV1, BallotPackageV1Input, CandidateDefinition, CandidateId, CandidateSet,
        ElectionId, ElectionLifecycleV1, ElectionManifestV1, ElectionManifestV1Input,
    };
    use tari_cc_private_ballot_crypto::{
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1, TariTriptychPrototypeVerifierV1,
    };
    use tari_cc_private_ballot_protocol::{
        Blake3HashProviderV1, CandidateSetCommitment, ManifestHash, PROTOCOL_VERSION_V1,
        RegistryCommitment, TEST_ONLY_SUITE_ID, ValidationCode,
    };

    const RISTRETTO_BASEPOINT_BYTES: [u8; 32] = [
        0xe2, 0xf2, 0xae, 0x0a, 0x6a, 0xbc, 0x4e, 0x71, 0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x00, 0x51,
        0x5f, 0x58, 0xe3, 0x0b, 0x6a, 0xa5, 0x82, 0xdd, 0x8d, 0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d,
        0x2d, 0x76,
    ];

    #[test]
    fn candidate_context_and_package_binding_fail_before_proof_or_ledger_mutation() {
        let provider = Blake3HashProviderV1;
        let candidates = candidates();
        let manifest = manifest(&candidates, TARI_TRIPTYCH_PROOF_SUITE_ID_V1, limits());
        let verifier = verifier(&manifest);

        let mismatched_manifest = manifest_with_candidate_commitment(
            &candidates,
            TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
            limits(),
            CandidateSetCommitment::new([9_u8; 32]),
        );
        let mismatched_package = package(
            &mismatched_manifest,
            payload(&candidates, vec![candidate_id(b"candidate-a")], limits()),
            Vec::new(),
        );
        let mut mismatched_ledger = BallotAcceptanceLedger::new();
        let mismatched_lifecycle = open_lifecycle(&mismatched_manifest, &provider);

        assert!(matches!(
            ingest_approval_ballot_package_v1(
                &package_bytes(&mismatched_package),
                &mismatched_manifest,
                &candidates,
                &mismatched_lifecycle,
                &mut mismatched_ledger,
                &provider,
                &verifier,
            ),
            Err(error) if error.code() == ValidationCode::CandidateSetCommitmentMismatch
        ));
        assert!(mismatched_ledger.is_empty());

        let wrong_manifest_package = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash: ManifestHash::new([7_u8; 32]),
            proof_suite_id: manifest.proof_suite_id().to_owned(),
            proof: Vec::new(),
            payload: payload(&candidates, vec![candidate_id(b"candidate-a")], limits()),
        });
        let Ok(wrong_manifest_package) = wrong_manifest_package else {
            panic!("wrong-manifest package fixture must be structurally valid");
        };
        let mut wrong_manifest_ledger = BallotAcceptanceLedger::new();
        let lifecycle = open_lifecycle(&manifest, &provider);

        assert!(matches!(
            ingest_approval_ballot_package_v1(
                &package_bytes(&wrong_manifest_package),
                &manifest,
                &candidates,
                &lifecycle,
                &mut wrong_manifest_ledger,
                &provider,
                &verifier,
            ),
            Err(error) if error.code() == ValidationCode::WrongManifestHash
        ));
        assert!(wrong_manifest_ledger.is_empty());

        let wrong_suite_package = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash: manifest_hash(&manifest, &provider),
            proof_suite_id: "OTHER_SUITE".to_owned(),
            proof: Vec::new(),
            payload: payload(&candidates, vec![candidate_id(b"candidate-a")], limits()),
        });
        let Ok(wrong_suite_package) = wrong_suite_package else {
            panic!("wrong-suite package fixture must be structurally valid");
        };
        let mut wrong_suite_ledger = BallotAcceptanceLedger::new();

        assert!(matches!(
            ingest_approval_ballot_package_v1(
                &package_bytes(&wrong_suite_package),
                &manifest,
                &candidates,
                &lifecycle,
                &mut wrong_suite_ledger,
                &provider,
                &verifier,
            ),
            Err(error) if error.code() == ValidationCode::UnsupportedProofSuite
        ));
        assert!(wrong_suite_ledger.is_empty());
    }

    #[test]
    fn manifest_limits_and_candidate_membership_are_enforced_before_proof() {
        let provider = Blake3HashProviderV1;
        let candidates = candidates();
        let manifest = manifest(&candidates, TARI_TRIPTYCH_PROOF_SUITE_ID_V1, limits());
        let verifier = verifier(&manifest);
        let lifecycle = open_lifecycle(&manifest, &provider);

        let broad_candidates = candidates_with_extra_member();
        let unknown_payload = payload(
            &broad_candidates,
            vec![candidate_id(b"candidate-c")],
            limits(),
        );
        let too_many_payload = payload(
            &candidates,
            vec![candidate_id(b"candidate-a"), candidate_id(b"candidate-b")],
            wider_limits(),
        );
        let abstention_payload = payload(&candidates, Vec::new(), abstention_limits());

        for (payload, expected_code) in [
            (unknown_payload, ValidationCode::UnknownCandidateId),
            (too_many_payload, ValidationCode::SelectionCountOutOfRange),
            (abstention_payload, ValidationCode::SelectionCountOutOfRange),
        ] {
            let package = package(&manifest, payload, Vec::new());
            let mut ledger = BallotAcceptanceLedger::new();

            assert!(matches!(
                ingest_approval_ballot_package_v1(
                    &package_bytes(&package),
                    &manifest,
                    &candidates,
                    &lifecycle,
                    &mut ledger,
                    &provider,
                    &verifier,
                ),
                Err(error) if error.code() == expected_code
            ));
            assert!(ledger.is_empty());
        }
    }

    #[test]
    fn production_ingestion_rejects_the_test_only_suite_before_proof_or_ledger_mutation() {
        let provider = Blake3HashProviderV1;
        let candidates = candidates();
        let manifest = manifest(&candidates, TEST_ONLY_SUITE_ID, limits());
        let package = package(
            &manifest,
            payload(&candidates, vec![candidate_id(b"candidate-a")], limits()),
            Vec::new(),
        );
        let verifier = verifier(&manifest);
        let lifecycle = open_lifecycle(&manifest, &provider);
        let mut ledger = BallotAcceptanceLedger::new();

        assert!(matches!(
            ingest_approval_ballot_package_v1(
                &package_bytes(&package),
                &manifest,
                &candidates,
                &lifecycle,
                &mut ledger,
                &provider,
                &verifier,
            ),
            Err(error) if error.code() == ValidationCode::UnsupportedProofSuite
        ));
        assert!(ledger.is_empty());
    }

    fn verifier(manifest: &ElectionManifestV1) -> TariTriptychPrototypeVerifierV1 {
        let result = TariTriptychPrototypeVerifierV1::new(
            manifest.registry_commitment(),
            vec![RISTRETTO_BASEPOINT_BYTES],
        );
        let Ok(verifier) = result else {
            panic!("real proof verifier fixture must be valid");
        };

        verifier
    }

    fn manifest(
        candidates: &CandidateSet,
        proof_suite_id: &str,
        approval_limits: ApprovalLimits,
    ) -> ElectionManifestV1 {
        let provider = Blake3HashProviderV1;
        let Ok(candidate_set_commitment) = candidates.canonical_commitment(&provider) else {
            panic!("candidate commitment fixture must be derivable");
        };

        manifest_with_candidate_commitment(
            candidates,
            proof_suite_id,
            approval_limits,
            candidate_set_commitment,
        )
    }

    fn manifest_with_candidate_commitment(
        _candidates: &CandidateSet,
        proof_suite_id: &str,
        approval_limits: ApprovalLimits,
        candidate_set_commitment: CandidateSetCommitment,
    ) -> ElectionManifestV1 {
        let Ok(election_id) = ElectionId::new(b"bound-ingestion-tests".to_vec()) else {
            panic!("test election identifier must be valid");
        };
        let result = ElectionManifestV1::new(ElectionManifestV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            election_id,
            ballot_kind: BallotKindV1::NonBindingApprovalPilot,
            ballot_confidentiality: BallotConfidentialityV1::Public,
            registry_commitment: RegistryCommitment::new([1_u8; 32]),
            candidate_set_commitment,
            proof_suite_id: proof_suite_id.to_owned(),
            approval_limits,
            governance_source_revision: "bound-ingestion-tests".to_owned(),
        });
        let Ok(manifest) = result else {
            panic!("test manifest must be valid");
        };

        manifest
    }

    fn package(
        manifest: &ElectionManifestV1,
        payload: ApprovalBallotPayload,
        proof: Vec<u8>,
    ) -> BallotPackageV1 {
        let provider = Blake3HashProviderV1;
        let result = BallotPackageV1::new(BallotPackageV1Input {
            protocol_version: PROTOCOL_VERSION_V1,
            manifest_hash: manifest_hash(manifest, &provider),
            proof_suite_id: manifest.proof_suite_id().to_owned(),
            proof,
            payload,
        });
        let Ok(package) = result else {
            panic!("test package must be structurally valid");
        };

        package
    }

    fn package_bytes(package: &BallotPackageV1) -> Vec<u8> {
        let result = package.to_canonical_cbor();
        let Ok(bytes) = result else {
            panic!("test package must encode canonically");
        };

        bytes
    }

    fn manifest_hash(
        manifest: &ElectionManifestV1,
        provider: &Blake3HashProviderV1,
    ) -> ManifestHash {
        let result = manifest.canonical_hash(provider);
        let Ok(hash) = result else {
            panic!("test manifest hash must be derivable");
        };

        hash
    }

    fn open_lifecycle(
        manifest: &ElectionManifestV1,
        provider: &Blake3HashProviderV1,
    ) -> ElectionLifecycleV1 {
        let mut lifecycle = ElectionLifecycleV1::new();

        assert!(
            lifecycle
                .freeze(
                    manifest_hash(manifest, provider),
                    manifest.registry_commitment()
                )
                .is_ok()
        );
        assert!(lifecycle.open().is_ok());

        lifecycle
    }

    fn candidates() -> CandidateSet {
        candidate_set(vec![b"candidate-a", b"candidate-b"])
    }

    fn candidates_with_extra_member() -> CandidateSet {
        candidate_set(vec![b"candidate-a", b"candidate-b", b"candidate-c"])
    }

    fn candidate_set(ids: Vec<&[u8]>) -> CandidateSet {
        let definitions: Vec<CandidateDefinition> = ids
            .into_iter()
            .map(|id| {
                let result = CandidateDefinition::new(
                    candidate_id(id),
                    String::from_utf8_lossy(id).into_owned(),
                );
                let Ok(definition) = result else {
                    panic!("test candidate definition must be valid");
                };

                definition
            })
            .collect();
        let result = CandidateSet::new(definitions);
        let Ok(candidates) = result else {
            panic!("test candidate set must be valid");
        };

        candidates
    }

    fn candidate_id(bytes: &[u8]) -> CandidateId {
        let result = CandidateId::new(bytes.to_vec());
        let Ok(id) = result else {
            panic!("test candidate identifier must be valid");
        };

        id
    }

    fn payload(
        candidates: &CandidateSet,
        selections: Vec<CandidateId>,
        approval_limits: ApprovalLimits,
    ) -> ApprovalBallotPayload {
        let result = ApprovalBallotPayload::new(selections, candidates, approval_limits);
        let Ok(payload) = result else {
            panic!("test payload fixture must be valid under its supplied context");
        };

        payload
    }

    fn limits() -> ApprovalLimits {
        let result = ApprovalLimits::new(1, 1, false);
        let Ok(limits) = result else {
            panic!("test approval limits must be valid");
        };

        limits
    }

    fn wider_limits() -> ApprovalLimits {
        let result = ApprovalLimits::new(1, 2, false);
        let Ok(limits) = result else {
            panic!("wider test approval limits must be valid");
        };

        limits
    }

    fn abstention_limits() -> ApprovalLimits {
        let result = ApprovalLimits::new(0, 1, true);
        let Ok(limits) = result else {
            panic!("abstention test approval limits must be valid");
        };

        limits
    }
}
