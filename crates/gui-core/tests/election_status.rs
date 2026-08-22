//! Distributed election-lifecycle propagation tests (authenticated status).
//!
//! These tests model two INDEPENDENT state domains â€” an organizer session
//! (Computer A) and a voter session (Computer B) built from the same frozen
//! artifacts but with separate memory, lifecycle, and durable knowledge. The
//! ONLY bridge between them is the signed election-status statement: no shared
//! process, no implicit session object, and no silent lifecycle inference.

mod common;

use ed25519_dalek::SigningKey;
use tari_cc_private_ballot_ballot::ElectionLifecycleStateV1;
use tari_cc_private_ballot_gui_core::{
    AppliedElectionStatusV1, AuthenticatedElectionStatusStatementV1,
    ElectionStatusErrorV1, ElectionStatusKnowledgeV1, GuiElectionArtifactsV1,
    GuiElectionSessionV1, PersistedElectionStatusRecordV1, TransportAuthorityRootSetV1,
    TransportAuthorityRootV1, load_persisted_election_status_v1,
    manifest_hash_lower_hex_v1, persist_election_status_record_v1,
    verify_and_apply_election_status_statement_v1,
};

use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use common::{
    TestDir, approval_limits, artifacts, artifacts_with_revision, candidate_set,
    manifest_with, registry_bytes, triptych_package_bytes,
};

const ROOT_KEY_ID: &str = "ceremony-root-1";

/// The organizer's signing identity (Computer A). Mirrors how the controlled-
/// test intake signs descriptors/receipts with one release-pinned root key.
struct AuthorityFixture {
    signing_key: SigningKey,
    roots: TransportAuthorityRootSetV1,
    root_public_key: [u8; 32],
}

fn authority() -> AuthorityFixture {
    let signing_key = SigningKey::from_bytes(&[0x5A; 32]);
    let root_public_key = signing_key.verifying_key().to_bytes();
    AuthorityFixture {
        roots: TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
            key_id: ROOT_KEY_ID.to_owned(),
            public_key: root_public_key,
        }),
        signing_key,
        root_public_key,
    }
}

/// Signs a statement for the canonical fixture election exactly as an
/// organizer export command would.
fn signed_for(
    authority_fixture: &AuthorityFixture,
    artifacts_fixture: &GuiElectionArtifactsV1,
    state: ElectionLifecycleStateV1,
    generation: u64,
) -> Vec<u8> {
    match AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
        artifacts_fixture
            .manifest()
            .election_id()
            .as_bytes()
            .to_vec(),
        artifacts_fixture.manifest_hash(),
        artifacts_fixture.registry_commitment(),
        state,
        generation,
        ROOT_KEY_ID.to_owned(),
        &authority_fixture.signing_key,
    ) {
        Ok(statement) => statement
            .to_canonical_cbor()
            .expect("statement must encode"),
        Err(error) => panic!("fixture statement must sign: {error}"),
    }
}

fn apply(
    voter_session: &mut GuiElectionSessionV1,
    knowledge: &mut ElectionStatusKnowledgeV1,
    authority_fixture: &AuthorityFixture,
    bytes: &[u8],
) -> Result<AppliedElectionStatusV1, ElectionStatusErrorV1> {
    verify_and_apply_election_status_statement_v1(bytes, &authority_fixture.roots, knowledge, voter_session)
}

#[test]
fn organizer_open_does_not_reach_an_independent_voter_without_evidence() {
    // Computer A: its own authoritative organizer session.
    let mut organizer = GuiElectionSessionV1::new(artifacts()).expect("organizer session");
    // Computer B: a fully independent voter session over imported artifacts.
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let voter_knowledge = ElectionStatusKnowledgeV1::new();

    organizer.open().expect("organizer opens voting locally");

    // Without authenticated evidence the voter MUST stay frozen (fail closed);
    // real ballot intake is refused while frozen.
    assert_eq!(
        voter.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Frozen
    );
    let package = triptych_package_bytes(0, &[b"candidate-a".as_slice()]);
    let error = voter
        .intake_ballot_package_bytes(&package)
        .expect_err("frozen election must refuse ballots");
    assert_eq!(error.code(), "ELECTION_NOT_OPEN");

    // And applying nothing changes nothing.
    assert_eq!(
        voter_knowledge.accepted_generation(),
        None
    );
}

#[test]
fn authenticated_open_evidence_advances_only_the_voter_view() {
    let authority_fixture = authority();
    let mut organizer = GuiElectionSessionV1::new(artifacts()).expect("organizer session");
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    organizer.open().expect("organizer opens");
    let open_statement = signed_for(&authority_fixture, organizer.artifacts(), ElectionLifecycleStateV1::Open, 2);

    let applied =
        apply(&mut voter, &mut knowledge, &authority_fixture, &open_statement).expect("OPEN applies");
    assert!(applied.advanced);
    assert_eq!(applied.effective_state, ElectionLifecycleStateV1::Open);
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Open);

    // The frozen election identity is untouched by lifecycle evidence.
    assert_eq!(
        voter.artifacts().manifest_hash(),
        artifacts().manifest_hash()
    );
    assert_eq!(
        voter.artifacts().registry_commitment(),
        artifacts().registry_commitment()
    );

    // With every other gate satisfied the same ballot now flows through real
    // protocol intake on the independent voter machine.
    let package = triptych_package_bytes(0, &[b"candidate-a".as_slice()]);
    let outcome = voter
        .intake_ballot_package_bytes(&package)
        .expect("opened election must accept a valid ballot");
    assert!(outcome.accepted);
    assert_eq!(outcome.code, "ACCEPTED");

    // The organizer session is a separate domain; it never observed the
    // voter-side application.
    assert_eq!(
        organizer.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Open
    );
}

#[test]
fn full_lifecycle_walk_frozen_to_finalized_via_authenticated_evidence() {
    let authority_fixture = authority();
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    for (state, generation) in [
        (ElectionLifecycleStateV1::Open, 2),
        (ElectionLifecycleStateV1::Closed, 3),
        (ElectionLifecycleStateV1::Verified, 4),
        (ElectionLifecycleStateV1::Finalized, 5),
    ] {
        let bytes = signed_for(&authority_fixture, voter.artifacts(), state, generation);
        let applied = apply(&mut voter, &mut knowledge, &authority_fixture, &bytes)
            .unwrap_or_else(|error| panic!("{state:?} must apply: {error}"));
        assert_eq!(applied.effective_state, state);
        assert_eq!(voter.lifecycle_state_v1(), state);
    }
    assert_eq!(knowledge.accepted_generation(), Some(5));
    assert_eq!(
        knowledge.accepted_state(),
        Some(ElectionLifecycleStateV1::Finalized)
    );
}

#[test]
fn wrong_election_statement_is_rejected_and_changes_nothing() {
    let authority_fixture = authority();
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    // A REAL second election: same machinery, different election id.
    let other_manifest = manifest_with(
        b"a-completely-different-election",
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        approval_limits(),
    );
    let other_artifacts = GuiElectionArtifactsV1::from_bytes(
        &other_manifest.to_canonical_cbor().expect("encode"),
        &registry_bytes(),
        &candidate_set_bytes(),
    )
    .expect("other election artifacts");
    assert_ne!(
        other_artifacts.manifest_hash(),
        voter.artifacts().manifest_hash()
    );

    let bytes = signed_for(&authority_fixture, &other_artifacts, ElectionLifecycleStateV1::Open, 2);
    let error = apply(&mut voter, &mut knowledge, &authority_fixture, &bytes)
        .expect_err("another election's OPEN must be refused");
    assert_eq!(error, ElectionStatusErrorV1::WrongElection);
    assert_eq!(
        voter.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Frozen
    );
    assert_eq!(knowledge.accepted_generation(), None);
}

#[test]
fn substituted_manifest_statement_is_rejected() {
    let authority_fixture = authority();
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    // SAME election id but a different governance revision produces a
    // different frozen manifest hash: a stale/substituted manifest artifact
    // must not unlock this election.
    let revised = artifacts_with_revision("gui-core-test-revision-SUBSTITUTED");
    assert_eq!(
        revised.manifest().election_id(),
        voter.artifacts().manifest().election_id()
    );
    assert_ne!(
        revised.manifest_hash(),
        voter.artifacts().manifest_hash()
    );

    let bytes = signed_for(&authority_fixture, &revised, ElectionLifecycleStateV1::Open, 2);
    let error = apply(&mut voter, &mut knowledge, &authority_fixture, &bytes)
        .expect_err("substituted manifest statement must be refused");
    assert_eq!(error, ElectionStatusErrorV1::WrongManifestHash);
    assert_eq!(
        voter.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Frozen
    );
}

#[test]
fn wrong_ballot_office_identity_is_rejected() {
    let authority_fixture = authority();
    let impostor = SigningKey::from_bytes(&[0xA5; 32]);
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    // Signed by an impostor key under the trusted root id: invalid signature.
    let impostor_statement = match AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
        voter.artifacts().manifest().election_id().as_bytes().to_vec(),
        voter.artifacts().manifest_hash(),
        voter.artifacts().registry_commitment(),
        ElectionLifecycleStateV1::Open,
        2,
        ROOT_KEY_ID.to_owned(),
        &impostor,
    ) {
        Ok(statement) => statement.to_canonical_cbor().expect("encode"),
        Err(error) => panic!("impostor statement must construct: {error}"),
    };
    let error = apply(&mut voter, &mut knowledge, &authority_fixture, &impostor_statement)
        .expect_err("impostor signature must fail");
    assert_eq!(error, ElectionStatusErrorV1::InvalidSignature);
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Frozen);

    // Signed by the right key but claiming an unknown root id: untrusted.
    let unknown_root = match AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony(
        voter.artifacts().manifest().election_id().as_bytes().to_vec(),
        voter.artifacts().manifest_hash(),
        voter.artifacts().registry_commitment(),
        ElectionLifecycleStateV1::Open,
        2,
        "unknown-office-root".to_owned(),
        &authority_fixture.signing_key,
    ) {
        Ok(statement) => statement.to_canonical_cbor().expect("encode"),
        Err(error) => panic!("unknown-root statement must construct: {error}"),
    };
    let error = apply(&mut voter, &mut knowledge, &authority_fixture, &unknown_root)
        .expect_err("unknown root id must fail closed");
    assert_eq!(error, ElectionStatusErrorV1::UntrustedRoot);
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Frozen);
}

#[test]
fn malformed_and_unauthenticated_statements_change_nothing() {
    let authority_fixture = authority();
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    let good = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Open, 2);
    let mut corrupted_signature = good.clone();
    let last = corrupted_signature.len() - 1;
    corrupted_signature[last] ^= 0x01;

    for hostile in [
        &b"not cbor at all"[..],
        &good[..good.len() - 3],
        corrupted_signature.as_slice(),
    ] {
        let result = apply(&mut voter, &mut knowledge, &authority_fixture, hostile);
        assert!(result.is_err(), "hostile input must be refused");
        assert_eq!(
            voter.lifecycle_state_v1(),
            ElectionLifecycleStateV1::Frozen,
            "session must remain untouched"
        );
        assert_eq!(knowledge.accepted_generation(), None);
    }
}

#[test]
fn closed_then_stale_open_rollback_is_rejected() {
    let authority_fixture = authority();
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    let open = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Open, 2);
    let closed = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Closed, 3);
    apply(&mut voter, &mut knowledge, &authority_fixture, &open).expect("OPEN applies");
    apply(&mut voter, &mut knowledge, &authority_fixture, &closed).expect("CLOSED applies");
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Closed);

    // Replaying the OLD OPEN artifact must fail closed twice over: it is both
    // a lower rank (rollback) and a stale generation. The session stays CLOSED
    // and knowledge stays at generation 3.
    let error = apply(&mut voter, &mut knowledge, &authority_fixture, &open)
        .expect_err("old OPEN after CLOSED must be rejected");
    assert_eq!(error, ElectionStatusErrorV1::LifecycleRollbackRejected);
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Closed);
    assert_eq!(knowledge.accepted_generation(), Some(3));
}

#[test]
fn equal_generation_conflict_fails_closed() {
    let authority_fixture = authority();
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    let open_gen2 = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Open, 2);
    let closed_gen2 = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Closed, 2);
    apply(&mut voter, &mut knowledge, &authority_fixture, &open_gen2).expect("first applies");

    let error = apply(&mut voter, &mut knowledge, &authority_fixture, &closed_gen2)
        .expect_err("equal-generation conflict must fail closed");
    assert_eq!(error, ElectionStatusErrorV1::ConflictingGeneration);
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Open);
    assert_eq!(knowledge.accepted_state(), Some(ElectionLifecycleStateV1::Open));
}

#[test]
fn restart_reconstructs_monotonic_knowledge_from_the_persisted_record() {
    let authority_fixture = authority();
    let dir = TestDir::new("status-restart");
    let manifest_hex = manifest_hash_lower_hex_v1(artifacts().manifest_hash());

    // --- Before restart: accept CLOSED at generation 7 and persist it. ---
    let closed = signed_for(&authority_fixture, &artifacts(), ElectionLifecycleStateV1::Closed, 7);
    {
        let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
        let mut knowledge = ElectionStatusKnowledgeV1::new();
        apply(&mut voter, &mut knowledge, &authority_fixture, &closed).expect("CLOSED applies");
        persist_election_status_record_v1(
            dir.path(),
            &manifest_hex,
            &PersistedElectionStatusRecordV1 {
                root_key_id: ROOT_KEY_ID.to_owned(),
                root_public_key: authority_fixture.root_public_key,
                statement: AuthenticatedElectionStatusStatementV1::from_canonical_cbor(&closed)
                    .expect("round trip"),
            },
        )
        .expect("record persists");
    }

    // --- Restart: brand-new session + knowledge rebuilt ONLY from disk. ---
    let mut restarted_voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let record = load_persisted_election_status_v1(
        dir.path(),
        &manifest_hex,
        restarted_voter.artifacts().manifest().election_id().as_bytes(),
        restarted_voter.artifacts().manifest_hash(),
        restarted_voter.artifacts().registry_commitment(),
    )
    .expect("record reloads offline")
    .expect("record exists after restart");
    let mut restarted_knowledge = ElectionStatusKnowledgeV1::from_accepted(
        record.statement.state(),
        record.statement.generation(),
    );
    // Re-applying the persisted statement restores the lifecycle view without
    // any bundle or network.
    let anchor_roots = TransportAuthorityRootSetV1::new(TransportAuthorityRootV1::Pinned {
        key_id: record.root_key_id.clone(),
        public_key: record.root_public_key,
    });
    let applied = verify_and_apply_election_status_statement_v1(
        &closed,
        &anchor_roots,
        &mut restarted_knowledge,
        &mut restarted_voter,
    )
    .expect("persisted statement re-applies idempotently");
    // The FRESH session advances FROZEN -> ... -> CLOSED again from durable
    // evidence alone (no bundle, no network); knowledge stays at generation 7.
    assert!(applied.advanced);
    assert_eq!(
        restarted_knowledge.accepted_generation(),
        Some(7)
    );
    assert_eq!(
        restarted_voter.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Closed
    );

    // Monotonic knowledge survived: the pre-restart OPEN artifact (generation
    // 2) can no longer roll the CLOSED session open. Rank protection fires
    // first here (OPEN < CLOSED); the pure-knowledge staleness path is covered
    // by the unit tests.
    let stale_open = signed_for(&authority_fixture, &artifacts(), ElectionLifecycleStateV1::Open, 2);
    let error = verify_and_apply_election_status_statement_v1(
        &stale_open,
        &anchor_roots,
        &mut restarted_knowledge,
        &mut restarted_voter,
    )
    .expect_err("pre-restart OPEN must stay rejected after restart");
    assert_eq!(error, ElectionStatusErrorV1::LifecycleRollbackRejected);
    assert_eq!(
        restarted_voter.lifecycle_state_v1(),
        ElectionLifecycleStateV1::Closed
    );
}

#[test]
fn failed_application_leaves_session_and_knowledge_untouched() {
    let authority_fixture = authority();
    let mut voter = GuiElectionSessionV1::new(artifacts()).expect("voter session");
    let mut knowledge = ElectionStatusKnowledgeV1::new();

    // Advance to OPEN, then CLOSED, so later failures have real state to
    // protect.
    let open = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Open, 2);
    apply(&mut voter, &mut knowledge, &authority_fixture, &open).expect("OPEN applies");
    let close = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Closed, 3);
    apply(&mut voter, &mut knowledge, &authority_fixture, &close).expect("CLOSED applies");

    // A rollback attempt must fail without touching session or knowledge.
    let rollback = signed_for(&authority_fixture, voter.artifacts(), ElectionLifecycleStateV1::Open, 4);
    let error = apply(&mut voter, &mut knowledge, &authority_fixture, &rollback)
        .expect_err("OPEN after CLOSED must fail");
    assert_eq!(error, ElectionStatusErrorV1::LifecycleRollbackRejected);
    assert_eq!(voter.lifecycle_state_v1(), ElectionLifecycleStateV1::Closed);
    assert_eq!(knowledge.accepted_generation(), Some(3));
    assert_eq!(knowledge.accepted_state(), Some(ElectionLifecycleStateV1::Closed));
}

fn candidate_set_bytes() -> Vec<u8> {
    candidate_set().to_canonical_cbor().expect("candidates encode")
}

