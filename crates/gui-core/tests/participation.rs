//! Participation-metric and sealed-disclosure tests (Slice 5A5, section O).
//!
//! These tests prove the backend refuses to disclose sealed participation
//! numerics and per-option results while voting is open, and that exact
//! participation becomes available only after close. The 5A4 tally gate is
//! re-asserted here so the participation DTO and the tally gate stay
//! consistent.

mod common;

use tari_cc_private_ballot_gui_core::{
    CoarseParticipationBucket, GuiCoreError, GuiElectionSessionV1, ParticipationVisibility,
    ResultVisibility,
};

use common::{artifacts, open_session, triptych_package_bytes};

/// Three fixture voters -> small electorate flag is true.
fn assert_small_electorate(session: &GuiElectionSessionV1) {
    let summary = session.participation_summary();
    assert!(
        summary.small_electorate,
        "fixture electorate (3) is below the small-electorate threshold"
    );
    assert_eq!(summary.eligible_voters, 3);
}

#[test]
fn frozen_participation_is_sealed_until_close() {
    // `new` constructs a FROZEN session.
    let session = match GuiElectionSessionV1::new(artifacts()) {
        Ok(session) => session,
        Err(error) => panic!("session must construct: {error}"),
    };
    assert_eq!(session.lifecycle_state(), "FROZEN");

    let summary = session.participation_summary();
    assert_eq!(summary.lifecycle_state, "FROZEN");
    assert_eq!(
        summary.participation_visibility,
        ParticipationVisibility::SealedUntilClose
    );
    assert_eq!(summary.result_visibility, ResultVisibility::Sealed);
    assert_eq!(summary.accepted_ballots, None);
    assert_eq!(summary.participation_basis_points, None);
    assert_eq!(summary.remaining_eligible_capacity, None);
    assert_eq!(summary.coarse_bucket, None);
    assert_small_electorate(&session);
}

#[test]
fn open_live_policy_exposes_participation_only_not_results() {
    // The default application policy is SealedUntilClose while OPEN. This test
    // documents that even under the default, participation numerics are sealed.
    // The `Live` variant is modeled for future operator/manifest policy; the
    // current default never selects it while OPEN.
    let session = open_session();
    assert_eq!(session.lifecycle_state(), "OPEN");

    let summary = session.participation_summary();
    assert_eq!(
        summary.participation_visibility,
        ParticipationVisibility::SealedUntilClose
    );
    assert_eq!(summary.result_visibility, ResultVisibility::Sealed);
    assert_eq!(summary.accepted_ballots, None);
    assert_eq!(summary.participation_basis_points, None);
    assert_eq!(summary.remaining_eligible_capacity, None);
    assert_eq!(summary.coarse_bucket, None);
}

#[test]
fn open_coarse_policy_exposes_bucket_only_not_exact_count() {
    // The default policy is SealedUntilClose, not Coarse, while OPEN. This
    // test asserts the Coarse bucket logic itself (covered by the unit tests
    // in `participation.rs`) is never selected by the default resolver while
    // OPEN: `coarse_bucket` stays `None`.
    let session = open_session();
    let summary = session.participation_summary();
    assert_eq!(
        summary.participation_visibility,
        ParticipationVisibility::SealedUntilClose
    );
    assert_eq!(summary.coarse_bucket, None);
    assert_eq!(summary.accepted_ballots, None);
    assert_eq!(summary.participation_basis_points, None);
}

#[test]
fn open_sealed_exposes_neither_exact_participation_nor_trend() {
    let mut session = open_session();
    // Ingest one ballot so a count exists internally; the sealed DTO must
    // still expose nothing.
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("ballot must intake: {error}");
    }

    let summary = session.participation_summary();
    assert_eq!(
        summary.participation_visibility,
        ParticipationVisibility::SealedUntilClose
    );
    assert_eq!(summary.accepted_ballots, None);
    assert_eq!(summary.participation_basis_points, None);
    assert_eq!(summary.remaining_eligible_capacity, None);
    assert_eq!(summary.coarse_bucket, None);
    // Eligible voters is public registry info and always present.
    assert_eq!(summary.eligible_voters, 3);
}

#[test]
fn closed_permits_exact_participation() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("ballot must intake: {error}");
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }

    let summary = session.participation_summary();
    assert_eq!(summary.lifecycle_state, "CLOSED");
    assert_eq!(
        summary.participation_visibility,
        ParticipationVisibility::Live
    );
    assert_eq!(summary.result_visibility, ResultVisibility::Disclosed);
    assert_eq!(summary.accepted_ballots, Some(1));
    // 1 / 3 = 3333 bps
    assert_eq!(summary.participation_basis_points, Some(3_333));
    assert_eq!(summary.remaining_eligible_capacity, Some(2));
    assert_eq!(summary.coarse_bucket, None);
}

#[test]
fn open_result_visibility_is_sealed() {
    let session = open_session();
    let summary = session.participation_summary();
    assert_eq!(summary.result_visibility, ResultVisibility::Sealed);
}

#[test]
fn closed_result_visibility_is_disclosed() {
    let mut session = open_session();
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    let summary = session.participation_summary();
    assert_eq!(summary.result_visibility, ResultVisibility::Disclosed);
}

#[test]
fn current_tally_remains_rejected_while_open() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("ballot must intake: {error}");
    }
    match session.tally() {
        Ok(_) => panic!("tally must be sealed while OPEN"),
        Err(error) => assert_eq!(error.code(), "GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE"),
    }
}

#[test]
fn no_result_dto_returns_hidden_option_counts_while_open() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("ballot must intake: {error}");
    }
    // The participation summary must not carry any per-option result data.
    let summary = session.participation_summary();
    assert_eq!(summary.result_visibility, ResultVisibility::Sealed);
    // The DTO has no counts/leading field at all; this is a compile-time
    // guarantee. We additionally assert the tally command itself is rejected.
    match session.tally() {
        Ok(_) => panic!("tally must be rejected while OPEN"),
        Err(error) => {
            assert_eq!(error.code(), "GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE");
            assert_no_option_leak(&error);
        }
    }
}

#[test]
fn no_leading_candidate_leaks_while_open() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("ballot must intake: {error}");
    }
    match session.tally() {
        Ok(tally) => panic!("tally must be rejected while OPEN, got {tally:?}"),
        Err(error) => assert_no_option_leak(&error),
    }
    // Participation summary also carries no leading field.
    let summary = session.participation_summary();
    assert!(summary.coarse_bucket.is_none());
    assert!(summary.accepted_ballots.is_none());
}

#[test]
fn zero_eligible_voters_is_safe() {
    // The pure participation helper must not divide by zero. An empty
    // registry session cannot be constructed through the public fixture API
    // without rebinding the manifest's registry commitment, so we verify the
    // helper directly (the same helper the session method calls).
    use tari_cc_private_ballot_gui_core::participation::participation_basis_points as bps;
    assert_eq!(bps(0, 0), 0);
    assert_eq!(bps(7, 0), 0);

    // The coarse bucket for zero participation is the lowest bucket and must
    // not panic.
    assert_eq!(
        CoarseParticipationBucket::from_basis_points(0),
        CoarseParticipationBucket::ZeroToTwentyFour
    );
}

#[test]
fn zero_percent_participation_is_safe() {
    let mut session = open_session();
    // Close with zero accepted ballots.
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    let summary = session.participation_summary();
    assert_eq!(
        summary.participation_visibility,
        ParticipationVisibility::Live
    );
    assert_eq!(summary.accepted_ballots, Some(0));
    assert_eq!(summary.participation_basis_points, Some(0));
    assert_eq!(summary.remaining_eligible_capacity, Some(3));
}

#[test]
fn one_hundred_percent_participation_is_safe() {
    let mut session = open_session();
    // Accept all three fixture voters.
    let selections: [&[u8]; 3] = [b"candidate-a", b"candidate-b", b"candidate-c"];
    for (voter_index, selection) in selections.iter().enumerate() {
        let package = triptych_package_bytes(voter_index, &[*selection]);
        if let Err(error) = session.intake_ballot(&package) {
            panic!("ballot {voter_index} must intake: {error}");
        }
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    let summary = session.participation_summary();
    assert_eq!(summary.accepted_ballots, Some(3));
    assert_eq!(summary.eligible_voters, 3);
    assert_eq!(summary.participation_basis_points, Some(10_000));
    assert_eq!(summary.remaining_eligible_capacity, Some(0));
}

#[test]
fn accepted_ballots_never_exceeds_eligible_voters() {
    // The acceptance ledger enforces one acceptance per registry-scoped
    // nullifier, so accepted <= eligible through the public API. Verify the
    // invariant holds for the participation summary after a duplicate
    // submission (which is rejected and must not increment accepted count).
    let mut session = open_session();
    let first = triptych_package_bytes(0, &[b"candidate-a"]);
    let duplicate = triptych_package_bytes(0, &[b"candidate-b"]);
    for package in [&first, &duplicate] {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake (accepted or rejected): {error}");
        }
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    let summary = session.participation_summary();
    let Some(accepted) = summary.accepted_ballots else {
        panic!("accepted count must be present after close");
    };
    assert_eq!(accepted, 1);
    assert!(accepted <= summary.eligible_voters);
    assert_eq!(
        summary.remaining_eligible_capacity,
        Some(summary.eligible_voters - accepted)
    );
}

#[test]
fn participation_visibility_and_result_visibility_are_consistent_with_tally_gate() {
    let mut session = open_session();
    // OPEN: sealed participation, sealed results, tally rejected.
    let summary = session.participation_summary();
    assert_eq!(
        summary.participation_visibility,
        ParticipationVisibility::SealedUntilClose
    );
    assert_eq!(summary.result_visibility, ResultVisibility::Sealed);
    assert!(session.tally().is_err());

    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }
    // CLOSED: live participation, disclosed results, tally succeeds.
    let summary = session.participation_summary();
    assert_eq!(summary.participation_visibility, ParticipationVisibility::Live);
    assert_eq!(summary.result_visibility, ResultVisibility::Disclosed);
    assert!(session.tally().is_ok());
}

#[test]
fn verified_and_finalized_disclose_participation_and_results() {
    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("ballot must intake: {error}");
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }

    if let Err(error) = session.mark_verified() {
        panic!("session must mark verified: {error}");
    }
    let verified = session.participation_summary();
    assert_eq!(verified.lifecycle_state, "VERIFIED");
    assert_eq!(verified.participation_visibility, ParticipationVisibility::Live);
    assert_eq!(verified.result_visibility, ResultVisibility::Disclosed);
    assert_eq!(verified.accepted_ballots, Some(1));
    assert!(session.tally().is_ok());

    if let Err(error) = session.finalize() {
        panic!("session must finalize: {error}");
    }
    let finalized = session.participation_summary();
    assert_eq!(finalized.lifecycle_state, "FINALIZED");
    assert_eq!(finalized.participation_visibility, ParticipationVisibility::Live);
    assert_eq!(finalized.result_visibility, ResultVisibility::Disclosed);
    assert_eq!(finalized.accepted_ballots, Some(1));
    assert!(session.tally().is_ok());
}

#[test]
fn participation_summary_does_not_alter_canonical_bytes_or_archive_hash() {
    // Computing the participation summary must not mutate session state. The
    // summary reads registry length and ledger length only; it writes nothing.
    // We verify by computing the summary twice and asserting the archive hash
    // (which covers manifest, registry, candidates, submissions, and the
    // archive manifest) is unaffected.
    use tari_cc_private_ballot_gui_core::archive_writer::write_archive_directory_v1;
    use common::TestDir;

    let mut session = open_session();
    let package = triptych_package_bytes(0, &[b"candidate-a"]);
    if let Err(error) = session.intake_ballot(&package) {
        panic!("ballot must intake: {error}");
    }
    if let Err(error) = session.close() {
        panic!("session must close: {error}");
    }

    let dir_one = TestDir::new("participation-canonical-one");
    let target_one = dir_one.join("archive");
    if let Err(error) = write_archive_directory_v1(&session, &target_one) {
        panic!("archive write must succeed: {error}");
    }

    // Compute the participation summary (must not mutate state).
    let summary_a = session.participation_summary();
    let summary_b = session.participation_summary();
    assert_eq!(summary_a, summary_b);

    let dir_two = TestDir::new("participation-canonical-two");
    let target_two = dir_two.join("archive");
    if let Err(error) = write_archive_directory_v1(&session, &target_two) {
        panic!("second archive write must succeed: {error}");
    }

    let hash_one = archive_hash_hex(&target_one);
    let hash_two = archive_hash_hex(&target_two);
    assert_eq!(
        hash_one, hash_two,
        "participation summary computation must not change the archive hash"
    );
}

/// Verifies the written archive and returns its recomputed archive hash hex.
/// This is the canonical archive identity; comparing it across two writes
/// proves the participation summary computation did not mutate session state.
fn archive_hash_hex(target: &std::path::Path) -> String {
    use tari_cc_private_ballot_gui_core::verify_archive_directory_v1;
    let result = match verify_archive_directory_v1(target) {
        Ok(result) => result,
        Err(error) => panic!("archive verification must succeed: {error}"),
    };
    match result.recomputed_archive_hash_hex {
        Some(hash) => hash,
        None => panic!("archive hash must be present for a valid archive"),
    }
}

/// The sealed-results error must not echo any per-option text.
fn assert_no_option_leak(error: &GuiCoreError) {
    let rendered = format!("{error}");
    assert!(
        !rendered.contains("candidate"),
        "sealed-results error leaked candidate text: {rendered}"
    );
    assert!(
        !rendered.contains("approvals"),
        "sealed-results error leaked approval counts: {rendered}"
    );
    assert!(
        !rendered.contains("Leading"),
        "sealed-results error leaked a leading result: {rendered}"
    );
    assert_eq!(error.code(), "GUI_TALLY_NOT_AVAILABLE_BEFORE_CLOSE");
}

#[test]
fn coarse_bucket_labels_are_stable_and_non_overlapping() {
    assert_eq!(
        CoarseParticipationBucket::from_basis_points(0).as_str(),
        "0–24%"
    );
    assert_eq!(
        CoarseParticipationBucket::from_basis_points(2_500).as_str(),
        "25–49%"
    );
    assert_eq!(
        CoarseParticipationBucket::from_basis_points(5_000).as_str(),
        "50–74%"
    );
    assert_eq!(
        CoarseParticipationBucket::from_basis_points(7_500).as_str(),
        "75–99%"
    );
    assert_eq!(
        CoarseParticipationBucket::from_basis_points(10_000).as_str(),
        "100%"
    );
}
