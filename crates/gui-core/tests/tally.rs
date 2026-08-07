//! Tally facade tests (required cases 16-19).

mod common;

use tari_cc_private_ballot_ballot::ApprovalLimits;
use tari_cc_private_ballot_crypto::TARI_TRIPTYCH_PROOF_SUITE_ID_V1;
use tari_cc_private_ballot_gui_core::{
    GuiElectionArtifactsV1, GuiElectionSessionV1, GuiLeadingResultV1,
};
use tari_cc_private_ballot_tally::{ApprovalTally, LeadingResult};

use common::{
    approval_limits, candidate_bytes, candidate_set, manifest_with, open_session,
    package_bytes_for, registry_bytes, triptych_package_bytes,
};

fn abstention_session() -> GuiElectionSessionV1 {
    let limits = match ApprovalLimits::new(0, 2, true) {
        Ok(limits) => limits,
        Err(_) => panic!("abstention limits must be valid"),
    };
    let manifest = manifest_with(
        b"gui-core-test-election",
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        limits,
    );
    let encoded_manifest = match manifest.to_canonical_cbor() {
        Ok(bytes) => bytes,
        Err(_) => panic!("manifest must encode"),
    };
    let artifacts = match GuiElectionArtifactsV1::from_bytes(
        &encoded_manifest,
        &registry_bytes(),
        &candidate_bytes(),
    ) {
        Ok(artifacts) => artifacts,
        Err(_) => panic!("abstention artifacts must load"),
    };
    let mut session = match GuiElectionSessionV1::new(artifacts) {
        Ok(session) => session,
        Err(_) => panic!("session must construct"),
    };
    if let Err(error) = session.open() {
        panic!("session must open: {error}");
    }
    session
}

#[test]
fn no_approvals_is_reported_without_inventing_a_winner() {
    let mut session = abstention_session();
    // One abstention: a valid ballot with an empty selection.
    let manifest = manifest_with(
        b"gui-core-test-election",
        TARI_TRIPTYCH_PROOF_SUITE_ID_V1,
        match ApprovalLimits::new(0, 2, true) {
            Ok(limits) => limits,
            Err(_) => panic!("limits must be valid"),
        },
    );
    let abstention = package_bytes_for(&manifest, 0, &[]);
    let result = match session.intake_ballot(&abstention) {
        Ok(result) => result,
        Err(error) => panic!("abstention ballot must intake: {error}"),
    };
    assert!(result.accepted);

    let tally = match session.tally() {
        Ok(tally) => tally,
        Err(error) => panic!("tally must compute: {error}"),
    };
    assert_eq!(tally.accepted_ballots, 1);
    assert_eq!(tally.abstentions, 1);
    assert_eq!(tally.leading, GuiLeadingResultV1::NoApprovals);
    assert!(tally.counts.iter().all(|count| count.approvals == 0));
}

#[test]
fn single_leader_is_reported() {
    let mut session = open_session();
    for (voter_index, selections) in [
        (0_usize, vec![b"candidate-a".as_slice()]),
        (1_usize, vec![b"candidate-a".as_slice()]),
        (2_usize, vec![b"candidate-b".as_slice()]),
    ] {
        let package = triptych_package_bytes(voter_index, &selections);
        if let Err(error) = session.intake_ballot(&package) {
            panic!("ballot must intake: {error}");
        }
    }

    let tally = match session.tally() {
        Ok(tally) => tally,
        Err(_) => panic!("tally must compute"),
    };
    assert_eq!(tally.accepted_ballots, 3);
    let GuiLeadingResultV1::SingleLeader {
        candidate_id_hex: _,
        ref display_name,
        approvals,
    } = tally.leading
    else {
        panic!("expected a single leader, got {:?}", tally.leading);
    };
    assert_eq!(display_name, "Candidate A");
    assert_eq!(approvals, 2);
}

#[test]
fn unresolved_top_count_is_reported_as_a_tie() {
    let mut session = open_session();
    let first = triptych_package_bytes(0, &[b"candidate-a"]);
    let second = triptych_package_bytes(1, &[b"candidate-b"]);
    for package in [first, second] {
        if let Err(error) = session.intake_ballot(&package) {
            panic!("ballot must intake: {error}");
        }
    }

    let tally = match session.tally() {
        Ok(tally) => tally,
        Err(_) => panic!("tally must compute"),
    };
    let GuiLeadingResultV1::Tie {
        ref candidate_ids_hex,
        approvals,
    } = tally.leading
    else {
        panic!("expected a tie, got {:?}", tally.leading);
    };
    assert_eq!(candidate_ids_hex.len(), 2);
    assert_eq!(approvals, 1);
}

#[test]
fn facade_tally_equals_direct_backend_tally() {
    let mut session = open_session();
    let packages = vec![
        triptych_package_bytes(0, &[b"candidate-a", b"candidate-c"]),
        triptych_package_bytes(1, &[b"candidate-a"]),
        triptych_package_bytes(0, &[b"candidate-b"]), // duplicate, not counted
        triptych_package_bytes(2, &[b"candidate-b"]),
    ];
    for package in &packages {
        if let Err(error) = session.intake_ballot(package) {
            panic!("ballot must intake: {error}");
        }
    }

    let facade = match session.tally() {
        Ok(tally) => tally,
        Err(_) => panic!("facade tally must compute"),
    };
    let direct = match session.direct_tally() {
        Ok(tally) => tally,
        Err(_) => panic!("direct tally must compute"),
    };

    // The facade summary must equal the rendering of the raw backend tally.
    let rendered = tari_cc_private_ballot_gui_core::tally::summarize_tally(
        &direct,
        session.artifacts().candidates(),
    );
    assert_eq!(facade, rendered);

    // The raw backend tally must equal an independent replay's tally.
    let mut replay = open_session();
    for package in &packages {
        if let Err(error) = replay.intake_ballot(package) {
            panic!("replay ballot must intake: {error}");
        }
    }
    match replay.direct_tally() {
        Ok(replayed) => assert_eq!(replayed, direct),
        Err(_) => panic!("replay tally must compute"),
    }

    // The ledger-based facade tally counts only accepted ballots: a naive
    // tally over every submitted package payload includes the duplicate and
    // must differ.
    let naive_payloads: Vec<_> = packages
        .iter()
        .filter_map(|package| {
            let envelope =
                tari_cc_private_ballot_ballot::BallotPackageEnvelopeV1::from_canonical_cbor(
                    package,
                )
                .ok()?;
            envelope
                .into_ballot_package(&candidate_set(), approval_limits())
                .ok()
                .map(|package| package.payload().clone())
        })
        .collect();
    let naive = ApprovalTally::from_ballots(&candidate_set(), naive_payloads.iter());
    match naive {
        Ok(naive) => {
            assert_eq!(naive.accepted_ballots(), 4);
            assert_eq!(direct.accepted_ballots(), 3);
        }
        Err(_) => panic!("naive tally must compute"),
    }

    match direct.leading_result() {
        LeadingResult::SingleLeader { approvals, .. } => assert_eq!(approvals, 2),
        other => panic!("expected single leader, got {other:?}"),
    }
}
