// Lightweight pure-logic unit tests for the frontend (Slice 5A4).
//
// No React test framework is installed (by design — ADR-0007 keeps the
// frontend dependency surface minimal and the offline package cache does not
// include a runner). These tests run under Node's built-in test runner with
// TypeScript type stripping (Node 24+). They cover the pure, framework-free
// presentation and error-mapping logic shared by every screen. Component-level
// render tests (the empty state, loaded cards, option tables, etc.) are
// documented in the slice review as requiring a later frontend-test harness.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { describeError } from "../src/api/errorDisplay.ts";
import { RequestGenerationGate } from "../src/requestGeneration.ts";
import {
  approvalRuleText,
  presentationFor,
  BALLOT_PRESENTATIONS,
} from "../src/ballot/ballotTypes.ts";
import {
  anchorDeploymentLockBlockers,
  anchorPrepareBlockers,
  anchorPublishBlockers,
  approvalBps,
  describeLeadingOutcome,
  approvalLabel,
  canWriteFinalArchive,
  canShowTally,
  coarseBucketLabel,
  formatPercent,
  isMultiApprovalBallot,
  participationAccessibleText,
  participationIsDisclosed,
  participationVisibilityLabel,
  resultsAreSealed,
  resultVisibilityLabel,
} from "../src/lifecycle.ts";
import {
  canProceedAfterCredential,
  credentialEligibilityTone,
  credentialStatusText,
  noSecretFieldNames,
  publicKeyDisplay,
  WALLET_SEED_WARNING,
} from "../src/voterCredential.ts";

const sampleSummary = {
  election_id_hex: "ab",
  election_id_text: null,
  lifecycle_state: "FROZEN",
  manifest_schema_version: 2,
  manifest_hash_hex: "cd",
  registry_commitment_hex: "ef",
  candidate_set_commitment_hex: "01",
  voter_count: 3,
  proof_suite_id: "tari-triptych-prototype-v1",
  ballot_kind: "NON_BINDING_APPROVAL_PILOT",
  ballot_confidentiality: "PUBLIC",
  approval_min: 1,
  approval_max: 2,
  abstention_allowed: false,
  governance_source_revision: "rev-1",
  proposal_question: "Should the sample proposal pass?",
  candidates: [],
};

describe("errorDisplay", () => {
  it("maps a binding-mismatch error to a concise title, safe message, and stable code", () => {
    const display = describeError({
      code: "GUI_REGISTRY_COMMITMENT_MISMATCH",
      category: "BINDING_MISMATCH",
      context: "registry",
      message: "the voter registry commitment does not match the election manifest",
    });
    assert.equal(display.title, "Election files do not match");
    assert.equal(
      display.message,
      "the voter registry commitment does not match the election manifest",
    );
    assert.equal(display.code, "GUI_REGISTRY_COMMITMENT_MISMATCH");
    assert.equal(display.category, "BINDING_MISMATCH");
    assert.equal(display.context, "registry");
  });

  it("maps a file-not-found error to the file-I/O title", () => {
    const display = describeError({
      code: "GUI_FILE_NOT_FOUND",
      category: "FILE_IO",
      context: "manifest",
      message: "a required file was not found",
    });
    assert.equal(display.title, "File could not be read");
    assert.equal(display.code, "GUI_FILE_NOT_FOUND");
  });

  it("falls back to a generic title for an unknown category", () => {
    const display = describeError({
      code: "GUI_UNEXPECTED_ERROR",
      category: "UNKNOWN_CATEGORY",
      context: null,
      message: "something happened",
    });
    assert.equal(display.title, "Something went wrong");
  });
});

describe("ballotTypes presentation", () => {
  it("uses the Candidates label for a candidate election", () => {
    assert.equal(BALLOT_PRESENTATIONS.candidate.optionSetNoun, "Candidates");
  });

  it("uses the Choices label for a governance proposal", () => {
    assert.equal(BALLOT_PRESENTATIONS["governance-proposal"].optionSetNoun, "Choices");
  });

  it("uses the Responses label for a ballot measure", () => {
    assert.equal(BALLOT_PRESENTATIONS["ballot-measure"].optionSetNoun, "Responses");
  });

  it("defaults to a neutral Ballot options label for a loaded election with no discriminator", () => {
    const presentation = presentationFor(sampleSummary);
    assert.equal(presentation.optionSetNoun, "Ballot options");
  });

  it("honors an explicitly requested candidate presentation", () => {
    const presentation = presentationFor(sampleSummary, "candidate");
    assert.equal(presentation.optionSetNoun, "Candidates");
  });
});

describe("approvalRuleText", () => {
  it("describes a range-selection rule and disallows abstention", () => {
    const text = approvalRuleText(sampleSummary);
    assert.match(text, /between 1 and 2 options/);
    assert.match(text, /Abstaining is not permitted/);
  });

  it("describes an exact-selection rule when min equals max", () => {
    const text = approvalRuleText({ ...sampleSummary, approval_min: 2, approval_max: 2 });
    assert.match(text, /exactly 2 options/);
  });

  it("describes abstention when permitted with a zero minimum", () => {
    const text = approvalRuleText({ ...sampleSummary, approval_min: 0, abstention_allowed: true });
    assert.match(text, /up to 2 options/);
    assert.match(text, /Abstaining .* is permitted/);
  });
});

describe("lifecycle tally gate", () => {
  it("seals tally results while the election is FROZEN", () => {
    assert.equal(canShowTally("FROZEN"), false);
    assert.equal(resultsAreSealed("FROZEN"), true);
  });

  it("seals tally results while the election is OPEN", () => {
    assert.equal(canShowTally("OPEN"), false);
    assert.equal(resultsAreSealed("OPEN"), true);
  });

  it("seals tally results while the election is DRAFT", () => {
    assert.equal(canShowTally("DRAFT"), false);
  });

  it("discloses tally results after voting is CLOSED", () => {
    assert.equal(canShowTally("CLOSED"), true);
    assert.equal(resultsAreSealed("CLOSED"), false);
  });

  it("discloses tally results after VERIFIED", () => {
    assert.equal(canShowTally("VERIFIED"), true);
  });

  it("discloses tally results after FINALIZED", () => {
    assert.equal(canShowTally("FINALIZED"), true);
  });

  it("treats null and unknown lifecycle states as sealed", () => {
    assert.equal(canShowTally(null), false);
    assert.equal(canShowTally(undefined), false);
    assert.equal(canShowTally("UNKNOWN"), false);
    assert.equal(resultsAreSealed(null), true);
  });
});

describe("participation percentage formatting", () => {
  it("formats basis points as a one-decimal percentage (truncated)", () => {
    assert.equal(formatPercent(6520), "65.2%");
    assert.equal(formatPercent(3333), "33.3%");
  });

  it("formats whole percentages without a decimal", () => {
    assert.equal(formatPercent(0), "0%");
    assert.equal(formatPercent(5000), "50%");
    assert.equal(formatPercent(10000), "100%");
  });

  it("treats null and undefined as 0%", () => {
    assert.equal(formatPercent(null), "0%");
    assert.equal(formatPercent(undefined), "0%");
  });

  it("clamps and truncates out-of-range values", () => {
    assert.equal(formatPercent(-1), "0%");
    assert.equal(formatPercent(99999), "100%");
    assert.equal(formatPercent(6520.9), "65.2%");
  });
});

describe("coarse participation buckets", () => {
  it("maps each bucket to a stable display label", () => {
    assert.equal(coarseBucketLabel("ZeroToTwentyFour"), "0–24%");
    assert.equal(coarseBucketLabel("TwentyFiveToFortyNine"), "25–49%");
    assert.equal(coarseBucketLabel("FiftyToSeventyFour"), "50–74%");
    assert.equal(coarseBucketLabel("SeventyFiveToNinetyNine"), "75–99%");
    assert.equal(coarseBucketLabel("OneHundred"), "100%");
  });

  it("renders an em dash for null/unknown buckets", () => {
    assert.equal(coarseBucketLabel(null), "—");
    assert.equal(coarseBucketLabel(undefined), "—");
  });
});

describe("participation sealed presentation", () => {
  const sealedSummary = {
    lifecycle_state: "OPEN",
    participation_visibility: "SEALED_UNTIL_CLOSE" as const,
    result_visibility: "SEALED" as const,
    eligible_voters: 250,
    accepted_ballots: null,
    participation_basis_points: null,
    remaining_eligible_capacity: null,
    coarse_bucket: null,
    small_electorate: false,
  };

  it("is not disclosed while sealed", () => {
    assert.equal(participationIsDisclosed(sealedSummary), false);
  });

  it("produces a sealed accessible text without leaking counts", () => {
    const text = participationAccessibleText(sealedSummary);
    assert.match(text, /sealed until voting closes/);
    assert.doesNotMatch(text, /\d+ of \d+ eligible voters/);
  });

  it("labels the visibility policy", () => {
    assert.equal(
      participationVisibilityLabel("SEALED_UNTIL_CLOSE"),
      "Sealed until close",
    );
    assert.equal(participationVisibilityLabel("LIVE"), "Live");
    assert.equal(participationVisibilityLabel("COARSE"), "Coarse");
  });

  it("labels the result visibility", () => {
    assert.equal(resultVisibilityLabel("SEALED"), "Sealed");
    assert.equal(resultVisibilityLabel("DISCLOSED"), "Disclosed");
  });
});

describe("participation disclosed presentation", () => {
  const disclosedSummary = {
    lifecycle_state: "CLOSED",
    participation_visibility: "LIVE" as const,
    result_visibility: "DISCLOSED" as const,
    eligible_voters: 250,
    accepted_ballots: 163,
    participation_basis_points: 6520,
    remaining_eligible_capacity: 87,
    coarse_bucket: null,
    small_electorate: false,
  };

  it("is disclosed after close", () => {
    assert.equal(participationIsDisclosed(disclosedSummary), true);
  });

  it("produces an accessible text with exact counts", () => {
    const text = participationAccessibleText(disclosedSummary);
    assert.match(text, /Participation 65\.2%, 163 of 250 eligible voters/);
  });
});

describe("coarse participation presentation", () => {
  const coarseSummary = {
    lifecycle_state: "OPEN",
    participation_visibility: "COARSE" as const,
    result_visibility: "SEALED" as const,
    eligible_voters: 250,
    accepted_ballots: null,
    participation_basis_points: null,
    remaining_eligible_capacity: null,
    coarse_bucket: "TwentyFiveToFortyNine" as const,
    small_electorate: false,
  };

  it("is not disclosed under coarse policy (exact counts hidden)", () => {
    assert.equal(participationIsDisclosed(coarseSummary), false);
  });

  it("produces a bucket-only accessible text without exact counts", () => {
    const text = participationAccessibleText(coarseSummary);
    assert.match(text, /Participation band: 25–49%/);
    assert.doesNotMatch(text, /\d+ of \d+ eligible voters/);
  });
});

describe("multi-approval result labeling", () => {
  it("computes approval basis points of accepted ballots", () => {
    assert.equal(approvalBps(61, 100), 6100);
    assert.equal(approvalBps(1, 3), 3333);
  });

  it("returns 0 when there are no accepted ballots", () => {
    assert.equal(approvalBps(5, 0), 0);
  });

  it("saturates at 10000 when approvals reach accepted ballots", () => {
    assert.equal(approvalBps(100, 100), 10000);
    assert.equal(approvalBps(101, 100), 10000);
  });

  it("labels approvals as a share of accepted ballots, not the vote", () => {
    const label = approvalLabel("option", 61, 100);
    assert.match(label, /Approved by 61% of accepted ballots/);
    assert.doesNotMatch(label, /of the vote/);
  });

  it("classifies v1 approval ballots as multi-approval (no pie assumption)", () => {
    const tally = {
      accepted_ballots: 3,
      abstentions: 0,
      counts: [
        { candidate_id_hex: "a", candidate_id_text: null, display_name: "A", approvals: 2 },
        { candidate_id_hex: "b", candidate_id_text: null, display_name: "B", approvals: 2 },
      ],
      leading: { Tie: { candidate_ids_hex: ["a", "b"], approvals: 2 } },
    };
    assert.equal(isMultiApprovalBallot(tally), true);
  });

  it("multi-approval bars may each exceed a single-choice share", () => {
    // 3 accepted ballots, two options each approved by 2 voters: 66.6% each.
    // Bars sum to 133.2%, which is correct for multi-approval and would be
    // misleading in a pie chart.
    assert.equal(approvalBps(2, 3), 6666);
    const label = approvalLabel("option", 2, 3);
    assert.match(label, /66\.6% of accepted ballots/);
  });
});

describe("tally leading outcome (zero-ballot ErrorBoundary regression)", () => {
  // `NoApprovals` is a serde unit variant: it deserializes to the BARE STRING
  // "NoApprovals", not an object. The old code did `"NoApprovals" in
  // tally.leading`, which throws `TypeError: Cannot use 'in' operator ... in a
  // string` during render and tripped the Manage Election ErrorBoundary the
  // moment an organizer computed the tally with zero accepted ballots.
  it("describes the string NoApprovals variant without throwing", () => {
    const tally = {
      accepted_ballots: 0,
      abstentions: 0,
      counts: [],
      leading: "NoApprovals",
    } as unknown as Parameters<typeof describeLeadingOutcome>[0];
    assert.doesNotThrow(() => describeLeadingOutcome(tally));
    assert.match(describeLeadingOutcome(tally), /No approvals recorded/);
  });

  it("describes the object SingleLeader variant", () => {
    const tally = {
      accepted_ballots: 3,
      abstentions: 0,
      counts: [],
      leading: { SingleLeader: { candidate_id_hex: "a", display_name: "Alice", approvals: 2 } },
    } as unknown as Parameters<typeof describeLeadingOutcome>[0];
    assert.match(describeLeadingOutcome(tally), /Leading: Alice \(2 approvals\)/);
  });

  it("describes the object Tie variant", () => {
    const tally = {
      accepted_ballots: 4,
      abstentions: 0,
      counts: [],
      leading: { Tie: { candidate_ids_hex: ["a", "b"], approvals: 2 } },
    } as unknown as Parameters<typeof describeLeadingOutcome>[0];
    assert.match(describeLeadingOutcome(tally), /Unresolved tie between 2 options/);
  });
});

describe("no fake trend state", () => {
  it("returns null for a null participation summary", () => {
    assert.equal(participationIsDisclosed(null), false);
    assert.match(participationAccessibleText(null), /No participation data available/);
  });
});

// ---------------------------------------------------------------------------
// Slice 5A6: organizer creation pure helpers.
// ---------------------------------------------------------------------------

import {
  approvalRulePreview,
  acquireElectionDraft,
  draftIsReady,
  freezeAvailable,
  hydrateCreateElectionSession,
  initializeElectionDraft,
  isUncastableApprovalConfig,
  NO_QUORUM_STATEMENT,
  optionNoun,
  optionSetNoun,
  optionValidationErrors,
  parseVoterHexList,
  presentationLabel,
  newCreateElectionSession,
  runAction,
} from "../src/creation.ts";
import type { DraftInitializationState } from "../src/creation.ts";
import {
  intakeCanImport,
  intakeResultMessage,
  intakeResultTitle,
} from "../src/intake.ts";

const KEY64 = "6a493210f7499cd17fecb510ae0a23fda0d4b58a1b48d4ecc0f4cbc9423e86f2";

describe("creation: voter hex list parsing", () => {
  it("accepts valid keys and trims/ignores blanks", () => {
    const text = `${KEY64}\n  ${KEY64.slice(0, 32)}\n\n`;
    // The second line is only 32 hex chars -> error.
    const parsed = parseVoterHexList(text);
    assert.equal(parsed.keys.length, 1);
    assert.equal(parsed.errors.length, 1);
  });

  it("rejects non-hex and wrong length", () => {
    const parsed = parseVoterHexList("notahexkey\nabc");
    assert.equal(parsed.keys.length, 0);
    assert.equal(parsed.errors.length, 2);
  });

  it("surfaces duplicate keys", () => {
    const parsed = parseVoterHexList(`${KEY64}\n${KEY64.toUpperCase()}`);
    assert.equal(parsed.keys.length, 1);
    assert.equal(parsed.errors.length, 1);
    assert.match(parsed.errors[0], /Duplicate/i);
  });
});

describe("creation: option validation", () => {
  it("rejects empty IDs, empty labels, and duplicates", () => {
    const empty = optionValidationErrors([
      { machine_id_text: "", display_name: "A" },
    ]);
    assert.ok(empty.some((e) => /empty stable ID/i.test(e)));
    const emptyLabel = optionValidationErrors([
      { machine_id_text: "b", display_name: "   " },
    ]);
    assert.ok(emptyLabel.some((e) => /empty display label/i.test(e)));
    const dup = optionValidationErrors([
      { machine_id_text: "c", display_name: "C" },
      { machine_id_text: "c", display_name: "D" },
    ]);
    assert.ok(dup.some((e) => /duplicate stable ID/i.test(e)));
  });

  it("rejects duplicate display labels after trim normalization", () => {
    const dup = optionValidationErrors([
      { machine_id_text: "a", display_name: "Yes" },
      { machine_id_text: "b", display_name: "Yes" },
    ]);
    assert.ok(dup.some((e) => /duplicate display label/i.test(e)));
    const trimDup = optionValidationErrors([
      { machine_id_text: "a", display_name: "Yes" },
      { machine_id_text: "b", display_name: "   Yes   " },
    ]);
    assert.ok(trimDup.some((e) => /duplicate display label/i.test(e)));
  });

  it("passes for a valid list or empty list", () => {
    assert.deepEqual(optionValidationErrors([]), []);
    assert.deepEqual(
      optionValidationErrors([
        { machine_id_text: "a", display_name: "A" },
        { machine_id_text: "b", display_name: "B" },
      ]),
      [],
    );
  });
});

describe("creation: freeze availability", () => {
  it("requires complete and not frozen", () => {
    assert.equal(freezeAvailable(null), false);
    assert.equal(freezeAvailable({ complete: false, frozen: false } as never), false);
    assert.equal(freezeAvailable({ complete: true, frozen: false } as never), true);
    assert.equal(freezeAvailable({ complete: true, frozen: true } as never), false);
  });
});

describe("creation: authoritative draft initialization", () => {
  it("keeps the wizard blocked until a deferred Rust draft start resolves", async () => {
    let resolveStart: (() => void) | undefined;
    const states: DraftInitializationState[] = [];
    let setBasicsCalls = 0;
    const start = new Promise<void>((resolve) => {
      resolveStart = resolve;
    });

    const initializing = initializeElectionDraft(
      () => start,
      (state) => states.push(state),
    );

    assert.deepEqual(states, ["initializing"]);
    assert.equal(draftIsReady(states[0] ?? "initializing"), false);
    if (draftIsReady(states[0] ?? "initializing")) setBasicsCalls += 1;
    assert.equal(setBasicsCalls, 0);

    resolveStart?.();
    await initializing;
    assert.deepEqual(states, ["initializing", "ready"]);
    assert.equal(draftIsReady(states[1] ?? "initializing"), true);
    if (draftIsReady(states[1] ?? "initializing")) setBasicsCalls += 1;
    assert.equal(setBasicsCalls, 1);
  });

  it("fails closed, retries the authoritative start, and starts fresh on re-entry", async () => {
    const states: DraftInitializationState[] = [];
    let starts = 0;
    const start = async () => {
      starts += 1;
      if (starts === 1) throw new Error("shell unavailable");
    };

    await assert.rejects(initializeElectionDraft(start, (state) => states.push(state)));
    assert.equal(states.at(-1), "failed");
    assert.equal(draftIsReady(states.at(-1) ?? "initializing"), false);

    await initializeElectionDraft(start, (state) => states.push(state));
    assert.equal(starts, 2);
    assert.equal(states.at(-1), "ready");

    await initializeElectionDraft(start, (state) => states.push(state));
    assert.equal(starts, 3);
    assert.deepEqual(states.slice(-2), ["initializing", "ready"]);
  });
});

describe("creation: non-destructive draft acquisition and hydration", () => {
  const preview = {
    election_id_text: "preserved-election",
    proposal_question: "Should this preserved election pass?",
    governance_source_revision: "preserved-revision",
    presentation: "GovernanceProposal",
    voters: [{ public_key_hex: KEY64, public_key_abbrev: "6a493210…3e86f2" }],
    options: [{ machine_id_hex: "796573", machine_id_text: "yes", display_name: "Yes" }],
    approval_min: 1,
    approval_max: 1,
    allow_abstention: false,
    governance_document: null,
  } as never;

  it("acquires one safe preview without invoking destructive start-new work", async () => {
    const states: DraftInitializationState[] = [];
    const received: unknown[] = [];
    let getOrCreateCalls = 0;

    const result = await acquireElectionDraft(
      async () => {
        getOrCreateCalls += 1;
        return preview;
      },
      (state) => states.push(state),
      (value) => received.push(value),
    );

    assert.equal(getOrCreateCalls, 1);
    assert.equal(result, preview);
    assert.deepEqual(states, ["initializing", "ready"]);
    assert.deepEqual(received, [preview]);
  });

  it("hydrates committed Rust fields while leaving a newer session buffer intact", () => {
    const hydrated = hydrateCreateElectionSession(preview);
    assert.equal(hydrated.electionIdText, "preserved-election");
    assert.equal(hydrated.governanceRevision, "preserved-revision");
    assert.equal(hydrated.ballotType, "GovernanceProposal");
    assert.equal(hydrated.voterText, KEY64);
    assert.deepEqual(hydrated.options, [{ id: "yes", label: "Yes" }]);
    assert.equal(hydrated.approvalMin, 1);
    assert.equal(hydrated.approvalMax, 1);

    const unsaved = {
      ...hydrated,
      step: "governance" as const,
      electionIdText: "newer-unsaved-election",
    };
    // CreateElection retains this app-session buffer on re-entry rather than
    // applying an older preview over it.
    assert.equal(unsaved.step, "governance");
    assert.equal(unsaved.electionIdText, "newer-unsaved-election");
    assert.equal(newCreateElectionSession().step, "basics");
  });
});

describe("creation: void Tauri actions", () => {
  it("treats a successful Rust-unit null result as success", async () => {
    const errors: unknown[] = [];
    let basicsCalls = 0;
    let presentationCalls = 0;

    const basicsOk = await runAction(async () => {
      basicsCalls += 1;
      return null;
    }, (error) => errors.push(error));
    const presentationOk = basicsOk && await runAction(async () => {
      presentationCalls += 1;
      return null;
    }, (error) => errors.push(error));

    assert.equal(basicsOk, true);
    assert.equal(presentationOk, true);
    assert.equal(basicsCalls, 1);
    assert.equal(presentationCalls, 1);
    assert.deepEqual(errors, []);
  });

  it("treats only a rejected command as failure and captures its error", async () => {
    const failure = new Error("backend rejected mutation");
    const errors: unknown[] = [];
    const ok = await runAction(async () => Promise.reject(failure), (error) => errors.push(error));

    assert.equal(ok, false);
    assert.deepEqual(errors, [failure]);
  });
});

describe("creation: presentation vocabulary", () => {
  it("maps presentation nouns", () => {
    assert.equal(presentationLabel("Candidate"), "Candidate election");
    assert.equal(optionSetNoun("GovernanceProposal"), "Choices");
    assert.equal(optionNoun("BallotMeasure"), "response");
  });
});

describe("creation: approval rule preview", () => {
  it("formats range, exact, and abstention rules", () => {
    assert.match(approvalRulePreview(1, 2, false), /between 1 and 2 options/);
    assert.match(approvalRulePreview(1, 1, false), /exactly 1 option/);
    assert.match(approvalRulePreview(0, 2, true), /up to 2 options.*Abstaining.*permitted/);
  });

  it("handles unset limits", () => {
    assert.match(approvalRulePreview(null, null, false), /not set/);
  });
});

describe("final archive lifecycle gate", () => {
  it("permits a final archive only after finalization", () => {
    assert.equal(canWriteFinalArchive("FROZEN"), false);
    assert.equal(canWriteFinalArchive("OPEN"), false);
    assert.equal(canWriteFinalArchive("CLOSED"), false);
    assert.equal(canWriteFinalArchive("VERIFIED"), false);
    assert.equal(canWriteFinalArchive("FINALIZED"), true);
  });
});

describe("organizer Ootle anchor blockers", () => {
  const readyPrepareInput = {
    canAct: true,
    busy: false,
    archiveResultPresent: true,
    trustedDeploymentPresent: true,
    walletdEndpoint: "http://127.0.0.1:5100",
    indexerEndpoint: "http://127.0.0.1:12500",
    accountReference: "organizer-fee-account",
    feeComponent: "component_fee",
    declaredSealPublicKey: KEY64,
    dedicatedOrganizerWalletAttested: true,
    acceptedBallotFloor: 2,
    maxEpochDelta: 12,
    maxFee: 1000,
  };

  it("enables prepare for the finalized post-archive successful path", () => {
    const lifecycle = "FINALIZED";
    assert.equal(canWriteFinalArchive(lifecycle), true);
    assert.deepEqual(anchorPrepareBlockers(readyPrepareInput), []);
  });

  it("names unmet prepare prerequisites without using lifecycle as a blocker", () => {
    const blockers = anchorPrepareBlockers({
      ...readyPrepareInput,
      archiveResultPresent: false,
      trustedDeploymentPresent: false,
      walletdEndpoint: "",
      indexerEndpoint: " ",
      accountReference: "",
      feeComponent: "",
      declaredSealPublicKey: "",
      dedicatedOrganizerWalletAttested: false,
      acceptedBallotFloor: 1,
      maxEpochDelta: 0,
      maxFee: 0,
      busy: true,
    });
    assert.deepEqual(blockers, [
      "Final archive has not been written and verified",
      "Ootle deployment is not locked",
      "Walletd endpoint is missing",
      "Indexer endpoint is missing",
      "Fee account is missing",
      "Fee component address is missing",
      "Declared seal public key is missing",
      "Dedicated organizer wallet acknowledgement required",
      "Accepted ballot floor must be at least 2",
      "Max epoch delta must be at least 1",
      "Max fee must be at least 1",
      "Another anchor operation is running",
    ]);
  });

  it("names deployment-lock blockers", () => {
    assert.deepEqual(
      anchorDeploymentLockBlockers({
        canAct: true,
        busy: false,
        templateAddress: "",
        selectedWasmPath: "",
        wasmInspectionPresent: false,
      }),
      [
        "Template address is missing",
        "Published template WASM has not been selected",
      ],
    );
    assert.deepEqual(
      anchorDeploymentLockBlockers({
        canAct: true,
        busy: false,
        templateAddress: "template_abc",
        selectedWasmPath: "anchor.wasm",
        wasmInspectionPresent: true,
      }),
      [],
    );
  });

  it("names publish blockers including walletd auth-token failures", () => {
    assert.deepEqual(
      anchorPublishBlockers({
        canAct: true,
        busy: false,
        archiveResultPresent: true,
        anchorConfigPresent: true,
      }),
      [],
    );
    assert.deepEqual(
      anchorPublishBlockers({
        canAct: true,
        busy: true,
        archiveResultPresent: false,
        anchorConfigPresent: false,
        walletdBearerTokenUnavailable: true,
      }),
      [
        "Final archive has not been written and verified",
        "Anchor configuration has not been prepared",
        "Walletd bearer token requested but unavailable",
        "Another anchor operation is running",
      ],
    );
  });
});

describe("stale presentation response guards", () => {
  it("ignores a late participation response after a newer lifecycle refresh", async () => {
    const gate = new RequestGenerationGate();
    let resolveOld!: (value: string) => void;
    const old = new Promise<string>((resolve) => { resolveOld = resolve; });
    const oldToken = gate.begin();
    const applied: string[] = [];
    void old.then((value) => { if (gate.isCurrent(oldToken)) applied.push(value); });
    const newToken = gate.begin();
    if (gate.isCurrent(newToken)) applied.push("new");
    resolveOld("old");
    await old;
    assert.deepEqual(applied, ["new"]);
  });

  it("ignores a late voter confirmation after election replacement", async () => {
    const gate = new RequestGenerationGate();
    let resolveOld!: (value: string) => void;
    const old = new Promise<string>((resolve) => { resolveOld = resolve; });
    const oldToken = gate.begin();
    let confirmation: string | null = null;
    void old.then((value) => { if (gate.isCurrent(oldToken)) confirmation = value; });
    gate.invalidate();
    resolveOld("old-election");
    await old;
    assert.equal(confirmation, null);
  });
});

describe("ballot office intake helpers", () => {
  it("uses safe accepted and duplicate messages without sequence or nullifier display", () => {
    const accepted = {
      accepted: true,
      code: "ACCEPTED",
      category: "Accepted",
      package_digest_hex: "a".repeat(64),
    } as const;
    const duplicate = {
      ...accepted,
      accepted: false,
      code: "DUPLICATE_BALLOT",
      category: "Duplicate",
    } as const;

    assert.equal(intakeResultTitle(accepted), "Ballot accepted");
    assert.equal(intakeResultMessage(accepted), "Ballot accepted.");
    assert.equal(intakeResultMessage(duplicate), "Duplicate ballot for this election.");
    assert.doesNotMatch(intakeResultMessage(duplicate), /nullifier/i);
  });

  it("gates import to the open lifecycle", () => {
    assert.equal(intakeCanImport(true, "OPEN"), true);
    assert.equal(intakeCanImport(true, "FROZEN"), false);
    assert.equal(intakeCanImport(true, "CLOSED"), false);
    assert.equal(intakeCanImport(false, "OPEN"), false);
  });
});

describe("creation: uncastable approval config", () => {
  it("flags zero max with abstention disabled", () => {
    assert.equal(isUncastableApprovalConfig(0, 0, false), true);
  });

  it("allows zero max when abstention is enabled", () => {
    assert.equal(isUncastableApprovalConfig(0, 0, true), false);
  });

  it("allows nonzero max with abstention disabled", () => {
    assert.equal(isUncastableApprovalConfig(0, 1, false), false);
    assert.equal(isUncastableApprovalConfig(1, 2, false), false);
  });

  it("treats unset limits as not uncastable", () => {
    assert.equal(isUncastableApprovalConfig(null, null, false), false);
    assert.equal(isUncastableApprovalConfig(null, 0, false), false);
    assert.equal(isUncastableApprovalConfig(0, null, false), false);
  });
});

describe("creation: quorum statement", () => {
  it("states no quorum field exists", () => {
    assert.match(NO_QUORUM_STATEMENT, /No quorum rule/i);
  });
});

describe("voter credential helpers", () => {
  const eligible = {
    credential_loaded: true,
    credential_origin: "Generated" as const,
    public_governance_key_hex: `${KEY64}${KEY64}`,
    public_governance_key_abbrev: "6a493210...3e86f2",
    eligibility: "Eligible" as const,
    eligibility_label: "Eligible",
    can_continue: true,
    session_only: true,
    session_notice: "Session only",
    saved_locally: false,
    wallet_key_warning: WALLET_SEED_WARNING,
    enrollment_notice: "Enroll before freeze",
  };

  it("gates the next stage on eligible backend status", () => {
    assert.equal(canProceedAfterCredential(eligible), true);
    assert.equal(
      canProceedAfterCredential({ ...eligible, eligibility: "NotEligible", can_continue: false }),
      false,
    );
    assert.equal(canProceedAfterCredential(null), false);
  });

  it("maps status text and key abbreviation", () => {
    assert.equal(credentialStatusText(eligible), "Loaded");
    assert.equal(publicKeyDisplay(eligible), "6a493210...3e86f2");
    assert.equal(credentialStatusText(null), "Not loaded");
    assert.equal(publicKeyDisplay(null), "Not loaded");
  });

  it("maps eligibility tone", () => {
    assert.equal(credentialEligibilityTone("Eligible"), "ok");
    assert.equal(credentialEligibilityTone("NotEligible"), "warn");
    assert.equal(credentialEligibilityTone("NotChecked"), "neutral");
  });

  it("keeps api field names free of secret-bearing material", () => {
    assert.equal(noSecretFieldNames(Object.keys(eligible)), true);
    assert.equal(noSecretFieldNames(["secret_scalar"]), false);
    assert.match(WALLET_SEED_WARNING, /Never enter a wallet seed phrase/);
  });
});
