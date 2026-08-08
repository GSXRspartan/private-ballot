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
import {
  approvalRuleText,
  presentationFor,
  BALLOT_PRESENTATIONS,
} from "../src/ballot/ballotTypes.ts";
import {
  approvalBps,
  approvalLabel,
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

const sampleSummary = {
  election_id_hex: "ab",
  election_id_text: null,
  lifecycle_state: "FROZEN",
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

describe("no fake trend state", () => {
  it("returns null for a null participation summary", () => {
    assert.equal(participationIsDisclosed(null), false);
    assert.match(participationAccessibleText(null), /No participation data available/);
  });
});
