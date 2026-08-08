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
import { canShowTally, resultsAreSealed } from "../src/lifecycle.ts";

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
