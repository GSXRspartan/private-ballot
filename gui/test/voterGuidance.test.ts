// Voter-facing guidance regression tests (Vote screen "How voting works"
// and "What privacy does this provide?").
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Where no React harness exists, GUI behaviors are pinned by semantic
// source assertions (identifiable elements and attributes), never by
// fragile pixel analysis.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");

// -------------------------------------------------------------------------
// "How voting works": compact, collapsible, nontechnical
// -------------------------------------------------------------------------

describe("voter-facing how voting works", () => {
  it("exists on the Vote screen as a collapsible section", () => {
    assert.match(vote, /How voting works/);
    // Collapsed by default: a plain <details> element with no `open`.
    const guide = vote.match(/<details className="voter-guide">/);
    assert.ok(guide, "missing collapsible voter-guide details element");
  });

  it("appears below the Vote introduction and before the Load Election card", () => {
    const lede = vote.indexOf("screen-lede");
    const guide = vote.indexOf("voter-guide");
    const loadCard = vote.indexOf('title="Load Election"');
    assert.ok(lede >= 0 && guide > lede, "guide must follow the Vote lede");
    assert.ok(loadCard > guide, "guide must precede the first action card");
  });

  it("walks the voter through the six journey steps in plain language", () => {
    assert.match(vote, /Load the election\./);
    assert.match(vote, /files belong together and have not been\s+altered/);
    assert.match(vote, /Review the election\./);
    assert.match(vote, /Prove you are eligible privately\./);
    assert.match(vote, /Choose your vote\./);
    assert.match(vote, /tied to this specific election/);
    assert.match(vote, /Submit your ballot\./);
    assert.match(vote, /Check its status\./);
    assert.match(vote, /received,\s+accepted, included in the final election record, and, where applicable, anchored/);
  });

  it("keeps protocol vocabulary out of the primary voter explanation", () => {
    const guide = vote.slice(
      vote.indexOf("voter-guide"),
      vote.indexOf("privacy-notice"),
    );
    // The primary steps never require protocol knowledge.
    const primary = guide.slice(0, guide.indexOf("Technical details"));
    assert.doesNotMatch(primary, /Triptych|nullifier|HPKE|CBOR|canonical serialization|archive internals/i);
    // Technical terms remain available under the disclosure.
    assert.match(guide, /Technical details/);
    assert.match(guide, /Tari Triptych/);
    assert.match(guide, /election-bound proof/);
    assert.match(guide, /receipt states/);
  });

  it("does not send the voter to GitHub or the README to learn how to vote", () => {
    const guide = vote.slice(
      vote.indexOf("voter-guide"),
      vote.indexOf("privacy-notice"),
    );
    assert.doesNotMatch(guide, /github\.com|README|https?:\/\//i);
  });
});

// -------------------------------------------------------------------------
// "What privacy does this provide?": all three points, always visible
// -------------------------------------------------------------------------

describe("voter-facing privacy notice", () => {
  it("is a visible notice (not collapsed) before any ballot action", () => {
    assert.match(vote, /What privacy does this provide\?/);
    const notice = vote.match(
      /<div className="notice notice-info privacy-notice" role="note">/,
    );
    assert.ok(notice, "privacy notice is not rendered as a visible notice");
    // It precedes proof creation and submission actions.
    assert.ok(
      vote.indexOf("privacy-notice") < vote.indexOf("Create anonymous eligibility proof"),
      "privacy notice must appear before ballot creation",
    );
  });

  it("explains eligibility anonymity", () => {
    assert.match(
      vote,
      /eligibility proof shows that an\s+approved voter participated without revealing which\s+eligible voter you are/,
    );
  });

  it("explains the ballot-content privacy limitation", () => {
    assert.match(vote, /Your vote choice is not permanently sealed\./);
    assert.match(vote, /may become visible\s+as part of the final verifiable election record/);
  });

  it("warns the voter to keep the credential private", () => {
    assert.match(vote, /Keep your voter credential private\./);
    assert.match(vote, /Never send it to the\s+organizer or another voter\./);
  });
});

// -------------------------------------------------------------------------
// Privacy claims stay accurate: no overstated guarantees
// -------------------------------------------------------------------------

describe("privacy claim accuracy", () => {
  it("never claims permanent ballot secrecy or sealed-ballot voting", () => {
    assert.doesNotMatch(vote, /permanently secret/i);
    assert.doesNotMatch(vote, /sealed[- ]ballot voting/i);
    assert.doesNotMatch(vote, /vote choice (is|stays|remains) (secret|hidden|private)/i);
  });

  it("never claims coercion resistance", () => {
    assert.doesNotMatch(vote, /coercion[- ]resistan/i);
    assert.doesNotMatch(vote, /receipt[- ]free/i);
  });

  it("never claims the organizer is invisible in all circumstances", () => {
    assert.doesNotMatch(vote, /organizer (cannever|can never|cannot) (see|know|link)/i);
    assert.doesNotMatch(vote, /fully anonymous/i);
  });
});

// -------------------------------------------------------------------------
// Protocol behavior unchanged: the guide is presentation-only
// -------------------------------------------------------------------------

describe("protocol behavior unchanged", () => {
  it("keeps the same backend API calls for the voting workflow", () => {
    for (const call of [
      "api.voterConfirmation(",
      "api.voterGovernanceCredentialStatus(",
      "api.resetVoterGovernanceCredential(",
      "api.voterWorkflowStatus(",
      "api.voterBallotSelectionStatus(",
      "api.setVoterBallotSelection(",
      "api.clearVoterBallotSelection(",
      "api.prepareVoterBallot(",
      "api.exportPreparedVoterBallot(",
      "api.submitPreparedVoterBallotPrivately(",
      "api.privateTransportAvailability(",
      "api.computeGovernanceDocumentDigest(",
    ]) {
      assert.ok(vote.includes(call), `Vote screen no longer calls ${call}`);
    }
  });

  it("loads the carried credential after review and never offers post-freeze generation", () => {
    assert.match(vote, /async function onEnterCredentialStage\(\)/);
    assert.match(vote, /setCredential\(await api\.voterGovernanceCredentialStatus\(\)\)/);
    assert.match(vote, /onClick=\{\(\) => void onEnterCredentialStage\(\)\}/);
    assert.doesNotMatch(vote, /Generate new credential/);
    assert.match(vote, /This election is already frozen\. Generating a new credential now cannot add/);
  });

  it("adds no new backend/API imports for the voter guidance", () => {
    const imports = vote.slice(0, vote.indexOf("export function Vote"));
    assert.doesNotMatch(imports, /api\/client.*prepareVoterBallot.*guide/is);
    // The guide uses only the shared presentational components.
    assert.match(imports, /DetailsSection/);
    // No network, wallet, or proof logic in the presentation layer.
    assert.doesNotMatch(vote, /fetch\(|invoke\(|\.prove\(/i);
  });
});
