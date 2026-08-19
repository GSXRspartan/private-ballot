// Pre-cast reconsideration + durable cast-lock frontend tests.
//
// Covers the voter-facing half: "Change my choice" is offered only before the
// cast, exporting is presented as the irreversible cast boundary with a
// warning, the cast state removes the reconsideration/preparation actions and
// never claims organizer acceptance/inclusion/anchoring, and the recovery state
// does not permit a different choice. Pure helpers are exercised directly;
// component behavior is pinned by semantic source assertions.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { workflowStateText, workflowTone } from "../src/voterWorkflow.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const client = readProjectFile("src/api/client.ts");
const types = readProjectFile("src/api/types.ts");

// -------------------------------------------------------------------------
// Pure workflow-state mapping for the new cast states
// -------------------------------------------------------------------------

describe("cast workflow-state wording", () => {
  it("maps BallotCast/CastPending to honest voter sentences", () => {
    assert.match(workflowStateText("BallotCast"), /exported and cast on this device/);
    assert.match(workflowStateText("CastPending"), /locked for this election/);
  });

  it("never implies organizer acceptance in the cast sentence", () => {
    assert.doesNotMatch(workflowStateText("BallotCast"), /accepted|counted|included|anchored/i);
  });

  it("tones: cast is ok, pending is a warning", () => {
    assert.equal(workflowTone("BallotCast"), "ok");
    assert.equal(workflowTone("CastPending"), "warn");
  });
});

// -------------------------------------------------------------------------
// DTO + command surface
// -------------------------------------------------------------------------

describe("cast-lock DTO and command surface", () => {
  it("exposes the durable cast_lock_state on the workflow DTO", () => {
    assert.match(types, /cast_lock_state:\s*GuiVoterCastLockStateV1/);
    assert.match(types, /"NOT_CAST"\s*\|\s*"CAST_PENDING"\s*\|\s*"CAST"/);
  });

  it("wires the Change my choice command", () => {
    assert.match(client, /changeMyBallotChoice:\s*\(\)\s*=>/);
    assert.match(client, /"change_my_ballot_choice"/);
    assert.match(vote, /await api\.changeMyBallotChoice\(\)/);
  });
});

// -------------------------------------------------------------------------
// Pre-cast reconsideration is offered only before the cast
// -------------------------------------------------------------------------

describe("pre-cast reconsideration", () => {
  it("offers exactly one Change my choice action, gated to the not-cast state", () => {
    const matches = vote.match(/>\s*Change my choice\s*</g) ?? [];
    assert.equal(matches.length, 1);
    // The reconsideration/export controls live in the non-cast branch of the
    // castLocked ternary; the cast/pending card is rendered instead when locked.
    assert.match(vote, /castLocked \? \(/);
    assert.match(vote, /ballotCast \? \(/);
  });

  it("presents the offline file save as the irreversible cast boundary with a warning", () => {
    // The offline-file button must NOT use misleading "cast" wording; it saves a
    // local encrypted file. The irreversibility warning and confirm dialog remain.
    assert.match(vote, />\s*Save encrypted ballot file\s*</);
    assert.doesNotMatch(vote, />\s*Export and cast ballot\s*</);
    assert.match(
      vote,
      /After this ballot is exported for submission, your vote for this election\s+cannot be changed/,
    );
    // The offline route is clearly labelled and states nothing is sent.
    assert.match(vote, /Offline submission/);
    assert.match(vote, /Nothing is sent over the network/);
    // A confirmation dialog guards the irreversible action.
    assert.match(vote, /confirmCast && \(/);
    assert.match(vote, /Save this ballot file\?/);
    assert.match(vote, /void onExportBallot\(\)/);
  });
});

// -------------------------------------------------------------------------
// Cast state: no reconsideration, no false acceptance claims
// -------------------------------------------------------------------------

describe("cast state presentation", () => {
  it("shows a dedicated offline cast card that does not claim organizer acceptance", () => {
    assert.match(vote, /Your ballot for this election was exported and cast on this device\./);
    assert.match(vote, /It does not mean the\s+organizer has received, accepted, counted, included, or anchored it/);
    assert.match(vote, /Deliver the exported ballot file through the election's approved intake/);
    // The OFFLINE cast presentation must not claim acceptance/inclusion/anchoring:
    // an exported file proves nothing about the organizer's record.
    const offlineBranch = vote.slice(
      vote.indexOf("Your ballot for this election was exported and cast on this device."),
      vote.indexOf("Why can't I change it?"),
    );
    assert.doesNotMatch(offlineBranch, /ballot (was|is|has been) (accepted|counted|included|anchored)/i);
    assert.doesNotMatch(offlineBranch, /your vote (was|is|has been) (counted|recorded|accepted)/i);
    assert.doesNotMatch(vote, /submitted to Ootle/i);
  });

  it("reports an authenticated online receipt without claiming archive inclusion", () => {
    // The authenticated-receipt presentation may say the ballot was ACCEPTED
    // (that is exactly what the verified organizer receipt means), but it must
    // point at the published archive for final inclusion instead of claiming it.
    assert.match(vote, /Your ballot was accepted ✓/);
    assert.match(
      vote,
      /The ballot office returned an authenticated receipt for this exact\s+ballot\./,
    );
    assert.match(
      vote,
      /Final inclusion can be independently checked from the published\s+election archive after voting closes\./,
    );
    assert.match(vote, /Receipt details/);
    // And it still never claims finalization/anchoring anywhere on the screen.
    assert.doesNotMatch(vote, /your ballot (is|has been) (finalized|anchored|included)/i);
  });

  it("explains the cross-computer limitation honestly (nullifier is authoritative)", () => {
    assert.match(vote, /election\s+independently rejects a second ballot from the same credential/);
  });
});

// -------------------------------------------------------------------------
// Recovery (CAST_PENDING): locked, no different choice
// -------------------------------------------------------------------------

describe("cast recovery state", () => {
  it("renders a locked recovery notice without change/prepare/export controls", () => {
    // Slice the pending branch (from the pending notice up to the start of the
    // non-cast "Protect your vote" proof card) and assert it exposes no
    // choice-editing/preparation/export controls and states the truthful
    // plaintext-not-restored recovery message (Issues 10/11).
    const start = vote.indexOf("Your ballot for this election is being finalized");
    assert.ok(start >= 0, "pending recovery notice must exist");
    const pendingBranchEnd = vote.indexOf('<Card title="Protect your vote">', start);
    assert.ok(pendingBranchEnd > start, "pending branch must precede the proof card");
    const pendingSlice = vote.slice(start, pendingBranchEnd);
    assert.match(pendingSlice, /your choice is\s+locked/);
    assert.match(pendingSlice, /plaintext choice is not\s+restored/);
    assert.match(pendingSlice, /Your vote was not erased/);
    assert.doesNotMatch(pendingSlice, /Change my choice|Save encrypted ballot file|onGenerateProof/);
  });
});
