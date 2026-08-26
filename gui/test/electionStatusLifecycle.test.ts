// Authenticated distributed lifecycle + phantom-selection regression tests.
//
// Covers two repairs:
//
// 1. DISTRIBUTED LIFECYCLE: a voter on an independent computer can only learn
//    FROZEN -> OPEN -> CLOSED through a SIGNED, election-bound status
//    statement (Rust-verified). The Vote screen must say the lifecycle truth
//    ("voting has not opened yet" / "voting has closed") and must offer the
//    signed-status import while FROZEN — never fabricate OPEN.
//
// 2. PHANTOM SELECTION: the checkbox draft is optimistic but strictly
//    reconciled against backend authority: failures roll back via an
//    authoritative re-read, stale async responses are dropped by generation,
//    and lifecycle blocking never shows "choose a response".
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Where no React harness exists, screen behaviors are pinned by semantic
// source assertions; pure presentation helpers are tested behaviorally.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  electionNotOpenText,
  workflowStateText,
  workflowTone,
} from "../src/voterWorkflow.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const manage = readProjectFile("src/screens/ManageElection.tsx");
const voterWorkflow = readProjectFile("src/voterWorkflow.ts");
const types = readProjectFile("src/api/types.ts");
const client = readProjectFile("src/api/client.ts");
const voterSession = readFileSync(
  new URL("../../crates/gui-core/src/voter_session.rs", import.meta.url),
  "utf8",
);
const electionStatus = readFileSync(
  new URL("../../crates/gui-core/src/election_status.rs", import.meta.url),
  "utf8",
);

// -------------------------------------------------------------------------
// Lifecycle truthfulness in voter messaging
// -------------------------------------------------------------------------

describe("lifecycle-truthful voter messaging", () => {
  it("FROZEN reports that voting has not opened", () => {
    const text = electionNotOpenText("FROZEN");
    assert.match(text, /has not opened/);
    assert.doesNotMatch(text, /choose a response/i);
  });

  it("CLOSED, VERIFIED, and FINALIZED report voting has closed", () => {
    for (const state of ["CLOSED", "VERIFIED", "FINALIZED"]) {
      const text = electionNotOpenText(state);
      assert.match(text, /closed/, `${state} must say voting closed`);
      assert.doesNotMatch(text, /has not opened/, `${state} must not say not-opened`);
      assert.doesNotMatch(text, /choose a response/i);
    }
  });

  it("ElectionNotOpen workflow text never tells the voter to choose a response", () => {
    const text = workflowStateText("ElectionNotOpen");
    assert.doesNotMatch(text, /choose a response/i);
    assert.match(text, /not open|closed/i);
  });

  it("keeps choose-a-response wording ONLY for genuinely missing selections", () => {
    // The default/SelectionIncomplete cases remain for a truly empty ballot;
    // they are simply no longer reachable while the lifecycle blocks progress.
    assert.equal(workflowStateText(null), "Choose a response to continue.");
    assert.equal(
      workflowStateText("SelectionIncomplete"),
      "Choose a response to continue.",
    );
  });

  it("renders the lifecycle truth when the backend reports ElectionNotOpen", () => {
    // The status pill prefers electionNotOpenText fed from the AUTHORITATIVE
    // backend lifecycle (selection.lifecycle_state, falling back to the shell
    // election summary) instead of workflowStateText's generic sentence.
    const pillSlice = vote.slice(
      vote.indexOf('<div className="selection-status"'),
      vote.indexOf("</div>", vote.indexOf('<div className="selection-status"')),
    );
    assert.match(pillSlice, /ElectionNotOpen/);
    assert.match(pillSlice, /electionNotOpenText\(/);
    assert.match(
      pillSlice,
      /selection\?\.lifecycle_state \?\? election\?\.lifecycle_state/,
    );
  });

  it("tones ElectionNotOpen as a warning", () => {
    assert.equal(workflowTone("ElectionNotOpen"), "warn");
  });

  it("shows a FROZEN notice with the signed-status import control", () => {
    assert.match(vote, /Voting has not opened yet\./);
    assert.match(vote, /Import signed election status…/);
    assert.match(vote, /onImportElectionStatus/);
    assert.match(vote, /Check via private connection/);
    assert.match(vote, /onFetchElectionStatusPrivate/);
    // The frozen notice explains WHY the frozen file cannot answer this.
    assert.match(vote, /frozen election file cannot say/);
  });

  it("shows a truthful closed notice on CLOSED or later", () => {
    assert.match(vote, /election\?\.lifecycle_state === "CLOSED"/);
    assert.match(vote, /election\?\.lifecycle_state === "FINALIZED"/);
  });

  it("import refreshes authoritative state after applying status", () => {
    // After a successful import the screen re-reads BOTH the shell summary
    // and the Rust-owned workflow so every gate reflects verified truth.
    const handler = vote.slice(
      vote.indexOf("async function onImportElectionStatus"),
      vote.indexOf("async function onImportElectionStatus") + 1600,
    );
    assert.match(handler, /api\.importElectionStatusArtifact\(/);
    assert.match(handler, /await refreshElection\(\)/);
    assert.match(handler, /await refreshWorkflow\(/);
  });
});

// -------------------------------------------------------------------------
// Signed election-status artifact surface (Rust contract)
// -------------------------------------------------------------------------

describe("authenticated election-status artifact contract", () => {
  it("statements bind election identity AND registry commitment, not just state", () => {
    assert.match(electionStatus, /expected_registry_commitment/);
    assert.match(electionStatus, /WrongRegistryCommitment/);
    assert.match(electionStatus, /WrongManifestHash/);
    assert.match(electionStatus, /WrongElection/);
  });

  it("statements refuse DRAFT and unsupported versions fail closed", () => {
    assert.match(electionStatus, /DraftNotSignable/);
    assert.match(electionStatus, /UnsupportedVersion/);
  });

  it("monotonic knowledge rejects rollback, staleness, and equal-generation conflicts", () => {
    assert.match(electionStatus, /LifecycleRollbackRejected/);
    assert.match(electionStatus, /StaleGeneration/);
    assert.match(electionStatus, /ConflictingGeneration/);
  });

  it("the shared apply path verifies before advancing and records accepted generations", () => {
    assert.match(
      electionStatus,
      /fn verify_and_apply_election_status_statement_v1/,
    );
    // Order of operations inside the single authoritative path.
    const applyStart = electionStatus.indexOf("fn verify_and_apply_election_status_statement_v1");
    const fnBody = electionStatus.slice(applyStart, applyStart + 2600);
    const verifyAt = fnBody.indexOf("statement.verify(");
    const planAt = fnBody.indexOf("knowledge.plan(");
    const advanceAt = fnBody.indexOf("advance_session_lifecycle_to_state_v1(session, target)");
    const recordAt = fnBody.indexOf("knowledge.record(");
    assert.ok(verifyAt >= 0, "must verify bindings+signature");
    assert.ok(planAt > verifyAt, "planning runs after verification");
    assert.ok(advanceAt > planAt, "advancing runs after planning");
    assert.ok(recordAt > advanceAt, "knowledge records only after success");
  });

  it("selection changes require OPEN in the Rust voter session", () => {
    assert.match(voterSession, /fn ensure_selection_lifecycle_open/);
    assert.match(
      voterSession,
      /voting has not opened yet; responses can be chosen only while voting is open/,
    );
    assert.match(
      voterSession,
      /voting has closed; responses can no longer be chosen or changed/,
    );
  });

  it("workflow state reports ElectionNotOpen ahead of selection states", () => {
    // The lifecycle check dominates credential/selection states in the
    // Rust-derived workflow state machine.
    const fnStart = voterSession.indexOf("fn workflow_state(");
    const fnBody = voterSession.slice(fnStart, fnStart + 2400);
    const lifecycleCheck = fnBody.indexOf("ElectionNotOpen");
    const credentialMatch = fnBody.indexOf("credential_status().eligibility");
    assert.ok(lifecycleCheck >= 0, "workflow state must expose ElectionNotOpen");
    assert.ok(
      credentialMatch < 0 || lifecycleCheck < credentialMatch,
      "lifecycle truth precedes credential/selection states",
    );
  });

  it("frontend type union includes ElectionNotOpen", () => {
    assert.match(types, /\|\s*"ElectionNotOpen"/);
  });

  it("client exposes both export and import status calls", () => {
    assert.match(client, /exportElectionStatusArtifact/);
    assert.match(client, /importElectionStatusArtifact/);
  });

  it("organizer export names the signed-status action and its purpose", () => {
    assert.match(manage, /Export signed election status/);
    assert.match(manage, /signed status statement/);
  });
});

// -------------------------------------------------------------------------
// Phantom-selection reconciliation
// -------------------------------------------------------------------------

describe("phantom-selection reconciliation", () => {
  function slice(name: string): string {
    const start = vote.indexOf(`async function ${name}`);
    assert.ok(start >= 0, `missing function ${name}`);
    // End at the first two-space-indented closing brace (line-ending agnostic).
    const rest = vote.slice(start);
    const closeMatch = rest.match(/\r?\n  \}/);
    return closeMatch?.index !== undefined ? rest.slice(0, closeMatch.index) : rest;
  }

  it("a rejected toggle rolls back to authoritative backend state", () => {
    const body = slice("setBackendSelection");
    const catchIndex = body.indexOf("catch");
    const rollback = body.slice(catchIndex);
    assert.match(rollback, /refreshSelection\(\)/);
    assert.match(rollback, /refreshWorkflow\(/);
    assert.match(rollback, /AUTHORITATIVE ROLLBACK/);
  });

  it("every selection write and read is gated by one monotonic token", () => {
    for (const name of ["setBackendSelection", "refreshWorkflow", "refreshSelection"]) {
      const body = slice(name);
      assert.match(body, /selectionStatusGateRef\.current\.begin\(\)/, name);
      assert.match(body, /isCurrent\(/, name);
    }
  });

  it("stale responses return before touching any state", () => {
    // In each gated function the isCurrent guard appears BEFORE the first
    // setState-style write, so a late response can never overwrite newer UI.
    for (const name of ["setBackendSelection", "refreshWorkflow", "refreshSelection"]) {
      const body = slice(name);
      const guard = body.indexOf("isCurrent(");
      const firstWrite = Math.min(
        ...["setSelection(", "setWorkflow(", "setSelectedOptionIds("]
          .map((marker) => body.indexOf(marker))
          .filter((index) => index >= 0),
      );
      assert.ok(firstWrite >= 0, `${name} writes state`);
      assert.ok(
        guard >= 0 && guard < firstWrite,
        `${name} must drop stale responses before writing`,
      );
    }
  });

  it("election switch invalidates pending selection operations", () => {
    const effectStart = vote.search(/useEffect\(\(\) => \{\r?\n    setConfirmation\(null\);/);
    assert.ok(effectStart >= 0, "election-switch reset effect present");
    const effect = vote.slice(
      effectStart,
      vote.indexOf("}, [electionManifestHashHex]);", effectStart),
    );
    assert.match(effect, /selectionStatusGateRef\.current\.invalidate\(\)/);
  });

  it("optimistic paint still mirrors into the draft ref only through reconciliation", () => {
    // Toggles keep painting optimistically (responsiveness) but always route
    // through setBackendSelection, which owns rollback + gating.
    const toggle = slice("onToggleOption");
    assert.match(toggle, /setSelectedOptionIds\(nextIds\)/);
    assert.match(toggle, /await setBackendSelection\(nextIds, false\)/);
  });

  it("proof preparation stays gated by backend can_prepare_ballot", () => {
    assert.match(vote, /!workflow\?\.can_prepare_ballot/);
    // And the frontend never fabricates the flag.
    assert.doesNotMatch(vote, /can_prepare_ballot\s*=\s*true/);
    assert.match(types, /can_prepare_ballot: boolean/);
  });

  it("backend refuses to store selections outside OPEN (behavioral contract)", () => {
    // The Rust unit tests enforce this behaviorally; here we pin that the
    // gate is actually wired into BOTH mutation entry points.
    const setSel = voterSession.indexOf("pub fn set_selection(");
    const clearSel = voterSession.indexOf("pub fn clear_selection(");
    assert.ok(setSel >= 0 && clearSel >= 0);
    assert.match(
      voterSession.slice(setSel, setSel + 900),
      /ensure_selection_lifecycle_open\(lifecycle_state\)\?/,
    );
    assert.match(
      voterSession.slice(clearSel, clearSel + 700),
      /ensure_selection_lifecycle_open\(lifecycle_state\)\?/,
    );
  });
});
