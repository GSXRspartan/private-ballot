// Invisible no-op lifecycle polling (voter side).
//
// The automatic authenticated status check must be UNSEEABLE when it does not
// advance knowledge, and surgical when it does. Two layers are tested here:
//
// 1. RUNTIME BEHAVIOR TESTS (real execution): the decision helpers in
//    `src/lifecyclePollApply.ts` are driven through full simulated poll
//    sequences — including user selection changes between ticks — asserting
//    that stable-state polls trigger NO refresh and repaint NOTHING, while a
//    genuine authenticated advance triggers exactly one authoritative
//    re-read. These exercise the exact functions the Vote screen calls; they
//    do not render React.
//
// 2. WIRING CONTRACT TESTS (source assertions, clearly labeled): Vote.tsx is
//    pinned to actually route its automatic tick through those helpers and to
//    key election-scoped effects on STABLE election identity (manifest hash)
//    instead of object identity — the periodic Vote-page reset defect. They
//    complement, never replace, the runtime tests above.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  appliedStatusDiffersFromPainted,
  authenticatedLifecycleAdvanced,
} from "../src/lifecyclePollApply.ts";
import type { AppliedElectionStatusResultV1 } from "../src/api/types";

function applied(
  effective_state: string,
  advanced: boolean,
  generation: number,
): AppliedElectionStatusResultV1 {
  return { effective_state, advanced, generation };
}

function voteSource(): string {
  return readFileSync(new URL("../src/screens/Vote.tsx", import.meta.url), "utf8");
}

// -------------------------------------------------------------------------
// Runtime behavior: the simulated poll/refresh model used below mirrors the
// Vote screen's success path one decision at a time:
//   paint   = appliedStatusDiffersFromPainted ? next : unchanged object
//   refresh = manual || authenticatedLifecycleAdvanced(applied, paintedState)
// -------------------------------------------------------------------------

/** Minimal faithful model of the screen state polling may touch. */
class PollModel {
  paintedStatusCard: AppliedElectionStatusResultV1 | null = null;
  paintedLifecycleState: string;
  electionRefreshes = 0;
  workflowRefreshes = 0;
  /** Local presentation state that must NEVER be disturbed by polling. */
  selectedOptionIds: string[] = [];
  currentStage = "election-review";

  constructor(lifecycleState: string) {
    this.paintedLifecycleState = lifecycleState;
  }

  /** One automatic tick with the backend's answer for this poll. */
  automaticTick(next: AppliedElectionStatusResultV1 | null): void {
    if (next === null) return; // transport failure: nothing happens at all
    if (appliedStatusDiffersFromPainted(this.paintedStatusCard, next)) {
      this.paintedStatusCard = { ...next };
    }
    if (authenticatedLifecycleAdvanced(next, this.paintedLifecycleState)) {
      // Exactly what the screen does on a real advance: re-read summary +
      // workflow. Nothing else is touched.
      this.electionRefreshes += 1;
      this.workflowRefreshes += 1;
      this.paintedLifecycleState = next.effective_state;
    }
  }

  manualCheck(next: AppliedElectionStatusResultV1): void {
    this.paintedStatusCard = { ...next };
    this.electionRefreshes += 1;
    this.workflowRefreshes += 1;
    this.paintedLifecycleState = next.effective_state;
  }
}

describe("no-op lifecycle polls are invisible (runtime behavior)", () => {
  it("stable OPEN election: repeated identical polls cause zero refreshes and zero repaints", () => {
    const model = new PollModel("OPEN");
    const answer = applied("OPEN", false, 7);
    for (let tick = 0; tick < 10; tick += 1) {
      model.automaticTick(answer);
    }
    assert.equal(model.electionRefreshes, 0);
    assert.equal(model.workflowRefreshes, 0);
    assert.equal(model.paintedLifecycleState, "OPEN");
    assert.deepEqual(model.paintedStatusCard, answer);
  });

  it("selection changes between no-op ticks survive every poll untouched", () => {
    const model = new PollModel("OPEN");
    model.selectedOptionIds = ["honda"];
    model.currentStage = "vote-choice";
    const answer = applied("OPEN", false, 7);

    model.automaticTick(answer);
    assert.deepEqual(model.selectedOptionIds, ["honda"]);
    assert.equal(model.currentStage, "vote-choice");

    // Voter changes Honda -> Subaru between polls.
    model.selectedOptionIds = ["subaru"];

    for (let tick = 0; tick < 3; tick += 1) {
      model.automaticTick(answer);
    }
    assert.deepEqual(model.selectedOptionIds, ["subaru"]);
    assert.equal(model.currentStage, "vote-choice");
    assert.equal(model.electionRefreshes, 0);
    assert.equal(model.workflowRefreshes, 0);
  });

  it("an identical answer never replaces the painted status card object", () => {
    const first = applied("OPEN", false, 7);
    const model = new PollModel("OPEN");
    model.automaticTick(first);
    const painted = model.paintedStatusCard;
    model.automaticTick(applied("OPEN", false, 7));
    assert.ok(model.paintedStatusCard === painted, "identical answer must keep identity");
    model.automaticTick(applied("OPEN", false, 8));
    assert.ok(model.paintedStatusCard !== painted, "new generation must replace the card");
    assert.equal(model.paintedStatusCard?.generation, 8);
  });

  it("a real FROZEN -> OPEN advance triggers exactly ONE authoritative re-read", () => {
    const model = new PollModel("FROZEN");
    model.automaticTick(applied("FROZEN", false, 3)); // still frozen: silent
    assert.equal(model.electionRefreshes, 0);

    model.automaticTick(applied("OPEN", true, 4)); // organizer opened voting
    assert.equal(model.paintedLifecycleState, "OPEN");
    assert.equal(model.electionRefreshes, 1);
    assert.equal(model.workflowRefreshes, 1);

    // Subsequent OPEN answers are again idempotent no-ops.
    model.automaticTick(applied("OPEN", false, 4));
    model.automaticTick(applied("OPEN", false, 4));
    assert.equal(model.electionRefreshes, 1);
    assert.equal(model.workflowRefreshes, 1);
  });

  it("forward transitions OPEN -> CLOSED -> VERIFIED each advance exactly once", () => {
    const model = new PollModel("OPEN");
    model.automaticTick(applied("CLOSED", true, 9));
    assert.equal(model.paintedLifecycleState, "CLOSED");
    model.automaticTick(applied("VERIFIED", true, 10));
    assert.equal(model.paintedLifecycleState, "VERIFIED");
    assert.equal(model.electionRefreshes, 2);
    assert.equal(model.workflowRefreshes, 2);
  });

  it("heals a drifted mirror exactly once even when advanced is false", () => {
    // Defense in depth: if the session ever sits at a state the screen has
    // not mirrored, the very next poll re-reads authority once — then stops.
    const model = new PollModel("FROZEN");
    model.automaticTick(applied("OPEN", false, 5));
    assert.equal(model.paintedLifecycleState, "OPEN");
    assert.equal(model.electionRefreshes, 1);
    model.automaticTick(applied("OPEN", false, 5));
    assert.equal(model.electionRefreshes, 1);
  });

  it("manual checks always heal regardless of advancement", () => {
    const model = new PollModel("OPEN");
    model.manualCheck(applied("OPEN", false, 4));
    assert.equal(model.electionRefreshes, 1);
  });
});

describe("decision helpers (runtime)", () => {
  it("appliedStatusDiffersFromPainted compares every painted field", () => {
    assert.equal(appliedStatusDiffersFromPainted(null, applied("OPEN", false, 1)), true);
    assert.equal(
      appliedStatusDiffersFromPainted(applied("OPEN", false, 1), applied("OPEN", false, 1)),
      false,
    );
    assert.equal(
      appliedStatusDiffersFromPainted(applied("FROZEN", false, 1), applied("OPEN", false, 1)),
      true,
    );
    assert.equal(
      appliedStatusDiffersFromPainted(applied("OPEN", true, 1), applied("OPEN", false, 1)),
      true,
    );
    assert.equal(
      appliedStatusDiffersFromPainted(applied("OPEN", false, 1), applied("OPEN", false, 2)),
      true,
    );
  });

  it("authenticatedLifecycleAdvanced trusts backend verdict or mirror drift only", () => {
    assert.equal(authenticatedLifecycleAdvanced(applied("OPEN", true, 4), "OPEN"), true);
    assert.equal(authenticatedLifecycleAdvanced(applied("OPEN", false, 4), "OPEN"), false);
    assert.equal(authenticatedLifecycleAdvanced(applied("OPEN", false, 4), "FROZEN"), true);
    assert.equal(authenticatedLifecycleAdvanced(applied("CLOSED", true, 5), "OPEN"), true);
  });
});

// -------------------------------------------------------------------------
// Wiring contract tests (SOURCE assertions — labeled as such). These pin that
// Vote.tsx actually routes polling through the runtime-tested helpers above
// and keys election effects on stable identity.
// -------------------------------------------------------------------------

describe("Vote-screen wiring for invisible polling (source contract)", () => {
  const vote = voteSource();

  function sliceBetween(startMarker: string, endMarker: string): string {
    const start = vote.indexOf(startMarker);
    assert.ok(start >= 0, `${startMarker} must exist`);
    const end = vote.indexOf(endMarker, start);
    assert.ok(end > start, `${endMarker} must bound the slice`);
    return vote.slice(start, end);
  }

  it("the shared handler gates broad refresh behind manual-or-real-advance", () => {
    const shared = sliceBetween(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    // Stale-response drop still precedes any state write (36b1f72 era guard).
    const guard = shared.indexOf("!lifecycleRefreshGateRef.current.isCurrent(requestToken)");
    const firstWrite = shared.indexOf("setStatusImport(");
    assert.ok(guard >= 0 && firstWrite >= 0);
    assert.ok(guard < firstWrite, "stale responses drop before writing state");
    // No-op polls skip both authoritative re-reads entirely.
    assert.match(shared, /appliedStatusDiffersFromPainted\(/);
    assert.match(
      shared,
      /if \(manual \|\| authenticatedLifecycleAdvanced\(\s*applied,\s*election\.lifecycle_state/,
    );
    const gateIdx = shared.indexOf("authenticatedLifecycleAdvanced(applied");
    const refreshElectionIdx = shared.indexOf("await refreshElection()");
    const refreshWorkflowIdx = shared.indexOf("await refreshWorkflow(confirmed)");
    assert.ok(refreshElectionIdx > gateIdx);
    assert.ok(refreshWorkflowIdx > refreshElectionIdx);
  });

  it("automatic tick still routes through the ONE authenticated path", () => {
    const tickFn = sliceBetween(
      "async function automaticLifecycleStatusTick",
      "async function onSubmitPrivately",
    );
    assert.match(tickFn, /onFetchElectionStatusPrivate\(false\)/);
    const shared = sliceBetween(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    assert.match(shared, /await api\.fetchElectionStatusPrivate\(\)/);
  });

  it("polling stays ballot-read-only and decoupled from busy/proof state", () => {
    const shared = sliceBetween(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    assert.doesNotMatch(
      shared,
      /prepareVoterBallot|submitPreparedVoterBallotPrivately|retryPrivateSubmission|setVoterBallotSelection|clearVoterBallotSelection|changeMyBallotChoice|resetVoterWorkflow/,
    );
    assert.doesNotMatch(shared, /setBusy\(|preparingProof|prepareInFlightStore/);
  });

  it("every election-scoped effect keys on STABLE manifest-hash identity, not object identity", () => {
    assert.doesNotMatch(vote, /\}, \[election[,)\]]/);
    // The reset effect (which clears guided-stage + selection presentation)
    // must trip ONLY on a real election switch.
    const resetEffect = sliceBetween(
      "setConfirmation(null);",
      "}, [electionManifestHashHex]);",
    );
    assert.match(resetEffect, /setSelectedOptionIds\(\[\]\)/);
    assert.match(resetEffect, /setSelectionStage\(false\)/);
    assert.match(resetEffect, /lifecycleRefreshGateRef\.current\.invalidate\(\)/);
  });
});
