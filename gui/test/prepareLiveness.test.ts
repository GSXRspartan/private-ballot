// prepare_voter_ballot concurrency + proof-button enablement invariants.
//
// Physical history (two-computer-try-03): on Computer B the voter selected a
// choice, but "Create anonymous eligibility proof" was disabled at rest until a
// Vote -> Settings -> Vote round-trip re-enabled it, with NO prepare invocation
// ever fired. Root cause: `setBackendSelection` guarded its `setBusy(false)` on
// a monotonic gate token that its OWN nested `refreshWorkflow`/`refreshSelection`
// advanced, so the shared `busy` flag leaked `true` after every selection change
// and disabled the whole surface (including the proof button) until a remount
// reset the component state.
//
// The repair has two parts, pinned here so a future edit cannot silently
// regress them:
//
//  1. STUCK-BUSY FIX. `setBackendSelection` releases `busy` UNCONDITIONALLY in
//     `finally` (it is the terminal owner; the checkboxes are disabled while it
//     runs). The monotonic gate still guards STALE STATE writes, not the flag.
//
//  2. PROOF ACTION DECOUPLED FROM SHARED BUSY. A module-level observable store
//     (`prepareInFlightStore`) is the SINGLE source of truth for both the
//     duplicate-prepare guard and the button's disabled state (read into React
//     with `useSyncExternalStore`). Because it lives at module scope it survives
//     Vote unmount/remount, so an abandoned invocation still blocks a duplicate
//     AND keeps the button disabled, and re-enables it truthfully when the
//     invocation settles. An UNRELATED async operation toggling `busy` can no
//     longer enable or disable the proof action incorrectly.
//
// The temporary forensic instrumentation from commit 51a7d5e (durable %TEMP%
// trace writer, startup sentinel, dev-only frontend breadcrumbs) has been
// removed now that the physical run localized the path; this suite covers the
// durable behavior that survives it.
//
// Source-assertion tests (no React mount harness exists — ADR-0007). These pin
// the shape of the concurrency contract in source; they do NOT prove runtime
// IPC behavior. Backend gating semantics remain covered by the gui-core shell
// regression tests, and the end-to-end path still requires physical regression.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const lib = readProjectFile("src-tauri/src/lib.rs");

/** The body of a top-level `async function <name>` in Vote.tsx, isolated so
 *  ordering assertions cannot accidentally match text elsewhere in the file. */
function asyncFunctionBody(name: string): string {
  const start = vote.indexOf(`async function ${name}(`);
  assert.ok(start >= 0, `${name} must exist`);
  const next = vote.indexOf("\n  async function ", start + 1);
  assert.ok(next > start, `a following function must bound ${name}`);
  return vote.slice(start, next);
}

describe("prepare_voter_ballot duplicate-prepare guard", () => {
  it("uses a module-level observable store (survives Vote unmount/remount)", () => {
    // Module scope (outside the component), so a remount cannot reset it.
    assert.match(vote, /\nconst prepareInFlightStore = \(\(\) => \{/);
    // The bare boolean tracker it replaced is fully gone.
    assert.doesNotMatch(vote, /prepareVoterBallotInFlight/);
  });

  it("refuses a second prepare while one is already in flight", () => {
    const body = asyncFunctionBody("onGenerateProof");
    assert.match(body, /if \(prepareInFlightStore\.getSnapshot\(\)\) return;/);
  });

  it("sets the guard BEFORE the awaited invoke and clears it ONLY in finally", () => {
    const body = asyncFunctionBody("onGenerateProof");
    const setTrue = body.indexOf("prepareInFlightStore.set(true);");
    const invoke = body.indexOf("await api.prepareVoterBallot()");
    const finallyIdx = body.indexOf("} finally {");
    const clear = body.indexOf("prepareInFlightStore.set(false);");
    assert.ok(setTrue >= 0, "guard must be set true");
    assert.ok(invoke >= 0, "must await the prepare invoke");
    assert.ok(finallyIdx >= 0, "must have a finally block");
    assert.ok(clear >= 0, "guard must be cleared");
    assert.ok(setTrue < invoke, "guard must be set BEFORE the await");
    assert.ok(clear > finallyIdx, "guard must be cleared inside finally");
    // Cleared exactly once (only in finally).
    assert.equal(
      body.split("prepareInFlightStore.set(false);").length - 1,
      1,
      "the in-flight guard must be cleared exactly once (in finally)",
    );
  });
});

describe("proof action is driven by the prepare store, not shared busy", () => {
  it("mirrors the store into React through useSyncExternalStore", () => {
    assert.match(
      vote,
      /useSyncExternalStore\(\s*prepareInFlightStore\.subscribe,\s*prepareInFlightStore\.getSnapshot,\s*\)/,
    );
  });

  it("gates the Create-proof button on preparingProof + backend authority (never busy)", () => {
    // The button's disabled expression uses the dedicated preparing indicator
    // and the backend flags — and specifically NOT the shared `busy`.
    assert.match(
      vote,
      /disabled=\{\s*preparingProof \|\|\s*!workflow\?\.can_prepare_ballot \|\|\s*workflow\?\.prepared_ballot\.state === "Ready"\s*\}/,
    );
  });

  it("shows the Creating… notice from preparingProof, not busy", () => {
    assert.match(
      vote,
      /\{preparingProof && workflow\?\.prepared_ballot\.state !== "Ready" && \(/,
    );
  });

  it("never fabricates backend can_prepare_ballot on the frontend", () => {
    assert.doesNotMatch(vote, /can_prepare_ballot\s*=\s*true/);
  });
});

describe("selection changes cannot leave busy stuck true", () => {
  it("setBackendSelection releases busy unconditionally in finally", () => {
    const body = asyncFunctionBody("setBackendSelection");
    // The finally block resets busy with no gate guard on the reset itself.
    assert.match(body, /\} finally \{[\s\S]*?\n {6}setBusy\(false\);\n {4}\}/);
    // The previous, defective guarded reset must be gone.
    assert.doesNotMatch(body, /isCurrent\([^)]*\)\)\s*setBusy\(false\)/);
  });

  it("still gates STALE STATE writes with the monotonic token", () => {
    // The fix only frees the busy reset; the gate must still protect the
    // authoritative state writes against stale/reordered responses.
    const body = asyncFunctionBody("setBackendSelection");
    assert.match(body, /selectionStatusGateRef\.current\.begin\(\)/);
    const guard = body.indexOf("isCurrent(");
    const firstWrite = body.indexOf("setSelection(");
    assert.ok(guard >= 0 && firstWrite >= 0, "guards and writes present");
    assert.ok(guard < firstWrite, "stale responses drop before writing state");
  });
});

describe("remount does not force or leak busy from the prepare guard", () => {
  it("the workflow-restore effect no longer force-sets busy from a tracker", () => {
    // The store (via useSyncExternalStore) keeps the button disabled across a
    // remount; manually restoring busy would leak it (the previous instance's
    // finally clears only its own state), so it must not be done here.
    const effectStart = vote.indexOf(
      "if (election && shellAvailable) void refreshWorkflow(false);",
    );
    assert.ok(effectStart >= 0, "workflow-restore effect present");
    const effect = vote.slice(effectStart, effectStart + 200);
    assert.doesNotMatch(effect, /setBusy\(true\)/);
  });
});

describe("temporary liveness instrumentation is removed", () => {
  it("the frontend prepare trace/breadcrumbs are gone", () => {
    assert.doesNotMatch(vote, /prepareTrace/);
    assert.doesNotMatch(vote, /PREPARE_PAGE_GENERATION|VOTE_MODULE_GENERATION/);
  });

  it("the Rust durable trace writer and startup sentinel are gone", () => {
    assert.doesNotMatch(lib, /prepare_lock_trace/);
    assert.doesNotMatch(lib, /prepare_trace_sender/);
    assert.doesNotMatch(lib, /tari-ballot-prepare-trace/);
  });

  it("keeps the genuine prepare lock-order hardening", () => {
    // The lock-order liveness contract (resolve cast_locks_dir on the async
    // thread before spawn_blocking; slot -> session -> voter) must remain.
    assert.match(lib, /LOCK-ORDER LIVENESS/);
    assert.match(lib, /state\.preparation_slot\.lock\(\)/);
  });
});
