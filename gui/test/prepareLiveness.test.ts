// prepare_voter_ballot liveness — boundary invariants + diagnostic instrumentation.
//
// Physical failure (two-computer-try-03): on Computer B the voter clicks
// "Create anonymous eligibility proof" once, the button shows "Creating your
// anonymous eligibility proof…" and then stays disabled with zero CPU; no
// `[prepare_voter_ballot]` line appeared in the console. Navigating
// Vote -> Settings -> Vote re-enables the button while the prepared ballot
// stays cleared.
//
// This suite pins the invariants the forensic review established, so a future
// edit cannot silently regress them:
//
//  1. FRONTEND CONCURRENCY GUARD. A module-level in-flight tracker is set
//     BEFORE the awaited invoke and cleared ONLY in `finally`, and a second
//     click is refused while it is set. Because routing is React `useState`
//     (no router, no reload) and a route change never re-evaluates the module,
//     this tracker persists across a Vote unmount/remount. The button can still
//     LOOK enabled if another mount-time operation clears shared `busy`; that
//     appearance does NOT prove the invoke settled, and the guard still refuses
//     a duplicate click.
//  2. REMOUNT RESTORE ATTEMPT. On remount the tracker sets `busy`; diagnostics
//     explicitly expose any later shared-busy clobber while prepare is live.
//  3. DURABLE BACKEND TRACE. `prepare_lock_trace` sends to a dedicated writer
//     thread with bounded `try_send`, so command/worker threads never perform
//     trace file I/O. A startup sentinel makes sink failure distinguishable
//     from absent command entry. It stays dev-only and secret-free.
//  4. FRONTEND BREADCRUMBS. Dev-only lifecycle breadcrumbs include separate
//     page-realm and module-evaluation identities, shared-busy state, and every
//     await after the prepare invoke.
//
// Source-assertion tests (no React mount harness exists — ADR-0007). Backend
// gating semantics remain covered by the gui-core shell regression tests.
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

/** The exact body of `onGenerateProof`, isolated so ordering assertions cannot
 *  accidentally match text elsewhere in the file. */
function onGenerateProofBody(): string {
  const start = vote.indexOf("async function onGenerateProof()");
  assert.ok(start >= 0, "onGenerateProof must exist");
  // The next top-level `async function ` after it bounds the body.
  const next = vote.indexOf("\n  async function ", start + 1);
  assert.ok(next > start, "a following function must bound onGenerateProof");
  return vote.slice(start, next);
}

describe("prepare_voter_ballot frontend concurrency guard", () => {
  it("keeps a module-level in-flight tracker (survives Vote unmount/remount)", () => {
    // Module scope (outside the component), so a remount cannot reset it.
    assert.match(vote, /\nlet prepareVoterBallotInFlight = false;/);
  });

  it("refuses a second prepare while one is already in flight", () => {
    const body = onGenerateProofBody();
    assert.match(body, /if \(prepareVoterBallotInFlight\)\s*\{[\s\S]*?return;/);
  });

  it("sets the tracker BEFORE the awaited invoke and clears it ONLY in finally", () => {
    const body = onGenerateProofBody();
    const setTrue = body.indexOf("prepareVoterBallotInFlight = true;");
    const invoke = body.indexOf("await api.prepareVoterBallot()");
    const finallyIdx = body.indexOf("} finally {");
    const clear = body.indexOf("prepareVoterBallotInFlight = false;");
    assert.ok(setTrue >= 0, "tracker must be set true");
    assert.ok(invoke >= 0, "must await the prepare invoke");
    assert.ok(finallyIdx >= 0, "must have a finally block");
    assert.ok(clear >= 0, "tracker must be cleared");
    assert.ok(setTrue < invoke, "tracker must be set BEFORE the await");
    assert.ok(
      clear > finallyIdx,
      "tracker must be cleared inside finally, not on the success path",
    );
    // The tracker is cleared exactly once (only in finally).
    assert.equal(
      body.split("prepareVoterBallotInFlight = false;").length - 1,
      1,
      "the in-flight tracker must be cleared exactly once (in finally)",
    );
  });

  it("attempts to restore busy on remount while a previous prepare is unresolved", () => {
    assert.match(vote, /if \(prepareVoterBallotInFlight\) setBusy\(true\);/);
  });
});

describe("prepare_voter_ballot durable backend trace", () => {
  it("moves durable file and stderr I/O off command/worker threads", () => {
    assert.match(lib, /tari-ballot-prepare-trace\.log/);
    assert.match(lib, /OpenOptions::new\(\)[\s\S]*?\.append\(true\)/);
    assert.match(lib, /writeln!\(stderr, "\{line\}"\)/);
    assert.match(lib, /std::env::temp_dir\(\)/);
    assert.match(lib, /sync_channel::<String>\(256\)/);
    assert.match(lib, /prepare_trace_sender\(\)\.try_send\(line\)/);
    assert.match(lib, /prepare_lock_trace\("trace sink initialized"\)/);
  });

  it("stays dev-only (a no-op in release builds)", () => {
    // The trace fn and its release no-op must both be gated on debug_assertions.
    assert.match(lib, /#\[cfg\(debug_assertions\)\]\s*\nfn prepare_lock_trace/);
    assert.match(
      lib,
      /#\[cfg\(not\(debug_assertions\)\)\][\s\S]*?fn prepare_lock_trace\(_step: &str\) \{\}/,
    );
  });

  it("records only step/thread/timestamp (no secrets) at the first body statement", () => {
    // The very first executable statement of the async command is the entry
    // trace. With the startup sentinel present, a missing 'command entry' line
    // is strong physical evidence that the body was not entered (the trace
    // remains best-effort, so absence is not a mathematical proof by itself).
    const cmd = lib.slice(lib.indexOf("async fn prepare_voter_ballot("));
    const firstStmt = cmd.indexOf("prepare_lock_trace(");
    const braceOpen = cmd.indexOf("{");
    assert.ok(firstStmt >= 0 && braceOpen >= 0);
    const prologue = cmd.slice(braceOpen, firstStmt);
    // Nothing but the opening brace/whitespace precedes the entry trace.
    assert.match(prologue, /^\{\s*$/);
    assert.match(cmd, /prepare_lock_trace\("command entry \(async thread\)"\)/);
  });
});

describe("prepare_voter_ballot frontend breadcrumbs (dev-only)", () => {
  it("distinguishes page-realm reload from module re-evaluation", () => {
    assert.match(vote, /const PREPARE_PAGE_GENERATION\s*=/);
    assert.match(vote, /performance\.timeOrigin/);
    assert.match(vote, /const VOTE_MODULE_GENERATION = /);
    assert.match(vote, /prepareTrace\("Vote module evaluated"\)/);
  });

  it("is gated on dev builds and prints no secrets", () => {
    // Only step names, an op counter, the generation id, and a timing are
    // logged — never proof/credential/nullifier/ballot material.
    assert.match(vote, /if \(!env\?\.DEV\) return;/);
    assert.match(vote, /\[prepare-trace\]/);
  });

  it("breadcrumbs each await plus mount/unmount and shared-busy state", () => {
    const body = onGenerateProofBody();
    assert.match(body, /prepareTrace\("onGenerateProof: entered"/);
    assert.match(body, /prepareTrace\("before api\.prepareVoterBallot \(invoke\)"/);
    assert.match(body, /prepareTrace\("invoke resolved"/);
    assert.match(body, /prepareTrace\("invoke rejected \(catch\)"/);
    assert.match(body, /prepareTrace\("finally/);
    assert.match(body, /prepareTrace\("before refreshWorkflow"/);
    assert.match(body, /prepareTrace\("after refreshManagedTorStatus"/);
    assert.match(vote, /prepareTrace\(`Vote mounted \(inFlight=/);
    assert.match(vote, /prepareTrace\(`Vote unmounted \(inFlight=/);
    assert.match(vote, /prepare UI state \(busy=/);
  });
});
