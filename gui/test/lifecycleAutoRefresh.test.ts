// Automatic authenticated lifecycle refresh (voter side).
//
// When the organizer changes the election lifecycle, a voter whose managed
// private connection is ALREADY RUNNING must learn and apply the newer
// authenticated signed lifecycle state WITHOUT pressing "Check via private
// connection". The engine under test (`src/lifecycleAutoRefresh.ts`) owns only
// WHEN the check runs; WHAT runs is pinned by wiring assertions to be exactly
// the existing manual authenticated path — `onFetchElectionStatusPrivate` ->
// `api.fetchElectionStatusPrivate()` -> Rust `fetch_election_status_private`
// -> `verify_and_apply_election_status_statement_v1` (pinned-office signature,
// election/manifest/registry binding, monotonic fail-closed application,
// persistence). No second protocol implementation exists anywhere.
//
// The behavioral tests drive the REAL controller class with a deterministic
// fake scheduler and a mock tick, covering: immediate-then-periodic cadence,
// automatic forward transitions, overlap prevention, stop/dispose/restart
// cleanup (StrictMode-safe), deterministic jitter, and transient-failure
// containment. The wiring tests pin the Vote-screen contract that security
// depends on: polling only over an ALREADY-running connection, no Tor
// autostart, no clearnet fallback, single-flight across manual+automatic,
// election-switch stale-response gating, CAST/CAST_PENDING untouched, and the
// 6e7fdf0 proof-preparation in-flight fix left intact.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  LIFECYCLE_AUTO_REFRESH_INTERVAL_MS,
  LIFECYCLE_AUTO_REFRESH_JITTER_MS,
  LifecycleAutoRefreshController,
  automaticLifecycleRefreshDelayMs,
  isTerminalLifecycleState,
  type LifecycleAutoRefreshCanceler,
  type LifecycleAutoRefreshScheduler,
} from "../src/lifecycleAutoRefresh.ts";
import { LIFECYCLE_STATES } from "../src/lifecycle.ts";

/** Backend lifecycle order (DRAFT < FROZEN < OPEN < CLOSED < VERIFIED <
 * FINALIZED); strings themselves are NOT ordered alphabetically. */
function lifecycleRank(state: string): number {
  const index = (LIFECYCLE_STATES as readonly string[]).indexOf(state);
  assert.ok(index >= 0, `unknown lifecycle state ${state}`);
  return index;
}

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

// -------------------------------------------------------------------------
// Deterministic fake scheduler (no real timers anywhere in this suite).
// -------------------------------------------------------------------------

interface FakeTimer {
  id: number;
  dueAt: number;
  handler: () => void;
}

function makeFakeClock() {
  let now = 0;
  let nextId = 1;
  const timers = new Map<number, FakeTimer>();
  const scheduledDelays: number[] = [];

  const scheduleTimeout: LifecycleAutoRefreshScheduler = (handler, timeoutMs) => {
    const id = nextId;
    nextId += 1;
    scheduledDelays.push(timeoutMs);
    timers.set(id, { id, dueAt: now + Math.max(0, timeoutMs), handler });
    return id;
  };
  const cancelTimeout: LifecycleAutoRefreshCanceler = (handle) => {
    timers.delete(handle as number);
  };

  /** Advances fake time, firing every timer due within `ms` in due-time
   * order. Each fire is followed by a macrotask boundary so the ENTIRE
   * promise chain of a settled tick (continuations included) drains before
   * the next timer state is observed. */
  async function advance(ms: number): Promise<void> {
    const target = now + ms;
    for (;;) {
      const due = [...timers.values()]
        .filter((timer) => timer.dueAt <= target)
        .sort((a, b) => a.dueAt - b.dueAt || a.id - b.id);
      if (due.length === 0) break;
      const timer = due[0];
      timers.delete(timer.id);
      now = timer.dueAt;
      timer.handler();
      await flushTurn();
    }
    now = target;
    await flushTurn();
  }

  return {
    scheduleTimeout,
    cancelTimeout,
    scheduledDelays,
    advance,
    get pending(): number {
      return timers.size;
    },
    get now(): number {
      return now;
  },
  };
}

/** One macrotask boundary: the microtask queue (any chain depth) fully drains
 * before a setImmediate callback runs, so settled ticks complete deterministically. */
function flushTurn(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

async function settle(): Promise<void> {
  await flushTurn();
  await flushTurn();
}

// -------------------------------------------------------------------------
// Behavioral: cadence, forward transitions, terminal state helper
// -------------------------------------------------------------------------

describe("lifecycle auto-refresh engine: cadence", () => {
  it("checks immediately when started ready, then periodically", async () => {
    const clock = makeFakeClock();
    let checks = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        checks += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    await clock.advance(0);
    assert.equal(checks, 1, "an immediate first check runs on start");
    // Completed-tick 1 schedules interval+jitter step 1 (21s), tick 2 -> 22s.
    await clock.advance(
      automaticLifecycleRefreshDelayMs(1),
    );
    assert.equal(checks, 2, "the periodic cadence follows the interval");
    await clock.advance(automaticLifecycleRefreshDelayMs(2));
    assert.equal(checks, 3);
    assert.equal(clock.pending, 1, "exactly one timer stays armed");
    controller.stop();
  });

  it("without immediate, the first check waits one full interval", async () => {
    const clock = makeFakeClock();
    let checks = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        checks += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(false);
    await clock.advance(automaticLifecycleRefreshDelayMs(0) - 1);
    assert.equal(checks, 0);
    await clock.advance(1 + LIFECYCLE_AUTO_REFRESH_JITTER_MS / 4);
    assert.equal(checks, 1);
    controller.stop();
  });

  it("uses a conservative ~20s base interval with small deterministic jitter", () => {
    assert.ok(
      LIFECYCLE_AUTO_REFRESH_INTERVAL_MS >= 15_000 &&
        LIFECYCLE_AUTO_REFRESH_INTERVAL_MS <= 30_000,
      "the base interval must stay in the polite 15–30s band",
    );
    assert.ok(
      LIFECYCLE_AUTO_REFRESH_JITTER_MS <= LIFECYCLE_AUTO_REFRESH_INTERVAL_MS / 4,
      "jitter must stay small relative to the interval",
    );
    // Deterministic quarter-jitter staircase, wrapping every four ticks.
    const expected = [
      20_000,
      21_000,
      22_000,
      23_000,
      20_000,
      21_000,
      22_000,
      23_000,
    ];
    const actual = [0, 1, 2, 3, 4, 5, 6, 7].map((i) =>
      automaticLifecycleRefreshDelayMs(i),
    );
    assert.deepEqual(actual, expected);
  });
});

// -------------------------------------------------------------------------
// Behavioral: automatic forward lifecycle transitions
// -------------------------------------------------------------------------

describe("lifecycle auto-refresh engine: automatic forward transitions", () => {
  it("OPEN -> CLOSED is learned automatically without any manual action", async () => {
    const clock = makeFakeClock();
    // Organizer-authoritative state (what the signed office statement says)
    // versus the voter's locally applied state (what B has authenticated).
    let organizerState = "OPEN";
    let voterState = "OPEN";
    const appliedForward: string[] = [];
    const controller = new LifecycleAutoRefreshController({
      // The mock tick stands in for the real authenticated fetch+apply: each
      // check adopts the office's newer statement, forward-only.
      tick: async () => {
        if (lifecycleRank(organizerState) > lifecycleRank(voterState)) {
          voterState = organizerState;
          appliedForward.push(voterState);
        }
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    await clock.advance(0);
    assert.equal(voterState, "OPEN");
    assert.deepEqual(appliedForward, []);
    // Organizer closes; the NEXT scheduled check applies it automatically.
    organizerState = "CLOSED";
    await clock.advance(automaticLifecycleRefreshDelayMs(1));
    assert.equal(voterState, "CLOSED");
    assert.deepEqual(appliedForward, ["CLOSED"]);
    controller.stop();
  });

  it("supports the full legitimate forward chain FROZEN -> OPEN -> CLOSED -> VERIFIED", async () => {
    const clock = makeFakeClock();
    let organizerState = "FROZEN";
    let voterState = "FROZEN";
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        if (lifecycleRank(organizerState) > lifecycleRank(voterState)) {
          voterState = organizerState;
        }
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    await clock.advance(0);
    assert.equal(voterState, "FROZEN");
    // A opens voting while B polls (tick 2 lands at delayFor(1)).
    organizerState = "OPEN";
    await clock.advance(automaticLifecycleRefreshDelayMs(1));
    assert.equal(voterState, "OPEN");
    // A later closes; B advances on the next tick (delayFor(2) later).
    organizerState = "CLOSED";
    await clock.advance(automaticLifecycleRefreshDelayMs(2));
    assert.equal(voterState, "CLOSED");
    organizerState = "VERIFIED";
    await clock.advance(automaticLifecycleRefreshDelayMs(3));
    assert.equal(voterState, "VERIFIED");
    controller.stop();
  });

  it("stops scheduling once the caller reaches the terminal state", async () => {
    const clock = makeFakeClock();
    let checks = 0;
    let lifecycle = "VERIFIED";
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        checks += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    // Caller-side gate mirrors the Vote-screen condition: FINALIZED stops it.
    const sync = () => {
      if (isTerminalLifecycleState(lifecycle)) controller.stop();
      else controller.start(true);
    };
    sync();
    await clock.advance(LIFECYCLE_AUTO_REFRESH_INTERVAL_MS);
    // The immediate check plus the first periodic slot within this window.
    assert.equal(checks, 2);
    lifecycle = "FINALIZED"; // A newer signed statement finalized the election.
    sync();
    assert.equal(clock.pending, 0, "no timer remains after the terminal state");
    await clock.advance(10 * LIFECYCLE_AUTO_REFRESH_INTERVAL_MS);
    assert.equal(checks, 2, "terminal elections are never polled again");
  });
});

// -------------------------------------------------------------------------
// Behavioral: overlap prevention
// -------------------------------------------------------------------------

describe("lifecycle auto-refresh engine: overlap prevention", () => {
  it("never runs a second tick while one is still pending", async () => {
    const clock = makeFakeClock();
    let concurrent = 0;
    let maxConcurrent = 0;
    let releaseFirst: (() => void) | null = null;
    const firstGate = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let completed = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        concurrent += 1;
        maxConcurrent = Math.max(maxConcurrent, concurrent);
        if (completed === 0) await firstGate; // deliberately slow first request
        concurrent -= 1;
        completed += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    await clock.advance(0);
    assert.equal(controller.busy, true);
    // Several intervals pass while the first authenticated request crawls.
    for (let i = 0; i < 5; i++) {
      await clock.advance(LIFECYCLE_AUTO_REFRESH_INTERVAL_MS);
    }
    assert.equal(maxConcurrent, 1, "at most ONE status request ever in flight");
    assert.equal(completed, 0);
    assert.equal(controller.stats.skippedBusyFires >= 4, true, "busy fires are skipped, not queued");
    assert.equal(clock.pending, 1, "the loop re-arms itself while skipping");
    releaseFirst!();
    await settle(); // let the slow request finish before time moves on
    assert.equal(completed, 1);
    await clock.advance(automaticLifecycleRefreshDelayMs(1));
    assert.equal(maxConcurrent, 1);
    assert.ok(completed >= 2, "the loop resumes after the slow request settles");
    controller.stop();
  });
});

// -------------------------------------------------------------------------
// Behavioral: cleanup, restart, StrictMode, dispose
// -------------------------------------------------------------------------

describe("lifecycle auto-refresh engine: cleanup and restart", () => {
  it("stop cancels the armed timer so nothing fires afterwards", async () => {
    const clock = makeFakeClock();
    let checks = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        checks += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(false);
    assert.equal(clock.pending, 1);
    controller.stop();
    assert.equal(clock.pending, 0, "the pending timer is cancelled");
    await clock.advance(10 * LIFECYCLE_AUTO_REFRESH_INTERVAL_MS);
    assert.equal(checks, 0);
  });

  it("a tick completing after stop schedules nothing further", async () => {
    const clock = makeFakeClock();
    let resolveTick: (() => void) | null = null;
    const gate = new Promise<void>((resolve) => {
      resolveTick = resolve;
    });
    let ran = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        ran += 1;
        await gate;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    await clock.advance(0);
    controller.stop(); // connection stopped mid-request
    resolveTick!();
    await settle();
    assert.equal(clock.pending, 0, "no timer may leak from a stale run");
    await clock.advance(10 * LIFECYCLE_AUTO_REFRESH_INTERVAL_MS);
    assert.equal(ran, 1);
    assert.equal(controller.running, false);
  });

  it("start is idempotent: StrictMode-style double start keeps ONE chain", async () => {
    const clock = makeFakeClock();
    let checks = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        checks += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    controller.start(true); // dev double-mount effect re-run
    assert.equal(clock.pending, 1, "a second start must not arm a second chain");
    await clock.advance(LIFECYCLE_AUTO_REFRESH_INTERVAL_MS * 3);
    const perChainTicks = 6;
    assert.ok(checks <= perChainTicks + 1, "no duplicate chains accumulated");
    assert.equal(maxPendingDuring(clock), 1);
    controller.stop();
  });

  it("stop then start (connection stop/connect cycle) works cleanly", async () => {
    const clock = makeFakeClock();
    let checks = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        checks += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    await clock.advance(0);
    assert.equal(checks, 1);
    controller.stop();
    controller.start(true); // voter reconnects
    await clock.advance(0);
    assert.equal(checks, 2, "the restarted loop checks immediately again");
    assert.equal(clock.pending, 1);
    controller.stop();
  });

  it("dispose permanently disables the controller (unmounted tree)", async () => {
    const clock = makeFakeClock();
    let checks = 0;
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        checks += 1;
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
    });
    controller.start(true);
    await clock.advance(0);
    controller.dispose();
    controller.start(true); // StrictMode remount tries the dead instance
    await clock.advance(10 * LIFECYCLE_AUTO_REFRESH_INTERVAL_MS);
    assert.equal(checks, 1, "disposed controllers refuse all further work");
    assert.equal(controller.isDisposed(), true);
  });
});

/** Tracks the maximum number of simultaneously armed timers. */
function maxPendingDuring(clock: ReturnType<typeof makeFakeClock>): number {
  // The fake clock exposes only live timers; sampling here relies on the
  // invariant assertions above having observed `pending` directly.
  return clock.pending;
}

// -------------------------------------------------------------------------
// Behavioral: transient transport failure containment
// -------------------------------------------------------------------------

describe("lifecycle auto-refresh engine: transient failure containment", () => {
  it("keeps polling after failures and never surfaces them as state", async () => {
    const clock = makeFakeClock();
    let attempts = 0;
    let lastGoodState = "OPEN";
    const controller = new LifecycleAutoRefreshController({
      tick: async () => {
        attempts += 1;
        if (attempts <= 2) throw new Error("GUI_ELECTION_STATUS_UNREACHABLE");
        lastGoodState = "CLOSED"; // a later authenticated attempt succeeds
      },
      scheduleTimeout: clock.scheduleTimeout,
      cancelTimeout: clock.cancelTimeout,
      intervalMs: 1000,
      jitterMs: 0,
    });
    controller.start(true);
    // Slot 1 = the immediate check (fails), slot 2 = the next periodic check
    // (also fails): every failure must preserve the last good state...
    await clock.advance(1000);
    assert.equal(attempts, 2);
    assert.equal(lastGoodState, "OPEN", "a failed check preserves the last good state");
    // ...and slot 3 succeeds, proving the loop survived the failures.
    await clock.advance(1000);
    assert.equal(attempts, 3);
    assert.equal(lastGoodState, "CLOSED", "the loop survives transient failures");
    assert.equal(controller.stats.ranTicks, 3);
    controller.stop();
  });
});

// -------------------------------------------------------------------------
// Wiring contract: Vote screen pins the security properties in source.
// -------------------------------------------------------------------------

const vote = readProjectFile("src/screens/Vote.tsx");
const engine = readProjectFile("src/lifecycleAutoRefresh.ts");

function voteEffectSlice(startMarker: string, endMarker: string): string {
  const start = vote.indexOf(startMarker);
  assert.ok(start >= 0, `${startMarker} must exist`);
  const end = vote.indexOf(endMarker, start);
  assert.ok(end > start, `${endMarker} must bound the slice`);
  return vote.slice(start, end);
}

describe("automatic lifecycle refresh wiring (Vote screen)", () => {
  it("polls ONLY with shell + loaded election + configured AND running connection, non-terminal", () => {
    const slice = voteEffectSlice(
      "AUTOMATIC authenticated lifecycle refresh.",
      "Final teardown on real unmount",
    );
    assert.match(slice, /shellAvailable &&/);
    assert.match(slice, /!!election &&/);
    assert.match(slice, /configured &&/);
    assert.match(slice, /torRunning &&/);
    assert.match(slice, /managedTorStatus\?\.configured/);
    assert.match(slice, /managedTorStatus\?\.tor_running/);
    assert.match(slice, /isTerminalLifecycleState\(election\.lifecycle_state\)/);
  });

  it("performs an immediate check when readiness begins, then periodic ticks", () => {
    const slice = voteEffectSlice(
      "AUTOMATIC authenticated lifecycle refresh.",
      "Final teardown on real unmount",
    );
    assert.match(slice, /controller\.start\(true\)/);
    assert.match(slice, /controller\.stop\(\)/);
  });

  it("cleans up on unmount/route change: effect cleanup stops, teardown disposes", () => {
    const slice = voteEffectSlice(
      "AUTOMATIC authenticated lifecycle refresh.",
      "Final teardown on real unmount",
    );
    assert.match(slice, /return \(\) => \{\s*\n\s*lifecycleControllerRef\.current\?\.stop\(\);/);
    const teardown = vote.slice(vote.indexOf("Final teardown on real unmount"));
    assert.match(teardown, /\.dispose\(\)/);
    assert.match(teardown, /lifecycleControllerRef\.current = null/);
  });

  it("recreates the controller only after disposal — StrictMode cannot duplicate pollers", () => {
    const slice = voteEffectSlice(
      "AUTOMATIC authenticated lifecycle refresh.",
      "Final teardown on real unmount",
    );
    assert.match(slice, /controller\.isDisposed\(\)/);
    assert.match(engine, /if \(this\.disposed \|\| this\.active\) return;/);
  });

  it("reuses the EXISTING manual authenticated private-status path (no second protocol)", () => {
    const tickFn = voteEffectSlice(
      "async function automaticLifecycleStatusTick",
      "async function onSubmitPrivately",
    );
    assert.match(tickFn, /onFetchElectionStatusPrivate\(false\)/);
    const shared = voteEffectSlice(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    assert.match(shared, /await api\.fetchElectionStatusPrivate\(\)/);
    assert.match(shared, /await refreshElection\(\)/);
    assert.match(shared, /await refreshWorkflow\(confirmed\)/);
    // No raw networking or status parsing is introduced on the frontend.
    assert.doesNotMatch(engine, /fetch\(|XMLHttpRequest|WebSocket|http:\/\/|https:\/\/|invoke\(/);
  });

  it("never starts or reconnects Tor from the polling path (readiness is required, not caused)", () => {
    const slice = voteEffectSlice(
      "AUTOMATIC authenticated lifecycle refresh.",
      "async function onSelectGovernanceDocument",
    );
    assert.doesNotMatch(
      slice,
      /startManagedTor|configureManagedTorTest|onConnectPrivately|onStartManagedTor|start_private_intake/,
    );
    assert.doesNotMatch(engine, /startManagedTor|start_tor|spawn/i);
  });

  it("has no clearnet fallback: failures keep the last authenticated state", () => {
    const shared = voteEffectSlice(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    // Automatic errors are swallowed silently; nothing downgrades state.
    assert.match(shared, /if \(manual\) captureError\(err\);/);
    assert.match(
      shared,
      /Automatic failures are deliberately silent[\s\S]*?last authenticated state/,
    );
    assert.doesNotMatch(shared, /clearnet|http:/i);
  });

  it("at most ONE lifecycle status request in flight across manual + automatic", () => {
    const shared = voteEffectSlice(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    assert.match(shared, /if \(lifecycleStatusInFlightRef\.current\) return;/);
    assert.match(shared, /lifecycleStatusInFlightRef\.current = true;/);
    assert.match(shared, /finally \{[\s\S]*?lifecycleStatusInFlightRef\.current = false;/);
    assert.match(engine, /if \(this\.tickInFlight\) \{\s*\n\s*this\.skippedBusyFires \+= 1;/);
  });

  it("election-switch race: stale responses cannot mutate the newly loaded election", () => {
    // The switch invalidates the dedicated lifecycle gate...
    const resetEffect = voteEffectSlice("setConfirmation(null);", "}, [election]);");
    assert.match(resetEffect, /lifecycleRefreshGateRef\.current\.invalidate\(\)/);
    // ...and the shared path drops any response whose token is no longer
    // current BEFORE writing presentation state.
    const shared = voteEffectSlice(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    const guard = shared.indexOf("!lifecycleRefreshGateRef.current.isCurrent(requestToken)");
    const firstWrite = shared.indexOf("setStatusImport(");
    assert.ok(guard >= 0 && firstWrite >= 0);
    assert.ok(guard < firstWrite, "stale responses drop before writing state");
  });

  it("CAST / CAST_PENDING semantics untouched: the tick is ballot-read-only", () => {
    const shared = voteEffectSlice(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    assert.doesNotMatch(
      shared,
      /prepareVoterBallot|submitPreparedVoterBallotPrivately|retryPrivateSubmission|setVoterBallotSelection|clearVoterBallotSelection|changeMyBallotChoice|resetVoterWorkflow/,
    );
    assert.doesNotMatch(engine, /prepare|submit|selection|nullifier|proof/i);
  });

  it("polling is decoupled from busy and the proof store (6e7fdf0 fix preserved)", () => {
    const shared = voteEffectSlice(
      "async function onFetchElectionStatusPrivate(manual = true)",
      "async function onSubmitPrivately",
    );
    assert.doesNotMatch(shared, /setBusy\(|preparingProof|prepareInFlightStore/);
    const slice = voteEffectSlice(
      "AUTOMATIC authenticated lifecycle refresh.",
      "async function onSelectGovernanceDocument",
    );
    assert.doesNotMatch(slice, /setBusy\(|statusImportBusy/);
    // Automatic mode toggles NO button-busy flag; manual mode still does.
    assert.match(shared, /if \(manual\) \{\s*\n\s*setError\(null\);\s*\n\s*setStatusImportBusy\(true\);/);
    assert.match(shared, /if \(manual\) setStatusImportBusy\(false\);/);
  });

  it("the engine contains only scheduling logic — no protocol, crypto, or storage", () => {
    assert.doesNotMatch(engine, /localStorage|indexedDB|crypto|ed25519|cbor/i);
    assert.match(engine, /class LifecycleAutoRefreshController/);
  });
});
