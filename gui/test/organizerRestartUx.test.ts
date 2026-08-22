// Organizer-restart / onion-reachability UX honesty tests.
//
// Real Crash-Test-3 rerun proved the durable CAST_PENDING + exact-retry path
// works: after the ballot office restarted its Tor intake, the SAME locked
// ballot eventually succeeded once the hidden-service descriptor had been
// re-published (observed to take up to ~1 minute). The app has NO reliable
// end-to-end onion-reachability signal (no Tor control port / HS_DESC events),
// so it must (a) NOT claim proven remote reachability, and (b) tolerate the
// republication latency with a bounded, restart-aware retry schedule while a
// recoverable CAST_PENDING ballot is never shown as a scary terminal error.
//
// The ballot protocol, exact-retry security model, and CAST_PENDING durability
// are unchanged — this is a wording + retry-timing repair only.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS,
  privateSubmissionStatus,
} from "../src/privateSubmission.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const manage = readProjectFile("src/screens/ManageElection.tsx");
const vote = readProjectFile("src/screens/Vote.tsx");

// -------------------------------------------------------------------------
// Organizer: "running" (local) never implies proven remote reachability.
// -------------------------------------------------------------------------

describe("organizer intake readiness is honest about reachability", () => {
  it("labels a running intake as running (local), not remotely reachable", () => {
    assert.match(manage, /<Pill tone="ok">Running ✓<\/Pill>/);
    assert.doesNotMatch(manage, /<Pill tone="ok">Ready ✓<\/Pill>/);
    assert.match(manage, /Private receiver running \(local\)/);
  });

  it("explains the private address may take time to become reachable after (re)start", () => {
    // The honest note sets expectations: local readiness is confirmed; remote
    // reachability may lag briefly after a restart, and the voter's ballot stays
    // safely locked meanwhile.
    assert.match(manage, /take a short\s+time[\s\S]*?become reachable by voters/);
    assert.match(manage, /stays safely locked/);
  });

  it("does not claim a proven end-to-end / global onion reachability signal", () => {
    assert.doesNotMatch(manage, /reachable by everyone|globally reachable|confirmed reachable/i);
  });
});

// -------------------------------------------------------------------------
// Voter: recoverable CAST_PENDING wording is calm and restart-aware.
// -------------------------------------------------------------------------

describe("voter CAST_PENDING wording is calm and restart-aware", () => {
  const pending = privateSubmissionStatus({
    castState: "CAST_PENDING",
    configured: true,
    torRunning: true,
    busy: false,
    lastReceiptState: null,
  });

  it("is a warning (recoverable), never a scary terminal error", () => {
    assert.equal(pending.phase, "PENDING");
    assert.equal(pending.tone, "warn");
    assert.notEqual(pending.tone, "error");
    assert.equal(pending.title, "Delivery wasn't confirmed");
  });

  it("explains the ballot is locked, the office may be briefly unreachable, and no new ballot", () => {
    assert.match(pending.detail, /safely locked/);
    assert.match(pending.detail, /not reachable yet/);
    assert.match(pending.detail, /restarts its private connection/);
    assert.match(pending.detail, /no new ballot/i);
  });

  it("distinguishes LOCAL private connection readiness from ballot-office reachability", () => {
    const ready = privateSubmissionStatus({
      castState: "NOT_CAST",
      configured: true,
      torRunning: true,
      busy: false,
      lastReceiptState: null,
    });
    assert.equal(ready.phase, "READY");
    assert.match(ready.title, /Local private connection ready/);
    // It must not promise the ballot office is definitely reachable.
    assert.doesNotMatch(ready.detail, /ballot office is reachable|definitely reachable/i);
  });

  it("keeps a durable CAST as the only success and never downgrades a pending to error", () => {
    const cast = privateSubmissionStatus({
      castState: "CAST",
      configured: true,
      torRunning: false,
      busy: false,
      lastReceiptState: null,
    });
    assert.equal(cast.phase, "SUCCESS");
    assert.equal(cast.tone, "ok");
  });
});

// -------------------------------------------------------------------------
// Retry policy: bounded, restart-aware, still terminating.
// -------------------------------------------------------------------------

describe("bounded restart-aware retry policy", () => {
  it("has quick then slower delays and remains finite", () => {
    assert.deepEqual(
      [...PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS],
      [2000, 5000, 8000, 15000, 30000],
    );
  });

  it("the auto-retry banner explains restart latency and that no new ballot is created", () => {
    assert.match(vote, /isn&rsquo;t reachable yet/);
    assert.match(vote, /waits a little longer between later\s*\n?\s*retries/);
    assert.match(vote, /never creates\s*\n?\s*another vote/);
    // Stop retrying remains available throughout.
    assert.match(vote, /Stop retrying/);
    assert.match(vote, /onStopAutoRetry/);
  });
});
