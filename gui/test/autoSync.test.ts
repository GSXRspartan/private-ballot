// Phase D — bounded automatic inbox sync (frontend surface).
//
// Auto-sync must reuse the SAME authoritative sync_private_intake path, run only
// while an election is loaded + voting is OPEN + a ready intake worker is bound
// to this election, avoid a busy loop, and keep the manual Sync button. Source-
// assertion tests (no React harness).
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const manage = readProjectFile("src/screens/ManageElection.tsx");

describe("bounded automatic inbox sync", () => {
  it("reuses the authoritative sync_private_intake path (no second writer)", () => {
    // Auto-sync calls the same client method the manual button uses.
    assert.match(manage, /autoSyncTick/);
    assert.match(manage, /await api\.syncPrivateIntake\(\)/);
  });

  it("runs only while loaded, OPEN, and a ready intake worker is bound here", () => {
    assert.match(manage, /const autoSyncActive =/);
    assert.match(manage, /lifecycle === "OPEN"/);
    assert.match(manage, /organizerStatus\?\.intake_running/);
    assert.match(manage, /organizerStatus\?\.election_bound/);
  });

  it("uses a fixed interval and an in-flight guard, not a tight loop", () => {
    assert.match(manage, /setInterval\(/);
    assert.match(manage, /clearInterval\(/);
    assert.match(manage, /autoSyncBusyRef/);
  });

  it("reconciles on first observation, then on each new acceptance", () => {
    // First-observation reconciliation is the restart/first-mount fix: the Tor
    // worker counter restarts at 0, so a durable inbox package accepted before
    // restart would never trigger a delta. The tick reconciles when prev is null
    // OR when the worker reports an increase; the authoritative sync is
    // idempotent and writes a revision only on a NEW acceptance, so this never
    // double-counts or churns revisions.
    assert.match(manage, /prevAcceptedRef/);
    assert.match(manage, /const firstObservation = prev === null/);
    assert.match(manage, /firstObservation \|\| status\.accepted_ballots > prev/);
  });

  it("reconciles a durable inbox package on OPEN election load/restart", () => {
    // A dedicated effect runs one authoritative reconciliation when an OPEN
    // election is loaded/recovered, so a durable package accepted before an app
    // restart is imported even if the Tor intake worker is not running again.
    assert.match(manage, /lifecycle !== "OPEN"/);
    assert.match(manage, /await api\.syncPrivateIntake\(\)/);
    assert.match(manage, /summary\.newly_accepted > 0/);
  });

  it("resets the per-election observation baseline when the election changes", () => {
    assert.match(manage, /prevAcceptedRef\.current = null/);
  });

  it("surfaces auto-sync failures instead of swallowing them", () => {
    const tick = manage.slice(
      manage.indexOf("const autoSyncTick"),
      manage.indexOf("const autoSyncActive"),
    );
    assert.match(tick, /catch \(error\) \{\s*[\s\S]*showError\(error\)/);
  });

  it("keeps the manual Sync accepted ballots button", () => {
    assert.match(manage, /Sync accepted ballots/);
  });
});

describe("intake count presentation is unambiguous", () => {
  it("shows the AUTHORITATIVE election accepted count from participation, not the worker", () => {
    // The authoritative total is the durable election count (participation),
    // which survives restart; it is never the process-local Tor worker counter.
    assert.match(manage, /label="Election accepted ballots"/);
    assert.match(manage, /participation\?\.accepted_ballots/);
  });

  it("labels the Tor worker counter as a per-session receiver count that resets", () => {
    assert.match(manage, /label="Received this intake session"/);
    // The old bare "Accepted ballots" field for the worker count is gone so a
    // worker restart never looks like ballots disappeared.
    assert.doesNotMatch(
      manage,
      /label="Accepted ballots">\{organizerStatus\.accepted_ballots\}/,
    );
    assert.match(manage, /resets\s*\n?\s*to 0 whenever intake restarts/);
  });
});
