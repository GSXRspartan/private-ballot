// Organizer managed-Tor HARD-KILL recovery UX tests.
//
// Root cause of the real Windows blocker: after a Task-Manager hard-kill of the
// app, an orphaned organizer tor.exe kept the lock of the FIXED persistent Tor
// DataDirectory, so a restart's new Tor child exited immediately — yet hostname
// discovery read the PERSISTENT hidden-service `hostname` file and falsely
// reported ready. The status poll then saw the dead child (ready=false) with the
// intake still recorded, and the UI sat in an indefinite "Starting…".
//
// The backend repair (fresh per-start DataDirectory split from the persistent
// hidden-service identity, plus an explicit FAILED status) means the UI must:
//   * expose the new `failed` / `failure_reason` status fields;
//   * show an explicit, recoverable "Could not start" state — never an endless
//     "Starting…" — when a required owned component has died;
//   * offer a one-click Restart (not only a "Stop" against a down service);
//   * keep reassuring the operator that the private address is unchanged.
//
// These are source/type-shape assertions (no real Tor, no network). The ballot
// protocol, receipt/durability ordering, and reachability-honesty wording are
// unchanged — this is a lifecycle + status wording repair only.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const manage = readProjectFile("src/screens/ManageElection.tsx");
const types = readProjectFile("src/api/types.ts");

describe("organizer intake status DTO carries an explicit failed state", () => {
  it("the OrganizerIntakeStatusV1 type exposes failed + failure_reason", () => {
    const dto = types.slice(
      types.indexOf("interface OrganizerIntakeStatusV1"),
      types.indexOf("interface OrganizerIntakeStatusV1") + 900,
    );
    assert.match(dto, /\bfailed:\s*boolean/);
    assert.match(dto, /failure_reason:\s*string\s*\|\s*null/);
  });
});

describe("a hard-killed intake surfaces an explicit, recoverable failure", () => {
  it("renders a distinct error pill for the failed state, checked BEFORE running/starting", () => {
    // The `failed` branch must be evaluated before the `intake_running` branches
    // so a dead child never renders as "Running ✓" or an endless "Starting…".
    const failedIdx = manage.indexOf('organizerStatus.failed ? (');
    const runningIdx = manage.indexOf("organizerStatus.intake_running && organizerStatus.ready");
    const startingIdx = manage.indexOf('<Pill tone="warn">Starting…</Pill>');
    assert.ok(failedIdx > 0, "a failed branch exists");
    assert.ok(runningIdx > failedIdx, "failed is checked before the running pill");
    assert.ok(startingIdx > failedIdx, "failed is checked before the starting pill");
    assert.match(manage, /<Pill tone="error">Could not start<\/Pill>/);
  });

  it("shows a calm error notice that keeps the private address/identity unchanged", () => {
    assert.match(manage, /Private intake could not start/);
    assert.match(manage, /private address and receiver\s*\n?\s*are safe and unchanged/);
    // The bounded diagnostic reason is surfaced (Advanced-style), never a secret.
    assert.match(manage, /organizerStatus\.failure_reason/);
    assert.match(manage, /diagnostic:/);
  });

  it("offers a one-click Restart for a failed intake, not only a Stop", () => {
    // When failed, the primary action restarts (reap + fresh start); the operator
    // is never left with only a "Stop" against a service that is already down.
    assert.match(manage, /Restart private intake/);
    const failedButtonBranch = manage.slice(
      manage.indexOf('organizerStatus?.failed ? ('),
      manage.indexOf('organizerStatus?.intake_running ? ('),
    );
    assert.match(failedButtonBranch, /onStartIntake\(\)/);
    assert.match(failedButtonBranch, /btn-primary/);
  });

  it("does NOT reintroduce a global-reachability 'Ready ✓' claim", () => {
    // The lifecycle repair must not weaken the earlier reachability-honesty work.
    assert.doesNotMatch(manage, /<Pill tone="ok">Ready ✓<\/Pill>/);
    assert.match(manage, /<Pill tone="ok">Running ✓<\/Pill>/);
  });
});
