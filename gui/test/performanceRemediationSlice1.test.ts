// Performance-remediation Slice 1 regression tests (source-level).
//
// Pins the Slice 1 architectural guarantees that have no React harness:
//
//   * ordinary lifecycle actions (Open/Close/Verify/Finalize) no longer trigger
//     a full workspace re-listing (which previously reconstructed and
//     re-verified every stored ballot of every workspace); the active row is
//     patched locally instead;
//   * the workspace-list and delete commands run OFF the Tauri event thread;
//   * per-workspace summarisation is metadata-only — it does NOT reconstruct a
//     GuiElectionSessionV1 from the durable snapshot and therefore performs no
//     Triptych verification;
//   * the workspace summary exposes an explicitly non-authoritative
//     stored-ballot count, never a "verified accepted" count.
//
// Behaviour with no harness is pinned by semantic source assertions plus the
// authoritative Rust command surface, matching the existing test house style.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const appState = readProjectFile("src/state/AppState.tsx");
const home = readProjectFile("src/screens/Home.tsx");
const types = readProjectFile("src/api/types.ts");
const shell = readProjectFile("src-tauri/src/lib.rs");
const workspaceRs = readProjectFile("../crates/gui-core/src/workspace.rs");
const sessionRs = readProjectFile("../crates/gui-core/src/session.rs");

function slice(source: string, start: string, end: string): string {
  const from = source.indexOf(start);
  assert.ok(from >= 0, `anchor not found: ${start}`);
  const to = source.indexOf(end, from + start.length);
  assert.ok(to >= 0, `end anchor not found after ${start}: ${end}`);
  return source.slice(from, to);
}

// -------------------------------------------------------------------------
// Frontend: lifecycle actions do not re-list all workspaces.
// -------------------------------------------------------------------------

describe("runLifecycle no longer triggers full workspace reconstruction", () => {
  const runLifecycle = slice(
    appState,
    "const runLifecycle = useCallback(",
    "const setSetting = useCallback(",
  );

  it("does not call refreshWorkspaces after a lifecycle transition", () => {
    assert.doesNotMatch(
      runLifecycle,
      /refreshWorkspaces\s*\(/,
      "a lifecycle action must not re-list (and thus re-reconstruct) all workspaces",
    );
  });

  it("patches only the active workspace row locally from the returned summary", () => {
    assert.match(
      runLifecycle,
      /setWorkspaces\s*\(/,
      "the active workspace row is updated locally",
    );
    assert.match(
      runLifecycle,
      /session_workspace_id/,
      "the local patch targets the active session workspace id",
    );
    assert.match(
      runLifecycle,
      /summary\.lifecycle_state/,
      "the patched lifecycle state comes from the authoritative backend summary",
    );
  });

  it("does not list refreshWorkspaces in its dependency array", () => {
    // The dependency array is the tail of the useCallback; a lingering
    // refreshWorkspaces dep would signal the call was only accidentally removed.
    const deps = runLifecycle.slice(runLifecycle.lastIndexOf("["));
    assert.doesNotMatch(deps, /refreshWorkspaces/);
  });
});

// -------------------------------------------------------------------------
// Shell: expensive discovery/delete run off the event thread.
// -------------------------------------------------------------------------

describe("workspace list/delete commands are off the Tauri event thread", () => {
  it("list_election_workspaces is async and uses the blocking worker", () => {
    const cmd = slice(
      shell,
      "async fn list_election_workspaces(",
      "async fn delete_election_workspace(",
    );
    assert.match(cmd, /run_blocking_command/, "listing runs on the blocking pool");
    assert.match(cmd, /list_election_workspaces_v1/);
  });

  it("delete_election_workspace is async and uses the blocking worker", () => {
    const cmd = slice(
      shell,
      "async fn delete_election_workspace(",
      "\n#[tauri::command]",
    );
    assert.match(cmd, /run_blocking_command/, "delete + re-list run on the blocking pool");
    // The active-workspace fail-closed guard is preserved.
    assert.match(cmd, /GUI_WORKSPACE_DELETE_ACTIVE/);
  });
});

// -------------------------------------------------------------------------
// gui-core: summarisation is metadata-only (no session reconstruction).
// -------------------------------------------------------------------------

describe("summarize_workspace is metadata-only", () => {
  const summarize = slice(workspaceRs, "fn summarize_workspace(", "fn encode_workspace(");

  it("does not reconstruct a session from the durable snapshot", () => {
    assert.doesNotMatch(
      summarize,
      /GuiElectionSessionV1::from_durable_snapshot/,
      "listing must not replay/verify stored ballots",
    );
  });

  it("derives election metadata from artifact bytes, not a verified session", () => {
    assert.match(
      summarize,
      /GuiElectionArtifactsV1::from_bytes/,
      "manifest hash + question come from artifact decode only",
    );
  });

  it("uses the stored durable lifecycle state and stored package count", () => {
    assert.match(summarize, /snapshot\.lifecycle_state/);
    assert.match(summarize, /snapshot\.packages\.len\(\)/);
    assert.match(summarize, /stored_ballot_count/);
  });
});

// -------------------------------------------------------------------------
// gui-core: durable reconstruction (the real verification path) is intact.
// -------------------------------------------------------------------------

describe("durable reconstruction still replays and verifies every ballot", () => {
  const reconstruct = slice(
    sessionRs,
    "fn from_durable_snapshot_inner(",
    "fn to_durable_snapshot(",
  );

  it("still replays every persisted package through intake", () => {
    assert.match(reconstruct, /for package in &snapshot\.packages/);
    assert.match(reconstruct, /intake_ballot_package_bytes/);
  });
});

// -------------------------------------------------------------------------
// Types/UI: the count is explicitly non-authoritative.
// -------------------------------------------------------------------------

describe("workspace summary count is display-only", () => {
  it("the workspace summary type exposes stored_ballot_count, not accepted", () => {
    const iface = slice(
      types,
      "export interface GuiElectionWorkspaceSummaryV1",
      "export interface GuiElectionWorkspaceResumeResultV1",
    );
    assert.match(iface, /stored_ballot_count/);
    assert.doesNotMatch(iface, /accepted_ballot_count/);
    assert.match(iface, /NON-AUTHORITATIVE/i, "provenance is documented on the field");
  });

  it("Home renders the stored count under a non-authoritative label", () => {
    assert.match(home, /workspace\.stored_ballot_count/);
    assert.doesNotMatch(home, /workspace\.accepted_ballot_count/);
    assert.match(home, /Ballots stored/);
  });
});
