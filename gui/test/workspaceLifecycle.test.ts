// Organizer workspace lifecycle regression tests (Failure 2).
//
// Pins the ghost-draft + Home/delete-contradiction repairs from the hard-crash
// testing pass:
//
//   * merely opening Create Election no longer persists an empty `draft-*`
//     workspace (the durable revision is deferred to the first real edit), so
//     no empty ghost row appears in Resume Election;
//   * the backend exposes the active session/draft workspace ids (public ids
//     only) so the frontend can stay consistent with the fail-closed delete
//     guard;
//   * Home offers "Resume" (not a failing "Delete") for the active workspace,
//     so "No election loaded" can no longer coexist with an undeletable active
//     draft;
//   * the active-workspace delete guard itself remains fail-closed.
//
// Where no React harness exists, behavior is pinned by semantic source
// assertions plus the authoritative Rust command surface.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const home = readProjectFile("src/screens/Home.tsx");
const appState = readProjectFile("src/state/AppState.tsx");
const client = readProjectFile("src/api/client.ts");
const types = readProjectFile("src/api/types.ts");
const shell = readProjectFile("src-tauri/src/lib.rs");

// -------------------------------------------------------------------------
// Backend: empty drafts are not persisted; active ids are exposed; the delete
// guard stays fail-closed.
// -------------------------------------------------------------------------

describe("draft workspace lifecycle (backend)", () => {
  it("get_or_create/start_election_draft no longer write an empty draft revision", () => {
    const getOrCreate = shell.slice(
      shell.indexOf("fn get_or_create_election_draft"),
      shell.indexOf("fn start_election_draft"),
    );
    assert.ok(getOrCreate.length > 0, "get_or_create_election_draft present");
    assert.doesNotMatch(
      getOrCreate,
      /write_draft_workspace_revision_v1/,
      "opening Create Election must not persist an empty draft",
    );
    assert.doesNotMatch(
      getOrCreate,
      /create_draft_workspace_id_v1/,
      "opening Create Election must not allocate a durable draft id",
    );
    assert.match(getOrCreate, /clear_draft_workspace_id/);

    const startFresh = shell.slice(
      shell.indexOf("fn start_election_draft"),
      shell.indexOf("fn discard_election_draft"),
    );
    assert.ok(startFresh.length > 0, "start_election_draft present");
    assert.doesNotMatch(startFresh, /write_draft_workspace_revision_v1/);
    assert.match(startFresh, /clear_draft_workspace_id/);
  });

  it("exposes the active session/draft workspace ids read-only", () => {
    assert.match(shell, /fn active_workspace_ids\(/);
    assert.match(shell, /struct ActiveWorkspaceIdsV1/);
    assert.match(shell, /session_workspace_id: Option<String>/);
    assert.match(shell, /draft_workspace_id: Option<String>/);
    // Registered in the invoke handler.
    assert.match(shell, /active_workspace_ids,/);
  });

  it("keeps the active-workspace delete guard fail-closed", () => {
    assert.match(shell, /GUI_WORKSPACE_DELETE_ACTIVE/);
    assert.match(
      shell,
      /active_session\.as_deref\(\) == Some\(workspace_id\.as_str\(\)\)/,
    );
    assert.match(
      shell,
      /active_draft\.as_deref\(\) == Some\(workspace_id\.as_str\(\)\)/,
    );
  });
});

// -------------------------------------------------------------------------
// Frontend wiring
// -------------------------------------------------------------------------

describe("active workspace ids (frontend wiring)", () => {
  it("the api client and DTOs expose active_workspace_ids", () => {
    assert.match(client, /activeWorkspaceIds: \(\) =>/);
    assert.match(client, /call<ActiveWorkspaceIdsV1>\("active_workspace_ids"\)/);
    assert.match(types, /interface ActiveWorkspaceIdsV1/);
    assert.match(types, /session_workspace_id: string \| null/);
    assert.match(types, /draft_workspace_id: string \| null/);
  });

  it("AppState fetches active ids alongside the workspace list", () => {
    assert.match(appState, /activeWorkspaceIds: ActiveWorkspaceIdsV1 \| null/);
    assert.match(appState, /api\.activeWorkspaceIds\(\)/);
    // Fetched together with the list so the two never drift apart.
    assert.match(appState, /api\.listElectionWorkspaces\(\),\s*api\.activeWorkspaceIds\(\),/);
  });
});

// -------------------------------------------------------------------------
// Home: the empty state cannot contradict an undeletable active workspace.
// -------------------------------------------------------------------------

describe("Home active-workspace consistency", () => {
  it("recognises the active workspace from the backend ids", () => {
    assert.match(home, /const isActiveWorkspace = \(workspaceId: string\) =>/);
    assert.match(home, /activeWorkspaceIds\?\.session_workspace_id/);
    assert.match(home, /activeWorkspaceIds\?\.draft_workspace_id/);
  });

  it("offers Resume (not a failing Delete) for the active workspace", () => {
    // Delete is rendered only in the non-active branch; the active branch shows
    // an "in progress" hint instead of a Delete button.
    assert.match(home, /isActiveWorkspace\(workspace\.workspace_id\) \? \(/);
    assert.match(home, /In progress — your current draft/);
    // The Delete control lives in the else branch (non-active rows only).
    // Line-ending agnostic: matches LF and CRLF checkouts alike.
    const deleteMatch = home.match(/>\r?\n\s+Delete\b/);
    const guardIdx = home.indexOf("isActiveWorkspace(workspace.workspace_id) ? (");
    assert.ok(
      guardIdx >= 0 && deleteMatch !== null && (deleteMatch.index ?? 0) > guardIdx,
      "Delete is gated behind the active-workspace check",
    );
  });
});
