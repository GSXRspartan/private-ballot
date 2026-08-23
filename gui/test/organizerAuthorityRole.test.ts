// ORGANIZER/VOTER ROLE-SEPARATION regression tests (two-computer authority fix).
//
// Physical failure being pinned: Computer B imported ONLY the public frozen
// election package yet received the full ballot-office control surface — and,
// worse, the backend would have accepted organizer commands from it (direct
// IPC included): opening voting, provisioning a competing organizer transport
// root for a legitimate frozen election, exporting a voter bundle, and signing
// election status under that new root.
//
// The repair is a backend authority model:
//   * authority is established ONLY by organizer flows (freeze, or resume of a
//     workspace carrying a durable organizer-authority provenance marker) or
//     by the voter import flow (imported_voter, never organizer);
//   * every organizer command is rejected in Rust — BEFORE any filesystem
//     mutation, transport provisioning, Tor launch, key creation, generation
//     reservation, workspace write, or lifecycle mutation — with the single
//     stable code GUI_ORGANIZER_AUTHORITY_REQUIRED;
//   * importing public artifacts no longer creates a durable organizer
//     workspace at all;
//   * the frontend mirrors the backend role truthfully (defense-in-depth UX,
//     never the enforcement point).
//
// Runs under Node's built-in test runner with TypeScript type stripping.
// Backend rules are pinned by semantic source assertions (the repo's
// established pattern); frontend role plumbing is asserted structurally.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

function readRepoFile(path: string): string {
  return readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");
}

const shell = readProjectFile("src-tauri/src/lib.rs");
const intake = readProjectFile("src-tauri/src/organizer_tor_intake.rs");
const statusCommands = readProjectFile(
  "src-tauri/src/election_status_commands.rs",
);
const workspaceRust = readRepoFile("crates/gui-core/src/workspace.rs");
const manage = readProjectFile("src/screens/ManageElection.tsx");
const home = readProjectFile("src/screens/Home.tsx");
const appState = readProjectFile("src/state/AppState.tsx");
const types = readProjectFile("src/api/types.ts");
const client = readProjectFile("src/api/client.ts");
const css = readProjectFile("src/styles/global.css");

const AUTHORITY_CODE = "GUI_ORGANIZER_AUTHORITY_REQUIRED";

/** Extracts the full body of a Rust function (balanced-brace scan). */
function rustFnBody(source: string, fnName: string): string {
  const genericStart = source.indexOf(`fn ${fnName}<`);
  const plainStart = source.indexOf(`fn ${fnName}(`);
  const start =
    genericStart !== -1 && (plainStart === -1 || genericStart < plainStart)
      ? genericStart
      : plainStart;
  assert.notEqual(start, -1, `fn ${fnName} must exist`);
  const bodyStart = source.indexOf("{", start);
  let depth = 0;
  for (let i = bodyStart; i < source.length; i++) {
    if (source[i] === "{") depth++;
    else if (source[i] === "}") {
      depth--;
      if (depth === 0) return source.slice(bodyStart, i + 1);
    }
  }
  assert.fail(`fn ${fnName} body must terminate`);
}

/** True when `ensure_organizer_authority` is called before `marker` inside
 *  the named function body. */
function gatePrecedes(source: string, fnName: string, marker: string): boolean {
  const body = rustFnBody(source, fnName);
  const gate = body.indexOf("ensure_organizer_authority()");
  const target = body.indexOf(marker);
  assert.notEqual(target, -1, `${fnName} must contain ${marker}`);
  assert.notEqual(gate, -1, `${fnName} must call the authority gate`);
  return gate < target;
}

// ---------------------------------------------------------------------------
// Backend: the authority model and its enforcement points
// ---------------------------------------------------------------------------

describe("backend organizer-authority model", () => {
  it("defines one stable, dedicated refusal for organizer commands", () => {
    assert.ok(shell.includes(AUTHORITY_CODE));
    assert.match(shell, /fn organizer_authority_required\(/);
    // The refusal explains the role truth instead of a generic failure.
    const body = rustFnBody(shell, "organizer_authority_required");
    assert.match(body, /organizer-owned election/);
  });

  it("authority is a session property installed only by explicit flows", () => {
    assert.match(shell, /enum SessionAuthorityV1[\s\S]*Organizer[\s\S]*ImportedVoter/);
    assert.match(
      shell,
      /install_frozen_session\(\s*&?self,\s*session: GuiElectionSessionV1,\s*authority: SessionAuthorityV1/,
    );
  });

  it("the transactional session mutator gates before ANY workspace write", () => {
    assert.ok(gatePrecedes(shell, "mutate_session_transactionally", "write_session_workspace_revision_v1"));
    // The gate is the FIRST statement: no directory resolution, no session
    // clone, nothing at all happens for an unauthorized caller.
    const body = rustFnBody(shell, "mutate_session_transactionally");
    assert.match(
      body,
      /ensure_organizer_authority\(\)\?;\s*let workspaces_dir/,
      "the authority gate must be the first effect-free statement",
    );
  });

  it("session and authority share ONE lock (no swap window for concurrent IPC)", () => {
    // Adversarial repair: with two separate mutexes, a concurrent import +
    // organizer command interleaving could evaluate the gate against the
    // PREVIOUS election's organizer authority while mutating a freshly
    // installed imported session. One lock makes snapshots atomic.
    assert.match(
      shell,
      /struct ActiveElectionSessionV1 \{[\s\S]*?session: GuiElectionSessionV1,[\s\S]*?authority: SessionAuthorityV1,/,
    );
    assert.match(shell, /session: Mutex<Option<ActiveElectionSessionV1>>/);
    assert.doesNotMatch(
      shell,
      /session_authority: Mutex/,
      "a second authority lock would reopen the swap race",
    );
    // Both authoritative writers re-check the SNAPSHOT under the lock.
    for (const fnName of ["mutate_session_transactionally"]) {
      const body = rustFnBody(shell, fnName);
      assert.match(body, /active\.authority != SessionAuthorityV1::Organizer/);
    }
    const sync = rustFnBody(shell, "sync_private_intake");
    assert.match(sync, /active\.authority != SessionAuthorityV1::Organizer/);
  });

  for (const command of [
    "open_voting",
    "close_voting",
    "mark_verified",
    "finalize_election",
    "intake_ballot_package",
    "sync_private_intake",
    "private_intake_inbox_path",
    "current_tally",
    "write_archive",
    "write_finalized_archive",
    "write_archive_with_governance_document",
  ]) {
    it(`${command} requires organizer authority`, () => {
      const start = shell.indexOf(`fn ${command}(`);
      assert.notEqual(start, -1, `command ${command} must exist`);
      const body = shell.slice(start, start + 2000);
      assert.ok(
        body.includes("ensure_organizer_authority()"),
        `${command} must call ensure_organizer_authority`,
      );
    });
  }

  it("close_voting checks authority BEFORE publishing the intake fence", () => {
    const body = rustFnBody(shell, "close_voting");
    const gate = body.indexOf("ensure_organizer_authority()");
    const fence = body.indexOf("fence_close_before_commit");
    assert.notEqual(gate, -1);
    assert.notEqual(fence, -1);
    assert.ok(gate < fence, "an unauthorized close must never touch the fence");
  });

  it("importing public artifacts grants voter-only authority and NO organizer workspace", () => {
    const body = rustFnBody(shell, "load_election_from_paths");
    // Session AND role are installed atomically under one lock.
    assert.match(
      body,
      /ActiveElectionSessionV1::new\(\s*session,\s*SessionAuthorityV1::ImportedVoter,?\s*\)/,
    );
    assert.doesNotMatch(
      body,
      /write_session_workspace_revision_v1/,
      "a public import must never create a durable organizer workspace",
    );
    assert.match(body, /clear_session_workspace_id/, "no organizer workspace id may be claimed");
  });

  it("freezing establishes durable organizer authority", () => {
    const body = rustFnBody(shell, "freeze_election");
    const commit = body.indexOf("write_session_workspace_revision_v1");
    const marker = body.indexOf("mark_workspace_organizer_authority_v1");
    assert.ok(
      commit !== -1 && marker !== -1 && commit < marker,
      "the provenance marker is written strictly after the workspace commit",
    );
    assert.match(body, /install_frozen_session\(session, SessionAuthorityV1::Organizer\)/);
  });

  it("resume restores authority fail-closed from durable provenance", () => {
    const body = rustFnBody(shell, "resume_election_workspace");
    assert.match(body, /workspace\.organizer_workspace/);
    assert.match(body, /SessionAuthorityV1::Organizer/);
    assert.match(body, /SessionAuthorityV1::ImportedVoter/);
  });

  it("the shell exposes the active authority to the frontend", () => {
    assert.match(shell, /fn active_election_authority\(/);
    assert.match(shell, /active_election_authority,/);
  });
});

// ---------------------------------------------------------------------------
// Backend: organizer transport and signing surfaces
// ---------------------------------------------------------------------------

describe("backend organizer transport and signing gates", () => {
  it("start_private_intake gates before ANY Tor/provisioning/filesystem work", () => {
    const body = rustFnBody(intake, "start_private_intake_blocking");
    const gate = body.indexOf("ensure_organizer_authority()");
    assert.notEqual(gate, -1);
    for (const laterOf of [
      "resolve_tor_executable",
      "bound_election",
      "election_transport_root",
      "provision_transport",
      "start_intake_worker",
    ]) {
      const idx = body.indexOf(laterOf);
      assert.notEqual(idx, -1, `start must contain ${laterOf}`);
      assert.ok(
        gate < idx,
        `authority must be checked before ${laterOf} (no provisioning for imports)`,
      );
    }
  });

  it("stop_private_intake and organizer status are organizer-only", () => {
    assert.ok(gatePrecedes(intake, "stop_private_intake_blocking", "organizer_intake"));
    assert.ok(
      gatePrecedes(intake, "organizer_tor_status_blocking", "resolve_tor_executable"),
    );
  });

  it("export_voter_transport_bundle is organizer-only", () => {
    const start = intake.indexOf("pub fn export_voter_transport_bundle(");
    const body = intake.slice(start, start + 1500);
    const gate = body.indexOf("ensure_organizer_authority()");
    const dest = body.indexOf("PathBuf::from(&destination_dir)");
    assert.ok(gate !== -1 && dest !== -1 && gate < dest);
  });

  it("export_election_status_artifact gates before reserving a generation or signing", () => {
    const body = rustFnBody(statusCommands, "export_election_status_blocking");
    const gate = body.indexOf("ensure_organizer_authority()");
    for (const laterOf of [
      "reserve_next_status_generation_v1",
      "organizer_private_bundle_dir",
      "AuthenticatedElectionStatusStatementV1::sign_for_test_or_ceremony",
    ]) {
      const idx = body.indexOf(laterOf);
      assert.notEqual(idx, -1, `status export must contain ${laterOf}`);
      assert.ok(
        gate < idx,
        `authority must be checked before ${laterOf} (no generation burn, no key load)`,
      );
    }
  });

  it("voter status import/fetch paths are NOT authority-gated", () => {
    for (const voterFn of [
      "import_election_status_blocking",
      "apply_election_status_bytes_blocking",
      "fetch_election_status_blocking",
    ]) {
      const body = rustFnBody(statusCommands, voterFn);
      assert.ok(
        !body.includes("ensure_organizer_authority"),
        `${voterFn} must stay usable by imported voter sessions`,
      );
    }
  });

  it("workspace provenance is a fail-closed durable marker", () => {
    assert.match(
      workspaceRust,
      /pub fn mark_workspace_organizer_authority_v1\(/,
    );
    assert.match(
      workspaceRust,
      /pub fn workspace_has_organizer_authority_v1\(workspaces_root: &Path, workspace_id: &str\) -> bool/,
    );
    const decode = rustFnBody(workspaceRust, "decode_organizer_authority_marker");
    assert.match(decode, /expect_bytes\(ORGANIZER_AUTHORITY_MAGIC_V1\)/);
    assert.match(decode, /reader\.finish\(\)\.is_ok\(\)/);
    const probe = rustFnBody(workspaceRust, "workspace_has_organizer_authority_v1");
    assert.match(probe, /unwrap_or_default\(\)/, "any read failure yields false");
  });
});

// ---------------------------------------------------------------------------
// Frontend: truthful role mirroring (defense in depth, never the gate)
// ---------------------------------------------------------------------------

describe("frontend role plumbing", () => {
  it("types carry the backend authority model", () => {
    assert.match(types, /export type GuiElectionAuthorityV1 = "organizer" \| "imported_voter";/);
    assert.match(types, /organizer_workspace: boolean;/);
    assert.match(types, /interface ActiveElectionAuthorityV1/);
  });

  it("the client calls the backend authority projection", () => {
    assert.match(client, /activeElectionAuthority: \(\) =>/);
    assert.match(client, /call<ActiveElectionAuthorityV1 \| null>\("active_election_authority"\)/);
  });

  it("AppState fetches authority with the summary and mirrors every flow", () => {
    assert.match(appState, /electionAuthority: GuiElectionAuthorityV1 \| null/);
    assert.match(
      appState,
      /Promise\.all\(\[\s*api\.electionSummary\(\),\s*api\.activeElectionAuthority\(\),?\s*\]\)/,
    );
    // Imports are always voter context.
    assert.match(appState, /setElectionAuthority\("imported_voter"\)/);
    // Resume maps durable provenance.
    assert.match(appState, /result\.organizer_workspace\s*\?\s*"organizer"/);
    // Unload clears it.
    assert.match(appState, /setElectionAuthority\(null\)/);
  });

  it("Manage Election hides organizer controls and explains the voter role", () => {
    assert.match(manage, /const isOrganizer = election !== null && electionAuthority === "organizer";/);
    assert.match(manage, /const isImportedVoter = election !== null && electionAuthority === "imported_voter";/);
    // The whole organizer card grid is inside the isOrganizer wrapper.
    const grid = manage.indexOf('{isOrganizer && (\n      <div className="card-grid">');
    assert.notEqual(grid, -1, "the organizer card grid must be organizer-gated");
    // No organizer Next-step guidance for voters.
    assert.match(manage, /\{isOrganizer && election && \(\s*\/\/ Plain-language guidance/);
    // The voter context explains itself.
    assert.match(manage, /This election was imported from public election artifacts/);
    assert.match(manage, /not its ballot office/);
    // Status/auto-sync effects never query organizer surfaces for voters.
    assert.match(manage, /election && shellAvailable && isOrganizer\) void refreshOrganizerStatus/);
    assert.match(manage, /lifecycle !== "OPEN" \|\| !isOrganizer\) return;/);
  });

  it("Home shows the durable role before resuming", () => {
    assert.match(home, /Ballot office/);
    assert.match(home, /Voter copy/);
    assert.match(home, /workspace\.organizer_workspace/);
  });

  it("frontend gating is documented as non-authoritative", () => {
    assert.match(
      manage,
      /defense-in-depth UX only[\s\S]*GUI_ORGANIZER_AUTHORITY_REQUIRED/,
      "the UI must not claim to be the enforcement point",
    );
  });
});

// ---------------------------------------------------------------------------
// Responsive layout repairs (physical two-computer UX findings)
// ---------------------------------------------------------------------------

describe("responsive layout repairs", () => {
  it("field-list labels can never inflate and values can always grow", () => {
    // Root cause of the wide-window character-wrapping: an `auto` max label
    // track participates in free-space distribution. max-content + minmax(0,1fr)
    // pins labels to content and gives values the rest.
    assert.match(
      css,
      /\.field-list \{[\s\S]*?grid-template-columns: minmax\(7\.5rem, max-content\) minmax\(0, 1fr\);/,
    );
    assert.doesNotMatch(
      css,
      /grid-template-columns: minmax\(9rem, auto\)/,
      "the fragile auto-max label track must be gone",
    );
    assert.match(css, /\.field-list > \* \{\s*min-width: 0;/);
  });

  it("large-desktop density uses more of wide monitors while staying centered", () => {
    assert.match(
      css,
      /\.main-inner \{[\s\S]*?max-width: 72rem;[\s\S]*?margin: 0 auto;/,
    );
    assert.doesNotMatch(css, /max-width: 62rem;/);
  });
});
