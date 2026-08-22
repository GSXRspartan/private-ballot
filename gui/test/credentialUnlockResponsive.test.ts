// Credential unlock regression tests (Failures 5 & 6).
//
// Failure 5 — the credential Argon2id KDF (64 MiB, t=3, p=4) is CPU-bound and
// froze the desktop window ("Not Responding") when run synchronously on the
// Tauri command thread. The unlock/create/import/backup commands now run that
// blocking work off the UI thread via the shared `run_blocking_command`
// (spawn_blocking), exactly as the managed-Tor path already does. The KDF
// parameters, container format, and fail-closed wrong-password behavior are
// unchanged (the same gui-core state methods run inside the task).
//
// Failure 6 — pressing Enter in the passphrase field did nothing because the
// inputs and button were not inside a <form>. The dialog is now a real
// submit-capable form: Enter and the button reach the SAME handler, gated by the
// same disabled condition, with no global keydown handler.
//
// Behavior is pinned by semantic source assertions (no React harness).
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const shell = readProjectFile("src-tauri/src/lib.rs");
const card = readProjectFile("src/components/VoterCredentialCard.tsx");

// -------------------------------------------------------------------------
// Failure 5: KDF is not run synchronously on the UI/command thread.
// -------------------------------------------------------------------------

describe("credential KDF runs off the UI thread", () => {
  function commandBody(name: string): string {
    const start = shell.indexOf(`fn ${name}(`);
    assert.ok(start >= 0, `command ${name} present`);
    // Take a generous slice covering the whole command body.
    return shell.slice(start, start + 1200);
  }

  it("run_blocking_command is available regardless of the managed-tor-test feature", () => {
    // It must NOT be feature-gated, because the always-compiled credential
    // commands rely on it.
    const idx = shell.indexOf("pub(crate) async fn run_blocking_command");
    assert.ok(idx >= 0, "run_blocking_command present");
    const preceding = shell.slice(Math.max(0, idx - 200), idx);
    assert.doesNotMatch(
      preceding,
      /#\[cfg\(feature = "managed-tor-test"\)\]\s*$/,
      "run_blocking_command must not be gated to the managed-tor-test feature",
    );
  });

  it("unlock/create/import/backup are async and run the KDF via run_blocking_command", () => {
    for (const name of [
      "unlock_saved_voter_credential",
      "create_durable_voter_credential",
      "import_voter_credential",
      "backup_voter_credential",
    ]) {
      assert.match(shell, new RegExp(`async fn ${name}\\(`), `${name} is async`);
      const body = commandBody(name);
      assert.match(body, /run_blocking_command\(move \|\| \{/, `${name} offloads to blocking pool`);
    }
  });

  it("does not change the credential KDF parameters or container format", () => {
    const container = readProjectFile("../crates/gui-core/src/voter_credential_container.rs");
    // KDF parameters are untouched (still Argon2id 64 MiB / t=3 / p=4).
    assert.match(container, /VOTER_CREDENTIAL_CONTAINER_V1_KDF_MEMORY_MIB: u32 = 64/);
    assert.match(container, /VOTER_CREDENTIAL_CONTAINER_V1_KDF_TIME_COST: u32 = 3/);
    assert.match(container, /VOTER_CREDENTIAL_CONTAINER_V1_KDF_PARALLELISM: u32 = 4/);
  });

  it("keeps the passphrase out of persistent JS state and zeroized in Rust", () => {
    // The passphrase is wrapped in Zeroizing inside each command task.
    for (const name of [
      "unlock_saved_voter_credential",
      "create_durable_voter_credential",
      "import_voter_credential",
      "backup_voter_credential",
    ]) {
      const body = commandBody(name);
      assert.match(body, /Zeroizing::new\(passphrase\)/, `${name} zeroizes the passphrase`);
    }
  });
});

// -------------------------------------------------------------------------
// Failure 6: Enter submits the passphrase via the same handler as the button.
// -------------------------------------------------------------------------

describe("passphrase dialog Enter-to-submit", () => {
  it("uses a real submit-capable form with a type=submit button", () => {
    assert.match(card, /<form\s+className="modal"/);
    assert.match(card, /onSubmit=\{\(event\) => \{/);
    assert.match(card, /event\.preventDefault\(\);/);
    assert.match(card, /if \(canSubmit\) onSubmit\(\);/);
    assert.match(card, /type="submit"/);
  });

  it("gates Enter and click with the same disabled condition (no duplicate/ungated submit)", () => {
    // One shared gate: busy or empty passphrase blocks BOTH Enter and the button.
    assert.match(card, /const canSubmit = !busy && passphrase\.length > 0;/);
    assert.match(card, /disabled=\{!canSubmit\}/);
    // The primary action button no longer carries its own onClick (submission
    // flows through the form), so a click cannot double-fire.
    const submitButton = card.slice(card.indexOf('type="submit"'), card.indexOf('type="submit"') + 160);
    assert.doesNotMatch(submitButton, /onClick=/);
  });

  it("keeps Cancel a non-submitting button and adds no global keydown handler", () => {
    assert.match(card, /type="button"[\s\S]*?onClick=\{onCancel\}/);
    assert.doesNotMatch(card, /addEventListener\(\s*["']keydown/);
    assert.doesNotMatch(card, /onKeyDown|onKeyPress/);
  });
});
