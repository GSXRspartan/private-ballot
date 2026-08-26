import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  BallotSaveDialogError,
  requestAndExportPreparedBallot,
} from "../src/voterExport.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

test("desktop capability permits only the native open and save dialogs (plus theme sync)", () => {
  const capability = JSON.parse(readProjectFile("src-tauri/capabilities/default.json"));
  assert.deepEqual(capability.permissions, [
    "dialog:allow-open",
    "dialog:allow-save",
    "core:window:allow-set-theme",
  ]);
  assert.ok(capability.permissions.includes("dialog:allow-open"));
  assert.ok(capability.permissions.includes("dialog:allow-save"));
  assert.ok(
    capability.permissions.every(
      (permission: string) =>
        permission.startsWith("dialog:") || permission === "core:window:allow-set-theme",
    ),
    "the ballot save repair must not add filesystem, shell, or network permissions",
  );
});

test("export reports success only after the Rust command succeeds", async () => {
  const events: string[] = [];
  let completeExport!: () => void;
  const exportCompleted = new Promise<void>((resolve) => {
    completeExport = resolve;
  });

  const result = requestAndExportPreparedBallot(
    async () => {
      events.push("dialog");
      return "C:\\ballots\\ballot-package.cbor";
    },
    async (path) => {
      events.push(`rust:${path}`);
      await exportCompleted;
    },
  );

  assert.deepEqual(events, ["dialog"]);
  await Promise.resolve();
  assert.deepEqual(events, ["dialog", "rust:C:\\ballots\\ballot-package.cbor"]);
  completeExport();
  assert.equal(await result, true);
});

test("cancelling the save dialog does not invoke Rust or report success", async () => {
  let exportCalls = 0;
  const result = await requestAndExportPreparedBallot(
    async () => null,
    async () => {
      exportCalls += 1;
    },
  );

  assert.equal(result, false);
  assert.equal(exportCalls, 0);
});

test("a save-dialog runtime failure is distinct and does not invoke Rust", async () => {
  let exportCalls = 0;
  await assert.rejects(
    requestAndExportPreparedBallot(
      async () => Promise.reject(new Error("dialog permission denied")),
      async () => {
        exportCalls += 1;
      },
    ),
    BallotSaveDialogError,
  );
  assert.equal(exportCalls, 0);
});

test("Vote surfaces dialog failures and refreshes state only after export", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  assert.match(vote, /await requestAndExportPreparedBallot\(/);
  assert.match(vote, /if \(!saved\) return;/);
  assert.match(vote, /GUI_BALLOT_SAVE_DIALOG_UNAVAILABLE/);
  assert.match(vote, /The native Save dialog could not open/);
  // Within onExportBallot, the workflow refresh (which reveals the cast state)
  // must wait for the Rust export command to complete.
  const exportFn = vote.slice(
    vote.indexOf("async function onExportBallot"),
    vote.indexOf("async function onChangeChoice"),
  );
  assert.ok(exportFn.length > 0, "onExportBallot must precede onChangeChoice");
  assert.ok(
    exportFn.indexOf("await requestAndExportPreparedBallot(") <
      exportFn.indexOf("refreshWorkflow(true)"),
    "success UI must wait for the Rust export command",
  );
});

test("the frontend passes only the chosen path; Rust retains ballot-byte ownership", () => {
  const vote = readProjectFile("src/screens/Vote.tsx");
  const exportFlow = readProjectFile("src/voterExport.ts");
  const dialog = readProjectFile("src/api/dialog.ts");
  const core = readProjectFile("../crates/gui-core/src/voter_session.rs");

  assert.match(vote, /api\.exportPreparedVoterBallot/);
  assert.match(exportFlow, /exportPreparedBallot\(path\)/);
  assert.doesNotMatch(exportFlow, /writeFile|writeFileSync|OpenOptions|canonical_bytes/i);
  assert.doesNotMatch(dialog, /writeFile|writeFileSync/i);
  assert.match(core, /OpenOptions::new\(\)/);
  assert.match(core, /\.create_new\(true\)/);
  assert.match(core, /file\.sync_all\(\)/);
  assert.match(core, /std::fs::read\(path\)/);
});
