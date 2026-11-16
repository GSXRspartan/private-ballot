// Release UX boundary checks for the ordinary Hosted ↔ Desktop binding bridge.
// The Desktop shell owns only file selection and its typed Tauri command; it
// never receives the Hosted organizer capability.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const manage = read("../src/screens/ManageElection.tsx");
const client = read("../src/api/client.ts");
const dialog = read("../src/api/dialog.ts");
const shell = read("../src-tauri/src/lib.rs");

describe("Hosted binding handoff", () => {
  it("uses native files rather than a raw binding paste field", () => {
    assert.match(manage, /pickHostedBindingRequest\(\)/);
    assert.match(manage, /pickHostedBindingHandoffPath\(\)/);
    assert.match(manage, /api\.writeHostedBindingHandoff\(requestPath, targetPath\)/);
    assert.match(dialog, /Import Hosted binding request/);
    assert.match(dialog, /Export verified Desktop binding handoff/);
    assert.doesNotMatch(manage, /transport_binding_cbor_hex/);
  });

  it("requires a finalized local organizer election and exact public identity", () => {
    assert.match(manage, /lifecycle !== "FINALIZED"/);
    assert.match(shell, /state\.ensure_organizer_authority\(\)/);
    assert.match(shell, /request\.election_id != election_id/);
    assert.match(shell, /request\.manifest_hash_hex != manifest_hash_hex/);
    assert.match(shell, /GUI_HOSTED_BINDING_HANDOFF_MISMATCH/);
  });

  it("writes only a derived public response and never a Hosted credential", () => {
    assert.match(client, /"write_hosted_binding_handoff"/);
    assert.match(shell, /DesktopBindingHandoffV1::new\(/);
    assert.match(shell, /finalized_transport_handoff_for_active_intake/);
    assert.doesNotMatch(shell, /x-private-ballot-organizer/);
    assert.doesNotMatch(shell, /organizer_secret_hex/);
  });
});
