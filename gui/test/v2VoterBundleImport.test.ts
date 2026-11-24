// Release UX boundary checks for the Desktop V2 voter-bundle import flow.
// The voter downloads a V2 bundle from the Hosted enrollment page and imports
// it in Desktop via import_v2_voter_bundle. This is the production path;
// it must not be confused with the test-only configure_managed_tor (V1).

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const read = (path: string) => readFileSync(new URL(path, import.meta.url), "utf8");
const vote = read("../src/screens/Vote.tsx");
const client = read("../src/api/client.ts");
const dialog = read("../src/api/dialog.ts");
const managedTor = read("../src-tauri/src/managed_tor.rs");

describe("Desktop V2 voter-bundle import", () => {
  it("wires pickV2VoterBundle and importV2VoterBundle into Vote", () => {
    assert.match(vote, /pickV2VoterBundle/);
    assert.match(vote, /api\.importV2VoterBundle\(/);
    assert.match(vote, /onImportV2Bundle/);
    assert.match(vote, /Import V2 bundle from Hosted/);
  });

  it("dialog provides a CBOR file picker for the V2 bundle", () => {
    assert.match(dialog, /pickV2VoterBundle/);
    assert.match(dialog, /Import V2 voter bundle from Hosted/);
  });

  it("client wraps import_v2_voter_bundle with bundle_path and tor config", () => {
    assert.match(client, /"import_v2_voter_bundle"/);
    assert.match(client, /bundle_path/);
    assert.match(client, /importV2VoterBundle/);
    assert.match(client, /ManagedTorStatusV1/);
  });

  it("V2 path is distinct from V1 configure_managed_tor path", () => {
    // Both paths exist: V2 is the new production path, V1 is legacy/test
    assert.match(client, /"configure_managed_tor"/);
    assert.match(client, /"import_v2_voter_bundle"/);
    // V2 import does not reuse voter_public_bundle_path (V1 field)
    const v2Section = client.slice(client.indexOf('"import_v2_voter_bundle"'));
    assert.doesNotMatch(v2Section, /voter_public_bundle_path/);
  });

  it("Rust V2 handler requires an absolute bundle path", () => {
    assert.match(managedTor, /bundle_path.*is_absolute/s);
    assert.match(managedTor, /GUI_V2_BUNDLE_PATH_NOT_ABSOLUTE/);
  });

  it("Rust V2 handler fully verifies the production bundle", () => {
    assert.match(managedTor, /HostedVoterPublicBundleV2/);
    assert.match(managedTor, /from_canonical_cbor/);
    assert.match(managedTor, /GUI_V2_BUNDLE_MALFORMED/);
  });

  it("V2 import sets managed-Tor status (enabling Connect button after import)", () => {
    assert.match(vote, /setManagedTorStatus\(status\)/);
    assert.match(vote, /setReconfiguring\(false\)/);
  });
});
