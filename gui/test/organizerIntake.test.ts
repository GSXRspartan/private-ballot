// Phase B — organizer near-one-click private intake (frontend surface).
//
// The organizer must be able to run private ballot intake without PowerShell,
// cargo, a torrc, a SOCKS/collector port, an onion hostname, a descriptor
// fingerprint, or an app-data-root lookup. These are source-assertion tests
// (no React harness): they pin the presence of the one-click controls, that the
// crowded operator details are demoted to diagnostics, that the client wires the
// backend commands, and that the status DTO carries no secret-bearing fields.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const manage = readProjectFile("src/screens/ManageElection.tsx");
const client = readProjectFile("src/api/client.ts");
const types = readProjectFile("src/api/types.ts");

describe("organizer one-click private intake controls", () => {
  it("offers Start / Stop / Export voter bundle as primary actions", () => {
    assert.match(manage, /Start private intake/);
    assert.match(manage, /Stop private intake/);
    assert.match(manage, /Export voter transport bundle/);
  });

  it("shows a plain Tor / transport status line, not raw ports or torrc", () => {
    assert.match(manage, /label="Tor"/);
    assert.match(manage, /label="Election transport"/);
    // Normal operation never asks the operator to type a SOCKS/collector port,
    // a torrc path, an onion hostname, or the app-data root.
    assert.doesNotMatch(manage, /SOCKS port/i);
    assert.doesNotMatch(manage, /collector port/i);
    assert.doesNotMatch(manage, /app-data root/i);
  });

  it("keeps the crowded operator details under an Advanced / diagnostics disclosure", () => {
    assert.match(manage, /Advanced \/ diagnostics/);
    // The onion, fingerprint, collector address and Tor data dir are diagnostics,
    // not primary UI.
    assert.match(manage, /Verified onion/);
    assert.match(manage, /Descriptor fingerprint/);
  });

  it("provides a Select Tor executable fallback and states it never downloads Tor", () => {
    assert.match(manage, /Select Tor executable/);
    assert.match(manage, /never downloads or installs Tor/);
  });

  it("does not auto-open voting when intake starts", () => {
    assert.match(manage, /Starting intake does not open voting/);
  });
});

describe("organizer intake client bindings", () => {
  it("wires the four backend intake commands", () => {
    assert.match(client, /organizer_tor_status/);
    assert.match(client, /start_private_intake/);
    assert.match(client, /stop_private_intake/);
    assert.match(client, /export_voter_transport_bundle/);
  });

  it("passes the tor.exe path as an optional convenience only", () => {
    // Both status and start accept an optional remembered path; the backend
    // re-validates and may fall back to its allowlist.
    assert.match(client, /organizerTorStatus:\s*\(torExePath\?: string\)/);
    assert.match(client, /startPrivateIntake:\s*\(torExePath\?: string\)/);
  });
});

describe("organizer intake status DTO is organizer-safe", () => {
  it("carries only aggregates and non-secret diagnostics", () => {
    const block = types.slice(
      types.indexOf("export interface OrganizerIntakeStatusV1"),
      types.indexOf("export interface VoterBundleExportResultV1"),
    );
    assert.match(block, /accepted_ballots: number/);
    assert.match(block, /transport_provisioned: boolean/);
    // No secret-bearing fields ever cross the boundary.
    assert.doesNotMatch(block, /secret|private_key|signing_key|receiver_secret|passphrase|seed/i);
  });
});
