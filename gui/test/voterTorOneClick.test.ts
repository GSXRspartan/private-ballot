// Phase C — voter near-one-click Tor (frontend surface).
//
// A normal voter must connect and submit over Tor without typing a SOCKS port,
// torrc, Tor data directory, onion hostname, or descriptor fingerprint. Source-
// assertion tests (no React harness): they pin the one-click Connect flow, the
// auto data directory (empty → backend-derived), the demotion of manual paths to
// Advanced, the Tor-found status line, and the absence of any clearnet fallback.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const client = readProjectFile("src/api/client.ts");

describe("voter one-click Tor connect", () => {
  it("offers a single Connect privately action", () => {
    assert.match(vote, /Connect privately/);
    assert.match(vote, /onConnectPrivately/);
  });

  it("shows a Tor installed status line and a ballot-office file status line", () => {
    assert.match(vote, /Tor installed/);
    assert.match(vote, /Ballot office/);
  });

  it("auto-derives the Tor data directory (passes an empty dir to the backend)", () => {
    // The one-click connect passes "" for the data dir so the backend derives an
    // app-owned, election-scoped directory the voter never chooses. The optional
    // 4th argument carries the advanced remote-SOCKS endpoint (undefined in the
    // default managed-local mode).
    assert.match(vote, /configureManagedTor\(torExePath, "", voterBundlePath, remoteConfigureArg\(\)\)/);
  });

  it("keeps the manual tor.exe/data-dir inputs under Advanced only", () => {
    // The data directory input carries an 'auto' placeholder and is not part of
    // the primary flow; it lives inside an Advanced disclosure.
    assert.match(vote, /Tor data directory \(optional\)/);
    assert.match(vote, /auto \(app-owned, election-scoped\)/);
    assert.match(vote, /summary="Advanced"/);
  });

  it("offers Select Tor executable and a ballot-office connection file picker when needed", () => {
    assert.match(vote, /Select Tor executable/);
    assert.match(vote, /Select ballot-office connection file/);
    assert.match(vote, /never downloads or installs Tor/);
  });

  it("routes the one-click connect only through managed Tor, no clearnet fallback", () => {
    // Connect privately configures + starts the managed Tor carrier; there is no
    // alternate clearnet start path in the one-click flow.
    assert.match(vote, /no clearnet fallback exists/);
    assert.match(vote, /await api\.startManagedTor\(\)/);
  });
});

describe("voter Tor status client binding", () => {
  it("wires the read-only voter_tor_status probe", () => {
    assert.match(client, /voter_tor_status/);
    assert.match(client, /voterTorStatus:\s*\(torExePath\?: string\)/);
  });
});
