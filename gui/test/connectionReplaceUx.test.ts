// Replace-ballot-office-connection UX regression tests (Crash Test 5).
//
// A voter accidentally configured a ballot-office connection (voter transport
// bundle) bound to a DIFFERENT election. Submission was correctly rejected as an
// election mismatch. But once a connection was configured, the connection-file
// selector was hidden, so — after Stop private connection — the voter was
// trapped: no visible way to replace the wrong connection file.
//
// Fix (frontend/application-state only): when a connection is configured, the
// private connection is stopped, and the ballot is NOT durably locked, offer
// "Change ballot-office connection", which re-opens the EXISTING configure/
// verify flow. It reuses the existing `configure_managed_tor` command, so
// the election-binding check still fails closed on a mismatch, and it never
// touches the prepared ballot / response / proof / nullifier / election state.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const managedTor = readProjectFile("src-tauri/src/managed_tor.rs");

// -------------------------------------------------------------------------
// The trapped state now has a visible, correctly-gated recovery action.
// -------------------------------------------------------------------------

describe("replace ballot-office connection (frontend)", () => {
  it("offers Change ballot-office connection when configured, stopped, and pre-release", () => {
    // Gate: configured && !tor_running && !ballotCast && !reconfiguring, with the
    // Change control itself only shown before the ballot is durably locked.
    assert.match(
      vote,
      /managedTorStatus\?\.configured &&\s*\n\s*!managedTorStatus\.tor_running &&\s*\n\s*!ballotCast &&\s*\n\s*!reconfiguring/,
    );
    assert.match(vote, /Change ballot-office connection/);
    // The Change control is inside a `!castLocked` guard (never after release).
    const changeIdx = vote.indexOf("Change ballot-office connection");
    const guardIdx = vote.lastIndexOf("{!castLocked && (", changeIdx);
    assert.ok(guardIdx >= 0 && guardIdx < changeIdx, "Change is gated on !castLocked");
  });

  it("Change re-opens the existing connection-file selector (reconfiguring state)", () => {
    assert.match(vote, /const \[reconfiguring, setReconfiguring\] = useState\(false\)/);
    assert.match(vote, /setReconfiguring\(true\)/);
    // The config block reveals when reconfiguring (and only while stopped).
    assert.match(
      vote,
      /\(reconfiguring && !castLocked\)\) &&\s*\n\s*!managedTorStatus\?\.tor_running/,
    );
    // A prominent "choose a different file" control appears during reconfigure.
    assert.match(vote, /Choose a different ballot-office connection file/);
    // And a Cancel to back out without changing anything.
    assert.match(vote, /onClick=\{\(\) => setReconfiguring\(false\)\}/);
  });

  it("reuses the EXISTING configure/verify path — no second validation", () => {
    // Reconnect goes through the same one-click connect (configure + start), which
    // re-runs the backend bundle verification; there is no parallel validator.
    assert.match(vote, /await api\.configureManagedTor\(/);
    assert.doesNotMatch(vote, /verify_and_accept_descriptor|descriptor\.verify/);
  });

  it("clears the reconfigure flow on a successful connect and on election change", () => {
    // Cleared after a successful (re)connect and configure.
    const connect = vote.slice(
      vote.indexOf("async function onConnectPrivately"),
      vote.indexOf("async function onBrowseTorExe"),
    );
    assert.match(connect, /setReconfiguring\(false\)/);
    // Reset on election switch (with the other per-election resets).
    assert.match(vote, /setPrivateError\(null\);\s*\n\s*setReconfiguring\(false\);/);
  });

  it("does not add a secret-bearing field (reconfiguring is a plain boolean)", () => {
    assert.match(vote, /const \[reconfiguring, setReconfiguring\] = useState\(false\)/);
    // No credential/secret is introduced by this control.
    assert.doesNotMatch(vote, /reconfiguring[A-Za-z]*[Pp]assphrase|reconfiguring[A-Za-z]*[Ss]ecret/);
  });
});

// -------------------------------------------------------------------------
// The backend replacement path stays fail-closed and never mutates the ballot.
// -------------------------------------------------------------------------

describe("replace ballot-office connection (backend invariants)", () => {
  function configureBody(): string {
    const start = managedTor.indexOf("pub fn configure_managed_tor");
    assert.ok(start >= 0, "configure command present");
    // End of the function = the first standalone closing brace at the start
    // of a line. Line-ending agnostic: matches LF and CRLF checkouts alike.
    const rest = managedTor.slice(start);
    const closeMatch = rest.match(/\r?\n\}(?:\r?\n|$)/);
    const end = closeMatch?.index !== undefined ? start + closeMatch.index : managedTor.length;
    return managedTor.slice(start, end);
  }

  it("re-verifies the bundle against the loaded election and fails closed on mismatch", () => {
    const body = configureBody();
    assert.match(body, /GUI_VOTER_BUNDLE_WRONG_ELECTION/);
    assert.match(body, /verify_and_accept_descriptor/);
  });

  it("never touches the voter session (prepared ballot / selection / proof preserved)", () => {
    const body = configureBody();
    // Configure only rebuilds the transport (managed_tor) state; it must not
    // read or mutate the voter session, the prepared ballot, or the selection.
    assert.doesNotMatch(body, /state\.voter|prepared_ballot|discard_prepared|set_selection|prepare_ballot|invalidate_prepared|generate_credential|reset_credential/);
    assert.match(body, /\*managed = Some\(managed_state\)/);
  });
});
