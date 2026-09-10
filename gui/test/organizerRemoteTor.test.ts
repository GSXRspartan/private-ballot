// External-remote organizer Tor hosting regression tests (local prototype).
//
// The remote organizer mode lets an EXTERNALLY managed Tor instance host the
// organizer onion service. Hard boundaries that must never regress:
//   * managed-local is the default; unknown/legacy mode tokens fail SAFE to it;
//   * a malformed persisted endpoint/port fails closed;
//   * the backend independently re-validates every value (frontend is
//     convenience-only);
//   * remote mode NEVER spawns/stops Tor, never creates a local
//     hidden-service directory, and never reserves a local SOCKS port;
//   * readiness is endpoint-scoped and sends ZERO ballot application bytes;
//   * there is no clearnet fallback anywhere.
//
// Where no React/DOM harness exists, behavior is pinned by direct unit tests
// of the persistence sanitizer plus semantic source assertions.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  recallOrganizerRemoteTorConfig,
  sanitizeOrganizerRemoteTorConfig,
} from "../src/api/organizerRemoteTorMemory.ts";

const intake = readFileSync(
  new URL("../src/screens/ManageElection.tsx", import.meta.url),
  "utf8",
);
const intakeBackend = readFileSync(
  new URL("../../gui/src-tauri/src/organizer_tor_intake.rs", import.meta.url),
  "utf8",
);
const backendCode = intakeBackend.split("#[cfg(test)]")[0] ?? "";
const transportTor = readFileSync(
  new URL("../../crates/transport-network/src/tor.rs", import.meta.url),
  "utf8",
);

// ---------------------------------------------------------------------------
// Persistence sanitizer (fail-safe normalization)
// ---------------------------------------------------------------------------

test("unknown organizer Tor mode normalizes to managed-local, never remote", () => {
  for (const bad of ["", "remote", "external", "EXTERNAL-REMOTE", "socks", "bogus"]) {
    assert.equal(
      sanitizeOrganizerRemoteTorConfig({ torMode: bad }).torMode,
      "managed-local",
      `mode ${bad} must fail safe to managed-local`,
    );
  }
  assert.equal(
    sanitizeOrganizerRemoteTorConfig({ torMode: "external-remote" }).torMode,
    "external-remote",
  );
  assert.equal(sanitizeOrganizerRemoteTorConfig(null).torMode, "managed-local");
  assert.equal(sanitizeOrganizerRemoteTorConfig({}).torMode, "managed-local");
});

test("malformed persisted ports are cleared so they fail closed on reload", () => {
  for (const bad of ["0", "70000", "not-a-port", "-1", "9050x", ""]) {
    assert.equal(
      sanitizeOrganizerRemoteTorConfig({ socksPort: bad }).socksPort,
      "",
      `port ${bad} must be cleared`,
    );
    assert.equal(
      sanitizeOrganizerRemoteTorConfig({ collectorPort: bad }).collectorPort,
      "",
      `collector port ${bad} must be cleared`,
    );
  }
  assert.equal(sanitizeOrganizerRemoteTorConfig({ socksPort: "9050" }).socksPort, "9050");
  assert.equal(
    sanitizeOrganizerRemoteTorConfig({ collectorPort: "18081" }).collectorPort,
    "18081",
  );
});

test("the persisted organizer remote config contains only non-secret keys", () => {
  const recalled = recallOrganizerRemoteTorConfig();
  for (const key of Object.keys(recalled)) {
    assert.match(
      key,
      /^(torMode|socksHost|socksPort|onionHostname|collectorPort)$/,
      "no secret material may enter the organizer remote config store",
    );
  }
});

// ---------------------------------------------------------------------------
// Frontend wiring (source assertions)
// ---------------------------------------------------------------------------

test("the intake start call threads the remote config through to the backend", () => {
  assert.match(intake, /api\.startPrivateIntake\(\s*intakeTorExepathOrUndefined\(\),\s*remoteIntakeArg\(\),\s*\)/);
  assert.match(intake, /api\.testRemoteOrganizerTor\(arg\)/);
  // Malformed numbers are sent as 0 so the backend rejects the whole request.
  assert.match(intake, /\? Number\(remoteSocksPort\.trim\(\)\)\s*: 0/);
  assert.match(intake, /\? Number\(remoteCollectorPort\.trim\(\)\)\s*: 0/);
});

test("the remote organizer UI carries the trusted-network security note", () => {
  assert.match(intake, /Remote Organizer Tor/);
  assert.match(intake, /trusted LAN, VPN, or protected tunnel/);
  assert.match(intake, /does not manage or\s+verify/);
  assert.match(intake, /not itself encrypted/);
  // The advanced mode selector is hidden from the guided view entirely.
  assert.match(intake, /showAllControls && \(\s*<>[\s\S]*?Organizer Tor hosting/);
});

// ---------------------------------------------------------------------------
// Backend boundaries (source assertions)
// ---------------------------------------------------------------------------

test("external-remote mode never spawns, kills, or owns a Tor process", () => {
  // The only child signal is guarded by Option::take on the owned child, which
  // is always None in remote mode; remote provisioning and the remote worker
  // must contain no spawn and no hidden-service/torrc writes.
  const remoteProvision = backendCode.match(
    /fn provision_transport_remote[\s\S]*?\n\}/,
  );
  assert.ok(remoteProvision, "remote provisioning function must exist");
  assert.ok(
    !/spawn|write_config|HiddenServiceDir|create_dir_all\(&paths\.hidden_service_dir\)/.test(
      remoteProvision[0],
    ),
    "remote provisioning must not spawn Tor or create a hidden-service directory",
  );
  const remoteWorker = backendCode.match(/fn start_remote_intake_worker[\s\S]*?\n\}/);
  assert.ok(remoteWorker, "remote worker function must exist");
  assert.ok(
    !/spawn\(|DiagnosticTorSpawnerV1|OrganizerHiddenServiceTorConfigV1|reserve_loopback/.test(
      remoteWorker[0],
    ),
    "the remote worker must not spawn Tor, build a torrc, or reserve a managed SOCKS port",
  );
  assert.match(
    backendCode,
    /tor_child: Option<Child>/,
    "the owned Tor child must be optional (None in remote mode)",
  );
});

test("remote mode fails closed on malformed config and unknown mode tokens", () => {
  assert.match(backendCode, /GUI_ORGANIZER_REMOTE_CONFIG_INVALID/);
  // Unknown/legacy tokens resolve to managed-local (fail safe).
  assert.match(
    backendCode,
    /"external-remote" => Self::ExternalRemote,\s*_ => Self::ManagedLocal/,
  );
});

test("remote readiness binds the exact onion and sends zero application bytes first", () => {
  // The remote worker must gate on descriptor-onion equality BEFORE readiness.
  const remoteWorker = backendCode.match(/fn start_remote_intake_worker[\s\S]*?Ok\(OrganizerIntakeState/);
  assert.ok(remoteWorker, "remote worker function must exist");
  const worker = remoteWorker[0];
  const equalityGate = worker.indexOf("descriptor_onion != config.onion_hostname");
  const probe = worker.indexOf("probe_remote_onion_hostname_v1");
  assert.ok(equalityGate > -1, "descriptor onion equality gate must exist");
  assert.ok(probe > equalityGate, "readiness runs only AFTER the binding gate");
  // Readiness is exactly: zero-byte probe, then one credential-free status GET.
  assert.match(worker, /probe_remote_onion_hostname_v1/);
  assert.match(worker, /fetch_election_status_over_remote_tor_onion/);
  assert.ok(
    worker.indexOf("probe_remote_onion_hostname_v1") <
      worker.indexOf("fetch_election_status_over_remote_tor_onion"),
    "the zero-application-byte probe must precede the status fetch",
  );
});

test("mode switching between managed-local and external-remote requires an explicit stop", () => {
  assert.match(backendCode, /GUI_ORGANIZER_INTAKE_MODE_MISMATCH/);
  assert.match(backendCode, /m\.mode == requested_mode/);
});

test("shutdown reaps only an OWNED child and leaves external infrastructure untouched", () => {
  assert.match(backendCode, /if let Some\(mut child\) = m\.tor_child\.take\(\)/);
  assert.match(
    backendCode,
    /tor_child: Option<Child>/,
  );
  assert.match(
    backendCode,
    /the external daemon is explicitly not owned/,
  );
});

// ---------------------------------------------------------------------------
// Transport primitives (no clearnet, literal onion)
// ---------------------------------------------------------------------------

test("the explicit-hostname remote probe reuses the shared zero-byte SOCKS path", () => {
  assert.match(transportTor, /pub fn probe_remote_onion_hostname_v1/);
  assert.match(transportTor, /pub fn fetch_election_status_over_remote_tor_onion/);
  // The onion hostname is validated BEFORE any connection in the probe.
  const probe = transportTor.match(
    /pub fn probe_remote_onion_hostname_v1[\s\S]*?\n\}/,
  );
  assert.ok(probe, "probe must exist");
  const validateAt = probe[0].indexOf("validate_onion_hostname_v1");
  const proxyAt = probe[0].indexOf("SocksProxyEndpointV1::Remote");
  assert.ok(validateAt > -1 && proxyAt > validateAt);
});
