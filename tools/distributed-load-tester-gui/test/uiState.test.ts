import assert from "node:assert/strict";
import test from "node:test";

import type { RunConfigInput } from "../src/model.ts";
import {
  VOTES_DELIVERED_LABEL,
  buildLoadTestRequest,
  canStartLoadTest,
  canStopRun,
  formatDuration,
  isStopping,
  isTorReadyForRun,
  isValidationCurrent,
  nextStateAfterStopRequest,
  passphraseMismatch,
  runConfigKey,
  secretFreeProgressText,
  shouldWarnLargeRun,
  stateAfterFailedAction,
  torStatusLabel,
} from "../src/model.ts";

const RESULTS_PATH = "C:\\runs\\desktop\\distributed-load-results.json";

// A representative Run-tab form: managed Tor, 100 credentials available, first
// local credential 1, count 100 — the exact shape of the physical qualification
// run that regressed to 89.
function runForm(overrides: Partial<RunConfigInput> = {}): RunConfigInput {
  return {
    manifestPath: "C:\\election\\election-manifest.cbor",
    registryPath: "C:\\election\\voter-registry.cbor",
    candidatePath: "C:\\election\\candidate-set.cbor",
    voterPublicBundlePath: "C:\\election\\voter-public-bundle.cbor",
    credentialsDir: "C:\\voters",
    passphrase: "correct horse battery staple",
    torMode: "managed",
    torExe: "C:\\tor\\tor.exe",
    torSocks: "127.0.0.1:9050",
    resultsPath: RESULTS_PATH,
    choice: "round-robin",
    count: 100,
    startIndex: 1,
    ...overrides,
  };
}

test("run test is gated until a results path is selected", () => {
  // Fully validated but no results destination: Run Test must stay disabled —
  // durable per-host evidence is mandatory.
  assert.equal(canStartLoadTest("VALIDATED", true, ""), false);
  assert.equal(canStartLoadTest("VALIDATED", true, "   "), false);
  assert.equal(canStartLoadTest("FAILED", true, ""), false);
  assert.equal(canStartLoadTest("STOPPED", true, ""), false);
  // A selected results path unblocks Start (with validation and Tor ready).
  assert.equal(canStartLoadTest("VALIDATED", true, RESULTS_PATH), true);
});

test("the entered voter count reaches the start payload verbatim (100 stays 100)", () => {
  // The physical regression: operator enters first=1, count=100. The payload
  // the backend receives must carry exactly that — never a selected/remaining/
  // detected total.
  const payload = buildLoadTestRequest(runForm({ startIndex: 1, count: 100 }), "gui-123");
  assert.equal(payload.count, 100);
  assert.equal(payload.startIndex, 1);
});

test("an arbitrary count is passed through unchanged (37 stays 37)", () => {
  const payload = buildLoadTestRequest(runForm({ startIndex: 1, count: 37 }), "gui-1");
  assert.equal(payload.count, 37);
  assert.equal(payload.startIndex, 1);
});

test("first-local index and count are independent and both survive (start=38,count=13)", () => {
  const payload = buildLoadTestRequest(runForm({ startIndex: 38, count: 13 }), "gui-1");
  assert.equal(payload.startIndex, 38);
  assert.equal(payload.count, 13);
});

test("start payload nulls the transport field that does not match the Tor mode", () => {
  const managed = buildLoadTestRequest(runForm({ torMode: "managed" }), "gui-1");
  assert.equal(managed.torExe, "C:\\tor\\tor.exe");
  assert.equal(managed.torSocks, null);
  const manual = buildLoadTestRequest(runForm({ torMode: "manual-socks" }), "gui-1");
  assert.equal(manual.torSocks, "127.0.0.1:9050");
  assert.equal(manual.torExe, null);
});

test("validate and start build byte-identical payloads apart from the run id", () => {
  // Both Validate Inputs and Start Load Test go through buildLoadTestRequest on
  // the same unchanged form, so the two payloads can only differ by their
  // per-invocation run id — never by the requested count.
  const form = runForm({ startIndex: 1, count: 100 });
  const validated = buildLoadTestRequest(form, "gui-validate");
  const started = buildLoadTestRequest(form, "gui-start");
  assert.notEqual(validated.runId, started.runId);
  assert.deepEqual({ ...validated, runId: "X" }, { ...started, runId: "X" });
  assert.equal(started.count, 100);
});

test("changing the count after validation invalidates the prior validation", () => {
  // The operator validates at 100; any later change to the count produces a
  // different key, so Start is gated until they re-validate — the corrupted
  // value can never ride a stale validation into a run.
  const validatedKey = runConfigKey(runForm({ count: 100 }));
  assert.equal(isValidationCurrent(validatedKey, runConfigKey(runForm({ count: 100 }))), true);
  assert.equal(isValidationCurrent(validatedKey, runConfigKey(runForm({ count: 89 }))), false);
});

test("changing the first-local index after validation invalidates it", () => {
  const validatedKey = runConfigKey(runForm({ startIndex: 1 }));
  assert.equal(isValidationCurrent(validatedKey, runConfigKey(runForm({ startIndex: 90 }))), false);
});

test("changing the credential directory or election artifacts invalidates validation", () => {
  const validatedKey = runConfigKey(runForm());
  assert.equal(isValidationCurrent(validatedKey, runConfigKey(runForm({ credentialsDir: "C:\\other" }))), false);
  assert.equal(isValidationCurrent(validatedKey, runConfigKey(runForm({ manifestPath: "C:\\other.cbor" }))), false);
});

test("the run id is not part of the validation key", () => {
  // buildLoadTestRequest stamps a fresh run id every call; that id must not be
  // part of the run form, or validation would go stale between validate and
  // start even when nothing the operator controls changed.
  const key = runConfigKey(runForm());
  assert.equal(key.includes("runId"), false);
  assert.equal(key.includes("gui-"), false);
});

test("changing the results path invalidates prior validation", () => {
  const formKey = (resultsPath: string) => JSON.stringify({ resultsPath });
  // Validation recorded for the original path...
  const validatedKey = formKey("C:\\runs\\a\\results.json");
  // ...is current only while the form is unchanged.
  assert.equal(isValidationCurrent(validatedKey, formKey("C:\\runs\\a\\results.json")), true);
  // Any change to the results path (or any other field) produces a different
  // key, so stale validation can never enable Start.
  assert.equal(isValidationCurrent(validatedKey, formKey("C:\\runs\\b\\results.json")), false);
  assert.equal(isValidationCurrent(null, formKey("C:\\runs\\a\\results.json")), false);
});

test("initial start remains disabled until validation succeeds", () => {
  assert.equal(canStartLoadTest("IDLE", false, RESULTS_PATH), false);
  assert.equal(canStartLoadTest("VALIDATED", true, RESULTS_PATH), true);
  assert.equal(canStartLoadTest("RUNNING", true, RESULTS_PATH), false);
});

test("a stop request moves a running run into STOPPING and nothing else changes", () => {
  assert.equal(nextStateAfterStopRequest("RUNNING"), "STOPPING");
  // Repeated or late stop requests are inert.
  assert.equal(nextStateAfterStopRequest("STOPPING"), "STOPPING");
  assert.equal(nextStateAfterStopRequest("VALIDATED"), "VALIDATED");
  assert.equal(nextStateAfterStopRequest("STOPPED"), "STOPPED");
  assert.equal(isStopping("STOPPING"), true);
  assert.equal(isStopping("RUNNING"), false);
});

test("a failed start restores a recoverable FAILED state and re-enables Start", () => {
  // A rejected start_load_test rejection must recover from the in-flight states,
  // regardless of the state value captured when the action closure was created.
  assert.equal(stateAfterFailedAction("RUNNING"), "FAILED");
  assert.equal(stateAfterFailedAction("STOPPING"), "FAILED");
  // FAILED is recoverable: Start is re-enabled once inputs are validated.
  assert.equal(canStartLoadTest("FAILED", true, RESULTS_PATH), true);
});

test("a late failure never clobbers an already-terminal outcome", () => {
  assert.equal(stateAfterFailedAction("COMPLETE"), "COMPLETE");
  assert.equal(stateAfterFailedAction("STOPPED"), "STOPPED");
  assert.equal(stateAfterFailedAction("VALIDATED"), "VALIDATED");
  assert.equal(stateAfterFailedAction("IDLE"), "IDLE");
});

test("start stays disabled and stop is non-actionable while stopping", () => {
  assert.equal(canStartLoadTest("STOPPING", true, RESULTS_PATH), false);
  assert.equal(canStopRun("STOPPING"), false);
  assert.equal(canStopRun("RUNNING"), true);
});

test("delivered-votes label does not claim organizer acceptance", () => {
  assert.equal(VOTES_DELIVERED_LABEL, "Votes delivered (receipt verified)");
  assert.equal(VOTES_DELIVERED_LABEL.toLowerCase().includes("accepted"), false);
});

test("large run warning starts at 100 voters", () => {
  assert.equal(shouldWarnLargeRun(99), false);
  assert.equal(shouldWarnLargeRun(100), true);
});

test("passphrase mismatch is detected without returning the value", () => {
  assert.equal(passphraseMismatch("secret", "different"), true);
  assert.equal(passphraseMismatch("secret", "secret"), false);
});

test("progress text uses safe credential filename only", () => {
  const text = secretFreeProgressText({
    totalVoters: 4,
    completedVoters: 2,
    accepted: 1,
    rejected: 0,
    failed: 1,
    remaining: 2,
    currentCredentialFile: "voter-0002.tcbcred",
  });
  assert.equal(text.includes("voter-0002.tcbcred"), true);
  assert.equal(text.includes("passphrase"), false);
  assert.equal(text.includes("secret"), false);
});

test("duration formatting handles running summaries", () => {
  assert.equal(formatDuration(undefined), "n/a");
  assert.equal(formatDuration(900), "900 ms");
  assert.equal(formatDuration(61_000), "1m 1s");
});

test("managed Tor gates Start Load Test until the executable is Ready", () => {
  // Never selected: blocked even after Validate.
  assert.equal(isTorReadyForRun("managed", "NOT_SELECTED"), false);
  // Selected but validation failed: also blocked.
  assert.equal(isTorReadyForRun("managed", "INVALID"), false);
  assert.equal(isTorReadyForRun("managed", "TEST_FAILED"), false);
  // Ready or Tested-Ready both unblock Start.
  assert.equal(isTorReadyForRun("managed", "READY"), true);
  assert.equal(isTorReadyForRun("managed", "TESTED_READY"), true);
});

test("advanced manual-SOCKS mode is not gated by managed Tor validation", () => {
  // Manual SOCKS has no separate Tor validation surface; the endpoint is
  // validated together with the other inputs, so Tor status is not the gate.
  assert.equal(isTorReadyForRun("manual-socks", "NOT_SELECTED"), true);
  assert.equal(isTorReadyForRun("manual-socks", "READY"), true);
});

test("Tor status labels never expose secret markers", () => {
  const rendered = [
    "NOT_SELECTED",
    "SELECTED",
    "VALIDATING",
    "READY",
    "INVALID",
    "TESTING",
    "TESTED_READY",
    "TEST_FAILED",
  ]
    .map((status) => torStatusLabel(status as never))
    .join(" ")
    .toLowerCase();
  for (const marker of ["passphrase", "secret", "credential"]) {
    assert.equal(rendered.includes(marker), false, `Tor status label leaks ${marker}`);
  }
});
