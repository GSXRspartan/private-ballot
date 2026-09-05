import assert from "node:assert/strict";
import test from "node:test";

import {
  VOTES_DELIVERED_LABEL,
  canStartLoadTest,
  canStopRun,
  formatDuration,
  isStopping,
  isTorReadyForRun,
  nextStateAfterStopRequest,
  passphraseMismatch,
  secretFreeProgressText,
  shouldWarnLargeRun,
  stateAfterFailedAction,
  torStatusLabel,
} from "../src/model.ts";

test("initial start remains disabled until validation succeeds", () => {
  assert.equal(canStartLoadTest("IDLE", false), false);
  assert.equal(canStartLoadTest("VALIDATED", true), true);
  assert.equal(canStartLoadTest("RUNNING", true), false);
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
  assert.equal(canStartLoadTest("FAILED", true), true);
});

test("a late failure never clobbers an already-terminal outcome", () => {
  assert.equal(stateAfterFailedAction("COMPLETE"), "COMPLETE");
  assert.equal(stateAfterFailedAction("STOPPED"), "STOPPED");
  assert.equal(stateAfterFailedAction("VALIDATED"), "VALIDATED");
  assert.equal(stateAfterFailedAction("IDLE"), "IDLE");
});

test("start stays disabled and stop is non-actionable while stopping", () => {
  assert.equal(canStartLoadTest("STOPPING", true), false);
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
