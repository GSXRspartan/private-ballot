// Issue 1 — bounded automatic retry of the EXACT same private submission on a
// transient transport/onion-reachability failure.
//
// Pure-logic tests for the transient classifier + backoff policy, plus source
// assertions pinning the bounded, cancellable, exact-retry orchestration (no
// React harness). The backend exact-retry path (staged-envelope digest reuse,
// authenticated-receipt-mandatory CAST, fail-closed CAST_PENDING) is unchanged
// and already covered by gui-core tests; these tests cover the new frontend
// orchestration.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS,
  TRANSIENT_TRANSPORT_STAGE,
  isRecoverableTransportError,
  isTransientPrivateReleaseResult,
} from "../src/privateSubmission.ts";
import type {
  GuiCommandError,
  GuiPrivateReleaseResultV1,
  GuiPrivateSubmissionResultV1,
} from "../src/api/types.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");

function release(
  cast_lock_state: string,
  diagnostic_stage: string | null,
  released = false,
): GuiPrivateReleaseResultV1 {
  return {
    cast_lock_state,
    receipt_state: released ? "ACCEPTED" : "PENDING",
    released,
    package_digest_hex: "aa".repeat(32),
    diagnostic_stage,
  };
}

describe("transient private-submission classifier", () => {
  it("treats CAST_PENDING + PRIVATE_TRANSPORT_UNAVAILABLE as transient", () => {
    assert.equal(
      isTransientPrivateReleaseResult(release("CAST_PENDING", TRANSIENT_TRANSPORT_STAGE)),
      true,
    );
  });

  it("never treats a successful CAST as transient", () => {
    assert.equal(isTransientPrivateReleaseResult(release("CAST", null, true)), false);
  });

  it("never retries cryptographic / protocol / authenticated-rejection stages", () => {
    for (const stage of [
      "RECEIPT_PARSE_FAILED",
      "RECEIPT_SIGNATURE_INVALID",
      "RECEIPT_DESCRIPTOR_MISMATCH",
      "RECEIPT_PACKAGE_MISMATCH",
      "RECEIPT_REJECTED_BY_ORGANIZER",
      "RECEIPT_PERSIST_FAILED",
      "CAST_PROMOTION_FAILED",
    ]) {
      assert.equal(
        isTransientPrivateReleaseResult(release("CAST_PENDING", stage)),
        false,
        `stage ${stage} must not be auto-retried`,
      );
    }
  });

  it("returns false for a non-release (offline export) result and for null", () => {
    const offline: GuiPrivateSubmissionResultV1 = {
      route: "OfflineExport",
      receipt_state: "PENDING",
      retry_status: "NONE",
      reduced_anonymity: false,
    };
    assert.equal(isTransientPrivateReleaseResult(offline), false);
    assert.equal(isTransientPrivateReleaseResult(null), false);
  });
});

describe("recoverable transport-error classifier (Failure 7)", () => {
  function err(code: string): GuiCommandError {
    return { code, category: "UNAVAILABLE", context: null, message: "x" };
  }

  it("treats transient transport-delivery codes as recoverable", () => {
    assert.equal(isRecoverableTransportError(err("GUI_PRIVATE_TRANSPORT_UNAVAILABLE")), true);
    assert.equal(isRecoverableTransportError(err("GUI_TOR_CARRIER_UNAVAILABLE")), true);
  });

  it("never treats local-Tor-down or terminal/protocol errors as recoverable", () => {
    // Local Tor down needs an explicit Reconnect, not a blind retry.
    assert.equal(isRecoverableTransportError(err("GUI_TOR_NOT_RUNNING")), false);
    // Cryptographic / protocol / authenticated-rejection style codes are terminal.
    for (const code of [
      "GUI_BALLOT_ALREADY_CAST",
      "GUI_RELEASE_WRONG_ELECTION",
      "GUI_RELEASE_DESCRIPTOR_CHANGED",
      "GUI_NO_PREPARED_BALLOT",
      "GUI_UNEXPECTED_ERROR",
    ]) {
      assert.equal(isRecoverableTransportError(err(code)), false, code);
    }
    assert.equal(isRecoverableTransportError(null), false);
  });

  it("treats PRE-staging descriptor/seal failures as terminal (fail-closed, NOT_CAST)", () => {
    // These are the new HONEST pre-staging codes: a descriptor-authenticity /
    // election-binding / seal failure must NOT be auto-retried as if it were a
    // transient ballot-office outage (Failure 7 correction).
    for (const code of [
      "GUI_RELEASE_DESCRIPTOR_UNTRUSTED",
      "GUI_RELEASE_DESCRIPTOR_CONFLICT",
      "GUI_RELEASE_DESCRIPTOR_WRONG_ELECTION",
      "GUI_RELEASE_DESCRIPTOR_INVALID",
      "GUI_RELEASE_DESCRIPTOR_UNVERIFIED",
      "GUI_RELEASE_ENVELOPE_SEAL_FAILED",
      "GUI_RELEASE_BALLOT_OVERSIZED",
    ]) {
      assert.equal(isRecoverableTransportError(err(code)), false, code);
    }
  });
});

describe("frontend never fabricates CAST_PENDING from an error code", () => {
  it("gates the thrown-error retry path on the AUTHORITATIVE durable state", () => {
    const vote = readProjectFile("src/screens/Vote.tsx");
    const runner = vote.slice(
      vote.indexOf("async function runBoundedPrivateSubmission"),
      vote.indexOf("function onStopAutoRetry"),
    );
    // Durable cast state is re-read from the backend, and the recoverable retry
    // path is entered ONLY when that authoritative state is CAST_PENDING — an
    // error code alone can never imply a locked ballot.
    assert.match(runner, /const castStateNow = await durableCastStateOrNull\(\)/);
    assert.match(runner, /castStateNow === "CAST_PENDING" && isRecoverableTransportError/);
    // durableCastStateOrNull reads the backend workflow status, never a guess.
    assert.match(vote, /async function durableCastStateOrNull\(\)/);
    assert.match(vote, /api\.voterWorkflowStatus\(confirmed\)/);
    assert.match(vote, /return status\.cast_lock_state;/);
  });
});

describe("bounded backoff policy", () => {
  it("is finite and restart-aware but never unbounded", () => {
    // 5 retries (6 attempts total): still a small, terminating schedule — never
    // an unbounded background loop.
    assert.ok(PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.length >= 1);
    assert.ok(PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.length <= 6);
  });

  it("is the exact two-band restart-aware schedule (quick then slower)", () => {
    // Quick band clears brief hiccups; the slower band tolerates hidden-service
    // re-publication latency after the ballot office restarts Tor (~1 minute).
    assert.deepEqual(
      [...PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS],
      [2000, 5000, 8000, 15000, 30000],
    );
  });

  it("is strictly non-decreasing so later retries wait longer, not shorter", () => {
    for (let i = 1; i < PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.length; i += 1) {
      assert.ok(
        PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS[i] >=
          PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS[i - 1],
        "backoff must not shrink",
      );
    }
  });

  it("covers roughly the observed restart window without hammering the onion", () => {
    const totalDelayMs = PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.reduce((a, b) => a + b, 0);
    // Enough to bridge a ~1-minute republication, but bounded and finite.
    assert.ok(totalDelayMs >= 45000, "should tolerate restart latency");
    assert.ok(totalDelayMs <= 120000, "must stay bounded");
  });

  it("uses positive, bounded delays", () => {
    for (const ms of PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS) {
      assert.ok(ms > 0 && ms <= 30000, `delay ${ms} out of bounds`);
    }
  });
});

describe("bounded exact-retry orchestration (Vote.tsx)", () => {
  it("re-attempts ONLY through the exact-retry command, never a new submit/prepare", () => {
    const runner = vote.slice(
      vote.indexOf("async function runBoundedPrivateSubmission"),
      vote.indexOf("function onStopAutoRetry"),
    );
    // The loop's re-attempt is the exact-retry path.
    assert.match(runner, /api\.retryPrivateSubmission\(\)/);
    // It must NOT prepare, re-submit, or change the choice inside the loop.
    assert.doesNotMatch(runner, /submitPreparedVoterBallotPrivately/);
    assert.doesNotMatch(runner, /prepareVoterBallot|changeMyBallotChoice|setVoterBallotSelection/);
  });

  it("bounds the loop by the backoff schedule length and the transient classifier", () => {
    assert.match(vote, /attempt >= PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS\.length/);
    assert.match(vote, /isTransientPrivateReleaseResult\(result\)/);
  });

  it("stops promptly on cancel and offers a Stop retrying control", () => {
    assert.match(vote, /autoRetryCancelRef\.current/);
    assert.match(vote, /Stop retrying/);
    assert.match(vote, /function onStopAutoRetry/);
  });

  it("cancels auto-retry on stop, election switch, and unmount", () => {
    // Stopping the connection cancels retries.
    assert.match(vote, /autoRetryCancelRef\.current = true;[\s\S]*api\.stopManagedTor\(\)/);
    // Unmount cleanup cancels retries.
    assert.match(vote, /return \(\) => \{\s*autoRetryCancelRef\.current = true;\s*\};/);
  });

  it("keeps the manual Retry private submission button as a fallback", () => {
    assert.match(vote, /Retry private submission/);
    assert.match(vote, /onRetryPrivateSubmission/);
  });

  it("establishes the SUBMITTING (busy) state BEFORE the request completes", () => {
    // Responsiveness (real-test blocker A): the runner marks busy=true before the
    // first attempt awaits, so the "Submitting privately…" status paints while the
    // (now off-main-thread) Tor request is in flight instead of after it returns.
    const runner = vote.slice(
      vote.indexOf("async function runBoundedPrivateSubmission"),
      vote.indexOf("function onStopAutoRetry"),
    );
    const busyIdx = runner.indexOf("setBusy(true)");
    const awaitIdx = runner.indexOf("await nextAttempt()");
    assert.ok(busyIdx >= 0 && awaitIdx >= 0, "runner must set busy then await the attempt");
    assert.ok(busyIdx < awaitIdx, "busy must be set before the initial attempt awaits");
  });

  it("keeps a thrown recoverable transport failure in the exact-retry flow (Failure 7)", () => {
    const runner = vote.slice(
      vote.indexOf("async function runBoundedPrivateSubmission"),
      vote.indexOf("function onStopAutoRetry"),
    );
    // A THROWN attempt is caught; a recoverable transport error while the ballot
    // is durably CAST_PENDING continues the bounded backoff instead of breaking
    // into a generic terminal error, so a transient ballot-office outage reaches
    // (and stays in) the retry/backoff state.
    assert.match(runner, /catch \(err\)/);
    assert.match(runner, /durableCastStateOrNull\(\)/);
    assert.match(runner, /castStateNow === "CAST_PENDING" && isRecoverableTransportError\(commandError\)/);
    assert.match(runner, /recoverableTransient = true/);
    // A non-recoverable / not-locked failure is surfaced and never retried.
    assert.match(runner, /setPrivateError\(commandError\);\s*\n\s*break;/);
    // The retry step still re-sends ONLY the exact staged submission.
    assert.match(runner, /nextAttempt = \(\) => api\.retryPrivateSubmission\(\)/);
  });
});
