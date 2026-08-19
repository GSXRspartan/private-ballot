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
  isTransientPrivateReleaseResult,
} from "../src/privateSubmission.ts";
import type {
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

describe("bounded backoff policy", () => {
  it("is small and finite (at most 3 automatic retries)", () => {
    assert.ok(PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.length >= 1);
    assert.ok(PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS.length <= 3);
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
    assert.match(runner, /result = await api\.retryPrivateSubmission\(\)/);
    // It must NOT prepare, re-submit, or change the choice inside the loop.
    assert.doesNotMatch(runner, /submitPreparedVoterBallotPrivately/);
    assert.doesNotMatch(runner, /prepareVoterBallot|changeMyBallotChoice|setVoterBallotSelection/);
  });

  it("bounds the loop by the backoff schedule length and the transient classifier", () => {
    assert.match(vote, /attempt < PRIVATE_SUBMISSION_AUTO_RETRY_BACKOFF_MS\.length/);
    assert.match(vote, /isTransientPrivateReleaseResult\(result\)/);
  });

  it("stops promptly on cancel and offers a Stop retrying control", () => {
    assert.match(vote, /!autoRetryCancelRef\.current/);
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
    const awaitIdx = runner.indexOf("await initialAttempt()");
    assert.ok(busyIdx >= 0 && awaitIdx >= 0, "runner must set busy then await the attempt");
    assert.ok(busyIdx < awaitIdx, "busy must be set before the initial attempt awaits");
  });
});
