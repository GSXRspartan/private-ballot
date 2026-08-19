// Controlled managed-Tor recovery/status regression tests.
//
// Pins the voter-facing repairs from the real one-computer test: the recovery
// card survives a restart (shown for CAST_PENDING / CAST, not only a Ready
// prepared ballot), CAST_PENDING exposes Retry and not a fresh Submit, the
// submission status is derived from DURABLE cast state (so SUCCESS/PENDING
// survive a refresh), private-submission errors render next to the controls,
// the stale "not available in this build" message no longer contradicts an
// active controlled-test card, and the three NON-SECRET test paths are
// remembered without ever storing secret material.
//
// Where no React harness exists, behavior is pinned by semantic source
// assertions plus direct unit tests of the pure helpers.
//
// Run with: npm test

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  managedTorTestCardVisible,
  privateSubmissionStageLabel,
  privateSubmissionStatus,
} from "../src/privateSubmission.ts";
import {
  recallManagedTorConfig,
  rememberManagedTorConfig,
  sanitizeManagedTorConfig,
} from "../src/api/managedTorConfigMemory.ts";

function readProjectFile(path: string): string {
  return readFileSync(new URL(`../${path}`, import.meta.url), "utf8");
}

const vote = readProjectFile("src/screens/Vote.tsx");
const dialog = readProjectFile("src/api/dialog.ts");

// -------------------------------------------------------------------------
// privateSubmissionStatus: derived from DURABLE cast state (Issues 4, 17)
// -------------------------------------------------------------------------

describe("privateSubmissionStatus derives from durable cast state", () => {
  const base = {
    configured: true,
    torRunning: true,
    busy: false,
    lastReceiptState: null as string | null,
  };

  it("CAST is unmistakable success referencing the authenticated receipt", () => {
    const s = privateSubmissionStatus({ ...base, castState: "CAST" });
    assert.equal(s.phase, "SUCCESS");
    assert.equal(s.tone, "ok");
    assert.match(s.title, /ballot was accepted/i);
    assert.match(s.detail, /authenticated receipt/i);
    // Success is delivery-only: it never claims counting/inclusion/anchoring.
    assert.doesNotMatch(`${s.title} ${s.detail}`, /counted|included|anchored/i);
  });

  it("CAST wins even if the transport connection looks down", () => {
    const s = privateSubmissionStatus({
      castState: "CAST",
      configured: false,
      torRunning: false,
      busy: false,
      lastReceiptState: null,
    });
    assert.equal(s.phase, "SUCCESS");
  });

  it("CAST_PENDING (idle) is a locked, retriable pending state", () => {
    const s = privateSubmissionStatus({ ...base, castState: "CAST_PENDING" });
    assert.equal(s.phase, "PENDING");
    assert.equal(s.tone, "warn");
    assert.match(s.title, /wasn't confirmed/i);
    assert.match(s.detail, /safely locked/i);
    assert.match(s.detail, /no new ballot will be created/i);
  });

  it("CAST_PENDING never claims success", () => {
    const s = privateSubmissionStatus({ ...base, castState: "CAST_PENDING" });
    assert.doesNotMatch(`${s.title} ${s.detail}`, /submitted successfully|accepted/i);
  });

  it("CAST_PENDING with a REJECTED receipt is an explicit rejection", () => {
    const s = privateSubmissionStatus({
      ...base,
      castState: "CAST_PENDING",
      lastReceiptState: "REJECTED",
    });
    assert.equal(s.phase, "REJECTED");
    assert.equal(s.tone, "error");
    assert.match(s.title, /rejected by the organizer/i);
  });

  it("an in-flight request shows SUBMITTING waiting for the receipt", () => {
    const s = privateSubmissionStatus({ ...base, castState: "NOT_CAST", busy: true });
    assert.equal(s.phase, "SUBMITTING");
    assert.match(s.detail, /authenticated organizer receipt/i);
  });

  it("NOT_CAST maps connection readiness truthfully", () => {
    assert.equal(
      privateSubmissionStatus({ ...base, castState: "NOT_CAST", configured: false, torRunning: false })
        .phase,
      "NOT_CONFIGURED",
    );
    assert.equal(
      privateSubmissionStatus({ ...base, castState: "NOT_CAST", configured: true, torRunning: false })
        .phase,
      "READY_TO_START",
    );
    assert.equal(
      privateSubmissionStatus({ ...base, castState: "NOT_CAST", configured: true, torRunning: true })
        .phase,
      "READY",
    );
  });

  it("a ready connection never by itself implies delivery", () => {
    const s = privateSubmissionStatus({ ...base, castState: "NOT_CAST" });
    assert.doesNotMatch(`${s.title} ${s.detail}`, /delivered|received by the organizer|submitted/i);
  });
});

// -------------------------------------------------------------------------
// Recovery card survives restart (Issue 2)
// -------------------------------------------------------------------------

describe("controlled-test recovery card gating", () => {
  // 1. Feature present + Ready → card visible.
  it("feature present + prepared Ready → controlled-test card visible", () => {
    assert.equal(
      managedTorTestCardVisible({
        featurePresent: true,
        preparedReady: true,
        castState: "NOT_CAST",
      }),
      true,
    );
  });

  // 2. Feature present + CAST_PENDING + NOT Ready → recovery card visible.
  it("feature present + CAST_PENDING + not Ready → recovery card visible (restart fix)", () => {
    assert.equal(
      managedTorTestCardVisible({
        featurePresent: true,
        preparedReady: false,
        castState: "CAST_PENDING",
      }),
      true,
    );
  });

  // 3. Feature present + CAST + NOT Ready → success card visible.
  it("feature present + CAST + not Ready → terminal success card visible", () => {
    assert.equal(
      managedTorTestCardVisible({
        featurePresent: true,
        preparedReady: false,
        castState: "CAST",
      }),
      true,
    );
  });

  // 4. Feature absent + Ready → controlled-test card absent.
  it("feature absent + Ready → controlled-test card absent", () => {
    assert.equal(
      managedTorTestCardVisible({
        featurePresent: false,
        preparedReady: true,
        castState: "NOT_CAST",
      }),
      false,
    );
  });

  // 5. Feature absent + CAST_PENDING → controlled-test card absent.
  it("feature absent + CAST_PENDING → controlled-test card absent", () => {
    assert.equal(
      managedTorTestCardVisible({
        featurePresent: false,
        preparedReady: false,
        castState: "CAST_PENDING",
      }),
      false,
    );
    assert.equal(
      managedTorTestCardVisible({
        featurePresent: false,
        preparedReady: false,
        castState: "CAST",
      }),
      false,
    );
  });

  it("feature present + NOT_CAST + not Ready → card absent (nothing to submit yet)", () => {
    assert.equal(
      managedTorTestCardVisible({
        featurePresent: true,
        preparedReady: false,
        castState: "NOT_CAST",
      }),
      false,
    );
  });

  it("the Vote screen gates the card through the feature-aware predicate", () => {
    // The card is rendered only via managedTorTestCardVisible with the feature
    // flag, never on prepared-ballot/cast state alone.
    assert.match(
      vote,
      /managedTorTestCardVisible\(\{\s*featurePresent: managedTorFeaturePresent,[\s\S]*?castState,\s*\}\)\s*&&\s*\(\s*<Card title="Submit your ballot privately">/,
    );
    // managedTorFeaturePresent is derived from the presence of the status DTO,
    // which is null in a production build without the feature.
    assert.match(vote, /const managedTorFeaturePresent = managedTorStatus !== null/);
  });

  it("renders the durable status block, not just a transient result", () => {
    assert.match(vote, /privateStatus\.title/);
    assert.match(vote, /privateStatus\.detail/);
    assert.match(vote, /privateSubmissionStatus\(\{/);
    assert.match(vote, /castState,/);
  });
});

// -------------------------------------------------------------------------
// Truthful ready-state: child liveness is authoritative (real-test blocker C)
// -------------------------------------------------------------------------

describe("managed-Tor ready state cannot go stale", () => {
  it("polls the authoritative status while configured and not yet CAST", () => {
    // A bounded interval re-reads managedTorTestStatus so a Tor child that exits
    // flips tor_running to false and the banner stops claiming "ready". The Rust
    // status checks child liveness (try_wait) + a fresh SOCKS probe.
    assert.match(vote, /setInterval\(\s*\(\)\s*=>\s*\{\s*void refreshManagedTorStatus\(\)/);
    assert.match(vote, /workflow\?\.cast_lock_state === "CAST"/);
    assert.match(vote, /managedTorStatus\?\.configured/);
  });

  it("re-reads status after a submission failure so a dead child is not shown ready", () => {
    // The catch branch refreshes managed-Tor status so a "process has exited"
    // failure flips the connection banner out of "ready" and reveals Reconnect.
    const runner = vote.slice(
      vote.indexOf("async function runBoundedPrivateSubmission"),
      vote.indexOf("function onStopAutoRetry"),
    );
    assert.match(runner, /catch \(err\)[\s\S]*refreshManagedTorStatus\(\)/);
  });

  it("reveals a reconnect action when configured but the connection is down", () => {
    // When the child is not running, the configured card offers Start (reconnect)
    // without requiring a new ballot/proof/nullifier or re-entering any Tor field.
    assert.match(
      vote,
      /managedTorStatus\?\.configured && !managedTorStatus\.tor_running && !ballotCast/,
    );
    assert.match(vote, /Start private connection/);
  });
});

// -------------------------------------------------------------------------
// 6. Production offline/unavailable guidance remains present
// -------------------------------------------------------------------------

describe("production offline/unavailable guidance", () => {
  it("keeps the truthful production 'not available in this build' + offline guidance", () => {
    assert.match(vote, /Online private submission is not available in this build\./);
    assert.match(
      vote,
      /Save the\s+ballot file above and deliver it through the election's approved/,
    );
    // The offline file-save path is still the primary save action.
    assert.match(vote, />\s*Save encrypted ballot file\s*</);
  });
});

// -------------------------------------------------------------------------
// Fresh Submit vs Retry gating (Issues 3, 18)
// -------------------------------------------------------------------------

describe("private submit/retry gating", () => {
  it("offers a fresh Submit only when nothing is durably locked", () => {
    assert.match(
      vote,
      /managedTorStatus\?\.tor_running && !castLocked && \([\s\S]*?Submit vote privately/,
    );
  });

  it("offers Retry (not fresh Submit) while CAST_PENDING", () => {
    const retryIdx = vote.indexOf("Retry private submission");
    assert.ok(retryIdx >= 0, "retry control must exist");
    // The retry control lives in the castPending-gated block.
    const before = vote.slice(0, retryIdx);
    assert.ok(
      before.lastIndexOf("{castPending && (") > before.lastIndexOf("{managedTorStatus?.tor_running && !castLocked"),
      "Retry must be gated by castPending, after the fresh-submit block",
    );
  });

  it("retry uses the exact staged-envelope recovery command, never a fresh release", () => {
    assert.match(vote, /onRetryPrivateSubmission[\s\S]*?api\.retryPrivateSubmission\(\)/);
  });
});

// -------------------------------------------------------------------------
// Local error display (Issue 5)
// -------------------------------------------------------------------------

describe("private submission errors render next to the controls", () => {
  it("keeps a dedicated private error state shown inside the controlled-test card", () => {
    assert.match(vote, /const \[privateError, setPrivateError\]/);
    assert.match(vote, /<BackendErrorNotice\s+error=\{privateError\}/);
    // The private handlers set the local error, not only the top-of-screen one.
    assert.match(vote, /setPrivateError\(commandErrorFromUnknown\(err\)\)/);
  });
});

// -------------------------------------------------------------------------
// Stale "unavailable" contradiction removed (Issue 9)
// -------------------------------------------------------------------------

describe("no stale online-unavailable contradiction", () => {
  it("suppresses the production 'not available' message when the feature is present", () => {
    assert.match(vote, /const managedTorFeaturePresent = managedTorStatus !== null/);
    assert.match(vote, /\) : managedTorFeaturePresent \? \(/);
    // The production string is retained for builds WITHOUT the feature.
    assert.match(vote, /Online private submission is not available in this build\./);
  });
});

// -------------------------------------------------------------------------
// Tor config UX: browse + full-width rows + non-secret memory (Issues 6, 7)
// -------------------------------------------------------------------------

describe("controlled-test transport configuration UX", () => {
  it("gives tor.exe and the bundle full-width rows with Browse buttons", () => {
    assert.match(dialog, /export async function pickTorExecutable/);
    assert.match(dialog, /export async function pickVoterTransportBundle/);
    assert.match(vote, /onBrowseTorExe/);
    assert.match(vote, /onBrowseVoterBundle/);
    // Each path field is a normal full-width form-row with a file-row + Browse.
    assert.match(vote, /htmlFor="tor-exe-path"[\s\S]*?onBrowseTorExe/);
    assert.match(vote, /htmlFor="voter-bundle-path"[\s\S]*?onBrowseVoterBundle/);
  });

  it("remembers only the non-secret paths across navigation/restart", () => {
    assert.match(vote, /recallManagedTorConfig\(/);
    assert.match(vote, /rememberManagedTorConfig\(\{/);
    // The remember call binds the election-specific paths to the election.
    assert.match(vote, /electionManifestHashHex,?\s*\}\)/);
  });

  it("stores no secret material in remembered config", () => {
    const stored = rememberManagedTorConfig({
      torExePath: "C:/tools/tor.exe",
      torDataDir: "C:/test/voter-tor",
      voterBundlePath: "C:/test/bundle.cbor",
      electionManifestHashHex: "aa".repeat(32),
    });
    // rememberManagedTorConfig returns void; recall reads it back (or empty when
    // storage is unavailable under the test runner).
    assert.equal(stored, undefined);
    const recalled = recallManagedTorConfig();
    for (const key of Object.keys(recalled)) {
      assert.match(
        key,
        /^(torExePath|torDataDir|voterBundlePath|electionManifestHashHex)$/,
      );
    }
  });

  it("clears election-specific paths when the election identity changes (F2)", () => {
    const electionA = "aa".repeat(32);
    const electionB = "bb".repeat(32);
    rememberManagedTorConfig({
      torExePath: "C:/tools/tor.exe",
      torDataDir: "C:/test/A/voter-tor",
      voterBundlePath: "C:/test/A/bundle.cbor",
      electionManifestHashHex: electionA,
    });
    // The runner may lack localStorage; only assert the same-election RESTORE
    // when the store actually round-trips. The cross-election CLEAR holds in
    // both cases (empty store also yields empty election-specific paths).
    const storageWorks = recallManagedTorConfig().torExePath === "C:/tools/tor.exe";
    if (storageWorks) {
      const sameElection = recallManagedTorConfig(electionA);
      assert.equal(sameElection.torDataDir, "C:/test/A/voter-tor");
      assert.equal(sameElection.voterBundlePath, "C:/test/A/bundle.cbor");
    }
    // Different election: the election-specific bundle and data directory are
    // never silently reused, regardless of storage availability.
    const otherElection = recallManagedTorConfig(electionB);
    assert.equal(otherElection.torDataDir, "");
    assert.equal(otherElection.voterBundlePath, "");
  });

  it("sanitizes away any injected non-path fields", () => {
    const cleaned = sanitizeManagedTorConfig({
      torExePath: "C:/tools/tor.exe",
      torDataDir: "C:/test/voter-tor",
      voterBundlePath: "C:/test/bundle.cbor",
      passphrase: "secret",
      nullifier: "deadbeef",
      selection: ["candidate-a"],
    });
    assert.deepEqual(Object.keys(cleaned).sort(), [
      "electionManifestHashHex",
      "torDataDir",
      "torExePath",
      "voterBundlePath",
    ]);
    assert.equal(cleaned.torExePath, "C:/tools/tor.exe");
  });

  it("uses full-width rows for the three long-path config fields", () => {
    const fullWidth = vote.match(/form-row form-row--full/g) ?? [];
    assert.equal(fullWidth.length, 3, "tor.exe, bundle, and data-dir rows are full width");
  });
});

// -------------------------------------------------------------------------
// Safe diagnostic stage (Phase B): voter-side Advanced/diagnostics label
// -------------------------------------------------------------------------

describe("private submission safe diagnostic stage", () => {
  it("returns null when there is no stage", () => {
    assert.equal(privateSubmissionStageLabel(null), null);
    assert.equal(privateSubmissionStageLabel(undefined), null);
    assert.equal(privateSubmissionStageLabel(""), null);
  });

  it("maps every known safe stage to a distinct voter-facing sentence", () => {
    const stages = [
      "PRIVATE_TRANSPORT_UNAVAILABLE",
      "RECEIPT_PARSE_FAILED",
      "RECEIPT_SIGNATURE_INVALID",
      "RECEIPT_DESCRIPTOR_MISMATCH",
      "RECEIPT_PACKAGE_MISMATCH",
      "RECEIPT_REJECTED_BY_ORGANIZER",
      "RECEIPT_PERSIST_FAILED",
      "CAST_PROMOTION_FAILED",
    ];
    const labels = stages.map((s) => privateSubmissionStageLabel(s));
    for (const label of labels) {
      assert.ok(label && label.length > 0, "each known stage yields a non-empty label");
    }
    assert.equal(new Set(labels).size, labels.length, "each known stage is distinct");
  });

  it("shows an unknown stage verbatim rather than hiding it", () => {
    assert.match(privateSubmissionStageLabel("SOME_NEW_STAGE") ?? "", /SOME_NEW_STAGE/);
  });

  it("never leaks secret material in any diagnostic label", () => {
    const stages = [
      "PRIVATE_TRANSPORT_UNAVAILABLE",
      "RECEIPT_PARSE_FAILED",
      "RECEIPT_SIGNATURE_INVALID",
      "RECEIPT_DESCRIPTOR_MISMATCH",
      "RECEIPT_PACKAGE_MISMATCH",
      "RECEIPT_REJECTED_BY_ORGANIZER",
      "RECEIPT_PERSIST_FAILED",
      "CAST_PROMOTION_FAILED",
    ];
    // No secret/network-identity material: no plaintext choice, credential/key,
    // passphrase, private nullifier, proof witness, Tor circuit, or IP address.
    for (const stage of stages) {
      const label = privateSubmissionStageLabel(stage) ?? "";
      assert.doesNotMatch(
        label,
        /nullifier|passphrase|secret key|witness|circuit|\b\d{1,3}(\.\d{1,3}){3}\b/i,
        `stage ${stage} must not leak secret/network material`,
      );
    }
  });

  it("surfaces the safe stage only under Advanced/diagnostics", () => {
    assert.match(vote, /privateSubmissionStageLabel\(/);
    // The stage is read from the release result's diagnostic_stage field.
    assert.match(vote, /"diagnostic_stage" in privateResult/);
    // It renders inside the Advanced connection details disclosure.
    const advancedIdx = vote.indexOf("Advanced connection details");
    const stageIdx = vote.indexOf("privateStageLabel &&");
    assert.ok(advancedIdx >= 0 && stageIdx > advancedIdx, "stage renders within Advanced section");
  });
});

// -------------------------------------------------------------------------
// Offline vs online submission is unmistakable (Phase D1)
// -------------------------------------------------------------------------

describe("offline vs online submission clarity", () => {
  it("labels the offline route and states nothing is sent", () => {
    assert.match(vote, /Offline submission/);
    assert.match(vote, /Nothing is sent over the network/);
    assert.match(vote, />\s*Save encrypted ballot file\s*</);
    // The misleading "Export and cast" wording is gone from the offline button.
    assert.doesNotMatch(vote, />\s*Export and cast ballot\s*</);
  });

  it("labels the online route as Tor and requires an authenticated receipt", () => {
    assert.match(vote, /Private online submission · Tor/);
    assert.match(vote, /confirmed only after an authenticated\s+organizer receipt is verified/);
    assert.match(vote, />\s*Submit vote privately\s*</);
  });
});
