import { describe, it } from "node:test";
import assert from "node:assert/strict";

import type { AnchorBundleV1 } from "../src/wallet/anchorBundle.ts";
import { parseAnchorBundle } from "../src/wallet/anchorBundle.ts";
import {
  assessAnchorWorkflow,
  phaseLabel,
  type AnchorWorkflowPhase,
} from "../src/wallet/anchorWorkflow.ts";
import type { AnchorRecoveryRecord } from "../src/wallet/recoveryStore.ts";
import {
  AnchorRecoveryStore,
  type RecoveryStorage,
} from "../src/wallet/recoveryStore.ts";
import type { VerifiedAnchorEvidence } from "../src/wallet/verifyReceipt.ts";

function memoryStorage(): RecoveryStorage {
  const map = new Map<string, string>();
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value);
    },
    removeItem: (key) => {
      map.delete(key);
    },
  };
}

function bundleFixture(network: string): AnchorBundleV1 {
  const isMainnet = network === "mainnet";
  return parseAnchorBundle({
    schemaVersion: 1,
    network,
    template: {
      address: isMainnet
        ? "template_ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb"
        : "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee",
      module: "tari_private_ballot_anchor_v2",
      function: "publish_anchor_v2",
      eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
      artifactDigestHex: isMainnet
        ? "6ea3448e1beae71920a5ee5ce0cf51057a135a1f3a4e05dd26717a310e076830"
        : "ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908",
    },
    anchorArgs: {
      anchorDigestHex: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7",
      network,
      electionId: "5e50e17c401682fb38dbea349a4c2713",
      publicSummary: '{"election_id":"5e50e17c401682fb38dbea349a4c2713"}',
    },
  });
}

function baseInput(network = "mainnet") {
  return {
    bundle: bundleFixture(network),
    bundleInvalidReason: null,
    walletConnected: true,
    walletNetworkName: network,
    recovery: null,
  };
}

function evidenceFixture(): VerifiedAnchorEvidence {
  return {
    transactionIdHex: "11".repeat(32),
    epoch: 7,
    eventIndex: 0,
  };
}

describe("anchor workflow assessment", () => {
  it("blocks on a missing or invalid bundle first", () => {
    assert.equal(assessAnchorWorkflow({ ...baseInput(), bundle: null }).kind, "no_bundle");
    const invalid = assessAnchorWorkflow({ ...baseInput(), bundleInvalidReason: "anchor_digest" });
    assert.deepEqual(invalid, { kind: "bundle_invalid", reason: "anchor_digest" });
  });

  it("allows mainnet publishing with the configured mainnet template address", () => {
    const phase = assessAnchorWorkflow(baseInput("mainnet"));
    assert.equal(phase.kind, "ready");
  });

  it("blocks a bundle that does not match the configured deployment", () => {
    const bundle = bundleFixture("mainnet");
    bundle.template.eventTopic =
      "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2";
    const phase = assessAnchorWorkflow({ ...baseInput(), bundle });
    assert.equal(phase.kind, "deployment_mismatch");
    if (phase.kind === "deployment_mismatch") {
      assert.match(phase.message, /event topic/);
    }
  });

  it("blocks an unknown network name fail-closed", () => {
    const bundle = bundleFixture("mysterynet");
    const phase = assessAnchorWorkflow({ ...baseInput(), bundle });
    assert.equal(phase.kind, "deployment_mismatch");
  });

  it("does not create requests for a historical Esmeralda deployment", () => {
    assert.equal(assessAnchorWorkflow(baseInput("esmeralda")).kind, "deployment_mismatch");
  });

  it("requires a connected wallet and a matching wallet network before ready", () => {
    assert.equal(
      assessAnchorWorkflow({ ...baseInput(), walletConnected: false }).kind,
      "wallet_required",
    );
    const mismatch = assessAnchorWorkflow({ ...baseInput(), walletNetworkName: "igor" });
    assert.equal(mismatch.kind, "wallet_network_mismatch");
    assert.match(phaseLabel(mismatch), /blocked/);
  });

  it("reaches ready only when every gate passes", () => {
    const phase = assessAnchorWorkflow(baseInput());
    assert.equal(phase.kind, "ready");
    assert.match(phaseLabel(phase), /review and approve/);
  });
});

describe("recovery resume", () => {
  it("resumes verification from a saved transaction id and never recreates a request", () => {
    const recovery: AnchorRecoveryRecord = {
      phase: "approved_submitted",
      requestId: "req_1",
      transactionId: "11".repeat(32),
      ownerToken: "a".repeat(32),
      leaseExpiresAtMs: 2,
      updatedAtMs: 1,
    };
    const phase = assessAnchorWorkflow({ ...baseInput(), recovery });
    assert.deepEqual(phase, {
      kind: "verifying",
      transactionId: "11".repeat(32),
    });
  });

  it("resumes an unsubmitted approval by its request id", () => {
    const recovery: AnchorRecoveryRecord = {
      phase: "submitted_awaiting_approval",
      requestId: "req_1",
      transactionId: null,
      ownerToken: "a".repeat(32),
      leaseExpiresAtMs: 2,
      updatedAtMs: 1,
    };
    const phase = assessAnchorWorkflow({ ...baseInput(), recovery });
    assert.deepEqual(phase, { kind: "awaiting_approval", requestId: "req_1" });
  });

  it("blocks resubmission when a saved submit call may already have reached the wallet", () => {
    const recovery: AnchorRecoveryRecord = {
      phase: "submit_in_flight",
      requestId: "req_1",
      transactionId: null,
      ownerToken: "a".repeat(32),
      leaseExpiresAtMs: 2,
      updatedAtMs: 1,
    };
    const phase = assessAnchorWorkflow({ ...baseInput(), recovery });
    assert.deepEqual(phase, { kind: "submission_unknown", requestId: "req_1" });
    assert.match(phaseLabel(phase), /never be submitted again automatically/);
  });

  it("re-verifies even a locally-verified record after a reload", () => {
    const recovery: AnchorRecoveryRecord = {
      phase: "verified",
      requestId: "req_1",
      transactionId: "22".repeat(32),
      ownerToken: "a".repeat(32),
      leaseExpiresAtMs: 2,
      updatedAtMs: 1,
    };
    const phase = assessAnchorWorkflow({ ...baseInput(), recovery });
    assert.deepEqual(phase, {
      kind: "verifying",
      transactionId: "22".repeat(32),
    });
  });

  it("fails closed on an incomplete recovery record", () => {
    const recovery: AnchorRecoveryRecord = {
      phase: "verifying",
      requestId: null,
      transactionId: null,
      ownerToken: "a".repeat(32),
      leaseExpiresAtMs: 2,
      updatedAtMs: 1,
    };
    const phase = assessAnchorWorkflow({ ...baseInput(), recovery });
    assert.equal(phase.kind, "failed_no_publish");
  });
});

describe("recovery store", () => {
  it("round-trips a valid record and drops malformed content", () => {
    const store = new AnchorRecoveryStore(memoryStorage());
    const key = "bundle-key";
    store.save(key, {
      phase: "approved_submitted",
      requestId: null,
      transactionId: "33".repeat(32),
      ownerToken: "a".repeat(32),
      leaseExpiresAtMs: 43,
      updatedAtMs: 42,
    });
    const loaded = store.load(key);
    assert.equal(loaded?.transactionId, "33".repeat(32));
    store.clear(key);
    assert.equal(store.load(key), null);
  });

  it("distinguishes corrupt JSON from an absent recovery record", () => {
    const storage = memoryStorage();
    const store = new AnchorRecoveryStore(storage);
    storage.setItem("k", "{not json");
    assert.equal(store.load("k"), null);
    assert.equal(store.loadState("k").kind, "corrupt");
    storage.setItem("k", JSON.stringify({ phase: "mystery", updatedAtMs: 1 }));
    assert.equal(store.load("k"), null);
    assert.equal(store.loadState("k").kind, "corrupt");
  });

  it("durably reserves before create and only lets one tab win", () => {
    const store = new AnchorRecoveryStore(memoryStorage());
    const first = store.reserve("bundle", "a".repeat(32), 10);
    const second = store.reserve("bundle", "b".repeat(32), 10);
    assert.equal(first.kind, "claimed");
    assert.equal(second.kind, "busy");
    assert.equal(store.loadState("bundle").kind, "record");
  });

  it("keeps the pre-create ambiguity when the post-create save fails", () => {
    const map = new Map<string, string>();
    let writes = 0;
    const store = new AnchorRecoveryStore({
      getItem: (key) => map.get(key) ?? null,
      setItem: (key, value) => {
        writes += 1;
        if (writes > 1) throw new Error("quota");
        map.set(key, value);
      },
      removeItem: (key) => map.delete(key),
    });
    const owner = "a".repeat(32);
    assert.equal(store.reserve("bundle", owner, 10).kind, "claimed");
    assert.throws(() => store.saveOwned("bundle", owner, {
      phase: "submitted_awaiting_approval", requestId: "req_1", transactionId: null,
    }, 11));
    const state = store.loadState("bundle");
    assert.equal(state.kind, "record");
    if (state.kind === "record") assert.equal(state.record.phase, "creating_request");
  });

  it("releases only canonical submitted transaction recovery for immediate read-only reload", () => {
    const store = new AnchorRecoveryStore(memoryStorage());
    const firstOwner = "a".repeat(32);
    const reloadedOwner = "b".repeat(32);
    assert.equal(store.reserve("bundle", firstOwner, 10).kind, "claimed");
    store.saveOwned("bundle", firstOwner, {
      phase: "approved_submitted",
      requestId: null,
      transactionId: "11".repeat(32),
    }, 11);

    // This models a legacy or interrupted browser record whose prior lease has
    // not yet expired. It is safe to take over only for transaction lookup.
    const immediateRecovery = store.claim("bundle", reloadedOwner, 12);
    assert.equal(immediateRecovery.kind, "claimed");
    if (immediateRecovery.kind === "claimed") {
      assert.equal(immediateRecovery.record.transactionId, "11".repeat(32));
      assert.equal(immediateRecovery.record.requestId, null);
    }

    store.releaseSubmittedRecoveryLease("bundle", reloadedOwner, 13);
    const released = store.loadState("bundle");
    assert.equal(released.kind, "record");
    if (released.kind === "record") assert.equal(released.record.leaseExpiresAtMs, 0);
  });

  it("retains unexpired leases for approval and uncertain-submit records", () => {
    const cases: Array<{
      phase: "submitted_awaiting_approval" | "submit_in_flight";
      requestId: string;
    }> = [
      { phase: "submitted_awaiting_approval", requestId: "req_approved" },
      { phase: "submit_in_flight", requestId: "req_unknown" },
    ];
    for (const scenario of cases) {
      const store = new AnchorRecoveryStore(memoryStorage());
      const firstOwner = "a".repeat(32);
      assert.equal(store.reserve("bundle", firstOwner, 10).kind, "claimed");
      store.saveOwned("bundle", firstOwner, {
        phase: scenario.phase,
        requestId: scenario.requestId,
        transactionId: null,
      }, 11);
      assert.equal(store.claim("bundle", "b".repeat(32), 12).kind, "busy", scenario.phase);
    }
  });

  it("rejects saveOwned that violates phase/ID invariants without persisting", () => {
    const map = new Map<string, string>();
    let writeCount = 0;
    const store = new AnchorRecoveryStore({
      getItem: (key) => map.get(key) ?? null,
      setItem: (key, value) => {
        writeCount += 1;
        map.set(key, value);
      },
      removeItem: (key) => map.delete(key),
    });
    const owner = "a".repeat(32);
    // First, establish a valid creating_request record
    assert.equal(store.reserve("bundle", owner, 10).kind, "claimed");
    const originalBytes = map.get("bundle");
    assert.ok(originalBytes);
    const originalRecord = JSON.parse(originalBytes);
    assert.equal(originalRecord.phase, "creating_request");

    // Attempt to save an invalid transition: creating_request with requestId (violates invariant)
    assert.throws(
      () => store.saveOwned("bundle", owner, {
        phase: "creating_request",
        requestId: "req_1",
        transactionId: null,
      }, 11),
      /violates phase\/ID invariants/
    );
    // Write should not have been called (no additional write)
    assert.equal(writeCount, 1, "setItem must not be called for invalid save");
    // Original bytes must be preserved exactly
    assert.equal(map.get("bundle"), originalBytes, "original valid bytes must be unchanged");

    // Attempt another invalid transition: submitted_awaiting_approval with transactionId (violates invariant)
    assert.throws(
      () => store.saveOwned("bundle", owner, {
        phase: "submitted_awaiting_approval",
        requestId: "req_1",
        transactionId: "11".repeat(32),
      }, 12),
      /violates phase\/ID invariants/
    );
    assert.equal(writeCount, 1, "setItem must not be called for invalid save");
    assert.equal(map.get("bundle"), originalBytes, "original valid bytes must be unchanged after second attempt");
  });

  it("rejects saveOwned with approved_submitted missing canonical transactionId", () => {
    const map = new Map<string, string>();
    let writeCount = 0;
    const store = new AnchorRecoveryStore({
      getItem: (key) => map.get(key) ?? null,
      setItem: (key, value) => {
        writeCount += 1;
        map.set(key, value);
      },
      removeItem: (key) => map.delete(key),
    });
    const owner = "a".repeat(32);
    assert.equal(store.reserve("bundle", owner, 10).kind, "claimed");
    store.saveOwned("bundle", owner, {
      phase: "submitted_awaiting_approval",
      requestId: "req_1",
      transactionId: null,
    }, 11);
    const originalBytes = map.get("bundle");
    assert.ok(originalBytes);

    // approved_submitted requires null requestId AND valid 64-hex transactionId
    assert.throws(
      () => store.saveOwned("bundle", owner, {
        phase: "approved_submitted",
        requestId: null,
        transactionId: "short",
      }, 12),
      /violates phase\/ID invariants/
    );
    assert.equal(writeCount, 2, "setItem must not be called for invalid save");
    assert.equal(map.get("bundle"), originalBytes, "original valid bytes must be unchanged");
  });
});
