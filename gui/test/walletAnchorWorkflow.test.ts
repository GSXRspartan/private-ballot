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
  return parseAnchorBundle({
    schemaVersion: 1,
    network,
    template: {
      address: "template_bb539bddc9c264e4744ec462647b076fb97e2bdedb8692ea435804a6eb1eddee",
      module: "tari_private_ballot_anchor_v2",
      function: "publish_anchor_v2",
      eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
      artifactDigestHex: "ce5334dfc0cdbfe74726accfe7201a778331bf2020865a2fc2b24a68a971d908",
    },
    anchorArgs: {
      anchorDigestHex: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7",
      network,
      electionId: "5e50e17c401682fb38dbea349a4c2713",
      publicSummary: '{"election_id":"5e50e17c401682fb38dbea349a4c2713"}',
    },
  });
}

function baseInput(network = "esmeralda") {
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

  it("blocks mainnet publishing while the mainnet template address is unreleased", () => {
    const phase = assessAnchorWorkflow(baseInput("mainnet"));
    assert.equal(phase.kind, "mainnet_disabled");
    assert.match(phaseLabel(phase), /disabled in this build/);
  });

  it("blocks a bundle that does not match the configured deployment", () => {
    const bundle = bundleFixture("esmeralda");
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
      updatedAtMs: 1,
    };
    const phase = assessAnchorWorkflow({ ...baseInput(), recovery });
    assert.deepEqual(phase, { kind: "awaiting_approval", requestId: "req_1" });
  });

  it("re-verifies even a locally-verified record after a reload", () => {
    const recovery: AnchorRecoveryRecord = {
      phase: "verified",
      requestId: "req_1",
      transactionId: "22".repeat(32),
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
      updatedAtMs: 1,
    };
    const phase = assessAnchorWorkflow({ ...baseInput(), recovery });
    assert.equal(phase.kind, "failed_no_publish");
  });
});

describe("recovery store", () => {
  it("round-trips a record and drops malformed content", () => {
    const store = new AnchorRecoveryStore(memoryStorage());
    const key = "bundle-key";
    store.save(key, {
      phase: "approved_submitted",
      requestId: "req_1",
      transactionId: "33".repeat(32),
      updatedAtMs: 42,
    });
    const loaded = store.load(key);
    assert.equal(loaded?.transactionId, "33".repeat(32));
    store.clear(key);
    assert.equal(store.load(key), null);
  });

  it("returns null for corrupt JSON or unknown phases", () => {
    const storage = memoryStorage();
    const store = new AnchorRecoveryStore(storage);
    storage.setItem("k", "{not json");
    assert.equal(store.load("k"), null);
    storage.setItem("k", JSON.stringify({ phase: "mystery", updatedAtMs: 1 }));
    assert.equal(store.load("k"), null);
  });
});
