import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { verifyBrowserAnchorEvidence } from "../src/wallet/chainEvidence.ts";
import { decodeExecuteResultBase64 } from "../src/wallet/executeResult.ts";
import {
  decodeTransactionReceiptBase64,
  verifyDurableTransactionReceiptBase64,
} from "../src/wallet/transactionReceipt.ts";
import { verifyV2AnchorExecutionResult } from "../src/wallet/verifyReceipt.ts";
import { defaultPublishDriver } from "../src/anchor/browserAnchorPublish.ts";
import type { AnchorBundleV1 } from "../src/wallet/anchorBundle.ts";
import type { WindowTariProvider } from "../src/wallet/provider.ts";
import { mainnetTransactionExplorerUrl } from "../src/wallet/anchorDeploymentConfig.ts";
import {
  MAINNET_ANCHOR_TX_ID,
  MAINNET_ANCHOR_DIGEST_HEX,
  MAINNET_ANCHOR_ELECTION_ID,
  MAINNET_ANCHOR_TEMPLATE_HEX,
  MAINNET_ANCHOR_EVENT_TOPIC,
  MAINNET_ANCHOR_PUBLIC_SUMMARY,
  MAINNET_ANCHOR_RECEIPT_BASE64,
  MAINNET_ANCHOR_EXECUTION_RESULT_BASE64,
} from "./mainnetAnchorVectors.generated.ts";

const template = {
  templateAddressHex: MAINNET_ANCHOR_TEMPLATE_HEX,
  eventTopic: MAINNET_ANCHOR_EVENT_TOPIC,
};
const payload = {
  anchorDigestHex: MAINNET_ANCHOR_DIGEST_HEX,
  network: "mainnet",
  electionId: MAINNET_ANCHOR_ELECTION_ID,
  publicSummary: MAINNET_ANCHOR_PUBLIC_SUMMARY,
};
const committedResult = {
  result: {
    Finalized: {
      final_decision: "Commit",
      execution_result: MAINNET_ANCHOR_EXECUTION_RESULT_BASE64,
      finalized_time: "2026-11-23 07:04:13.0",
      abort_details: null,
    },
  },
};
const adapter = {
  getTransactionResult: async () => committedResult,
} as unknown as WindowTariProvider;
const bundle = {} as AnchorBundleV1;

function withReceiptAvailability(isIndexed: () => boolean): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const path = new URL(input.toString(), "https://app.test").pathname;
    if (path === "/chain/network") return Response.json({ network: "mainnet", network_byte: 0 });
    if (path.endsWith("/result")) return new Response(null, { status: 404 });
    if (path.includes("/transaction-receipts/")) {
      if (!isIndexed()) return new Response(null, { status: 404 });
      return Response.json({ receipt: MAINNET_ANCHOR_RECEIPT_BASE64 });
    }
    throw new Error(`unexpected route ${path}`);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

describe("real Mainnet V2 anchor receipt and recovery", () => {
  it("decodes and verifies the observed finalized execution result and durable receipt", () => {
    const execution = decodeExecuteResultBase64(MAINNET_ANCHOR_EXECUTION_RESULT_BASE64);
    const receipt = decodeTransactionReceiptBase64(MAINNET_ANCHOR_RECEIPT_BASE64);
    assert.equal(execution.transactionHashHex, MAINNET_ANCHOR_TX_ID);
    assert.equal(execution.epoch, 39270);
    assert.equal(execution.resultVariant, "accept");
    assert.equal(receipt.outcome, "Commit");
    assert.equal(receipt.epoch, 39270);

    const fromExecution = verifyV2AnchorExecutionResult(
      MAINNET_ANCHOR_TX_ID,
      template,
      payload,
      execution,
    );
    const fromReceipt = verifyDurableTransactionReceiptBase64(
      MAINNET_ANCHOR_TX_ID,
      template,
      payload,
      MAINNET_ANCHOR_RECEIPT_BASE64,
    );
    assert.deepEqual(fromExecution, fromReceipt);
    assert.equal(fromReceipt.eventIndex, 1);
  });

  it("retries an unindexed receipt and verifies it once indexed without resubmitting", async () => {
    let indexed = false;
    const restore = withReceiptAvailability(() => indexed);
    const driver = defaultPublishDriver({
      verifyAttempts: 3,
      verifyIntervalMs: 0,
      verifyWithEvidence: (provider) =>
        verifyBrowserAnchorEvidence(provider, MAINNET_ANCHOR_TX_ID, template, payload),
    });
    try {
      const before = await driver.verify(adapter, bundle, MAINNET_ANCHOR_TX_ID);
      assert.equal(before.kind, "pending");
      if (before.kind === "pending") {
        assert.match(before.detail ?? "", /not indexed yet \(status 404\)/);
      }
      indexed = true;
      const after = await driver.verify(adapter, bundle, MAINNET_ANCHOR_TX_ID);
      assert.equal(after.kind, "verified");
      if (after.kind === "verified") {
        assert.equal(after.evidence.transactionIdHex, MAINNET_ANCHOR_TX_ID);
        assert.equal(after.evidence.epoch, 39270);
        assert.equal(after.evidence.eventIndex, 1);
      }
    } finally {
      restore();
    }
  });

  it("surfaces only a validated Mainnet explorer URL for a saved transaction", () => {
    assert.equal(
      mainnetTransactionExplorerUrl(MAINNET_ANCHOR_TX_ID),
      `https://explorer.tari.mw/tx/${MAINNET_ANCHOR_TX_ID}`,
    );
    assert.equal(mainnetTransactionExplorerUrl("not-a-transaction-id"), null);
  });
});
