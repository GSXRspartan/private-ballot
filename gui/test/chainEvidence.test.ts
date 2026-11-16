import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { verifyBrowserAnchorEvidence } from "../src/wallet/chainEvidence.ts";
import type { WindowTariProvider } from "../src/wallet/provider.ts";
import { RESULT_JSON_FINALIZED_COMMIT, RESULT_JSON_PENDING } from "./anchorVectors.generated.ts";
import { RECEIPT_VECTORS } from "./receiptVectors.generated.ts";
import { SAPIENT_EXECUTE_RESULT_JSON } from "./sapientExecuteResult.generated.ts";
import { TRANSIENT_RESULT_TIMEOUT_MS } from "../src/wallet/chainEvidence.ts";

const transactionId = "9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b";
const template = { templateAddressHex: "5f1ecbe69b1c6e8b64b97b37f32f6975be4b1e2a1d9c4a5e3f2b6c8d0a9e7f41", eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2" };
const payload = { anchorDigestHex: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7", network: "mainnet", electionId: "5e50e17c401682fb38dbea349a4c2713", publicSummary: '{"election_id":"5e50e17c401682fb38dbea349a4c2713","questions":[{"text":"Adopt the charter?","options":["Yes","No"]}],"ballot_count":10}' };
const COMMITTED_RESULT = JSON.parse(RESULT_JSON_FINALIZED_COMMIT);
const ALIGNED_RECEIPT = RECEIPT_VECTORS.commit_receipt_aligned_with_exec_vector;
const WALLET_ADAPTER = {
  getTransactionResult: async () => COMMITTED_RESULT,
} as unknown as WindowTariProvider;

function finalizedResultWithExecuteResult(executeResult: Record<string, unknown>): Record<string, unknown> {
  const result = structuredClone(COMMITTED_RESULT) as { result: { Finalized: Record<string, unknown> } };
  result.result.Finalized.execution_result = executeResult;
  return result;
}

function sapientResultWith({ epoch = 7, transactionId: id = transactionId }: { epoch?: number; transactionId?: string } = {}): Record<string, unknown> {
  const executeResult = JSON.parse(SAPIENT_EXECUTE_RESULT_JSON) as { finalize: { transaction_hash: string }; execute_epoch: number };
  executeResult.finalize.transaction_hash = id;
  executeResult.execute_epoch = epoch;
  return finalizedResultWithExecuteResult(executeResult as unknown as Record<string, unknown>);
}

interface RouteAnswer {
  status: number;
  body: unknown;
}

function withRoutes(routes: (path: string) => RouteAnswer): void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const path = new URL(input.toString(), "https://app.test").pathname;
    const answer = routes(path);
    if (answer.status !== 200) return new Response(null, { status: answer.status });
    return Response.json(answer.body);
  }) as typeof fetch;
  return () => {
    globalThis.fetch = original;
  };
}

function withTransientFailure(mode: "throw" | "hang"): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const path = new URL(input.toString(), "https://app.test").pathname;
    if (path === "/chain/network") return Response.json({ network: "mainnet", network_byte: 0 });
    if (path.includes("/transaction-receipts/")) return Response.json({ receipt: ALIGNED_RECEIPT.base64 });
    if (path.endsWith("/result")) {
      if (mode === "throw") throw new Error("transient unavailable");
      return new Promise<Response>(() => {});
    }
    throw new Error(`unexpected route ${path}`);
  }) as typeof fetch;
  return () => { globalThis.fetch = original; };
}

function withRawDurableEnvelope(source: string): () => void {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input) => {
    const path = new URL(input.toString(), "https://app.test").pathname;
    if (path === "/chain/network") return Response.json({ network: "mainnet", network_byte: 0 });
    if (path.endsWith("/result")) return new Response(null, { status: 404 });
    if (path.includes("/transaction-receipts/")) return new Response(source, { headers: { "content-type": "application/json" } });
    throw new Error(`unexpected route ${path}`);
  }) as typeof fetch;
  return () => { globalThis.fetch = original; };
}

describe("browser chain evidence", () => {
  it("succeeds when the wallet result, transient result, and durable receipt agree", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 200, body: COMMITTED_RESULT };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64 } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      assert.equal((await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload)).kind, "verified");
    } finally {
      restore();
    }
  });

  it("retains independently verified final agreement before a transient Pending result", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 200, body: JSON.parse(RESULT_JSON_PENDING) };
      if (path.includes("/transaction-receipts/")) return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64 } };
      throw new Error(`unexpected route ${path}`);
    });
    try {
      assert.equal((await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload)).kind, "pending");
    } finally {
      restore();
    }
  });

  it("makes wallet and durable final disagreement terminal before transient Pending", async () => {
    const adapter = { getTransactionResult: async () => sapientResultWith({ epoch: 8 }) } as unknown as WindowTariProvider;
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 200, body: JSON.parse(RESULT_JSON_PENDING) };
      if (path.includes("/transaction-receipts/")) return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64 } };
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(adapter, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") assert.match(outcome.message, /wallet and durable receipt evidence disagree/);
    } finally {
      restore();
    }
  });

  it("makes a wallet transaction mismatch terminal even when durable evidence is final and transient is Pending", async () => {
    const adapter = { getTransactionResult: async () => sapientResultWith({ transactionId: "ab".repeat(32) }) } as unknown as WindowTariProvider;
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 200, body: JSON.parse(RESULT_JSON_PENDING) };
      if (path.includes("/transaction-receipts/")) return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64 } };
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(adapter, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") assert.equal(outcome.failure, "wrong_transaction");
    } finally {
      restore();
    }
  });

  it("rejects a later final transient result that disagrees with agreeing wallet and durable evidence", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 200, body: sapientResultWith({ epoch: 8 }) };
      if (path.includes("/transaction-receipts/")) return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64 } };
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") assert.match(outcome.message, /transient indexer result disagrees/);
    } finally {
      restore();
    }
  });

  it("succeeds from the durable receipt when the transient result route is 404", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64 } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      assert.equal((await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload)).kind, "verified");
    } finally {
      restore();
    }
  });

  for (const mode of ["throw", "hang"] as const) {
    it(`keeps agreeing final wallet and durable evidence authoritative when transient fetch ${mode}s`, async () => {
      const restore = withTransientFailure(mode);
      const started = Date.now();
      try {
        const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
        assert.equal(outcome.kind, "verified");
        if (mode === "hang") assert.ok(Date.now() - started < TRANSIENT_RESULT_TIMEOUT_MS + 500);
      } finally {
        restore();
      }
    });

    it(`reports a known final conflict when transient fetch ${mode}s`, async () => {
      const adapter = { getTransactionResult: async () => sapientResultWith({ epoch: 8 }) } as unknown as WindowTariProvider;
      const restore = withTransientFailure(mode);
      try {
        const outcome = await verifyBrowserAnchorEvidence(adapter, transactionId, template, payload);
        assert.equal(outcome.kind, "terminal_failure");
        if (outcome.kind === "terminal_failure") assert.match(outcome.message, /wallet and durable receipt evidence disagree/);
      } finally {
        restore();
      }
    });
  }

  it("fails closed when any two sources disagree", async () => {
    // The wallet reports a different execution epoch than the durable receipt.
    const walletDisagreeing = JSON.parse(RESULT_JSON_FINALIZED_COMMIT);
    walletDisagreeing.result.Finalized.execution_result = walletDisagreeing.result.Finalized.execution_result;
    const disagreeingEpoch = structuredClone(COMMITTED_RESULT);
    disagreeingEpoch.result.Finalized.execution_time = { secs: 2, nanos: 0 };
    const adapter = {
      getTransactionResult: async () => disagreeingEpoch,
    } as unknown as WindowTariProvider;
    // Epoch comes from the CBOR execution result; instead flip the event index by
    // presenting the receipt before the wallet verifies against a duplicate event.
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 200, body: COMMITTED_RESULT };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: RECEIPT_VECTORS.duplicate_anchor_receipt.base64 } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(adapter, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.equal(outcome.failure, "duplicate_anchor_events");
      }
    } finally {
      restore();
    }
  });

  it("fails closed when the durable receipt is a fee-intent-only commit", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: RECEIPT_VECTORS.fee_intent_commit_receipt.base64 } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.equal(outcome.failure, "fee_only_acceptance");
      }
    } finally {
      restore();
    }
  });

  it("fails closed when the durable receipt route answers a rejected envelope", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { result: { Rejected: { details: "mempool rejected" } } } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.equal(outcome.failure, "malformed_result");
      }
    } finally {
      restore();
    }
  });

  it("fails closed when the durable receipt duplicates or drops the anchor event", async () => {
    for (const vector of [RECEIPT_VECTORS.duplicate_anchor_receipt, RECEIPT_VECTORS.missing_anchor_receipt]) {
      const restore = withRoutes((path) => {
        if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
        if (path.endsWith("/result")) return { status: 404, body: null };
        if (path.includes("/transaction-receipts/")) {
          return { status: 200, body: { receipt: vector.base64 } };
        }
        throw new Error(`unexpected route ${path}`);
      });
      try {
        const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
        assert.equal(outcome.kind, "terminal_failure");
      } finally {
        restore();
      }
    }
  });

  it("fails closed when the durable receipt carries the wrong template or payload", async () => {
    for (const [vector, failure] of [
      [RECEIPT_VECTORS.wrong_template_exec_receipt, "wrong_event_template"],
      [RECEIPT_VECTORS.wrong_digest_exec_receipt, "wrong_anchor_digest"],
    ] as const) {
      const restore = withRoutes((path) => {
        if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
        if (path.endsWith("/result")) return { status: 404, body: null };
        if (path.includes("/transaction-receipts/")) {
          return { status: 200, body: { receipt: vector.base64 } };
        }
        throw new Error(`unexpected route ${path}`);
      });
      try {
        const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
        assert.equal(outcome.kind, "terminal_failure");
        if (outcome.kind === "terminal_failure") {
          assert.equal(outcome.failure, failure);
        }
      } finally {
        restore();
      }
    }
  });

  it("fails closed when the durable receipt bytes are malformed", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: "////" } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.equal(outcome.failure, "malformed_result");
      }
    } finally {
      restore();
    }
  });

  it("fails closed when the receipt response has neither wire shape", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { unexpected: true } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
    } finally {
      restore();
    }
  });

  it("fails closed unless the proxy proves both Mainnet name and byte", async () => {
    const restore = withRoutes(() => ({ status: 200, body: { network: "mainnet", network_byte: 38 } }));
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
    } finally {
      restore();
    }
  });

  it("fails closed when wallet valid but durable receipt is 404", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 404, body: null };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.match(outcome.message, /unavailable/);
      }
    } finally {
      restore();
    }
  });

  it("fails closed when transient result valid but durable receipt is 500", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 200, body: COMMITTED_RESULT };
      if (path.includes("/transaction-receipts/")) {
        return { status: 500, body: null };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.match(outcome.message, /unavailable/);
      }
    } finally {
      restore();
    }
  });

  it("rejects mixed receipt + result envelope", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64, result: COMMITTED_RESULT } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.match(outcome.message, /exactly one supported receipt evidence field/);
      }
    } finally {
      restore();
    }
  });

  it("rejects receipt + transaction_result envelope", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64, transaction_result: { status: "success" } } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") {
        assert.match(outcome.message, /exactly one supported receipt evidence field/);
      }
    } finally {
      restore();
    }
  });

  it("rejects receipt + transaction_receipt envelope", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64, transaction_receipt: ALIGNED_RECEIPT.base64 } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") assert.match(outcome.message, /exactly one supported receipt evidence field/);
    } finally {
      restore();
    }
  });

  it("rejects an undocumented transaction_receipt-only envelope", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) return { status: 200, body: { transaction_receipt: ALIGNED_RECEIPT.base64 } };
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") assert.match(outcome.message, /exactly one supported receipt evidence field/);
    } finally {
      restore();
    }
  });

  it("rejects any extra competing durable evidence field", async () => {
    const restore = withRoutes((path) => {
      if (path === "/chain/network") return { status: 200, body: { network: "mainnet", network_byte: 0 } };
      if (path.endsWith("/result")) return { status: 404, body: null };
      if (path.includes("/transaction-receipts/")) {
        return { status: 200, body: { receipt: ALIGNED_RECEIPT.base64, evidence: { source: "other" } } };
      }
      throw new Error(`unexpected route ${path}`);
    });
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") assert.match(outcome.message, /exactly one supported receipt evidence field/);
    } finally {
      restore();
    }
  });

  it("rejects duplicate receipt names before JSON parsing collapses them", async () => {
    const restore = withRawDurableEnvelope(`{"receipt":"${ALIGNED_RECEIPT.base64}","receipt":"${ALIGNED_RECEIPT.base64}"}`);
    try {
      const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
      if (outcome.kind === "terminal_failure") assert.match(outcome.message, /exactly one supported receipt evidence field/);
    } finally {
      restore();
    }
  });

  it("rejects duplicate competing evidence names and malformed durable JSON", async () => {
    for (const source of [
      `{"receipt":"${ALIGNED_RECEIPT.base64}","result":{},"result":{}}`,
      `{"receipt":"${ALIGNED_RECEIPT.base64}"`,
    ]) {
      const restore = withRawDurableEnvelope(source);
      try {
        const outcome = await verifyBrowserAnchorEvidence(WALLET_ADAPTER, transactionId, template, payload);
        assert.equal(outcome.kind, "terminal_failure");
      } finally {
        restore();
      }
    }
  });
});
