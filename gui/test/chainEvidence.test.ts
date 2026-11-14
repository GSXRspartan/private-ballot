import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { verifyBrowserAnchorEvidence } from "../src/wallet/chainEvidence.ts";
import type { WindowTariProvider } from "../src/wallet/provider.ts";
import { RESULT_JSON_FINALIZED_COMMIT } from "./anchorVectors.generated.ts";

const transactionId = "9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b";
const template = { templateAddressHex: "5f1ecbe69b1c6e8b64b97b37f32f6975be4b1e2a1d9c4a5e3f2b6c8d0a9e7f41", eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2" };
const payload = { anchorDigestHex: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7", network: "mainnet", electionId: "5e50e17c401682fb38dbea349a4c2713", publicSummary: '{"election_id":"5e50e17c401682fb38dbea349a4c2713","questions":[{"text":"Adopt the charter?","options":["Yes","No"]}],"ballot_count":10}' };
const adapter = { getTransactionResult: async () => JSON.parse(RESULT_JSON_FINALIZED_COMMIT) } as unknown as WindowTariProvider;

describe("browser chain evidence", () => {
  it("uses the durable receipt when the transient result endpoint is absent", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async (input) => {
      const path = new URL(input.toString(), "https://app.test").pathname;
      if (path === "/chain/network") return Response.json({ network: "mainnet", network_byte: 0 });
      if (path.includes("/result")) return new Response(null, { status: 404 });
      return Response.json(JSON.parse(RESULT_JSON_FINALIZED_COMMIT));
    };
    try {
      assert.equal((await verifyBrowserAnchorEvidence(adapter, transactionId, template, payload)).kind, "verified");
    } finally {
      globalThis.fetch = original;
    }
  });

  it("fails closed unless the proxy proves both Mainnet name and byte", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = async () => Response.json({ network: "mainnet", network_byte: 38 });
    try {
      const outcome = await verifyBrowserAnchorEvidence(adapter, transactionId, template, payload);
      assert.equal(outcome.kind, "terminal_failure");
    } finally {
      globalThis.fetch = original;
    }
  });
});
