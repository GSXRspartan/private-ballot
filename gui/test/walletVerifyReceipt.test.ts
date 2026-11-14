import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  ANCHOR_EVENT_DIGEST_KEY_V2,
  VerificationFailure,
  anchorFailureMessage,
  parseResultEnvelope,
  verifyV2AnchorExecutionResult,
  verifyV2AnchorTransaction,
  type ExpectedAnchorEventPayload,
  type ExpectedAnchorTemplate,
} from "../src/wallet/verifyReceipt.ts";
import { decodeExecuteResultBase64 } from "../src/wallet/executeResult.ts";
import {
  EXEC_RESULT_BASE64,
  RESULT_JSON_ABORTED,
  RESULT_JSON_FEE_INTENT_COMMIT,
  RESULT_JSON_FINALIZED_COMMIT,
  RESULT_JSON_MEMPOOL_REJECTED,
  RESULT_JSON_PENDING,
} from "./anchorVectors.generated.ts";

const TEMPLATE: ExpectedAnchorTemplate = {
  templateAddressHex: "5f1ecbe69b1c6e8b64b97b37f32f6975be4b1e2a1d9c4a5e3f2b6c8d0a9e7f41",
  eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
};

const PAYLOAD: ExpectedAnchorEventPayload = {
  anchorDigestHex: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7",
  network: "mainnet",
  electionId: "5e50e17c401682fb38dbea349a4c2713",
  publicSummary:
    '{"election_id":"5e50e17c401682fb38dbea349a4c2713","questions":[{"text":"Adopt the charter?","options":["Yes","No"]}],"ballot_count":10}',
};

const TRANSACTION_HEX = "9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b";

function envelope(json: string): unknown {
  return JSON.parse(json);
}

function expectFailureKind(
  run: () => unknown,
  kind: string,
): void {
  try {
    run();
    assert.fail(`expected ${kind}`);
  } catch (error) {
    assert.ok(error instanceof VerificationFailure, `expected VerificationFailure, got ${error}`);
    assert.equal((error as VerificationFailure).kind, kind);
  }
}

describe("result envelope parsing", () => {
  it("parses pending, rejected, and committed envelopes from the Rust wire vectors", () => {
    assert.deepEqual(parseResultEnvelope(envelope(RESULT_JSON_PENDING)), {
      kind: "pending",
    });
    assert.deepEqual(parseResultEnvelope(envelope(RESULT_JSON_MEMPOOL_REJECTED)), {
      kind: "rejected",
      details: "mempool rejected",
    });
    const finalized = parseResultEnvelope(envelope(RESULT_JSON_FINALIZED_COMMIT));
    assert.equal(finalized.kind, "finalized");
    if (finalized.kind === "finalized") {
      assert.equal(finalized.committed, true);
      assert.equal(finalized.executionResult, EXEC_RESULT_BASE64);
    }
  });

  it("treats an aborted final decision as not committed", () => {
    const finalized = parseResultEnvelope(envelope(RESULT_JSON_ABORTED));
    assert.equal(finalized.kind, "finalized");
    if (finalized.kind === "finalized") {
      assert.equal(finalized.committed, false);
      assert.equal(finalized.abortDetails, "consensus aborted");
    }
  });

  it("rejects malformed envelopes", () => {
    assert.equal(parseResultEnvelope(null).kind, "malformed");
    assert.equal(parseResultEnvelope({}).kind, "malformed");
    assert.equal(parseResultEnvelope({ result: "Weird" }).kind, "malformed");
    assert.equal(parseResultEnvelope({ result: { Mystery: {} } }).kind, "malformed");
    assert.equal(parseResultEnvelope({ result: { Pending: {}, Finalized: {} } }).kind, "malformed");
  });
});

describe("V2 anchor execution-result verification (Rust vectors)", () => {
  it("verifies the real committed fixture", () => {
    const decoded = decodeExecuteResultBase64(EXEC_RESULT_BASE64);
    const evidence = verifyV2AnchorExecutionResult(
      TRANSACTION_HEX,
      TEMPLATE,
      PAYLOAD,
      decoded,
    );
    assert.equal(evidence.transactionIdHex, TRANSACTION_HEX);
    assert.equal(evidence.epoch, 7);
    assert.equal(evidence.eventIndex, 0);
  });

  it("fails closed on every mismatch class", () => {
    const decoded = decodeExecuteResultBase64(EXEC_RESULT_BASE64);
    expectFailureKind(
      () =>
        verifyV2AnchorExecutionResult(
          "aa".repeat(32),
          TEMPLATE,
          PAYLOAD,
          decoded,
        ),
      "wrong_transaction",
    );
    const feeDecoded = decodeExecuteResultBase64(
      JSON.parse(RESULT_JSON_FEE_INTENT_COMMIT).result.Finalized.execution_result,
    );
    expectFailureKind(
      () => verifyV2AnchorExecutionResult("aa".repeat(32), TEMPLATE, PAYLOAD, feeDecoded),
      "wrong_transaction",
    );
    expectFailureKind(
      () =>
        verifyV2AnchorExecutionResult(
          feeDecoded.transactionHashHex,
          TEMPLATE,
          PAYLOAD,
          feeDecoded,
        ),
      "fee_only_acceptance",
    );
  });

  it("fails on a wrong anchor digest with the dedicated error", () => {
    const decoded = decodeExecuteResultBase64(EXEC_RESULT_BASE64);
    expectFailureKind(
      () =>
        verifyV2AnchorExecutionResult(TRANSACTION_HEX, TEMPLATE, {
          ...PAYLOAD,
          anchorDigestHex: "ab".repeat(32),
        }, decoded),
      "wrong_anchor_digest",
    );
  });

  it("fails on a wrong event network, election id, or summary", () => {
    const decoded = decodeExecuteResultBase64(EXEC_RESULT_BASE64);
    for (const payload of [
      { ...PAYLOAD, network: "esmeralda" },
      { ...PAYLOAD, electionId: "aa".repeat(16) },
      { ...PAYLOAD, publicSummary: "{}" },
    ]) {
      expectFailureKind(
        () => verifyV2AnchorExecutionResult(TRANSACTION_HEX, TEMPLATE, payload, decoded),
        "malformed_anchor_event",
      );
    }
  });

  it("fails on a different template or topic", () => {
    const decoded = decodeExecuteResultBase64(EXEC_RESULT_BASE64);
    expectFailureKind(
      () =>
        verifyV2AnchorExecutionResult(TRANSACTION_HEX, {
          ...TEMPLATE,
          templateAddressHex: "ab".repeat(32),
        }, PAYLOAD, decoded),
      "wrong_event_template",
    );
    expectFailureKind(
      () =>
        verifyV2AnchorExecutionResult(TRANSACTION_HEX, {
          ...TEMPLATE,
          eventTopic: "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
        }, PAYLOAD, decoded),
      "wrong_event_topic",
    );
  });

  it("gives every failure kind a bounded human message", () => {
    for (const kind of [
      "wrong_transaction",
      "fee_only_acceptance",
      "rejected_transaction",
      "malformed_result",
      "wrong_event_template",
      "wrong_event_topic",
      "missing_anchor_event",
      "duplicate_anchor_events",
      "unexpected_event_metadata",
      "malformed_anchor_event",
      "wrong_anchor_digest",
    ] as const) {
      assert.ok(anchorFailureMessage(kind).length > 10);
    }
    assert.ok(anchorFailureMessage("wrong_anchor_digest").length > 10);
  });
});

describe("end-to-end transaction verification", () => {
  it("verifies Sapient's decoded ExecuteResult JSON representation", () => {
    const decoded = decodeExecuteResultBase64(EXEC_RESULT_BASE64);
    const sapientExecuteResult = {
      finalize: {
        transaction_hash: decoded.transactionHashHex,
        events: decoded.events.map((event) => ({
          substate_id: null,
          template_address: event.templateAddressHex,
          topic: event.topic,
          payload: Object.fromEntries(event.metadata.map((entry) => [entry.key, entry.value])),
        })),
        logs: [],
        result: { Accept: {} },
        fee_receipt: {},
        total_fees_required: 0,
      },
      execution_time: { secs: 0, nanos: 0 },
      execute_epoch: decoded.epoch,
      wasm_execution_points: 0,
      native_execution_points: 0,
    };
    const result = envelope(RESULT_JSON_FINALIZED_COMMIT) as { result: { Finalized: Record<string, unknown> } };
    result.result.Finalized.execution_result = sapientExecuteResult;
    assert.equal(
      verifyV2AnchorTransaction(TRANSACTION_HEX, TEMPLATE, PAYLOAD, result).kind,
      "verified",
    );
  });

  it("verifies the real committed vector end to end", () => {
    const outcome = verifyV2AnchorTransaction(
      TRANSACTION_HEX,
      TEMPLATE,
      PAYLOAD,
      envelope(RESULT_JSON_FINALIZED_COMMIT),
    );
    assert.equal(outcome.kind, "verified");
  });

  it("maps pending and rejected outcomes without resubmission hints", () => {
    assert.deepEqual(
      verifyV2AnchorTransaction(TRANSACTION_HEX, TEMPLATE, PAYLOAD, envelope(RESULT_JSON_PENDING)),
      { kind: "pending" },
    );
    const rejected = verifyV2AnchorTransaction(
      TRANSACTION_HEX,
      TEMPLATE,
      PAYLOAD,
      envelope(RESULT_JSON_MEMPOOL_REJECTED),
    );
    assert.equal(rejected.kind, "terminal_failure");
    if (rejected.kind === "terminal_failure") {
      assert.equal(rejected.failure, "rejected_transaction");
    }
  });

  it("maps a fee-only commit to a terminal failure", () => {
    const outcome = verifyV2AnchorTransaction(
      "aa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
      TEMPLATE,
      PAYLOAD,
      envelope(RESULT_JSON_FEE_INTENT_COMMIT),
    );
    assert.equal(outcome.kind, "terminal_failure");
    if (outcome.kind === "terminal_failure") {
      assert.equal(outcome.failure, "fee_only_acceptance");
    }
  });

  it("maps an aborted decision to a terminal rejection", () => {
    const outcome = verifyV2AnchorTransaction(
      "bb1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
      TEMPLATE,
      PAYLOAD,
      envelope(RESULT_JSON_ABORTED),
    );
    assert.equal(outcome.kind, "terminal_failure");
  });

  it("maps a wrong digest on the committed vector to a terminal wrong-digest failure", () => {
    const outcome = verifyV2AnchorTransaction(
      TRANSACTION_HEX,
      TEMPLATE,
      { ...PAYLOAD, anchorDigestHex: "cd".repeat(32) },
      envelope(RESULT_JSON_FINALIZED_COMMIT),
    );
    assert.equal(outcome.kind, "terminal_failure");
    if (outcome.kind === "terminal_failure") {
      assert.equal(outcome.failure, "wrong_anchor_digest");
    }
  });
});
