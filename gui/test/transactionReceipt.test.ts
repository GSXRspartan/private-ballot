import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  decodeTransactionReceiptBase64,
  verifyDurableTransactionReceipt,
  TransactionReceiptDecodeError,
  type DecodedTransactionReceipt,
} from "../src/wallet/transactionReceipt.ts";
import { VerificationFailure } from "../src/wallet/verifyReceipt.ts";
import { RECEIPT_VECTORS } from "./receiptVectors.generated.ts";

const COMMIT = RECEIPT_VECTORS.commit_receipt;
const ALIGNED = RECEIPT_VECTORS.commit_receipt_aligned_with_exec_vector;

const TEMPLATE = {
  templateAddressHex: "ef4d7f348a4c3db7b6f9a9c30ac4fcbfdfb73e8bec59a808258861fcbbdc6cdb",
  eventTopic: "tari_private_ballot_anchor_v2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
};
const PAYLOAD = {
  anchorDigestHex: "67e995cdbc0077967e8ed55ac6f33b6c7df0a369938b4a40bc45e3fe7b2778c7",
  network: "mainnet",
  electionId: "5e50e17c401682fb38dbea349a4c2713",
  publicSummary:
    '{"election_id":"5e50e17c401682fb38dbea349a4c2713","questions":[{"text":"Adopt the charter?","options":["Yes","No"]}],"ballot_count":10}',
};
const TRANSACTION_HEX = "9a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b";

function expectFailureKind(run: () => unknown, kind: string): void {
  try {
    run();
    assert.fail(`expected ${kind}`);
  } catch (error) {
    assert.ok(error instanceof VerificationFailure, `expected VerificationFailure, got ${error}`);
    assert.equal((error as VerificationFailure).kind, kind);
  }
}

describe("durable TransactionReceipt wire decode (v0.53.x fixture)", () => {
  it("decodes the real committed receipt byte-for-byte", () => {
    const decoded = decodeTransactionReceiptBase64(COMMIT.base64);
    assert.equal(decoded.outcome, "Commit");
    assert.equal(decoded.epoch, 42);
    assert.equal(decoded.intentCommitmentHex, "00".repeat(32));
    assert.equal(decoded.events.length, 2);
    const [anchor, payFee] = decoded.events;
    assert.equal(anchor.templateAddressHex, TEMPLATE.templateAddressHex);
    assert.equal(anchor.topic, TEMPLATE.eventTopic);
    assert.equal(anchor.eventIndex, 0);
    assert.equal(payFee.topic, "std.vault.pay_fee");
    // Unrelated engine metadata keeps its native type: the amount is a number.
    const amount = payFee.metadata.find((entry) => entry.key === "amount");
    assert.equal(typeof amount?.value, "number");
    assert.equal(amount?.value, 123);
  });

  it("keeps anchor metadata values strictly typed strings", () => {
    const decoded = decodeTransactionReceiptBase64(COMMIT.base64);
    const anchor = decoded.events[0];
    const digest = anchor.metadata.find((entry) => entry.key === "anchor_digest_v2");
    assert.equal(typeof digest?.value, "string");
    assert.equal(digest?.value, PAYLOAD.anchorDigestHex);
  });

  it("rejects malformed receipt bytes", () => {
    assert.throws(() => decodeTransactionReceiptBase64("////"), TransactionReceiptDecodeError);
    // A base64 body with trailing bytes after the CBOR value.
    const good = decodeTransactionReceiptBase64(COMMIT.base64);
    assert.ok(good.outcome === "Commit");
    assert.throws(
      () => decodeTransactionReceiptBase64("gYSA",
      ),
      TransactionReceiptDecodeError,
    );
    assert.throws(() => decodeTransactionReceiptBase64(""), TransactionReceiptDecodeError);
  });

  it("rejects a truncated or non-array receipt body", () => {
    // `f6` is a lone CBOR null; the receipt must be a 7-item array.
    assert.throws(() => decodeTransactionReceiptBase64("hg=="), TransactionReceiptDecodeError);
    assert.throws(() => decodeTransactionReceiptBase64("nw=="), TransactionReceiptDecodeError);
  });
});

describe("durable receipt verification", () => {
  it("verifies the real committed receipt", () => {
    const decoded = decodeTransactionReceiptBase64(COMMIT.base64);
    const evidence = verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, decoded);
    assert.equal(evidence.transactionIdHex, TRANSACTION_HEX);
    assert.equal(evidence.epoch, 42);
    assert.equal(evidence.eventIndex, 0);
  });

  it("never accepts FeeIntentCommit as full anchor success", () => {
    const decoded = decodeTransactionReceiptBase64(RECEIPT_VECTORS.fee_intent_commit_receipt.base64);
    expectFailureKind(
      () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, decoded),
      "fee_only_acceptance",
    );
  });

  it("fails on a missing or duplicate anchor event", () => {
    const missing = decodeTransactionReceiptBase64(RECEIPT_VECTORS.missing_anchor_receipt.base64);
    expectFailureKind(
      () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, missing),
      "missing_anchor_event",
    );
    const duplicate = decodeTransactionReceiptBase64(RECEIPT_VECTORS.duplicate_anchor_receipt.base64);
    expectFailureKind(
      () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, duplicate),
      "duplicate_anchor_events",
    );
  });

  it("fails on a wrong template, topic, or digest", () => {
    const wrongTemplate = decodeTransactionReceiptBase64(RECEIPT_VECTORS.wrong_template_receipt.base64);
    expectFailureKind(
      () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, wrongTemplate),
      "wrong_event_template",
    );
    const wrongTopic = decodeTransactionReceiptBase64(RECEIPT_VECTORS.wrong_topic_receipt.base64);
    expectFailureKind(
      () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, wrongTopic),
      "wrong_event_topic",
    );
    const wrongDigest = decodeTransactionReceiptBase64(RECEIPT_VECTORS.wrong_digest_receipt.base64);
    expectFailureKind(
      () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, wrongDigest),
      "wrong_anchor_digest",
    );
  });

  it("fails on a wrong network, election id, or summary", () => {
    const decoded = decodeTransactionReceiptBase64(COMMIT.base64);
    for (const payload of [
      { ...PAYLOAD, network: "esmeralda" },
      { ...PAYLOAD, electionId: "aa".repeat(16) },
      { ...PAYLOAD, publicSummary: "{}" },
    ]) {
      expectFailureKind(
        () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, payload, decoded),
        "malformed_anchor_event",
      );
    }
  });

  it("fails when a matching anchor event value is not text", () => {
    const decoded: DecodedTransactionReceipt = decodeTransactionReceiptBase64(COMMIT.base64);
    const digest = decoded.events[0].metadata.find((entry) => entry.key === "anchor_digest_v2");
    assert.ok(digest);
    digest.value = 123;
    expectFailureKind(
      () => verifyDurableTransactionReceipt(TRANSACTION_HEX, TEMPLATE, PAYLOAD, decoded),
      "malformed_anchor_event",
    );
  });

  it("rejects a malformed expected transaction id", () => {
    const decoded = decodeTransactionReceiptBase64(COMMIT.base64);
    assert.throws(
      () => verifyDurableTransactionReceipt("AB".repeat(32), TEMPLATE, PAYLOAD, decoded),
      /64 lowercase hex/,
    );
  });

  it("verifies the aligned receipt against the execution-vector identity", () => {
    const decoded = decodeTransactionReceiptBase64(ALIGNED.base64);
    const evidence = verifyDurableTransactionReceipt(TRANSACTION_HEX, {
      templateAddressHex: "5f1ecbe69b1c6e8b64b97b37f32f6975be4b1e2a1d9c4a5e3f2b6c8d0a9e7f41",
      eventTopic: "TariPrivateBallotAnchorV2.TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2",
    }, PAYLOAD, decoded);
    assert.equal(evidence.epoch, 7);
    assert.equal(evidence.eventIndex, 0);
  });
});
