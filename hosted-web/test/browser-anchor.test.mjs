import assert from "node:assert/strict";
import test from "node:test";

import { submittedTransactionId } from "../src/browserAnchor.ts";

test("browser anchor recovery accepts only a canonical submitted transaction id", () => {
  const transactionId = "ab".repeat(32);
  assert.equal(submittedTransactionId({ status: "submitted", result: { transactionId } }), transactionId);
  assert.equal(submittedTransactionId({ status: "submitted", result: transactionId }), transactionId);
  assert.equal(submittedTransactionId({ status: "submitted", result: { transactionId: transactionId.toUpperCase() } }), null);
  assert.equal(submittedTransactionId({ status: "submitted", result: { transactionId: "short" } }), null);
});
