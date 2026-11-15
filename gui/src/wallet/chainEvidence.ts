import type { WindowTariProvider } from "./provider.ts";
import {
  verifyV2AnchorTransaction,
  VerificationFailure,
  type AnchorVerificationOutcome,
  type ExpectedAnchorEventPayload,
  type ExpectedAnchorTemplate,
} from "./verifyReceipt.ts";
import {
  decodeTransactionReceiptBase64,
  verifyDurableTransactionReceipt,
  TransactionReceiptDecodeError,
} from "./transactionReceipt.ts";

const CHAIN_PREFIX = "/chain";

function terminal(message: string): AnchorVerificationOutcome {
  return { kind: "terminal_failure", failure: "malformed_result", message };
}

function sameEvidence(left: Extract<AnchorVerificationOutcome, { kind: "verified" }>, right: Extract<AnchorVerificationOutcome, { kind: "verified" }>): boolean {
  return left.evidence.transactionIdHex === right.evidence.transactionIdHex &&
    left.evidence.epoch === right.evidence.epoch &&
    left.evidence.eventIndex === right.evidence.eventIndex;
}

/**
 * Decodes and verifies the durable receipt response. The Mainnet indexer
 * returns `{ "receipt": "<base64 CBOR TransactionReceipt>" }` (HTTP 200) even
 * when the transient transaction-result route answers 404. The receipt is
 * decoded and verified in the pinned v0.53.x wire format; a FeeIntentCommit
 * outcome is never a full anchor success. A legacy response carrying a
 * canonical result envelope instead is still verified through the same
 * canonical verifier, and a receipt response with neither shape is terminal.
 */
function verifyDurableReceiptResponse(
  transactionId: string,
  template: ExpectedAnchorTemplate,
  payload: ExpectedAnchorEventPayload,
  json: unknown,
): AnchorVerificationOutcome {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return terminal("the durable transaction receipt response is not an object");
  }
  const record = json as Record<string, unknown>;
  const receiptField = record.receipt;
  if (typeof receiptField === "string") {
    try {
      const decoded = decodeTransactionReceiptBase64(receiptField);
      return { kind: "verified", evidence: verifyDurableTransactionReceipt(transactionId, template, payload, decoded) };
    } catch (error) {
      if (error instanceof TransactionReceiptDecodeError) {
        return terminal(error.message);
      }
      if (error instanceof VerificationFailure) {
        return { kind: "terminal_failure", failure: error.kind, message: error.message };
      }
      throw error;
    }
  }
  if ("result" in record) {
    return verifyV2AnchorTransaction(transactionId, template, payload, record);
  }
  return terminal("the durable transaction receipt has no canonical result envelope");
}

async function readJson(path: string): Promise<{ status: number; json: unknown | null }> {
  const response = await fetch(`${CHAIN_PREFIX}${path}`, { headers: { Accept: "application/json" } });
  if (!response.ok) return { status: response.status, json: null };
  try {
    return { status: response.status, json: await response.json() };
  } catch {
    return { status: response.status, json: null };
  }
}

/**
 * Requires one wallet result plus one independent read-only chain response.
 * A transient result endpoint can be replaced by the durable receipt endpoint;
 * any finalized conflicting or malformed response is terminal and fail-closed.
 * The wallet result, the transient result, and the durable receipt must all
 * agree; disagreement between any of them is terminal. Local verified state is
 * never accepted as a substitute for chain evidence.
 */
export async function verifyBrowserAnchorEvidence(
  adapter: WindowTariProvider,
  transactionId: string,
  template: ExpectedAnchorTemplate,
  payload: ExpectedAnchorEventPayload,
): Promise<AnchorVerificationOutcome> {
  const network = await readJson("/network");
  if (network.status !== 200 || typeof network.json !== "object" || network.json === null) {
    return { kind: "pending" };
  }
  const networkRecord = network.json as Record<string, unknown>;
  if (networkRecord.network !== "mainnet" || networkRecord.network_byte !== 0) {
    return terminal("the indexer proxy did not prove Mainnet network name and byte");
  }
  const walletJson = await adapter.getTransactionResult(transactionId);
  const wallet = verifyV2AnchorTransaction(transactionId, template, payload, walletJson);
  if (wallet.kind !== "verified") return wallet;

  const [result, receipt] = await Promise.all([
    readJson(`/transactions/${transactionId}/result`),
    readJson(`/transaction-receipts/${transactionId}`),
  ]);
  const evidence: Extract<AnchorVerificationOutcome, { kind: "verified" }>[] = [];
  if (result.status === 200) {
    if (result.json === null) return terminal("the indexer result response is not JSON");
    const outcome = verifyV2AnchorTransaction(transactionId, template, payload, result.json);
    if (outcome.kind !== "verified") return outcome;
    evidence.push(outcome);
  }
  if (receipt.status === 200) {
    if (receipt.json === null) return terminal("the durable receipt response is not JSON");
    const outcome = verifyDurableReceiptResponse(transactionId, template, payload, receipt.json);
    if (outcome.kind !== "verified") return outcome;
    evidence.push(outcome);
  }
  if (evidence.length === 0) return { kind: "pending" };
  if (evidence.some((outcome) => !sameEvidence(wallet, outcome))) {
    return terminal("wallet and indexer evidence disagree");
  }
  if (evidence.length === 2 && !sameEvidence(evidence[0], evidence[1])) {
    return terminal("indexer result and durable receipt disagree");
  }
  return wallet;
}
