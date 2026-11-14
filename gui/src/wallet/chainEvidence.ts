import type { WindowTariProvider } from "./provider.ts";
import {
  verifyV2AnchorTransaction,
  type AnchorVerificationOutcome,
  type ExpectedAnchorEventPayload,
  type ExpectedAnchorTemplate,
} from "./verifyReceipt.ts";

const CHAIN_PREFIX = "/chain";

function terminal(message: string): AnchorVerificationOutcome {
  return { kind: "terminal_failure", failure: "malformed_result", message };
}

function sameEvidence(left: Extract<AnchorVerificationOutcome, { kind: "verified" }>, right: Extract<AnchorVerificationOutcome, { kind: "verified" }>): boolean {
  return left.evidence.transactionIdHex === right.evidence.transactionIdHex &&
    left.evidence.epoch === right.evidence.epoch &&
    left.evidence.eventIndex === right.evidence.eventIndex;
}

function receiptEnvelope(value: unknown): unknown {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  if ("result" in record) return value;
  if (typeof record.transaction_result === "object" && record.transaction_result !== null) {
    return record.transaction_result;
  }
  return null;
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
    const envelope = receiptEnvelope(receipt.json);
    if (envelope === null) return terminal("the durable transaction receipt has no canonical result envelope");
    const outcome = verifyV2AnchorTransaction(transactionId, template, payload, envelope);
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
