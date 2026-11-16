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
/** A transient indexer read may refine final evidence, but never blocks it. */
export const TRANSIENT_RESULT_TIMEOUT_MS = 2_000;

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
 * returns `{ "receipt": "<base64 CBOR TransactionReceipt>" }` (HTTP 200).
 * The receipt is decoded and verified in the pinned v0.53.x wire format;
 * a FeeIntentCommit outcome is never a full anchor success. A response
 * returns exactly that one-field envelope. No alternate durable shape is
 * documented or accepted. A legacy result envelope is not durable evidence
 * and a response with extra evidence fields is ambiguous, so both fail closed.
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
  const fields = Object.keys(record);
  // `receipt` is the only documented, supported durable representation. Do
  // not select it by precedence from a larger envelope: doing so would hide a
  // competing result from an independently observable source.
  if (fields.length !== 1 || fields[0] !== "receipt" || typeof record.receipt !== "string") {
    return terminal("the durable receipt response must contain exactly one supported receipt evidence field");
  }
  try {
    const decoded = decodeTransactionReceiptBase64(record.receipt);
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

type JsonResponse = { status: number; json: unknown | null };

async function readJson(path: string, signal?: AbortSignal): Promise<JsonResponse> {
  let response: Response;
  try {
    response = await fetch(`${CHAIN_PREFIX}${path}`, { headers: { Accept: "application/json" }, signal });
  } catch {
    return { status: 0, json: null };
  }
  if (!response.ok) return { status: response.status, json: null };
  try {
    return { status: response.status, json: await response.json() };
  } catch {
    return { status: response.status, json: null };
  }
}

async function readTransientJson(path: string): Promise<JsonResponse> {
  const controller = new AbortController();
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      readJson(path, controller.signal),
      new Promise<JsonResponse>((resolve) => {
        timeout = setTimeout(() => {
          controller.abort();
          resolve({ status: 0, json: null });
        }, TRANSIENT_RESULT_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timeout !== undefined) clearTimeout(timeout);
  }
}

/**
 * Requires a wallet result AND a valid durable receipt.
 * The transient result endpoint is consulted but a valid durable receipt is
 * REQUIRED for final "verified" success. If the receipt is unavailable (404,
 * 500, proxy failure, malformed, or proxy unavailable), verification fails
 * closed. The wallet result and the durable receipt must agree; any
 * disagreement is terminal.
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

  // Begin the optional lookup promptly, then establish durable authority
  // independently. A failed or slow transient route must not hide a known
  // final conflict between the wallet and the durable receipt.
  const transient = readTransientJson(`/transactions/${transactionId}/result`);
  const receipt = await readJson(`/transaction-receipts/${transactionId}`);

  // Durable receipt is REQUIRED for final verification.
  if (receipt.status !== 200) {
    return terminal("the durable transaction receipt is unavailable (status " + receipt.status + "); final verification requires a valid receipt");
  }
  if (receipt.json === null) {
    return terminal("the durable receipt response is not JSON");
  }
  const receiptOutcome = verifyDurableReceiptResponse(transactionId, template, payload, receipt.json);
  if (receiptOutcome.kind !== "verified") return receiptOutcome;

  // These are independent final sources. Their disagreement is already
  // conclusive and must not be masked by a transient result route reporting
  // Pending, a timeout, or an unavailable response.
  if (!sameEvidence(wallet, receiptOutcome)) {
    return terminal("wallet and durable receipt evidence disagree");
  }

  const result = await transient;
  // If transient result exists, it must agree with the durable receipt.
  if (result.status === 200) {
    if (result.json === null) return terminal("the indexer result response is not JSON");
    const resultOutcome = verifyV2AnchorTransaction(transactionId, template, payload, result.json);
    if (resultOutcome.kind !== "verified") return resultOutcome;
    if (!sameEvidence(receiptOutcome, resultOutcome)) {
      return terminal("the transient indexer result disagrees with the durable receipt");
    }
  }

  return receiptOutcome;
}
