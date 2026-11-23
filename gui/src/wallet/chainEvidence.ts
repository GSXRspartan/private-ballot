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
  wireFields: readonly string[] | null,
): AnchorVerificationOutcome {
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return terminal("the durable transaction receipt response is not an object");
  }
  const record = json as Record<string, unknown>;
  const fields = Object.keys(record);
  // `receipt` is the only documented, supported durable representation. Do
  // not select it by precedence from a larger envelope: doing so would hide a
  // competing result from an independently observable source.
  if (
    wireFields === null || wireFields.length !== 1 || wireFields[0] !== "receipt" ||
    fields.length !== 1 || fields[0] !== "receipt" || typeof record.receipt !== "string"
  ) {
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

function skipWhitespace(source: string, index: number): number {
  while (index < source.length && /[\t\n\r ]/.test(source[index]!)) index += 1;
  return index;
}

function readJsonString(source: string, index: number): { value: string; next: number } | null {
  if (source[index] !== '"') return null;
  let cursor = index + 1;
  let escaped = false;
  while (cursor < source.length) {
    const character = source[cursor]!;
    if (escaped) {
      escaped = false;
    } else if (character === "\\") {
      escaped = true;
    } else if (character === '"') {
      try {
        return { value: JSON.parse(source.slice(index, cursor + 1)) as string, next: cursor + 1 };
      } catch {
        return null;
      }
    } else if (character < " ") {
      return null;
    }
    cursor += 1;
  }
  return null;
}

/**
 * Returns top-level member names without interpreting member values. Durable
 * receipts have a fixed one-member envelope, so this small scanner lets us
 * detect duplicate names before JSON.parse collapses them.
 */
function topLevelJsonMemberNames(source: string): string[] | null {
  let cursor = skipWhitespace(source, 0);
  if (source[cursor] !== "{") return null;
  cursor = skipWhitespace(source, cursor + 1);
  const names: string[] = [];
  if (source[cursor] === "}") return names;
  while (cursor < source.length) {
    const key = readJsonString(source, cursor);
    if (key === null) return null;
    names.push(key.value);
    cursor = skipWhitespace(source, key.next);
    if (source[cursor] !== ":") return null;
    cursor = skipWhitespace(source, cursor + 1);

    let nesting = 0;
    let inString = false;
    let escaped = false;
    while (cursor < source.length) {
      const character = source[cursor]!;
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
      } else if (character === '"') {
        inString = true;
      } else if (character === "{" || character === "[") {
        nesting += 1;
      } else if (character === "}" || character === "]") {
        if (nesting === 0) {
          if (character !== "}") return null;
          break;
        }
        nesting -= 1;
      } else if (character === "," && nesting === 0) {
        break;
      }
      cursor += 1;
    }
    if (cursor >= source.length || inString || nesting !== 0) return null;
    if (source[cursor] === "}") {
      cursor = skipWhitespace(source, cursor + 1);
      return cursor === source.length ? names : null;
    }
    cursor = skipWhitespace(source, cursor + 1);
  }
  return null;
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

async function readDurableReceipt(path: string): Promise<JsonResponse & { wireFields: string[] | null }> {
  let response: Response;
  try {
    response = await fetch(`${CHAIN_PREFIX}${path}`, { headers: { Accept: "application/json" } });
  } catch {
    return { status: 0, json: null, wireFields: null };
  }
  if (!response.ok) return { status: response.status, json: null, wireFields: null };
  let source: string;
  try {
    source = await response.text();
  } catch {
    return { status: response.status, json: null, wireFields: null };
  }
  const wireFields = topLevelJsonMemberNames(source);
  try {
    return { status: response.status, json: JSON.parse(source) as unknown, wireFields };
  } catch {
    return { status: response.status, json: null, wireFields: null };
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
 * REQUIRED for final "verified" success. A receipt that is not yet indexed
 * (404), or a receipt route that is temporarily unreachable (5xx / fetch
 * failure), is a retryable "pending" outcome: it never becomes "verified"
 * without the receipt, and it is never misreported as a terminal rejection.
 * A response that is malformed, has an unsupported envelope, or disagrees with
 * the wallet is still terminal. The wallet result and the durable receipt must
 * agree; any disagreement is terminal.
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
  const receipt = await readDurableReceipt(`/transaction-receipts/${transactionId}`);

  // Durable receipt is REQUIRED for final verification. An indexed-but-not-yet
  // visible receipt is a normal transient state during mainnet indexing, so a
  // missing or unreachable receipt keeps the saved transaction retryable
  // instead of mislabelling it as a failed/rejected anchor.
  if (receipt.status !== 200) {
    return {
      kind: "pending",
      detail: `the durable transaction receipt is not indexed yet (status ${receipt.status})`,
    };
  }
  if (receipt.json === null) {
    return terminal("the durable receipt response is not JSON");
  }
  const receiptOutcome = verifyDurableReceiptResponse(transactionId, template, payload, receipt.json, receipt.wireFields);
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
