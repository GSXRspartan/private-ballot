/**
 * Durable Tari/Ootle TransactionReceipt decoding and verification.
 *
 * On the observed Mainnet indexer the transient transaction-result route can
 * return 404 while the durable route (`/transaction-receipts/{id}`) returns
 * `{ "receipt": "<base64 CBOR TransactionReceipt>" }`. The bytes are the exact
 * `Encoded<TransactionReceipt>` CBOR the pinned Ootle engine persists
 * (`tari_engine_types::transaction_receipt::TransactionReceipt`, unchanged
 * field structure across the v0.48–v0.53.x cohorts):
 *
 * - array(7): outcome, diff_summary, fee_withdrawals, events, fee_receipt,
 *   epoch, intent_commitment;
 * - `FinalizeOutcome` is the 2-element enum array `[variantIndex, []]` with
 *   `Commit = 0` and `FeeIntentCommit = 1`;
 * - each `Event` is array(4): substate_id, 32-byte template address, topic
 *   text, and the tag-129 metadata map whose values are arbitrary raw CBOR
 *   (only the matching V2 anchor event must carry the exact four text values).
 *
 * The receipt itself is addressed by (and therefore does not carry) the
 * transaction id, so transaction identity is bound by fetching the durable
 * receipt for the exact expected transaction id and verifying its anchor event
 * against the expected election identity.
 */
import { cborDecodeStrict, CborError, type CborNode } from "./cbor.ts";
import { base64ToBytes } from "./executeResult.ts";
import {
  ANCHOR_EVENT_DIGEST_KEY_V2,
  VerificationFailure,
  type ExpectedAnchorEventPayload,
  type ExpectedAnchorTemplate,
  type VerifiedAnchorEvidence,
} from "./verifyReceipt.ts";

export type DurableReceiptOutcome = "Commit" | "FeeIntentCommit";

export interface DecodedReceiptEvent {
  eventIndex: number;
  templateAddressHex: string;
  topic: string;
  metadata: { key: string; value: unknown }[];
}

export interface DecodedTransactionReceipt {
  outcome: DurableReceiptOutcome;
  epoch: number;
  intentCommitmentHex: string;
  events: DecodedReceiptEvent[];
}

export class TransactionReceiptDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TransactionReceiptDecodeError";
  }
}

/** Mirrors MAX_RECEIPT_LOG_ENTRIES in the Rust receipt adapter. */
const MAX_RECEIPT_EVENTS = 256;
const METADATA_TAG = 129;

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

function expectType(node: CborNode, type: CborNode["type"], what: string): CborNode {
  if (node.type !== type) {
    throw new TransactionReceiptDecodeError(`expected ${what} to be ${type}`);
  }
  return node;
}

function expectArrayLength(node: CborNode, length: number, what: string): CborNode[] {
  expectType(node, "array", what);
  if (node.value !== length) {
    throw new TransactionReceiptDecodeError(`expected ${what} to have ${length} items`);
  }
  return node.children;
}

function expectBytes32(node: CborNode, what: string): string {
  expectType(node, "bytes", what);
  const bytes = node.value as Uint8Array;
  if (bytes.length !== 32) {
    throw new TransactionReceiptDecodeError(`expected ${what} to be 32 bytes`);
  }
  return toHex(bytes);
}

function expectText(node: CborNode, what: string): string {
  expectType(node, "text", what);
  return node.value as string;
}

function decodeOutcome(node: CborNode): DurableReceiptOutcome {
  const fields = expectArrayLength(node, 2, "receipt outcome");
  const variant = fields[0];
  expectType(variant, "uint", "receipt outcome variant");
  const fieldsArray = fields[1];
  // The outcome variant must carry an EMPTY CBOR array as its payload.
  // The pinned wire format is [variant, []] - NOT [variant, 0] or [variant, {}].
  expectType(fieldsArray, "array", "receipt outcome fields array");
  if (fieldsArray.children.length !== 0) {
    throw new TransactionReceiptDecodeError("receipt outcome variant fields array must be empty");
  }
  if (variant.value === 0) return "Commit";
  if (variant.value === 1) return "FeeIntentCommit";
  throw new TransactionReceiptDecodeError("unknown receipt outcome variant");
}

function decodeEpoch(node: CborNode): number {
  expectType(node, "uint", "receipt epoch");
  const epoch = node.value as number;
  if (typeof epoch !== "number" || !Number.isSafeInteger(epoch) || epoch < 0) {
    throw new TransactionReceiptDecodeError("receipt epoch is out of range");
  }
  return epoch;
}

function decodeMetadata(node: CborNode): { key: string; value: unknown }[] {
  expectType(node, "tag", "event metadata");
  if (node.tag !== METADATA_TAG) {
    throw new TransactionReceiptDecodeError(`expected event metadata tag ${METADATA_TAG}`);
  }
  const map = node.children[0];
  expectType(map, "map", "event metadata map");
  const metadata: { key: string; value: unknown }[] = [];
  for (const entry of map.entries) {
    metadata.push({
      key: expectText(entry.key, "event metadata key"),
      value: metadataValue(entry.value),
    });
  }
  return metadata;
}

function decodeEvent(node: CborNode, eventIndex: number): DecodedReceiptEvent {
  const fields = expectArrayLength(node, 4, "receipt event");
  return {
    eventIndex,
    templateAddressHex: expectBytes32(fields[1], "receipt event template address"),
    topic: expectText(fields[2], "receipt event topic"),
    metadata: decodeMetadata(fields[3]),
  };
}

/** Preserves the decoded CBOR value's type; never coerces into strings. */
function metadataValue(node: CborNode): unknown {
  switch (node.type) {
    case "uint":
    case "negint":
      return node.value;
    case "bytes":
      return (node.value as Uint8Array).slice();
    case "text":
      return node.value;
    case "array":
      return node.children.map(metadataValue);
    case "map": {
      const out: Record<string, unknown> = {};
      for (const entry of node.entries) {
        const key = entry.key.type === "text"
          ? entry.key.value as string
          : `${entry.key.type}:${String(entry.key.value)}`;
        out[key] = metadataValue(entry.value);
      }
      return out;
    }
    case "tag":
      return { tag: node.tag, value: metadataValue(node.children[0]) };
    case "simple":
    case "float":
      return node.value;
  }
}

export function decodeTransactionReceiptCbor(bytes: Uint8Array): DecodedTransactionReceipt {
  let root: CborNode;
  try {
    root = cborDecodeStrict(bytes);
  } catch (error) {
    if (error instanceof CborError) {
      throw new TransactionReceiptDecodeError(`malformed transaction receipt: ${error.message}`);
    }
    throw error;
  }
  const top = expectArrayLength(root, 7, "transaction receipt");
  const outcome = decodeOutcome(top[0]);
  // diff_summary is the 2-field (upped, downed) struct; both halves are arrays.
  const diffSummary = expectArrayLength(top[1], 2, "receipt diff summary");
  expectType(diffSummary[0], "array", "receipt diff summary upped");
  expectType(diffSummary[1], "array", "receipt diff summary downed");
  expectType(top[2], "array", "receipt fee withdrawals");
  const eventNodes = expectType(top[3], "array", "receipt events");
  if (eventNodes.children.length > MAX_RECEIPT_EVENTS) {
    throw new TransactionReceiptDecodeError("receipt carries too many events");
  }
  expectType(top[4], "array", "receipt fee receipt");
  const epoch = decodeEpoch(top[5]);
  const intentCommitmentHex = expectBytes32(top[6], "receipt intent commitment");
  const events = eventNodes.children.map((node, index) => decodeEvent(node, index));
  return { outcome, epoch, intentCommitmentHex, events };
}

export function decodeTransactionReceiptBase64(value: string): DecodedTransactionReceipt {
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(value);
  } catch (error) {
    if (error instanceof TransactionReceiptDecodeError) throw error;
    throw new TransactionReceiptDecodeError("malformed base64 transaction receipt");
  }
  return decodeTransactionReceiptCbor(bytes);
}

/**
 * Verifies the durable receipt for the expected transaction id against the
 * expected V2 anchor identity. Fails closed on every mismatch class: a
 * fee-intent-only commit is never a full anchor success, a rejected or
 * non-committed outcome never verifies, and the exact V2 anchor event must
 * exist exactly once with the exact four text values.
 */
export function verifyDurableTransactionReceipt(
  expectedTransactionHex: string,
  expectedTemplate: ExpectedAnchorTemplate,
  expectedPayload: ExpectedAnchorEventPayload,
  receipt: DecodedTransactionReceipt,
): VerifiedAnchorEvidence {
  if (!/^[0-9a-f]{64}$/.test(expectedTransactionHex)) {
    throw new Error("expected transaction id must be 64 lowercase hex characters");
  }
  if (receipt.outcome === "FeeIntentCommit") {
    throw new VerificationFailure("fee_only_acceptance");
  }
  if (receipt.outcome !== "Commit") {
    throw new VerificationFailure("rejected_transaction");
  }

  const candidates: DecodedReceiptEvent[] = [];
  for (const event of receipt.events) {
    const hasV2Digest = event.metadata.some((entry) => entry.key === ANCHOR_EVENT_DIGEST_KEY_V2);
    if (
      event.templateAddressHex === expectedTemplate.templateAddressHex &&
      event.topic !== expectedTemplate.eventTopic
    ) {
      throw new VerificationFailure("wrong_event_topic");
    }
    if (
      event.topic === expectedTemplate.eventTopic &&
      event.templateAddressHex !== expectedTemplate.templateAddressHex
    ) {
      throw new VerificationFailure("wrong_event_template");
    }
    if (event.topic === expectedTemplate.eventTopic || hasV2Digest) {
      candidates.push(event);
    }
  }
  if (candidates.length === 0) {
    throw new VerificationFailure("missing_anchor_event");
  }
  if (candidates.length > 1) {
    throw new VerificationFailure("duplicate_anchor_events");
  }

  const candidate = candidates[0];
  if (candidate.templateAddressHex !== expectedTemplate.templateAddressHex) {
    throw new VerificationFailure("wrong_event_template");
  }
  if (candidate.topic !== expectedTemplate.eventTopic) {
    throw new VerificationFailure("wrong_event_topic");
  }
  if (candidate.metadata.length !== 4) {
    throw new VerificationFailure("unexpected_event_metadata");
  }

  const expected: [string, string][] = [
    [ANCHOR_EVENT_DIGEST_KEY_V2, expectedPayload.anchorDigestHex],
    ["network", expectedPayload.network],
    ["election_id", expectedPayload.electionId],
    ["public_summary", expectedPayload.publicSummary],
  ];
  for (const [key, value] of expected) {
    const entries = candidate.metadata.filter((entry) => entry.key === key);
    if (entries.length !== 1) {
      throw new VerificationFailure("malformed_anchor_event");
    }
    // Matching-event fields are strictly typed strings; nothing is normalized.
    if (typeof entries[0].value !== "string") {
      throw new VerificationFailure("malformed_anchor_event");
    }
    if (entries[0].value !== value) {
      throw new VerificationFailure(
        key === ANCHOR_EVENT_DIGEST_KEY_V2 ? "wrong_anchor_digest" : "malformed_anchor_event",
      );
    }
  }

  return {
    transactionIdHex: expectedTransactionHex,
    epoch: receipt.epoch,
    eventIndex: candidate.eventIndex,
  };
}

export function verifyDurableTransactionReceiptBase64(
  expectedTransactionHex: string,
  expectedTemplate: ExpectedAnchorTemplate,
  expectedPayload: ExpectedAnchorEventPayload,
  base64: string,
): VerifiedAnchorEvidence {
  return verifyDurableTransactionReceipt(
    expectedTransactionHex,
    expectedTemplate,
    expectedPayload,
    decodeTransactionReceiptBase64(base64),
  );
}
