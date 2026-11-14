import { cborDecodeStrict, CborError, type CborNode } from "./cbor.ts";

export type AnchorResultVariant = "accept" | "fee_only" | "reject";

export interface DecodedEventMetadataEntry {
  key: string;
  value: string;
}

export interface DecodedExecutionEvent {
  eventIndex: number;
  templateAddressHex: string;
  topic: string;
  metadata: DecodedEventMetadataEntry[];
}

export interface DecodedExecuteResult {
  transactionHashHex: string;
  epoch: number | null;
  resultVariant: AnchorResultVariant;
  events: DecodedExecutionEvent[];
}

export class ExecutionResultDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ExecutionResultDecodeError";
  }
}

function expectType(node: CborNode, type: CborNode["type"], what: string): CborNode {
  if (node.type !== type) {
    throw new ExecutionResultDecodeError(`expected ${what} to be ${type}`);
  }
  return node;
}

function expectArray(node: CborNode, length: number, what: string): CborNode[] {
  expectType(node, "array", what);
  if (node.value !== length) {
    throw new ExecutionResultDecodeError(
      `expected ${what} to have ${length} items`,
    );
  }
  return node.children;
}

function expectBytes32(node: CborNode, what: string): string {
  expectType(node, "bytes", what);
  const bytes = node.value as Uint8Array;
  if (bytes.length !== 32) {
    throw new ExecutionResultDecodeError(`expected ${what} to be 32 bytes`);
  }
  return toHex(bytes);
}

function expectText(node: CborNode, what: string): string {
  expectType(node, "text", what);
  return node.value as string;
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

const METADATA_TAG = 129;

function decodeMetadata(
  node: CborNode,
  bytes: Uint8Array,
): DecodedEventMetadataEntry[] {
  expectType(node, "tag", "event metadata");
  if (node.tag !== METADATA_TAG) {
    throw new ExecutionResultDecodeError(
      `expected event metadata tag ${METADATA_TAG}`,
    );
  }
  const map = node.children[0];
  expectType(map, "map", "event metadata map");
  const metadata: DecodedEventMetadataEntry[] = [];
  for (const entry of map.entries) {
    const key = expectText(entry.key, "event metadata key");
    let value: string;
    if (entry.value.type === "text") {
      value = entry.value.value as string;
    } else {
      value = toHex(bytes.subarray(entry.value.rawStart, entry.value.rawEnd));
    }
    metadata.push({ key, value });
  }
  return metadata;
}

function decodeTransactionResult(node: CborNode): AnchorResultVariant {
  expectType(node, "array", "transaction result");
  if (node.value !== 2 || node.children.length !== 2) {
    throw new ExecutionResultDecodeError("malformed transaction result");
  }
  const variant = node.children[0];
  expectType(variant, "uint", "transaction result variant");
  const fields = node.children[1];
  expectType(fields, "array", "transaction result fields");
  if (variant.value === 0) {
    if (fields.value !== 1) {
      throw new ExecutionResultDecodeError("malformed accept result");
    }
    return "accept";
  }
  if (variant.value === 1) {
    if (fields.value !== 2) {
      throw new ExecutionResultDecodeError("malformed fee-only result");
    }
    return "fee_only";
  }
  if (variant.value === 2) {
    if (fields.value !== 1) {
      throw new ExecutionResultDecodeError("malformed reject result");
    }
    return "reject";
  }
  throw new ExecutionResultDecodeError("unknown transaction result variant");
}

function decodeEvent(
  node: CborNode,
  eventIndex: number,
  bytes: Uint8Array,
): DecodedExecutionEvent {
  const fields = expectArray(node, 4, "event");
  const templateAddressHex = expectBytes32(fields[1], "event template address");
  const topic = expectText(fields[2], "event topic");
  const metadata = decodeMetadata(fields[3], bytes);
  return { eventIndex, templateAddressHex, topic, metadata };
}

function decodeEpoch(node: CborNode): number | null {
  if (node.type === "simple" && node.value === null) {
    return null;
  }
  expectType(node, "uint", "execution epoch");
  const value = node.value as number;
  if (!Number.isSafeInteger(value)) {
    throw new ExecutionResultDecodeError("execution epoch is out of range");
  }
  return value;
}

export function decodeExecuteResultCbor(bytes: Uint8Array): DecodedExecuteResult {
  let root: CborNode;
  try {
    root = cborDecodeStrict(bytes);
  } catch (error) {
    if (error instanceof CborError) {
      throw new ExecutionResultDecodeError(`malformed execution result: ${error.message}`);
    }
    throw error;
  }
  const top = expectArray(root, 5, "execute result");
  const finalize = expectArray(top[0], 6, "finalize result");
  const transactionHashHex = expectBytes32(finalize[0], "transaction hash");
  if (finalize[1].type !== "array") {
    throw new ExecutionResultDecodeError("expected events to be an array");
  }
  const events = finalize[1].children.map((node, index) =>
    decodeEvent(node, index, bytes),
  );
  const resultVariant = decodeTransactionResult(finalize[3]);
  const epoch = decodeEpoch(top[2]);
  return { transactionHashHex, epoch, resultVariant, events };
}

export function base64ToBytes(value: string): Uint8Array {
  const normalized = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new ExecutionResultDecodeError("malformed base64 execution result");
  }
  const binary = atob(normalized);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function decodeExecuteResultBase64(value: string): DecodedExecuteResult {
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(value);
  } catch {
    throw new ExecutionResultDecodeError("malformed base64 execution result");
  }
  return decodeExecuteResultCbor(bytes);
}

/**
 * Strictly narrows the object returned by Sapient after its published BOR
 * decoder has already expanded `execution_result`. This is deliberately not a
 * best-effort JSON mapper: only the pinned `ExecuteResult` fields needed for
 * the canonical verifier are accepted, and fee-only/reject variants remain
 * terminal failures.
 */
export function decodeExecuteResultJson(value: unknown): DecodedExecuteResult {
  const root = expectJsonRecord(value, "decoded execution result");
  const finalize = expectJsonRecord(root.finalize, "decoded finalize result");
  const transactionHashHex = expectJsonHex(finalize.transaction_hash, "decoded transaction hash");
  const eventsValue = finalize.events;
  if (!Array.isArray(eventsValue)) throw new ExecutionResultDecodeError("decoded events must be an array");
  const events = eventsValue.map((value, eventIndex) => {
    const event = expectJsonRecord(value, "decoded event");
    const templateAddressHex = expectJsonHex(event.template_address, "decoded event template address");
    const topic = expectJsonText(event.topic, "decoded event topic");
    const payload = expectJsonRecord(event.payload, "decoded event metadata");
    const metadata = Object.entries(payload).map(([key, entry]) => ({
      key,
      value: expectJsonText(entry, "decoded event metadata value"),
    }));
    return { eventIndex, templateAddressHex, topic, metadata };
  });
  const result = expectJsonRecord(finalize.result, "decoded transaction result");
  const variants = Object.keys(result);
  if (variants.length !== 1) throw new ExecutionResultDecodeError("decoded transaction result has conflicting variants");
  const resultVariant: AnchorResultVariant = variants[0] === "Accept"
    ? "accept"
    : variants[0] === "AcceptFeeRejectRest"
      ? "fee_only"
      : variants[0] === "Reject"
        ? "reject"
        : (() => { throw new ExecutionResultDecodeError("unknown decoded transaction result variant"); })();
  const epochValue = root.execute_epoch;
  const epoch = epochValue === null || epochValue === undefined
    ? null
    : typeof epochValue === "number" && Number.isSafeInteger(epochValue) && epochValue >= 0
      ? epochValue
      : (() => { throw new ExecutionResultDecodeError("decoded execution epoch is out of range"); })();
  return { transactionHashHex, epoch, resultVariant, events };
}

function expectJsonRecord(value: unknown, what: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ExecutionResultDecodeError(`expected ${what} to be an object`);
  }
  return value as Record<string, unknown>;
}

function expectJsonText(value: unknown, what: string): string {
  if (typeof value !== "string") throw new ExecutionResultDecodeError(`expected ${what} to be text`);
  return value;
}

function expectJsonHex(value: unknown, what: string): string {
  const text = expectJsonText(value, what);
  if (!/^[0-9a-f]{64}$/.test(text)) throw new ExecutionResultDecodeError(`expected ${what} to be 32 lowercase bytes`);
  return text;
}
