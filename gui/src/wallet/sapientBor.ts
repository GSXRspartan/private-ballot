/**
 * TS port of the pinned Ootle BOR (tari_bor, rev 9f03f90) value expansion that
 * the Sapient wallet applies to a finalized transaction's `execution_result`
 * before it reaches this verifier.
 *
 * The expansion follows the pinned minicbor derive shapes:
 * - structs decode positionally into objects with snake_case field names in
 *   declaration order (ExecuteResult, FinalizeResult, Event);
 * - enums decode as `{ Variant: fields }` (TransactionResult);
 * - event metadata is the tag-129 (`BinaryTag::Metadata`) map whose values are
 *   arbitrary raw CBOR, so unrelated engine/fee events can legally carry
 *   numbers (`std.vault.pay_fee.amount`) and those types are preserved.
 *
 * Any value that is not needed by the canonical verifier is expanded with a
 * total generic mapper; nothing here normalizes arbitrary metadata into
 * strings.
 */
import { cborDecodeStrict, type CborNode } from "./cbor.ts";

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

function expectArrayFields(node: CborNode, what: string): CborNode[] {
  if (node.type !== "array") {
    throw new Error(`expected ${what} to be a BOR array`);
  }
  return node.children;
}

function expectText(node: CborNode, what: string): string {
  if (node.type !== "text") {
    throw new Error(`expected ${what} to be a BOR text string`);
  }
  return node.value as string;
}

const METADATA_TAG = 129;

function expandMetadata(node: CborNode, bytes: Uint8Array): Record<string, unknown> {
  if (node.type !== "tag" || node.tag !== METADATA_TAG) {
    throw new Error("expected event metadata tag 129");
  }
  const map = node.children[0];
  if (map.type !== "map") {
    throw new Error("expected event metadata map");
  }
  const payload: Record<string, unknown> = {};
  for (const entry of map.entries) {
    payload[expectText(entry.key, "event metadata key")] = expandValue(entry.value, bytes);
  }
  return payload;
}

function rawSlice(node: CborNode, bytes: Uint8Array): Uint8Array {
  return bytes.subarray(node.rawStart, node.rawEnd);
}

/** Total generic expansion of any BOR/CBOR value with its type preserved. */
function expandValue(node: CborNode, bytes: Uint8Array): unknown {
  switch (node.type) {
    case "uint":
    case "negint":
      return node.value;
    case "bytes":
      return (node.value as Uint8Array).slice();
    case "text":
      return node.value;
    case "array":
      return node.children.map((child) => expandValue(child, bytes));
    case "map": {
      const out: Record<string, unknown> = {};
      for (const entry of node.entries) {
        const key = entry.key.type === "text"
          ? entry.key.value as string
          : `cbor:${toHex(rawSlice(entry.key, bytes))}`;
        out[key] = expandValue(entry.value, bytes);
      }
      return out;
    }
    case "tag":
      return { tag: node.tag, value: expandValue(node.children[0], bytes) };
    case "simple":
    case "float":
      return node.value;
  }
}

export interface SapientEventShape {
  substate_id: unknown;
  template_address: string;
  topic: string;
  payload: Record<string, unknown>;
}

function expandEvent(node: CborNode, bytes: Uint8Array, eventIndex: number): SapientEventShape {
  const fields = expectArrayFields(node, "decoded event");
  if (fields.length !== 4) {
    throw new Error(`expected decoded event ${eventIndex} to have 4 fields`);
  }
  if (fields[1].type !== "bytes" || (fields[1].value as Uint8Array).length !== 32) {
    throw new Error(`expected decoded event ${eventIndex} template address to be 32 bytes`);
  }
  return {
    substate_id: expandValue(fields[0], bytes),
    template_address: toHex(fields[1].value as Uint8Array),
    topic: expectText(fields[2], `decoded event ${eventIndex} topic`),
    payload: expandMetadata(fields[3], bytes),
  };
}

const RESULT_VARIANTS = ["Accept", "AcceptFeeRejectRest", "Reject"] as const;

function expandTransactionResult(node: CborNode, bytes: Uint8Array): Record<string, unknown> {
  const fields = expectArrayFields(node, "decoded transaction result");
  if (fields.length !== 2) {
    throw new Error("expected decoded transaction result to have variant and fields");
  }
  const index = fields[0];
  if (index.type !== "uint" || typeof index.value !== "number") {
    throw new Error("expected decoded transaction result variant index");
  }
  const variant = RESULT_VARIANTS[index.value];
  if (variant === undefined) {
    throw new Error("unknown decoded transaction result variant");
  }
  const variantFields = expectArrayFields(fields[1], "decoded transaction result fields");
  return { [variant]: variantFields.map((field) => expandValue(field, bytes)) };
}

export interface SapientFinalizeShape {
  transaction_hash: string;
  events: SapientEventShape[];
  logs: unknown[];
  result: Record<string, unknown>;
  fee_receipt: unknown;
  total_fees_required: unknown;
}

function expandFinalize(node: CborNode, bytes: Uint8Array): SapientFinalizeShape {
  const fields = expectArrayFields(node, "decoded finalize result");
  if (fields.length !== 6) {
    throw new Error("expected decoded finalize result to have 6 fields");
  }
  if (fields[0].type !== "bytes" || (fields[0].value as Uint8Array).length !== 32) {
    throw new Error("expected decoded transaction hash to be 32 bytes");
  }
  if (fields[1].type !== "array") {
    throw new Error("expected decoded events to be an array");
  }
  return {
    transaction_hash: toHex(fields[0].value as Uint8Array),
    events: fields[1].children.map((event, index) => expandEvent(event, bytes, index)),
    logs: expandValue(fields[2], bytes) as unknown[],
    result: expandTransactionResult(fields[3], bytes),
    fee_receipt: expandValue(fields[4], bytes),
    total_fees_required: expandValue(fields[5], bytes),
  };
}

/**
 * Expands the raw CBOR `execution_result` bytes exactly as the pinned Ootle
 * BOR decoder used by Sapient does, producing the JSON object that the
 * verifier's `decodeExecuteResultJson` accepts. Metadata value types are
 * preserved throughout.
 */
export function decodeExecuteResultJsonFromBor(bytes: Uint8Array): Record<string, unknown> {
  const root = cborDecodeStrict(bytes);
  const top = expectArrayFields(root, "decoded execute result");
  if (top.length !== 5) {
    throw new Error("expected decoded execute result to have 5 fields");
  }
  return {
    finalize: expandFinalize(top[0], bytes),
    execution_time: expandValue(top[1], bytes),
    execute_epoch: expandValue(top[2], bytes),
    wasm_execution_points: expandValue(top[3], bytes),
    native_execution_points: expandValue(top[4], bytes),
  };
}
