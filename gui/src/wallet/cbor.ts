export interface CborNode {
  type: "uint" | "negint" | "bytes" | "text" | "array" | "map" | "tag" | "simple" | "float";
  value: number | bigint | string | boolean | null;
  rawStart: number;
  rawEnd: number;
  children: CborNode[];
  entries: Array<{ key: CborNode; value: CborNode }>;
  tag: number | null;
}

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}

const MAX_DEPTH = 64;
const MAX_ITEMS = 65536;

function readHead(bytes: Uint8Array, offset: number): {
  major: number;
  short: number;
  value: number | bigint;
  headerEnd: number;
} {
  if (offset >= bytes.length) {
    throw new CborError("unexpected end of input");
  }
  const initial = bytes[offset];
  const major = initial >> 5;
  const short = initial & 0x1f;
  let value: number | bigint = short;
  let headerEnd = offset + 1;
  if (short < 24) {
    return { major, short, value, headerEnd };
  }
  if (short === 31) {
    throw new CborError("indefinite-length items are not accepted");
  }
  if (short > 27) {
    throw new CborError("reserved CBOR additional info");
  }
  const length = 1 << (short - 24);
  if (offset + 1 + length > bytes.length) {
    throw new CborError("unexpected end of input in item header");
  }
  let big = 0n;
  for (let i = 0; i < length; i++) {
    big = (big << 8n) | BigInt(bytes[offset + 1 + i]);
  }
  if (big <= BigInt(Number.MAX_SAFE_INTEGER)) {
    value = Number(big);
  } else {
    value = big;
  }
  headerEnd = offset + 1 + length;
  return { major, short, value, headerEnd };
}

function decodeAt(bytes: Uint8Array, offset: number, depth: number): CborNode {
  if (depth > MAX_DEPTH) {
    throw new CborError("nesting too deep");
  }
  const head = readHead(bytes, offset);
  const rawEndBase = head.headerEnd;
  if (head.major === 0) {
    return {
      type: "uint",
      value: head.value,
      rawStart: offset,
      rawEnd: rawEndBase,
      children: [],
      entries: [],
      tag: null,
    };
  }
  if (head.major === 1) {
    return {
      type: "negint",
      value: head.value,
      rawStart: offset,
      rawEnd: rawEndBase,
      children: [],
      entries: [],
      tag: null,
    };
  }
  if (head.major === 2 || head.major === 3) {
    const length = Number(head.value);
    const rawEnd = rawEndBase + length;
    if (rawEnd > bytes.length) {
      throw new CborError("unexpected end of input in item body");
    }
    const body = bytes.subarray(rawEndBase, rawEnd);
    return {
      type: head.major === 2 ? "bytes" : "text",
      value:
        head.major === 2
          ? body
          : new TextDecoder("utf-8", { fatal: true }).decode(body),
      rawStart: offset,
      rawEnd,
      children: [],
      entries: [],
      tag: null,
    };
  }
  if (head.major === 4) {
    const count = Number(head.value);
    if (count > MAX_ITEMS) {
      throw new CborError("too many array items");
    }
    const children: CborNode[] = [];
    let next = rawEndBase;
    for (let i = 0; i < count; i++) {
      const child = decodeAt(bytes, next, depth + 1);
      children.push(child);
      next = child.rawEnd;
    }
    return {
      type: "array",
      value: count,
      rawStart: offset,
      rawEnd: next,
      children,
      entries: [],
      tag: null,
    };
  }
  if (head.major === 5) {
    const count = Number(head.value);
    if (count > MAX_ITEMS) {
      throw new CborError("too many map entries");
    }
    const entries: Array<{ key: CborNode; value: CborNode }> = [];
    let next = rawEndBase;
    for (let i = 0; i < count; i++) {
      const key = decodeAt(bytes, next, depth + 1);
      const value = decodeAt(bytes, key.rawEnd, depth + 1);
      entries.push({ key, value });
      next = value.rawEnd;
    }
    return {
      type: "map",
      value: count,
      rawStart: offset,
      rawEnd: next,
      children: [],
      entries,
      tag: null,
    };
  }
  if (head.major === 6) {
    const inner = decodeAt(bytes, rawEndBase, depth + 1);
    return {
      type: "tag",
      value: Number(head.value),
      rawStart: offset,
      rawEnd: inner.rawEnd,
      children: [inner],
      entries: [],
      tag: Number(head.value),
    };
  }
  if (head.major === 7) {
    if (head.short <= 23 || head.short === 24) {
      const simpleNames: Record<number, string | boolean | null> = {
        20: false,
        21: true,
        22: null,
      };
      const short = head.short === 24 ? Number(head.value) : head.short;
      if (short in simpleNames) {
        return {
          type: "simple",
          value: simpleNames[short],
          rawStart: offset,
          rawEnd: rawEndBase,
          children: [],
          entries: [],
          tag: null,
        };
      }
      return {
        type: "simple",
        value: short,
        rawStart: offset,
        rawEnd: rawEndBase,
        children: [],
        entries: [],
        tag: null,
      };
    }
    if (head.short === 26 || head.short === 27) {
      const length = 1 << (head.short - 24);
      if (rawEndBase > bytes.length) {
        throw new CborError("unexpected end of input in float");
      }
      const view = new DataView(
        bytes.buffer,
        bytes.byteOffset + offset + 1,
        length,
      );
      const float =
        head.short === 26
          ? view.getFloat32(0)
          : view.getFloat64(0);
      return {
        type: "float",
        value: float,
        rawStart: offset,
        rawEnd: rawEndBase,
        children: [],
        entries: [],
        tag: null,
      };
    }
    throw new CborError("unsupported CBOR simple value");
  }
  throw new CborError("unsupported CBOR major type");
}

export function cborDecodeStrict(bytes: Uint8Array): CborNode {
  if (bytes.length === 0) {
    throw new CborError("empty input");
  }
  const node = decodeAt(bytes, 0, 0);
  if (node.rawEnd !== bytes.length) {
    throw new CborError("trailing bytes after CBOR value");
  }
  return node;
}
