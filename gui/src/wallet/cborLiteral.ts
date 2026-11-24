export function utf8Bytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

export function encodeCborTextLiteral(value: string): string {
  const body = utf8Bytes(value);
  if (body.length < 24) {
    return toHex(new Uint8Array([0x60 + body.length, ...body]));
  }
  if (body.length <= 0xff) {
    return toHex(new Uint8Array([0x78, body.length, ...body]));
  }
  if (body.length <= 0xffff) {
    return toHex(
      new Uint8Array([0x79, body.length >> 8, body.length & 0xff, ...body]),
    );
  }
  const header = new Uint8Array(5);
  header[0] = 0x7a;
  new DataView(header.buffer).setUint32(1, body.length);
  return toHex(new Uint8Array([...header, ...body]));
}
