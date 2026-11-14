// Private Ballot read-only Tari Ootle indexer proxy (Cloudflare Worker).
//
// Security model:
//  - GET/HEAD only; every other method is rejected before any upstream call.
//  - A fixed allowlist of read-only paths. Every other path is rejected. No
//    write path, no wallet endpoint, and no query string is ever forwarded.
//  - The upstream indexer URL is a server-side secret (worker env var). When
//    it is not configured the worker fails closed with 503.
//  - Responses are capped in size and time; the proxy never caches.
//  - CORS is allowed only for the exact origin configured server-side; with
//    no origin configured the worker serves no CORS header at all, so no
//    browser page can read its responses cross-origin.

const ALLOWED_RESULT_PATTERN = /^\/transactions\/([0-9a-f]{64})\/result$/;
const ALLOWED_RECEIPT_PATTERN = /^\/transaction-receipts\/([0-9a-zA-Z_.:-]{1,256})$/;
const ALLOWED_NETWORK_PATTERN = /^\/network$/;
const MAX_RESPONSE_BYTES = 512 * 1024;
const UPSTREAM_TIMEOUT_MS = 10000;

export function matchAllowedPath(pathname) {
  const result = ALLOWED_RESULT_PATTERN.exec(pathname);
  if (result) {
    return { kind: "result", transactionId: result[1] };
  }
  const receipt = ALLOWED_RECEIPT_PATTERN.exec(pathname);
  if (receipt) {
    return { kind: "receipt", objectKey: receipt[1] };
  }
  if (ALLOWED_NETWORK_PATTERN.test(pathname)) {
    return { kind: "network" };
  }
  return null;
}

export function buildUpstreamUrl(upstreamBase, match) {
  let base;
  try {
    base = new URL(upstreamBase);
  } catch {
    return null;
  }
  if (base.protocol !== "https:" && base.protocol !== "http:") {
    return null;
  }
  const target = new URL(base.toString());
  if (match.kind === "result") {
    target.pathname = `${base.pathname.replace(/\/$/, "")}/transactions/${match.transactionId}/result`;
  } else if (match.kind === "receipt") {
    target.pathname = `${base.pathname.replace(/\/$/, "")}/transaction-receipts/${match.objectKey}`;
  } else {
    target.pathname = `${base.pathname.replace(/\/$/, "")}/network`;
  }
  target.search = "";
  return target;
}

function corsHeaders(env) {
  const origin = env.ALLOWED_ORIGIN;
  if (typeof origin !== "string" || origin.length === 0) {
    return {};
  }
  return {
    "Access-Control-Allow-Origin": origin,
    Vary: "Origin",
  };
}

const NO_STORE = { "Cache-Control": "no-store" };

export async function handleRequest(request, env) {
  const cors = corsHeaders(env);
  const upstreamBase = env.INDEXER_UPSTREAM;
  if (typeof upstreamBase !== "string" || upstreamBase.length === 0) {
    return jsonResponse(
      503,
      { error: "the indexer proxy is not configured" },
      cors,
    );
  }
  const url = new URL(request.url);
  const match = matchAllowedPath(url.pathname);
  if (!match) {
    return jsonResponse(
      404,
      { error: "this path is not served by the indexer proxy" },
      cors,
    );
  }
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors });
  }
  if (request.method !== "GET" && request.method !== "HEAD") {
    return jsonResponse(405, { error: "only read-only requests are served" }, cors);
  }
  const upstream = buildUpstreamUrl(upstreamBase, match);
  if (!upstream) {
    return jsonResponse(503, { error: "the indexer proxy is misconfigured" }, cors);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
  try {
    const response = await fetch(upstream.toString(), {
      method: request.method === "HEAD" ? "GET" : request.method,
      headers: { Accept: "application/json" },
      signal: controller.signal,
    });
    if (request.method === "HEAD") {
      await response.body?.cancel().catch(() => {});
      return new Response(null, {
        status: response.status,
        headers: { "Content-Type": response.headers.get("Content-Type") ?? "application/json", ...NO_STORE, ...cors },
      });
    }
    const body = await readLimitedBody(response, MAX_RESPONSE_BYTES);
    if (body === null) {
      return jsonResponse(502, { error: "the indexer response exceeds the proxy size limit" }, cors);
    }
    return new Response(body, {
      status: response.status,
      headers: {
        "Content-Type": response.headers.get("Content-Type") ?? "application/json",
        ...NO_STORE,
        ...cors,
      },
    });
  } catch {
    return jsonResponse(502, { error: "the indexer could not be reached" }, cors);
  } finally {
    clearTimeout(timeout);
  }
}

/** Reads no more than limit bytes and actively cancels an oversized stream. */
export async function readLimitedBody(response, limit) {
  const advertised = response.headers.get("Content-Length");
  if (advertised !== null && (!/^\d+$/.test(advertised) || Number(advertised) > limit)) {
    await response.body?.cancel().catch(() => {});
    return null;
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error("upstream body chunk is not bytes");
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel("response limit exceeded");
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

function jsonResponse(status, body, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...NO_STORE,
      ...extraHeaders,
    },
  });
}

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
};
