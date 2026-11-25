/**
 * Private Ballot staging edge — Cloudflare Worker (Stage 3).
 *
 * STAGING ONLY. Not deployed until a human runs `npx wrangler deploy`.
 *
 * Responsibilities (defense in depth; the backend is authoritative):
 *  1. Block `/api/v1/admin` and `/api/v1/admin/*` with 404 before anything
 *     reaches the Tunnel/backend (the public backend plane has no admin
 *     routes at all, so a missed edge rule still fails closed).
 *  2. Proxy `/api/*` to the staging Tunnel ingress, stripping any
 *     client-supplied origin headers and injecting the Worker-side
 *     `x-private-ballot-origin` token. Browser JavaScript never knows the
 *     token. Direct hits to the ingress hostname fail closed on the
 *     backend when PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN is configured.
 *  3. Serve static assets from `dist/` (vite output, zero runtime deps)
 *     with security headers and cache policy: hashed assets immutable,
 *     HTML revalidated, API responses never cached.
 *
 * No analytics, no trackers, no remote scripts. No voter secret, wallet
 * credential, or admin token ever touches this Worker.
 *  */

import { buildUpstreamHeaders, isAdminPath } from "./headers.mjs";

const UNIVERSE_ORIGIN = "https://universe.tari.mw";
const DAPP_DOCUMENT_PATHS = new Set([
  "/",
  "/index.html",
  "/manage",
  "/manage.html",
  "/create",
  "/create.html",
  "/enroll",
  "/enroll.html",
  "/vote",
  "/vote.html",
  "/archive",
  "/archive.html",
  "/evidence",
  "/evidence.html",
  "/guide",
  "/guide.html",
  "/anchor",
  "/anchor.html",
  "/about",
  "/about.html",
  "/settings",
  "/settings.html",
]);

const BASE_CSP =
  "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'";

const SECURITY_HEADERS_NO_FRAME: ReadonlyArray<readonly [string, string]> = [
  [`content-security-policy`, `${BASE_CSP}; frame-ancestors 'none'`],
  ["x-content-type-options", "nosniff"],
  ["referrer-policy", "strict-origin-when-cross-origin"],
  ["permissions-policy", "camera=(), microphone=(), geolocation=()"],
  ["strict-transport-security", "max-age=31536000; includeSubDomains"],
  // COOP and COEP are applied only to embeddable dApp documents below;
  // the single-threaded WASM generator needs no cross-origin isolation.
];

const SECURITY_HEADERS_WITH_UNIVERSE_FRAME: ReadonlyArray<readonly [string, string]> = [
  [`content-security-policy`, `${BASE_CSP}; frame-ancestors 'self' ${UNIVERSE_ORIGIN}`],
  ["cross-origin-embedder-policy", "require-corp"],
  ["cross-origin-resource-policy", "cross-origin"],
  ["x-content-type-options", "nosniff"],
  ["referrer-policy", "strict-origin-when-cross-origin"],
  ["permissions-policy", "camera=(), microphone=(), geolocation=()"],
  ["strict-transport-security", "max-age=31536000; includeSubDomains"],
];

function isDappRoute(pathname: string): boolean {
  // Both forms are accepted because Workers Static Assets may redirect the
  // explicit .html form to the extensionless canonical document path.
  return DAPP_DOCUMENT_PATHS.has(pathname);
}

interface Env {
  ASSETS: { fetch: (request: Request) => Promise<Response> };
  STAGING_ORIGIN: string;
  ORIGIN_TOKEN?: string;
  /** Separate, read-only Worker service binding; never the organizer proxy. */
  INDEXER_PROXY?: { fetch: (request: Request) => Promise<Response> };
}

const INDEXER_ROUTE_PREFIX = "/chain";

function errorResponse(status: number, code: string): Response {
  return new Response(JSON.stringify({ code, message: code }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "private, no-store" },
  });
}

function applySecurityHeaders(response: Response, headers: ReadonlyArray<readonly [string, string]>): Response {
  const headersObj = new Headers(response.headers);
  for (const [name, value] of headers) {
    headersObj.set(name, value);
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: headersObj });
}

function chooseSecurityHeaders(pathname: string): ReadonlyArray<readonly [string, string]> {
  if (isDappRoute(pathname)) {
    return SECURITY_HEADERS_WITH_UNIVERSE_FRAME;
  }
  return SECURITY_HEADERS_NO_FRAME;
}

async function proxyApi(request: Request, env: Env, url: URL): Promise<Response> {
  const origin = env.STAGING_ORIGIN.replace(/\/$/, "");
  const target = `${origin}${url.pathname}${url.search}`;
  const headers = buildUpstreamHeaders(request.headers, env.ORIGIN_TOKEN);
  const method = request.method.toUpperCase();
  const init: RequestInit = { method, headers };
  if (method !== "GET" && method !== "HEAD") {
    init.body = request.body;
  }
  const upstream = await fetch(target, init);
  const responseHeaders = new Headers(upstream.headers);
  responseHeaders.set("cache-control", "private, no-store");
  const response = new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers: responseHeaders,
  });
  return applySecurityHeaders(response, chooseSecurityHeaders(url.pathname));
}

/** Routes a narrow same-origin read-only path to the dedicated chain Worker. */
export async function proxyIndexer(request: Request, env: Env, url: URL): Promise<Response> {
  if (!env.INDEXER_PROXY) return applySecurityHeaders(errorResponse(503, "indexer_proxy_unavailable"), SECURITY_HEADERS_NO_FRAME);
  if ((request.method !== "GET" && request.method !== "HEAD") || url.search) {
    return applySecurityHeaders(errorResponse(404, "not_found"), SECURITY_HEADERS_NO_FRAME);
  }
  const suffix = url.pathname.slice(INDEXER_ROUTE_PREFIX.length);
  if (!suffix.startsWith("/")) return applySecurityHeaders(errorResponse(404, "not_found"), SECURITY_HEADERS_NO_FRAME);
  const target = new URL(request.url);
  target.pathname = suffix;
  target.search = "";
  const upstream = await env.INDEXER_PROXY.fetch(new Request(target, {
    method: request.method,
    headers: { Accept: "application/json" },
  }));
  const headers = new Headers(upstream.headers);
  headers.set("cache-control", "no-store");
  return applySecurityHeaders(new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  }), SECURITY_HEADERS_NO_FRAME);
}

async function handleAssets(request: Request, env: Env, url: URL): Promise<Response> {
  const response = await env.ASSETS.fetch(request);
  const headers = new Headers(response.headers);
  if (url.pathname.startsWith("/assets/")) {
    headers.set("cache-control", "public, max-age=31536000, immutable");
  } else if (response.headers.get("content-type")?.includes("text/html")) {
    headers.set("cache-control", "no-cache");
  }
  const withCache = new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
  return applySecurityHeaders(withCache, chooseSecurityHeaders(url.pathname));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (isAdminPath(url.pathname)) {
      return applySecurityHeaders(errorResponse(404, "not_found"), chooseSecurityHeaders(url.pathname));
    }
    if (url.pathname === INDEXER_ROUTE_PREFIX || url.pathname.startsWith(`${INDEXER_ROUTE_PREFIX}/`)) {
      return proxyIndexer(request, env, url);
    }
    if (url.pathname.startsWith("/api/")) {
      return proxyApi(request, env, url);
    }
    return handleAssets(request, env, url);
  },
};
