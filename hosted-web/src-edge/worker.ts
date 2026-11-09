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
 */

const ORIGIN_TOKEN_HEADER = "x-private-ballot-origin";

const SECURITY_HEADERS: ReadonlyArray<readonly [string, string]> = [
  [
    "content-security-policy",
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
  ],
  ["x-content-type-options", "nosniff"],
  ["referrer-policy", "strict-origin-when-cross-origin"],
  ["permissions-policy", "camera=(), microphone=(), geolocation=()"],
  // Staging is HTTPS-only (Cloudflare terminates TLS). Browsers accept
  // this on the workers.dev hostname and any staging custom hostname.
  ["strict-transport-security", "max-age=31536000; includeSubDomains"],
  // COOP/COEP deliberately omitted: the WASM proof generator is
  // single-threaded and needs no cross-origin isolation; requiring it
  // would only risk asset-loading regressions on older browsers.
];

interface Env {
  ASSETS: { fetch: (request: Request) => Promise<Response> };
  STAGING_ORIGIN: string;
  ORIGIN_TOKEN?: string;
}

function errorResponse(status: number, code: string): Response {
  return new Response(JSON.stringify({ code, message: code }), {
    status,
    headers: { "content-type": "application/json", "cache-control": "private, no-store" },
  });
}

function applySecurityHeaders(response: Response): Response {
  const headers = new Headers(response.headers);
  for (const [name, value] of SECURITY_HEADERS) {
    headers.set(name, value);
  }
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function isAdminPath(pathname: string): boolean {
  return pathname === "/api/v1/admin" || pathname.startsWith("/api/v1/admin/");
}

async function proxyApi(request: Request, env: Env, url: URL): Promise<Response> {
  const origin = env.STAGING_ORIGIN.replace(/\/$/, "");
  const target = `${origin}${url.pathname}${url.search}`;
  const headers = new Headers(request.headers);
  headers.delete(ORIGIN_TOKEN_HEADER);
  headers.delete("x-admin-token");
  if (env.ORIGIN_TOKEN) {
    headers.set(ORIGIN_TOKEN_HEADER, env.ORIGIN_TOKEN);
  }
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
  return applySecurityHeaders(response);
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
  return applySecurityHeaders(withCache);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (isAdminPath(url.pathname)) {
      return applySecurityHeaders(errorResponse(404, "not_found"));
    }
    if (url.pathname.startsWith("/api/")) {
      return proxyApi(request, env, url);
    }
    return handleAssets(request, env, url);
  },
};
