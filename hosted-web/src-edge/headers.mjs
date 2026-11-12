/**
 * Private Ballot staging edge - pure header helpers.
 *
 * Plain ESM (no TypeScript) so Node's built-in test runner can exercise
 * the exact code the Worker ships. Header policy is defense in depth;
 * the backend remains authoritative.
 *
 *  - Client-supplied origin/admin credential headers are ALWAYS stripped
 *    before proxying (the browser must never be able to claim them).
 *  - The Worker-side origin token is injected from Worker config only.
 *  - The organizer capability header is forwarded untouched: it is an
 *    election-scoped browser credential, not a server trust anchor.
 */

export const ORIGIN_TOKEN_HEADER = "x-private-ballot-origin";
export const ADMIN_TOKEN_HEADER = "x-admin-token";
export const ORGANIZER_TOKEN_HEADER = "x-private-ballot-organizer";

/** Global admin plane paths are blocked at the edge, before the backend. */
export function isAdminPath(pathname) {
  return pathname === "/api/v1/admin" || pathname.startsWith("/api/v1/admin/");
}

/**
 * Build upstream request headers for the staging backend: strip any
 * client-supplied origin/admin credential headers, then inject the
 * Worker-configured origin token (if one is configured).
 */
export function buildUpstreamHeaders(requestHeaders, originToken) {
  const headers = new Headers(requestHeaders);
  headers.delete(ORIGIN_TOKEN_HEADER);
  headers.delete(ADMIN_TOKEN_HEADER);
  if (originToken) {
    headers.set(ORIGIN_TOKEN_HEADER, originToken);
  }
  return headers;
}
