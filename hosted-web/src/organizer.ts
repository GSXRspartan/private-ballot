/**
 * Shared self-service organizer support.
 *
 * Security invariants maintained throughout:
 * - The organizer capability secret is generated in the browser with
 *   crypto.getRandomValues (32 bytes) and lives in module-scoped memory only.
 *   It is never placed in URLs, query strings, hash fragments,
 *   localStorage, sessionStorage, IndexedDB, cookies, or logs.
 * - The secret is sent only in the `x-private-ballot-organizer` request
 *   header, never in the request body or URL.
 * - An optional access file lets an organizer move the credential between
 *   their own devices; downloading it is always an explicit user action
 *   and the file is clearly marked as containing a secret.
 * - All DOM output uses esc() for untrusted string content; no innerHTML
 *   of untrusted data.
 * - Irreversible lifecycle actions require window.confirm().
 */

import { hostedShell } from "./shell";

export const ACCESS_SCHEMA = "private-ballot-organizer-access-v1";

export type OrganizerAccess = {
  service_url: string;
  election_id: string;
  organizer_secret_hex: string;
  created_at?: string;
};

type ElectionView = {
  election_id: string;
  eligibility_state: string;
  election_state: string | null;
  authorized_slot_count: number;
  total_slots: number;
  consumed_slots: number;
  available_slots: number;
  enrolled_count: number;
  registry_commitment_hex: string | null;
  proof_suite_id: string;
  created_at_ms: number;
  candidates: { id_hex: string; id_text: string; display_name: string }[];
  finalized_archive_hash_hex: string | null;
  finalized_anchor_digest_hex: string | null;
  finalized_public_summary_json: string | null;
  transport_binding_status: string;
};

export type ManagedFinalizedElectionIdentity = {
  electionId: string;
  archiveHashHex: string;
  anchorDigestHex: string;
  publicSummary: string;
};

type SlotView = {
  slot_id: string;
  consumed: boolean;
  invitation_id: string | null;
  invitation_state: string | null;
};

type InvitationIssued = {
  invitation_id: string;
  slot_id: string;
  invitation_secret_hex: string;
};

type OrganizerResponse = {
  status: number;
  ok: boolean;
  json: Record<string, unknown> | null;
};

const app = document.getElementById("app") as HTMLElement;

export function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string)
  );
}

export function shortHex(h: string, n = 16): string {
  if (h.length <= n * 2) return h;
  return h.slice(0, n) + "…" + h.slice(-n);
}

export function isValidElectionId(id: string): boolean {
  return /^[A-Za-z0-9._-]{1,128}$/.test(id);
}

export function isValidOrganizerSecret(secret: string): boolean {
  return /^[0-9a-f]{64}$/.test(secret);
}

export function generateOrganizerSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function accessToDownload(access: OrganizerAccess): string {
  return JSON.stringify(
    {
      schema: ACCESS_SCHEMA,
      service_url: access.service_url,
      election_id: access.election_id,
      organizer_secret_hex: access.organizer_secret_hex,
      created_at: access.created_at ?? new Date().toISOString(),
    },
    null,
    2
  );
}

export function parseAccessFile(text: string): OrganizerAccess | string {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return "The access file is not valid JSON.";
  }
  if (parsed["schema"] !== ACCESS_SCHEMA) {
    return `The access file schema is not ${ACCESS_SCHEMA}.`;
  }
  const serviceUrl = typeof parsed["service_url"] === "string" ? parsed["service_url"].trim() : "";
  const electionId = typeof parsed["election_id"] === "string" ? parsed["election_id"].trim() : "";
  const secret = typeof parsed["organizer_secret_hex"] === "string" ? parsed["organizer_secret_hex"].trim().toLowerCase() : "";
  if (!isValidElectionId(electionId)) return "The access file contains an invalid election ID.";
  if (!isValidOrganizerSecret(secret)) return "The access file contains an invalid organizer secret.";
  return { service_url: serviceUrl, election_id: electionId, organizer_secret_hex: secret };
}

function normalizeAccess(
  serviceUrl: string,
  electionId: string,
  secret: string
): OrganizerAccess | string {
  const trimmedUrl = serviceUrl.trim().replace(/\/+$/, "");
  if (trimmedUrl && !/^https:\/\//.test(trimmedUrl)) {
    return "Service URL must be empty (this site) or an https:// URL.";
  }
  if (!isValidElectionId(electionId.trim())) {
    return "Election ID must be 1..128 characters of A-Z a-z 0-9 . _ -";
  }
  if (!isValidOrganizerSecret(secret.trim().toLowerCase())) {
    return "Organizer secret must be exactly 64 hex characters (32 bytes).";
  }
  return {
    service_url: trimmedUrl,
    election_id: electionId.trim(),
    organizer_secret_hex: secret.trim().toLowerCase(),
  };
}

async function organizerFetch(
  access: OrganizerAccess,
  method: string,
  path: string,
  body?: Record<string, unknown>
): Promise<OrganizerResponse> {
  const base = access.service_url === "" ? "" : access.service_url;
  const headers: Record<string, string> = {
    "x-private-ballot-organizer": access.organizer_secret_hex,
  };
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers["content-type"] = "application/json";
    init.body = JSON.stringify(body);
  }
  let res: Response;
  try {
    res = await fetch(`${base}${path}`, init);
  } catch (e) {
    return { status: 0, ok: false, json: { code: "network_error", message: e instanceof Error ? e.message : String(e) } };
  }
  let json: Record<string, unknown> | null = null;
  try {
    json = (await res.json()) as Record<string, unknown>;
  } catch {
    json = null;
  }
  return { status: res.status, ok: res.ok, json };
}

function apiPath(access: OrganizerAccess, suffix: string): string {
  return `/api/v1/organizer/elections/${encodeURIComponent(access.election_id)}${suffix}`;
}

// ---------- Organizer console (shared by Create and Manage pages) ----------

type ConsoleState = {
  access: OrganizerAccess;
  election: ElectionView | null;
  slots: SlotView[];
  lastInvitation: InvitationIssued | null;
  errorMsg: string;
  infoMsg: string;
  busy: boolean;
};

let cs: ConsoleState | null = null;
let manageExtensionRenderer: ((container: HTMLElement, identity: ManagedFinalizedElectionIdentity) => void) | null = null;

/** Lets the hosted Manage entry point attach optional browser-only tooling. */
export function setManageExtensionRenderer(
  renderer: ((container: HTMLElement, identity: ManagedFinalizedElectionIdentity) => void) | null,
): void {
  manageExtensionRenderer = renderer;
}

function clearTransientSecret() {
  if (cs) cs.lastInvitation = null;
}

function setError(msg: string) {
  if (cs) { cs.errorMsg = msg; cs.infoMsg = ""; }
}

function renderConsole() {
  if (!cs) return;
  const err = cs.errorMsg ? `<div class="error" role="alert">${esc(cs.errorMsg)}</div>` : "";
  const info = cs.infoMsg ? `<div class="ok" role="status">${esc(cs.infoMsg)}</div>` : "";
  const invitationBlock = cs.lastInvitation
    ? `<div class="card error">
        <h2>New invitation issued (shown once)</h2>
        <p>Give this invitation code to the voter. It is shown only once and cannot
        be recovered; if it is lost, void it and issue a replacement.</p>
        <div class="mono" id="invitation-display">${esc(cs.lastInvitation.invitation_secret_hex)}</div>
        <button id="btn-copy-invitation">Copy invitation code</button>
        <button id="btn-dismiss-invitation">I have delivered it</button>
      </div>`
    : "";

  const election = cs.election;
  if (!election) {
    app.innerHTML = hostedShell(`${err}<div class="card"><h2>Manage election</h2><p>Loading…</p></div>`, "manage");
    bindConsole();
    return;
  }

  const commitShort = election.registry_commitment_hex ? shortHex(election.registry_commitment_hex) : "";
  const candidates = election.candidates
    .map((c) => `<li><span class="mono">${esc(c.display_name)}</span></li>`)
    .join("");
  const slotRows = cs.slots
    .map((s) => {
      const inv = s.invitation_id
        ? `<span class="mono">${esc(shortHex(s.invitation_id, 8))}</span> (${esc(s.invitation_state ?? "?")})
           ${s.invitation_state === "ACTIVE" ? `<button data-void="${esc(s.invitation_id)}">Void</button>` : ""}`
        : "—";
      const issue = s.consumed || s.invitation_state === "ACTIVE"
        ? ""
        : `<button data-issue="${esc(s.slot_id)}">Issue for this seat</button>`;
      return `<tr>
        <td><span class="mono">${esc(shortHex(s.slot_id, 8))}</span></td>
        <td>${s.consumed ? "enrolled" : "open"}</td>
        <td>${inv}</td>
        <td>${issue}</td>
      </tr>`;
    })
    .join("");

  const actions: string[] = [];
  if (election.eligibility_state === "DRAFT") {
    actions.push(`<button id="btn-open-enrollment">Open enrollment</button>`);
  }
  if (election.eligibility_state === "ENROLLMENT_OPEN") {
    actions.push(`<button id="btn-issue-auto">Issue invitation (next open seat)</button>`);
    actions.push(`<button id="btn-freeze" class="danger">Freeze voter registry…</button>`);
  }
  if (election.eligibility_state === "REGISTRY_FROZEN" && election.election_state === null) {
    actions.push(`<button id="btn-open-voting" class="danger">Open voting…</button>`);
  }
  if (election.election_state === "open") {
    actions.push(`<button id="btn-close" class="danger">Close voting…</button>`);
  }
  if (election.election_state === "closed" && election.transport_binding_status === "verified") {
    actions.push(`<button id="btn-finalize" class="danger">Finalize and publish archive…</button>`);
  }
  if (election.election_state === "finalized") {
    actions.push(`<a class="btn-link btn-primary-link" href="/archive.html">View archive</a>`);
  }

  app.innerHTML = hostedShell(`
    ${err}
    ${info}
    ${invitationBlock}
    <div class="card">
      <h2>Election: <span class="mono">${esc(election.election_id)}</span></h2>
      <p><strong>Registry state:</strong> ${esc(election.eligibility_state)}
        ${election.election_state ? ` · <strong>Voting state:</strong> ${esc(election.election_state)}` : ""}</p>
      <p><strong>Seats:</strong> ${esc(String(election.total_slots))} total,
        ${esc(String(election.consumed_slots))} enrolled,
        ${esc(String(election.available_slots))} open</p>
      ${election.registry_commitment_hex
        ? `<p><strong>Registry commitment:</strong>
             <span class="mono" title="${esc(election.registry_commitment_hex)}">${esc(commitShort)}</span></p>`
        : ""}
      <p><strong>Ballot options:</strong></p>
      <ul>${candidates}</ul>
      <details>
        <summary>Download organizer access file</summary>
        <p>The access file contains your organizer secret in plaintext. Store it
        like a password; anyone with the file controls this election.</p>
        <button id="btn-download-access">Download access file</button>
      </details>
      ${election.election_state
        ? `<details>
             <summary>Set up Desktop organizer workspace</summary>
             <p>Download the signed bootstrap and import it in Desktop. It is bound to this exact V2 election and contains public election data only; it does not contain your organizer secret.</p>
             <button id="btn-download-desktop-bootstrap">Download Desktop bootstrap</button>
           </details>`
        : ""}
      ${election.election_state === "open"
        ? `<details>
             <summary>Authorize Desktop transport descriptor</summary>
             <p>Choose the public descriptor-request file exported by Desktop for this exact election. Hosted authenticates you with the existing organizer session and returns a signed response file for Desktop. This file is not an organizer credential.</p>
             <label class="btn-link" for="desktop-descriptor-request-file">Import Desktop descriptor request</label>
             <input id="desktop-descriptor-request-file" type="file" accept="application/cbor,.cbor" hidden />
           </details>`
        : ""}
      <p><small>Organizer secret and issued invitations live only in this browser
      tab's memory and are never stored or logged.</small></p>
    </div>
    <div class="card">
      <h2>Voter seats</h2>
      <table class="mono-table">
        <thead><tr><th>Seat</th><th>Status</th><th>Invitation</th><th>Action</th></tr></thead>
        <tbody>${slotRows}</tbody>
      </table>
      <p>${esc(String(election.enrolled_count))} credential(s) enrolled.</p>
    </div>
    <div class="card">
      <h2>Lifecycle</h2>
      <div class="action-row">${actions.join("\n")}</div>
      ${election.election_state === "closed" ? bindingHandoffMarkup(election) : ""}
      <p><small>Freezing locks the voter registry permanently. Closing stops new
      ballots. Finalizing publishes the archive. These actions are irreversible.</small></p>
    </div>
    ${election.election_state === "finalized" ? '<section id="browser-anchor-root"></section>' : ""}
  `, "manage");
  bindConsole();
  const extensionRoot = document.getElementById("browser-anchor-root");
  if (extensionRoot && manageExtensionRenderer) {
    const archiveHash = election.finalized_archive_hash_hex;
    const anchorDigest = election.finalized_anchor_digest_hex;
    const publicSummary = election.finalized_public_summary_json;
    if (typeof archiveHash !== "string" || !/^[0-9a-f]{64}$/.test(archiveHash) ||
        typeof anchorDigest !== "string" || !/^[0-9a-f]{64}$/.test(anchorDigest) ||
        typeof publicSummary !== "string") {
      extensionRoot.textContent = "The native finalized anchor identity is unavailable. Browser anchoring is blocked.";
    } else {
      manageExtensionRenderer(extensionRoot, {
        electionId: election.election_id,
        archiveHashHex: archiveHash,
        anchorDigestHex: anchorDigest,
        publicSummary,
      });
    }
  }
}

function bindingHandoffMarkup(election: ElectionView): string {
  if (election.transport_binding_status === "verified") {
    return `<div class="card ok">
      <h3>Desktop binding verified</h3>
      <p>The Hosted service has authenticated the Desktop-produced transport binding for this exact election. You can now finalize and publish the archive.</p>
    </div>`;
  }
  return `<div class="card">
    <h3>Desktop binding required before finalization</h3>
    <p>Download the election-bound request, open it in Desktop after Desktop has finalized and verified the transport history, then import the Desktop handoff file here. The organizer secret is never put in either handoff file, and no binding bytes need to be copied or pasted.</p>
    <div class="action-row">
      <button id="btn-download-binding-request">1. Download Desktop request</button>
      <label class="btn-link" for="desktop-binding-handoff-file">2. Import Desktop handoff</label>
      <input id="desktop-binding-handoff-file" type="file" accept="application/json,.json" hidden />
    </div>
    <p><small>Finalization remains blocked until Hosted independently verifies the imported binding against its closed election.</small></p>
  </div>`;
}

function bindConsole() {
  if (!cs) return;

  const copyBtn = document.getElementById("btn-copy-invitation") as HTMLButtonElement | null;
  copyBtn?.addEventListener("click", () => {
    if (!cs?.lastInvitation) return;
    navigator.clipboard.writeText(cs.lastInvitation.invitation_secret_hex).catch(() => {});
  });
  const dismissBtn = document.getElementById("btn-dismiss-invitation") as HTMLButtonElement | null;
  dismissBtn?.addEventListener("click", () => {
    clearTransientSecret();
    renderConsole();
  });

  const accessBtn = document.getElementById("btn-download-access") as HTMLButtonElement | null;
  accessBtn?.addEventListener("click", () => {
    if (!cs) return;
    const blob = new Blob([accessToDownload(cs.access)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `private-ballot-organizer-${cs.access.election_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  });

  const openEnrollBtn = document.getElementById("btn-open-enrollment") as HTMLButtonElement | null;
  openEnrollBtn?.addEventListener("click", lifecycleAction("open-enrollment", false, () => "Enrollment opened."));
  const freezeBtn = document.getElementById("btn-freeze") as HTMLButtonElement | null;
  freezeBtn?.addEventListener("click", lifecycleAction("freeze", true, () => "Voter registry frozen."));
  const openVoteBtn = document.getElementById("btn-open-voting") as HTMLButtonElement | null;
  openVoteBtn?.addEventListener("click", lifecycleAction("open-voting", true, () => "Voting is open."));
  const bootstrapBtn = document.getElementById("btn-download-desktop-bootstrap") as HTMLButtonElement | null;
  bootstrapBtn?.addEventListener("click", () => { void downloadDesktopBootstrap(); });
  const descriptorRequestInput = document.getElementById("desktop-descriptor-request-file") as HTMLInputElement | null;
  descriptorRequestInput?.addEventListener("change", () => {
    const file = descriptorRequestInput.files?.[0];
    if (file) void uploadDesktopDescriptorRequest(file);
  });
  const closeBtn = document.getElementById("btn-close") as HTMLButtonElement | null;
  closeBtn?.addEventListener("click", lifecycleAction("close", true, () => "Voting closed."));
  const finalizeBtn = document.getElementById("btn-finalize") as HTMLButtonElement | null;
  finalizeBtn?.addEventListener("click", lifecycleAction("finalize", true, () => "Election finalized; archive published."));

  const bindingRequestBtn = document.getElementById("btn-download-binding-request") as HTMLButtonElement | null;
  bindingRequestBtn?.addEventListener("click", () => { void downloadBindingRequest(); });
  const bindingHandoffInput = document.getElementById("desktop-binding-handoff-file") as HTMLInputElement | null;
  bindingHandoffInput?.addEventListener("change", () => {
    const file = bindingHandoffInput.files?.[0];
    if (file) void importDesktopBindingHandoff(file);
  });

  const autoBtn = document.getElementById("btn-issue-auto") as HTMLButtonElement | null;
  autoBtn?.addEventListener("click", () => issueInvitation(null));
  for (const el of Array.from(document.querySelectorAll("button[data-issue]"))) {
    el.addEventListener("click", () => issueInvitation((el as HTMLElement).dataset.issue ?? null));
  }
  for (const el of Array.from(document.querySelectorAll("button[data-void]"))) {
    el.addEventListener("click", () => voidInvitation((el as HTMLElement).dataset.void ?? ""));
  }
}

async function downloadDesktopBootstrap() {
  if (!cs || cs.busy) return;
  cs.busy = true;
  cs.errorMsg = "";
  cs.infoMsg = "";
  renderConsole();
  const access = cs.access;
  const base = access.service_url === "" ? "" : access.service_url;
  let response: Response;
  try {
    response = await fetch(`${base}${apiPath(access, "/desktop-bootstrap")}`, {
      method: "GET",
      headers: { "x-private-ballot-organizer": access.organizer_secret_hex },
    });
  } catch {
    cs.busy = false;
    setError("Could not reach Hosted to download the Desktop bootstrap.");
    renderConsole();
    return;
  }
  cs.busy = false;
  if (!response.ok) {
    if (response.status === 401) setError("Organizer credential rejected (401).");
    else if (response.status === 409) setError("The Desktop bootstrap is available only after this V2 election has been opened.");
    else setError(`Could not download the Desktop bootstrap (${response.status}).`);
    renderConsole();
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `private-ballot-${access.election_id}.organizer-bootstrap.cbor`;
  a.click();
  URL.revokeObjectURL(url);
  cs.infoMsg = "Signed Desktop organizer bootstrap downloaded. Import it in Desktop before provisioning transport.";
  renderConsole();
}

async function uploadDesktopDescriptorRequest(file: File) {
  if (!cs || cs.busy) return;
  // Mirrors the Hosted route's global bounded body limit before reading the
  // file. The canonical artifact remains opaque to browser code.
  if (file.size === 0 || file.size > 64 * 1024) {
    setError("The Desktop descriptor request must be a non-empty file no larger than 64 KiB.");
    renderConsole();
    return;
  }
  cs.busy = true;
  cs.errorMsg = "";
  cs.infoMsg = "";
  renderConsole();
  const access = cs.access;
  const base = access.service_url === "" ? "" : access.service_url;
  let response: Response;
  try {
    response = await fetch(`${base}${apiPath(access, "/descriptor-issuance")}`, {
      method: "POST",
      headers: {
        "content-type": "application/cbor",
        "x-private-ballot-organizer": access.organizer_secret_hex,
      },
      body: await file.arrayBuffer(),
    });
  } catch {
    cs.busy = false;
    setError("Could not reach Hosted to authorize the Desktop descriptor request.");
    renderConsole();
    return;
  }
  cs.busy = false;
  if (!response.ok) {
    if (response.status === 401) setError("Organizer credential rejected (401).");
    else if (response.status === 409) setError("The descriptor request does not match this open V2 election, its environment, or a prior request ID.");
    else setError(`Desktop descriptor request rejected (${response.status}).`);
    renderConsole();
    return;
  }
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `private-ballot-${access.election_id}.descriptor-response.cbor`;
  a.click();
  URL.revokeObjectURL(url);
  cs.infoMsg = "Signed descriptor response downloaded. Import it in the same Desktop organizer workspace that exported the request.";
  renderConsole();
}

async function downloadBindingRequest() {
  if (!cs || cs.busy) return;
  cs.busy = true;
  cs.errorMsg = "";
  cs.infoMsg = "";
  renderConsole();
  const access = cs.access;
  const res = await organizerFetch(access, "GET", apiPath(access, "/binding-handoff"));
  cs.busy = false;
  if (!res.ok || !res.json) {
    if (res.status === 401) setError("Organizer credential rejected (401).");
    else if (res.status === 409) setError("The binding request is only available after voting is closed and before finalization.");
    else setError(`Could not download the Desktop binding request (${res.status}).`);
    renderConsole();
    return;
  }
  const blob = new Blob([JSON.stringify(res.json, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `private-ballot-${access.election_id}.hosted-binding-request.json`;
  a.click();
  URL.revokeObjectURL(url);
  cs.infoMsg = "Desktop binding request downloaded. In Desktop, select it after the transport history is finalized and verified.";
  renderConsole();
}

async function importDesktopBindingHandoff(file: File) {
  if (!cs || cs.busy) return;
  let handoff: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(await file.text());
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
    handoff = parsed as Record<string, unknown>;
  } catch {
    setError("The selected Desktop binding handoff is not valid JSON.");
    renderConsole();
    return;
  }
  cs.busy = true;
  cs.errorMsg = "";
  cs.infoMsg = "";
  renderConsole();
  const res = await organizerFetch(cs.access, "POST", apiPath(cs.access, "/transport-binding"), handoff);
  cs.busy = false;
  if (res.ok) {
    cs.infoMsg = "Desktop binding accepted and independently verified. You can now finalize the election.";
  } else if (res.status === 401) {
    setError("Organizer credential rejected (401).");
  } else {
    const code = typeof res.json?.["code"] === "string" ? res.json["code"] : "";
    setError(`Desktop binding handoff rejected (${code || res.status}). The election identity, state, and binding provenance must all match.`);
  }
  await refreshConsole();
}

async function refreshConsole() {
  if (!cs) return;
  const access = cs.access;
  const res = await organizerFetch(access, "GET", apiPath(access, ""));
  if (res.status === 200 && res.json) {
    cs.election = res.json as unknown as ElectionView;
    const slotsRes = await organizerFetch(access, "GET", apiPath(access, "/slots"));
    cs.slots = slotsRes.ok && Array.isArray(slotsRes.json)
      ? (slotsRes.json as unknown as SlotView[])
      : [];
  } else if (res.status === 401) {
    setError("Organizer credential rejected for this election (401).");
  } else if (res.status === 404) {
    setError("Election not found for this credential.");
  } else {
    setError(`Failed to load election (${res.status}).`);
  }
  renderConsole();
}

function lifecycleAction(suffix: string, needsConfirm: boolean, successMsg: () => string) {
  return async () => {
    if (!cs || cs.busy) return;
    if (needsConfirm && !window.confirm(`Run "${suffix}" now? This action is irreversible.`)) return;
    clearTransientSecret();
    cs.busy = true;
    cs.errorMsg = "";
    cs.infoMsg = "";
    renderConsole();
    const res = await organizerFetch(cs.access, "POST", apiPath(cs.access, `/${suffix}`));
    cs.busy = false;
    if (res.ok) {
      cs.infoMsg = successMsg();
    } else {
      const code = typeof res.json?.["code"] === "string" ? res.json["code"] : "";
      if (res.status === 401) setError("Organizer credential rejected (401).");
      else if (res.status === 409) setError(`Rejected for the current state (${code || res.status}).`);
      else setError(`Action failed (${res.status}).`);
    }
    await refreshConsole();
  };
}

async function issueInvitation(slotId: string | null) {
  if (!cs || cs.busy) return;
  clearTransientSecret();
  cs.busy = true;
  cs.errorMsg = "";
  cs.infoMsg = "";
  renderConsole();
  const body = slotId ? { slot_id: slotId } : {};
  const res = await organizerFetch(cs.access, "POST", apiPath(cs.access, "/invitations"), body);
  cs.busy = false;
  if (res.status === 201 && res.json) {
    cs.lastInvitation = {
      invitation_id: String(res.json["invitation_id"] ?? ""),
      slot_id: String(res.json["slot_id"] ?? ""),
      invitation_secret_hex: String(res.json["invitation_secret_hex"] ?? ""),
    };
  } else if (res.status === 401) {
    setError("Organizer credential rejected (401).");
  } else {
    setError(`Could not issue an invitation (${res.status}).`);
  }
  await refreshConsole();
}

async function voidInvitation(invitationId: string) {
  if (!cs || cs.busy || !invitationId) return;
  clearTransientSecret();
  cs.busy = true;
  cs.errorMsg = "";
  cs.infoMsg = "";
  renderConsole();
  const res = await organizerFetch(
    cs.access,
    "POST",
    apiPath(cs.access, `/invitations/${encodeURIComponent(invitationId)}/void`)
  );
  cs.busy = false;
  if (res.ok) {
    cs.infoMsg = "Invitation voided; the seat can be reissued.";
  } else if (res.status === 401) {
    setError("Organizer credential rejected (401).");
  } else {
    setError(`Could not void the invitation (${res.status}).`);
  }
  await refreshConsole();
}

// ---------- Credential entry (used by the Manage page) ----------

export function renderCredentialEntry(
  onSubmit: (access: OrganizerAccess) => void,
  notice: string
): void {
  app.innerHTML = hostedShell(`
    ${notice}
    <div class="card">
      <h2>Open your election console</h2>
      <p>Provide the organizer credential you received when the election was created
      (or import your saved access file). The secret stays in this browser tab's
      memory only; it is never stored, logged, or placed in a URL.</p>
      <div class="error" id="cred-error" hidden role="alert"></div>
      <label for="access-file">Access file (optional)</label>
      <input type="file" id="access-file" accept="application/json,.json" />
      <p><strong>— or —</strong></p>
      <label for="eid-input">Election ID</label>
      <input type="text" id="eid-input" placeholder="e.g. my-election-2026" autocomplete="off" />
      <label for="service-input">Service URL (leave empty for this site)</label>
      <input type="text" id="service-input" placeholder="https://…" autocomplete="off" />
      <label for="secret-input">Organizer secret (64 hex characters)</label>
      <input type="password" id="secret-input" placeholder="Paste organizer secret here" autocomplete="off" />
      <button id="btn-open-console">Open console</button>
    </div>
  `, "manage");

  const errBox = document.getElementById("cred-error") as HTMLElement;
  const fileInput = document.getElementById("access-file") as HTMLInputElement;
  const eidInput = document.getElementById("eid-input") as HTMLInputElement;
  const serviceInput = document.getElementById("service-input") as HTMLInputElement;
  const secretInput = document.getElementById("secret-input") as HTMLInputElement;

  const showErr = (msg: string) => {
    errBox.textContent = msg;
    errBox.hidden = false;
  };

  let fileAccess: OrganizerAccess | null = null;
  fileInput.addEventListener("change", async () => {
    const file = fileInput.files?.[0];
    if (!file) return;
    const parsed = parseAccessFile(await file.text());
    if (typeof parsed === "string") {
      fileAccess = null;
      showErr(parsed);
      return;
    }
    fileAccess = parsed;
    eidInput.value = parsed.election_id;
    serviceInput.value = parsed.service_url;
    secretInput.value = parsed.organizer_secret_hex;
    errBox.hidden = true;
  });

  (document.getElementById("btn-open-console") as HTMLButtonElement).addEventListener("click", () => {
    const access = normalizeAccess(serviceInput.value, eidInput.value, secretInput.value);
    if (typeof access === "string") {
      showErr(access);
      return;
    }
    void fileAccess;
    onSubmit(access);
  });
}

// ---------- Shared boot for create/manage pages ----------

export function startManage(access: OrganizerAccess): void {
  cs = {
    access,
    election: null,
    slots: [],
    lastInvitation: null,
    errorMsg: "",
    infoMsg: "",
    busy: false,
  };
  void refreshConsole();
}
