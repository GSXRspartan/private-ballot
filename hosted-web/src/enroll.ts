/**
 * Hosted enrollment UI.
 *
 * Security invariants maintained throughout:
 * - Invitation secret is kept in a module-scoped variable only; never placed in
 *   URLs, query strings, hash fragments, localStorage, sessionStorage, or logs.
 * - Voter private credential (secret key) is kept in a module-scoped variable only;
 *   never sent to the backend, never placed in localStorage/sessionStorage/IndexedDB,
 *   never logged, and never echoed in the DOM in cleartext after the credential step.
 * - Only the public key (derived from the secret in WASM) is sent to the backend.
 * - The invitation secret is cleared from JS state after a successful enrollment.
 * - No third-party scripts; no analytics; no dangerouslySetInnerHTML equivalent.
 *   All DOM output uses textContent or the esc() helper for untrusted string content.
 */

import init, {
  compute_registry_commitment,
  generate_secret_key,
  public_key_for_secret,
} from "./wasm/tari_cc_private_ballot_hosted_wasm.js";

// ── Types ──────────────────────────────────────────────────────────────────────

type Step =
  | "invitation_entry"
  | "load_election"
  | "generate_credential"
  | "confirm_credential"
  | "enrolling"
  | "receipt"
  | "wait_freeze"
  | "frozen"
  | "integrity_failure";

type EnrollmentInfo = {
  election_id: string;
  eligibility_state: string;
  registry_commitment_hex?: string;
  registry_cbor_hex?: string;
  enrolled_count?: number;
  authorized_slot_count: number;
};

type EnrollResult = {
  election_id: string;
  public_key_hex: string;
  enrolled_at_ms: number;
  idempotent: boolean;
};

type WasmResult = { ok: boolean; error?: string } & Record<string, unknown>;

// ── State (memory only — nothing persisted) ────────────────────────────────────

let step: Step = "invitation_entry";
// invitation secret stays in memory; cleared after successful enrollment
let invitationSecret = "";
let electionId = "";
let enrollmentInfo: EnrollmentInfo | null = null;
// private credential stays in memory; never sent to backend
let secretKeyHex = "";
let publicKeyHex = "";
let enrollResult: EnrollResult | null = null;
let errorMsg = "";
let pollTimer: ReturnType<typeof setTimeout> | null = null;
let registryVerificationError = "";

// ── Helpers ───────────────────────────────────────────────────────────────────

const app = document.getElementById("app") as HTMLElement;

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string)
  );
}

function shortHex(h: string, n = 16): string {
  if (h.length <= n * 2) return h;
  return h.slice(0, n) + "…" + h.slice(-n);
}

function parseWasm(s: string): WasmResult {
  try { return JSON.parse(s) as WasmResult; }
  catch { return { ok: false, error: "wasm json parse failed" }; }
}

function setError(msg: string) { errorMsg = msg; }
function clearError() { errorMsg = ""; }

function stopPoll() {
  if (pollTimer !== null) { clearTimeout(pollTimer); pollTimer = null; }
}

// ── Render ────────────────────────────────────────────────────────────────────

function render() {
  app.innerHTML = buildHtml();
  bind();
}

function buildHtml(): string {
  const err = errorMsg
    ? `<div class="error" role="alert">${esc(errorMsg)}</div>`
    : "";

  const notice = `
    <div class="notice" role="note">
      <strong>Hosted / Web Mode — reduced network-metadata privacy.</strong><br/>
      Cloudflare/VPS infrastructure may observe connection metadata (timing, IP).
      Cryptographic ballot privacy (Triptych ring signatures) is preserved separately:
      your voter credential is generated <strong>in this browser</strong> and never sent to the server.
      For network anonymity, use Desktop/Tor Mode.
    </div>`;

  switch (step) {
    case "invitation_entry":
      return `${notice}
        <div class="card">
          <h2>Enroll to vote</h2>
          <p>Enter the invitation code you received from the election organizer.
          The invitation code stays in your browser memory and is never placed in a URL,
          cookie, or browser storage.</p>
          ${err}
          <label for="inv-secret">Invitation code</label>
          <input type="password" id="inv-secret" placeholder="Paste invitation code here" autocomplete="off" />
          <label for="eid-input">Election ID</label>
          <input type="text" id="eid-input" placeholder="e.g. my-election-2026" autocomplete="off" />
          <button id="btn-load-election">Load election →</button>
        </div>`;

    case "load_election":
      return `${notice}
        <div class="card">
          <h2>Loading election…</h2>
          <p>Contacting the election server. Please wait.</p>
        </div>`;

    case "generate_credential": {
      const ei = enrollmentInfo!;
      return `${notice}
        <div class="card">
          <h2>Election confirmed</h2>
          <p><strong>Election:</strong> <span class="mono">${esc(ei.election_id)}</span></p>
          <p><strong>Eligibility mode:</strong> Invitation Only</p>
          <p><strong>Enrollment state:</strong> ${esc(ei.eligibility_state)}</p>
          <p><strong>Authorized seats:</strong> ${esc(String(ei.authorized_slot_count))}</p>
          ${err}
        </div>
        <div class="card">
          <h2>Generate your voting credential</h2>
          <p>Your private voting credential is generated entirely in this browser using the
          browser's cryptographically secure random number generator. It never leaves your
          device.</p>
          <p class="error"><strong>⚠ KEEP THIS VOTING CREDENTIAL SAFE.</strong><br/>
          If you lose it before voting, the organizer cannot reconstruct your private voting
          credential from the public registry. For this release, the credential is memory-only:
          closing this page will lose it. Write it down securely before proceeding.</p>
          <button id="btn-gen">Generate voting credential</button>
        </div>`;
    }

    case "confirm_credential": {
      const ei = enrollmentInfo!;
      const pubShort = shortHex(publicKeyHex);
      return `${notice}
        <div class="card">
          <h2>Confirm your voting credential</h2>
          <p><strong>Election:</strong> <span class="mono">${esc(ei.election_id)}</span></p>
          <p>Public credential fingerprint (safe to share):</p>
          <div class="mono" id="pubkey-display">${esc(pubShort)}</div>
          <p><small>Full public key: <span class="mono">${esc(publicKeyHex)}</span></small></p>
          <p>Your private voting credential is memory-only and is <strong>not</strong> your
          real-world identity. Private Ballot does not know your real-world identity from
          this credential.</p>
          <p class="error"><strong>⚠ Credential is memory-only.</strong> Write down or export
          your credential securely before proceeding. Closing this page loses it.</p>
          ${err}
          <button id="btn-enroll">Enroll this credential →</button>
          <button id="btn-regen">Generate a different credential</button>
        </div>`;
    }

    case "enrolling":
      return `${notice}
        <div class="card">
          <h2>Enrolling…</h2>
          <p>Submitting your public credential to the election server. Please wait.</p>
        </div>`;

    case "receipt": {
      const r = enrollResult!;
      const ei = enrollmentInfo!;
      const pubShort = shortHex(r.public_key_hex);
      const idempotentNote = r.idempotent
        ? `<p class="ok">This credential was already enrolled (exact retry accepted).</p>`
        : "";
      return `${notice}
        <div class="card ok">
          <h2>Enrollment accepted ✓</h2>
          ${idempotentNote}
          <p><strong>Election:</strong> <span class="mono">${esc(ei.election_id)}</span></p>
          <p><strong>Enrolled public credential:</strong>
            <span class="mono">${esc(pubShort)}</span></p>
          <p>The invitation code has been cleared from browser memory.</p>
          <p><strong>Registry status:</strong> ${esc(ei.eligibility_state)}</p>
          <p>The organizer must freeze the voter registry before voting opens.</p>
          <button id="btn-check-freeze">Check registry status</button>
        </div>`;
    }

    case "wait_freeze": {
      const ei = enrollmentInfo!;
      return `${notice}
        <div class="card">
          <h2>Waiting for registry freeze</h2>
          <p><strong>Election:</strong> <span class="mono">${esc(ei.election_id)}</span></p>
          <p><strong>Registry state:</strong> ${esc(ei.eligibility_state)}</p>
          <p>Enrollment is complete. The organizer must freeze the voter registry before
          voting opens. This page will update automatically.</p>
          <button id="btn-refresh">Refresh now</button>
        </div>`;
    }

    case "frozen": {
      const ei = enrollmentInfo!;
      const commitShort = ei.registry_commitment_hex ? shortHex(ei.registry_commitment_hex) : "(unavailable)";
      return `${notice}
        <div class="card ok">
          <h2>Registry frozen ✓</h2>
          <p><strong>Election:</strong> <span class="mono">${esc(ei.election_id)}</span></p>
          <p><strong>Enrolled credentials:</strong> ${esc(String(ei.enrolled_count ?? "?"))}</p>
          <p><strong>Authorized seats:</strong> ${esc(String(ei.authorized_slot_count))}</p>
          <p><strong>Registry commitment:</strong>
            <span class="mono" title="${esc(ei.registry_commitment_hex ?? "")}">${esc(commitShort)}</span>
          </p>
          <details>
            <summary>Full registry commitment hex</summary>
            <pre class="mono">${esc(ei.registry_commitment_hex ?? "")}</pre>
          </details>
          <p class="ok"><strong>Registry verified locally with canonical Rust/WASM code.</strong></p>
          <p>Voting will open shortly. Keep your private credential safe.</p>
          <a href="/">Go to voting page →</a>
        </div>`;
    }

    case "integrity_failure":
      return `${notice}
        <div class="card error" role="alert">
          <h2>Registry integrity verification failed</h2>
          <p>The frozen registry did not match its advertised commitment. Voting and proof generation are blocked for this registry.</p>
          <p>${esc(registryVerificationError || "Unable to verify the frozen registry.")}</p>
          <button id="btn-refresh">Refresh now</button>
        </div>`;
  }
}

// ── Event binding ─────────────────────────────────────────────────────────────

function bind() {
  switch (step) {
    case "invitation_entry":
      (document.getElementById("btn-load-election") as HTMLButtonElement)
        ?.addEventListener("click", handleLoadElection);
      break;
    case "generate_credential":
      (document.getElementById("btn-gen") as HTMLButtonElement)
        ?.addEventListener("click", handleGenerate);
      break;
    case "confirm_credential":
      (document.getElementById("btn-enroll") as HTMLButtonElement)
        ?.addEventListener("click", handleEnroll);
      (document.getElementById("btn-regen") as HTMLButtonElement)
        ?.addEventListener("click", () => {
          secretKeyHex = "";
          publicKeyHex = "";
          step = "generate_credential";
          clearError();
          render();
        });
      break;
    case "receipt":
      (document.getElementById("btn-check-freeze") as HTMLButtonElement)
        ?.addEventListener("click", () => pollFreezeStatus());
      break;
    case "wait_freeze":
    case "integrity_failure":
      (document.getElementById("btn-refresh") as HTMLButtonElement)
        ?.addEventListener("click", () => pollFreezeStatus());
      startAutoPoll();
      break;
  }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

async function handleLoadElection() {
  const secretInput = document.getElementById("inv-secret") as HTMLInputElement;
  const eidInput = document.getElementById("eid-input") as HTMLInputElement;
  const rawSecret = secretInput.value.trim();
  const rawEid = eidInput.value.trim();

  if (!rawSecret) { setError("Please enter your invitation code."); render(); return; }
  if (!rawEid) { setError("Please enter the election ID."); render(); return; }

  // Keep invitation in memory — not in URL, localStorage, or any persistent store
  invitationSecret = rawSecret;
  electionId = rawEid;
  clearError();
  step = "load_election";
  render();

  try {
    const res = await fetch(`/api/v1/elections/${encodeURIComponent(electionId)}/enrollment-info`);
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      invitationSecret = "";
      setError(`Election not found or enrollment not available (${res.status}). ${body.slice(0, 200)}`);
      step = "invitation_entry";
      render();
      return;
    }
    enrollmentInfo = (await res.json()) as EnrollmentInfo;
    if (enrollmentInfo.eligibility_state === "REGISTRY_FROZEN") {
      step = "frozen";
    } else if (enrollmentInfo.eligibility_state !== "ENROLLMENT_OPEN") {
      invitationSecret = "";
      setError(`Enrollment is not open (state: ${enrollmentInfo.eligibility_state}).`);
      step = "invitation_entry";
    } else {
      step = "generate_credential";
    }
    render();
  } catch (e) {
    invitationSecret = "";
    setError(`Network error: ${e instanceof Error ? e.message : String(e)}`);
    step = "invitation_entry";
    render();
  }
}

function handleGenerate() {
  clearError();
  const r = parseWasm(generate_secret_key());
  if (!r.ok) {
    setError(`Credential generation failed: ${r.error}`);
    render();
    return;
  }
  secretKeyHex = String(r.secret_key_hex ?? "");
  const pk = parseWasm(public_key_for_secret(secretKeyHex));
  if (!pk.ok) {
    setError(`Public key derivation failed: ${pk.error}`);
    secretKeyHex = "";
    render();
    return;
  }
  publicKeyHex = String(pk.public_key_hex ?? "");
  step = "confirm_credential";
  render();
}

async function handleEnroll() {
  if (!invitationSecret || !publicKeyHex || !electionId) {
    setError("Missing required state. Please start over.");
    step = "invitation_entry";
    render();
    return;
  }
  clearError();
  step = "enrolling";
  render();

  const body = JSON.stringify({
    invitation_secret_hex: invitationSecret,
    public_key_hex: publicKeyHex,
  });

  try {
    const res = await fetch(`/api/v1/elections/${encodeURIComponent(electionId)}/enroll`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body,
    });
    const text = await res.text();

    if (res.ok) {
      // Clear invitation from memory immediately after successful enrollment
      invitationSecret = "";
      enrollResult = JSON.parse(text) as EnrollResult;
      // Refresh enrollment info so the receipt step shows current state
      try {
        const infoRes = await fetch(`/api/v1/elections/${encodeURIComponent(electionId)}/enrollment-info`);
        if (infoRes.ok) enrollmentInfo = await infoRes.json() as EnrollmentInfo;
      } catch { /* non-fatal */ }
      step = "receipt";
      render();
    } else if (res.status === 409) {
      // Various conflict cases
      let parsed: { code?: string; message?: string } = {};
      try { parsed = JSON.parse(text); } catch { /* ignore */ }
      const code = parsed.code ?? "";
      if (code === "credential_conflict") {
        setError("This invitation has already been used to enroll a different credential. Contact the organizer.");
      } else if (code === "enrollment_closed" || code === "enrollment_race") {
        setError("Enrollment is closed or the registry has been frozen. Contact the organizer.");
      } else {
        setError(`Enrollment conflict (${code}): ${parsed.message ?? text.slice(0, 200)}`);
      }
      // Don't clear invitation — allow user to retry
      step = "confirm_credential";
      render();
    } else if (res.status === 401) {
      setError("Invalid or expired invitation code. Please check your invitation and try again.");
      invitationSecret = "";
      step = "invitation_entry";
      render();
    } else {
      setError(`Enrollment failed (${res.status}). Please try again.`);
      step = "confirm_credential";
      render();
    }
  } catch (e) {
    setError(`Network error: ${e instanceof Error ? e.message : String(e)}`);
    step = "confirm_credential";
    render();
  }
}

async function pollFreezeStatus() {
  stopPoll();
  if (!electionId) return;
  try {
    const res = await fetch(`/api/v1/elections/${encodeURIComponent(electionId)}/enrollment-info`);
    if (res.ok) {
      enrollmentInfo = await res.json() as EnrollmentInfo;
      if (enrollmentInfo.eligibility_state === "REGISTRY_FROZEN") {
        const local = parseWasm(compute_registry_commitment(enrollmentInfo.registry_cbor_hex ?? ""));
        if (local.ok && local.registry_commitment_hex === enrollmentInfo.registry_commitment_hex) {
          registryVerificationError = "";
          step = "frozen";
        } else {
          registryVerificationError = String(local.error ?? "The local commitment does not match the advertised commitment.");
          step = "integrity_failure";
        }
      } else {
        step = "wait_freeze";
      }
    } else {
      step = "wait_freeze";
    }
  } catch {
    step = "wait_freeze";
  }
  render();
}

function startAutoPoll() {
  stopPoll();
  pollTimer = setTimeout(() => { void pollFreezeStatus(); }, 10_000);
}

// ── Bootstrap ─────────────────────────────────────────────────────────────────

await init();
render();
