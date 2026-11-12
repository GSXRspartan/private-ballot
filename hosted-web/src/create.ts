/**
 * Hosted organizer: create a self-service election.
 *
 * Security invariants maintained throughout:
 * - The organizer secret is generated locally with crypto.getRandomValues
 *   (32 bytes) and kept in module memory only. It is never persisted,
 *   never placed in a URL, and never logged.
 * - The secret is submitted exactly once, in the create-election request
 *   body over the organizer namespace; afterwards the server stores only a
 *   verifier. The page switches in-place to the manage console so the
 *   secret never lands in a URL or browser storage.
 * - Downloading the access file (which contains the secret) is an explicit
 *   user action inside the manage console.
 */

import { hostedShell } from "./shell";
import {
  ACCESS_SCHEMA,
  esc,
  generateOrganizerSecret,
  isValidElectionId,
  startManage,
} from "./organizer";

type CreateResult = {
  election_id: string;
  eligibility_state: string;
  authorized_slot_count: number;
  proof_suite_id: string;
};

const app = document.getElementById("app") as HTMLElement;

let step: "form" | "submitting" | "success" = "form";
let errorMsg = "";
let createdSecret = "";
let createdElectionId = "";

function render() {
  const err = errorMsg ? `<div class="error" role="alert">${esc(errorMsg)}</div>` : "";

  if (step === "submitting") {
    app.innerHTML = hostedShell(`
      ${err}
      <div class="card">
        <h2>Creating election…</h2>
        <p>Contacting the election server. Please wait.</p>
      </div>
    `, "create");
    return;
  }

  if (step === "success") {
    startManage({ service_url: "", election_id: createdElectionId, organizer_secret_hex: createdSecret });
    return;
  }

  app.innerHTML = hostedShell(`
    <div class="notice" role="note">
      <strong>Self-service organizer.</strong> You control this election with a secret
      credential generated in your browser. The server stores only a verifier of the
      secret; if you lose the secret, you lose organizer access to the election.
    </div>
    ${err}
    <div class="card">
      <h2>Create a new election</h2>
      <label for="eid-input">Election ID</label>
      <input type="text" id="eid-input" placeholder="e.g. club-vote-2026-11" autocomplete="off" />
      <small>1..128 characters of A-Z a-z 0-9 . _ -</small>

      <label for="options-input">Ballot options (one per line)</label>
      <textarea id="options-input" rows="4" placeholder="Yes&#10;No&#10;Abstain"></textarea>
      <small>Up to 256 options; duplicates are rejected.</small>

      <label for="slots-input">Authorized voter seats</label>
      <input type="number" id="slots-input" min="1" value="10" autocomplete="off" />

      <label for="min-approvals">Minimum approvals per ballot</label>
      <input type="number" id="min-approvals" min="1" value="1" autocomplete="off" />

      <label for="max-approvals">Maximum approvals per ballot</label>
      <input type="number" id="max-approvals" min="1" value="1" autocomplete="off" />

      <label>
        <input type="checkbox" id="allow-abstention" checked />
        Allow explicit abstention
      </label>

      <label for="revision-input">Governance source revision (optional)</label>
      <input type="text" id="revision-input" placeholder="e.g. club-charter §3.1" autocomplete="off" />

      <button id="btn-create">Create election</button>
      <p><small>By creating an election you agree to act as its organizer: you issue
      invitations, freeze the voter registry, and close/finalize the election.</small></p>
      <p><small>Access schema: <span class="mono">${esc(ACCESS_SCHEMA)}</span></small></p>
    </div>
  `, "create");

  (document.getElementById("btn-create") as HTMLButtonElement).addEventListener("click", handleCreate);
}

function readOptions(): string[] {
  const raw = (document.getElementById("options-input") as HTMLTextAreaElement).value;
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

async function handleCreate() {
  errorMsg = "";
  const eid = (document.getElementById("eid-input") as HTMLInputElement).value.trim();
  const options = readOptions();
  const slots = Number((document.getElementById("slots-input") as HTMLInputElement).value);
  const minApprovals = Number((document.getElementById("min-approvals") as HTMLInputElement).value);
  const maxApprovals = Number((document.getElementById("max-approvals") as HTMLInputElement).value);
  const allowAbstention = (document.getElementById("allow-abstention") as HTMLInputElement).checked;
  const revision = (document.getElementById("revision-input") as HTMLInputElement).value.trim();

  if (!isValidElectionId(eid)) {
    errorMsg = "Election ID must be 1..128 characters of A-Z a-z 0-9 . _ -";
    render();
    return;
  }
  if (options.length === 0) {
    errorMsg = "Provide at least one ballot option.";
    render();
    return;
  }

  // 32 random bytes from the browser CSPRNG; memory-only, never persisted.
  const secret = generateOrganizerSecret();
  createdSecret = secret;
  createdElectionId = eid;

  step = "submitting";
  render();

  const body: Record<string, unknown> = {
    election_id: eid,
    options,
    organizer_secret_hex: secret,
    min_approvals: Number.isFinite(minApprovals) ? minApprovals : undefined,
    max_approvals: Number.isFinite(maxApprovals) ? maxApprovals : undefined,
    allow_abstention: allowAbstention,
    authorized_slot_count: Number.isFinite(slots) ? slots : undefined,
  };
  if (revision) body["governance_revision"] = revision;

  let result: CreateResult | null = null;
  let status = 0;
  try {
    const res = await fetch("/api/v1/organizer/elections", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    status = res.status;
    if (res.ok) result = (await res.json()) as CreateResult;
  } catch {
    status = 0;
  }

  if (result && status === 201) {
    createdSecret = secret;
    createdElectionId = String(result.election_id ?? eid);
    step = "success";
    render();
    return;
  }

  step = "form";
  if (status === 409) errorMsg = "An election with this ID already exists.";
  else if (status === 400) errorMsg = "The server rejected the election definition (check the ID, options, and limits).";
  else if (status === 0) errorMsg = "Network error: could not reach the election server.";
  else errorMsg = `Election creation failed (${status}).`;
  render();
}

render();
