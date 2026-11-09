import init, {
  create_ballot_package,
  election_info,
  generate_secret_key,
  package_hash_hex,
  public_key_for_secret,
} from "./wasm/tari_cc_private_ballot_hosted_wasm.js";

type Pkg = {
  election_id: string;
  state: string;
  manifest_cbor_hex: string;
  registry_cbor_hex: string;
  candidate_cbor_hex: string;
  manifest_hash_hex: string;
  package_hash_hex: string;
  candidates: { id_hex: string; id_text: string; display_name: string }[];
};

type WasmResult = { ok: boolean; error?: string } & Record<string, unknown>;

function parseWasm(s: string): WasmResult {
  return JSON.parse(s) as WasmResult;
}

const app = document.getElementById("app") as HTMLElement;
let pkg: Pkg | null = null;
let secretHex = "";
let lastSubmission: { receipt_id: string; body: string } | null = null;

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string));
}

function render() {
  app.innerHTML = `
  <div class="notice" role="alert">
    <strong>Hosted / Web Mode - reduced network-metadata privacy.</strong><br/>
    Hosted/Web Mode provides easier access but <strong>reduced network-metadata privacy</strong> compared with
    Desktop/Tor Mode. Cloudflare/VPS infrastructure in the eventual deployment may observe connection metadata
    (timing, IP-derived data, request sizes). This mode is <strong>not anonymous</strong> and is not Tor-equivalent.
    Cryptographic ballot privacy (Triptych anonymous membership, nullifiers) is preserved separately from
    network anonymity: your voter secret and proof are created <strong>in this browser</strong> and never sent to the server.
    For network anonymity, use Desktop/Tor Mode.
  </div>
  <div class="card">
    <h2>1. Load election</h2>
    <input type="text" id="election-id" placeholder="election id" value="hosted-synthetic-001" />
    <button id="load">Load public package</button>
    <div id="election-info">${pkg ? "Loaded" : "Not loaded"}</div>
  </div>
  <div class="card">
    <h2>2. Voter credential (memory only)</h2>
    <p>Secret stays in memory for this session only. It is never put in a URL, never stored in localStorage,
    never sent to the backend, and never logged. Close the tab to discard it.</p>
    <button id="gen-secret">Generate new credential</button>
    <input type="password" id="secret" placeholder="voter secret hex (memory only)" autocomplete="off" />
    <button id="show-pubkey">Show public key</button>
    <div id="pubkey" class="mono"></div>
  </div>
  <div class="card">
    <h2>3. Ballot choice</h2>
    <div id="candidates">${pkg ? pkg.candidates.map((c) => `<label><input type="checkbox" value="${esc(c.id_hex)}" /> ${esc(c.display_name)} <span class="mono">${esc(c.id_text)}</span></label>`).join("<br/>") : "Load an election first"}</div>
    <button id="create">Create ballot + proof locally</button>
    <div id="created" class="mono"></div>
  </div>
  <div class="card">
    <h2>4. Review &amp; submit</h2>
    <p>Review the envelope hash and nullifier (public linking tag) before submitting. Only the canonical
    ballot package + receipt id are submitted.</p>
    <button id="submit" disabled>Submit ballot</button>
    <button id="retry" disabled>Retry exact same submission</button>
    <div id="receipt" class="mono"></div>
  </div>
  <div class="card">
    <h2>5. Receipt / results / archive</h2>
    <input type="text" id="receipt-id" placeholder="receipt id" />
    <button id="get-receipt">Get receipt</button>
    <button id="get-results">Get results</button>
    <button id="get-archive">Get archive info</button>
    <pre id="output" class="mono"></pre>
  </div>`;
  bind();
}

function bind() {
  document.getElementById("load")?.addEventListener("click", async () => {
    const id = (document.getElementById("election-id") as HTMLInputElement).value.trim();
    const res = await fetch(`/api/v1/elections/${encodeURIComponent(id)}/public-package`);
    if (!res.ok) { output(`load failed: ${res.status}`); return; }
    pkg = (await res.json()) as Pkg;
    // Verify package binding hash locally in WASM
    const local = parseWasm(package_hash_hex(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex));
    const info = parseWasm(election_info(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex));
    const infoEl = document.getElementById("election-info") as HTMLElement;
    const hashOk = local.package_hash_hex === pkg.package_hash_hex;
    infoEl.innerHTML = `State: ${esc(pkg.state)}<br/>Manifest: <span class="mono">${esc(pkg.manifest_hash_hex)}</span><br/>Package hash match: <span class="${hashOk ? "ok" : "error"}">${hashOk ? "YES" : "NO"}</span><br/>Election: ${esc(String(info.election_id_text ?? ""))} | Eligible: ${esc(String(info.eligible_voter_count ?? ""))} | Suite: ${esc(String(info.proof_suite_id ?? ""))}`;
    render();
  });
  document.getElementById("gen-secret")?.addEventListener("click", () => {
    const r = parseWasm(generate_secret_key());
    if (r.ok) { secretHex = String(r.secret_key_hex); (document.getElementById("secret") as HTMLInputElement).value = secretHex; output("credential generated (memory only)"); }
    else output(`generate failed: ${r.error}`);
  });
  (document.getElementById("secret") as HTMLInputElement)?.addEventListener("input", (e) => { secretHex = (e.target as HTMLInputElement).value.trim(); });
  document.getElementById("show-pubkey")?.addEventListener("click", () => {
    if (!secretHex) { output("no secret in memory"); return; }
    const r = parseWasm(public_key_for_secret(secretHex));
    (document.getElementById("pubkey") as HTMLElement).textContent = r.ok ? `pubkey: ${r.public_key_hex}` : `error: ${r.error}`;
  });
  document.getElementById("create")?.addEventListener("click", () => {
    if (!pkg) { output("load election first"); return; }
    const checked = Array.from(document.querySelectorAll<HTMLInputElement>('#candidates input[type="checkbox"]:checked')).map((el) => el.value);
    const r = parseWasm(create_ballot_package(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex, secretHex, JSON.stringify(checked)));
    if (!r.ok) { output(`create failed: ${r.error}`); return; }
    (document.getElementById("created") as HTMLElement).innerHTML = `envelope: <span class="mono">${esc(String(r.envelope_hash_hex))}</span><br/>nullifier: <span class="mono">${esc(String(r.nullifier_hex))}</span><br/>package: <span class="mono">${esc(String(r.package_cbor_hex).slice(0, 64))}...</span>`;
    const receiptId = crypto.randomUUID();
    lastSubmission = { receipt_id: receiptId, body: JSON.stringify({ receipt_id: receiptId, package_cbor_hex: r.package_cbor_hex, api_version: "v1" }) };
    (document.getElementById("submit") as HTMLButtonElement).disabled = false;
    (document.getElementById("retry") as HTMLButtonElement).disabled = false;
    output("ballot created and locally verified. Review then submit.");
  });
  document.getElementById("submit")?.addEventListener("click", async () => { await doSubmit(); });
  document.getElementById("retry")?.addEventListener("click", async () => { await doSubmit(); });
  document.getElementById("get-receipt")?.addEventListener("click", async () => {
    if (!pkg) return;
    const rid = (document.getElementById("receipt-id") as HTMLInputElement).value.trim();
    const res = await fetch(`/api/v1/elections/${encodeURIComponent(pkg.election_id)}/receipt/${encodeURIComponent(rid)}`);
    output(`${res.status}: ${await res.text()}`);
  });
  document.getElementById("get-results")?.addEventListener("click", async () => {
    if (!pkg) return;
    const res = await fetch(`/api/v1/elections/${encodeURIComponent(pkg.election_id)}/results`);
    output(`${res.status}: ${await res.text()}`);
  });
  document.getElementById("get-archive")?.addEventListener("click", async () => {
    if (!pkg) return;
    const res = await fetch(`/api/v1/elections/${encodeURIComponent(pkg.election_id)}/archive`);
    output(`${res.status}: ${(await res.text()).slice(0, 2000)}`);
  });
}

async function doSubmit() {
  if (!pkg || !lastSubmission) return;
  const el = document.getElementById("receipt") as HTMLElement;
  const res = await fetch(`/api/v1/elections/${encodeURIComponent(pkg.election_id)}/ballots`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: lastSubmission.body,
  });
  const text = await res.text();
  el.innerHTML = `${res.status} ${esc(text)}`;
  (document.getElementById("receipt-id") as HTMLInputElement).value = lastSubmission.receipt_id;
}

function output(s: string) {
  const el = document.getElementById("output");
  if (el) el.textContent = s;
}

await init();
render();
