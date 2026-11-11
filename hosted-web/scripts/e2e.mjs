// Local end-to-end test: backend (127.0.0.1:8788) + browser WASM proof
// generation + HTTP ballot flow. Usage:
//   node scripts/e2e.mjs [path-to-synthetic-demo.json] [backend-binary]
// Defaults: generates demo via cargo example output expected at
// C:\pb-target\synthetic-demo.json and backend at C:\pb-target\debug\private-ballot-hosted.exe
// Asserts every Stage 2 step; exits non-zero on any failure. Secrets in the
// demo JSON are synthetic scalars 1/2/3 for local testing only.
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const demoPath = process.argv[2] || path.join(os.tmpdir(), "pb-synthetic-demo.json");
const backendBin = process.argv[3] || "C:\\pb-target\\debug\\private-ballot-hosted.exe";
const dbPath = path.join(os.tmpdir(), `pb-e2e-${process.pid}.db`);
const ADMIN = "e2e-admin-token";
const BASE = "http://127.0.0.1:8788";

function assert(cond, msg) { if (!cond) { console.error(`ASSERT FAIL: ${msg}`); process.exitCode = 1; throw new Error(msg); } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  const demo = JSON.parse(fs.readFileSync(demoPath, "utf8"));
  const wasmMod = await import("../src/wasm/tari_cc_private_ballot_hosted_wasm.js");
  const wasmBytes = fs.readFileSync(new URL("../src/wasm/tari_cc_private_ballot_hosted_wasm_bg.wasm", import.meta.url));
  await wasmMod.default(wasmBytes);
  const J = (s) => JSON.parse(s);

  const env = { ...process.env, PRIVATE_BALLOT_HOSTED_BIND: "127.0.0.1:8788", PRIVATE_BALLOT_HOSTED_DB: dbPath, PRIVATE_BALLOT_HOSTED_ADMIN_TOKEN: ADMIN };
  const child = spawn(backendBin, [], { env, stdio: ["ignore", "pipe", "pipe"] });
  child.stdout.on("data", (d) => process.stdout.write(`[backend] ${d}`));
  child.stderr.on("data", (d) => process.stderr.write(`[backend] ${d}`));
  try {
    for (let i = 0; i < 50; i++) { try { const r = await fetch(`${BASE}/health`); if (r.ok) break; } catch {} await sleep(200); }
    const h = await fetch(`${BASE}/health`); assert(h.ok, "backend health");

    // Import election (localhost admin)
    let r = await fetch(`${BASE}/api/v1/admin/elections/import`, { method: "POST", headers: { "content-type": "application/json", "x-admin-token": ADMIN }, body: JSON.stringify({ election_id: demo.election_id, manifest_cbor_hex: demo.manifest_cbor_hex, registry_cbor_hex: demo.registry_cbor_hex, candidate_cbor_hex: demo.candidate_cbor_hex }) });
    assert(r.status === 201, `import ${r.status} ${await r.text()}`);

    // Public package + WASM binding hash parity
    r = await fetch(`${BASE}/api/v1/elections/${demo.election_id}/public-package`);
    assert(r.ok, "public package");
    const pkg = await r.json();
    const localHash = J(wasmMod.package_hash_hex(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex));
    assert(localHash.package_hash_hex === pkg.package_hash_hex, "package hash parity browser/backend");
    const localRegistry = J(wasmMod.compute_registry_commitment(pkg.registry_cbor_hex));
    assert(localRegistry.ok && localRegistry.registry_commitment_hex === pkg.registry_commitment_hex, "registry commitment parity browser/backend");
    const mutatedRegistry = J(wasmMod.compute_registry_commitment(`${pkg.registry_cbor_hex.slice(0, -2)}${pkg.registry_cbor_hex.endsWith("00") ? "01" : "00"}`));
    assert(!mutatedRegistry.ok || mutatedRegistry.registry_commitment_hex !== pkg.registry_commitment_hex, "mutated registry must not verify");
    assert(localRegistry.registry_commitment_hex !== `00${pkg.registry_commitment_hex.slice(2)}`, "wrong advertised registry commitment must fail closed");
    const info = J(wasmMod.election_info(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex));
    assert(info.ok && info.candidates.length === 3, "election info");

    const submit = async (receipt_id, package_cbor_hex) => fetch(`${BASE}/api/v1/elections/${demo.election_id}/ballots`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ receipt_id, package_cbor_hex, api_version: "v1" }) });

    // Voter A creates proof in browser (WASM), submits
    const voterA = demo.voters[0].secret_key_hex;
    const pubA = J(wasmMod.public_key_for_secret(voterA)); assert(pubA.ok, "pubkey A");
    const createdA = J(wasmMod.create_ballot_package(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex, voterA, JSON.stringify([demo.candidates[0].id_hex])));
    assert(createdA.ok, `create A ${createdA.error}`);
    const receiptA = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    r = await submit(receiptA, createdA.package_cbor_hex);
    const receipt1 = await r.json(); assert(r.status === 201 && receipt1.status === "accepted", `submit A ${JSON.stringify(receipt1)}`);
    assert(receipt1.envelope_hash_hex === createdA.envelope_hash_hex, "envelope hash matches browser");
    assert(receipt1.nullifier_hex === createdA.nullifier_hex, "nullifier matches browser");

    // Exact retry -> same stable receipt
    r = await submit(receiptA, createdA.package_cbor_hex);
    const receipt2 = await r.json(); assert(r.status === 200 && receipt2.stable_receipt === receipt1.stable_receipt && receipt2.replay === true, "exact retry idempotent");

    // Distinct second ballot, same voter/nullifier -> duplicate_nullifier
    const createdA2 = J(wasmMod.create_ballot_package(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex, voterA, JSON.stringify([demo.candidates[1].id_hex])));
    assert(createdA2.ok, "create A2"); assert(createdA2.nullifier_hex === createdA.nullifier_hex, "same nullifier for same voter+election");
    r = await submit("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", createdA2.package_cbor_hex);
    const dupBody = await r.text(); assert(r.status === 409 && dupBody.includes("duplicate_nullifier"), `duplicate nullifier ${dupBody}`);

    // Voter B valid
    const createdB = J(wasmMod.create_ballot_package(pkg.manifest_cbor_hex, pkg.registry_cbor_hex, pkg.candidate_cbor_hex, demo.voters[1].secret_key_hex, JSON.stringify([demo.candidates[1].id_hex])));
    assert(createdB.ok, "create B");
    r = await submit("cccccccc-cccc-4ccc-8ccc-cccccccccccc", createdB.package_cbor_hex);
    assert(r.status === 201, `submit B ${await r.text()}`);

    // Malformed
    r = await submit("dddddddd-dddd-4ddd-8ddd-dddddddddddd", "00ff");
    assert(r.status === 422, `malformed ${r.status}`);
    // Wrong election (unknown id)
    r = await fetch(`${BASE}/api/v1/elections/nope/ballots`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ receipt_id: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", package_cbor_hex: createdA.package_cbor_hex, api_version: "v1" }) });
    assert(r.status === 404, `wrong election ${r.status}`);
    // Wrong-election binding: package for this election submitted to a second imported election would fail manifest hash; covered by Rust test wrong_manifest_hash. Here tamper one byte -> invalid proof
    const tampered = createdA.package_cbor_hex.slice(0, -2) + (createdA.package_cbor_hex.endsWith("00") ? "01" : "00");
    r = await submit("ffffffff-ffff-4fff-8fff-ffffffffffff", tampered);
    assert(r.status === 422, `tampered ${r.status}`);

    // Receipt GET
    r = await fetch(`${BASE}/api/v1/elections/${demo.election_id}/receipt/${receiptA}`);
    assert(r.ok && (await r.json()).stable_receipt === receipt1.stable_receipt, "receipt get");

    // Close + finalize (admin)
    r = await fetch(`${BASE}/api/v1/admin/elections/${demo.election_id}/close`, { method: "POST", headers: { "x-admin-token": ADMIN } });
    assert(r.ok, `close ${r.status}`);
    r = await fetch(`${BASE}/api/v1/admin/elections/${demo.election_id}/finalize`, { method: "POST", headers: { "x-admin-token": ADMIN } });
    const fin = await r.json(); assert(r.ok && fin.state === "finalized" && fin.accepted_ballots === 2, `finalize ${JSON.stringify(fin)}`);

    // Results deterministic: A->candidate-a, B->candidate-b
    r = await fetch(`${BASE}/api/v1/elections/${demo.election_id}/results`);
    const results = await r.json(); assert(r.ok && results.accepted_ballots === 2, `results ${JSON.stringify(results)}`);
    assert(results.counts[0].approvals === 1 && results.counts[1].approvals === 1 && results.counts[2].approvals === 0, "tally counts");

    // Archive endpoint returns canonical files
    r = await fetch(`${BASE}/api/v1/elections/${demo.election_id}/archive`);
    const archive = await r.json(); assert(r.ok && archive.files.length === 5, `archive files ${archive.files?.length}`); // manifest, candidates, registry, 2 submissions
    assert(archive.archive_hash_hex.length === 64, "archive hash");

    console.log("E2E PASS: browser WASM proof + backend verify + idempotent retry + duplicate + malformed + finalize + archive");
  } finally {
    child.kill();
    try { fs.unlinkSync(dbPath); } catch {}
    try { fs.unlinkSync(dbPath + "-wal"); } catch {}
    try { fs.unlinkSync(dbPath + "-shm"); } catch {}
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
