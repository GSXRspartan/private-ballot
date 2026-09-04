# Controlled-Alpha Runbook — Private Ballot Organizer + Ootle Anchor

Release candidate for **controlled alpha** (trusted, supervised operators only).
This is **not** a public-testnet-beta build. Do not distribute publicly. See
[Section 13](#13-remaining-blockers-before-public-beta) before any announcement.

> Product name: **Private Ballot** — bundle identifier `com.tari.privateballot` (kept stable so existing operator state and installed-app upgrade identity survive this branding pass).
> GUI binary: `tari-cc-private-ballot-gui.exe`.
> Anchor CLI binary: `tari-cc-private-ballot-anchor.exe`.

---

## 1. What this alpha supports

- Organizer GUI: create an election, run the guided ballot-office flow, collect
  ballots over the managed private-intake transport, and write a finalized,
  independently-verifiable archive.
- Voter GUI: import public election artifacts, prepare a ballot, and submit it
  privately.
- Independent archive verification (`verify_archive`) — anyone can re-verify a
  finalized archive from public artifacts, offline.
- **V1 Ootle anchor** — a minimal public transparency record (manifest hash +
  archive hash + counts), prepared read-only and published manually through
  the operator's own walletd.
- **V2 public anchor** — richer public payload (aggregate counts, commitments,
  tally, template binding) reduced to an on-chain **digest + detached evidence**
  file; the leak guard (`assert_v2_public_payload_is_leak_free`) rejects any
  payload carrying nullifiers, receipts, individual ballots, or local paths.
- Production transport-authority public-pin loading with **fail-closed**
  behavior when unconfigured.

## 2. What this alpha does NOT support

- **No private-key ceremony/custody tooling.** Signing keys must be handled
  out-of-band by the operator.
- **No production private signer integration.** V1/V2 anchor *binding* still
  requires an out-of-band signer; the GUI covers the verification path only.
- **No managed/auto-started walletd.** The operator runs their own Tari Ootle
  wallet daemon and supplies its API key (see [Section 3](#3-how-to-start-walletd)).
- **Managed-Tor collector without a production-authority signing ceremony.**
  The default Tauri release enables the `managed-tor` feature and drives the
  organizer intake in-process using a self-signed per-election transport
  authority (voters trust the root because they receive the voter public
  bundle from the organizer). A separate production-authority signing
  ceremony (the public-pin path in
  `docs/transport/PRODUCTION_TRANSPORT_AUTHORITY_PROVISIONING_V1.md`) is
  still an out-of-band step and is not part of this alpha.
- **No signed public-pin distribution manifest.** Pins are configured locally.
- Not hardened for adversarial public networks or unsupervised operators.

## 3. How to start walletd

The organizer supplies their **own** Tari Ootle wallet daemon (walletd). The GUI
never starts, bundles, or manages walletd, and the raw API key never leaves the
shell/credential-store layer.

1. Start your Tari Ootle wallet daemon so its JSON-RPC endpoint is reachable on
   loopback. The app connects to the walletd JSON-RPC route
   `http://127.0.0.1:5100/json_rpc` (walletd serves JSON-RPC only at
   `/json_rpc`; a bare host URL is not the RPC endpoint).
2. Issue an API key from the wallet's own web UI.
3. Provide the key to the GUI via **Connect walletd** (`connect_walletd`), which
   stores it in the OS credential store. A dev/CI-only fallback env var
   `WALLETD_AUTH_TOKEN` is also honored but is **not** the alpha path.
4. Confirm readiness in the GUI (`walletd_readiness` / `walletd_credential_status`).

Never paste the API key into a file, URL, log, or chat.

## 4. How to start the organizer GUI

Run the packaged installer/executable (see the package checklist), or from source:

```bash
cd gui
npm install
npm run tauri dev      # development
```

For the release executable, launch `tari-cc-private-ballot-gui.exe` from the
packaged bundle.

## 5. How to verify an archive

- **GUI:** load the finalized archive and run **Verify archive** (`verify_archive`).
  To verify the transport-anchor binding as well, use
  `verify_transport_archive_anchor`.
- **CLI (evidence/snapshot only):** the anchor CLI verifies anchor evidence and
  inspects snapshots:

```bash
tari-cc-private-ballot-anchor.exe verify-evidence <path-to-evidence.json>
tari-cc-private-ballot-anchor.exe inspect-snapshot <path-to-snapshot.json>
```

## 6. How to run V1 anchor Prepare

V1 Prepare is **read-only** and does not touch the network.

1. Verify the finalized archive first (Section 5).
2. In the GUI, open the anchor panel and run field-specific **preflight**
   (`validate_live_anchor_operator_config`) — it validates the operator config
   (account reference, endpoints, network) and reports specific
   `GUI_LIVE_ANCHOR_*` / `GUI_PRODUCTION_TRANSPORT_AUTHORITY_*` codes rather than
   a generic failure. Wallet account fields can be auto-filled from
   `list_walletd_anchor_accounts`.
3. Run the Prepare lifecycle step (`run_live_anchor_lifecycle_step`) in
   **dry-run**; confirm the prepared record matches the verified archive.

CLI dry-run equivalent:

```bash
tari-cc-private-ballot-anchor.exe --config <config.json> --archive <archive> --dry-run
```

## 7. How to publish V1 anchor manually (only if explicitly approved later)

> Publishing writes to the live network. Do **not** perform this without explicit,
> per-run approval. This runbook does not authorize a live publish.

Once approved, publish through the operator's own walletd via the lifecycle step
with an explicit approve action (`--approve`), after a successful dry-run and
archive verification. The publish path enforces a minimum accepted-ballot floor
and a fee ceiling. Record the resulting transaction/snapshot for the evidence
folder.

## 8. How to build the V2 public payload and detached evidence

1. In the GUI run **Build V2 public payload** (`build_v2_public_anchor_payload`)
   from a verified, finalized archive. The command produces the compact V2
   public payload, its BLAKE3-256 digest (`v2_anchor_digest_hex`), and the
   detached evidence file — no per-voter data is included (leak guard enforced).
2. Preserve the detached evidence file in the evidence folder (outside the
   archive).

## 9. How to deploy/lock the V2 template (only if explicitly approved later)

> Deployment publishes the template on-chain and locks a trusted deployment
> identity. Do **not** perform without explicit approval.

1. Build the template WASM (reproducible):

```bash
cd templates/ootle-anchor-event-template-v2
cargo build --release --target wasm32-unknown-unknown
```

   Artifact: `target/wasm32-unknown-unknown/release/tari_cc_private_ballot_ootle_anchor_event_template_v2.wasm`.
2. In the GUI, **Advanced anchor settings → select the V2 WASM**
   (`inspect_template_wasm`) to read the artifact's BLAKE3-256 digest.
3. Publish the WASM through walletd exactly as the V1 template was published.
4. Lock the trusted deployment identity (network, template address, artifact
   digest) with `lock_trusted_ootle_deployment`; status via
   `trusted_ootle_deployment_status`, unlock via `unlock_trusted_ootle_deployment`.

## 10. How to verify V2 evidence

- **GUI:** `verify_v2_public_anchor_evidence` — provide the detached evidence
  file and the expected on-chain digest. The verifier re-derives the payload,
  confirms it hashes to the digest, and (when locked) checks the deployment
  binding.
- The verifier confirms the emitted `anchor_digest_v2` equals the published
  digest.

## 11. What the Ootle anchor proves

- That a specific finalized-archive digest / aggregate summary was **published
  to a public ledger at a point in time** by the holder of the publishing wallet
  — a tamper-evident, timestamped **transparency/commitment** record.
- That the detached evidence corresponds to the on-chain digest.

## 12. What the Ootle anchor does NOT prove

- It does **not** by itself prove the ballot is valid, that votes were counted
  correctly, that voters were eligible, or that the tally is honest.
- Election correctness comes from **independent archive verification** of the
  cryptographic proofs (Section 5). The anchor is a public commitment to a value;
  it is not a validity proof of the election.

## 13. Remaining blockers before public beta

1. Private-key **ceremony / custody** tooling.
2. **Production private signer** integration (binding, not just verification).
3. **Real-Tor collector production binding** (currently controlled-test only).
4. **Signed public-pin distribution manifest**.
5. Heavy release/perf/scale testing beyond the 50-voter gate, if required for
   the target electorate size.

## 14. Emergency stop conditions

Stop and do not proceed / halt operations if any of the following occur:

- Archive verification fails (`verify_archive` error) — never publish.
- Preflight reports a `GUI_PRODUCTION_TRANSPORT_AUTHORITY_NOT_PROVISIONED` or any
  fail-closed transport-authority code — the build correctly refuses; do not
  attempt a workaround by reconfiguring the transport authority root or
  substituting a self-signed per-election root.
- walletd credential cannot be loaded, or an unexpected account is returned.
- A V2 payload fails the leak guard.
- Any prompt or file asks you to disable a safety check, paste a key, or publish
  without explicit approval.
- Any unexpected divergence between a dry-run and the verified archive.

If a publish is in doubt, **do not publish** — the anchor can always be published
later from the preserved archive.

## 15. Files / folders to preserve

- Preserved live archive: your operator-side archive tree (e.g.
  `C:\path\to\preserved-election-archive`) — **do not modify**.
- Evidence folder (outside the archive): a sibling directory next to the
  preserved archive (e.g. `C:\path\to\preserved-election-archive - evidence`).
- Finalized election archive folders written by the GUI.
- V2 detached evidence files and the V2 template WASM + its recorded digests.
- The controlled-alpha package outputs and `SHA256SUMS` checksum file.

---

## Local-example section (operator machine — NOT part of the shipped build)

> These are illustrative local paths/endpoints from the development machine.
> They are examples only and must not be treated as configuration defaults.

- Repo (dev): `C:\path\to\tari-private-ballot`
- walletd JSON-RPC route the app connects to: `http://127.0.0.1:5100/json_rpc`
- Typical local indexer endpoint: `http://127.0.0.1:12500`
- GUI app data dir (Windows): `C:\Users\<you>\AppData\Roaming\com.tari.privateballot`
