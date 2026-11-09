# Ootle Reset / Cohort-Upgrade Runbook (Phase 17)

Goal: after the next protocol/reset event, the process is explicit and configuration-driven. Do not hard-code the next template address.

## Steps

1. **Detect** the new official Ootle release/reset version (`tari-project/tari-ootle` releases page). Record the tag + commit.
2. **Verify the dependency cohort:** read the tagged `Cargo.toml` workspace versions (as in `docs/modernization/OOTLE_CURRENT_STATE.md`). Pin the four `crates/ootle-*/Cargo.toml` git revs + `templates/ootle-anchor-event-template-v2/Cargo.toml` `tari_template_lib` in one commit. Never pin unreleased development commits.
3. **Reset wallet** per official instructions (v0.51.0: walletd migrates on first start; validator DB migrates on first start; no data wipe for a cohort upgrade without a reset — see `docs/modernization/OOTLE_CURRENT_STATE.md`).
4. **Rebuild the V2 template** against the new `tari_template_lib` (`wasm32-unknown-unknown --release`, path-clean with `--remap-path-prefix`). The four-argument ABI must remain byte-compatible; if it cannot, stop and classify as a protocol migration (see below).
5. **Measure** SHA-256 and BLAKE3-256 of the WASM (`Get-FileHash`/sha256sum + BLAKE3 tool).
6. **Publish** the template (Wallet Web UI is the supported publish path; never spend testnet funds in Stage 1).
7. **Record** the deployment transaction ID.
8. **Write a new `DeploymentRegistry` entry** (`crates/deployment-registry`): network, network generation, `ootle_version`, logical name, ABI (`TariPrivateBallotAnchorV2`), template address, artifact SHA-256/BLAKE3, deployment tx, activation time. Leave the old entry in place.
9. **Verify ABI:** call `publish_anchor_v2` with the four arguments in a dry run; confirm the `TARI_CC_PRIVATE_BALLOT_OOTLE_ANCHOR_V2` event.
10. **Execute one synthetic anchor** (organizer approval required; fee-bearing; retryable — a fee failure is not an election failure).
11. **Verify** receipt/event/digest: `convert_receipt_response` → `AnchorReceiptV1` → `verify_anchor_receipt`; recompute the anchor digest from the emitted `public_summary`.
12. **Mark** the new deployment `CURRENT` (exactly one per network; the registry refuses to resolve with zero or multiple `CURRENT`).
13. **Mark** the old deployment `SUPERSEDED` (never delete; `HISTORICAL` for pre-reset evidence).
14. **Run focused regression:** `cargo test -p tari-cc-private-ballot-ootle-receipt-anchor-adapter -p tari-cc-private-ballot-ootle-anchor-adapter -p tari-cc-private-ballot-ootle-walletd-anchor-adapter -p tari-cc-private-ballot-deployment-registry` + `cargo check --workspace --all-targets`.
15. **Update runtime config:** deployment registry file, hosted `HOSTED_CONFIG`, docs version refs. No source archaeology.

## Protocol-migration stop rule

If any of these cannot remain byte/semantic compatible — ballot format, Triptych proof behavior, nullifiers, archive format, tally, `public_summary`, anchor digest, `publish_anchor_v2` ABI — stop, classify as a protocol migration, and get explicit review before proceeding. Stage 1 proves the v0.51.0 migration kept all of them (see final report §4).

## Historical evidence

The v0.39.2 / v0.42.0 artifacts, addresses, and digests in `docs/CONTROLLED_ALPHA_PACKAGE_CHECKLIST.md`, `templates/ootle-anchor-event-template-v2/DEPLOYMENT_RUNBOOK.md:169`, and `crates/gui-core/src/trusted_anchor_deployment.rs` (BLAKE3 `ce5334df...`, SHA-256 `76532c3c...`, 61479 bytes) are `HISTORICAL`/`SUPERSEDED` evidence. They are never deleted or silently rewritten.
