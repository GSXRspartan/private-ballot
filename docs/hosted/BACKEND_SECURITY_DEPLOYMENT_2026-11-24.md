# Staging backend security deployment — 2026-11-24

STAGING ONLY. This record covers the backend upgrade from the reviewed branch
`review/web-mainnet-anchor-6a936d9`. No production deployment, no PR merge,
no new Mainnet transaction, no authority-key rotation, and no election-data
change were performed.

## 1. Source provenance

| Item | Value |
|---|---|
| Source branch | `review/web-mainnet-anchor-6a936d9` |
| Source HEAD | `75ac3d76c390c98fdf329a10370651bb11dff4d0` |
| Security commit | `e6fc580` (`fix(hosted): rate-limit heavy public reads and harden enrollment validation`) |
| Later approved commits present | `fa54902` (edge hardening), `b6523c3`, `75ac3d7` |
| Local tree at build time | clean; in sync with `origin/review/web-mainnet-anchor-6a936d9` |
| Transfer to VPS | `git bundle` SHA-256 `8b166604b2e97158bb25af75e77bb90d4cc05ffad96f90da130b331105884e6b` |
| VPS checkout | `/opt/private-ballot-hosted/source`, HEAD verified as above, `git status --porcelain` empty |
| Ancestry checks | `git merge-base --is-ancestor e6fc580 HEAD` and the same for `fa54902`: both OK |

No pre-existing Private Ballot source checkout or dirty working tree was found
on the VPS; the checkout above was created from the verified bundle, so no
operator changes were overwritten.

## 2. Access verification

- SSH key `~/.ssh/ghostgate_vps` (public-key comment `pdark@Dark_Laptop`);
  private key never displayed or copied.
- Documented VPS target `ubuntu@40.160.90.9` (from the existing Ghost Gate
  staging deployment script). `pdark@` and `root@` were confirmed rejected.
- Live ED25519 host key `SHA256:u4mEOHUDyRu3j0V7zRTzvHJUXZnJiebvcRUZxNVDSso`
  matched the trusted `known_hosts` record before any login (StrictHostKeyChecking=yes).
- Cloudflare Wrangler `4.166.0` OAuth login verified with `wrangler whoami`;
  staging Worker `private-ballot-staging` remains at deployment version
  `f8015e7c-3796-4613-b995-9517a4d4d8dd` (`edge-hardening-fa54902`).

## 3. Pre-deployment state and rollback preparation

| Item | Value |
|---|---|
| Service | `private-ballot-hosted.service` (enabled, active) |
| Unit | `/etc/systemd/system/private-ballot-hosted.service` |
| Unit SHA-256 | `ab3faa5f522eacee321dec6630656743830f324edefb146ff0cab7f89fbff523` |
| Old binary | `/opt/private-ballot-hosted/private-ballot-hosted` |
| Old binary SHA-256 | `0aaed7e1e440f5884162eef0202371ddfd13c912e45d247c3835e3ff4f8d8c7e` |
| Database | `/var/lib/private-ballot-hosted/hosted.sqlite3` (WAL, schema v7) |
| Backup directory | `/var/lib/private-ballot-hosted/backups` |
| Verified DB backup | `hosted-20261124T143637Z.sqlite3` |
| DB backup SHA-256 | `c79e9bd3a5d38e6582d5853cc572fa91ca1627800886df2b5f9f586004c5a0f9` |
| Binary rollback copy | `private-ballot-hosted.rollback-20261124T143637Z` (mode 0755, same hash as old binary) |
| Unit backup | `private-ballot-hosted.service.20261124T143637Z` |
| Environment backup | `hosted-env-20261124T143637Z.tar.gz` (mode 0600, sealed; contents never printed) |
| Environment SHA-256 | `a3e56786aeea8382a045694646a40f5567849c03dfce4d84da90f4c2eed58f22` (unchanged after deployment) |
| Free disk | 28 GB available on `/` |

Backup verification: readable, `PRAGMA integrity_check` returned `ok`,
`schema_version=7`, expected 11 tables present, `journal_mode=wal`.

**Runbook caveat (resolved in a subsequent commit on this branch):** at
deployment time `deploy/staging/backup.sh` and `restore-verify.sh` still
asserted `schema_version=4`. The live database and reviewed source both use
v7 (`crates/hosted/src/storage.rs` migrates 6→7), so the online backup was
created successfully but those stale assertions failed. The backup was
verified against the actual v7 schema before deployment. The scripts now use
the explicit allowlist in `deploy/staging/schema-versions.sh` (currently `7`)
and are covered by `deploy/staging/test-backup-verification.sh`; qualification
evidence is in `docs/hosted/STAGING_RECOVERY_QUALIFICATION.md`.

## 4. Build and replacement

- Toolchain installed on VPS from `rust-toolchain.toml`: `rustc 1.97.1`,
  `cargo 1.97.1`, host `x86_64-unknown-linux-gnu`.
- Build: `cargo build --locked --release -p tari-cc-private-ballot-hosted`
  from `/opt/private-ballot-hosted/source`; exit code 0.
- New binary SHA-256:
  `a23cef08703c7e6c19d7f3b92984e2a38b099ed79c3b777662835056b3707600`
  (ELF 64-bit x86-64, 9,114,480 bytes, mode 0755 root:root).
- The new binary was installed to a temporary same-filesystem path, hash
  checked, then atomically `mv`-replaced. Only `private-ballot-hosted` was
  restarted; `cloudflared` and all other services were left running.
- New binary is deployed at `/opt/private-ballot-hosted/private-ballot-hosted`
  with the hash above; service `active (running)`.

## 5. Validation evidence

Local VPS checks: `deploy/staging/health-check.sh` passed all three planes;
startup journal showed the expected service/bind/database and only HTTP 200
request lines. `/chain/network` returned
`{"network":"mainnet","network_byte":0,"epoch":39364}`.

Public staging responses were captured before and after the swap. Status,
size and SHA-256 prefix were identical for every endpoint:

| Endpoint (staging origin) | Status | Bytes | Body SHA-256 prefix |
|---|---|---|---|
| `/api/v1/status` | 200 | 63 | `A07DDACB9C2065D32B5C` |
| `/api/v1/elections/pb-staging-browser-e2e-1795362392453/results` | 200 | 333 | `AF725B489199FDE30962` |
| `.../archive` | 200 | 4710 | `05003D8F1834A04E09CC` |
| `.../public-package` | 200 | 1332 | `D39C894AE9F6EE1973A8` |
| `.../anchor-payload` | 200 | 6133 | `DE79C5B4D389CE2020D4` |
| `/chain/network` | 200 | 52 | `03C712075C3D38903DEE` |
| `/chain/transaction-receipts/28c789e6...bf01f2` | 200 | 2442 | `E06C88B7B24EDB5C92CB` |
| `/chain/transactions/28c789e6...bf01f2/result?include_proof=true` | 404 | 42 | `CA9A640B1AF9C42FE990` |

Admin paths `/api/v1/admin/elections/import`, percent-encoded
`/api/v1/admin%2felections%2fimport`, double-slash
`/api/v1/admin//elections/import`, and the election close path all returned
the canonical 42-byte edge 404 before and after the swap. The Worker version
was unchanged, so the `fa54902` edge hardening remains live.

The environment file hash and timestamp were unchanged, and the mainnet chain
response was identical, so no authority or network configuration changed.

## 6. High-severity fix verification

Evidence that the mitigation is live, not merely assumed:

1. **Source:** the deployed binary was built from the clean checkout containing
   `RATE_MAP_MAX_ENTRIES = 4096`, `LEDGER_CACHE_MAX_ELECTIONS = 16`,
   `cached_finalized_replay()` with manifest-hash guarding, and per-route
   `results-read`, `archive-read` and `enroll` buckets.
2. **Binary provenance:** the new binary contains strings absent from the
   previous binary, including `results-read`, `archive-read`,
   `public_key_hex must be a canonical 32-byte Ristretto255 point`, and
   `invitation not found for this election`.
3. **Tests on the VPS checkout:** `cargo test --locked --release -p
   tari-cc-private-ballot-hosted` returned `77 passed; 0 failed`, including
   `rate_map_never_grows_from_oversized_ids_and_limits_within_the_window`,
   `finalized_results_reads_are_rate_limited_and_served_from_cache`,
   `enrollment_rejects_non_canonical_ristretto_governance_keys`, and
   `admin_void_invitation_requires_the_matching_election`.
4. **Bounded live behaviour:** repeated public results/archive reads after the
   restart were served in 0–2 ms in the service journal, consistent with the
   warmed verified-ledger cache. No synthetic flood was sent to the public
   staging site; the limit-enforcement path was proven by the reviewed tests
   rather than by deliberate load.

## 7. Rollback

If a problem is observed, restore only the staging backend:

```bash
sudo systemctl stop private-ballot-hosted
sudo install -o root -g root -m 0755 \
  /opt/private-ballot-hosted/private-ballot-hosted.rollback-20261124T143637Z \
  /opt/private-ballot-hosted/private-ballot-hosted
sudo systemctl start private-ballot-hosted
curl -fsS http://127.0.0.1:8788/health
```

The database requires no rollback: it was not modified by this deployment. If
a DB restore is ever needed, stop the service first and use the verified
backup at `/var/lib/private-ballot-hosted/backups/hosted-20261124T143637Z.sqlite3`
with the repository's restore procedure. The sealed environment/authority-key
backup is retained at mode 0600 and was not consumed.
