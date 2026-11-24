# Hosted staging operations runbook

## Health checks

```bash
# On the VPS (local planes)
bash deploy/staging/health-check.sh

# From the public Internet (via the edge)
curl -s https://<staging-workers-dev>/api/v1/status
curl -s -o /dev/null -w "%{http_code}\n" https://<staging-workers-dev>/api/v1/admin/elections/import   # expect 404

# Direct ingress (origin-token fail-closed check)
curl -s -o /dev/null -w "%{http_code}\n" https://<ingress-host>/api/v1/status   # expect 401
```

## systemd

```bash
sudo systemctl status private-ballot-hosted
sudo systemctl restart private-ballot-hosted
journalctl -u private-ballot-hosted --since "10 min ago"   # method/path/status/duration only
sudo systemctl status cloudflared
```

## Backup / restore

Authoritative schema is **v7** (`crates/hosted/src/storage.rs`: a fresh
database is written as `schema_version=7`; 2–6 are migration inputs only).
The scripts accept ONLY the versions listed in
`deploy/staging/schema-versions.sh` (currently `7`) and fail closed on any
other, missing, or corrupt version.

### Backup and verify (on the VPS)

```bash
sudo bash /opt/private-ballot-hosted/source/deploy/staging/backup.sh
sudo bash /opt/private-ballot-hosted/source/deploy/staging/restore-verify.sh \
  /var/lib/private-ballot-hosted/backups/<latest>.sqlite3
```

`backup.sh` uses SQLite's online backup API against the live WAL database,
sets mode 0600, and checks `PRAGMA integrity_check`, the explicit schema
allowlist, and the critical tables. Never copy a live database's
`-wal`/`-shm` sidecars by hand.

### Script regression tests (no live database use)

```bash
bash /opt/private-ballot-hosted/source/deploy/staging/test-backup-verification.sh
```

Creates temporary fixtures for v7 (accepted), v2/v4/v6/v8 (rejected),
missing `schema_version` (rejected), and corrupted files (rejected).

### Non-destructive restore drill (isolated DB and service config)

This never touches the live database or the live service.

```bash
SRC=/var/lib/private-ballot-hosted/backups/<verified-backup>.sqlite3
TMP=$(sudo mktemp -d -p /var/tmp pb-recovery-drill.XXXXXX)
sudo chown private-ballot-hosted:private-ballot-hosted "$TMP"
sudo chmod 700 "$TMP"
sudo cp "$SRC" "$TMP/restored.sqlite3"
sudo chown private-ballot-hosted:private-ballot-hosted "$TMP/restored.sqlite3"
sudo chmod 600 "$TMP/restored.sqlite3"
sudo bash /opt/private-ballot-hosted/source/deploy/staging/restore-verify.sh "$TMP/restored.sqlite3"

# Isolated env: same secrets, overridden DB and loopback ports. Never print it.
sudo bash -c 'umask 077; grep -vE "^PRIVATE_BALLOT_HOSTED_(DB|BIND|ADMIN_BIND)=" /etc/private-ballot-hosted/hosted.env > "$1"; printf "PRIVATE_BALLOT_HOSTED_DB=%s\nPRIVATE_BALLOT_HOSTED_BIND=127.0.0.1:8878\nPRIVATE_BALLOT_HOSTED_ADMIN_BIND=127.0.0.1:8879\n" "$2" >> "$1"' _ "$TMP/hosted.env" "$TMP/restored.sqlite3"
sudo chown private-ballot-hosted:private-ballot-hosted "$TMP/hosted.env"
sudo chmod 600 "$TMP/hosted.env"

sudo systemd-run --unit=pb-recovery-drill --collect \
  --property=User=private-ballot-hosted \
  --property=Group=private-ballot-hosted \
  --property=EnvironmentFile="$TMP/hosted.env" \
  --property=WorkingDirectory=/opt/private-ballot-hosted \
  /opt/private-ballot-hosted/private-ballot-hosted
curl -fsS http://127.0.0.1:8878/health
sudo bash -c 'set -a; . "$1"; set +a; curl -fsS -H "x-private-ballot-origin: $PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN" http://127.0.0.1:8878/api/v1/status' _ "$TMP/hosted.env"

sudo systemctl stop pb-recovery-drill.service
sudo rm -rf "$TMP"
```

### Real restore (only with explicit operator authorization)

```bash
sudo systemctl stop private-ballot-hosted
sudo install -o private-ballot-hosted -g private-ballot-hosted -m 0600 \
  /var/lib/private-ballot-hosted/backups/<verified-backup>.sqlite3 \
  /var/lib/private-ballot-hosted/hosted.sqlite3
sudo rm -f /var/lib/private-ballot-hosted/hosted.sqlite3-wal \
          /var/lib/private-ballot-hosted/hosted.sqlite3-shm
sudo systemctl start private-ballot-hosted
curl -fsS http://127.0.0.1:8788/health
```

Only the stale sidecars of the *stopped* service are removed; never copy a
live database's `-wal`/`-shm` files. The database is not changed by a backup
or by an isolated drill.

## Restart / recovery acceptance (Phase 23)

1. Cast ballots, note receipts.
2. `systemctl restart private-ballot-hosted`; `systemctl restart cloudflared`.
3. Confirm: elections, receipts, accepted ballots survive; exact retry
   after restart returns the same receipt with `replay=true` and no
   double count (same guarantee as the local
   `concurrent_same_receipt_does_not_double_count` test).

## Failure drill (Phase 24)

- Stop backend → edge returns 502. Restart → same receipt returned, no
  duplicate.
- Stop Tunnel → edge returns 502. Restart → frontend reconnects.
- Oversized body → 413. Wrong content-type → 415. Malformed JSON/package
  → 400/422. Invalid proof → 422. Duplicate nullifier → 409.
  Unknown election → 404. Closed election → 409. Public admin call → 404.

## Incident basics

- Do not restart by deleting the database. Back up first, restore second.
- Do not disable the origin token without removing the Worker secret too
  (edge and backend must agree).
- A suspected secret leak means rotating BOTH `PRIVATE_BALLOT_HOSTED_ADMIN_TOKEN`
  and `PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN` (VPS env + Worker secret),
  then restarting the backend and redeploying the Worker.

## Upgrade procedure

1. Merge the new commit on `hosted-v2-stage3` (never main).
2. Rebuild the backend on the VPS from the exact commit; prefer
   reproducible build; record SHA-256.
3. Backup the database (script above) before upgrading.
4. Stop the service, replace the binary, start, health-check.

## Rollback

Revert to the previous binary (keep a copy), keep the same database
(schema is additive-only; do not run migrations backwards), restart.
Worker rollback: `npx wrangler rollback` (keeps the previous version).
