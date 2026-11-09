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

- Backup: `bash deploy/staging/backup.sh` — online SQLite backup,
  integrity + schema verification, 0600 perms. Schedule with cron/systemd
  timer (e.g. hourly for staging).
- Restore: `bash deploy/staging/restore-verify.sh <backup>` verifies into
  a temp copy first. To restore for real: stop the service, replace the
  DB file at `PRIVATE_BALLOT_HOSTED_DB`, start the service. Never copy a
  live database's `-wal`/`-shm` files by hand.

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
