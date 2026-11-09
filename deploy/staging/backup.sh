#!/usr/bin/env bash
# Private Ballot staging SQLite backup (Phase 14). Run ON the VPS as root
# or sudo. No secrets are printed. Uses SQLite's online backup API via the
# dot-command so a live WAL database is captured consistently (never copy
# the live -wal/-shm sidecars by hand).
set -euo pipefail

DB_PATH="${PRIVATE_BALLOT_HOSTED_DB:-/var/lib/private-ballot-hosted/hosted.sqlite3}"
BACKUP_DIR="${STAGING_BACKUP_DIR:-/var/lib/private-ballot-hosted/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_DIR/hosted-$STAMP.sqlite3"

mkdir -p "$BACKUP_DIR"
if [ ! -f "$DB_PATH" ]; then echo "DB not found: $DB_PATH" >&2; exit 1; fi

sqlite3 "$DB_PATH" ".backup '$DEST'"
chmod 600 "$DEST"

# Verification: integrity + schema version + expected tables.
sqlite3 "$DEST" "PRAGMA integrity_check;" | grep -qx ok
sqlite3 "$DEST" "SELECT value FROM meta WHERE key = 'schema_version';" | grep -qx 2
sqlite3 "$DEST" "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('elections','ballots');" | sort | tr '\n' ',' | grep -qx "ballots,elections,"

echo "backup ok: $DEST"
ls -l "$DEST"
