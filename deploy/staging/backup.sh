#!/usr/bin/env bash
# Private Ballot staging SQLite backup (Phase 14). Run ON the VPS as root
# or sudo. No secrets are printed. Uses SQLite's online backup API via the
# dot-command so a live WAL database is captured consistently (never copy
# the live -wal/-shm sidecars by hand).
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
. "$SCRIPT_DIR/schema-versions.sh"

DB_PATH="${PRIVATE_BALLOT_HOSTED_DB:-/var/lib/private-ballot-hosted/hosted.sqlite3}"
BACKUP_DIR="${STAGING_BACKUP_DIR:-/var/lib/private-ballot-hosted/backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="$BACKUP_DIR/hosted-$STAMP.sqlite3"
# A failed verification must not leave a valid-looking but unverified backup
# behind for a later glob or operator to select as a restore point.
KEEP_BACKUP=0
CREATED_DEST=0
trap 'if [ "$KEEP_BACKUP" -eq 0 ] && [ "$CREATED_DEST" -eq 1 ] && [ -n "$DEST" ]; then rm -f "$DEST"; fi' EXIT

mkdir -p "$BACKUP_DIR"
if [ ! -f "$DB_PATH" ]; then echo "DB not found: $DB_PATH" >&2; exit 1; fi
if [ -e "$DEST" ] || [ -L "$DEST" ]; then echo "backup destination already exists: $DEST" >&2; exit 1; fi

CREATED_DEST=1
sqlite3 "$DB_PATH" ".backup '$DEST'"
chmod 600 "$DEST"

# Verification: integrity + explicit schema allowlist + expected tables.
sqlite3 "$DEST" "PRAGMA integrity_check;" | grep -qx ok
assert_supported_schema_version "$DEST"
sqlite3 "$DEST" "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('elections','ballots','organizer_credentials');" | sort | tr '\n' ',' | grep -qx "ballots,elections,organizer_credentials,"

KEEP_BACKUP=1
echo "backup ok: $DEST"
ls -l "$DEST"
