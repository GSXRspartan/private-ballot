#!/usr/bin/env bash
# Restore-verify a staging backup into a TEMPORARY location and run a
# read-only schema/consistency test. Never touches the live database.
#   restore-verify.sh /var/lib/private-ballot-hosted/backups/hosted-....sqlite3
set -euo pipefail

SRC="${1:?usage: restore-verify.sh <backup-file>}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
COPY="$TMP/restored.sqlite3"
cp "$SRC" "$COPY"
chmod 600 "$COPY"

sqlite3 "$COPY" "PRAGMA integrity_check;" | grep -qx ok
sqlite3 "$COPY" "PRAGMA journal_mode;" | grep -qx wal
sqlite3 "$COPY" "SELECT value FROM meta WHERE key = 'schema_version';" | grep -qx 2
# Uniqueness enforcement is schema-level (UNIQUE constraints); verify the
# constraints exist rather than loading ballots (no sensitive bulk reads).
sqlite3 "$COPY" "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'ballots';" | grep -q "UNIQUE"
sqlite3 "$COPY" "SELECT COUNT(*) FROM elections;" >/dev/null

echo "restore-verify ok: $SRC"
echo "  schema_version=2, integrity=ok, journal_mode=wal, UNIQUE constraints present; temp copy removed"
