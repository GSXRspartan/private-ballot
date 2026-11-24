#!/usr/bin/env bash
# Regression tests for staging backup schema-version and corruption checks.
# Run with: bash deploy/staging/test-backup-verification.sh
# Requires sqlite3 and bash; creates fixtures only in a temporary directory.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0

make_db() {
  local db_path="$1"
  local version="${2:-7}"
  local include_meta="${3:-yes}"
  sqlite3 "$db_path" "PRAGMA journal_mode=wal;" >/dev/null
  if [ "$include_meta" = "yes" ]; then
    sqlite3 "$db_path" "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
      INSERT INTO meta(key,value) VALUES('schema_version','$version');"
  fi
  sqlite3 "$db_path" "CREATE TABLE elections(id TEXT PRIMARY KEY, manifest_hash_hex TEXT NOT NULL,
      finalized_archive_hash_hex TEXT NOT NULL, finalized_anchor_digest_hex TEXT NOT NULL);
    CREATE TABLE ballots(receipt_id TEXT PRIMARY KEY, election_id TEXT NOT NULL,
      nullifier_hex TEXT NOT NULL, UNIQUE(nullifier_hex));
    CREATE TABLE organizer_credentials(election_id TEXT PRIMARY KEY,
      organizer_verifier_hex TEXT NOT NULL, created_at_ms INTEGER NOT NULL);"
}

run_backup() {
  local db_path="$1"
  local backup_dir="$2"
  PRIVATE_BALLOT_HOSTED_DB="$db_path" STAGING_BACKUP_DIR="$backup_dir" \
    bash "$HERE/backup.sh"
}

expect_ok() {
  local label="$1"
  shift
  local log="$TMP/expect-ok.log"
  if "$@" >"$log" 2>&1; then
    echo "PASS: $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $label (expected success)"
    cat "$log"
    FAIL=$((FAIL + 1))
  fi
}

expect_rejected() {
  local label="$1"
  local pattern="$2"
  shift 2
  local log="$TMP/expect-rejected.log"
  if "$@" >"$log" 2>&1; then
    echo "FAIL: $label (unexpected success)"
    FAIL=$((FAIL + 1))
  elif grep -Eq "$pattern" "$log"; then
    echo "PASS: $label"
    PASS=$((PASS + 1))
  else
    echo "FAIL: $label (wrong error message)"
    cat "$log"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== supported schema version ==="
make_db "$TMP/v7.sqlite3" 7
expect_ok "v7 backup accepted" run_backup "$TMP/v7.sqlite3" "$TMP/backups-v7"
V7_BACKUP="$(ls -1t "$TMP"/backups-v7/hosted-*.sqlite3 | head -n 1)"
expect_ok "v7 restore-verify accepted" bash "$HERE/restore-verify.sh" "$V7_BACKUP"

echo "=== explicitly unsupported schema versions ==="
for version in 2 4 6 8; do
  db="$TMP/v${version}.sqlite3"
  dir="$TMP/backups-v${version}"
  make_db "$db" "$version"
  expect_rejected "v${version} backup rejected" "unsupported schema version: $version" \
    run_backup "$db" "$dir"
  expect_rejected "v${version} restore-verify rejected" "unsupported schema version: $version" \
    bash "$HERE/restore-verify.sh" "$db"
done

for version in abc 007 17 7x; do
  db="$TMP/v${version}.sqlite3"
  dir="$TMP/backups-v${version}"
  make_db "$db" "$version"
  expect_rejected "non-exact version $version rejected" "unsupported schema version: $version" \
    run_backup "$db" "$dir"
done
expect_ok "failed backup leaves no unverified file" \
  bash -c '[ -d "$1" ] && [ -z "$(ls -A "$1")" ]' _ "$TMP/backups-v4"

echo "=== corruption and missing-version fail closed ==="
make_db "$TMP/no-meta.sqlite3" 7 no
expect_rejected "missing schema_version rejected" "meta.schema_version missing or unreadable" \
  run_backup "$TMP/no-meta.sqlite3" "$TMP/backups-no-meta"
printf 'not a sqlite database' >"$TMP/corrupt.sqlite3"
expect_rejected "corrupt backup source rejected" "not a database|malformed|unsupported schema version" \
  run_backup "$TMP/corrupt.sqlite3" "$TMP/backups-corrupt"
expect_rejected "corrupt restore input rejected" "not a database|malformed|unsupported schema version" \
  bash "$HERE/restore-verify.sh" "$TMP/corrupt.sqlite3"

echo "=== result: $PASS passed, $FAIL failed ==="
[ "$FAIL" -eq 0 ]
