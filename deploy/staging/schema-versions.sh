#!/usr/bin/env bash
# Shared schema-version policy for staging backup and recovery verification.
#
# Authoritative source: crates/hosted/src/storage.rs. A freshly opened database
# is written as schema_version=7; versions 2..6 are migration inputs only and
# require a separate reviewed migration procedure before being used as a
# recovery point. Any other value is incompatible and must fail closed.
#
# This allowlist is deliberately explicit: no wildcard, ranged or implicit
# acceptance. Add a version here only together with a reviewed migration and
# recovery qualification for that version.

SUPPORTED_SCHEMA_VERSIONS="7"

schema_version_of() {
  local value=""
  value="$(sqlite3 "$1" "SELECT value FROM meta WHERE key = 'schema_version';" 2>/dev/null)" || value=""
  printf '%s\n' "$value" | head -n 1
}

assert_supported_schema_version() {
  local db_path="$1"
  local observed
  observed="$(schema_version_of "$db_path")"
  if [ -z "$observed" ]; then
    echo "unsupported schema version: meta.schema_version missing or unreadable (expected one of: $SUPPORTED_SCHEMA_VERSIONS)" >&2
    return 1
  fi
  case " $SUPPORTED_SCHEMA_VERSIONS " in
    *" $observed "*) return 0 ;;
  esac
  echo "unsupported schema version: $observed (expected one of: $SUPPORTED_SCHEMA_VERSIONS)" >&2
  return 1
}
