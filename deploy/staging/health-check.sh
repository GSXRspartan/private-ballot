#!/usr/bin/env bash
# Local staging health check (Phases 6/15). Run ON the VPS. Public plane
# require an origin token when one is configured for /api/* paths, so this
# script reads the token from the environment file without echoing it.
set -euo pipefail

ENV_FILE="${ENV_FILE:-/etc/private-ballot-hosted/hosted.env}"
# shellcheck disable=SC1090
. "$ENV_FILE"
PUBLIC_BASE="http://127.0.0.1:8788"
ADMIN_BASE="http://127.0.0.1:8789"

curl -fsS "$PUBLIC_BASE/health" | grep -q '"status":"ok"'
echo "public /health ok"
curl -fsS -H "x-private-ballot-origin: $PRIVATE_BALLOT_HOSTED_ORIGIN_TOKEN" "$PUBLIC_BASE/api/v1/status" | grep -q '"mode"'
echo "public /api/v1/status ok (origin-token operator verified)"
curl -fsS "$ADMIN_BASE/admin-health" | grep -q '"status":"ok"'
echo "admin /admin-health ok"
echo "all local health checks passed"
