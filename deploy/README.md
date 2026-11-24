# VPS packaging (Stage 2 preparation - DO NOT DEPLOY from this stage)

Release build:

    cargo build --release -p tari-cc-private-ballot-hosted

Binary: `private-ballot-hosted`. It defaults to `127.0.0.1:8788` and SQLite
at `$PRIVATE_BALLOT_HOSTED_DB` (default `hosted.db` in the working
directory). See `deploy/hosted.env.example` for the full config schema and
`deploy/private-ballot-hosted.service` for a systemd unit template.

Backup: use SQLite's online backup API (`sqlite3 "$DB" ".backup '$DEST'"`)
against the live WAL database; never copy the live `-wal`/`-shm` sidecars by
hand. `deploy/staging/backup.sh` does this and then verifies integrity,
the explicit schema allowlist, and critical tables. Restore by placing a
verified backup at `PRIVATE_BALLOT_HOSTED_DB` and starting the service;
the schema version is stored in `meta` and is currently `7`.

Migrations: `crates/hosted/src/storage.rs` writes schema v7 for a fresh
database. Versions 2–6 are migration inputs only; they are NOT accepted as
verified recovery points because they require a separate migration step.
`deploy/staging/schema-versions.sh` is the explicit allowlist (currently `7`)
and `deploy/staging/test-backup-verification.sh` covers supported,
unsupported, missing-version and corrupted databases. A future migration
must remain additive, be added to the allowlist only with a reviewed recovery
qualification, and be tested against a copy of an existing database.

Graceful shutdown: Ctrl-C / SIGTERM via `tokio::signal::ctrl_c` and axum
graceful shutdown. Health: `GET /health`, `GET /api/v1/status`.

Nothing in this directory deploys anything. Stage 3 performs the actual
VPS + Cloudflare deployment.
