# VPS packaging (Stage 2 preparation - DO NOT DEPLOY from this stage)

Release build:

    cargo build --release -p tari-cc-private-ballot-hosted

Binary: `private-ballot-hosted`. It defaults to `127.0.0.1:8788` and SQLite
at `$PRIVATE_BALLOT_HOSTED_DB` (default `hosted.db` in the working
directory). See `deploy/hosted.env.example` for the full config schema and
`deploy/private-ballot-hosted.service` for a systemd unit template.

Backup: stop the service (or use `sqlite3 hosted.db ".backup '/path/to/backup.db'"`)
and copy the single `.db` file (plus `-wal`/`-shm` sidecars only while
running). Restore by placing the file at the configured path and starting
the service; schema version is stored in `meta` (`schema_version=2`) and
migrations run on startup.

Migrations: none required in Stage 2 beyond the startup `CREATE TABLE IF NOT
EXISTS` + schema-version check. A future migration must be additive and
tested against a copy of a Stage 2 database.

Graceful shutdown: Ctrl-C / SIGTERM via `tokio::signal::ctrl_c` and axum
graceful shutdown. Health: `GET /health`, `GET /api/v1/status`.

Nothing in this directory deploys anything. Stage 3 performs the actual
VPS + Cloudflare deployment.
