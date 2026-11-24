# Staging backup/recovery qualification — 2026-11-24

SCOPE: staging backup and recovery scripts only. No backend redeploy, no
Worker change, no live database restore, no authority-key rotation, no
production work, and no Mainnet transaction were performed.

## Root cause

`deploy/staging/backup.sh` and `deploy/staging/restore-verify.sh` hard-coded
`grep -qx 4` against `meta.schema_version`. The authoritative version for the
reviewed backend is **7**: `crates/hosted/src/storage.rs` writes `'7'` for a
fresh database, migrates 2–6 forward, and rejects any other value. The live
staging database was already v7, so the online backup succeeded but the stale
assertion made the scripts exit non-zero.

A second obsolete assumption exists but was **not** changed:
`crates/hosted/src/lib.rs:121` declares an unused `pub const SCHEMA_VERSION:
i64 = 5`. It has no callers, and changing it would break source/binary
provenance for the already deployed backend (`a23cef08…`) without any runtime
benefit. It should be removed in a separate reviewed source change with a
rebuild. The runtime truth remains `storage.rs`.

## Fix

- Added `deploy/staging/schema-versions.sh` with an explicit allowlist:
  `SUPPORTED_SCHEMA_VERSIONS="7"`. There is no wildcard, range, or implicit
  acceptance. `assert_supported_schema_version` fails closed with a clear
  message on an unexpected, missing, or unreadable version.
- `backup.sh` and `restore-verify.sh` now call that shared check. SQLite
  `PRAGMA integrity_check`, the critical-table check, `journal_mode=wal`
  verification, `ballots` UNIQUE-constraint verification, and 0600 backup
  permissions are preserved. Backups still use SQLite's online backup API
  (`.backup`), never a copy of live `-wal`/`-shm` sidecars.
- `deploy/README.md`, `docs/hosted/OPERATIONS.md` and the prior deployment
  record were updated. Exact operational commands are in `OPERATIONS.md`.

Supported versions: **7 only**. Versions 2–6 require a separate reviewed
migration procedure and are deliberately rejected as recovery points.

## Regression tests

`deploy/staging/test-backup-verification.sh` creates temporary fixtures only:

| Case | Expected | Result |
|---|---|---|
| v7 backup | accepted, verified | PASS |
| v7 restore-verify | accepted | PASS |
| v2 / v4 / v6 / v8 backup | rejected with explicit version error | PASS (4 cases) |
| v2 / v4 / v6 / v8 restore-verify | rejected | PASS (4 cases) |
| missing `meta.schema_version` | rejected | PASS |
| corrupted DB as backup source | rejected | PASS |
| corrupted DB as restore input | rejected | PASS |
| non-exact values `abc`, `007`, `17`, `7x` | rejected (exact token match) | PASS (4 cases) |
| failed backup leaves no valid-looking file | directory empty | PASS |

Result on the staging VPS: **18 passed, 0 failed**.

An independent review also flagged that a failed verification could leave the
`.backup` output on disk under a valid-looking name; `backup.sh` now removes
any unverified destination that *this run* created via an EXIT trap, refuses
to overwrite a same-second destination, and that behaviour is covered by the
regression above.

## Live backup verification

- Repaired `restore-verify.sh` accepted the pre-existing backup
  `hosted-20261124T143637Z.sqlite3`: `schema_version=7`, `integrity=ok`,
  `journal_mode=wal`, UNIQUE constraints present.
- Repaired `backup.sh` created fresh online backups
  `hosted-20261124T163820Z.sqlite3` and `hosted-20261124T164657Z.sqlite3`,
  both SHA-256 `c79e9bd3a5d38e6582d5853cc572fa91ca1627800886df2b5f9f586004c5a0f9`,
  mode 0600; `restore-verify.sh` accepted both.
- A zero-byte stray file literally named `hosted-*.sqlite3` (an artifact of an
  earlier shell-glob mistake) was removed; it was not a database or a record.

## Isolated restore drill

The verified backup was copied into a service-owned temporary directory under
`/var/tmp`; an isolated environment file (secrets never printed) overrode the
database path and bound a transient backend to `127.0.0.1:8878` / `:8879`.
After verification the transient unit `pb-recovery-drill.service` was stopped
and the temporary directory removed.

| Check | Live baseline | Isolated restore |
|---|---|---|
| `PRAGMA integrity_check` | ok | ok |
| `schema_version` | 7 | 7 |
| Tables / elections / ballots | 11 / 11 / 6 | 11 / 11 / 6 |
| Election + finalized binding identity hash | `8a22a05e96e74bf51474d5220085d75cc3ba73431ae2e2d010d8e0effcffc996` | identical |
| `ballots` UNIQUE constraint | present | present |
| `/api/v1/status` | 63 bytes, `a07ddacb…` | identical |
| Finalized `results` | 333 bytes, `af725b48…` | identical |
| Finalized `archive` | 4710 bytes, `05003d8f…` | identical |
| `public-package` | 1332 bytes, `d39c894a…` | identical |
| `anchor-payload` | 6133 bytes, `de79c5b4…` | identical |

Live database SHA-256 was `89a2318c…` both before and after the drill; live
`private-ballot-hosted.service` stayed active and its binary remained
`a23cef08…`. No election record was written or deleted.

## Security review

No credentials, authority keys, database records, or backup bytes are
committed. Scripts fail closed on unexpected or corrupt input. The drill used
a transient unit on alternate loopback ports and never stopped the live
service. No unrelated service, Worker, DNS, or chain state was touched.

## Conclusion

The staging backup/recovery system is **qualified for operational recovery**
using the commands in `docs/hosted/OPERATIONS.md`. A real restore still
requires explicit operator authorization and a stop/restore/start sequence;
it was not performed as part of this qualification.
