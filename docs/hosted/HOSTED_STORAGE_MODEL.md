# Hosted Storage Model (Stage 2 implementation)

## Selected backend: SQLite (embedded, single VPS)

`crates/hosted/src/storage.rs` implements the `HostedStorage` trait with:

- `SqliteStorage` (rusqlite, bundled SQLite): WAL mode, foreign keys,
  busy timeout, transactional ballot inserts. Schema version `2` stored in
  `meta`; startup migration is `CREATE TABLE IF NOT EXISTS` + version check
  (fail-closed on unknown version).
- `InMemoryStorage`: unit-test implementation with identical semantics.

### Schema

```sql
meta(key TEXT PRIMARY KEY, value TEXT)  -- schema_version = '2'
elections(id TEXT PRIMARY KEY, manifest_cbor BLOB, registry_cbor BLOB,
          candidate_cbor BLOB, state TEXT, manifest_hash_hex TEXT)
ballots(election_id TEXT, receipt_id TEXT, package_cbor BLOB,
        envelope_hash_hex TEXT, nullifier BLOB, seq INTEGER,
        PRIMARY KEY (election_id, receipt_id),
        UNIQUE (election_id, nullifier))
```

`PRIMARY KEY (election_id, receipt_id)` + `UNIQUE (election_id, nullifier)`
enforce transport idempotency and nullifier uniqueness at the database
layer, in addition to the in-memory ingestion lock and the canonical
ledger replay. Ballot insert (ballot row + receipt identity) is a single
SQLite transaction.

### What is stored / never stored

Stored: public election packages (manifest/registry/candidate canonical
bytes), canonical ballot packages, verified nullifiers, envelope hashes,
receipt ids, election state, finalized archive inputs.

Never stored: voter secret scalars, Triptych witnesses, wallet private
keys, bearer tokens, admin tokens (env only), request bodies beyond the
canonical package. The trait has no method accepting secrets. A test
(`stored_ballot_does_not_contain_voter_secret`) asserts the raw secret
scalar does not appear verbatim in the stored package.

Note on "plaintext": the only Private Ballot confidentiality mode in the
canonical protocol is `PUBLIC` (`BallotConfidentialityV1::Public`); the
canonical ballot package therefore contains the public approval payload
by protocol design, exactly as in every Desktop archive. Voter *identity*
linkage (anonymous membership) and voter *secrets* are what Hosted Mode
protects; it does not invent a confidential-ballot variant.

### File layout / backup

Single `.db` file at `$PRIVATE_BALLOT_HOSTED_DB` (default `hosted.db`).
Backup with SQLite `.backup` or by copying the file while the service is
stopped. See `deploy/README.md`.
