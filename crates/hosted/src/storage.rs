#![forbid(unsafe_code)]

//! Hosted storage: trait, in-memory test implementation, and SQLite
//! persistent implementation (Stage 2, schema version 2).
//!
//! Stored categories only: public election packages, canonical ballot
//! packages (PUBLIC confidentiality by protocol design; the same bytes appear
//! in every Desktop archive), nullifiers derived from verified proofs,
//! receipts, and election state. NEVER stored: voter secret keys, Triptych
//! witnesses, wallet private keys, bearer tokens, ballot plaintext beyond
//! the protocol-public package itself.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{Connection, OptionalExtension, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElectionRecord {
    pub id: String,
    pub manifest_cbor: Vec<u8>,
    pub registry_cbor: Vec<u8>,
    pub candidate_cbor: Vec<u8>,
    pub state: String,
    pub manifest_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BallotRecord {
    pub election_id: String,
    pub receipt_id: String,
    pub package_cbor: Vec<u8>,
    pub envelope_hash_hex: String,
    pub nullifier: Vec<u8>,
    pub seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageError {
    ElectionExists,
    ElectionNotFound,
    DuplicateReceipt,
    DuplicateNullifier,
    InvalidState,
    Db,
}
impl StorageError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ElectionExists => "STORAGE_ELECTION_EXISTS",
            Self::ElectionNotFound => "STORAGE_ELECTION_NOT_FOUND",
            Self::DuplicateReceipt => "STORAGE_DUPLICATE_RECEIPT",
            Self::DuplicateNullifier => "STORAGE_DUPLICATE_NULLIFIER",
            Self::InvalidState => "STORAGE_INVALID_STATE",
            Self::Db => "STORAGE_DB_ERROR",
        }
    }
}
impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { f.write_str(self.as_str()) }
}
impl std::error::Error for StorageError {}

fn map_rusqlite(e: &rusqlite::Error) -> StorageError {
    let msg = e.to_string();
    if msg.contains("UNIQUE constraint") && msg.contains("ballots.receipt_id") { return StorageError::DuplicateReceipt; }
    if msg.contains("UNIQUE constraint") && msg.contains("nullifier") { return StorageError::DuplicateNullifier; }
    if msg.contains("UNIQUE constraint") && msg.contains("elections") { return StorageError::ElectionExists; }
    StorageError::Db
}

pub trait HostedStorage: Send + Sync {
    fn append_ballot_envelope(&self, election_id: &str, envelope: Vec<u8>);
    fn ballot_envelope_count(&self, election_id: &str) -> usize;
    fn put_election(&self, record: ElectionRecord) -> Result<(), StorageError>;
    fn get_election(&self, id: &str) -> Result<Option<ElectionRecord>, StorageError>;
    fn set_election_state(&self, id: &str, from: &str, to: &str) -> Result<bool, StorageError>;
    fn get_ballot_by_receipt(&self, election_id: &str, receipt_id: &str) -> Result<Option<BallotRecord>, StorageError>;
    fn insert_ballot(&self, record: BallotRecord) -> Result<(), StorageError>;
    fn list_ballots(&self, election_id: &str) -> Result<Vec<BallotRecord>, StorageError>;
}

#[derive(Debug, Default)]
pub struct InMemoryStorage {
    elections: Mutex<HashMap<String, ElectionRecord>>,
    ballots: Mutex<HashMap<String, Vec<BallotRecord>>>,
    legacy: Mutex<HashMap<String, Vec<Vec<u8>>>>,
}
impl InMemoryStorage {
    #[must_use] pub fn new() -> Self { Self::default() }
}
impl HostedStorage for InMemoryStorage {
    fn append_ballot_envelope(&self, election_id: &str, envelope: Vec<u8>) {
        let mut g = self.legacy.lock().unwrap_or_else(|e| e.into_inner());
        g.entry(election_id.to_owned()).or_default().push(envelope);
    }
    fn ballot_envelope_count(&self, election_id: &str) -> usize {
        let g = self.legacy.lock().unwrap_or_else(|e| e.into_inner());
        g.get(election_id).map_or(0, Vec::len)
    }
    fn put_election(&self, record: ElectionRecord) -> Result<(), StorageError> {
        let mut g = self.elections.lock().unwrap_or_else(|e| e.into_inner());
        if g.contains_key(&record.id) { return Err(StorageError::ElectionExists); }
        g.insert(record.id.clone(), record);
        Ok(())
    }
    fn get_election(&self, id: &str) -> Result<Option<ElectionRecord>, StorageError> {
        Ok(self.elections.lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned())
    }
    fn set_election_state(&self, id: &str, from: &str, to: &str) -> Result<bool, StorageError> {
        let mut g = self.elections.lock().unwrap_or_else(|e| e.into_inner());
        match g.get_mut(id) {
            None => Err(StorageError::ElectionNotFound),
            Some(r) if r.state == from => { r.state = to.to_owned(); Ok(true) }
            Some(_) => Ok(false),
        }
    }
    fn get_ballot_by_receipt(&self, election_id: &str, receipt_id: &str) -> Result<Option<BallotRecord>, StorageError> {
        let g = self.ballots.lock().unwrap_or_else(|e| e.into_inner());
        Ok(g.get(election_id).and_then(|v| v.iter().find(|b| b.receipt_id == receipt_id).cloned()))
    }
    fn insert_ballot(&self, record: BallotRecord) -> Result<(), StorageError> {
        let mut g = self.ballots.lock().unwrap_or_else(|e| e.into_inner());
        let entry = g.entry(record.election_id.clone()).or_default();
        if entry.iter().any(|b| b.receipt_id == record.receipt_id) { return Err(StorageError::DuplicateReceipt); }
        if entry.iter().any(|b| b.nullifier == record.nullifier) { return Err(StorageError::DuplicateNullifier); }
        entry.push(record);
        Ok(())
    }
    fn list_ballots(&self, election_id: &str) -> Result<Vec<BallotRecord>, StorageError> {
        let g = self.ballots.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = g.get(election_id).cloned().unwrap_or_default();
        v.sort_by_key(|b| b.seq);
        Ok(v)
    }
}

pub struct SqliteStorage { conn: Mutex<Connection> }
impl std::fmt::Debug for SqliteStorage { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str("SqliteStorage") } }

impl SqliteStorage {
    pub fn open(path: &Path) -> Result<Self, StorageError> {
        let conn = if path.to_string_lossy() == ":memory:" {
            Connection::open_in_memory().map_err(|_| StorageError::Db)?
        } else {
            if let Some(parent) = path.parent() { if !parent.as_os_str().is_empty() { std::fs::create_dir_all(parent).map_err(|_| StorageError::Db)?; } }
            Connection::open(path).map_err(|_| StorageError::Db)?
        };
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|_| StorageError::Db)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(|_| StorageError::Db)?;
        conn.pragma_update(None, "busy_timeout", 5000).map_err(|_| StorageError::Db)?;
        let storage = Self { conn: Mutex::new(conn) };
        storage.migrate()?;
        Ok(storage)
    }
    fn migrate(&self) -> Result<(), StorageError> {
        let g = self.conn.lock().unwrap_or_else(|e| e.into_inner());
        g.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS elections (id TEXT PRIMARY KEY, manifest_cbor BLOB NOT NULL, registry_cbor BLOB NOT NULL, candidate_cbor BLOB NOT NULL, state TEXT NOT NULL, manifest_hash_hex TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS ballots (election_id TEXT NOT NULL, receipt_id TEXT NOT NULL, package_cbor BLOB NOT NULL, envelope_hash_hex TEXT NOT NULL, nullifier BLOB NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY (election_id, receipt_id), UNIQUE (election_id, nullifier), FOREIGN KEY (election_id) REFERENCES elections(id));",
        ).map_err(|_| StorageError::Db)?;
        let existing: Option<String> = g.query_row("SELECT value FROM meta WHERE key = 'schema_version'", [], |r| r.get(0)).optional().map_err(|_| StorageError::Db)?;
        match existing.as_deref() {
            None => { g.execute("INSERT INTO meta (key, value) VALUES ('schema_version', '2')", []).map_err(|_| StorageError::Db)?; }
            Some("2") => {}
            Some(_) => return Err(StorageError::Db),
        }
        Ok(())
    }
    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> { self.conn.lock().unwrap_or_else(|e| e.into_inner()) }
}

impl HostedStorage for SqliteStorage {
    fn append_ballot_envelope(&self, _election_id: &str, _envelope: Vec<u8>) {}
    fn ballot_envelope_count(&self, election_id: &str) -> usize { self.list_ballots(election_id).map(|v| v.len()).unwrap_or(0) }
    fn put_election(&self, record: ElectionRecord) -> Result<(), StorageError> {
        let g = self.lock();
        g.execute("INSERT INTO elections (id, manifest_cbor, registry_cbor, candidate_cbor, state, manifest_hash_hex) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![record.id, record.manifest_cbor, record.registry_cbor, record.candidate_cbor, record.state, record.manifest_hash_hex]).map_err(|e| map_rusqlite(&e))?;
        Ok(())
    }
    fn get_election(&self, id: &str) -> Result<Option<ElectionRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g.prepare("SELECT id, manifest_cbor, registry_cbor, candidate_cbor, state, manifest_hash_hex FROM elections WHERE id = ?1").map_err(|_| StorageError::Db)?;
        let rows = stmt.query_map(params![id], |r| Ok(ElectionRecord { id: r.get(0)?, manifest_cbor: r.get(1)?, registry_cbor: r.get(2)?, candidate_cbor: r.get(3)?, state: r.get(4)?, manifest_hash_hex: r.get(5)? })).map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows { out = Some(row.map_err(|_| StorageError::Db)?); }
        Ok(out)
    }
    fn set_election_state(&self, id: &str, from: &str, to: &str) -> Result<bool, StorageError> {
        let g = self.lock();
        if g.query_row("SELECT state FROM elections WHERE id = ?1", params![id], |r| r.get::<_, String>(0)).optional().map_err(|_| StorageError::Db)?.is_none() { return Err(StorageError::ElectionNotFound); }
        let n = g.execute("UPDATE elections SET state = ?1 WHERE id = ?2 AND state = ?3", params![to, id, from]).map_err(|_| StorageError::Db)?;
        Ok(n == 1)
    }
    fn get_ballot_by_receipt(&self, election_id: &str, receipt_id: &str) -> Result<Option<BallotRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g.prepare("SELECT election_id, receipt_id, package_cbor, envelope_hash_hex, nullifier, seq FROM ballots WHERE election_id = ?1 AND receipt_id = ?2").map_err(|_| StorageError::Db)?;
        let rows = stmt.query_map(params![election_id, receipt_id], |r| Ok(BallotRecord { election_id: r.get(0)?, receipt_id: r.get(1)?, package_cbor: r.get(2)?, envelope_hash_hex: r.get(3)?, nullifier: r.get(4)?, seq: r.get::<_, i64>(5)? as u64 })).map_err(|_| StorageError::Db)?;
        let mut out = None;
        for row in rows { out = Some(row.map_err(|_| StorageError::Db)?); }
        Ok(out)
    }
    fn insert_ballot(&self, record: BallotRecord) -> Result<(), StorageError> {
        let mut g = self.lock();
        let tx = g.transaction().map_err(|_| StorageError::Db)?;
        tx.execute("INSERT INTO ballots (election_id, receipt_id, package_cbor, envelope_hash_hex, nullifier, seq) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![record.election_id, record.receipt_id, record.package_cbor, record.envelope_hash_hex, record.nullifier, record.seq as i64]).map_err(|e| map_rusqlite(&e))?;
        tx.commit().map_err(|_| StorageError::Db)?;
        Ok(())
    }
    fn list_ballots(&self, election_id: &str) -> Result<Vec<BallotRecord>, StorageError> {
        let g = self.lock();
        let mut stmt = g.prepare("SELECT election_id, receipt_id, package_cbor, envelope_hash_hex, nullifier, seq FROM ballots WHERE election_id = ?1 ORDER BY seq ASC").map_err(|_| StorageError::Db)?;
        let rows = stmt.query_map(params![election_id], |r| Ok(BallotRecord { election_id: r.get(0)?, receipt_id: r.get(1)?, package_cbor: r.get(2)?, envelope_hash_hex: r.get(3)?, nullifier: r.get(4)?, seq: r.get::<_, i64>(5)? as u64 })).map_err(|_| StorageError::Db)?;
        let mut out = Vec::new();
        for row in rows { out.push(row.map_err(|_| StorageError::Db)?); }
        Ok(out)
    }
}
