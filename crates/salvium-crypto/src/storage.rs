//! SQLCipher-backed wallet storage engine.
//!
//! Provides encrypted, WAL-mode SQLite storage for wallet outputs, transactions,
//! key images, and sync state. Accessed via opaque handles through the FFI boundary.
//!
//! Only compiled on native targets (`cfg(not(target_arch = "wasm32"))`).

use rusqlite::{Connection, params, OptionalExtension};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// ─── Handle Management ─────────────────────────────────────────────────────

static NEXT_HANDLE: AtomicU32 = AtomicU32::new(1);

fn dbs() -> &'static Mutex<HashMap<u32, WalletDb>> {
    use std::sync::OnceLock;
    static DBS: OnceLock<Mutex<HashMap<u32, WalletDb>>> = OnceLock::new();
    DBS.get_or_init(|| Mutex::new(HashMap::new()))
}

// ─── Schema DDL ─────────────────────────────────────────────────────────────

const SCHEMA_DDL: &str = "
CREATE TABLE IF NOT EXISTS outputs (
  key_image       TEXT PRIMARY KEY,
  public_key      TEXT,
  tx_hash         TEXT NOT NULL,
  output_index    INTEGER NOT NULL DEFAULT 0,
  global_index    INTEGER,
  asset_type_index INTEGER,
  block_height    INTEGER,
  block_timestamp INTEGER,
  amount          TEXT NOT NULL DEFAULT '0',
  asset_type      TEXT NOT NULL DEFAULT 'SAL',
  commitment      TEXT,
  mask            TEXT,
  subaddr_major   INTEGER NOT NULL DEFAULT 0,
  subaddr_minor   INTEGER NOT NULL DEFAULT 0,
  is_carrot       INTEGER NOT NULL DEFAULT 0,
  carrot_ephemeral_pubkey TEXT,
  carrot_shared_secret    TEXT,
  carrot_enote_type       INTEGER,
  is_spent        INTEGER NOT NULL DEFAULT 0,
  spent_height    INTEGER,
  spent_tx_hash   TEXT,
  unlock_time     TEXT NOT NULL DEFAULT '0',
  tx_type         INTEGER NOT NULL DEFAULT 3,
  tx_pub_key      TEXT,
  is_frozen       INTEGER NOT NULL DEFAULT 0,
  created_at      INTEGER,
  updated_at      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_outputs_height ON outputs(block_height);
CREATE INDEX IF NOT EXISTS idx_outputs_spent ON outputs(is_spent);
CREATE INDEX IF NOT EXISTS idx_outputs_asset ON outputs(asset_type);

CREATE TABLE IF NOT EXISTS transactions (
  tx_hash           TEXT PRIMARY KEY,
  tx_pub_key        TEXT,
  block_height      INTEGER,
  block_timestamp   INTEGER,
  confirmations     INTEGER NOT NULL DEFAULT 0,
  in_pool           INTEGER NOT NULL DEFAULT 0,
  is_failed         INTEGER NOT NULL DEFAULT 0,
  is_confirmed      INTEGER NOT NULL DEFAULT 0,
  is_incoming       INTEGER NOT NULL DEFAULT 0,
  is_outgoing       INTEGER NOT NULL DEFAULT 0,
  incoming_amount   TEXT NOT NULL DEFAULT '0',
  outgoing_amount   TEXT NOT NULL DEFAULT '0',
  fee               TEXT NOT NULL DEFAULT '0',
  change_amount     TEXT NOT NULL DEFAULT '0',
  transfers         TEXT,
  payment_id        TEXT,
  unlock_time       TEXT NOT NULL DEFAULT '0',
  tx_type           INTEGER NOT NULL DEFAULT 3,
  asset_type        TEXT NOT NULL DEFAULT 'SAL',
  is_miner_tx       INTEGER NOT NULL DEFAULT 0,
  is_protocol_tx    INTEGER NOT NULL DEFAULT 0,
  note              TEXT NOT NULL DEFAULT '',
  created_at        INTEGER,
  updated_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_txs_height ON transactions(block_height);

CREATE TABLE IF NOT EXISTS key_images (
  key_image    TEXT PRIMARY KEY,
  tx_hash      TEXT,
  output_index INTEGER,
  is_spent     INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT
);

CREATE TABLE IF NOT EXISTS stakes (
  stake_tx_hash     TEXT PRIMARY KEY,
  stake_height      INTEGER,
  stake_timestamp   INTEGER,
  amount_staked     TEXT NOT NULL DEFAULT '0',
  fee               TEXT NOT NULL DEFAULT '0',
  asset_type        TEXT NOT NULL DEFAULT 'SAL',
  change_output_key TEXT,
  status            TEXT NOT NULL DEFAULT 'locked',
  return_tx_hash    TEXT,
  return_height     INTEGER,
  return_timestamp  INTEGER,
  return_amount     TEXT NOT NULL DEFAULT '0',
  created_at        INTEGER,
  updated_at        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_stakes_status ON stakes(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_stakes_output_key ON stakes(change_output_key) WHERE change_output_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS address_book (
  row_id          INTEGER PRIMARY KEY AUTOINCREMENT,
  address         TEXT NOT NULL,
  label           TEXT NOT NULL DEFAULT '',
  description     TEXT NOT NULL DEFAULT '',
  payment_id      TEXT NOT NULL DEFAULT '',
  created_at      INTEGER,
  updated_at      INTEGER
);
";

// ─── Data Models ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputRow {
    pub key_image: Option<String>,
    pub public_key: Option<String>,
    pub tx_hash: String,
    #[serde(default)]
    pub output_index: i64,
    pub global_index: Option<i64>,
    pub asset_type_index: Option<i64>,
    pub block_height: Option<i64>,
    pub block_timestamp: Option<i64>,
    #[serde(default = "default_zero_str")]
    pub amount: String,
    #[serde(default = "default_sal")]
    pub asset_type: String,
    pub commitment: Option<String>,
    pub mask: Option<String>,
    #[serde(default)]
    pub subaddress_index: SubaddressIndex,
    #[serde(default)]
    pub is_carrot: bool,
    pub carrot_ephemeral_pubkey: Option<String>,
    pub carrot_shared_secret: Option<String>,
    pub carrot_enote_type: Option<i64>,
    #[serde(default)]
    pub is_spent: bool,
    pub spent_height: Option<i64>,
    pub spent_tx_hash: Option<String>,
    #[serde(default = "default_zero_str")]
    pub unlock_time: String,
    #[serde(default = "default_tx_type", deserialize_with = "deserialize_tx_type")]
    pub tx_type: i64,
    pub tx_pub_key: Option<String>,
    #[serde(default)]
    pub is_frozen: bool,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SubaddressIndex {
    #[serde(default)]
    pub major: i64,
    #[serde(default)]
    pub minor: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransactionRow {
    pub tx_hash: String,
    pub tx_pub_key: Option<String>,
    pub block_height: Option<i64>,
    pub block_timestamp: Option<i64>,
    #[serde(default)]
    pub confirmations: i64,
    #[serde(default)]
    pub in_pool: bool,
    #[serde(default)]
    pub is_failed: bool,
    #[serde(default)]
    pub is_confirmed: bool,
    #[serde(default)]
    pub is_incoming: bool,
    #[serde(default)]
    pub is_outgoing: bool,
    #[serde(default = "default_zero_str")]
    pub incoming_amount: String,
    #[serde(default = "default_zero_str")]
    pub outgoing_amount: String,
    #[serde(default = "default_zero_str")]
    pub fee: String,
    #[serde(default = "default_zero_str")]
    pub change_amount: String,
    pub transfers: Option<serde_json::Value>,
    pub payment_id: Option<String>,
    #[serde(default = "default_zero_str")]
    pub unlock_time: String,
    #[serde(default = "default_tx_type", deserialize_with = "deserialize_tx_type")]
    pub tx_type: i64,
    #[serde(default = "default_sal")]
    pub asset_type: String,
    #[serde(default)]
    pub is_miner_tx: bool,
    #[serde(default)]
    pub is_protocol_tx: bool,
    #[serde(default)]
    pub note: String,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputQuery {
    pub is_spent: Option<bool>,
    pub is_frozen: Option<bool>,
    pub asset_type: Option<String>,
    pub tx_type: Option<i64>,
    pub account_index: Option<i64>,
    pub subaddress_index: Option<i64>,
    pub min_amount: Option<String>,
    pub max_amount: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxQuery {
    pub is_incoming: Option<bool>,
    pub is_outgoing: Option<bool>,
    pub is_confirmed: Option<bool>,
    pub in_pool: Option<bool>,
    pub tx_type: Option<i64>,
    pub min_height: Option<i64>,
    pub max_height: Option<i64>,
    pub tx_hash: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResult {
    pub balance: String,
    pub unlocked_balance: String,
    pub locked_balance: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakeRow {
    pub stake_tx_hash: String,
    pub stake_height: Option<i64>,
    pub stake_timestamp: Option<i64>,
    #[serde(default = "default_zero_str")]
    pub amount_staked: String,
    #[serde(default = "default_zero_str")]
    pub fee: String,
    #[serde(default = "default_sal")]
    pub asset_type: String,
    pub change_output_key: Option<String>,
    #[serde(default = "default_locked")]
    pub status: String,
    pub return_tx_hash: Option<String>,
    pub return_height: Option<i64>,
    pub return_timestamp: Option<i64>,
    #[serde(default = "default_zero_str")]
    pub return_amount: String,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressBookEntry {
    pub row_id: i64,
    pub address: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub payment_id: String,
    pub created_at: Option<i64>,
    pub updated_at: Option<i64>,
}

fn default_zero_str() -> String { "0".to_string() }
fn default_sal() -> String { "SAL".to_string() }
fn default_tx_type() -> i64 { 3 }
fn default_locked() -> String { "locked".to_string() }

/// Deserialize tx_type from either an integer or a string name.
/// Accepts: 0-8 (integers), "miner", "protocol", "transfer", "convert", "burn", "stake", "return", "audit"
fn deserialize_tx_type<'de, D>(deserializer: D) -> Result<i64, D::Error>
where D: serde::Deserializer<'de>
{
    use serde::de;

    struct TxTypeVisitor;
    impl<'de> de::Visitor<'de> for TxTypeVisitor {
        type Value = i64;
        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("an integer or tx type name string")
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<i64, E> { Ok(v) }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<i64, E> { Ok(v as i64) }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<i64, E> { Ok(v as i64) }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<i64, E> {
            match v {
                "miner" => Ok(1),
                "protocol" => Ok(2),
                "transfer" => Ok(3),
                "convert" => Ok(4),
                "burn" => Ok(5),
                "stake" => Ok(6),
                "return" => Ok(7),
                "audit" => Ok(8),
                _ => v.parse::<i64>().map_err(de::Error::custom),
            }
        }
    }
    deserializer.deserialize_any(TxTypeVisitor)
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

// ─── WalletDb ───────────────────────────────────────────────────────────────

pub struct WalletDb {
    conn: Connection,
}

impl WalletDb {
    pub fn open(path: &str, key: &[u8]) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
        // Set SQLCipher key (hex-encoded)
        let hex_key = hex::encode(key);
        conn.execute_batch(&format!("PRAGMA key = \"x'{hex_key}'\";"))?;
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
        conn.execute_batch("PRAGMA foreign_keys = OFF;")?;
        Self::create_tables(&conn)?;
        Ok(WalletDb { conn })
    }

    fn create_tables(conn: &Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch(SCHEMA_DDL)?;
        Ok(())
    }

    // ── Output Operations ───────────────────────────────────────────────

    pub fn put_output(&self, row: &OutputRow) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        self.conn.execute(
            "INSERT OR REPLACE INTO outputs (
                key_image, public_key, tx_hash, output_index, global_index,
                asset_type_index, block_height, block_timestamp, amount, asset_type,
                commitment, mask, subaddr_major, subaddr_minor, is_carrot,
                carrot_ephemeral_pubkey, carrot_shared_secret, carrot_enote_type,
                is_spent, spent_height, spent_tx_hash, unlock_time, tx_type,
                tx_pub_key, is_frozen, created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18,
                ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27
            )",
            params![
                row.key_image, row.public_key, row.tx_hash, row.output_index,
                row.global_index, row.asset_type_index, row.block_height,
                row.block_timestamp, row.amount, row.asset_type,
                row.commitment, row.mask, row.subaddress_index.major,
                row.subaddress_index.minor, row.is_carrot as i64,
                row.carrot_ephemeral_pubkey, row.carrot_shared_secret,
                row.carrot_enote_type, row.is_spent as i64,
                row.spent_height, row.spent_tx_hash, row.unlock_time,
                row.tx_type, row.tx_pub_key, row.is_frozen as i64,
                row.created_at.unwrap_or(now), now
            ],
        )?;

        // Also upsert into key_images table
        if let Some(ref ki) = row.key_image {
            self.conn.execute(
                "INSERT OR REPLACE INTO key_images (key_image, tx_hash, output_index, is_spent)
                 VALUES (?1, ?2, ?3, ?4)",
                params![ki, row.tx_hash, row.output_index, row.is_spent as i64],
            )?;
        }
        Ok(())
    }

    pub fn get_output(&self, key_image: &str) -> Result<Option<OutputRow>, rusqlite::Error> {
        self.conn.query_row(
            "SELECT key_image, public_key, tx_hash, output_index, global_index,
                    asset_type_index, block_height, block_timestamp, amount, asset_type,
                    commitment, mask, subaddr_major, subaddr_minor, is_carrot,
                    carrot_ephemeral_pubkey, carrot_shared_secret, carrot_enote_type,
                    is_spent, spent_height, spent_tx_hash, unlock_time, tx_type,
                    tx_pub_key, is_frozen, created_at, updated_at
             FROM outputs WHERE key_image = ?1",
            params![key_image],
            |r| Ok(row_to_output(r)),
        ).optional()
    }

    pub fn get_outputs(&self, query: &OutputQuery) -> Result<Vec<OutputRow>, rusqlite::Error> {
        let mut sql = String::from(
            "SELECT key_image, public_key, tx_hash, output_index, global_index,
                    asset_type_index, block_height, block_timestamp, amount, asset_type,
                    commitment, mask, subaddr_major, subaddr_minor, is_carrot,
                    carrot_ephemeral_pubkey, carrot_shared_secret, carrot_enote_type,
                    is_spent, spent_height, spent_tx_hash, unlock_time, tx_type,
                    tx_pub_key, is_frozen, created_at, updated_at
             FROM outputs WHERE 1=1"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(is_spent) = query.is_spent {
            sql.push_str(&format!(" AND is_spent = ?{}", param_values.len() + 1));
            param_values.push(Box::new(is_spent as i64));
        }
        if let Some(is_frozen) = query.is_frozen {
            sql.push_str(&format!(" AND is_frozen = ?{}", param_values.len() + 1));
            param_values.push(Box::new(is_frozen as i64));
        }
        if let Some(ref asset_type) = query.asset_type {
            sql.push_str(&format!(" AND asset_type = ?{}", param_values.len() + 1));
            param_values.push(Box::new(asset_type.clone()));
        }
        if let Some(tx_type) = query.tx_type {
            sql.push_str(&format!(" AND tx_type = ?{}", param_values.len() + 1));
            param_values.push(Box::new(tx_type));
        }
        if let Some(account_index) = query.account_index {
            sql.push_str(&format!(" AND subaddr_major = ?{}", param_values.len() + 1));
            param_values.push(Box::new(account_index));
        }
        if let Some(subaddress_index) = query.subaddress_index {
            sql.push_str(&format!(" AND subaddr_minor = ?{}", param_values.len() + 1));
            param_values.push(Box::new(subaddress_index));
        }

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |r| Ok(row_to_output(r)))?;

        let mut results = Vec::new();
        for row in rows {
            let output = row?;
            // Filter by amount in Rust since SQLite stores amounts as text
            if let Some(ref min_amount) = query.min_amount {
                if let (Ok(amt), Ok(min)) = (output.amount.parse::<u128>(), min_amount.parse::<u128>()) {
                    if amt < min { continue; }
                }
            }
            if let Some(ref max_amount) = query.max_amount {
                if let (Ok(amt), Ok(max)) = (output.amount.parse::<u128>(), max_amount.parse::<u128>()) {
                    if amt > max { continue; }
                }
            }
            results.push(output);
        }
        Ok(results)
    }

    pub fn mark_spent(&self, key_image: &str, spending_tx: &str, spent_height: i64) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        self.conn.execute(
            "UPDATE outputs SET is_spent = 1, spent_tx_hash = ?1, spent_height = ?2, updated_at = ?3
             WHERE key_image = ?4",
            params![spending_tx, spent_height, now, key_image],
        )?;
        self.conn.execute(
            "UPDATE key_images SET is_spent = 1 WHERE key_image = ?1",
            params![key_image],
        )?;
        Ok(())
    }

    pub fn mark_unspent(&self, key_image: &str) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        self.conn.execute(
            "UPDATE outputs SET is_spent = 0, spent_tx_hash = NULL, spent_height = NULL, updated_at = ?1 WHERE key_image = ?2",
            params![now, key_image],
        )?;
        self.conn.execute(
            "UPDATE key_images SET is_spent = 0 WHERE key_image = ?1",
            params![key_image],
        )?;
        Ok(())
    }

    // ── Transaction Operations ──────────────────────────────────────────

    pub fn put_tx(&self, row: &TransactionRow) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        let transfers_json = row.transfers.as_ref()
            .map(|v| serde_json::to_string(v).unwrap_or_default());
        self.conn.execute(
            "INSERT OR REPLACE INTO transactions (
                tx_hash, tx_pub_key, block_height, block_timestamp,
                confirmations, in_pool, is_failed, is_confirmed,
                is_incoming, is_outgoing, incoming_amount, outgoing_amount,
                fee, change_amount, transfers, payment_id, unlock_time,
                tx_type, asset_type, is_miner_tx, is_protocol_tx, note,
                created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20,
                ?21, ?22, ?23, ?24
            )",
            params![
                row.tx_hash, row.tx_pub_key, row.block_height, row.block_timestamp,
                row.confirmations, row.in_pool as i64, row.is_failed as i64,
                row.is_confirmed as i64, row.is_incoming as i64, row.is_outgoing as i64,
                row.incoming_amount, row.outgoing_amount, row.fee, row.change_amount,
                transfers_json, row.payment_id, row.unlock_time,
                row.tx_type, row.asset_type, row.is_miner_tx as i64,
                row.is_protocol_tx as i64, row.note,
                row.created_at.unwrap_or(now), now
            ],
        )?;
        Ok(())
    }

    pub fn get_tx(&self, tx_hash: &str) -> Result<Option<TransactionRow>, rusqlite::Error> {
        self.conn.query_row(
            "SELECT tx_hash, tx_pub_key, block_height, block_timestamp,
                    confirmations, in_pool, is_failed, is_confirmed,
                    is_incoming, is_outgoing, incoming_amount, outgoing_amount,
                    fee, change_amount, transfers, payment_id, unlock_time,
                    tx_type, asset_type, is_miner_tx, is_protocol_tx, note,
                    created_at, updated_at
             FROM transactions WHERE tx_hash = ?1",
            params![tx_hash],
            |r| Ok(row_to_tx(r)),
        ).optional()
    }

    pub fn get_txs(&self, query: &TxQuery) -> Result<Vec<TransactionRow>, rusqlite::Error> {
        let mut sql = String::from(
            "SELECT tx_hash, tx_pub_key, block_height, block_timestamp,
                    confirmations, in_pool, is_failed, is_confirmed,
                    is_incoming, is_outgoing, incoming_amount, outgoing_amount,
                    fee, change_amount, transfers, payment_id, unlock_time,
                    tx_type, asset_type, is_miner_tx, is_protocol_tx, note,
                    created_at, updated_at
             FROM transactions WHERE 1=1"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(is_incoming) = query.is_incoming {
            sql.push_str(&format!(" AND is_incoming = ?{}", param_values.len() + 1));
            param_values.push(Box::new(is_incoming as i64));
        }
        if let Some(is_outgoing) = query.is_outgoing {
            sql.push_str(&format!(" AND is_outgoing = ?{}", param_values.len() + 1));
            param_values.push(Box::new(is_outgoing as i64));
        }
        if let Some(is_confirmed) = query.is_confirmed {
            sql.push_str(&format!(" AND is_confirmed = ?{}", param_values.len() + 1));
            param_values.push(Box::new(is_confirmed as i64));
        }
        if let Some(in_pool) = query.in_pool {
            sql.push_str(&format!(" AND in_pool = ?{}", param_values.len() + 1));
            param_values.push(Box::new(in_pool as i64));
        }
        if let Some(tx_type) = query.tx_type {
            sql.push_str(&format!(" AND tx_type = ?{}", param_values.len() + 1));
            param_values.push(Box::new(tx_type));
        }
        if let Some(min_height) = query.min_height {
            sql.push_str(&format!(" AND block_height >= ?{}", param_values.len() + 1));
            param_values.push(Box::new(min_height));
        }
        if let Some(max_height) = query.max_height {
            sql.push_str(&format!(" AND block_height <= ?{}", param_values.len() + 1));
            param_values.push(Box::new(max_height));
        }
        if let Some(ref tx_hash) = query.tx_hash {
            sql.push_str(&format!(" AND tx_hash = ?{}", param_values.len() + 1));
            param_values.push(Box::new(tx_hash.clone()));
        }
        sql.push_str(" ORDER BY block_height DESC");

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |r| Ok(row_to_tx(r)))?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    // ── Sync State ──────────────────────────────────────────────────────

    pub fn get_sync_height(&self) -> Result<i64, rusqlite::Error> {
        let result: Option<String> = self.conn.query_row(
            "SELECT value FROM meta WHERE key = 'sync_height'",
            [],
            |r| r.get(0),
        ).optional()?;
        Ok(result.and_then(|s| s.parse().ok()).unwrap_or(0))
    }

    pub fn set_sync_height(&self, height: i64) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('sync_height', ?1)",
            params![height.to_string()],
        )?;
        Ok(())
    }

    pub fn put_block_hash(&self, height: i64, hash: &str) -> Result<(), rusqlite::Error> {
        let meta_key = format!("block:{}", height);
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
            params![meta_key, hash],
        )?;
        Ok(())
    }

    pub fn get_block_hash(&self, height: i64) -> Result<Option<String>, rusqlite::Error> {
        let meta_key = format!("block:{}", height);
        self.conn.query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![meta_key],
            |r| r.get(0),
        ).optional()
    }

    // ── Rollback ────────────────────────────────────────────────────────

    pub fn rollback(&self, height: i64) -> Result<(), rusqlite::Error> {
        let tx = self.conn.unchecked_transaction()?;

        // Delete outputs above height
        tx.execute("DELETE FROM outputs WHERE block_height > ?1", params![height])?;

        // Delete transactions above height
        tx.execute("DELETE FROM transactions WHERE block_height > ?1", params![height])?;

        // Delete block hashes above height
        tx.execute("DELETE FROM meta WHERE key LIKE 'block:%' AND CAST(SUBSTR(key, 7) AS INTEGER) > ?1", params![height])?;

        // Unspend outputs that were spent above height
        let now = now_millis();
        tx.execute(
            "UPDATE outputs SET is_spent = 0, spent_tx_hash = NULL, spent_height = NULL, updated_at = ?1
             WHERE is_spent = 1 AND spent_height > ?2",
            params![now, height],
        )?;

        // Update key_images to match
        tx.execute(
            "UPDATE key_images SET is_spent = 0 WHERE key_image IN (
                SELECT key_image FROM outputs WHERE is_spent = 0
            )",
            [],
        )?;

        // Update sync height
        tx.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('sync_height', ?1)",
            params![height.to_string()],
        )?;

        tx.commit()
    }

    // ── Clear ───────────────────────────────────────────────────────────

    pub fn clear(&self) -> Result<(), rusqlite::Error> {
        self.conn.execute_batch(
            "DELETE FROM outputs;
             DELETE FROM transactions;
             DELETE FROM key_images;
             DELETE FROM meta;
             DELETE FROM address_book;"
        )
    }

    // ── Asset Types ────────────────────────────────────────────────────

    /// Returns the distinct asset types present in the outputs table.
    pub fn get_asset_types(&self) -> Result<Vec<String>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT asset_type FROM outputs ORDER BY asset_type"
        )?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    // ── Balance Computation ─────────────────────────────────────────────

    pub fn get_balance(&self, current_height: i64, asset_type: &str, account_index: i32) -> Result<BalanceResult, rusqlite::Error> {
        let mut sql = String::from(
            "SELECT amount, block_height, unlock_time, tx_type, subaddr_major
             FROM outputs WHERE is_spent = 0 AND is_frozen = 0 AND asset_type = ?1"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
        param_values.push(Box::new(asset_type.to_string()));

        if account_index >= 0 {
            sql.push_str(&format!(" AND subaddr_major = ?{}", param_values.len() + 1));
            param_values.push(Box::new(account_index as i64));
        }

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |r| {
            Ok((
                r.get::<_, String>(0)?,      // amount
                r.get::<_, Option<i64>>(1)?,  // block_height
                r.get::<_, String>(2)?,       // unlock_time
                r.get::<_, i64>(3)?,          // tx_type
            ))
        })?;

        let mut total: u128 = 0;
        let mut unlocked: u128 = 0;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u128;

        for row in rows {
            let (amount_str, block_height, unlock_time_str, tx_type) = row?;
            let amount: u128 = amount_str.parse().unwrap_or(0);
            total += amount;

            if is_unlocked(current_height, block_height, &unlock_time_str, tx_type, now_secs) {
                unlocked += amount;
            }
        }

        let locked = total - unlocked;
        Ok(BalanceResult {
            balance: total.to_string(),
            unlocked_balance: unlocked.to_string(),
            locked_balance: locked.to_string(),
        })
    }

    /// Get balances for ALL asset types in the wallet. Returns a map of
    /// asset_type -> BalanceResult, computed in a single pass.
    pub fn get_all_balances(&self, current_height: i64, account_index: i32) -> Result<HashMap<String, BalanceResult>, rusqlite::Error> {
        let mut sql = String::from(
            "SELECT asset_type, amount, block_height, unlock_time, tx_type
             FROM outputs WHERE is_spent = 0 AND is_frozen = 0"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if account_index >= 0 {
            sql.push_str(&format!(" AND subaddr_major = ?{}", param_values.len() + 1));
            param_values.push(Box::new(account_index as i64));
        }

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u128;

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |r| {
            Ok((
                r.get::<_, String>(0)?,       // asset_type
                r.get::<_, String>(1)?,       // amount
                r.get::<_, Option<i64>>(2)?,  // block_height
                r.get::<_, String>(3)?,       // unlock_time
                r.get::<_, i64>(4)?,          // tx_type
            ))
        })?;

        let mut balances: HashMap<String, (u128, u128)> = HashMap::new();

        for row in rows {
            let (asset_type, amount_str, block_height, unlock_time_str, tx_type) = row?;
            let amount: u128 = amount_str.parse().unwrap_or(0);
            let entry = balances.entry(asset_type).or_insert((0, 0));
            entry.0 += amount;
            if is_unlocked(current_height, block_height, &unlock_time_str, tx_type, now_secs) {
                entry.1 += amount;
            }
        }

        let mut result = HashMap::new();
        for (asset_type, (total, unlocked)) in balances {
            result.insert(asset_type, BalanceResult {
                balance: total.to_string(),
                unlocked_balance: unlocked.to_string(),
                locked_balance: (total - unlocked).to_string(),
            });
        }
        Ok(result)
    }

    // ── Stake Operations ────────────────────────────────────────────────

    pub fn put_stake(&self, row: &StakeRow) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        self.conn.execute(
            "INSERT OR REPLACE INTO stakes (
                stake_tx_hash, stake_height, stake_timestamp,
                amount_staked, fee, asset_type, change_output_key,
                status, return_tx_hash, return_height, return_timestamp,
                return_amount, created_at, updated_at
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
            )",
            params![
                row.stake_tx_hash, row.stake_height, row.stake_timestamp,
                row.amount_staked, row.fee, row.asset_type, row.change_output_key,
                row.status, row.return_tx_hash, row.return_height, row.return_timestamp,
                row.return_amount, row.created_at.unwrap_or(now), now
            ],
        )?;
        Ok(())
    }

    pub fn get_stake(&self, stake_tx_hash: &str) -> Result<Option<StakeRow>, rusqlite::Error> {
        self.conn.query_row(
            "SELECT stake_tx_hash, stake_height, stake_timestamp,
                    amount_staked, fee, asset_type, change_output_key,
                    status, return_tx_hash, return_height, return_timestamp,
                    return_amount, created_at, updated_at
             FROM stakes WHERE stake_tx_hash = ?1",
            params![stake_tx_hash],
            |r| Ok(StakeRow {
                stake_tx_hash: r.get(0)?,
                stake_height: r.get(1)?,
                stake_timestamp: r.get(2)?,
                amount_staked: r.get(3)?,
                fee: r.get(4)?,
                asset_type: r.get(5)?,
                change_output_key: r.get(6)?,
                status: r.get(7)?,
                return_tx_hash: r.get(8)?,
                return_height: r.get(9)?,
                return_timestamp: r.get(10)?,
                return_amount: r.get(11)?,
                created_at: r.get(12)?,
                updated_at: r.get(13)?,
            }),
        ).optional()
    }

    pub fn get_stakes(&self, status: Option<&str>, asset_type: Option<&str>) -> Result<Vec<StakeRow>, rusqlite::Error> {
        let mut sql = String::from(
            "SELECT stake_tx_hash, stake_height, stake_timestamp,
                    amount_staked, fee, asset_type, change_output_key,
                    status, return_tx_hash, return_height, return_timestamp,
                    return_amount, created_at, updated_at
             FROM stakes WHERE 1=1"
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(s) = status {
            sql.push_str(&format!(" AND status = ?{}", param_values.len() + 1));
            param_values.push(Box::new(s.to_string()));
        }
        if let Some(at) = asset_type {
            sql.push_str(&format!(" AND asset_type = ?{}", param_values.len() + 1));
            param_values.push(Box::new(at.to_string()));
        }

        sql.push_str(" ORDER BY stake_height ASC");

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |r| {
            Ok(StakeRow {
                stake_tx_hash: r.get(0)?,
                stake_height: r.get(1)?,
                stake_timestamp: r.get(2)?,
                amount_staked: r.get(3)?,
                fee: r.get(4)?,
                asset_type: r.get(5)?,
                change_output_key: r.get(6)?,
                status: r.get(7)?,
                return_tx_hash: r.get(8)?,
                return_height: r.get(9)?,
                return_timestamp: r.get(10)?,
                return_amount: r.get(11)?,
                created_at: r.get(12)?,
                updated_at: r.get(13)?,
            })
        })?;

        let mut results = Vec::new();
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    pub fn get_stake_by_output_key(&self, change_output_key: &str) -> Result<Option<StakeRow>, rusqlite::Error> {
        self.conn.query_row(
            "SELECT stake_tx_hash, stake_height, stake_timestamp,
                    amount_staked, fee, asset_type, change_output_key,
                    status, return_tx_hash, return_height, return_timestamp,
                    return_amount, created_at, updated_at
             FROM stakes WHERE change_output_key = ?1",
            params![change_output_key],
            |r| Ok(StakeRow {
                stake_tx_hash: r.get(0)?,
                stake_height: r.get(1)?,
                stake_timestamp: r.get(2)?,
                amount_staked: r.get(3)?,
                fee: r.get(4)?,
                asset_type: r.get(5)?,
                change_output_key: r.get(6)?,
                status: r.get(7)?,
                return_tx_hash: r.get(8)?,
                return_height: r.get(9)?,
                return_timestamp: r.get(10)?,
                return_amount: r.get(11)?,
                created_at: r.get(12)?,
                updated_at: r.get(13)?,
            }),
        ).optional()
    }

    pub fn mark_stake_returned(
        &self,
        stake_tx_hash: &str,
        return_tx_hash: &str,
        return_height: i64,
        return_timestamp: i64,
        return_amount: &str,
    ) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        self.conn.execute(
            "UPDATE stakes SET status = 'returned', return_tx_hash = ?1, return_height = ?2,
             return_timestamp = ?3, return_amount = ?4, updated_at = ?5
             WHERE stake_tx_hash = ?6",
            params![return_tx_hash, return_height, return_timestamp, return_amount, now, stake_tx_hash],
        )?;
        Ok(())
    }

    pub fn delete_stakes_above(&self, height: i64) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        // Delete stakes created above the height
        self.conn.execute(
            "DELETE FROM stakes WHERE stake_height > ?1",
            params![height],
        )?;
        // Undo returns above the height (revert to 'locked')
        self.conn.execute(
            "UPDATE stakes SET status = 'locked', return_tx_hash = NULL, return_height = NULL,
             return_timestamp = NULL, return_amount = '0', updated_at = ?1
             WHERE return_height > ?2",
            params![now, height],
        )?;
        Ok(())
    }

    // ── Transaction Notes ────────────────────────────────────────────────

    /// Set a user-provided note on a transaction.
    pub fn set_tx_note(&self, tx_hash: &str, note: &str) -> Result<(), rusqlite::Error> {
        let now = now_millis();
        self.conn.execute(
            "UPDATE transactions SET note = ?1, updated_at = ?2 WHERE tx_hash = ?3",
            params![note, now, tx_hash],
        )?;
        Ok(())
    }

    /// Get notes for a list of transaction hashes.
    /// Returns a map of tx_hash → note (only for txs that exist).
    pub fn get_tx_notes(&self, tx_hashes: &[&str]) -> Result<HashMap<String, String>, rusqlite::Error> {
        let mut result = HashMap::new();
        for hash in tx_hashes {
            if let Some(row) = self.get_tx(hash)? {
                result.insert(row.tx_hash, row.note);
            }
        }
        Ok(result)
    }

    // ── Address Book ─────────────────────────────────────────────────────

    /// Add an entry to the address book. Returns the row_id.
    pub fn add_address_book_entry(
        &self,
        address: &str,
        label: &str,
        description: &str,
        payment_id: &str,
    ) -> Result<i64, rusqlite::Error> {
        let now = now_millis();
        self.conn.execute(
            "INSERT INTO address_book (address, label, description, payment_id, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![address, label, description, payment_id, now, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Get all address book entries.
    pub fn get_address_book(&self) -> Result<Vec<AddressBookEntry>, rusqlite::Error> {
        let mut stmt = self.conn.prepare(
            "SELECT row_id, address, label, description, payment_id, created_at, updated_at
             FROM address_book ORDER BY row_id"
        )?;
        let rows = stmt.query_map([], |r| Ok(row_to_address_book(r)))?;
        let mut result = Vec::new();
        for row in rows {
            result.push(row?);
        }
        Ok(result)
    }

    /// Get a single address book entry by row_id.
    pub fn get_address_book_entry(&self, row_id: i64) -> Result<Option<AddressBookEntry>, rusqlite::Error> {
        self.conn.query_row(
            "SELECT row_id, address, label, description, payment_id, created_at, updated_at
             FROM address_book WHERE row_id = ?1",
            params![row_id],
            |r| Ok(row_to_address_book(r)),
        ).optional()
    }

    /// Edit an address book entry.
    pub fn edit_address_book_entry(
        &self,
        row_id: i64,
        address: Option<&str>,
        label: Option<&str>,
        description: Option<&str>,
        payment_id: Option<&str>,
    ) -> Result<bool, rusqlite::Error> {
        let now = now_millis();
        let mut sets = vec!["updated_at = ?1".to_string()];
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(now)];

        if let Some(addr) = address {
            param_values.push(Box::new(addr.to_string()));
            sets.push(format!("address = ?{}", param_values.len()));
        }
        if let Some(lbl) = label {
            param_values.push(Box::new(lbl.to_string()));
            sets.push(format!("label = ?{}", param_values.len()));
        }
        if let Some(desc) = description {
            param_values.push(Box::new(desc.to_string()));
            sets.push(format!("description = ?{}", param_values.len()));
        }
        if let Some(pid) = payment_id {
            param_values.push(Box::new(pid.to_string()));
            sets.push(format!("payment_id = ?{}", param_values.len()));
        }

        param_values.push(Box::new(row_id));
        let sql = format!(
            "UPDATE address_book SET {} WHERE row_id = ?{}",
            sets.join(", "),
            param_values.len()
        );

        let params_ref: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|b| b.as_ref()).collect();
        let changed = self.conn.execute(&sql, params_ref.as_slice())?;
        Ok(changed > 0)
    }

    /// Delete an address book entry by row_id.
    pub fn delete_address_book_entry(&self, row_id: i64) -> Result<bool, rusqlite::Error> {
        let changed = self.conn.execute(
            "DELETE FROM address_book WHERE row_id = ?1",
            params![row_id],
        )?;
        Ok(changed > 0)
    }
}

// ─── Unlock Logic ───────────────────────────────────────────────────────────

fn is_unlocked(current_height: i64, block_height: Option<i64>, unlock_time_str: &str, tx_type: i64, now_secs: u128) -> bool {
    let bh = match block_height {
        Some(h) => h,
        None => return false,
    };

    // Coinbase (tx_type 1=miner, 2=protocol): requires 60 confirmations
    if tx_type == 1 || tx_type == 2 {
        return (current_height - bh) >= 60;
    }

    let unlock_time: u128 = unlock_time_str.parse().unwrap_or(0);

    if unlock_time == 0 {
        // Standard: 10 confirmations
        return (current_height - bh) >= 10;
    }

    if unlock_time < 500_000_000 {
        // Block height threshold
        return current_height >= unlock_time as i64;
    }

    // Unix timestamp threshold
    now_secs >= unlock_time
}

// ─── Row Mapping Helpers ────────────────────────────────────────────────────

fn row_to_output(r: &rusqlite::Row<'_>) -> OutputRow {
    OutputRow {
        key_image: r.get(0).ok(),
        public_key: r.get(1).ok(),
        tx_hash: r.get::<_, String>(2).unwrap_or_default(),
        output_index: r.get(3).unwrap_or(0),
        global_index: r.get(4).ok(),
        asset_type_index: r.get(5).ok(),
        block_height: r.get(6).ok(),
        block_timestamp: r.get(7).ok(),
        amount: r.get::<_, String>(8).unwrap_or_else(|_| "0".into()),
        asset_type: r.get::<_, String>(9).unwrap_or_else(|_| "SAL".into()),
        commitment: r.get(10).ok(),
        mask: r.get(11).ok(),
        subaddress_index: SubaddressIndex {
            major: r.get(12).unwrap_or(0),
            minor: r.get(13).unwrap_or(0),
        },
        is_carrot: r.get::<_, i64>(14).unwrap_or(0) != 0,
        carrot_ephemeral_pubkey: r.get(15).ok(),
        carrot_shared_secret: r.get(16).ok(),
        carrot_enote_type: r.get(17).ok(),
        is_spent: r.get::<_, i64>(18).unwrap_or(0) != 0,
        spent_height: r.get(19).ok(),
        spent_tx_hash: r.get(20).ok(),
        unlock_time: r.get::<_, String>(21).unwrap_or_else(|_| "0".into()),
        tx_type: r.get(22).unwrap_or(3),
        tx_pub_key: r.get(23).ok(),
        is_frozen: r.get::<_, i64>(24).unwrap_or(0) != 0,
        created_at: r.get(25).ok(),
        updated_at: r.get(26).ok(),
    }
}

fn row_to_tx(r: &rusqlite::Row<'_>) -> TransactionRow {
    let transfers_str: Option<String> = r.get(14).ok();
    let transfers = transfers_str.and_then(|s| serde_json::from_str(&s).ok());

    TransactionRow {
        tx_hash: r.get::<_, String>(0).unwrap_or_default(),
        tx_pub_key: r.get(1).ok(),
        block_height: r.get(2).ok(),
        block_timestamp: r.get(3).ok(),
        confirmations: r.get(4).unwrap_or(0),
        in_pool: r.get::<_, i64>(5).unwrap_or(0) != 0,
        is_failed: r.get::<_, i64>(6).unwrap_or(0) != 0,
        is_confirmed: r.get::<_, i64>(7).unwrap_or(0) != 0,
        is_incoming: r.get::<_, i64>(8).unwrap_or(0) != 0,
        is_outgoing: r.get::<_, i64>(9).unwrap_or(0) != 0,
        incoming_amount: r.get::<_, String>(10).unwrap_or_else(|_| "0".into()),
        outgoing_amount: r.get::<_, String>(11).unwrap_or_else(|_| "0".into()),
        fee: r.get::<_, String>(12).unwrap_or_else(|_| "0".into()),
        change_amount: r.get::<_, String>(13).unwrap_or_else(|_| "0".into()),
        transfers,
        payment_id: r.get(15).ok(),
        unlock_time: r.get::<_, String>(16).unwrap_or_else(|_| "0".into()),
        tx_type: r.get(17).unwrap_or(3),
        asset_type: r.get::<_, String>(18).unwrap_or_else(|_| "SAL".into()),
        is_miner_tx: r.get::<_, i64>(19).unwrap_or(0) != 0,
        is_protocol_tx: r.get::<_, i64>(20).unwrap_or(0) != 0,
        note: r.get::<_, String>(21).unwrap_or_default(),
        created_at: r.get(22).ok(),
        updated_at: r.get(23).ok(),
    }
}

fn row_to_address_book(r: &rusqlite::Row<'_>) -> AddressBookEntry {
    AddressBookEntry {
        row_id: r.get(0).unwrap_or(0),
        address: r.get::<_, String>(1).unwrap_or_default(),
        label: r.get::<_, String>(2).unwrap_or_default(),
        description: r.get::<_, String>(3).unwrap_or_default(),
        payment_id: r.get::<_, String>(4).unwrap_or_default(),
        created_at: r.get(5).ok(),
        updated_at: r.get(6).ok(),
    }
}

// ─── Public API (called from FFI) ──────────────────────────────────────────

pub fn storage_open(path: &str, key: &[u8]) -> Result<u32, String> {
    let db = WalletDb::open(path, key).map_err(|e| e.to_string())?;
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
    dbs().lock().unwrap().insert(handle, db);
    Ok(handle)
}

pub fn storage_close(handle: u32) -> Result<(), String> {
    dbs().lock().unwrap().remove(&handle)
        .ok_or_else(|| "invalid handle".to_string())?;
    Ok(())
}

pub fn with_db<F, R>(handle: u32, f: F) -> Result<R, String>
where
    F: FnOnce(&WalletDb) -> Result<R, rusqlite::Error>,
{
    let map = dbs().lock().unwrap();
    let db = map.get(&handle).ok_or_else(|| "invalid handle".to_string())?;
    f(db).map_err(|e| e.to_string())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    static TEST_ID: AtomicU32 = AtomicU32::new(0);

    fn test_db() -> (u32, String) {
        let id = TEST_ID.fetch_add(1, Ordering::SeqCst);
        let path = format!("/tmp/salvium_test_{}.db", id);
        // Clean up any leftover files from previous runs
        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(format!("{}-wal", &path));
        let _ = fs::remove_file(format!("{}-shm", &path));
        let key = [0x42u8; 32];
        let handle = storage_open(&path, &key).expect("open failed");
        (handle, path)
    }

    fn cleanup(handle: u32, path: &str) {
        let _ = storage_close(handle);
        let _ = fs::remove_file(path);
        // WAL/SHM files
        let _ = fs::remove_file(format!("{}-wal", path));
        let _ = fs::remove_file(format!("{}-shm", path));
    }

    #[test]
    fn test_open_close() {
        let (handle, path) = test_db();
        assert!(handle > 0);
        cleanup(handle, &path);
    }

    #[test]
    fn test_put_get_output() {
        let (handle, path) = test_db();
        let output = OutputRow {
            key_image: Some("ki_abc123".into()),
            public_key: Some("pk_xyz".into()),
            tx_hash: "tx_001".into(),
            output_index: 0,
            global_index: Some(100),
            asset_type_index: None,
            block_height: Some(1000),
            block_timestamp: Some(1700000000),
            amount: "500000000000".into(),
            asset_type: "SAL".into(),
            commitment: None,
            mask: None,
            subaddress_index: SubaddressIndex { major: 0, minor: 0 },
            is_carrot: false,
            carrot_ephemeral_pubkey: None,
            carrot_shared_secret: None,
            carrot_enote_type: None,
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: "0".into(),
            tx_type: 3,
            tx_pub_key: None,
            is_frozen: false,
            created_at: None,
            updated_at: None,
        };

        with_db(handle, |db| db.put_output(&output)).unwrap();
        let got = with_db(handle, |db| db.get_output("ki_abc123")).unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.tx_hash, "tx_001");
        assert_eq!(got.amount, "500000000000");
        assert_eq!(got.block_height, Some(1000));

        cleanup(handle, &path);
    }

    #[test]
    fn test_mark_spent() {
        let (handle, path) = test_db();
        let output = OutputRow {
            key_image: Some("ki_spend".into()),
            public_key: None,
            tx_hash: "tx_002".into(),
            output_index: 0,
            global_index: None,
            asset_type_index: None,
            block_height: Some(500),
            block_timestamp: None,
            amount: "1000".into(),
            asset_type: "SAL".into(),
            commitment: None,
            mask: None,
            subaddress_index: SubaddressIndex::default(),
            is_carrot: false,
            carrot_ephemeral_pubkey: None,
            carrot_shared_secret: None,
            carrot_enote_type: None,
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: "0".into(),
            tx_type: 3,
            tx_pub_key: None,
            is_frozen: false,
            created_at: None,
            updated_at: None,
        };

        with_db(handle, |db| db.put_output(&output)).unwrap();
        with_db(handle, |db| db.mark_spent("ki_spend", "tx_spend", 600)).unwrap();
        let got = with_db(handle, |db| db.get_output("ki_spend")).unwrap().unwrap();
        assert!(got.is_spent);
        assert_eq!(got.spent_tx_hash, Some("tx_spend".into()));
        assert_eq!(got.spent_height, Some(600));

        cleanup(handle, &path);
    }

    #[test]
    fn test_put_get_tx() {
        let (handle, path) = test_db();
        let tx = TransactionRow {
            tx_hash: "tx_100".into(),
            tx_pub_key: None,
            block_height: Some(2000),
            block_timestamp: Some(1700001000),
            confirmations: 10,
            in_pool: false,
            is_failed: false,
            is_confirmed: true,
            is_incoming: true,
            is_outgoing: false,
            incoming_amount: "1000000".into(),
            outgoing_amount: "0".into(),
            fee: "100".into(),
            change_amount: "0".into(),
            transfers: None,
            payment_id: None,
            unlock_time: "0".into(),
            tx_type: 3,
            asset_type: "SAL".into(),
            is_miner_tx: false,
            is_protocol_tx: false,
            note: "test".into(),
            created_at: None,
            updated_at: None,
        };

        with_db(handle, |db| db.put_tx(&tx)).unwrap();
        let got = with_db(handle, |db| db.get_tx("tx_100")).unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.incoming_amount, "1000000");
        assert!(got.is_confirmed);
        assert!(got.is_incoming);

        cleanup(handle, &path);
    }

    #[test]
    fn test_sync_height() {
        let (handle, path) = test_db();

        let h = with_db(handle, |db| db.get_sync_height()).unwrap();
        assert_eq!(h, 0);

        with_db(handle, |db| db.set_sync_height(12345)).unwrap();
        let h = with_db(handle, |db| db.get_sync_height()).unwrap();
        assert_eq!(h, 12345);

        cleanup(handle, &path);
    }

    #[test]
    fn test_block_hashes() {
        let (handle, path) = test_db();

        with_db(handle, |db| db.put_block_hash(100, "hash100")).unwrap();
        with_db(handle, |db| db.put_block_hash(101, "hash101")).unwrap();

        let h = with_db(handle, |db| db.get_block_hash(100)).unwrap();
        assert_eq!(h, Some("hash100".into()));

        let h = with_db(handle, |db| db.get_block_hash(999)).unwrap();
        assert_eq!(h, None);

        cleanup(handle, &path);
    }

    #[test]
    fn test_rollback() {
        let (handle, path) = test_db();

        // Insert outputs at heights 100, 200, 300
        for h in [100, 200, 300] {
            let output = OutputRow {
                key_image: Some(format!("ki_{}", h)),
                public_key: None,
                tx_hash: format!("tx_{}", h),
                output_index: 0,
                global_index: None,
                asset_type_index: None,
                block_height: Some(h),
                block_timestamp: None,
                amount: "1000".into(),
                asset_type: "SAL".into(),
                commitment: None,
                mask: None,
                subaddress_index: SubaddressIndex::default(),
                is_carrot: false,
                carrot_ephemeral_pubkey: None,
                carrot_shared_secret: None,
                carrot_enote_type: None,
                is_spent: false,
                spent_height: None,
                spent_tx_hash: None,
                unlock_time: "0".into(),
                tx_type: 3,
                tx_pub_key: None,
                is_frozen: false,
                created_at: None,
                updated_at: None,
            };
            with_db(handle, |db| db.put_output(&output)).unwrap();
        }

        // Mark ki_100 as spent at height 250
        with_db(handle, |db| db.mark_spent("ki_100", "tx_spend", 250)).unwrap();

        // Insert block hashes
        for h in [100, 200, 300] {
            with_db(handle, |db| db.put_block_hash(h, &format!("hash_{}", h))).unwrap();
        }

        // Rollback to height 150
        with_db(handle, |db| db.rollback(150)).unwrap();

        // ki_100 should still exist, but ki_200 and ki_300 should be gone
        let o100 = with_db(handle, |db| db.get_output("ki_100")).unwrap();
        assert!(o100.is_some());
        let o200 = with_db(handle, |db| db.get_output("ki_200")).unwrap();
        assert!(o200.is_none());
        let o300 = with_db(handle, |db| db.get_output("ki_300")).unwrap();
        assert!(o300.is_none());

        // ki_100 was spent at 250 (> 150), so it should be unspent now
        let o100 = o100.unwrap();
        assert!(!o100.is_spent);
        assert_eq!(o100.spent_tx_hash, None);

        // Block hash at 100 should exist, 200/300 should not
        let bh100 = with_db(handle, |db| db.get_block_hash(100)).unwrap();
        assert_eq!(bh100, Some("hash_100".into()));
        let bh200 = with_db(handle, |db| db.get_block_hash(200)).unwrap();
        assert_eq!(bh200, None);

        cleanup(handle, &path);
    }

    #[test]
    fn test_balance() {
        let (handle, path) = test_db();

        // Insert unspent outputs
        for i in 0..3 {
            let output = OutputRow {
                key_image: Some(format!("ki_bal_{}", i)),
                public_key: None,
                tx_hash: format!("tx_bal_{}", i),
                output_index: 0,
                global_index: None,
                asset_type_index: None,
                block_height: Some(100),
                block_timestamp: None,
                amount: "1000000000".into(),
                asset_type: "SAL".into(),
                commitment: None,
                mask: None,
                subaddress_index: SubaddressIndex::default(),
                is_carrot: false,
                carrot_ephemeral_pubkey: None,
                carrot_shared_secret: None,
                carrot_enote_type: None,
                is_spent: false,
                spent_height: None,
                spent_tx_hash: None,
                unlock_time: "0".into(),
                tx_type: 3,
                tx_pub_key: None,
                is_frozen: false,
                created_at: None,
                updated_at: None,
            };
            with_db(handle, |db| db.put_output(&output)).unwrap();
        }

        // Height 105: only 5 confs, needs 10 → all locked
        let bal = with_db(handle, |db| db.get_balance(105, "SAL", -1)).unwrap();
        assert_eq!(bal.balance, "3000000000");
        assert_eq!(bal.unlocked_balance, "0");
        assert_eq!(bal.locked_balance, "3000000000");

        // Height 110: exactly 10 confs → all unlocked
        let bal = with_db(handle, |db| db.get_balance(110, "SAL", -1)).unwrap();
        assert_eq!(bal.balance, "3000000000");
        assert_eq!(bal.unlocked_balance, "3000000000");
        assert_eq!(bal.locked_balance, "0");

        cleanup(handle, &path);
    }

    #[test]
    fn test_balance_coinbase() {
        let (handle, path) = test_db();

        let output = OutputRow {
            key_image: Some("ki_cb".into()),
            public_key: None,
            tx_hash: "tx_cb".into(),
            output_index: 0,
            global_index: None,
            asset_type_index: None,
            block_height: Some(100),
            block_timestamp: None,
            amount: "5000000000".into(),
            asset_type: "SAL".into(),
            commitment: None,
            mask: None,
            subaddress_index: SubaddressIndex::default(),
            is_carrot: false,
            carrot_ephemeral_pubkey: None,
            carrot_shared_secret: None,
            carrot_enote_type: None,
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: "60".into(), // coinbase unlock
            tx_type: 1, // miner
            tx_pub_key: None,
            is_frozen: false,
            created_at: None,
            updated_at: None,
        };
        with_db(handle, |db| db.put_output(&output)).unwrap();

        // Height 150: only 50 confs, coinbase needs 60
        let bal = with_db(handle, |db| db.get_balance(150, "SAL", -1)).unwrap();
        assert_eq!(bal.unlocked_balance, "0");

        // Height 160: 60 confs → unlocked
        let bal = with_db(handle, |db| db.get_balance(160, "SAL", -1)).unwrap();
        assert_eq!(bal.unlocked_balance, "5000000000");

        cleanup(handle, &path);
    }

    #[test]
    fn test_clear() {
        let (handle, path) = test_db();

        let output = OutputRow {
            key_image: Some("ki_clear".into()),
            public_key: None,
            tx_hash: "tx_clear".into(),
            output_index: 0,
            global_index: None,
            asset_type_index: None,
            block_height: Some(100),
            block_timestamp: None,
            amount: "1000".into(),
            asset_type: "SAL".into(),
            commitment: None,
            mask: None,
            subaddress_index: SubaddressIndex::default(),
            is_carrot: false,
            carrot_ephemeral_pubkey: None,
            carrot_shared_secret: None,
            carrot_enote_type: None,
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: "0".into(),
            tx_type: 3,
            tx_pub_key: None,
            is_frozen: false,
            created_at: None,
            updated_at: None,
        };
        with_db(handle, |db| db.put_output(&output)).unwrap();
        with_db(handle, |db| db.set_sync_height(5000)).unwrap();

        with_db(handle, |db| db.clear()).unwrap();

        let got = with_db(handle, |db| db.get_output("ki_clear")).unwrap();
        assert!(got.is_none());
        let h = with_db(handle, |db| db.get_sync_height()).unwrap();
        assert_eq!(h, 0);

        cleanup(handle, &path);
    }

    #[test]
    fn test_get_outputs_filtered() {
        let (handle, path) = test_db();

        for i in 0..5 {
            let output = OutputRow {
                key_image: Some(format!("ki_filter_{}", i)),
                public_key: None,
                tx_hash: format!("tx_filter_{}", i),
                output_index: 0,
                global_index: None,
                asset_type_index: None,
                block_height: Some(100 + i),
                block_timestamp: None,
                amount: format!("{}", (i + 1) * 1000),
                asset_type: if i < 3 { "SAL".into() } else { "STAKE".into() },
                commitment: None,
                mask: None,
                subaddress_index: SubaddressIndex::default(),
                is_carrot: false,
                carrot_ephemeral_pubkey: None,
                carrot_shared_secret: None,
                carrot_enote_type: None,
                is_spent: i == 0, // first one is spent
                spent_height: if i == 0 { Some(200) } else { None },
                spent_tx_hash: if i == 0 { Some("tx_spend".into()) } else { None },
                unlock_time: "0".into(),
                tx_type: 3,
                tx_pub_key: None,
                is_frozen: false,
                created_at: None,
                updated_at: None,
            };
            with_db(handle, |db| db.put_output(&output)).unwrap();
        }

        // Query unspent SAL
        let query = OutputQuery {
            is_spent: Some(false),
            is_frozen: None,
            asset_type: Some("SAL".into()),
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 2); // ki_filter_1 and ki_filter_2

        cleanup(handle, &path);
    }

    // ── Helpers for concise output/tx/stake construction ──────────────────

    fn make_output(key_image: &str, height: i64, amount: &str, asset_type: &str) -> OutputRow {
        OutputRow {
            key_image: Some(key_image.into()),
            public_key: None,
            tx_hash: format!("tx_{}", key_image),
            output_index: 0,
            global_index: None,
            asset_type_index: None,
            block_height: Some(height),
            block_timestamp: None,
            amount: amount.into(),
            asset_type: asset_type.into(),
            commitment: None,
            mask: None,
            subaddress_index: SubaddressIndex::default(),
            is_carrot: false,
            carrot_ephemeral_pubkey: None,
            carrot_shared_secret: None,
            carrot_enote_type: None,
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: "0".into(),
            tx_type: 3,
            tx_pub_key: None,
            is_frozen: false,
            created_at: None,
            updated_at: None,
        }
    }

    fn make_tx(tx_hash: &str, height: i64) -> TransactionRow {
        TransactionRow {
            tx_hash: tx_hash.into(),
            tx_pub_key: None,
            block_height: Some(height),
            block_timestamp: None,
            confirmations: 0,
            in_pool: false,
            is_failed: false,
            is_confirmed: true,
            is_incoming: true,
            is_outgoing: false,
            incoming_amount: "1000".into(),
            outgoing_amount: "0".into(),
            fee: "0".into(),
            change_amount: "0".into(),
            transfers: None,
            payment_id: None,
            unlock_time: "0".into(),
            tx_type: 3,
            asset_type: "SAL".into(),
            is_miner_tx: false,
            is_protocol_tx: false,
            note: String::new(),
            created_at: None,
            updated_at: None,
        }
    }

    fn make_stake(stake_tx_hash: &str, height: i64, amount: &str) -> StakeRow {
        StakeRow {
            stake_tx_hash: stake_tx_hash.into(),
            stake_height: Some(height),
            stake_timestamp: Some(1700000000),
            amount_staked: amount.into(),
            fee: "100".into(),
            asset_type: "SAL".into(),
            change_output_key: Some(format!("outkey_{}", stake_tx_hash)),
            status: "locked".into(),
            return_tx_hash: None,
            return_height: None,
            return_timestamp: None,
            return_amount: "0".into(),
            created_at: None,
            updated_at: None,
        }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Wallet-reorg tests (ported from wallet-reorg.test.js)
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_rollback_multi_height_cascade() {
        let (handle, path) = test_db();

        // Insert outputs at heights 5, 10, 15
        for h in [5, 10, 15] {
            let output = make_output(&format!("ki_h{}", h), h, "1000", "SAL");
            with_db(handle, |db| db.put_output(&output)).unwrap();
        }

        // Rollback to height 10
        with_db(handle, |db| db.rollback(10)).unwrap();

        // Height 5 and 10 outputs survive
        let o5 = with_db(handle, |db| db.get_output("ki_h5")).unwrap();
        assert!(o5.is_some(), "output at height 5 should survive rollback to 10");

        let o10 = with_db(handle, |db| db.get_output("ki_h10")).unwrap();
        assert!(o10.is_some(), "output at height 10 should survive rollback to 10");

        // Height 15 output removed
        let o15 = with_db(handle, |db| db.get_output("ki_h15")).unwrap();
        assert!(o15.is_none(), "output at height 15 should be removed by rollback to 10");

        cleanup(handle, &path);
    }

    #[test]
    fn test_rollback_unspend() {
        let (handle, path) = test_db();

        // Insert output at height 5
        let output = make_output("ki_unspend", 5, "500", "SAL");
        with_db(handle, |db| db.put_output(&output)).unwrap();

        // Mark spent at height 12
        with_db(handle, |db| db.mark_spent("ki_unspend", "spending_tx", 12)).unwrap();

        // Verify it is spent
        let got = with_db(handle, |db| db.get_output("ki_unspend")).unwrap().unwrap();
        assert!(got.is_spent);
        assert_eq!(got.spent_height, Some(12));

        // Rollback to height 10 -> spent at 12 should be undone
        with_db(handle, |db| db.rollback(10)).unwrap();

        let got = with_db(handle, |db| db.get_output("ki_unspend")).unwrap().unwrap();
        assert!(!got.is_spent, "output should be unspent after rollback past spent_height");
        assert_eq!(got.spent_tx_hash, None);
        assert_eq!(got.spent_height, None);

        cleanup(handle, &path);
    }

    #[test]
    fn test_block_hash_mismatch_detection() {
        let (handle, path) = test_db();

        // Put a hash at height 100
        with_db(handle, |db| db.put_block_hash(100, "hash_original")).unwrap();
        let h = with_db(handle, |db| db.get_block_hash(100)).unwrap();
        assert_eq!(h, Some("hash_original".into()));

        // Put a different hash at the same height (simulates reorg detection)
        with_db(handle, |db| db.put_block_hash(100, "hash_reorged")).unwrap();
        let h = with_db(handle, |db| db.get_block_hash(100)).unwrap();
        assert_eq!(h, Some("hash_reorged".into()), "last hash written should win (INSERT OR REPLACE)");

        cleanup(handle, &path);
    }

    #[test]
    fn test_rollback_stakes() {
        let (handle, path) = test_db();

        // Insert stakes at heights 5, 10, 15
        for h in [5i64, 10, 15] {
            let stake = make_stake(&format!("stake_h{}", h), h, "10000");
            with_db(handle, |db| db.put_stake(&stake)).unwrap();
        }

        // Mark stake at height 5 as returned at height 12
        with_db(handle, |db| {
            db.mark_stake_returned("stake_h5", "return_tx", 12, 1700001000, "9900")
        }).unwrap();

        // Delete stakes above height 10
        with_db(handle, |db| db.delete_stakes_above(10)).unwrap();

        // Stake at height 5 should still exist
        let s5 = with_db(handle, |db| db.get_stake("stake_h5")).unwrap();
        assert!(s5.is_some(), "stake at height 5 should survive");
        // Its return was at height 12 (> 10), so it should be reverted to locked
        let s5 = s5.unwrap();
        assert_eq!(s5.status, "locked", "stake return above rollback height should be reverted");
        assert_eq!(s5.return_tx_hash, None);
        assert_eq!(s5.return_height, None);
        assert_eq!(s5.return_amount, "0");

        // Stake at height 10 should still exist
        let s10 = with_db(handle, |db| db.get_stake("stake_h10")).unwrap();
        assert!(s10.is_some(), "stake at height 10 should survive");
        assert_eq!(s10.unwrap().status, "locked");

        // Stake at height 15 should be deleted
        let s15 = with_db(handle, |db| db.get_stake("stake_h15")).unwrap();
        assert!(s15.is_none(), "stake at height 15 should be deleted");

        cleanup(handle, &path);
    }

    #[test]
    fn test_rollback_preserves_below() {
        let (handle, path) = test_db();

        // Insert outputs, txs, and block hashes at heights 50 and 100
        let o50 = make_output("ki_50", 50, "1000", "SAL");
        let o100 = make_output("ki_100rb", 100, "2000", "SAL");
        with_db(handle, |db| db.put_output(&o50)).unwrap();
        with_db(handle, |db| db.put_output(&o100)).unwrap();

        let tx50 = make_tx("tx_50", 50);
        let tx100 = make_tx("tx_100rb", 100);
        with_db(handle, |db| db.put_tx(&tx50)).unwrap();
        with_db(handle, |db| db.put_tx(&tx100)).unwrap();

        with_db(handle, |db| db.put_block_hash(50, "bh_50")).unwrap();
        with_db(handle, |db| db.put_block_hash(100, "bh_100")).unwrap();

        with_db(handle, |db| db.set_sync_height(100)).unwrap();

        // Rollback to height 100 (nothing above)
        with_db(handle, |db| db.rollback(100)).unwrap();

        // Everything at 100 and below should remain intact
        let got_o50 = with_db(handle, |db| db.get_output("ki_50")).unwrap();
        assert!(got_o50.is_some());
        let got_o100 = with_db(handle, |db| db.get_output("ki_100rb")).unwrap();
        assert!(got_o100.is_some());

        let got_tx50 = with_db(handle, |db| db.get_tx("tx_50")).unwrap();
        assert!(got_tx50.is_some());
        let got_tx100 = with_db(handle, |db| db.get_tx("tx_100rb")).unwrap();
        assert!(got_tx100.is_some());

        let got_bh50 = with_db(handle, |db| db.get_block_hash(50)).unwrap();
        assert_eq!(got_bh50, Some("bh_50".into()));
        let got_bh100 = with_db(handle, |db| db.get_block_hash(100)).unwrap();
        assert_eq!(got_bh100, Some("bh_100".into()));

        let height = with_db(handle, |db| db.get_sync_height()).unwrap();
        assert_eq!(height, 100);

        cleanup(handle, &path);
    }

    #[test]
    fn test_rollback_txs() {
        let (handle, path) = test_db();

        // Insert transactions at different heights
        for h in [5i64, 10, 15, 20] {
            let tx = make_tx(&format!("tx_rb_{}", h), h);
            with_db(handle, |db| db.put_tx(&tx)).unwrap();
        }

        // Rollback to height 12
        with_db(handle, |db| db.rollback(12)).unwrap();

        // Txs at 5, 10 should survive
        let t5 = with_db(handle, |db| db.get_tx("tx_rb_5")).unwrap();
        assert!(t5.is_some(), "tx at height 5 should survive rollback to 12");
        let t10 = with_db(handle, |db| db.get_tx("tx_rb_10")).unwrap();
        assert!(t10.is_some(), "tx at height 10 should survive rollback to 12");

        // Txs at 15, 20 should be removed
        let t15 = with_db(handle, |db| db.get_tx("tx_rb_15")).unwrap();
        assert!(t15.is_none(), "tx at height 15 should be removed by rollback to 12");
        let t20 = with_db(handle, |db| db.get_tx("tx_rb_20")).unwrap();
        assert!(t20.is_none(), "tx at height 20 should be removed by rollback to 12");

        cleanup(handle, &path);
    }

    // ══════════════════════════════════════════════════════════════════════
    // Wallet-store tests (ported from wallet-store.test.js)
    // ══════════════════════════════════════════════════════════════════════

    #[test]
    fn test_mark_unspent() {
        let (handle, path) = test_db();

        let output = make_output("ki_mu", 100, "5000", "SAL");
        with_db(handle, |db| db.put_output(&output)).unwrap();

        // Mark spent
        with_db(handle, |db| db.mark_spent("ki_mu", "spend_tx", 200)).unwrap();
        let got = with_db(handle, |db| db.get_output("ki_mu")).unwrap().unwrap();
        assert!(got.is_spent);
        assert_eq!(got.spent_tx_hash, Some("spend_tx".into()));
        assert_eq!(got.spent_height, Some(200));

        // Mark unspent
        with_db(handle, |db| db.mark_unspent("ki_mu")).unwrap();
        let got = with_db(handle, |db| db.get_output("ki_mu")).unwrap().unwrap();
        assert!(!got.is_spent, "output should be unspent after mark_unspent");
        assert_eq!(got.spent_tx_hash, None);
        assert_eq!(got.spent_height, None);

        cleanup(handle, &path);
    }

    #[test]
    fn test_full_field_validation() {
        let (handle, path) = test_db();

        let output = OutputRow {
            key_image: Some("ki_full".into()),
            public_key: Some("pk_full".into()),
            tx_hash: "tx_full".into(),
            output_index: 7,
            global_index: Some(42),
            asset_type_index: Some(3),
            block_height: Some(9999),
            block_timestamp: Some(1700000000),
            amount: "123456789012345".into(),
            asset_type: "SAL1".into(),
            commitment: Some("commit_abc".into()),
            mask: Some("mask_def".into()),
            subaddress_index: SubaddressIndex { major: 2, minor: 5 },
            is_carrot: true,
            carrot_ephemeral_pubkey: Some("carrot_eph_key".into()),
            carrot_shared_secret: Some("carrot_secret".into()),
            carrot_enote_type: Some(1),
            is_spent: false,
            spent_height: None,
            spent_tx_hash: None,
            unlock_time: "500".into(),
            tx_type: 4,
            tx_pub_key: Some("tx_pub_full".into()),
            is_frozen: true,
            created_at: Some(1700000000),
            updated_at: None,
        };

        with_db(handle, |db| db.put_output(&output)).unwrap();
        let got = with_db(handle, |db| db.get_output("ki_full")).unwrap().unwrap();

        assert_eq!(got.key_image, Some("ki_full".into()));
        assert_eq!(got.public_key, Some("pk_full".into()));
        assert_eq!(got.tx_hash, "tx_full");
        assert_eq!(got.output_index, 7);
        assert_eq!(got.global_index, Some(42));
        assert_eq!(got.asset_type_index, Some(3));
        assert_eq!(got.block_height, Some(9999));
        assert_eq!(got.block_timestamp, Some(1700000000));
        assert_eq!(got.amount, "123456789012345");
        assert_eq!(got.asset_type, "SAL1");
        assert_eq!(got.commitment, Some("commit_abc".into()));
        assert_eq!(got.mask, Some("mask_def".into()));
        assert_eq!(got.subaddress_index.major, 2);
        assert_eq!(got.subaddress_index.minor, 5);
        assert!(got.is_carrot);
        assert_eq!(got.carrot_ephemeral_pubkey, Some("carrot_eph_key".into()));
        assert_eq!(got.carrot_shared_secret, Some("carrot_secret".into()));
        assert_eq!(got.carrot_enote_type, Some(1));
        assert!(!got.is_spent);
        assert_eq!(got.spent_height, None);
        assert_eq!(got.spent_tx_hash, None);
        assert_eq!(got.unlock_time, "500");
        assert_eq!(got.tx_type, 4);
        assert_eq!(got.tx_pub_key, Some("tx_pub_full".into()));
        assert!(got.is_frozen);
        assert_eq!(got.created_at, Some(1700000000));
        assert!(got.updated_at.is_some());

        cleanup(handle, &path);
    }

    #[test]
    fn test_multi_asset_balance() {
        let (handle, path) = test_db();

        // Insert SAL outputs
        let o1 = make_output("ki_sal_1", 100, "1000000", "SAL");
        let o2 = make_output("ki_sal_2", 100, "2000000", "SAL");
        with_db(handle, |db| db.put_output(&o1)).unwrap();
        with_db(handle, |db| db.put_output(&o2)).unwrap();

        // Insert SAL1 outputs
        let o3 = make_output("ki_sal1_1", 100, "5000000", "SAL1");
        let o4 = make_output("ki_sal1_2", 100, "3000000", "SAL1");
        with_db(handle, |db| db.put_output(&o3)).unwrap();
        with_db(handle, |db| db.put_output(&o4)).unwrap();

        // Query SAL balance (height 200 so outputs are unlocked, 100 confs > 10)
        let sal_bal = with_db(handle, |db| db.get_balance(200, "SAL", -1)).unwrap();
        assert_eq!(sal_bal.balance, "3000000");
        assert_eq!(sal_bal.unlocked_balance, "3000000");

        // Query SAL1 balance
        let sal1_bal = with_db(handle, |db| db.get_balance(200, "SAL1", -1)).unwrap();
        assert_eq!(sal1_bal.balance, "8000000");
        assert_eq!(sal1_bal.unlocked_balance, "8000000");

        cleanup(handle, &path);
    }

    #[test]
    fn test_get_all_balances() {
        let (handle, path) = test_db();

        // Insert outputs of different asset types
        let o1 = make_output("ki_ab_sal", 100, "1000", "SAL");
        let o2 = make_output("ki_ab_sal1", 100, "2000", "SAL1");
        let o3 = make_output("ki_ab_sal2", 100, "3000", "SAL");
        with_db(handle, |db| db.put_output(&o1)).unwrap();
        with_db(handle, |db| db.put_output(&o2)).unwrap();
        with_db(handle, |db| db.put_output(&o3)).unwrap();

        let all = with_db(handle, |db| db.get_all_balances(200, -1)).unwrap();

        assert!(all.contains_key("SAL"), "should contain SAL balance");
        assert!(all.contains_key("SAL1"), "should contain SAL1 balance");

        let sal = &all["SAL"];
        assert_eq!(sal.balance, "4000"); // 1000 + 3000
        assert_eq!(sal.unlocked_balance, "4000");

        let sal1 = &all["SAL1"];
        assert_eq!(sal1.balance, "2000");
        assert_eq!(sal1.unlocked_balance, "2000");

        cleanup(handle, &path);
    }

    #[test]
    fn test_amount_range_queries() {
        let (handle, path) = test_db();

        // Insert outputs with varying amounts
        let amounts = [("ki_ar_1", "100"), ("ki_ar_2", "500"), ("ki_ar_3", "1000"), ("ki_ar_4", "5000")];
        for (ki, amt) in &amounts {
            let o = make_output(ki, 100, amt, "SAL");
            with_db(handle, |db| db.put_output(&o)).unwrap();
        }

        // Query with min_amount only
        let query = OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: Some("500".into()),
            max_amount: None,
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 3, "should get outputs with amount >= 500");

        // Query with max_amount only
        let query = OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: None,
            max_amount: Some("1000".into()),
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 3, "should get outputs with amount <= 1000");

        // Query with both min and max
        let query = OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: Some("200".into()),
            max_amount: Some("800".into()),
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 1, "should get only the 500 amount output");
        assert_eq!(results[0].amount, "500");

        cleanup(handle, &path);
    }

    #[test]
    fn test_frozen_output_excluded() {
        let (handle, path) = test_db();

        // Insert a normal output
        let o1 = make_output("ki_normal", 100, "1000", "SAL");
        with_db(handle, |db| db.put_output(&o1)).unwrap();

        // Insert a frozen output
        let mut o2 = make_output("ki_frozen", 100, "2000", "SAL");
        o2.is_frozen = true;
        with_db(handle, |db| db.put_output(&o2)).unwrap();

        // Balance should exclude the frozen output
        let bal = with_db(handle, |db| db.get_balance(200, "SAL", -1)).unwrap();
        assert_eq!(bal.balance, "1000", "frozen output should be excluded from balance");
        assert_eq!(bal.unlocked_balance, "1000");

        // Query with is_frozen filter
        let query = OutputQuery {
            is_spent: None,
            is_frozen: Some(false),
            asset_type: None,
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 1, "only non-frozen outputs returned");
        assert_eq!(results[0].key_image, Some("ki_normal".into()));

        cleanup(handle, &path);
    }

    #[test]
    fn test_subaddress_filtering() {
        let (handle, path) = test_db();

        // Insert outputs with different subaddress indices
        let mut o1 = make_output("ki_sa_00", 100, "1000", "SAL");
        o1.subaddress_index = SubaddressIndex { major: 0, minor: 0 };
        with_db(handle, |db| db.put_output(&o1)).unwrap();

        let mut o2 = make_output("ki_sa_10", 100, "2000", "SAL");
        o2.subaddress_index = SubaddressIndex { major: 1, minor: 0 };
        with_db(handle, |db| db.put_output(&o2)).unwrap();

        let mut o3 = make_output("ki_sa_01", 100, "3000", "SAL");
        o3.subaddress_index = SubaddressIndex { major: 0, minor: 1 };
        with_db(handle, |db| db.put_output(&o3)).unwrap();

        // Query by account_index (major) = 0
        let query = OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: Some(0),
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 2, "should get 2 outputs for account 0");

        // Query by account_index = 1
        let query = OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: Some(1),
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 1, "should get 1 output for account 1");
        assert_eq!(results[0].key_image, Some("ki_sa_10".into()));

        // Query by account_index = 0, subaddress_index (minor) = 1
        let query = OutputQuery {
            is_spent: None,
            is_frozen: None,
            asset_type: None,
            tx_type: None,
            account_index: Some(0),
            subaddress_index: Some(1),
            min_amount: None,
            max_amount: None,
        };
        let results = with_db(handle, |db| db.get_outputs(&query)).unwrap();
        assert_eq!(results.len(), 1, "should get 1 output for account 0 subaddress 1");
        assert_eq!(results[0].key_image, Some("ki_sa_01".into()));

        cleanup(handle, &path);
    }

    #[test]
    fn test_stake_crud() {
        let (handle, path) = test_db();

        // put_stake
        let stake = make_stake("stake_crud_1", 100, "50000");
        with_db(handle, |db| db.put_stake(&stake)).unwrap();

        // get_stake
        let got = with_db(handle, |db| db.get_stake("stake_crud_1")).unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.stake_tx_hash, "stake_crud_1");
        assert_eq!(got.stake_height, Some(100));
        assert_eq!(got.amount_staked, "50000");
        assert_eq!(got.fee, "100");
        assert_eq!(got.asset_type, "SAL");
        assert_eq!(got.change_output_key, Some("outkey_stake_crud_1".into()));
        assert_eq!(got.status, "locked");
        assert_eq!(got.return_tx_hash, None);
        assert_eq!(got.return_height, None);
        assert_eq!(got.return_amount, "0");

        // Insert a second stake
        let stake2 = make_stake("stake_crud_2", 200, "30000");
        with_db(handle, |db| db.put_stake(&stake2)).unwrap();

        // get_stakes with no filter returns all
        let all = with_db(handle, |db| db.get_stakes(None, None)).unwrap();
        assert_eq!(all.len(), 2);

        // get_stakes with status filter
        let locked = with_db(handle, |db| db.get_stakes(Some("locked"), None)).unwrap();
        assert_eq!(locked.len(), 2);

        // mark_stake_returned
        with_db(handle, |db| {
            db.mark_stake_returned("stake_crud_1", "ret_tx_1", 300, 1700001000, "49900")
        }).unwrap();

        let returned = with_db(handle, |db| db.get_stakes(Some("returned"), None)).unwrap();
        assert_eq!(returned.len(), 1);
        assert_eq!(returned[0].stake_tx_hash, "stake_crud_1");
        assert_eq!(returned[0].return_tx_hash, Some("ret_tx_1".into()));
        assert_eq!(returned[0].return_height, Some(300));
        assert_eq!(returned[0].return_amount, "49900");

        let still_locked = with_db(handle, |db| db.get_stakes(Some("locked"), None)).unwrap();
        assert_eq!(still_locked.len(), 1);
        assert_eq!(still_locked[0].stake_tx_hash, "stake_crud_2");

        cleanup(handle, &path);
    }

    #[test]
    fn test_stake_by_output_key() {
        let (handle, path) = test_db();

        let stake = make_stake("stake_by_ok", 100, "25000");
        with_db(handle, |db| db.put_stake(&stake)).unwrap();

        // Look up by change_output_key
        let got = with_db(handle, |db| db.get_stake_by_output_key("outkey_stake_by_ok")).unwrap();
        assert!(got.is_some());
        let got = got.unwrap();
        assert_eq!(got.stake_tx_hash, "stake_by_ok");
        assert_eq!(got.amount_staked, "25000");

        // Non-existent key returns None
        let none = with_db(handle, |db| db.get_stake_by_output_key("nonexistent_key")).unwrap();
        assert!(none.is_none());

        cleanup(handle, &path);
    }
}
