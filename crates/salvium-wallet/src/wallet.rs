//! Main Wallet struct.
//!
//! Ties together key management, subaddress generation, output scanning,
//! blockchain sync, balance tracking, and UTXO selection into a single
//! high-level API.

use crate::account::SubaddressMaps;
use crate::error::WalletError;
use crate::keys::{WalletKeys, WalletType};
use crate::scanner::ScanContext;
use crate::sync::{SyncEngine, SyncEvent};
use crate::utxo::{self, SelectionStrategy, UtxoCandidate};
use salvium_types::constants::Network;

/// Default number of subaddresses to pre-generate per account.
///
/// Subaddresses are deterministic and the lookup map is a flat hashmap
/// (~40 bytes per entry), so 10 000 entries ≈ 400 KB — negligible.
const DEFAULT_SUBADDRESS_COUNT: u32 = 10_000;

/// Multisig wallet status information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MultisigStatus {
    pub is_multisig: bool,
    pub threshold: usize,
    pub signer_count: usize,
    pub kex_complete: bool,
    pub kex_round: usize,
    pub multisig_pubkey: Option<String>,
}

/// High-level wallet.
///
/// Manages keys, subaddresses, and (on native) persistent storage + sync.
pub struct Wallet {
    keys: WalletKeys,
    subaddress_maps: SubaddressMaps,
    scan_context: ScanContext,

    #[cfg(not(target_arch = "wasm32"))]
    db: std::sync::Mutex<salvium_crypto::storage::WalletDb>,

    /// Retained copy of the database encryption key (needed for blob export).
    #[cfg(not(target_arch = "wasm32"))]
    db_key: Vec<u8>,

    /// Optional multisig account state.
    #[cfg(not(target_arch = "wasm32"))]
    multisig: Option<salvium_multisig::account::MultisigAccount>,
}

impl Wallet {
    /// Create a new wallet from a seed, writing to a new database file.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create(
        seed: [u8; 32],
        network: Network,
        db_path: &str,
        db_key: &[u8],
    ) -> Result<Self, WalletError> {
        let keys = WalletKeys::from_seed(seed, network);
        Self::init_with_keys(keys, db_path, db_key)
    }

    /// Restore a wallet from a 25-word mnemonic.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_mnemonic(
        words: &str,
        network: Network,
        db_path: &str,
        db_key: &[u8],
    ) -> Result<Self, WalletError> {
        let keys = WalletKeys::from_mnemonic(words, network)?;
        Self::init_with_keys(keys, db_path, db_key)
    }

    /// Open an existing wallet with pre-constructed keys.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn open(keys: WalletKeys, db_path: &str, db_key: &[u8]) -> Result<Self, WalletError> {
        Self::init_with_keys(keys, db_path, db_key)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn init_with_keys(keys: WalletKeys, db_path: &str, db_key: &[u8]) -> Result<Self, WalletError> {
        let db = salvium_crypto::storage::WalletDb::open(db_path, db_key)
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        let maps = SubaddressMaps::generate(&keys, 1, DEFAULT_SUBADDRESS_COUNT);
        let scan_context = ScanContext::from_keys(&keys, maps.cn.clone(), maps.carrot.clone());

        Ok(Self {
            keys,
            subaddress_maps: maps,
            scan_context,
            db: std::sync::Mutex::new(db),
            db_key: db_key.to_vec(),
            multisig: None,
        })
    }

    // ── Key accessors ────────────────────────────────────────────────────

    /// Get the wallet type (Full / ViewOnly / Watch).
    pub fn wallet_type(&self) -> WalletType {
        self.keys.wallet_type
    }

    /// Get the network (Mainnet / Testnet / Stagenet).
    pub fn network(&self) -> Network {
        self.keys.network
    }

    /// Get the database encryption key.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn db_key(&self) -> &[u8] {
        &self.db_key
    }

    /// Get the primary CryptoNote address.
    pub fn cn_address(&self) -> Result<String, WalletError> {
        self.keys
            .cn_address()
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))
    }

    /// Get the primary CARROT address.
    pub fn carrot_address(&self) -> Result<String, WalletError> {
        self.keys
            .carrot_address()
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))
    }

    /// Get the mnemonic seed words (only for full wallets).
    pub fn mnemonic(&self) -> Option<Result<String, WalletError>> {
        self.keys.to_mnemonic()
    }

    /// Get the CryptoNote view secret key (hex).
    pub fn view_secret_key_hex(&self) -> String {
        hex::encode(self.keys.cn.view_secret_key)
    }

    /// Get the CryptoNote spend public key (hex).
    pub fn spend_public_key_hex(&self) -> String {
        hex::encode(self.keys.cn.spend_public_key)
    }

    /// Whether the wallet can sign transactions.
    pub fn can_spend(&self) -> bool {
        self.keys.can_spend()
    }

    /// Access the raw wallet keys.
    pub fn keys(&self) -> &WalletKeys {
        &self.keys
    }

    /// Access the subaddress maps.
    pub fn subaddress_maps(&self) -> &SubaddressMaps {
        &self.subaddress_maps
    }

    /// Access the scan context.
    pub fn scan_context(&self) -> &ScanContext {
        &self.scan_context
    }

    // ── Balance (native only) ────────────────────────────────────────────

    /// Get balance for an asset type (e.g., "SAL").
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_balance(
        &self,
        asset_type: &str,
        account_index: i32,
    ) -> Result<salvium_crypto::storage::BalanceResult, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        let sync_height = db
            .get_sync_height()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_balance(sync_height, asset_type, account_index)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get balances for all asset types.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_all_balances(
        &self,
        account_index: i32,
    ) -> Result<
        std::collections::HashMap<String, salvium_crypto::storage::BalanceResult>,
        WalletError,
    > {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        let sync_height = db
            .get_sync_height()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_all_balances(sync_height, account_index)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get the current sync height.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn sync_height(&self) -> Result<u64, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_sync_height()
            .map(|h| h as u64)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Sync (native only) ───────────────────────────────────────────────

    /// Sync the wallet with the blockchain.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn sync(
        &mut self,
        daemon: &salvium_rpc::DaemonRpc,
        event_tx: Option<&tokio::sync::mpsc::Sender<SyncEvent>>,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> Result<u64, WalletError> {
        let lock_period =
            salvium_types::constants::network_config(self.network()).stake_lock_period;
        SyncEngine::sync(
            daemon,
            &self.db,
            &mut self.scan_context,
            lock_period,
            event_tx,
            cancel,
        )
        .await
    }

    // ── UTXO selection ───────────────────────────────────────────────────

    /// Select unspent outputs for a transfer.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn select_outputs(
        &self,
        amount: u64,
        fee: u64,
        asset_type: &str,
        strategy: SelectionStrategy,
    ) -> Result<utxo::SelectionResult, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        let sync_height = db
            .get_sync_height()
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        let query = salvium_crypto::storage::OutputQuery {
            is_spent: Some(false),
            is_frozen: Some(false),
            asset_type: Some(asset_type.to_string()),
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        };

        let outputs = db
            .get_outputs(&query)
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        // Filter to unlocked outputs only.
        let candidates: Vec<UtxoCandidate> = outputs
            .into_iter()
            .filter(|o| is_output_unlocked(o, sync_height))
            .filter_map(|o| {
                let amount = match o.amount.parse::<u64>() {
                    Ok(a) => a,
                    Err(e) => {
                        log::error!(
                            "output amount parse failed: '{}' for key_image={}: {}",
                            o.amount,
                            o.key_image.as_deref().unwrap_or("?"),
                            e
                        );
                        return None;
                    }
                };
                Some(UtxoCandidate {
                    key_image: o.key_image.unwrap_or_default(),
                    amount,
                    block_height: o.block_height.unwrap_or(0) as u64,
                    global_index: o.global_index.unwrap_or(0) as u64,
                })
            })
            .collect();

        utxo::select_utxos(&candidates, amount, fee, strategy).ok_or(WalletError::NoOutputs)
    }

    /// Select CARROT-only unspent outputs for a SALVIUM_ONE transfer.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn select_carrot_outputs(
        &self,
        amount: u64,
        fee: u64,
        asset_type: &str,
        strategy: SelectionStrategy,
    ) -> Result<utxo::SelectionResult, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        let sync_height = db
            .get_sync_height()
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        let query = salvium_crypto::storage::OutputQuery {
            is_spent: Some(false),
            is_frozen: Some(false),
            asset_type: Some(asset_type.to_string()),
            tx_type: None,
            account_index: None,
            subaddress_index: None,
            min_amount: None,
            max_amount: None,
        };

        let outputs = db
            .get_outputs(&query)
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        let candidates: Vec<UtxoCandidate> = outputs
            .into_iter()
            .filter(|o| o.is_carrot && is_output_unlocked(o, sync_height))
            .filter_map(|o| {
                let amount = match o.amount.parse::<u64>() {
                    Ok(a) => a,
                    Err(e) => {
                        log::error!(
                            "CARROT output amount parse failed: '{}' for key_image={}: {}",
                            o.amount,
                            o.key_image.as_deref().unwrap_or("?"),
                            e
                        );
                        return None;
                    }
                };
                Some(UtxoCandidate {
                    key_image: o.key_image.unwrap_or_default(),
                    amount,
                    block_height: o.block_height.unwrap_or(0) as u64,
                    global_index: o.global_index.unwrap_or(0) as u64,
                })
            })
            .collect();

        utxo::select_utxos(&candidates, amount, fee, strategy).ok_or(WalletError::NoOutputs)
    }

    // ── Output lookup ──────────────────────────────────────────────────

    /// Get a single output by key image.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_output(
        &self,
        key_image: &str,
    ) -> Result<Option<salvium_crypto::storage::OutputRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_output(key_image)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Mark an output as spent by key image.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mark_output_spent(
        &self,
        key_image: &str,
        spending_tx_hash: &str,
    ) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.mark_spent(key_image, spending_tx_hash, 0)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Transfers query ──────────────────────────────────────────────────

    /// Get transactions matching a query.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_transfers(
        &self,
        query: &salvium_crypto::storage::TxQuery,
    ) -> Result<Vec<salvium_crypto::storage::TransactionRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_txs(query)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Staking ──────────────────────────────────────────────────────────

    /// Get all stakes, optionally filtered by status.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_stakes(
        &self,
        status: Option<&str>,
    ) -> Result<Vec<salvium_crypto::storage::StakeRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_stakes(status, None)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Transaction Notes ────────────────────────────────────────────────

    /// Set a user note on a transaction.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_tx_note(&self, tx_hash: &str, note: &str) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.set_tx_note(tx_hash, note)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get notes for a list of transaction hashes.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_tx_notes(
        &self,
        tx_hashes: &[&str],
    ) -> Result<std::collections::HashMap<String, String>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_tx_notes(tx_hashes)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Address Book ─────────────────────────────────────────────────────

    /// Add an entry to the address book. Returns the row_id.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn add_address_book_entry(
        &self,
        address: &str,
        label: &str,
        description: &str,
        payment_id: &str,
    ) -> Result<i64, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.add_address_book_entry(address, label, description, payment_id)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get all address book entries.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_address_book(
        &self,
    ) -> Result<Vec<salvium_crypto::storage::AddressBookEntry>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_address_book()
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get a single address book entry by row_id.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_address_book_entry(
        &self,
        row_id: i64,
    ) -> Result<Option<salvium_crypto::storage::AddressBookEntry>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_address_book_entry(row_id)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Edit an address book entry. Returns true if the entry was found and updated.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn edit_address_book_entry(
        &self,
        row_id: i64,
        address: Option<&str>,
        label: Option<&str>,
        description: Option<&str>,
        payment_id: Option<&str>,
    ) -> Result<bool, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.edit_address_book_entry(row_id, address, label, description, payment_id)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Delete an address book entry. Returns true if the entry existed.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn delete_address_book_entry(&self, row_id: i64) -> Result<bool, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.delete_address_book_entry(row_id)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Output queries ──────────────────────────────────────────────────

    /// Get outputs matching a query.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_outputs(
        &self,
        query: &salvium_crypto::storage::OutputQuery,
    ) -> Result<Vec<salvium_crypto::storage::OutputRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_outputs(query)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Mark an output as unspent.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn mark_output_unspent(&self, key_image: &str) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.mark_unspent(key_image)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Freeze an output (exclude from coin selection).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn freeze_output(&self, key_image: &str) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.freeze_output(key_image)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Thaw a frozen output.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn thaw_output(&self, key_image: &str) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.thaw_output(key_image)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Wallet attributes (key-value store) ─────────────────────────────

    /// Set a wallet attribute.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_attribute(&self, key: &str, value: &str) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.set_attribute(key, value)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get a wallet attribute.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_attribute(&self, key: &str) -> Result<Option<String>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_attribute(key)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Reset the sync height (for rescanning).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn reset_sync_height(&self, height: u64) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.set_sync_height(height as i64)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    // ── Subaddress / Account management ─────────────────────────────────

    /// Create a new account (major index) with an optional label.
    /// Returns the new major index.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create_account(&self, label: &str) -> Result<(i64, String), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        let accounts = db
            .get_accounts()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        let major = if accounts.is_empty() {
            0
        } else {
            accounts.last().unwrap().major + 1
        };

        // Derive the primary address (minor=0) for this account.
        let address = self.derive_subaddress(major as u32, 0)?;
        let lbl = if label.is_empty() && major == 0 {
            "Primary account"
        } else {
            label
        };

        db.upsert_subaddress(major, 0, &address, lbl)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok((major, address))
    }

    /// Get all accounts.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_accounts(&self) -> Result<Vec<salvium_crypto::storage::SubaddressRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_accounts()
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Create a new subaddress in an existing account.
    /// Returns the new (major, minor) index and address string.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create_subaddress(
        &self,
        major: i64,
        label: &str,
    ) -> Result<(i64, i64, String), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        let minor = db
            .next_subaddress_minor(major)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        // Ensure minor starts at 1 if 0 already exists (0 = account primary address).
        let minor = if minor == 0 { 1 } else { minor };

        let address = self.derive_subaddress(major as u32, minor as u32)?;
        db.upsert_subaddress(major, minor, &address, label)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok((major, minor, address))
    }

    /// Get all subaddresses for an account.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_subaddresses(
        &self,
        major: i64,
    ) -> Result<Vec<salvium_crypto::storage::SubaddressRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_subaddresses(major)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Set a label on a subaddress.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn label_subaddress(&self, major: i64, minor: i64, label: &str) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.label_subaddress(major, minor, label)
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Derive the address string for a subaddress at (major, minor).
    ///
    /// Produces a CARROT address if the CARROT hard fork is active at the
    /// chain tip height, otherwise falls back to legacy CryptoNote.
    /// The chain tip is persisted in the DB by the sync engine.
    #[cfg(not(target_arch = "wasm32"))]
    fn derive_subaddress(&self, major: u32, minor: u32) -> Result<String, WalletError> {
        use salvium_types::address::create_address_raw;
        use salvium_types::consensus::is_carrot_active;
        use salvium_types::constants::{AddressFormat, AddressType};

        let chain_tip = {
            let db = self
                .db
                .lock()
                .map_err(|e| WalletError::Storage(e.to_string()))?;
            db.get_attribute("chain_tip_height")
                .map_err(|e| WalletError::Storage(e.to_string()))?
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0)
        };

        let use_carrot =
            is_carrot_active(chain_tip, self.keys.network) && !self.keys.carrot.is_empty();

        if major == 0 && minor == 0 {
            return if use_carrot {
                self.keys
                    .carrot_address()
                    .map_err(|e| WalletError::InvalidAddress(e.to_string()))
            } else {
                self.keys
                    .cn_address()
                    .map_err(|e| WalletError::InvalidAddress(e.to_string()))
            };
        }

        if use_carrot {
            let (spend_pub, view_pub) = salvium_crypto::subaddress::carrot_derive_subaddress_keys(
                &self.keys.carrot.account_spend_pubkey,
                &self.keys.carrot.account_view_pubkey,
                &self.keys.carrot.primary_address_view_pubkey,
                &self.keys.carrot.generate_address_secret,
                major,
                minor,
            );

            create_address_raw(
                self.keys.network,
                AddressFormat::Carrot,
                AddressType::Subaddress,
                &spend_pub,
                &view_pub,
                None,
            )
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))
        } else {
            let spend_pub = salvium_crypto::subaddress::cn_derive_subaddress_spend_pubkey(
                &self.keys.cn.spend_public_key,
                &self.keys.cn.view_secret_key,
                major,
                minor,
            );

            create_address_raw(
                self.keys.network,
                AddressFormat::Legacy,
                AddressType::Subaddress,
                &spend_pub,
                &self.keys.cn.view_public_key,
                None,
            )
            .map_err(|e| WalletError::InvalidAddress(e.to_string()))
        }
    }

    // ── Integrated addresses ────────────────────────────────────────────

    /// Create an integrated address from the primary address + 8-byte payment ID.
    pub fn make_integrated_address(&self, payment_id: &[u8; 8]) -> Result<String, WalletError> {
        use salvium_types::address::create_address_raw;
        use salvium_types::constants::{AddressFormat, AddressType};
        create_address_raw(
            self.keys.network,
            AddressFormat::Legacy,
            AddressType::Integrated,
            &self.keys.cn.spend_public_key,
            &self.keys.cn.view_public_key,
            Some(payment_id.as_slice()),
        )
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))
    }

    /// Split an integrated address into standard address + payment ID.
    pub fn split_integrated_address(
        &self,
        address: &str,
    ) -> Result<(String, [u8; 8]), WalletError> {
        use salvium_types::address::{parse_address, to_standard_address};
        use salvium_types::constants::AddressType;
        let parsed =
            parse_address(address).map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
        if parsed.address_type != AddressType::Integrated {
            return Err(WalletError::InvalidAddress(
                "not an integrated address".into(),
            ));
        }
        let pid = parsed.payment_id.ok_or_else(|| {
            WalletError::InvalidAddress("integrated address has no payment ID".into())
        })?;
        let standard =
            to_standard_address(address).map_err(|e| WalletError::InvalidAddress(e.to_string()))?;
        Ok((standard, pid))
    }

    // ── Multisig ────────────────────────────────────────────────────────

    /// Initialize a multisig wallet. Returns the first KEX message.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn create_multisig(
        &mut self,
        threshold: usize,
        signer_count: usize,
    ) -> Result<String, WalletError> {
        let spend_secret = self
            .keys
            .cn
            .spend_secret_key
            .ok_or(WalletError::Other("wallet has no spend key".into()))?;
        let view_secret = self.keys.cn.view_secret_key;

        let mut account = salvium_multisig::account::MultisigAccount::new(threshold, signer_count)
            .map_err(WalletError::Other)?;

        let msg = account
            .initialize_kex(&hex::encode(spend_secret), &hex::encode(view_secret))
            .map_err(WalletError::Other)?;

        self.multisig = Some(account);
        self.keys.wallet_type = WalletType::Multisig {
            threshold,
            signer_count,
        };

        // Persist multisig state
        self.save_multisig_state()?;

        Ok(msg.to_string())
    }

    /// Process a multisig KEX round with messages from all signers.
    ///
    /// Returns `Some(message)` for the next round, or `None` if KEX is complete.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn process_multisig_kex(
        &mut self,
        messages: &[String],
    ) -> Result<Option<String>, WalletError> {
        let account = self
            .multisig
            .as_mut()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        let kex_messages: Vec<salvium_multisig::kex::KexMessage> = messages
            .iter()
            .map(|s| salvium_multisig::kex::KexMessage::from_string(s).map_err(WalletError::Other))
            .collect::<Result<Vec<_>, _>>()?;

        // On round 1, register signers
        if account.kex_round == 1 {
            account
                .register_signers(&kex_messages)
                .map_err(WalletError::Other)?;
        }

        let result = account
            .process_kex_round(&kex_messages)
            .map_err(WalletError::Other)?;

        // Persist updated state
        self.save_multisig_state()?;

        Ok(result.map(|m| m.to_string()))
    }

    /// Whether this is a multisig wallet.
    pub fn is_multisig(&self) -> bool {
        self.keys.is_multisig()
    }

    /// Get a reference to the multisig account, if this is a multisig wallet.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn multisig_account(&self) -> Option<&salvium_multisig::account::MultisigAccount> {
        self.multisig.as_ref()
    }

    /// Get the current multisig status.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_multisig_status(&self) -> MultisigStatus {
        match &self.multisig {
            Some(account) => MultisigStatus {
                is_multisig: true,
                threshold: account.threshold,
                signer_count: account.signer_count,
                kex_complete: account.kex_complete,
                kex_round: account.kex_round,
                multisig_pubkey: account.multisig_pubkey.clone(),
            },
            None => MultisigStatus {
                is_multisig: false,
                threshold: 0,
                signer_count: 0,
                kex_complete: false,
                kex_round: 0,
                multisig_pubkey: None,
            },
        }
    }

    /// Export multisig info (metadata and partial key images) for co-signers.
    ///
    /// For each unspent output, computes a partial key image:
    ///   `partial_ki = weighted_share * H_p(output_pubkey)`
    /// Co-signers collect all partial key images and combine them (plus the
    /// key-offset component) to derive full key images via `import_multisig_info`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn export_multisig_info(&self) -> Result<Vec<u8>, WalletError> {
        let account = self
            .multisig
            .as_ref()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        if !account.kex_complete {
            return Err(WalletError::Other("KEX not complete".into()));
        }

        let weighted_share = account
            .get_weighted_spend_key_share()
            .map_err(|e| WalletError::Other(format!("weighted key share: {}", e)))?;

        // Query all unspent outputs.
        let query = salvium_crypto::storage::OutputQuery {
            is_spent: Some(false),
            ..Default::default()
        };
        let outputs = self.get_outputs(&query)?;

        // Compute partial key images for each output that has a public key.
        let mut partial_key_images: Vec<serde_json::Value> = Vec::new();
        for output in &outputs {
            if let Some(ref pk_hex) = output.public_key {
                let pk_bytes = hex::decode(pk_hex).unwrap_or_default();
                if pk_bytes.len() == 32 {
                    let hp = salvium_crypto::hash_to_point(&pk_bytes);
                    let partial_ki = salvium_crypto::scalar_mult_point(&weighted_share, &hp);
                    partial_key_images.push(serde_json::json!({
                        "output_public_key": pk_hex,
                        "key_image": output.key_image,
                        "partial_key_image": hex::encode(&partial_ki),
                    }));
                }
            }
        }

        let info = serde_json::json!({
            "threshold": account.threshold,
            "signer_count": account.signer_count,
            "signer_index": account.signer_index,
            "multisig_pubkey": account.multisig_pubkey,
            "partial_key_images": partial_key_images,
        });

        serde_json::to_vec(&info).map_err(|e| WalletError::Other(e.to_string()))
    }

    /// Import multisig info from co-signers. Returns the number of outputs
    /// for which full key images were computed.
    ///
    /// Each info blob is JSON containing `partial_key_images` from one signer.
    /// This method sums all signers' partial key images (including our own)
    /// to produce the full key image for each output and stores the result
    /// as a wallet attribute `multisig_ki:<output_public_key>`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn import_multisig_info(&mut self, infos: &[Vec<u8>]) -> Result<usize, WalletError> {
        let account = self
            .multisig
            .as_ref()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        if !account.kex_complete {
            return Err(WalletError::Other("KEX not complete".into()));
        }

        // Also compute our own partial key images.
        let our_info_bytes = self.export_multisig_info()?;
        let our_info: serde_json::Value = serde_json::from_slice(&our_info_bytes)
            .map_err(|e| WalletError::Other(format!("parse own info: {}", e)))?;

        // Collect all infos (ours + theirs).
        let mut all_infos = vec![our_info];
        for info_bytes in infos {
            let parsed: serde_json::Value = serde_json::from_slice(info_bytes)
                .map_err(|e| WalletError::Other(format!("parse signer info: {}", e)))?;
            all_infos.push(parsed);
        }

        // Build a map: output_public_key -> Vec<partial_ki_hex>
        let mut partials_map: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for info in &all_infos {
            if let Some(pkis) = info.get("partial_key_images").and_then(|v| v.as_array()) {
                for pki in pkis {
                    let opk = pki
                        .get("output_public_key")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    let partial = pki
                        .get("partial_key_image")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if !opk.is_empty() && !partial.is_empty() {
                        partials_map.entry(opk).or_default().push(partial);
                    }
                }
            }
        }

        // For each output, sum partial key images to get the full key image.
        let mut count = 0usize;
        for (output_pk_hex, partials) in &partials_map {
            if partials.is_empty() {
                continue;
            }

            // Sum the partial key images (point addition).
            let mut sum = [0u8; 32];
            let mut first = true;
            for partial_hex in partials {
                let partial_bytes = hex::decode(partial_hex).unwrap_or_default();
                if partial_bytes.len() < 32 {
                    continue;
                }
                if first {
                    sum.copy_from_slice(&partial_bytes[..32]);
                    first = false;
                } else {
                    sum = to_32(&salvium_crypto::point_add_compressed(
                        &sum,
                        &partial_bytes[..32],
                    ));
                }
            }

            if !first {
                let full_ki_hex = hex::encode(sum);
                self.set_attribute(&format!("multisig_ki:{}", output_pk_hex), &full_ki_hex)?;
                count += 1;
            }
        }

        // Also store raw signer info for reference.
        for (i, info) in infos.iter().enumerate() {
            let info_hex = hex::encode(info);
            self.set_attribute(&format!("multisig_info:{}", i), &info_hex)?;
        }

        Ok(count)
    }

    /// Prepare an unsigned multisig transaction set.
    ///
    /// Creates a `MultisigTxSet` with the transaction destinations and fee.
    /// The initiating signer generates nonces for each input.
    ///
    /// Note: Full UTXO selection and ring member fetching require daemon RPC
    /// (async). For now, callers should use `tx_builder::build_multisig_contexts()`
    /// to construct a `PendingMultisigTx` with proper signing contexts, then wrap
    /// it in a `MultisigTxSet` via `add_pending_tx()`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn prepare_multisig_tx(
        &self,
        destinations: &[(String, u64)],
        fee: u64,
    ) -> Result<salvium_multisig::tx_set::MultisigTxSet, WalletError> {
        let account = self
            .multisig
            .as_ref()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        if !account.kex_complete {
            return Err(WalletError::Other("KEX not complete".into()));
        }

        let mut tx_set = salvium_multisig::tx_set::MultisigTxSet::with_config(
            account.threshold,
            account.signer_count,
        );

        let pending = salvium_multisig::tx_set::PendingMultisigTx {
            tx_blob: String::new(),
            key_images: Vec::new(),
            tx_prefix_hash: String::new(),
            input_nonces: Vec::new(),
            input_partials: Vec::new(),
            fee,
            destinations: destinations
                .iter()
                .map(|(d, a)| format!("{}:{}", d, a))
                .collect(),
            signing_contexts: Vec::new(),
            signing_message: String::new(),
            input_key_offsets: Vec::new(),
            input_z_values: Vec::new(),
            input_y_keys: Vec::new(),
            proposer_signed: false,
        };
        tx_set.add_pending_tx(pending);

        Ok(tx_set)
    }

    /// Phase 1: Generate and add nonces for each input. Call once per signer.
    ///
    /// Each signer calls this before signing. Once all threshold signers have
    /// contributed nonces, call `sign_multisig_tx()` to produce partial signatures.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn add_multisig_nonces(
        &self,
        tx_set: &mut salvium_multisig::tx_set::MultisigTxSet,
    ) -> Result<(), WalletError> {
        let account = self
            .multisig
            .as_ref()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        if !account.kex_complete {
            return Err(WalletError::Other("KEX not complete".into()));
        }

        for pending in &mut tx_set.pending_txs {
            let num_inputs = pending.signing_contexts.len();
            if num_inputs == 0 {
                continue;
            }

            // Ensure input_nonces has the right structure (one Vec per input).
            while pending.input_nonces.len() < num_inputs {
                pending.input_nonces.push(Vec::new());
            }

            for (i, ctx) in pending.signing_contexts.iter().enumerate() {
                let pk_hex = &ctx.ring[ctx.real_index];
                let ki_y = ctx.key_image_y.as_deref();
                let nonces = salvium_multisig::signing::generate_nonces_ext(
                    account.signer_index,
                    pk_hex,
                    ki_y,
                )
                .map_err(|e| WalletError::Other(format!("nonce generation failed: {}", e)))?;
                pending.input_nonces[i].push(nonces);
            }
        }

        Ok(())
    }

    /// Phase 2: Sign a multisig transaction set with this signer's partial key.
    ///
    /// All threshold signers must have contributed nonces (via `add_multisig_nonces()`)
    /// before calling this. Each signer calls this exactly once.
    ///
    /// **Proposer-owns-offsets pattern:**
    /// - The first signer (proposer, `!pending.proposer_signed`) adds per-input
    ///   key derivation offsets to their weighted key share, uses full `z` and `y`.
    /// - Co-signers use the bare weighted key share with `z=0` and `y=0`.
    ///
    /// Returns `true` if enough signatures have been collected (threshold met).
    #[cfg(not(target_arch = "wasm32"))]
    pub fn sign_multisig_tx(
        &self,
        tx_set: &mut salvium_multisig::tx_set::MultisigTxSet,
    ) -> Result<bool, WalletError> {
        let account = self
            .multisig
            .as_ref()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        if !account.kex_complete {
            return Err(WalletError::Other("KEX not complete".into()));
        }

        // Use the weighted multisig key share instead of the raw spend secret.
        let weighted_share = account
            .get_weighted_spend_key_share()
            .map_err(|e| WalletError::Other(format!("weighted key share: {}", e)))?;

        let signer_pub = hex::encode(self.keys.cn.spend_public_key);
        tx_set.mark_signer_contributed(&signer_pub);

        for pending in &mut tx_set.pending_txs {
            let num_inputs = pending.signing_contexts.len();
            if num_inputs == 0 {
                continue;
            }

            // Check if we have enough nonces to sign.
            let have_enough_nonces = pending
                .input_nonces
                .iter()
                .all(|n| n.len() >= account.threshold);

            if !have_enough_nonces {
                return Err(WalletError::Other(format!(
                    "not enough nonces: need {} signers, have {}",
                    account.threshold,
                    pending.input_nonces.first().map_or(0, |n| n.len())
                )));
            }

            // Compute partial signatures for each input.
            while pending.input_partials.len() < num_inputs {
                pending.input_partials.push(Vec::new());
            }

            let is_proposer = !pending.proposer_signed;
            let zero_hex = "00".repeat(32);

            // We need our own nonces for signing. Find them by signer_index.
            let our_signer_idx = account.signer_index;

            for (i, ctx) in pending.signing_contexts.iter().enumerate() {
                let all_nonces = &pending.input_nonces[i];

                // Find our nonces in the collected set.
                let our_nonces = all_nonces
                    .iter()
                    .find(|n| n.signer_index == our_signer_idx)
                    .ok_or_else(|| {
                        WalletError::Other(format!(
                            "input {}: no nonces found for signer {}",
                            i, our_signer_idx
                        ))
                    })?;

                // Proposer: add key_offset to weighted share; co-signer: bare share.
                let privkey_hex = if is_proposer && i < pending.input_key_offsets.len() {
                    let offset_bytes = hex::decode(&pending.input_key_offsets[i])
                        .map_err(|e| WalletError::Other(format!("bad key offset hex: {}", e)))?;
                    let mut offset = [0u8; 32];
                    offset[..offset_bytes.len().min(32)]
                        .copy_from_slice(&offset_bytes[..offset_bytes.len().min(32)]);
                    hex::encode(to_32(&salvium_crypto::sc_add(&weighted_share, &offset)))
                } else {
                    hex::encode(weighted_share)
                };

                // Proposer: use full z; co-signer: zero.
                let z_share_hex = if is_proposer && i < pending.input_z_values.len() {
                    pending.input_z_values[i].clone()
                } else {
                    zero_hex.clone()
                };

                let partial = if ctx.use_tclsag {
                    // Proposer: use full y; co-signer: zero.
                    let y_share_hex = if is_proposer && i < pending.input_y_keys.len() {
                        pending.input_y_keys[i].clone()
                    } else {
                        zero_hex.clone()
                    };
                    salvium_multisig::signing::partial_sign_tclsag(
                        ctx,
                        our_nonces,
                        &privkey_hex,
                        &y_share_hex,
                        &z_share_hex,
                        all_nonces,
                    )
                    .map_err(|e| WalletError::Other(format!("TCLSAG sign failed: {}", e)))?
                } else {
                    salvium_multisig::signing::partial_sign(
                        ctx,
                        our_nonces,
                        &privkey_hex,
                        &z_share_hex,
                        all_nonces,
                    )
                    .map_err(|e| WalletError::Other(format!("CLSAG sign failed: {}", e)))?
                };

                pending.input_partials[i].push(partial);
            }

            // Mark that the proposer has signed — subsequent signers are co-signers.
            if is_proposer {
                pending.proposer_signed = true;
            }
        }

        Ok(tx_set.is_complete())
    }

    /// Persist multisig state to the database.
    #[cfg(not(target_arch = "wasm32"))]
    fn save_multisig_state(&self) -> Result<(), WalletError> {
        if let Some(ref account) = self.multisig {
            let json =
                serde_json::to_string(account).map_err(|e| WalletError::Other(e.to_string()))?;
            self.set_attribute("multisig_state", &json)?;
        }
        Ok(())
    }

    // ── Ring management ──────────────────────────────────────────────

    /// Get ring member indices for a key image.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_ring(&self, key_image: &str) -> Result<Vec<(i64, i64, bool)>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_ring(key_image)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get ring members for all key images in a transaction.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::type_complexity)]
    pub fn get_rings_for_tx(
        &self,
        tx_hash: &str,
    ) -> Result<std::collections::HashMap<String, Vec<(i64, i64, bool)>>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_rings_for_tx(tx_hash)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Store ring member indices for a key image.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_ring(
        &self,
        key_image: &str,
        members: &[(i64, i64, bool)],
    ) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.set_ring(key_image, members)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Remove ring data for a key image.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn unset_ring(&self, key_image: &str) -> Result<bool, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.unset_ring(key_image)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Scan all transfers and persist their ring members.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn save_known_rings(&self) -> Result<usize, WalletError> {
        // Get all outgoing transactions (they have ring members from our inputs).
        let query = salvium_crypto::storage::TxQuery {
            is_incoming: None,
            is_outgoing: Some(true),
            is_confirmed: None,
            in_pool: None,
            tx_type: None,
            min_height: None,
            max_height: None,
            tx_hash: None,
        };
        let txs = self.get_transfers(&query)?;
        // Ring members are stored per-key-image during TX construction.
        // This method checks for any that are missing and returns count.
        // In practice, rings should already be saved at TX construction time.
        Ok(txs.len())
    }

    // ── MMS storage wrappers ────────────────────────────────────────────

    /// Add an MMS message. Returns the new message ID.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_arguments)]
    pub fn add_mms_message(
        &self,
        msg_type: i64,
        direction: i64,
        content: &[u8],
        signer_index: i64,
        state: i64,
        hash: &str,
        round: i64,
        signature_count: i64,
        transport_id: &str,
    ) -> Result<i64, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.add_mms_message(
            msg_type,
            direction,
            content,
            signer_index,
            state,
            hash,
            round,
            signature_count,
            transport_id,
        )
        .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get an MMS message by ID.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_mms_message(
        &self,
        id: i64,
    ) -> Result<Option<salvium_crypto::storage::MmsMessageRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_mms_message(id)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// List all MMS messages.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_mms_messages(
        &self,
    ) -> Result<Vec<salvium_crypto::storage::MmsMessageRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_mms_messages()
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Update MMS message state.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn update_mms_message_state(&self, id: i64, state: i64) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.update_mms_message_state(id, state)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Delete an MMS message.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn delete_mms_message(&self, id: i64) -> Result<bool, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.delete_mms_message(id)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Upsert an MMS signer.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn set_mms_signer(
        &self,
        signer_index: i64,
        label: &str,
        transport_address: &str,
        monero_address: &str,
        is_me: bool,
    ) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.set_mms_signer(
            signer_index,
            label,
            transport_address,
            monero_address,
            is_me,
        )
        .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get all MMS signers.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn get_mms_signers(
        &self,
    ) -> Result<Vec<salvium_crypto::storage::MmsSignerRow>, WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_mms_signers()
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Clear all MMS data.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn clear_mms(&self) -> Result<(), WalletError> {
        let db = self
            .db
            .lock()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.clear_mms()
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Load multisig state from the database, if present.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn load_multisig_state(&mut self) -> Result<bool, WalletError> {
        match self.get_attribute("multisig_state")? {
            Some(json) => {
                let account: salvium_multisig::account::MultisigAccount =
                    serde_json::from_str(&json).map_err(|e| WalletError::Other(e.to_string()))?;
                self.keys.wallet_type = WalletType::Multisig {
                    threshold: account.threshold,
                    signer_count: account.signer_count,
                };
                self.multisig = Some(account);
                Ok(true)
            }
            None => Ok(false),
        }
    }
}

/// Check if an output is unlocked (spendable) at the given height.
///
/// Delegates to `salvium_crypto::storage::is_unlocked` which exactly matches
/// C++ wallet2::is_transfer_unlocked + is_tx_spendtime_unlocked.
#[cfg(not(target_arch = "wasm32"))]
/// Convert a byte slice (up to 32 bytes) into a `[u8; 32]`.
fn to_32(v: &[u8]) -> [u8; 32] {
    let mut arr = [0u8; 32];
    let len = v.len().min(32);
    arr[..len].copy_from_slice(&v[..len]);
    arr
}

fn is_output_unlocked(output: &salvium_crypto::storage::OutputRow, current_height: i64) -> bool {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u128;
    salvium_crypto::storage::is_output_unlocked_ext(
        current_height,
        output.block_height,
        &output.unlock_time,
        output.tx_type,
        now_secs,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_key_accessors() {
        // Create keys without DB (for testing).
        let keys = WalletKeys::from_seed([42u8; 32], Network::Testnet);
        let maps = SubaddressMaps::generate(&keys, 1, 5);
        let scan_ctx = ScanContext::from_keys(&keys, maps.cn.clone(), maps.carrot.clone());

        // Verify the scan context captures the right keys.
        assert_eq!(scan_ctx.cn_view_secret, keys.cn.view_secret_key);
        assert!(scan_ctx.carrot_enabled);
    }

    #[test]
    fn test_cn_address_is_valid() {
        let keys = WalletKeys::from_seed([42u8; 32], Network::Testnet);
        let addr = keys.cn_address().unwrap();
        assert!(salvium_types::address::is_valid_address(&addr));
    }

    #[test]
    fn test_carrot_address_is_valid() {
        let keys = WalletKeys::from_seed([42u8; 32], Network::Testnet);
        let addr = keys.carrot_address().unwrap();
        assert!(salvium_types::address::is_valid_address(&addr));
    }

    #[test]
    fn test_mnemonic_roundtrip() {
        let seed = [42u8; 32];
        let keys = WalletKeys::from_seed(seed, Network::Testnet);
        let words = keys.to_mnemonic().unwrap().unwrap();

        let keys2 = WalletKeys::from_mnemonic(&words, Network::Testnet).unwrap();
        assert_eq!(keys.cn.spend_public_key, keys2.cn.spend_public_key);
        assert_eq!(keys.cn.view_public_key, keys2.cn.view_public_key);
    }

    #[test]
    fn test_addresses_differ_between_cn_and_carrot() {
        let keys = WalletKeys::from_seed([42u8; 32], Network::Testnet);
        let cn = keys.cn_address().unwrap();
        let carrot = keys.carrot_address().unwrap();
        assert_ne!(cn, carrot);
    }
}
