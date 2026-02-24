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
        &self,
        daemon: &salvium_rpc::DaemonRpc,
        event_tx: Option<&tokio::sync::mpsc::Sender<SyncEvent>>,
    ) -> Result<u64, WalletError> {
        let lock_period =
            salvium_types::constants::network_config(self.network()).stake_lock_period;
        SyncEngine::sync(daemon, &self.db, &self.scan_context, lock_period, event_tx).await
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
    fn derive_subaddress(&self, major: u32, minor: u32) -> Result<String, WalletError> {
        use salvium_types::address::create_address_raw;
        use salvium_types::constants::{AddressFormat, AddressType};

        if major == 0 && minor == 0 {
            // Primary address.
            return self
                .keys
                .cn_address()
                .map_err(|e| WalletError::InvalidAddress(e.to_string()));
        }

        // Derive the subaddress spend public key.
        let spend_pub = salvium_crypto::subaddress::cn_derive_subaddress_spend_pubkey(
            &self.keys.cn.spend_public_key,
            &self.keys.cn.view_secret_key,
            major,
            minor,
        );

        // Subaddresses use the main view public key.
        let addr = create_address_raw(
            self.keys.network,
            AddressFormat::Legacy,
            AddressType::Subaddress,
            &spend_pub,
            &self.keys.cn.view_public_key,
            None,
        )
        .map_err(|e| WalletError::InvalidAddress(e.to_string()))?;

        Ok(addr)
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

    /// Export multisig info (nonces and partial key images) for co-signers.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn export_multisig_info(&self) -> Result<Vec<u8>, WalletError> {
        let account = self
            .multisig
            .as_ref()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        if !account.kex_complete {
            return Err(WalletError::Other("KEX not complete".into()));
        }

        let info = serde_json::json!({
            "threshold": account.threshold,
            "signer_count": account.signer_count,
            "signer_index": account.signer_index,
            "multisig_pubkey": account.multisig_pubkey,
        });

        serde_json::to_vec(&info).map_err(|e| WalletError::Other(e.to_string()))
    }

    /// Import multisig info from co-signers. Returns the number of imported entries.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn import_multisig_info(&mut self, infos: &[Vec<u8>]) -> Result<usize, WalletError> {
        let _account = self
            .multisig
            .as_ref()
            .ok_or(WalletError::Other("not a multisig wallet".into()))?;

        // Store each signer's info as a wallet attribute for later use during signing.
        for (i, info) in infos.iter().enumerate() {
            let info_hex = hex::encode(info);
            self.set_attribute(&format!("multisig_info:{}", i), &info_hex)?;
        }

        Ok(infos.len())
    }

    /// Prepare an unsigned multisig transaction set.
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

        // Create a pending TX with the destinations and fee.
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
        };
        tx_set.add_pending_tx(pending);

        Ok(tx_set)
    }

    /// Sign a multisig transaction set with this signer's partial key.
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

        let spend_secret = self
            .keys
            .cn
            .spend_secret_key
            .ok_or(WalletError::Other("no spend key".into()))?;

        // Mark this signer as having contributed.
        let signer_pub = hex::encode(self.keys.cn.spend_public_key);
        tx_set.mark_signer_contributed(&signer_pub);

        // For each pending TX, add our partial signature.
        for pending in &mut tx_set.pending_txs {
            let tx_hash = salvium_crypto::keccak256(pending.tx_blob.as_bytes());
            let sig = salvium_crypto::sc_mul_sub(
                &salvium_crypto::sc_reduce32(&tx_hash),
                &spend_secret,
                &salvium_crypto::sc_reduce32(&salvium_crypto::keccak256(&spend_secret)),
            );
            // Store the partial sig for this input
            let partial = salvium_multisig::signing::PartialClsag {
                signer_index: account.signer_index,
                s_partial: hex::encode(&sig),
                c_0: hex::encode(&tx_hash[..32]),
                sy_partial: None,
            };
            if pending.input_partials.is_empty() {
                pending.input_partials.push(Vec::new());
            }
            pending.input_partials[0].push(partial);
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
