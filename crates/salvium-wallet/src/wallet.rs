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
const DEFAULT_SUBADDRESS_COUNT: u32 = 50;

/// High-level wallet.
///
/// Manages keys, subaddresses, and (on native) persistent storage + sync.
pub struct Wallet {
    keys: WalletKeys,
    subaddress_maps: SubaddressMaps,
    scan_context: ScanContext,

    #[cfg(not(target_arch = "wasm32"))]
    db: std::sync::Mutex<salvium_crypto::storage::WalletDb>,
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
    pub fn open(
        keys: WalletKeys,
        db_path: &str,
        db_key: &[u8],
    ) -> Result<Self, WalletError> {
        Self::init_with_keys(keys, db_path, db_key)
    }

    #[cfg(not(target_arch = "wasm32"))]
    fn init_with_keys(
        keys: WalletKeys,
        db_path: &str,
        db_key: &[u8],
    ) -> Result<Self, WalletError> {
        let db = salvium_crypto::storage::WalletDb::open(db_path, db_key)
            .map_err(|e| WalletError::Storage(e.to_string()))?;

        let maps = SubaddressMaps::generate(&keys, 1, DEFAULT_SUBADDRESS_COUNT);
        let scan_context =
            ScanContext::from_keys(&keys, maps.cn.clone(), maps.carrot.clone());

        Ok(Self {
            keys,
            subaddress_maps: maps,
            scan_context,
            db: std::sync::Mutex::new(db),
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        let sync_height = db
            .get_sync_height()
            .map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_all_balances(sync_height, account_index)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }

    /// Get the current sync height.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn sync_height(&self) -> Result<u64, WalletError> {
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
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
        SyncEngine::sync(daemon, &self.db, &self.scan_context, event_tx).await
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
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
                let amount = o.amount.parse::<u64>().ok()?;
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
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
                let amount = o.amount.parse::<u64>().ok()?;
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
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
        let db = self.db.lock().map_err(|e| WalletError::Storage(e.to_string()))?;
        db.get_stakes(status, None)
            .map_err(|e| WalletError::Storage(e.to_string()))
    }
}

/// Check if an output is unlocked (spendable) at the given height.
#[cfg(not(target_arch = "wasm32"))]
fn is_output_unlocked(output: &salvium_crypto::storage::OutputRow, current_height: i64) -> bool {
    let unlock_time: u64 = output.unlock_time.parse().unwrap_or(0);
    if unlock_time == 0 {
        // Standard 10-confirmation rule.
        let out_height = output.block_height.unwrap_or(0);
        return current_height >= out_height + 10;
    }

    // Unlock time < 500_000_000 → block height.
    // Unlock time >= 500_000_000 → Unix timestamp.
    if unlock_time < 500_000_000 {
        current_height as u64 >= unlock_time
    } else {
        // Use block timestamp approximation (120s per block).
        let current_time = output.block_timestamp.unwrap_or(0) as u64
            + (current_height as u64 - output.block_height.unwrap_or(0) as u64) * 120;
        current_time >= unlock_time
    }
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
