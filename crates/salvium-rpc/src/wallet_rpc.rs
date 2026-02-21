//! Wallet RPC client.
//!
//! Typed async methods for the Salvium wallet RPC interface.
//! Covers balance, addresses, transfers, key management, and signing.
//!
//! Reference: salvium wallet RPC documentation, wallet.js

use crate::client::{RpcClient, RpcConfig};
use crate::error::RpcError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

// =============================================================================
// Response Types
// =============================================================================

/// Balance info from `get_balance`.
#[derive(Debug, Clone, Deserialize)]
pub struct BalanceInfo {
    pub balance: u64,
    pub unlocked_balance: u64,
    #[serde(default)]
    pub multisig_import_needed: bool,
    #[serde(default)]
    pub per_subaddress: Vec<SubaddressBalance>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Per-subaddress balance.
#[derive(Debug, Clone, Deserialize)]
pub struct SubaddressBalance {
    #[serde(default)]
    pub account_index: u32,
    #[serde(default)]
    pub address_index: u32,
    pub address: String,
    pub balance: u64,
    pub unlocked_balance: u64,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub num_unspent_outputs: u64,
}

/// Address info from `get_address`.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressResult {
    pub address: String,
    #[serde(default)]
    pub addresses: Vec<AddressEntry>,
}

/// Single address entry.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressEntry {
    pub address: String,
    #[serde(default)]
    pub address_index: u32,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub used: bool,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Account info from `get_accounts`.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountsResult {
    pub total_balance: u64,
    pub total_unlocked_balance: u64,
    pub subaddress_accounts: Vec<AccountEntry>,
}

/// Single account entry.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountEntry {
    pub account_index: u32,
    pub base_address: String,
    pub balance: u64,
    pub unlocked_balance: u64,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub tag: String,
}

/// Transfer result from `transfer` / `transfer_split`.
#[derive(Debug, Clone, Deserialize)]
pub struct TransferResult {
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub tx_key: Option<String>,
    #[serde(default)]
    pub amount: u64,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub tx_blob: Option<String>,
    #[serde(default)]
    pub tx_metadata: Option<String>,
    #[serde(default)]
    pub unsigned_txset: Option<String>,
    #[serde(default)]
    pub multisig_txset: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Split transfer result.
#[derive(Debug, Clone, Deserialize)]
pub struct TransferSplitResult {
    #[serde(default)]
    pub tx_hash_list: Vec<String>,
    #[serde(default)]
    pub tx_key_list: Vec<String>,
    #[serde(default)]
    pub amount_list: Vec<u64>,
    #[serde(default)]
    pub fee_list: Vec<u64>,
    #[serde(default)]
    pub tx_blob_list: Vec<String>,
    #[serde(default)]
    pub unsigned_txset: Option<String>,
    #[serde(default)]
    pub multisig_txset: Option<String>,
}

/// Transfer entry from `get_transfers`.
#[derive(Debug, Clone, Deserialize)]
pub struct TransferEntry {
    pub txid: String,
    #[serde(default)]
    pub payment_id: String,
    pub height: u64,
    pub timestamp: u64,
    pub amount: u64,
    #[serde(default)]
    pub fee: u64,
    #[serde(rename = "type")]
    #[serde(default)]
    pub transfer_type: String,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub unlock_time: u64,
    #[serde(default)]
    pub confirmations: u64,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub double_spend_seen: bool,
    #[serde(default)]
    pub subaddr_index: SubaddrIndex,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Subaddress index pair.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SubaddrIndex {
    pub major: u32,
    pub minor: u32,
}

/// Transfer history grouped by direction.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct TransfersResult {
    #[serde(rename = "in")]
    #[serde(default)]
    pub incoming: Vec<TransferEntry>,
    #[serde(default)]
    pub out: Vec<TransferEntry>,
    #[serde(default)]
    pub pending: Vec<TransferEntry>,
    #[serde(default)]
    pub failed: Vec<TransferEntry>,
    #[serde(default)]
    pub pool: Vec<TransferEntry>,
}

/// Validate address result.
#[derive(Debug, Clone, Deserialize)]
pub struct ValidateAddressResult {
    pub valid: bool,
    #[serde(default)]
    pub integrated: bool,
    #[serde(default)]
    pub subaddress: bool,
    #[serde(default)]
    pub nettype: String,
    #[serde(default)]
    pub openalias_address: Option<String>,
}

/// Refresh result.
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshResult {
    pub blocks_fetched: u64,
    pub received_money: bool,
}

/// Incoming transfer entry.
#[derive(Debug, Clone, Deserialize)]
pub struct IncomingTransfer {
    pub amount: u64,
    pub spent: bool,
    pub global_index: u64,
    pub tx_hash: String,
    #[serde(default)]
    pub subaddr_index: SubaddrIndex,
    #[serde(default)]
    pub key_image: String,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub frozen: bool,
    #[serde(default)]
    pub unlocked: bool,
}

// =============================================================================
// Transfer Destination
// =============================================================================

/// Destination for a transfer.
#[derive(Debug, Clone, Serialize)]
pub struct Destination {
    pub address: String,
    pub amount: u64,
}

/// Transfer priority levels.
pub mod priority {
    pub const DEFAULT: u32 = 0;
    pub const UNIMPORTANT: u32 = 1;
    pub const NORMAL: u32 = 2;
    pub const ELEVATED: u32 = 3;
}

// =============================================================================
// New Response Types
// =============================================================================

/// Address index result from `get_address_index`.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressIndexResult {
    pub index: SubaddrIndex,
}

/// Result from `create_account`.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateAccountResult {
    pub account_index: u32,
    pub address: String,
}

/// Account tag entry from `get_account_tags`.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountTag {
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub accounts: Vec<u32>,
}

/// Result from `get_account_tags`.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountTagsResult {
    #[serde(default)]
    pub account_tags: Vec<AccountTag>,
}

/// Address book entry.
#[derive(Debug, Clone, Deserialize)]
pub struct AddressBookEntry {
    pub index: u64,
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub payment_id: String,
}

/// Result from `sign_transfer`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignTransferResult {
    #[serde(default)]
    pub signed_txset: String,
    #[serde(default)]
    pub tx_hash_list: Vec<String>,
    #[serde(default)]
    pub tx_raw_list: Vec<String>,
}

/// Recipient in a transfer description.
#[derive(Debug, Clone, Deserialize)]
pub struct TransferRecipient {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub amount: u64,
}

/// Transfer description from `describe_transfer`.
#[derive(Debug, Clone, Deserialize)]
pub struct TransferDescription {
    #[serde(default)]
    pub amount_in: u64,
    #[serde(default)]
    pub amount_out: u64,
    #[serde(default)]
    pub recipients: Vec<TransferRecipient>,
    #[serde(default)]
    pub change_amount: u64,
    #[serde(default)]
    pub change_address: String,
    #[serde(default)]
    pub fee: u64,
    #[serde(default)]
    pub ring_size: u32,
    #[serde(default)]
    pub unlock_time: u64,
    #[serde(default)]
    pub dummy_outputs: u64,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Result from `describe_transfer`.
#[derive(Debug, Clone, Deserialize)]
pub struct DescribeTransferResult {
    #[serde(default)]
    pub desc: Vec<TransferDescription>,
}

/// Result from `estimate_tx_size_and_weight`.
#[derive(Debug, Clone, Deserialize)]
pub struct TxSizeAndWeightResult {
    pub size: u64,
    pub weight: u64,
}

/// Payment entry from `get_payments` / `get_bulk_payments`.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentEntry {
    #[serde(default)]
    pub payment_id: String,
    #[serde(default)]
    pub tx_hash: String,
    #[serde(default)]
    pub amount: u64,
    #[serde(default)]
    pub block_height: u64,
    #[serde(default)]
    pub unlock_time: u64,
    #[serde(default)]
    pub locked: bool,
    #[serde(default)]
    pub subaddr_index: SubaddrIndex,
    #[serde(default)]
    pub address: String,
}

/// Result from `check_tx_key`.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckTxKeyResult {
    #[serde(default)]
    pub confirmations: u64,
    #[serde(default)]
    pub received: u64,
    #[serde(default)]
    pub in_pool: bool,
}

/// Result from `check_tx_proof`.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckTxProofResult {
    #[serde(default)]
    pub good: bool,
    #[serde(default)]
    pub confirmations: u64,
    #[serde(default)]
    pub received: u64,
    #[serde(default)]
    pub in_pool: bool,
}

/// Result from `check_reserve_proof`.
#[derive(Debug, Clone, Deserialize)]
pub struct CheckReserveProofResult {
    #[serde(default)]
    pub good: bool,
    #[serde(default)]
    pub total: u64,
    #[serde(default)]
    pub spent: u64,
}

/// Result from `make_integrated_address`.
#[derive(Debug, Clone, Deserialize)]
pub struct IntegratedAddressResult {
    pub integrated_address: String,
    pub payment_id: String,
}

/// Result from `split_integrated_address`.
#[derive(Debug, Clone, Deserialize)]
pub struct SplitIntegratedAddressResult {
    pub standard_address: String,
    pub payment_id: String,
    #[serde(default)]
    pub is_subaddress: bool,
}

/// Parsed URI from `parse_uri`.
#[derive(Debug, Clone, Deserialize)]
pub struct ParsedUri {
    #[serde(default)]
    pub address: String,
    #[serde(default)]
    pub amount: u64,
    #[serde(default)]
    pub payment_id: String,
    #[serde(default)]
    pub recipient_name: String,
    #[serde(default)]
    pub tx_description: String,
}

/// Result from `generate_from_keys`.
#[derive(Debug, Clone, Deserialize)]
pub struct GenerateFromKeysResult {
    pub address: String,
    #[serde(default)]
    pub info: String,
}

/// Result from `prepare_multisig`.
#[derive(Debug, Clone, Deserialize)]
pub struct PrepareMultisigResult {
    pub multisig_info: String,
}

/// Result from `make_multisig`.
#[derive(Debug, Clone, Deserialize)]
pub struct MakeMultisigResult {
    pub address: String,
    pub multisig_info: String,
}

/// Result from `exchange_multisig_keys`.
#[derive(Debug, Clone, Deserialize)]
pub struct ExchangeMultisigKeysResult {
    pub address: String,
    pub multisig_info: String,
}

/// Result from `sign_multisig`.
#[derive(Debug, Clone, Deserialize)]
pub struct SignMultisigResult {
    pub tx_data_hex: String,
    #[serde(default)]
    pub tx_hash_list: Vec<String>,
}

// =============================================================================
// WalletRpc
// =============================================================================

/// Async RPC client for the Salvium wallet.
pub struct WalletRpc {
    client: RpcClient,
}

impl WalletRpc {
    /// Create a wallet RPC client connected to the given URL.
    pub fn new(url: &str) -> Self {
        Self {
            client: RpcClient::new(url),
        }
    }

    /// Create with full configuration.
    pub fn with_config(config: RpcConfig) -> Self {
        Self {
            client: RpcClient::with_config(config),
        }
    }

    /// Get the underlying RPC client.
    pub fn client(&self) -> &RpcClient {
        &self.client
    }

    // =========================================================================
    // Wallet Management
    // =========================================================================

    /// Open a wallet file.
    pub async fn open_wallet(&self, filename: &str, password: &str) -> Result<(), RpcError> {
        self.client
            .call(
                "open_wallet",
                serde_json::json!({
                    "filename": filename,
                    "password": password,
                }),
            )
            .await?;
        Ok(())
    }

    /// Close the current wallet.
    pub async fn close_wallet(&self) -> Result<(), RpcError> {
        self.client
            .call("close_wallet", serde_json::json!({}))
            .await?;
        Ok(())
    }

    /// Create a new wallet.
    pub async fn create_wallet(
        &self,
        filename: &str,
        password: &str,
        language: &str,
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "create_wallet",
                serde_json::json!({
                    "filename": filename,
                    "password": password,
                    "language": language,
                }),
            )
            .await?;
        Ok(())
    }

    /// Restore a wallet from mnemonic seed.
    pub async fn restore_deterministic_wallet(
        &self,
        filename: &str,
        seed: &str,
        password: &str,
        restore_height: u64,
        language: &str,
    ) -> Result<AddressResult, RpcError> {
        let val = self
            .client
            .call(
                "restore_deterministic_wallet",
                serde_json::json!({
                    "filename": filename,
                    "seed": seed,
                    "password": password,
                    "restore_height": restore_height,
                    "language": language,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Generate (restore) a wallet from keys (view key, spend key, address).
    pub async fn generate_from_keys(
        &self,
        filename: &str,
        address: &str,
        spendkey: &str,
        viewkey: &str,
        password: &str,
        restore_height: u64,
    ) -> Result<GenerateFromKeysResult, RpcError> {
        let val = self
            .client
            .call(
                "generate_from_keys",
                serde_json::json!({
                    "filename": filename,
                    "address": address,
                    "spendkey": spendkey,
                    "viewkey": viewkey,
                    "password": password,
                    "restore_height": restore_height,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Change the wallet password.
    pub async fn change_wallet_password(
        &self,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "change_wallet_password",
                serde_json::json!({
                    "old_password": old_password,
                    "new_password": new_password,
                }),
            )
            .await?;
        Ok(())
    }

    /// Get available languages for mnemonic seed.
    pub async fn get_languages(&self) -> Result<Vec<String>, RpcError> {
        let val = self
            .client
            .call("get_languages", serde_json::json!({}))
            .await?;
        let languages = val
            .get("languages")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(languages)?)
    }

    /// Save the wallet to disk.
    pub async fn store(&self) -> Result<(), RpcError> {
        self.client
            .call("store", serde_json::json!({}))
            .await?;
        Ok(())
    }

    // =========================================================================
    // Balance & Address
    // =========================================================================

    /// Get wallet balance.
    pub async fn get_balance(&self, account_index: u32) -> Result<BalanceInfo, RpcError> {
        let val = self
            .client
            .call(
                "get_balance",
                serde_json::json!({ "account_index": account_index }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get wallet address(es).
    pub async fn get_address(&self, account_index: u32) -> Result<AddressResult, RpcError> {
        let val = self
            .client
            .call(
                "get_address",
                serde_json::json!({ "account_index": account_index }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Create a new subaddress.
    pub async fn create_address(
        &self,
        account_index: u32,
        label: &str,
    ) -> Result<AddressEntry, RpcError> {
        let val = self
            .client
            .call(
                "create_address",
                serde_json::json!({
                    "account_index": account_index,
                    "label": label,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get all accounts.
    pub async fn get_accounts(&self) -> Result<AccountsResult, RpcError> {
        let val = self
            .client
            .call("get_accounts", serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Validate an address.
    pub async fn validate_address(&self, address: &str) -> Result<ValidateAddressResult, RpcError> {
        let val = self
            .client
            .call(
                "validate_address",
                serde_json::json!({ "address": address }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get the wallet's current height.
    pub async fn get_height(&self) -> Result<u64, RpcError> {
        let val = self
            .client
            .call("get_height", serde_json::json!({}))
            .await?;
        val.get("height")
            .and_then(|v| v.as_u64())
            .ok_or(RpcError::NoResult { context: "wallet get_height".into() })
    }

    /// Get the index of a subaddress given its address string.
    pub async fn get_address_index(&self, address: &str) -> Result<AddressIndexResult, RpcError> {
        let val = self
            .client
            .call(
                "get_address_index",
                serde_json::json!({ "address": address }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Label a subaddress.
    pub async fn label_address(
        &self,
        account_index: u32,
        address_index: u32,
        label: &str,
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "label_address",
                serde_json::json!({
                    "index": {
                        "major": account_index,
                        "minor": address_index,
                    },
                    "label": label,
                }),
            )
            .await?;
        Ok(())
    }

    // =========================================================================
    // Account Management
    // =========================================================================

    /// Create a new account with an optional label.
    pub async fn create_account(&self, label: &str) -> Result<CreateAccountResult, RpcError> {
        let val = self
            .client
            .call(
                "create_account",
                serde_json::json!({ "label": label }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Set a label for an account.
    pub async fn label_account(
        &self,
        account_index: u32,
        label: &str,
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "label_account",
                serde_json::json!({
                    "account_index": account_index,
                    "label": label,
                }),
            )
            .await?;
        Ok(())
    }

    /// Get account tags.
    pub async fn get_account_tags(&self) -> Result<AccountTagsResult, RpcError> {
        let val = self
            .client
            .call("get_account_tags", serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Tag a set of accounts.
    pub async fn tag_accounts(&self, tag: &str, accounts: &[u32]) -> Result<(), RpcError> {
        self.client
            .call(
                "tag_accounts",
                serde_json::json!({
                    "tag": tag,
                    "accounts": accounts,
                }),
            )
            .await?;
        Ok(())
    }

    /// Remove tags from a set of accounts.
    pub async fn untag_accounts(&self, accounts: &[u32]) -> Result<(), RpcError> {
        self.client
            .call(
                "untag_accounts",
                serde_json::json!({ "accounts": accounts }),
            )
            .await?;
        Ok(())
    }

    /// Set a description for an account tag.
    pub async fn set_account_tag_description(
        &self,
        tag: &str,
        description: &str,
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "set_account_tag_description",
                serde_json::json!({
                    "tag": tag,
                    "description": description,
                }),
            )
            .await?;
        Ok(())
    }

    // =========================================================================
    // Address Book
    // =========================================================================

    /// Get address book entries.
    pub async fn get_address_book(
        &self,
        entries: &[u64],
    ) -> Result<Vec<AddressBookEntry>, RpcError> {
        let val = self
            .client
            .call(
                "get_address_book",
                serde_json::json!({ "entries": entries }),
            )
            .await?;
        let entries = val
            .get("entries")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(entries)?)
    }

    /// Add an entry to the address book.
    pub async fn add_address_book(
        &self,
        address: &str,
        description: &str,
        payment_id: &str,
    ) -> Result<u64, RpcError> {
        let val = self
            .client
            .call(
                "add_address_book",
                serde_json::json!({
                    "address": address,
                    "description": description,
                    "payment_id": payment_id,
                }),
            )
            .await?;
        val.get("index")
            .and_then(|v| v.as_u64())
            .ok_or(RpcError::NoResult { context: "add_address_book(index)".into() })
    }

    /// Edit an address book entry.
    pub async fn edit_address_book(
        &self,
        index: u64,
        address: &str,
        description: &str,
        payment_id: &str,
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "edit_address_book",
                serde_json::json!({
                    "index": index,
                    "set_address": true,
                    "address": address,
                    "set_description": true,
                    "description": description,
                    "set_payment_id": true,
                    "payment_id": payment_id,
                }),
            )
            .await?;
        Ok(())
    }

    /// Delete an address book entry by index.
    pub async fn delete_address_book(&self, index: u64) -> Result<(), RpcError> {
        self.client
            .call(
                "delete_address_book",
                serde_json::json!({ "index": index }),
            )
            .await?;
        Ok(())
    }

    // =========================================================================
    // Transfers
    // =========================================================================

    /// Send a transfer to one or more destinations.
    pub async fn transfer(
        &self,
        destinations: &[Destination],
        account_index: u32,
        priority: u32,
        ring_size: u32,
        get_tx_key: bool,
    ) -> Result<TransferResult, RpcError> {
        let val = self
            .client
            .call(
                "transfer",
                serde_json::json!({
                    "destinations": destinations,
                    "account_index": account_index,
                    "priority": priority,
                    "ring_size": ring_size,
                    "get_tx_key": get_tx_key,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Send a split transfer (may produce multiple transactions).
    pub async fn transfer_split(
        &self,
        destinations: &[Destination],
        account_index: u32,
        priority: u32,
        ring_size: u32,
    ) -> Result<TransferSplitResult, RpcError> {
        let val = self
            .client
            .call(
                "transfer_split",
                serde_json::json!({
                    "destinations": destinations,
                    "account_index": account_index,
                    "priority": priority,
                    "ring_size": ring_size,
                    "get_tx_keys": true,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Sweep all unlocked balance to an address.
    pub async fn sweep_all(
        &self,
        address: &str,
        account_index: u32,
        priority: u32,
    ) -> Result<TransferSplitResult, RpcError> {
        let val = self
            .client
            .call(
                "sweep_all",
                serde_json::json!({
                    "address": address,
                    "account_index": account_index,
                    "priority": priority,
                    "get_tx_keys": true,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Sweep unmixable (dust) outputs.
    pub async fn sweep_dust(&self) -> Result<TransferSplitResult, RpcError> {
        let val = self
            .client
            .call(
                "sweep_dust",
                serde_json::json!({ "get_tx_keys": true }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Sweep a single output identified by its key image.
    pub async fn sweep_single(
        &self,
        key_image: &str,
        address: &str,
        priority: u32,
        ring_size: u32,
    ) -> Result<TransferResult, RpcError> {
        let val = self
            .client
            .call(
                "sweep_single",
                serde_json::json!({
                    "key_image": key_image,
                    "address": address,
                    "priority": priority,
                    "ring_size": ring_size,
                    "get_tx_key": true,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Relay a previously created but not relayed transaction.
    pub async fn relay_tx(&self, hex: &str) -> Result<String, RpcError> {
        let val = self
            .client
            .call("relay_tx", serde_json::json!({ "hex": hex }))
            .await?;
        val.get("tx_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "relay_tx(tx_hash)".into() })
    }

    /// Sign an unsigned transaction set (for cold-signing workflow).
    pub async fn sign_transfer(
        &self,
        unsigned_txset: &str,
    ) -> Result<SignTransferResult, RpcError> {
        let val = self
            .client
            .call(
                "sign_transfer",
                serde_json::json!({ "unsigned_txset": unsigned_txset }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Describe an unsigned or multisig transaction set without signing it.
    pub async fn describe_transfer(
        &self,
        unsigned_txset: Option<&str>,
        multisig_txset: Option<&str>,
    ) -> Result<DescribeTransferResult, RpcError> {
        let mut params = serde_json::json!({});
        if let Some(txset) = unsigned_txset {
            params["unsigned_txset"] = serde_json::json!(txset);
        }
        if let Some(txset) = multisig_txset {
            params["multisig_txset"] = serde_json::json!(txset);
        }
        let val = self.client.call("describe_transfer", params).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Submit a previously signed transaction.
    pub async fn submit_transfer(&self, tx_data_hex: &str) -> Result<Vec<String>, RpcError> {
        let val = self
            .client
            .call(
                "submit_transfer",
                serde_json::json!({ "tx_data_hex": tx_data_hex }),
            )
            .await?;
        let list = val
            .get("tx_hash_list")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(list)?)
    }

    /// Estimate transaction size and weight.
    pub async fn estimate_tx_size_and_weight(
        &self,
        n_inputs: u32,
        n_outputs: u32,
        ring_size: u32,
    ) -> Result<TxSizeAndWeightResult, RpcError> {
        let val = self
            .client
            .call(
                "estimate_tx_size_and_weight",
                serde_json::json!({
                    "n_inputs": n_inputs,
                    "n_outputs": n_outputs,
                    "ring_size": ring_size,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Payment Operations
    // =========================================================================

    /// Get payments by payment ID.
    pub async fn get_payments(&self, payment_id: &str) -> Result<Vec<PaymentEntry>, RpcError> {
        let val = self
            .client
            .call(
                "get_payments",
                serde_json::json!({ "payment_id": payment_id }),
            )
            .await?;
        let payments = val
            .get("payments")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(payments)?)
    }

    /// Get payments for multiple payment IDs above a minimum block height.
    pub async fn get_bulk_payments(
        &self,
        payment_ids: &[&str],
        min_block_height: u64,
    ) -> Result<Vec<PaymentEntry>, RpcError> {
        let val = self
            .client
            .call(
                "get_bulk_payments",
                serde_json::json!({
                    "payment_ids": payment_ids,
                    "min_block_height": min_block_height,
                }),
            )
            .await?;
        let payments = val
            .get("payments")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(payments)?)
    }

    // =========================================================================
    // Transfer History
    // =========================================================================

    /// Get transfer history.
    #[allow(clippy::too_many_arguments)]
    pub async fn get_transfers(
        &self,
        incoming: bool,
        outgoing: bool,
        pending: bool,
        failed: bool,
        pool: bool,
        account_index: u32,
        min_height: Option<u64>,
        max_height: Option<u64>,
    ) -> Result<TransfersResult, RpcError> {
        let mut params = serde_json::json!({
            "in": incoming,
            "out": outgoing,
            "pending": pending,
            "failed": failed,
            "pool": pool,
            "account_index": account_index,
        });

        if let Some(min) = min_height {
            params["filter_by_height"] = serde_json::json!(true);
            params["min_height"] = serde_json::json!(min);
        }
        if let Some(max) = max_height {
            params["filter_by_height"] = serde_json::json!(true);
            params["max_height"] = serde_json::json!(max);
        }

        let val = self.client.call("get_transfers", params).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get a specific transfer by transaction ID.
    pub async fn get_transfer_by_txid(&self, txid: &str) -> Result<TransferEntry, RpcError> {
        let val = self
            .client
            .call(
                "get_transfer_by_txid",
                serde_json::json!({ "txid": txid }),
            )
            .await?;
        let transfer = val.get("transfer").ok_or(RpcError::NoResult { context: "get_transfer_by_txid".into() })?;
        Ok(serde_json::from_value(transfer.clone())?)
    }

    /// Get incoming transfers (UTXOs).
    pub async fn incoming_transfers(
        &self,
        transfer_type: &str, // "all", "available", "unavailable"
        account_index: u32,
    ) -> Result<Vec<IncomingTransfer>, RpcError> {
        let val = self
            .client
            .call(
                "incoming_transfers",
                serde_json::json!({
                    "transfer_type": transfer_type,
                    "account_index": account_index,
                }),
            )
            .await?;
        let transfers = val
            .get("transfers")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(transfers)?)
    }

    // =========================================================================
    // Key Management
    // =========================================================================

    /// Get the mnemonic seed.
    pub async fn get_mnemonic(&self) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "query_key",
                serde_json::json!({ "key_type": "mnemonic" }),
            )
            .await?;
        val.get("key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_mnemonic(key)".into() })
    }

    /// Get the view key.
    pub async fn get_view_key(&self) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "query_key",
                serde_json::json!({ "key_type": "view_key" }),
            )
            .await?;
        val.get("key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_view_key(key)".into() })
    }

    /// Get the spend key.
    pub async fn get_spend_key(&self) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "query_key",
                serde_json::json!({ "key_type": "spend_key" }),
            )
            .await?;
        val.get("key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_spend_key(key)".into() })
    }

    /// Export key images.
    pub async fn export_key_images(&self) -> Result<Vec<KeyImageEntry>, RpcError> {
        let val = self
            .client
            .call(
                "export_key_images",
                serde_json::json!({ "all": true }),
            )
            .await?;
        let images = val
            .get("signed_key_images")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(images)?)
    }

    /// Import key images.
    pub async fn import_key_images(
        &self,
        signed_key_images: &[KeyImageEntry],
    ) -> Result<KeyImageImportResult, RpcError> {
        let val = self
            .client
            .call(
                "import_key_images",
                serde_json::json!({ "signed_key_images": signed_key_images }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // Output Import/Export
    // =========================================================================

    /// Export outputs as hex data.
    pub async fn export_outputs(&self, all: bool) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "export_outputs",
                serde_json::json!({ "all": all }),
            )
            .await?;
        val.get("outputs_data_hex")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "export_outputs(outputs_data_hex)".into() })
    }

    /// Import outputs from hex data.
    pub async fn import_outputs(&self, outputs_data_hex: &str) -> Result<u64, RpcError> {
        let val = self
            .client
            .call(
                "import_outputs",
                serde_json::json!({ "outputs_data_hex": outputs_data_hex }),
            )
            .await?;
        val.get("num_imported")
            .and_then(|v| v.as_u64())
            .ok_or(RpcError::NoResult { context: "import_outputs(num_imported)".into() })
    }

    // =========================================================================
    // Wallet Operations
    // =========================================================================

    /// Refresh the wallet (scan for new transactions).
    pub async fn refresh(&self, start_height: Option<u64>) -> Result<RefreshResult, RpcError> {
        let params = match start_height {
            Some(h) => serde_json::json!({ "start_height": h }),
            None => serde_json::json!({}),
        };
        let val = self.client.call("refresh", params).await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Rescan the blockchain from scratch.
    pub async fn rescan_blockchain(&self) -> Result<(), RpcError> {
        self.client
            .call("rescan_blockchain", serde_json::json!({}))
            .await?;
        Ok(())
    }

    /// Get the wallet's version.
    pub async fn get_version(&self) -> Result<u32, RpcError> {
        let val = self
            .client
            .call("get_version", serde_json::json!({}))
            .await?;
        val.get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .ok_or(RpcError::NoResult { context: "get_version".into() })
    }

    /// Check if wallet is multisig.
    pub async fn is_multisig(&self) -> Result<bool, RpcError> {
        let val = self
            .client
            .call("is_multisig", serde_json::json!({}))
            .await?;
        Ok(val.get("multisig").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    // =========================================================================
    // Signing & Proofs
    // =========================================================================

    /// Sign arbitrary data.
    pub async fn sign(&self, data: &str) -> Result<String, RpcError> {
        let val = self
            .client
            .call("sign", serde_json::json!({ "data": data }))
            .await?;
        val.get("signature")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "sign(signature)".into() })
    }

    /// Verify a signature.
    pub async fn verify(
        &self,
        data: &str,
        address: &str,
        signature: &str,
    ) -> Result<bool, RpcError> {
        let val = self
            .client
            .call(
                "verify",
                serde_json::json!({
                    "data": data,
                    "address": address,
                    "signature": signature,
                }),
            )
            .await?;
        Ok(val.get("good").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    /// Get a TX key for a given transaction.
    pub async fn get_tx_key(&self, txid: &str) -> Result<String, RpcError> {
        let val = self
            .client
            .call("get_tx_key", serde_json::json!({ "txid": txid }))
            .await?;
        val.get("tx_key")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_tx_key(tx_key)".into() })
    }

    /// Check a TX key to verify a payment to an address.
    pub async fn check_tx_key(
        &self,
        txid: &str,
        tx_key: &str,
        address: &str,
    ) -> Result<CheckTxKeyResult, RpcError> {
        let val = self
            .client
            .call(
                "check_tx_key",
                serde_json::json!({
                    "txid": txid,
                    "tx_key": tx_key,
                    "address": address,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get a transaction proof.
    pub async fn get_tx_proof(
        &self,
        txid: &str,
        address: &str,
        message: &str,
    ) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "get_tx_proof",
                serde_json::json!({
                    "txid": txid,
                    "address": address,
                    "message": message,
                }),
            )
            .await?;
        val.get("signature")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_tx_proof(signature)".into() })
    }

    /// Check a transaction proof.
    pub async fn check_tx_proof(
        &self,
        txid: &str,
        address: &str,
        message: &str,
        signature: &str,
    ) -> Result<CheckTxProofResult, RpcError> {
        let val = self
            .client
            .call(
                "check_tx_proof",
                serde_json::json!({
                    "txid": txid,
                    "address": address,
                    "message": message,
                    "signature": signature,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Get a spend proof for a transaction.
    pub async fn get_spend_proof(
        &self,
        txid: &str,
        message: &str,
    ) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "get_spend_proof",
                serde_json::json!({
                    "txid": txid,
                    "message": message,
                }),
            )
            .await?;
        val.get("signature")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_spend_proof(signature)".into() })
    }

    /// Verify a spend proof.
    pub async fn check_spend_proof(
        &self,
        txid: &str,
        message: &str,
        signature: &str,
    ) -> Result<bool, RpcError> {
        let val = self
            .client
            .call(
                "check_spend_proof",
                serde_json::json!({
                    "txid": txid,
                    "message": message,
                    "signature": signature,
                }),
            )
            .await?;
        Ok(val.get("good").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    /// Get a reserve proof to prove balance.
    pub async fn get_reserve_proof(
        &self,
        all: bool,
        account_index: u32,
        amount: u64,
        message: &str,
    ) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "get_reserve_proof",
                serde_json::json!({
                    "all": all,
                    "account_index": account_index,
                    "amount": amount,
                    "message": message,
                }),
            )
            .await?;
        val.get("signature")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_reserve_proof(signature)".into() })
    }

    /// Verify a reserve proof.
    pub async fn check_reserve_proof(
        &self,
        address: &str,
        message: &str,
        signature: &str,
    ) -> Result<CheckReserveProofResult, RpcError> {
        let val = self
            .client
            .call(
                "check_reserve_proof",
                serde_json::json!({
                    "address": address,
                    "message": message,
                    "signature": signature,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // TX Notes
    // =========================================================================

    /// Set notes for transactions.
    pub async fn set_tx_notes(
        &self,
        txids: &[&str],
        notes: &[&str],
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "set_tx_notes",
                serde_json::json!({
                    "txids": txids,
                    "notes": notes,
                }),
            )
            .await?;
        Ok(())
    }

    /// Get notes for transactions.
    pub async fn get_tx_notes(&self, txids: &[&str]) -> Result<Vec<String>, RpcError> {
        let val = self
            .client
            .call(
                "get_tx_notes",
                serde_json::json!({ "txids": txids }),
            )
            .await?;
        let notes = val
            .get("notes")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(notes)?)
    }

    // =========================================================================
    // Attributes
    // =========================================================================

    /// Set an arbitrary attribute on the wallet.
    pub async fn set_attribute(&self, key: &str, value: &str) -> Result<(), RpcError> {
        self.client
            .call(
                "set_attribute",
                serde_json::json!({
                    "key": key,
                    "value": value,
                }),
            )
            .await?;
        Ok(())
    }

    /// Get an attribute value from the wallet.
    pub async fn get_attribute(&self, key: &str) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "get_attribute",
                serde_json::json!({ "key": key }),
            )
            .await?;
        val.get("value")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "get_attribute(value)".into() })
    }

    // =========================================================================
    // Integrated Addresses
    // =========================================================================

    /// Create an integrated address from a standard address and payment ID.
    pub async fn make_integrated_address(
        &self,
        standard_address: &str,
        payment_id: &str,
    ) -> Result<IntegratedAddressResult, RpcError> {
        let val = self
            .client
            .call(
                "make_integrated_address",
                serde_json::json!({
                    "standard_address": standard_address,
                    "payment_id": payment_id,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Split an integrated address into standard address and payment ID.
    pub async fn split_integrated_address(
        &self,
        integrated_address: &str,
    ) -> Result<SplitIntegratedAddressResult, RpcError> {
        let val = self
            .client
            .call(
                "split_integrated_address",
                serde_json::json!({ "integrated_address": integrated_address }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    // =========================================================================
    // URI
    // =========================================================================

    /// Create a payment URI.
    pub async fn make_uri(
        &self,
        address: &str,
        amount: u64,
        payment_id: &str,
        recipient_name: &str,
        tx_description: &str,
    ) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "make_uri",
                serde_json::json!({
                    "address": address,
                    "amount": amount,
                    "payment_id": payment_id,
                    "recipient_name": recipient_name,
                    "tx_description": tx_description,
                }),
            )
            .await?;
        val.get("uri")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "make_uri(uri)".into() })
    }

    /// Parse a payment URI.
    pub async fn parse_uri(&self, uri: &str) -> Result<ParsedUri, RpcError> {
        let val = self
            .client
            .call(
                "parse_uri",
                serde_json::json!({ "uri": uri }),
            )
            .await?;
        let uri_obj = val.get("uri").ok_or(RpcError::NoResult {
            context: "parse_uri(uri)".into(),
        })?;
        Ok(serde_json::from_value(uri_obj.clone())?)
    }

    // =========================================================================
    // Multisig
    // =========================================================================

    /// Prepare a wallet for multisig by generating a multisig info string.
    pub async fn prepare_multisig(&self) -> Result<PrepareMultisigResult, RpcError> {
        let val = self
            .client
            .call("prepare_multisig", serde_json::json!({}))
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Make a multisig wallet from the info strings of all participants.
    pub async fn make_multisig(
        &self,
        multisig_info: &[&str],
        threshold: u32,
        password: &str,
    ) -> Result<MakeMultisigResult, RpcError> {
        let val = self
            .client
            .call(
                "make_multisig",
                serde_json::json!({
                    "multisig_info": multisig_info,
                    "threshold": threshold,
                    "password": password,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Export multisig info for other participants.
    pub async fn export_multisig_info(&self) -> Result<String, RpcError> {
        let val = self
            .client
            .call("export_multisig_info", serde_json::json!({}))
            .await?;
        val.get("info")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "export_multisig_info(info)".into() })
    }

    /// Import multisig info from other participants.
    pub async fn import_multisig_info(&self, info: &[&str]) -> Result<u64, RpcError> {
        let val = self
            .client
            .call(
                "import_multisig_info",
                serde_json::json!({ "info": info }),
            )
            .await?;
        val.get("n_outputs")
            .and_then(|v| v.as_u64())
            .ok_or(RpcError::NoResult { context: "import_multisig_info(n_outputs)".into() })
    }

    /// Finalize a multisig wallet setup.
    pub async fn finalize_multisig(
        &self,
        multisig_info: &[&str],
        password: &str,
    ) -> Result<String, RpcError> {
        let val = self
            .client
            .call(
                "finalize_multisig",
                serde_json::json!({
                    "multisig_info": multisig_info,
                    "password": password,
                }),
            )
            .await?;
        val.get("address")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or(RpcError::NoResult { context: "finalize_multisig(address)".into() })
    }

    /// Exchange multisig keys (for N-1/N and M/N multisig).
    pub async fn exchange_multisig_keys(
        &self,
        multisig_info: &[&str],
        password: &str,
    ) -> Result<ExchangeMultisigKeysResult, RpcError> {
        let val = self
            .client
            .call(
                "exchange_multisig_keys",
                serde_json::json!({
                    "multisig_info": multisig_info,
                    "password": password,
                }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Sign a multisig transaction.
    pub async fn sign_multisig(
        &self,
        tx_data_hex: &str,
    ) -> Result<SignMultisigResult, RpcError> {
        let val = self
            .client
            .call(
                "sign_multisig",
                serde_json::json!({ "tx_data_hex": tx_data_hex }),
            )
            .await?;
        Ok(serde_json::from_value(val)?)
    }

    /// Submit a signed multisig transaction for broadcasting.
    pub async fn submit_multisig(&self, tx_data_hex: &str) -> Result<Vec<String>, RpcError> {
        let val = self
            .client
            .call(
                "submit_multisig",
                serde_json::json!({ "tx_data_hex": tx_data_hex }),
            )
            .await?;
        let list = val
            .get("tx_hash_list")
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        Ok(serde_json::from_value(list)?)
    }

    // =========================================================================
    // Sync Operations
    // =========================================================================

    /// Enable or disable auto-refresh, with an optional period in seconds.
    pub async fn auto_refresh(
        &self,
        enable: bool,
        period: Option<u64>,
    ) -> Result<(), RpcError> {
        let mut params = serde_json::json!({ "enable": enable });
        if let Some(p) = period {
            params["period"] = serde_json::json!(p);
        }
        self.client.call("auto_refresh", params).await?;
        Ok(())
    }

    /// Rescan the blockchain for spent outputs.
    pub async fn rescan_spent(&self) -> Result<(), RpcError> {
        self.client
            .call("rescan_spent", serde_json::json!({}))
            .await?;
        Ok(())
    }

    /// Scan specific transactions by their IDs.
    pub async fn scan_tx(&self, txids: &[&str]) -> Result<(), RpcError> {
        self.client
            .call(
                "scan_tx",
                serde_json::json!({ "txids": txids }),
            )
            .await?;
        Ok(())
    }

    // =========================================================================
    // Daemon Connection
    // =========================================================================

    /// Set the daemon the wallet should connect to.
    pub async fn set_daemon(
        &self,
        address: &str,
        trusted: bool,
    ) -> Result<(), RpcError> {
        self.client
            .call(
                "set_daemon",
                serde_json::json!({
                    "address": address,
                    "trusted": trusted,
                }),
            )
            .await?;
        Ok(())
    }

    // =========================================================================
    // Output Freeze/Thaw
    // =========================================================================

    /// Freeze an output by key image, preventing it from being used in transactions.
    pub async fn freeze(&self, key_image: &str) -> Result<(), RpcError> {
        self.client
            .call(
                "freeze",
                serde_json::json!({ "key_image": key_image }),
            )
            .await?;
        Ok(())
    }

    /// Thaw (unfreeze) a previously frozen output.
    pub async fn thaw(&self, key_image: &str) -> Result<(), RpcError> {
        self.client
            .call(
                "thaw",
                serde_json::json!({ "key_image": key_image }),
            )
            .await?;
        Ok(())
    }

    /// Check if an output is frozen.
    pub async fn frozen(&self, key_image: &str) -> Result<bool, RpcError> {
        let val = self
            .client
            .call(
                "frozen",
                serde_json::json!({ "key_image": key_image }),
            )
            .await?;
        Ok(val.get("frozen").and_then(|v| v.as_bool()).unwrap_or(false))
    }
}

/// Key image entry for import/export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyImageEntry {
    pub key_image: String,
    pub signature: String,
}

/// Result of key image import.
#[derive(Debug, Clone, Deserialize)]
pub struct KeyImageImportResult {
    pub height: u64,
    pub spent: u64,
    pub unspent: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_rpc_creation() {
        let wallet = WalletRpc::new("http://localhost:19083");
        assert_eq!(wallet.client().url(), "http://localhost:19083");
    }

    #[test]
    fn test_destination_serialize() {
        let dest = Destination {
            address: "SaLv...".to_string(),
            amount: 100_000_000,
        };
        let json = serde_json::to_value(&dest).unwrap();
        assert_eq!(json["amount"], 100_000_000);
    }

    #[test]
    fn test_balance_info_deserialize() {
        let json = serde_json::json!({
            "balance": 500_000_000,
            "unlocked_balance": 400_000_000,
            "multisig_import_needed": false
        });
        let info: BalanceInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.balance, 500_000_000);
        assert_eq!(info.unlocked_balance, 400_000_000);
    }

    #[test]
    fn test_transfers_result_deserialize() {
        let json = serde_json::json!({
            "in": [{
                "txid": "abc123",
                "payment_id": "",
                "height": 100,
                "timestamp": 1700000000,
                "amount": 50_000_000,
                "fee": 0,
                "confirmations": 10,
                "address": "SaLv...",
                "subaddr_index": { "major": 0, "minor": 0 }
            }],
            "out": []
        });
        let result: TransfersResult = serde_json::from_value(json).unwrap();
        assert_eq!(result.incoming.len(), 1);
        assert_eq!(result.incoming[0].amount, 50_000_000);
        assert!(result.out.is_empty());
    }

    #[test]
    fn test_address_book_entry_deserialize() {
        let json = serde_json::json!({
            "index": 0,
            "address": "SaLv1234...",
            "description": "Bob's wallet",
            "payment_id": "0000000000000000"
        });
        let entry: AddressBookEntry = serde_json::from_value(json).unwrap();
        assert_eq!(entry.index, 0);
        assert_eq!(entry.address, "SaLv1234...");
        assert_eq!(entry.description, "Bob's wallet");
    }

    #[test]
    fn test_check_tx_proof_result_deserialize() {
        let json = serde_json::json!({
            "good": true,
            "confirmations": 42,
            "received": 1_000_000_000,
            "in_pool": false
        });
        let result: CheckTxProofResult = serde_json::from_value(json).unwrap();
        assert!(result.good);
        assert_eq!(result.confirmations, 42);
        assert_eq!(result.received, 1_000_000_000);
        assert!(!result.in_pool);
    }

    #[test]
    fn test_transfer_description_deserialize() {
        let json = serde_json::json!({
            "amount_in": 2_000_000_000,
            "amount_out": 1_500_000_000,
            "recipients": [
                { "address": "SaLv1234...", "amount": 1_000_000_000 },
                { "address": "SaLv5678...", "amount": 500_000_000 }
            ],
            "change_amount": 490_000_000,
            "change_address": "SaLvChange...",
            "fee": 10_000_000,
            "ring_size": 16
        });
        let desc: TransferDescription = serde_json::from_value(json).unwrap();
        assert_eq!(desc.amount_in, 2_000_000_000);
        assert_eq!(desc.amount_out, 1_500_000_000);
        assert_eq!(desc.recipients.len(), 2);
        assert_eq!(desc.recipients[0].amount, 1_000_000_000);
        assert_eq!(desc.fee, 10_000_000);
        assert_eq!(desc.ring_size, 16);
    }
}
