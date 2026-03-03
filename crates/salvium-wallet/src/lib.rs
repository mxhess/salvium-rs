//! Salvium wallet core.
//!
//! Provides key management, output scanning, blockchain sync, balance tracking,
//! UTXO selection, and wallet file encryption.

pub mod account;
#[cfg(not(target_arch = "wasm32"))]
pub mod device;
pub mod encryption;
pub mod error;
pub mod js_import;
pub mod keys;
#[cfg(not(target_arch = "wasm32"))]
pub mod mms;
#[cfg(not(target_arch = "wasm32"))]
pub(crate) mod pool_scan;
pub mod pqc;
#[cfg(not(target_arch = "wasm32"))]
pub mod query;
pub mod scanner;
pub mod stake;
pub mod sync;
pub mod token;
pub mod utxo;
pub mod wallet;

pub use account::Account;
pub use error::WalletError;
pub use js_import::{decrypt_js_wallet, JsWalletSecrets};
pub use keys::{CarrotKeys, CnKeys, WalletKeys, WalletType};
#[cfg(not(target_arch = "wasm32"))]
pub use pool_scan::PoolScanResult;
pub use pqc::{decrypt_envelope, encrypt_envelope, PqcEnvelope, WalletSecrets};
pub use scanner::{FoundOutput, ScanContext};
pub use sync::{SyncEngine, SyncEvent};
pub use token::{validate_create_token_params, CreateTokenParams, CREATE_TOKEN_COST};
pub use utxo::{SelectionOptions, SelectionStrategy};
pub use wallet::{MultisigStatus, Wallet};

// Re-export storage types from salvium-crypto for convenience.
#[cfg(not(target_arch = "wasm32"))]
pub use salvium_crypto::storage::{
    AddressBookEntry, BalanceResult, MmsMessageRow, MmsSignerRow, OutputQuery, OutputRow, StakeRow,
    SubaddressIndex, SubaddressRow, TransactionRow, TxQuery, WalletDb,
};
