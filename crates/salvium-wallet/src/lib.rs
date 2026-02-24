//! Salvium wallet core.
//!
//! Provides key management, output scanning, blockchain sync, balance tracking,
//! UTXO selection, and wallet file encryption.

pub mod error;
pub mod keys;
pub mod account;
pub mod scanner;
pub mod sync;
pub mod utxo;
pub mod encryption;
pub mod js_import;
pub mod pqc;
pub mod wallet;
pub mod stake;
#[cfg(not(target_arch = "wasm32"))]
pub mod query;

pub use error::WalletError;
pub use keys::{WalletKeys, WalletType, CnKeys, CarrotKeys};
pub use account::Account;
pub use scanner::{ScanContext, FoundOutput};
pub use sync::{SyncEngine, SyncEvent};
pub use utxo::{SelectionStrategy, SelectionOptions};
pub use wallet::{Wallet, MultisigStatus};
pub use js_import::{JsWalletSecrets, decrypt_js_wallet};
pub use pqc::{WalletSecrets, PqcEnvelope, encrypt_envelope, decrypt_envelope};

// Re-export storage types from salvium-crypto for convenience.
#[cfg(not(target_arch = "wasm32"))]
pub use salvium_crypto::storage::{
    OutputRow, TransactionRow, StakeRow, SubaddressIndex, SubaddressRow,
    OutputQuery, TxQuery, BalanceResult, WalletDb, AddressBookEntry,
};
