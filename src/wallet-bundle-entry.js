/**
 * Wallet-only entry point for QuickJS bundle.
 * Excludes mining, stratum, RandomX, and other Node.js-dependent modules.
 */

// Core crypto and helpers
export * from './constants.js';
export * from './keccak.js';
export * from './base58.js';
export * from './address.js';
export * from './signature.js';
export * from './blake2b.js';
export * from './carrot.js';
export * from './subaddress.js';
export * from './mnemonic.js';
export * from './scanning.js';
export * from './keyimage.js';
export * from './transaction.js';
export * from './bulletproofs_plus.js';
export * from './wallet.js';
export * from './query.js';
export * from './connection-manager.js';
export * from './offline.js';
export * from './multisig.js';
export * from './wallet-store.js';
export * from './wallet-sync.js';
export { transfer, sweep, stake } from './wallet/transfer.js';
export * from './persistent-wallet.js';
export * from './consensus.js';

// Post-quantum wallet encryption
export { encryptWalletJSON, decryptWalletJSON, reEncryptWalletJSON, isEncryptedWallet, encryptData, decryptData } from './wallet-encryption.js';

// Validation
export * from './validation.js';
export * as validation from './validation.js';

// Oracle (selective)
export {
  ASSET_TYPES,
  ORACLE_URLS,
  createEmptyPricingRecord,
  isPricingRecordEmpty,
  getAssetPrice,
  getConversionRate,
  getConvertedAmount,
  calculateConversion,
  fetchPricingRecord
} from './oracle.js';

// Wordlists
export * as wordlists from './wordlists/index.js';

// RPC clients
export * as rpc from './rpc/index.js';
export {
  RPCClient,
  DaemonRPC,
  WalletRPC,
  createDaemonRPC,
  createWalletRPC,
  RPC_ERROR_CODES,
  RPC_STATUS,
  PRIORITY,
  TRANSFER_TYPE
} from './rpc/index.js';

// Crypto backend
export { setCryptoBackend, getCryptoBackend, getCurrentBackendType } from './crypto/index.js';

// Wallet class
import {
  Wallet,
  createWallet,
  restoreWallet,
  createViewOnlyWallet
} from './wallet.js';

export { Wallet, createWallet, restoreWallet, createViewOnlyWallet };
