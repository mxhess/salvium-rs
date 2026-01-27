/**
 * Wallet Module Index
 *
 * Re-exports all wallet-related functionality from submodules.
 * This allows for both granular imports and backward-compatible bulk imports.
 *
 * @module wallet
 */

// Constants
export {
  TX_TYPE,
  MAX_SUBADDRESS_MAJOR_INDEX,
  MAX_SUBADDRESS_MINOR_INDEX,
  DEFAULT_UNLOCK_BLOCKS,
  WALLET_TYPE
} from './constants.js';

// Listener Classes
export {
  WalletListener,
  ConsoleListener,
  CallbackListener
} from './listener.js';

// Account Class
export { Account } from './account.js';
