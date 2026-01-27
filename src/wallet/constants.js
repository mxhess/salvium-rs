/**
 * Wallet Constants Module
 *
 * Constants specific to wallet operations:
 * - Subaddress limits
 * - Wallet types
 * - Default unlock time
 *
 * @module wallet/constants
 */

// TX_TYPE is re-exported from transaction for convenience
import { TX_TYPE } from '../transaction.js';
export { TX_TYPE };

// =============================================================================
// SUBADDRESS LIMITS
// =============================================================================

/**
 * Subaddress index limits (32-bit unsigned integers)
 * No practical limit - use as many accounts/subaddresses as needed
 */
export const MAX_SUBADDRESS_MAJOR_INDEX = 0xFFFFFFFF;
export const MAX_SUBADDRESS_MINOR_INDEX = 0xFFFFFFFF;

// =============================================================================
// UNLOCK CONSTANTS
// =============================================================================

/**
 * Default unlock time in blocks
 */
export const DEFAULT_UNLOCK_BLOCKS = 10;

// =============================================================================
// WALLET TYPES
// =============================================================================

/**
 * Wallet types
 */
export const WALLET_TYPE = {
  FULL: 'full',           // Full wallet with spend key
  VIEW_ONLY: 'view_only', // View-only (no spend key)
  WATCH: 'watch'          // Watch-only (public keys only)
};
