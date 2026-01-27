/**
 * Transaction Constants Module
 *
 * All constants used throughout the transaction system:
 * - Curve constants (L, H)
 * - Transaction types and versions
 * - RingCT types
 * - Input/Output types
 * - Fee constants and priorities
 * - CARROT domain separators
 * - Network parameters
 *
 * @module transaction/constants
 */

// =============================================================================
// ERROR CLASSES
// =============================================================================

/**
 * Error thrown when parsing fails
 * Provides detailed context about what went wrong and where
 */
export class ParseError extends Error {
  constructor(message, context = {}) {
    super(message);
    this.name = 'ParseError';
    this.offset = context.offset;
    this.field = context.field;
    this.expected = context.expected;
    this.actual = context.actual;
    this.dataLength = context.dataLength;
  }

  toString() {
    let msg = `ParseError: ${this.message}`;
    if (this.field) msg += ` [field: ${this.field}]`;
    if (this.offset !== undefined) msg += ` [offset: ${this.offset}]`;
    if (this.dataLength !== undefined) msg += ` [dataLength: ${this.dataLength}]`;
    if (this.expected !== undefined) msg += ` [expected: ${this.expected}]`;
    if (this.actual !== undefined) msg += ` [actual: ${this.actual}]`;
    return msg;
  }
}

// =============================================================================
// CURVE CONSTANTS
// =============================================================================

/**
 * The subgroup order L = 2^252 + 27742317777372353535851937790883648493
 * This is the order of the prime-order subgroup of the Ed25519 curve.
 * All scalar operations are performed mod L.
 */
export const L = 2n ** 252n + 27742317777372353535851937790883648493n;

/**
 * The field prime p = 2^255 - 19
 */
export const P = 2n ** 255n - 19n;

/**
 * H = toPoint(cn_fast_hash(G)) - the second generator for Pedersen commitments
 * H is computed as H_p(G) where H_p is the hash-to-point function
 * Pre-computed value from rctTypes.h
 */
export const H = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';

// =============================================================================
// TRANSACTION VERSION CONSTANTS
// =============================================================================

/**
 * Transaction version constants
 */
export const TX_VERSION = {
  V1: 1,  // Pre-RingCT
  V2: 2   // RingCT
};

// =============================================================================
// TRANSACTION TYPE CONSTANTS
// =============================================================================

/**
 * Transaction type constants (from cryptonote_protocol/enums.h)
 */
export const TX_TYPE = {
  UNSET: 0,
  MINER: 1,
  PROTOCOL: 2,
  TRANSFER: 3,
  CONVERT: 4,
  BURN: 5,
  STAKE: 6,
  RETURN: 7,
  AUDIT: 8
};

// =============================================================================
// RINGCT TYPE CONSTANTS
// =============================================================================

/**
 * RingCT type constants
 */
export const RCT_TYPE = {
  Null: 0,
  Full: 1,
  Simple: 2,
  Bulletproof: 3,
  Bulletproof2: 4,
  CLSAG: 5,
  BulletproofPlus: 6,
  FullProofs: 7,       // Salvium: BulletproofPlus + CLSAGs + partial salvium_data
  SalviumZero: 8,      // Salvium: BulletproofPlus + CLSAGs + full salvium_data
  SalviumOne: 9        // Salvium: BulletproofPlus + TCLSAGs + full salvium_data
};

// =============================================================================
// INPUT/OUTPUT TYPE CONSTANTS
// =============================================================================

/**
 * Transaction output type constants
 */
export const TXOUT_TYPE = {
  ToKey: 0x02,
  KEY: 0x02,          // Alias
  ToTaggedKey: 0x03,
  TAGGED_KEY: 0x03    // Alias
};

/**
 * Transaction input type constants
 */
export const TXIN_TYPE = {
  Gen: 0xff,    // Coinbase/generation
  GEN: 0xff,    // Alias
  ToKey: 0x02,  // Regular input
  KEY: 0x02     // Alias
};

// =============================================================================
// NETWORK PARAMETERS
// =============================================================================

/**
 * Difficulty target (seconds per block)
 */
export const DIFFICULTY_TARGET = 120;

/**
 * Recent spend window in seconds (outputs expected to be spent quickly)
 */
export const RECENT_SPEND_WINDOW = 15 * DIFFICULTY_TARGET; // 1800 seconds

/**
 * Default number of confirmations before output is spendable
 */
export const CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10;

/**
 * Default ring size for transactions
 */
export const DEFAULT_RING_SIZE = 16;

/**
 * HF version that enables oracle pricing records
 * (Currently set to 255, meaning pricing records not yet active)
 */
export const HF_VERSION_ENABLE_ORACLE = 255;

// =============================================================================
// FEE CONSTANTS
// =============================================================================

/**
 * Fee per KB (legacy)
 */
export const FEE_PER_KB = 200000n; // 2 * 10^5 atomic units

/**
 * Fee per byte
 */
export const FEE_PER_BYTE = 30n;

/**
 * Dynamic fee base fee per KB
 */
export const DYNAMIC_FEE_PER_KB_BASE_FEE = 200000n;

/**
 * Dynamic fee base block reward
 */
export const DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD = 1000000000n; // 10 * 10^8

/**
 * Dynamic fee reference transaction weight
 */
export const DYNAMIC_FEE_REFERENCE_TX_WEIGHT = 3000n;

/**
 * Fee quantization decimals
 */
export const FEE_QUANTIZATION_DECIMALS = 8;

/**
 * Fee priority multipliers (algorithm 3)
 * Priority 1 (low) to 4 (high)
 */
export const FEE_MULTIPLIERS = [1n, 5n, 25n, 1000n];

/**
 * Fee priority levels
 */
export const FEE_PRIORITY = {
  LOW: 1,
  NORMAL: 2,
  HIGH: 3,
  HIGHEST: 4
};

/**
 * Get fee multiplier for priority level
 * @param {number} priority - Priority level (1-4)
 * @returns {bigint} Multiplier
 */
export function getFeeMultiplier(priority) {
  if (priority < 1) priority = 1;
  if (priority > 4) priority = 4;
  return FEE_MULTIPLIERS[priority - 1];
}

// =============================================================================
// UTXO SELECTION STRATEGIES
// =============================================================================

/**
 * UTXO selection strategies for transaction building
 */
export const UTXO_STRATEGY = {
  LARGEST_FIRST: 'largest_first',    // Minimize number of inputs
  SMALLEST_FIRST: 'smallest_first',  // Privacy: use oldest/smallest first
  RANDOM: 'random',                   // Privacy: randomize selection
  FIFO: 'fifo'                        // First In First Out (oldest first)
};

// =============================================================================
// CARROT DOMAIN SEPARATORS
// =============================================================================

/**
 * CARROT protocol domain separators for key derivation and encryption
 */
export const CARROT_DOMAIN = {
  EPHEMERAL_PRIVKEY: 'Carrot sending key normal',
  SENDER_RECEIVER_SECRET: 'Carrot sender-receiver secret',
  VIEW_TAG: 'Carrot view tag',
  COMMITMENT_MASK: 'Carrot commitment mask',
  ONETIME_EXTENSION_G: 'Carrot key extension G',
  ONETIME_EXTENSION_T: 'Carrot key extension T',
  ENCRYPTION_MASK_ANCHOR: 'Carrot encryption mask anchor',
  ENCRYPTION_MASK_AMOUNT: 'Carrot encryption mask a',
  ENCRYPTION_MASK_PAYMENT_ID: 'Carrot encryption mask pid',
  JANUS_ANCHOR_SPECIAL: 'Carrot janus anchor special',
  INPUT_CONTEXT_COINBASE: 'C',
  INPUT_CONTEXT_RINGCT: 'R'
};

/**
 * CARROT enote types for amount blinding factor derivation
 */
export const CARROT_ENOTE_TYPE = {
  PAYMENT: 0,
  CHANGE: 1,
  SELF_SPEND: 2
};
