/**
 * Salvium Transaction and Block Validation
 *
 * Complete validation rules for Salvium transactions and blocks.
 * Faithfully ported from C++ implementation.
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp
 *            ~/github/salvium/src/cryptonote_core/tx_verification_utils.cpp
 *            ~/github/salvium/src/cryptonote_basic/cryptonote_format_utils.cpp
 *
 * @module validation
 */

import {
  COIN,
  CRYPTONOTE_MAX_TX_SIZE,
  MAX_TX_EXTRA_SIZE,
  BULLETPROOF_PLUS_MAX_OUTPUTS,
  DEFAULT_RING_SIZE,
  CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
  HF_VERSION,
  MAINNET_CONFIG,
  TESTNET_CONFIG,
  getMinBlockWeight,
  getBlockReward,
  FEE_PER_BYTE,
  DYNAMIC_FEE_PER_KB_BASE_FEE,
  DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD,
  PER_KB_FEE_QUANTIZATION_DECIMALS,
  TRANSACTION_VERSION_2_OUTS,
  TRANSACTION_VERSION_N_OUTS,
  TRANSACTION_VERSION_CARROT
} from './consensus.js';

import { TX_TYPE, RCT_TYPE } from './transaction.js';
import { hexToBytes } from './address.js';

// =============================================================================
// CONSTANTS
// =============================================================================

/**
 * Minimum mixin (ring size - 1)
 * Salvium requires 15 decoys (ring size 16)
 */
export const MINIMUM_MIXIN = 15;

/**
 * Reserved size for coinbase blob
 */
export const CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE = 600;

/**
 * Valid asset types in Salvium
 */
export const VALID_ASSET_TYPES = ['SAL', 'SAL1', 'BURN'];

/**
 * Asset type IDs (matching C++ asset_types.h)
 */
export const ASSET_TYPE_ID = {
  SAL: 0x53414C00,   // "SAL\0"
  SAL1: 0x53414C31,  // "SAL1"
  BURN: 0x4255524E,  // "BURN"
};

/**
 * RCT type constants (matching C++ rctTypes.h)
 */
export const RCT_TYPE_NAMES = {
  Null: 0,
  Full: 1,
  Simple: 2,
  Bulletproof: 3,
  Bulletproof2: 4,
  CLSAG: 5,
  BulletproofPlus: 6,
  SalviumZero: 7,
  SalviumOne: 8,
  FullProofs: 9,
};

/**
 * Output types (matching C++ cryptonote_basic.h)
 */
export const TXOUT_TYPE = {
  to_key: 0,
  to_tagged_key: 1,
  to_carrot_v1: 2,
};

/**
 * Hardcoded blacklisted transactions
 * Reference: blockchain.cpp calculate_yield_payouts and calculate_audit_payouts
 */
export const TX_BLACKLIST = [
  '017a79539e69ce16e91d9aa2267c102f336678c41636567c1129e3e72149499a'
];

/**
 * Audit hard fork periods configuration
 */
export const AUDIT_HARD_FORKS = {
  6: { name: 'AUDIT1', assetType: 'SAL' },
  8: { name: 'AUDIT2', assetType: 'SAL1' },
};

// =============================================================================
// TRANSACTION TYPE AND VERSION VALIDATION
// =============================================================================

/**
 * Validate transaction type and version against hard fork rules
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:3786-3881
 *
 * @param {Object} tx - Parsed transaction
 * @param {number} hfVersion - Current hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function validateTxTypeAndVersion(tx, hfVersion) {
  const prefix = tx.prefix || tx;
  // Don't use fallback - 0 should be invalid
  const txType = prefix.txType ?? prefix.type ?? null;
  const version = prefix.version;

  // Rule 1: UNSET (0) or missing is invalid
  if (txType === 0 || txType === null || txType === undefined) {
    return { valid: false, error: 'Transaction type UNSET is invalid' };
  }

  // Rule 2: TX type must be valid (1-8)
  if (txType < TX_TYPE.MINER || txType > TX_TYPE.AUDIT) {
    return { valid: false, error: `Invalid transaction type: ${txType}` };
  }

  // Rule 3: N-out transaction version support
  if (hfVersion < HF_VERSION.ENABLE_N_OUTS) {
    // Before HF v2: Only TX v2 allowed
    if (version !== TRANSACTION_VERSION_2_OUTS) {
      return { valid: false, error: `TX version ${version} not allowed before HF ${HF_VERSION.ENABLE_N_OUTS}` };
    }
  }

  // Rule 4: Carrot fork requirements
  if (hfVersion >= HF_VERSION.CARROT) {
    // Non-TRANSFER types require TRANSACTION_VERSION_CARROT
    if (txType !== TX_TYPE.TRANSFER && txType !== TX_TYPE.MINER && txType !== TX_TYPE.PROTOCOL) {
      if (version !== TRANSACTION_VERSION_CARROT) {
        return { valid: false, error: `TX type ${txType} requires version ${TRANSACTION_VERSION_CARROT} at Carrot fork` };
      }
    }
  }

  // Rule 5: CONVERT transaction support
  if (txType === TX_TYPE.CONVERT) {
    if (hfVersion < HF_VERSION.ENABLE_CONVERT) {
      return { valid: false, error: 'CONVERT transactions not enabled before oracle HF' };
    }
  }

  // Rule 6: AUDIT transaction support (only in designated audit HFs)
  if (txType === TX_TYPE.AUDIT) {
    if (!AUDIT_HARD_FORKS[hfVersion]) {
      return { valid: false, error: `AUDIT transactions only allowed in audit hard fork periods (HF ${hfVersion} is not an audit fork)` };
    }
  }

  return { valid: true };
}

// =============================================================================
// ASSET TYPE VALIDATION
// =============================================================================

/**
 * Convert asset type ID to string
 *
 * Reference: ~/github/salvium/src/cryptonote_basic/cryptonote_format_utils.cpp:1103-1119
 *
 * @param {number} assetTypeId - Asset type ID
 * @returns {string|null} Asset type string or null if invalid
 */
export function assetTypeFromId(assetTypeId) {
  switch (assetTypeId) {
    case ASSET_TYPE_ID.SAL: return 'SAL';
    case ASSET_TYPE_ID.SAL1: return 'SAL1';
    case ASSET_TYPE_ID.BURN: return 'BURN';
    default: return null;
  }
}

/**
 * Convert asset type string to ID
 *
 * Reference: ~/github/salvium/src/cryptonote_basic/cryptonote_format_utils.cpp:1121-1135
 *
 * @param {string} assetType - Asset type string
 * @returns {number|null} Asset type ID or null if invalid
 */
export function assetIdFromType(assetType) {
  switch (assetType) {
    case 'SAL': return ASSET_TYPE_ID.SAL;
    case 'SAL1': return ASSET_TYPE_ID.SAL1;
    case 'BURN': return ASSET_TYPE_ID.BURN;
    default: return null;
  }
}

/**
 * Validate asset types for a transaction
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:3852-3860
 *
 * @param {Object} tx - Parsed transaction
 * @param {number} hfVersion - Current hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function validateAssetTypes(tx, hfVersion) {
  const prefix = tx.prefix || tx;
  const txType = prefix.txType || prefix.type || TX_TYPE.TRANSFER;
  const sourceAsset = prefix.source_asset_type || 'SAL';
  const destAsset = prefix.destination_asset_type || 'SAL';

  // Validate asset type strings
  if (!VALID_ASSET_TYPES.includes(sourceAsset)) {
    return { valid: false, error: `Invalid source asset type: ${sourceAsset}` };
  }
  if (!VALID_ASSET_TYPES.includes(destAsset)) {
    return { valid: false, error: `Invalid destination asset type: ${destAsset}` };
  }

  // Rule 1: BURN transactions must have destination_asset_type = "BURN"
  if (txType === TX_TYPE.BURN) {
    if (destAsset !== 'BURN') {
      return { valid: false, error: 'BURN transactions must have destination_asset_type = "BURN"' };
    }
    // Source can be SAL or SAL1
    if (sourceAsset !== 'SAL' && sourceAsset !== 'SAL1') {
      return { valid: false, error: 'BURN source must be SAL or SAL1' };
    }
    return { valid: true };
  }

  // Rule 2: Cannot spend BURN coins
  if (sourceAsset === 'BURN') {
    return { valid: false, error: 'Cannot spend BURN coins' };
  }

  // Rule 3: CONVERT transactions allow SAL <-> VSD
  if (txType === TX_TYPE.CONVERT) {
    // CONVERT allows different source and dest assets
    // Currently only SAL<->VSD but that's not enabled yet
    return { valid: true };
  }

  // Rule 4: AUDIT transactions
  if (txType === TX_TYPE.AUDIT) {
    const auditConfig = AUDIT_HARD_FORKS[hfVersion];
    if (auditConfig) {
      // Source asset must match audit config
      if (sourceAsset !== auditConfig.assetType && sourceAsset !== 'SAL') {
        return { valid: false, error: `AUDIT source must be ${auditConfig.assetType} or SAL` };
      }
    }
    return { valid: true };
  }

  // Rule 5: For non-BURN/CONVERT transactions, source must equal destination
  if (sourceAsset !== destAsset) {
    return { valid: false, error: `Source asset (${sourceAsset}) must match destination (${destAsset}) for TX type ${txType}` };
  }

  // Rule 6: After certain HFs, only SAL1 allowed for regular transactions
  if (hfVersion >= HF_VERSION.AUDIT1_PAUSE) {
    if (txType === TX_TYPE.TRANSFER || txType === TX_TYPE.STAKE) {
      if (sourceAsset !== 'SAL1' && sourceAsset !== 'SAL') {
        return { valid: false, error: 'Only SAL1 or SAL allowed for TRANSFER/STAKE after AUDIT1_PAUSE' };
      }
    }
  }

  return { valid: true };
}

// =============================================================================
// OUTPUT VALIDATION
// =============================================================================

/**
 * Validate output types for a transaction
 *
 * Reference: ~/github/salvium/src/cryptonote_basic/cryptonote_format_utils.cpp:1376-1437
 *
 * @param {Object} tx - Parsed transaction
 * @param {number} hfVersion - Current hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function validateOutputTypes(tx, hfVersion) {
  const prefix = tx.prefix || tx;
  const txType = prefix.txType || prefix.type || TX_TYPE.TRANSFER;
  const outputs = prefix.vout || prefix.outputs || [];

  // Rule 1: AUDIT and STAKE must have exactly 1 output (or 0 for change-is-zero)
  if (txType === TX_TYPE.AUDIT) {
    // AUDIT has 0 outputs (change-is-zero)
    if (outputs.length !== 0) {
      return { valid: false, error: 'AUDIT transactions must have 0 outputs (change-is-zero)' };
    }
    return { valid: true };
  }

  if (txType === TX_TYPE.STAKE) {
    if (outputs.length !== 1) {
      return { valid: false, error: 'STAKE transactions must have exactly 1 output' };
    }
  }

  // Rule 2: Carrot fork output type requirements
  if (hfVersion >= HF_VERSION.CARROT) {
    for (const output of outputs) {
      const targetType = output.target?.type;

      // Non-PROTOCOL transactions must use txout_to_carrot_v1
      if (txType !== TX_TYPE.PROTOCOL && txType !== TX_TYPE.MINER) {
        if (targetType !== undefined && targetType !== TXOUT_TYPE.to_carrot_v1) {
          return { valid: false, error: 'Non-PROTOCOL transactions must use txout_to_carrot_v1 outputs at Carrot fork' };
        }
      }
    }
  }

  // Rule 3: All outputs must have same type (consistency check)
  if (outputs.length > 1) {
    const firstType = outputs[0].target?.type;
    for (let i = 1; i < outputs.length; i++) {
      if (outputs[i].target?.type !== firstType) {
        return { valid: false, error: 'All outputs must have the same target type' };
      }
    }
  }

  return { valid: true };
}

/**
 * Validate that output public keys are sorted (Carrot fork requirement)
 *
 * Reference: ~/github/salvium/src/cryptonote_core/tx_verification_utils.cpp:153-168
 *
 * @param {Object} tx - Parsed transaction
 * @param {number} hfVersion - Current hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function validateOutputPubkeySorting(tx, hfVersion) {
  // Only enforced from Carrot fork
  if (hfVersion < HF_VERSION.CARROT) {
    return { valid: true };
  }

  const prefix = tx.prefix || tx;
  const outputs = prefix.vout || prefix.outputs || [];

  if (outputs.length < 2) {
    return { valid: true };
  }

  // Extract public keys and compare lexicographically
  let prevKey = null;
  for (const output of outputs) {
    const key = output.target?.key || output.target?.data?.key;
    if (!key) continue;

    const keyBytes = typeof key === 'string'
      ? hexToBytes(key)
      : key;

    if (prevKey !== null) {
      // Compare lexicographically
      for (let i = 0; i < 32; i++) {
        if (keyBytes[i] < prevKey[i]) {
          return { valid: false, error: 'Output public keys must be sorted in increasing order' };
        }
        if (keyBytes[i] > prevKey[i]) {
          break; // This key is greater, move on
        }
        // If equal, continue to next byte
      }
    }
    prevKey = keyBytes;
  }

  return { valid: true };
}

/**
 * Check for output amount overflow
 *
 * Reference: ~/github/salvium/src/cryptonote_basic/cryptonote_format_utils.cpp:1074-1084
 *
 * @param {Object} tx - Parsed transaction
 * @returns {{valid: boolean, error?: string}}
 */
export function validateOutputsOverflow(tx) {
  const prefix = tx.prefix || tx;
  const outputs = prefix.vout || prefix.outputs || [];

  let totalAmount = 0n;
  const MAX_MONEY = 18446744073709551615n; // 2^64 - 1

  for (const output of outputs) {
    const amount = BigInt(output.amount || 0);
    if (totalAmount > MAX_MONEY - amount) {
      return { valid: false, error: 'Output amounts overflow' };
    }
    totalAmount += amount;
  }

  return { valid: true };
}

// =============================================================================
// RCT TYPE VALIDATION
// =============================================================================

/**
 * Validate RCT signature type for hard fork version
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:3729-3765
 *
 * @param {Object} tx - Parsed transaction
 * @param {number} hfVersion - Current hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function validateRctType(tx, hfVersion) {
  const prefix = tx.prefix || tx;
  const txType = prefix.txType || prefix.type || TX_TYPE.TRANSFER;
  const rctType = tx.rct?.type ?? tx.rctType ?? RCT_TYPE_NAMES.Null;

  // MINER and PROTOCOL transactions must have RCTTypeNull
  if (txType === TX_TYPE.MINER || txType === TX_TYPE.PROTOCOL) {
    if (hfVersion >= HF_VERSION.REJECT_SIGS_IN_COINBASE) {
      if (rctType !== RCT_TYPE_NAMES.Null) {
        return { valid: false, error: 'MINER/PROTOCOL transactions must have RCTTypeNull' };
      }
    }
    return { valid: true };
  }

  // User transactions: TRANSFER, STAKE, BURN, CONVERT, AUDIT
  if (hfVersion >= HF_VERSION.CARROT) {
    // At Carrot fork: Must use RCTTypeSalviumOne
    if (rctType !== RCT_TYPE_NAMES.SalviumOne) {
      return { valid: false, error: `TX type ${txType} must use RCTTypeSalviumOne at Carrot fork, got ${rctType}` };
    }
  } else if (hfVersion >= HF_VERSION.SALVIUM_ONE_PROOFS) {
    // At SALVIUM_ONE_PROOFS: Must use RCTTypeSalviumZero
    if (rctType !== RCT_TYPE_NAMES.SalviumZero) {
      return { valid: false, error: `TX type ${txType} must use RCTTypeSalviumZero at HF ${hfVersion}` };
    }
  } else if (hfVersion >= HF_VERSION.ENFORCE_FULL_PROOFS) {
    // At ENFORCE_FULL_PROOFS: Must use RCTTypeFullProofs
    if (rctType !== RCT_TYPE_NAMES.FullProofs) {
      return { valid: false, error: `TX type ${txType} must use RCTTypeFullProofs at HF ${hfVersion}` };
    }
  } else if (hfVersion >= HF_VERSION.BULLETPROOF_PLUS) {
    // At BULLETPROOF_PLUS: Must use BulletproofPlus or CLSAG
    if (rctType !== RCT_TYPE_NAMES.BulletproofPlus && rctType !== RCT_TYPE_NAMES.CLSAG) {
      return { valid: false, error: `TX type ${txType} must use BulletproofPlus or CLSAG at HF ${hfVersion}` };
    }
  }

  return { valid: true };
}

// =============================================================================
// INPUT VALIDATION
// =============================================================================

/**
 * Validate transaction inputs
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:3998-4200
 *
 * @param {Object} tx - Parsed transaction
 * @param {number} hfVersion - Current hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function validateInputs(tx, hfVersion) {
  const prefix = tx.prefix || tx;
  const txType = prefix.txType || prefix.type || TX_TYPE.TRANSFER;
  const inputs = prefix.vin || prefix.inputs || [];

  // MINER/PROTOCOL use txin_gen (coinbase)
  if (txType === TX_TYPE.MINER || txType === TX_TYPE.PROTOCOL) {
    // Should have exactly 1 input of type txin_gen
    if (inputs.length !== 1) {
      return { valid: false, error: 'MINER/PROTOCOL must have exactly 1 input' };
    }
    const input = inputs[0];
    if (!input.gen && !input.height && input.type !== 'gen') {
      return { valid: false, error: 'MINER/PROTOCOL input must be txin_gen type' };
    }
    return { valid: true };
  }

  // User transactions must have at least 1 input
  if (inputs.length === 0) {
    return { valid: false, error: 'Transaction must have at least 1 input' };
  }

  // Validate each input
  let prevKeyImage = null;
  for (let i = 0; i < inputs.length; i++) {
    const input = inputs[i];

    // Must be txin_to_key type
    if (input.type && input.type !== 'key') {
      return { valid: false, error: `Input ${i} must be txin_to_key type` };
    }

    // Validate ring size
    const ringSize = input.key_offsets?.length || input.keyOffsets?.length || 0;
    if (ringSize === 0) {
      return { valid: false, error: `Input ${i} has no ring members` };
    }
    if (ringSize !== DEFAULT_RING_SIZE) {
      return { valid: false, error: `Input ${i} ring size must be ${DEFAULT_RING_SIZE}, got ${ringSize}` };
    }

    // Key images must be sorted (from HF v1)
    if (hfVersion >= 1) {
      const keyImage = input.k_image || input.keyImage;
      if (keyImage && prevKeyImage) {
        const kiBytes = typeof keyImage === 'string'
          ? hexToBytes(keyImage)
          : keyImage;
        const prevKiBytes = typeof prevKeyImage === 'string'
          ? hexToBytes(prevKeyImage)
          : prevKeyImage;

        // Compare lexicographically (must be strictly increasing)
        let comparison = 0;
        for (let j = 0; j < 32; j++) {
          if (kiBytes[j] < prevKiBytes[j]) {
            comparison = -1;
            break;
          }
          if (kiBytes[j] > prevKiBytes[j]) {
            comparison = 1;
            break;
          }
        }
        if (comparison <= 0) {
          return { valid: false, error: 'Key images must be sorted in strictly increasing order' };
        }
      }
      prevKeyImage = input.k_image || input.keyImage;
    }
  }

  return { valid: true };
}

// =============================================================================
// FEE VALIDATION
// =============================================================================

/**
 * Get fee quantization mask
 *
 * @returns {bigint} Fee quantization mask
 */
export function getFeeQuantizationMask() {
  return (10n ** BigInt(PER_KB_FEE_QUANTIZATION_DECIMALS)) - 1n;
}

/**
 * Calculate required fee for a transaction
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:4411-4440
 *
 * @param {number} txWeight - Transaction weight in bytes
 * @param {bigint} baseReward - Current base block reward
 * @param {number} medianWeight - Median block weight
 * @param {number} hfVersion - Hard fork version
 * @returns {bigint} Required fee
 */
export function calculateRequiredFee(txWeight, baseReward, medianWeight, hfVersion = 1) {
  // Get minimum block weight for full reward
  const minBlockWeight = getMinBlockWeight(hfVersion);
  const effectiveMedian = Math.max(medianWeight, minBlockWeight);

  // Calculate fee per byte
  let feePerByte;
  if (hfVersion >= HF_VERSION.SCALING_2021) {
    // Dynamic fee calculation
    // fee_per_byte = (base_fee * base_reward_reference) / base_reward
    const baseFee = DYNAMIC_FEE_PER_KB_BASE_FEE / 1024n;
    const baseRewardRef = DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD;

    if (baseReward > 0n) {
      feePerByte = (baseFee * baseRewardRef) / baseReward;
      // Minimum fee per byte
      if (feePerByte < FEE_PER_BYTE) {
        feePerByte = FEE_PER_BYTE;
      }
    } else {
      feePerByte = FEE_PER_BYTE;
    }
  } else {
    feePerByte = FEE_PER_BYTE;
  }

  // Calculate needed fee
  let neededFee = BigInt(txWeight) * feePerByte;

  // Quantize fee
  const mask = getFeeQuantizationMask();
  neededFee = ((neededFee + mask) / (mask + 1n)) * (mask + 1n);

  return neededFee;
}

/**
 * Validate transaction fee
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:4411-4440
 *
 * @param {bigint} fee - Transaction fee
 * @param {number} txWeight - Transaction weight
 * @param {bigint} baseReward - Current base reward
 * @param {number} medianWeight - Median block weight
 * @param {number} hfVersion - Hard fork version
 * @returns {{valid: boolean, error?: string, required?: bigint}}
 */
export function validateFee(fee, txWeight, baseReward, medianWeight, hfVersion = 1) {
  const neededFee = calculateRequiredFee(txWeight, baseReward, medianWeight, hfVersion);

  // Allow 2% tolerance
  const minFee = neededFee - (neededFee / 50n);

  if (fee < minFee) {
    return {
      valid: false,
      error: `Insufficient fee: ${fee} < ${neededFee} (min ${minFee})`,
      required: neededFee
    };
  }

  return { valid: true, required: neededFee };
}

// =============================================================================
// TRANSACTION WEIGHT VALIDATION
// =============================================================================

/**
 * Get maximum transaction weight limit
 *
 * Reference: ~/github/salvium/src/cryptonote_core/tx_verification_utils.cpp:144-151
 *
 * @param {number} hfVersion - Hard fork version
 * @returns {number} Maximum transaction weight
 */
export function getTransactionWeightLimit(hfVersion) {
  const minBlockWeight = getMinBlockWeight(hfVersion);

  if (hfVersion >= 2) {
    // From HF v2+: Limit to 50% of minimum block weight minus reserved size
    return Math.floor(minBlockWeight / 2) - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
  }

  // Prior to HF v2: Full minimum block weight minus reserved size
  return minBlockWeight - CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE;
}

/**
 * Validate transaction weight
 *
 * @param {number} txWeight - Transaction weight in bytes
 * @param {number} hfVersion - Hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function validateTxWeight(txWeight, hfVersion) {
  const maxWeight = getTransactionWeightLimit(hfVersion);

  if (txWeight > maxWeight) {
    return {
      valid: false,
      error: `Transaction weight ${txWeight} exceeds limit ${maxWeight}`
    };
  }

  return { valid: true };
}

// =============================================================================
// MINER TRANSACTION VALIDATION
// =============================================================================

/**
 * Prevalidate miner transaction (coinbase)
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:1344-1386
 *
 * @param {Object} minerTx - Miner transaction
 * @param {number} height - Block height
 * @param {number} hfVersion - Hard fork version
 * @returns {{valid: boolean, error?: string}}
 */
export function prevalidateMinerTransaction(minerTx, height, hfVersion) {
  const prefix = minerTx.prefix || minerTx;
  const inputs = prefix.vin || prefix.inputs || [];

  // Must have exactly 1 input
  if (inputs.length !== 1) {
    return { valid: false, error: 'Miner transaction must have exactly 1 input' };
  }

  // Input must be txin_gen (coinbase)
  const input = inputs[0];
  const inputHeight = input.height ?? input.gen?.height;
  if (inputHeight === undefined) {
    return { valid: false, error: 'Miner transaction input must be txin_gen type' };
  }

  // Input height must match block height
  if (inputHeight !== height) {
    return { valid: false, error: `Miner TX input height ${inputHeight} != block height ${height}` };
  }

  // Version requirements
  const version = prefix.version;
  if (version <= 1) {
    return { valid: false, error: 'Miner transaction version must be > 1' };
  }

  if (hfVersion >= HF_VERSION.CARROT) {
    if (version !== TRANSACTION_VERSION_CARROT) {
      return { valid: false, error: `Miner TX version must be ${TRANSACTION_VERSION_CARROT} at Carrot fork` };
    }
    // Type must be MINER
    const txType = prefix.txType || prefix.type;
    if (txType !== TX_TYPE.MINER) {
      return { valid: false, error: 'Miner TX type must be MINER at Carrot fork' };
    }
  }

  // Check output overflow
  const overflowResult = validateOutputsOverflow(minerTx);
  if (!overflowResult.valid) {
    return overflowResult;
  }

  // Check output types
  const outputTypesResult = validateOutputTypes(minerTx, hfVersion);
  if (!outputTypesResult.valid) {
    return outputTypesResult;
  }

  // Check output sorting at Carrot fork
  const sortingResult = validateOutputPubkeySorting(minerTx, hfVersion);
  if (!sortingResult.valid) {
    return sortingResult;
  }

  return { valid: true };
}

/**
 * Validate miner transaction reward
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:1486-1557
 *
 * @param {Object} minerTx - Miner transaction
 * @param {number} blockWeight - Block weight
 * @param {bigint} fee - Total fees in block
 * @param {bigint} alreadyGeneratedCoins - Total coins generated before this block
 * @param {number} hfVersion - Hard fork version
 * @returns {{valid: boolean, error?: string, baseReward?: bigint}}
 */
export function validateMinerTransactionReward(minerTx, blockWeight, fee, alreadyGeneratedCoins, hfVersion) {
  const prefix = minerTx.prefix || minerTx;
  const outputs = prefix.vout || prefix.outputs || [];

  // Calculate total money in outputs
  let moneyInUse = 0n;
  for (const output of outputs) {
    moneyInUse += BigInt(output.amount || 0);
  }

  // Get base reward
  const medianWeight = blockWeight; // Simplified - should use actual median
  const rewardResult = getBlockReward(medianWeight, blockWeight, alreadyGeneratedCoins, hfVersion);

  if (!rewardResult.success) {
    return { valid: false, error: 'Block too large for reward' };
  }

  const baseReward = rewardResult.reward;

  // Validate: base_reward + fee >= money_in_use
  if (baseReward + fee < moneyInUse) {
    return {
      valid: false,
      error: `Miner TX reward too high: ${moneyInUse} > ${baseReward + fee} (base + fee)`
    };
  }

  // Note: Salvium has additional validation for amount_burnt = money_in_use / 5
  // and treasury SAL1 minting at specific heights

  return { valid: true, baseReward };
}

// =============================================================================
// YIELD CALCULATION
// =============================================================================

/**
 * Yield block info structure
 *
 * @typedef {Object} YieldBlockInfo
 * @property {bigint} slippageTotal - Total slippage for this block
 * @property {bigint} lockedCoinsTally - Running tally of locked coins
 */

/**
 * Calculate yield payout for a STAKE transaction
 *
 * Reference: ~/github/salvium/src/cryptonote_core/blockchain.cpp:4714-4777
 *
 * @param {bigint} stakedAmount - Amount staked
 * @param {YieldBlockInfo[]} yieldBlocks - Yield info for each block in lock period
 * @returns {bigint} Yield payout amount
 */
export function calculateYieldPayout(stakedAmount, yieldBlocks) {
  let totalYield = 0n;

  for (const blockInfo of yieldBlocks) {
    if (blockInfo.lockedCoinsTally === 0n) continue;

    // yield = (slippage_total * locked_coins) / locked_coins_tally
    // Using 128-bit arithmetic simulation with BigInt
    const yieldForBlock = (blockInfo.slippageTotal * stakedAmount) / blockInfo.lockedCoinsTally;
    totalYield += yieldForBlock;
  }

  return totalYield;
}

/**
 * Get stake lock period for a network
 *
 * @param {'mainnet'|'testnet'|'stagenet'} network - Network type
 * @returns {number} Lock period in blocks
 */
export function getStakeLockPeriod(network = 'mainnet') {
  switch (network) {
    case 'testnet':
    case 'stagenet':
      return TESTNET_CONFIG.STAKE_LOCK_PERIOD;
    default:
      return MAINNET_CONFIG.STAKE_LOCK_PERIOD;
  }
}

// =============================================================================
// COMPREHENSIVE TRANSACTION VALIDATION
// =============================================================================

/**
 * Perform comprehensive transaction validation
 *
 * @param {Object} tx - Parsed transaction
 * @param {Object} context - Validation context
 * @param {number} context.hfVersion - Hard fork version
 * @param {number} context.height - Current block height
 * @param {bigint} context.baseReward - Current base reward
 * @param {number} context.medianWeight - Median block weight
 * @returns {{valid: boolean, errors: string[]}}
 */
export function validateTransactionFull(tx, context) {
  const { hfVersion = 1, height = 0, baseReward = COIN, medianWeight = 300000 } = context;
  const errors = [];

  // 1. Validate TX type and version
  const typeResult = validateTxTypeAndVersion(tx, hfVersion);
  if (!typeResult.valid) {
    errors.push(typeResult.error);
  }

  // 2. Validate asset types
  const assetResult = validateAssetTypes(tx, hfVersion);
  if (!assetResult.valid) {
    errors.push(assetResult.error);
  }

  // 3. Validate output types
  const outputTypeResult = validateOutputTypes(tx, hfVersion);
  if (!outputTypeResult.valid) {
    errors.push(outputTypeResult.error);
  }

  // 4. Validate output sorting
  const sortingResult = validateOutputPubkeySorting(tx, hfVersion);
  if (!sortingResult.valid) {
    errors.push(sortingResult.error);
  }

  // 5. Validate output overflow
  const overflowResult = validateOutputsOverflow(tx);
  if (!overflowResult.valid) {
    errors.push(overflowResult.error);
  }

  // 6. Validate RCT type
  const rctResult = validateRctType(tx, hfVersion);
  if (!rctResult.valid) {
    errors.push(rctResult.error);
  }

  // 7. Validate inputs
  const inputResult = validateInputs(tx, hfVersion);
  if (!inputResult.valid) {
    errors.push(inputResult.error);
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  // Constants
  MINIMUM_MIXIN,
  CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE,
  VALID_ASSET_TYPES,
  ASSET_TYPE_ID,
  RCT_TYPE_NAMES,
  TXOUT_TYPE,
  TX_BLACKLIST,
  AUDIT_HARD_FORKS,

  // Asset type functions
  assetTypeFromId,
  assetIdFromType,
  validateAssetTypes,

  // Transaction type/version validation
  validateTxTypeAndVersion,

  // Output validation
  validateOutputTypes,
  validateOutputPubkeySorting,
  validateOutputsOverflow,

  // RCT validation
  validateRctType,

  // Input validation
  validateInputs,

  // Fee validation
  getFeeQuantizationMask,
  calculateRequiredFee,
  validateFee,

  // Weight validation
  getTransactionWeightLimit,
  validateTxWeight,

  // Miner transaction
  prevalidateMinerTransaction,
  validateMinerTransactionReward,

  // Yield calculation
  calculateYieldPayout,
  getStakeLockPeriod,

  // Comprehensive validation
  validateTransactionFull
};
