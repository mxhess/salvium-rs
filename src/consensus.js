/**
 * Salvium Consensus Rules and Constants
 *
 * This module contains all consensus-critical constants and validation functions
 * needed to implement a full validating node.
 *
 * Reference: salvium/src/cryptonote_config.h, cryptonote_basic_impl.cpp, difficulty.cpp
 */

// =============================================================================
// CORE CONSTANTS
// =============================================================================

// Money supply and emission
export const MONEY_SUPPLY = 18440000000000000n; // 184.4M coins * 10^8
export const EMISSION_SPEED_FACTOR_PER_MINUTE = 21;
export const FINAL_SUBSIDY_PER_MINUTE = 30000000n; // 3 * 10^7 (tail emission)
export const COIN = 100000000n; // 10^8 atomic units per coin
export const CRYPTONOTE_DISPLAY_DECIMAL_POINT = 8;

// Premine
export const PREMINE_AMOUNT = 2210000000000000n; // 12% of MONEY_SUPPLY
export const PREMINE_AMOUNT_UPFRONT = 650000000000000n; // 3.4% of MONEY_SUPPLY
export const PREMINE_AMOUNT_MONTHLY = 65000000000000n; // 8.6%/24 of MONEY_SUPPLY

// Treasury SAL1 minting
export const TREASURY_SAL1_MINT_AMOUNT = 130000000000000n; // 1.3M
export const TREASURY_SAL1_MINT_COUNT = 8;

// Block timing
export const DIFFICULTY_TARGET_V1 = 60; // seconds (before first fork)
export const DIFFICULTY_TARGET_V2 = 120; // seconds (current)
export const CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT = 60 * 60 * 2; // 2 hours
export const BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW = 60;

// Difficulty adjustment
export const DIFFICULTY_WINDOW = 720;
export const DIFFICULTY_WINDOW_V2 = 70;
export const DIFFICULTY_LAG = 15;
export const DIFFICULTY_CUT = 60;
export const DIFFICULTY_BLOCKS_COUNT = DIFFICULTY_WINDOW + DIFFICULTY_LAG;
export const DIFFICULTY_BLOCKS_COUNT_V2 = DIFFICULTY_WINDOW_V2;

// Block size/weight
export const CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1 = 20000;
export const CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2 = 60000;
export const CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300000;
export const CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE = 100000;
export const CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR = 50;

// Transaction limits
export const CRYPTONOTE_MAX_TX_SIZE = 1000000;
export const CRYPTONOTE_MAX_TX_PER_BLOCK = 0x10000000;
export const MAX_TX_EXTRA_SIZE = 1060;
export const BULLETPROOF_MAX_OUTPUTS = 16;
export const BULLETPROOF_PLUS_MAX_OUTPUTS = 16;

// Maturity and unlock
export const CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW = 60;
export const CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10;
export const CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS = 1;

// Transaction versions
export const CURRENT_TRANSACTION_VERSION = 4;
export const TRANSACTION_VERSION_2_OUTS = 2;
export const TRANSACTION_VERSION_N_OUTS = 3;
export const TRANSACTION_VERSION_CARROT = 4;

// Fees
export const FEE_PER_KB = 200000n; // 2 * 10^5
export const FEE_PER_BYTE = 30n;
export const DYNAMIC_FEE_PER_KB_BASE_FEE = 200000n;
export const DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD = 1000000000n; // 10 * 10^8
export const DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT = 3000n;
export const PER_KB_FEE_QUANTIZATION_DECIMALS = 8;
export const DEFAULT_DUST_THRESHOLD = 2000000000n; // 2 * 10^9
export const BASE_REWARD_CLAMP_THRESHOLD = 100000000n; // 10^8

// Mempool
export const CRYPTONOTE_MEMPOOL_TX_LIVETIME = 86400 * 3; // 3 days
export const CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME = 604800; // 1 week
export const DEFAULT_TXPOOL_MAX_WEIGHT = 648000000n; // 3 days at 300000

// Ring size (Salvium uses 16)
export const DEFAULT_RING_SIZE = 16;

// Pricing record
export const PRICING_RECORD_VALID_BLOCKS = 10;
export const PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK = 120;

// Lock periods
export const BURN_LOCK_PERIOD = 0;
export const CONVERT_LOCK_PERIOD = 0;

// =============================================================================
// HARD FORK VERSIONS
// =============================================================================

export const HF_VERSION = {
  // Version 1 features
  DYNAMIC_FEE: 1,
  PER_BYTE_FEE: 1,
  ENFORCE_MIN_AGE: 1,
  EXACT_COINBASE: 1,
  CLSAG: 1,
  DETERMINISTIC_UNLOCK_TIME: 1,
  SMALLER_BP: 1,
  MIN_V2_COINBASE_TX: 1,
  REJECT_SIGS_IN_COINBASE: 1,
  BULLETPROOF_PLUS: 1,
  ENABLE_RETURN: 1,
  VIEW_TAGS: 1,

  // Version 2 features
  LONG_TERM_BLOCK_WEIGHT: 2,
  SCALING_2021: 2,
  ENABLE_N_OUTS: 2,

  // Version 3+
  FULL_PROOFS: 3,
  ENFORCE_FULL_PROOFS: 4,
  SHUTDOWN_USER_TXS: 5,
  AUDIT1: 6,
  SALVIUM_ONE_PROOFS: 6,
  AUDIT1_PAUSE: 7,
  AUDIT2: 8,
  AUDIT2_PAUSE: 9,
  CARROT: 10,

  // Future (v255 placeholder)
  REQUIRE_VIEW_TAGS: 255,
  ENABLE_CONVERT: 255,
  ENABLE_ORACLE: 255,
  SLIPPAGE_YIELD: 255,
};

// =============================================================================
// NETWORK CONFIGURATIONS
// =============================================================================

export const NETWORK_ID = {
  MAINNET: 0,
  TESTNET: 1,
  STAGENET: 2,
  FAKECHAIN: 3,
};

export const MAINNET_CONFIG = {
  ADDRESS_PREFIX: 0x3ef318n, // SaLv
  INTEGRATED_ADDRESS_PREFIX: 0x55ef318n, // SaLvi
  SUBADDRESS_PREFIX: 0xf5ef318n, // SaLvs
  CARROT_ADDRESS_PREFIX: 0x180c96n, // SC1
  CARROT_INTEGRATED_PREFIX: 0x2ccc96n, // SC1i
  CARROT_SUBADDRESS_PREFIX: 0x314c96n, // SC1s
  P2P_PORT: 19080,
  RPC_PORT: 19081,
  ZMQ_PORT: 19082,
  GENESIS_NONCE: 10000,
  GENESIS_TX: '020001ff000180c0d0c7bbbff603031c7d3e2240c8ddbc2966c9dcbf703c3aa99624d34b82fbfebd71dcfa001c59800353414c3cb42101d7be8f8312cdd54e1ae390e86d6733c3d8f1ef7be27f75f5acbf0dc57aa8e60d010000',
  STAKE_LOCK_PERIOD: 30 * 24 * 30, // blocks
  TREASURY_SAL1_MINT_PERIOD: 30 * 24 * 30,
  TREASURY_ADDRESS: 'SaLvdZR6w1A21sf2Wh6jYEh1wzY4GSbT7RX6FjyPsnLsffWLrzFQeXUXJcmBLRWDzZC2YXeYe5t7qKsnrg9FpmxmEcxPHsEYfqA',
  // Hard fork heights (from hardforks.cpp)
  HARD_FORK_HEIGHTS: {
    1: 1,        // Genesis
    2: 89800,    // November 4, 2024
    3: 121100,   // December 19, 2024
    4: 121800,   // December 20, 2024
    5: 136100,   // January 9, 2025
    6: 154750,   // February 4, 2025 (AUDIT1)
    7: 161900,   // February 14, 2025 (AUDIT1_PAUSE)
    8: 172000,   // February 28, 2025 (AUDIT2)
    9: 179200,   // March 10, 2025 (AUDIT2_PAUSE)
    10: 334750,  // October 13, 2025 (CARROT)
  },
};

export const TESTNET_CONFIG = {
  ADDRESS_PREFIX: 0x15beb318n, // SaLvT
  INTEGRATED_ADDRESS_PREFIX: 0xd055eb318n, // SaLvTi
  SUBADDRESS_PREFIX: 0xa59eb318n, // SaLvTs
  CARROT_ADDRESS_PREFIX: 0x254c96n, // SC1T
  CARROT_INTEGRATED_PREFIX: 0x1ac50c96n, // SC1Ti
  CARROT_SUBADDRESS_PREFIX: 0x3c54c96n, // SC1Ts
  P2P_PORT: 29080,
  RPC_PORT: 29081,
  ZMQ_PORT: 29082,
  GENESIS_NONCE: 10001,
  GENESIS_TX: '020001ff000180c0d0c7bbbff60302838f76f69b70bb0d0f1961a12f6082a033d22285c07d4f12ec93c28197ae2a600353414c3c2101009e8b0abce686c417a1b1344eb7337176bdca90cc928b0facec8a9516190645010000',
  STAKE_LOCK_PERIOD: 20,
  TREASURY_SAL1_MINT_PERIOD: 20,
  TREASURY_ADDRESS: 'SaLvTyLFta9BiAXeUfFkKvViBkFt4ay5nEUBpWyDKewYggtsoxBbtCUVqaBjtcCDyY1euun8Giv7LLEgvztuurLo5a6Km1zskZn36',
  // Hard fork heights (from hardforks.cpp)
  HARD_FORK_HEIGHTS: {
    1: 1,      // Genesis
    2: 250,
    3: 500,
    4: 600,
    5: 800,
    6: 815,    // AUDIT1
    7: 900,    // AUDIT1_PAUSE
    8: 950,    // AUDIT2
    9: 1000,   // AUDIT2_PAUSE
    10: 1100,  // CARROT
  },
};

export const STAGENET_CONFIG = {
  ADDRESS_PREFIX: 0x149eb318n, // SaLvS
  INTEGRATED_ADDRESS_PREFIX: 0xf343eb318n, // SaLvSi
  SUBADDRESS_PREFIX: 0x2d47eb318n, // SaLvSs
  CARROT_ADDRESS_PREFIX: 0x24cc96n, // SC1S
  CARROT_INTEGRATED_PREFIX: 0x1a848c96n, // SC1Si
  CARROT_SUBADDRESS_PREFIX: 0x384cc96n, // SC1Ss
  P2P_PORT: 39080,
  RPC_PORT: 39081,
  ZMQ_PORT: 39082,
  GENESIS_NONCE: 10002,
  GENESIS_TX: '013c01ff0001ffffffffffff0302df5d56da0c7d643ddd1ce61901c7bdc5fb1738bfe39fbe69c28a3a7032729c0f2101168d0c4ca86fb55a4cf6a36d31431be1c53a3bd7411bb24e8832410289fa6f3b',
  STAKE_LOCK_PERIOD: 20,
  TREASURY_SAL1_MINT_PERIOD: 20,
  TREASURY_ADDRESS: 'fuLMowH85abK8nz9BBMEem7MAfUbQu4aSHHUV9j5Z86o6Go9Lv2U5ZQiJCWPY9R9HA8p5idburazjAhCqDngLo7fYPCD9ciM9ee1A',
  // Hard fork heights - stagenet matches testnet
  HARD_FORK_HEIGHTS: {
    1: 1,      // Genesis
    2: 250,
    3: 500,
    4: 600,
    5: 800,
    6: 815,
    7: 900,
    8: 950,
    9: 1000,
    10: 1100,  // CARROT
  },
};

/**
 * Get network configuration
 * @param {number} network - Network type (MAINNET, TESTNET, STAGENET)
 * @returns {Object} Network configuration
 */
export function getNetworkConfig(network) {
  switch (network) {
    case NETWORK_ID.MAINNET:
    case NETWORK_ID.FAKECHAIN:
      return MAINNET_CONFIG;
    case NETWORK_ID.TESTNET:
      return TESTNET_CONFIG;
    case NETWORK_ID.STAGENET:
      return STAGENET_CONFIG;
    default:
      throw new Error(`Invalid network type: ${network}`);
  }
}

/**
 * Get hard fork version for a given block height
 *
 * Reference: ~/github/salvium/src/hardforks/hardforks.cpp
 *
 * @param {number} height - Block height
 * @param {number} network - Network type (MAINNET, TESTNET, STAGENET)
 * @returns {number} Hard fork version active at this height
 */
export function getHfVersionForHeight(height, network = NETWORK_ID.MAINNET) {
  const config = getNetworkConfig(network);
  const hfHeights = config.HARD_FORK_HEIGHTS;

  if (!hfHeights) {
    return 1; // Default to version 1 if no HF heights defined
  }

  // Find the highest HF version that has been activated at this height
  let activeVersion = 1;
  for (const [version, activationHeight] of Object.entries(hfHeights)) {
    if (height >= activationHeight && parseInt(version) > activeVersion) {
      activeVersion = parseInt(version);
    }
  }

  return activeVersion;
}

/**
 * Check if a specific hard fork is active at a given height
 *
 * @param {number} hfVersion - Hard fork version to check
 * @param {number} height - Block height
 * @param {number} network - Network type
 * @returns {boolean} True if the hard fork is active
 */
export function isHfActive(hfVersion, height, network = NETWORK_ID.MAINNET) {
  return getHfVersionForHeight(height, network) >= hfVersion;
}

/**
 * Check if CARROT outputs are enabled at a given height
 *
 * @param {number} height - Block height
 * @param {number} network - Network type
 * @returns {boolean} True if CARROT is active
 */
export function isCarrotActive(height, network = NETWORK_ID.MAINNET) {
  return isHfActive(HF_VERSION.CARROT, height, network);
}

// =============================================================================
// BLOCK REWARD CALCULATION
// =============================================================================

/**
 * Get minimum block weight for full reward
 * @param {number} version - Hard fork version
 * @returns {number} Minimum block weight in bytes
 */
export function getMinBlockWeight(version) {
  if (version < 2) {
    return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1;
  }
  return CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
}

/**
 * Calculate block reward
 *
 * Formula: base_reward = (MONEY_SUPPLY - already_generated) >> emission_speed_factor
 * With penalty for blocks larger than median weight
 *
 * @param {number} medianWeight - Median block weight
 * @param {number} currentBlockWeight - Current block weight
 * @param {bigint} alreadyGeneratedCoins - Total coins generated so far
 * @param {number} version - Hard fork version
 * @returns {{ success: boolean, reward: bigint }} Block reward result
 */
export function getBlockReward(medianWeight, currentBlockWeight, alreadyGeneratedCoins, version = 1) {
  const target = DIFFICULTY_TARGET_V2;
  const targetMinutes = target / 60;
  const emissionSpeedFactor = EMISSION_SPEED_FACTOR_PER_MINUTE - (targetMinutes - 1);

  // Calculate base reward
  let baseReward = (MONEY_SUPPLY - alreadyGeneratedCoins) >> BigInt(emissionSpeedFactor);

  // Apply tail emission (minimum subsidy)
  const minSubsidy = FINAL_SUBSIDY_PER_MINUTE * BigInt(targetMinutes);
  if (baseReward < minSubsidy) {
    baseReward = minSubsidy;
  }

  // Genesis block (premine)
  if (alreadyGeneratedCoins === 0n) {
    return { success: true, reward: PREMINE_AMOUNT };
  }

  // Get full reward zone
  let fullRewardZone = BigInt(getMinBlockWeight(version));
  if (BigInt(medianWeight) < fullRewardZone) {
    medianWeight = Number(fullRewardZone);
  }

  // No penalty if block is small
  if (currentBlockWeight <= medianWeight) {
    return { success: true, reward: baseReward };
  }

  // Block too large
  if (currentBlockWeight > 2 * medianWeight) {
    return { success: false, reward: 0n };
  }

  // Calculate penalty: reward * (2*M - W) * W / M^2
  // Where M = median weight, W = current weight
  const multiplicand = BigInt(2 * medianWeight - currentBlockWeight) * BigInt(currentBlockWeight);
  const reward = (baseReward * multiplicand) / BigInt(medianWeight) / BigInt(medianWeight);

  return { success: true, reward };
}

/**
 * Calculate total emission at a given height (approximate)
 * @param {number} height - Block height
 * @returns {bigint} Approximate total emission
 */
export function getApproximateEmission(height) {
  if (height === 0) return PREMINE_AMOUNT;

  // Simplified calculation - actual emission is cumulative
  // This is an approximation; real emission requires summing all block rewards
  const target = DIFFICULTY_TARGET_V2;
  const targetMinutes = target / 60;
  const emissionSpeedFactor = EMISSION_SPEED_FACTOR_PER_MINUTE - (targetMinutes - 1);

  // Geometric series approximation
  // Sum ≈ MONEY_SUPPLY * (1 - 0.5^(height/halvingPeriod))
  // Where halvingPeriod = 2^emissionSpeedFactor blocks

  let emission = PREMINE_AMOUNT;
  let remaining = MONEY_SUPPLY - PREMINE_AMOUNT;

  for (let h = 1; h <= height && remaining > 0n; h++) {
    const reward = remaining >> BigInt(emissionSpeedFactor);
    const minReward = FINAL_SUBSIDY_PER_MINUTE * BigInt(targetMinutes);
    const actualReward = reward < minReward ? minReward : reward;
    emission += actualReward;
    remaining -= actualReward;
  }

  return emission;
}

// =============================================================================
// DIFFICULTY CALCULATION
// =============================================================================

/**
 * Calculate next difficulty using original algorithm
 *
 * @param {number[]} timestamps - Block timestamps (newest first)
 * @param {bigint[]} cumulativeDifficulties - Cumulative difficulties
 * @param {number} targetSeconds - Target block time
 * @returns {bigint} Next difficulty
 */
export function nextDifficulty(timestamps, cumulativeDifficulties, targetSeconds = DIFFICULTY_TARGET_V2) {
  // Trim to window size
  if (timestamps.length > DIFFICULTY_WINDOW) {
    timestamps = timestamps.slice(0, DIFFICULTY_WINDOW);
    cumulativeDifficulties = cumulativeDifficulties.slice(0, DIFFICULTY_WINDOW);
  }

  const length = timestamps.length;
  if (length !== cumulativeDifficulties.length) {
    throw new Error('Timestamps and difficulties must have same length');
  }

  if (length <= 1) {
    return 1n;
  }

  // Sort timestamps
  timestamps = [...timestamps].sort((a, b) => a - b);

  // Calculate cut points
  let cutBegin, cutEnd;
  if (length <= DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) {
    cutBegin = 0;
    cutEnd = length;
  } else {
    cutBegin = Math.floor((length - (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT) + 1) / 2);
    cutEnd = cutBegin + (DIFFICULTY_WINDOW - 2 * DIFFICULTY_CUT);
  }

  // Calculate time span and work
  let timeSpan = BigInt(timestamps[cutEnd - 1] - timestamps[cutBegin]);
  if (timeSpan === 0n) timeSpan = 1n;

  const totalWork = cumulativeDifficulties[cutEnd - 1] - cumulativeDifficulties[cutBegin];

  // difficulty = work * target / timeSpan
  return (totalWork * BigInt(targetSeconds) + timeSpan - 1n) / timeSpan;
}

/**
 * Calculate next difficulty using LWMA (Linearly Weighted Moving Average) v2
 *
 * LWMA algorithm by Zawy
 * https://github.com/zawy12/difficulty-algorithms/issues/3
 *
 * @param {number[]} timestamps - Block timestamps (oldest first, length N+1)
 * @param {bigint[]} cumulativeDifficulties - Cumulative difficulties (length N+1)
 * @param {number} targetSeconds - Target block time
 * @returns {bigint} Next difficulty
 */
export function nextDifficultyV2(timestamps, cumulativeDifficulties, targetSeconds = DIFFICULTY_TARGET_V2) {
  const T = targetSeconds;
  let N = DIFFICULTY_WINDOW_V2;

  // Trim to window
  if (timestamps.length > N + 1) {
    timestamps = timestamps.slice(0, N + 1);
    cumulativeDifficulties = cumulativeDifficulties.slice(0, N + 1);
  }

  const n = timestamps.length;
  if (n !== cumulativeDifficulties.length) {
    throw new Error('Timestamps and difficulties must have same length');
  }

  // First 5 blocks: return difficulty 1
  if (n < 6) return 1n;

  // If height < N+1, adjust N
  if (n < N + 1) N = n - 1;

  // Adjustment factor for average solvetime accuracy
  const adjust = 0.998;
  // Normalization divisor
  const k = N * (N + 1) / 2;

  let LWMA = 0;
  let sumInverseD = 0;

  // Loop through N most recent blocks
  for (let i = 1; i <= N; i++) {
    let solveTime = Number(timestamps[i]) - Number(timestamps[i - 1]);
    // Clamp solve time to [-7T, 7T]
    solveTime = Math.min(T * 7, Math.max(solveTime, -7 * T));

    const difficulty = Number(cumulativeDifficulties[i] - cumulativeDifficulties[i - 1]);
    LWMA += (solveTime * i) / k;
    sumInverseD += 1 / difficulty;
  }

  // Sanity check
  if (LWMA < T / 20) LWMA = T / 20;

  // Calculate harmonic mean of difficulties
  const harmonicMeanD = N / sumInverseD * adjust;

  // Next difficulty
  const nextDiff = harmonicMeanD * T / LWMA;

  return BigInt(Math.floor(nextDiff));
}

/**
 * Check if a hash meets difficulty target
 *
 * hash * difficulty <= 2^256
 *
 * @param {Uint8Array} hash - 32-byte hash
 * @param {bigint} difficulty - Difficulty target
 * @returns {boolean} True if hash meets difficulty
 */
export function checkHash(hash, difficulty) {
  if (hash.length !== 32) {
    throw new Error('Hash must be 32 bytes');
  }

  // Convert hash to big-endian bigint
  let hashVal = 0n;
  for (let i = 0; i < 32; i++) {
    hashVal = (hashVal << 8n) | BigInt(hash[i]);
  }

  // Check: hash * difficulty <= 2^256
  const max256 = (1n << 256n) - 1n;
  return hashVal * difficulty <= max256;
}

// =============================================================================
// TIMESTAMP VALIDATION
// =============================================================================

/**
 * Get median timestamp from recent blocks
 * @param {number[]} timestamps - Recent block timestamps (most recent first)
 * @returns {number} Median timestamp
 */
export function getMedianTimestamp(timestamps) {
  if (timestamps.length === 0) return 0;

  const sorted = [...timestamps].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);

  if (sorted.length % 2 === 0) {
    return Math.floor((sorted[mid - 1] + sorted[mid]) / 2);
  }
  return sorted[mid];
}

/**
 * Validate block timestamp
 *
 * Timestamp must be:
 * 1. Greater than median of last BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW blocks
 * 2. Not more than CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT in the future
 *
 * @param {number} timestamp - Block timestamp
 * @param {number[]} recentTimestamps - Recent block timestamps
 * @param {number} currentTime - Current Unix timestamp
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateBlockTimestamp(timestamp, recentTimestamps, currentTime) {
  // Check future limit
  if (timestamp > currentTime + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT) {
    return {
      valid: false,
      error: `Timestamp too far in future: ${timestamp} > ${currentTime + CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT}`
    };
  }

  // Check median time rule
  if (recentTimestamps.length >= BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW) {
    const medianTime = getMedianTimestamp(recentTimestamps.slice(0, BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW));
    if (timestamp <= medianTime) {
      return {
        valid: false,
        error: `Timestamp not greater than median: ${timestamp} <= ${medianTime}`
      };
    }
  }

  return { valid: true };
}

// =============================================================================
// UNLOCK TIME VALIDATION
// =============================================================================

/**
 * Check if an output is unlocked (spendable)
 *
 * @param {bigint} unlockTime - Unlock time (0 = no lock, <500M = block height, >=500M = unix timestamp)
 * @param {number} currentHeight - Current blockchain height
 * @param {number} currentTime - Current Unix timestamp
 * @param {number} version - Hard fork version
 * @returns {boolean} True if unlocked
 */
export function isOutputUnlocked(unlockTime, currentHeight, currentTime, version = 1) {
  // No lock
  if (unlockTime === 0n) return true;

  const unlockTimeNum = Number(unlockTime);

  // Threshold: 500,000,000 - below = height, above = timestamp
  const UNLOCK_TIME_THRESHOLD = 500000000;

  if (unlockTimeNum < UNLOCK_TIME_THRESHOLD) {
    // Block height based unlock
    const allowedDelta = version >= 2
      ? CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
      : CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;
    return currentHeight + allowedDelta >= unlockTimeNum;
  } else {
    // Timestamp based unlock
    const allowedDelta = version >= 2
      ? DIFFICULTY_TARGET_V2 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS
      : DIFFICULTY_TARGET_V1 * CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS;
    return currentTime + allowedDelta >= unlockTimeNum;
  }
}

/**
 * Check if coinbase output is mature (spendable)
 *
 * @param {number} outputHeight - Height where output was created
 * @param {number} currentHeight - Current blockchain height
 * @returns {boolean} True if mature
 */
export function isCoinbaseMature(outputHeight, currentHeight) {
  return currentHeight >= outputHeight + CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW;
}

/**
 * Check if output meets minimum age requirement
 *
 * @param {number} outputHeight - Height where output was created
 * @param {number} currentHeight - Current blockchain height
 * @returns {boolean} True if old enough
 */
export function meetsMinimumAge(outputHeight, currentHeight) {
  return currentHeight >= outputHeight + CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE;
}

// =============================================================================
// FEE VALIDATION
// =============================================================================

/**
 * Calculate minimum required fee
 *
 * @param {number} txWeight - Transaction weight in bytes
 * @param {bigint} baseReward - Current block reward
 * @param {number} version - Hard fork version
 * @returns {bigint} Minimum fee
 */
export function getMinimumFee(txWeight, baseReward, version = 1) {
  if (version >= HF_VERSION.PER_BYTE_FEE) {
    // Per-byte fee
    return BigInt(txWeight) * FEE_PER_BYTE;
  }

  // Legacy per-KB fee
  const kbSize = BigInt(Math.ceil(txWeight / 1024));
  return kbSize * FEE_PER_KB;
}

/**
 * Calculate dynamic fee based on block reward
 *
 * @param {bigint} baseReward - Current block reward
 * @param {number} txWeight - Transaction weight
 * @param {number} version - Hard fork version
 * @returns {bigint} Dynamic fee
 */
export function getDynamicFee(baseReward, txWeight, version = 1) {
  const fee = DYNAMIC_FEE_PER_KB_BASE_FEE * BigInt(txWeight) / 1024n;

  // Scale by reward ratio
  if (baseReward > 0n) {
    const scaledFee = fee * DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD / baseReward;
    return scaledFee > fee ? scaledFee : fee;
  }

  return fee;
}

/**
 * Quantize fee (round to reduce fingerprinting)
 *
 * @param {bigint} fee - Raw fee
 * @returns {bigint} Quantized fee
 */
export function quantizeFee(fee) {
  const mask = (10n ** BigInt(PER_KB_FEE_QUANTIZATION_DECIMALS)) - 1n;
  return ((fee + mask) / (mask + 1n)) * (mask + 1n);
}

// =============================================================================
// BLOCK VALIDATION
// =============================================================================

/**
 * Validate block header chain linkage
 *
 * @param {Object} currentHeader - Current block header
 * @param {Object} previousHeader - Previous block header
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateBlockLinkage(currentHeader, previousHeader) {
  // Check previous hash matches
  const prevHashHex = typeof currentHeader.prevId === 'string'
    ? currentHeader.prevId
    : Buffer.from(currentHeader.prevId).toString('hex');

  const expectedPrevHash = typeof previousHeader.hash === 'string'
    ? previousHeader.hash
    : Buffer.from(previousHeader.hash).toString('hex');

  if (prevHashHex !== expectedPrevHash) {
    return {
      valid: false,
      error: `Previous hash mismatch: ${prevHashHex} != ${expectedPrevHash}`
    };
  }

  // Check height is sequential
  if (currentHeader.height !== previousHeader.height + 1) {
    return {
      valid: false,
      error: `Height not sequential: ${currentHeader.height} != ${previousHeader.height + 1}`
    };
  }

  return { valid: true };
}

/**
 * Validate block size/weight
 *
 * @param {number} blockWeight - Block weight in bytes
 * @param {number} medianWeight - Median block weight
 * @param {number} version - Hard fork version
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateBlockWeight(blockWeight, medianWeight, version = 1) {
  const maxWeight = 2 * Math.max(medianWeight, getMinBlockWeight(version));

  if (blockWeight > maxWeight) {
    return {
      valid: false,
      error: `Block weight ${blockWeight} exceeds max ${maxWeight}`
    };
  }

  return { valid: true };
}

// =============================================================================
// TRANSACTION VALIDATION
// =============================================================================

/**
 * Validate transaction size
 *
 * @param {number} txSize - Transaction size in bytes
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateTxSize(txSize) {
  if (txSize > CRYPTONOTE_MAX_TX_SIZE) {
    return {
      valid: false,
      error: `Transaction size ${txSize} exceeds max ${CRYPTONOTE_MAX_TX_SIZE}`
    };
  }
  return { valid: true };
}

/**
 * Validate transaction extra field size
 *
 * @param {number} extraSize - Extra field size in bytes
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateTxExtraSize(extraSize) {
  if (extraSize > MAX_TX_EXTRA_SIZE) {
    return {
      valid: false,
      error: `Transaction extra size ${extraSize} exceeds max ${MAX_TX_EXTRA_SIZE}`
    };
  }
  return { valid: true };
}

/**
 * Validate transaction output count
 *
 * @param {number} outputCount - Number of outputs
 * @param {number} version - Hard fork version
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateOutputCount(outputCount, version = 1) {
  if (outputCount === 0) {
    return { valid: false, error: 'Transaction must have at least one output' };
  }

  if (outputCount > BULLETPROOF_PLUS_MAX_OUTPUTS) {
    return {
      valid: false,
      error: `Output count ${outputCount} exceeds max ${BULLETPROOF_PLUS_MAX_OUTPUTS}`
    };
  }

  return { valid: true };
}

/**
 * Validate ring size
 *
 * @param {number} ringSize - Ring size (number of decoys + 1)
 * @param {number} version - Hard fork version
 * @returns {{ valid: boolean, error?: string }}
 */
export function validateRingSize(ringSize, version = 1) {
  if (ringSize < 1) {
    return { valid: false, error: 'Ring size must be at least 1' };
  }

  // Salvium requires ring size of 16
  if (ringSize !== DEFAULT_RING_SIZE) {
    return {
      valid: false,
      error: `Ring size must be ${DEFAULT_RING_SIZE}, got ${ringSize}`
    };
  }

  return { valid: true };
}

// =============================================================================
// EXPORTS
// =============================================================================

export default {
  // Constants
  MONEY_SUPPLY,
  EMISSION_SPEED_FACTOR_PER_MINUTE,
  FINAL_SUBSIDY_PER_MINUTE,
  COIN,
  PREMINE_AMOUNT,
  DIFFICULTY_TARGET_V1,
  DIFFICULTY_TARGET_V2,
  DIFFICULTY_WINDOW,
  DIFFICULTY_WINDOW_V2,
  CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
  CRYPTONOTE_MAX_TX_SIZE,
  DEFAULT_RING_SIZE,
  FEE_PER_KB,
  FEE_PER_BYTE,
  HF_VERSION,
  NETWORK_ID,

  // Functions
  getNetworkConfig,
  getBlockReward,
  nextDifficulty,
  nextDifficultyV2,
  checkHash,
  getMedianTimestamp,
  validateBlockTimestamp,
  isOutputUnlocked,
  isCoinbaseMature,
  meetsMinimumAge,
  getMinimumFee,
  getDynamicFee,
  validateBlockLinkage,
  validateBlockWeight,
  validateTxSize,
  validateRingSize,
};
