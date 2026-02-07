/**
 * Dynamic Fee Calculation Module
 *
 * Implements the exact fee calculation algorithms from the Salvium C++ source:
 * - Emission curve (get_block_reward)
 * - Dynamic base fee (get_dynamic_base_fee)
 * - 2021 scaling fee tiers (get_dynamic_base_fee_estimate_2021_scaling)
 * - Fee rounding (round_money_up)
 *
 * Reference files:
 * - cryptonote_config.h: constants
 * - cryptonote_basic/cryptonote_basic_impl.cpp: get_block_reward
 * - cryptonote_core/blockchain.cpp: get_dynamic_base_fee, check_fee, 2021 scaling
 *
 * @module transaction/fee
 */

// =============================================================================
// CONSTANTS (from cryptonote_config.h)
// =============================================================================

/** Total supply: 184.4M SAL = 18,440,000,000,000,000 atomic units */
export const MONEY_SUPPLY = 18_440_000_000_000_000n;

/** Emission speed factor per minute */
export const EMISSION_SPEED_FACTOR_PER_MINUTE = 21;

/** Minimum subsidy per minute (tail emission) */
export const FINAL_SUBSIDY_PER_MINUTE = 30_000_000n;

/** Block time target in seconds */
export const DIFFICULTY_TARGET_V2 = 120;

/** Premine amount (block 0 reward) */
export const PREMINE_AMOUNT = 2_210_000_000_000_000n;

/** Reference TX weight for dynamic fee formula */
export const DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT = 3000n;

/** Full reward zone V5 (min median block weight) */
export const CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 = 300_000n;

/** Full reward zone V1 */
export const CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1 = 20_000n;

/** Display decimal point */
export const CRYPTONOTE_DISPLAY_DECIMAL_POINT = 8;

/** Fee quantization decimals */
export const PER_KB_FEE_QUANTIZATION_DECIMALS = 8;

/** Fee rounding places for 2021 scaling */
export const CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES = 2;

// =============================================================================
// DERIVED CONSTANTS
// =============================================================================

const TARGET_MINUTES = BigInt(DIFFICULTY_TARGET_V2) / 60n;
const EMISSION_SPEED_FACTOR = BigInt(EMISSION_SPEED_FACTOR_PER_MINUTE) - (TARGET_MINUTES - 1n);
const FINAL_SUBSIDY = FINAL_SUBSIDY_PER_MINUTE * TARGET_MINUTES;

// =============================================================================
// BLOCK REWARD (cryptonote_basic_impl.cpp:81-132)
// =============================================================================

/**
 * Get minimum block weight for a given hard fork version
 * Matches C++ get_min_block_weight()
 *
 * @param {number} version - Hard fork version
 * @returns {bigint} Minimum block weight
 */
export function getMinBlockWeight(version = 2) {
  return version < 2
    ? CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1
    : CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
}

/**
 * Calculate block reward from emission curve.
 * Matches C++ get_block_reward(median, 1, already_generated_coins, reward, version)
 *
 * Note: Uses current_block_weight=1 (same as check_fee) so no penalty applies.
 * Block 0 returns PREMINE_AMOUNT.
 *
 * @param {bigint} alreadyGeneratedCoins - Total coins mined so far
 * @returns {bigint} Block reward in atomic units
 */
export function getBlockReward(alreadyGeneratedCoins) {
  // Block 0 is the premine
  if (alreadyGeneratedCoins === 0n) {
    return PREMINE_AMOUNT;
  }

  let baseReward = (MONEY_SUPPLY - alreadyGeneratedCoins) >> EMISSION_SPEED_FACTOR;
  if (baseReward < FINAL_SUBSIDY) {
    baseReward = FINAL_SUBSIDY;
  }
  return baseReward;
}

// =============================================================================
// ALREADY GENERATED COINS ESTIMATION
// =============================================================================

/**
 * Estimate already_generated_coins at a given block height.
 * Iterates the emission curve accounting for the premine at block 0.
 *
 * For heights up to ~100k, this runs in under 100ms.
 * Uses batching (1000 blocks per step) for efficiency.
 *
 * @param {number} height - Current blockchain height
 * @returns {bigint} Estimated total coins generated through blocks 0..height-1
 */
export function estimateAlreadyGeneratedCoins(height) {
  if (height <= 0) return 0n;

  // Block 0 generates the premine
  let coins = PREMINE_AMOUNT;
  if (height === 1) return coins;

  // Blocks 1..height-1: normal emission
  let h = 1;
  while (h < height) {
    const remaining = MONEY_SUPPLY - coins;
    let reward = remaining >> EMISSION_SPEED_FACTOR;
    if (reward < FINAL_SUBSIDY) reward = FINAL_SUBSIDY;

    // Batch: apply same reward for up to 1000 blocks
    // (reward changes by < 0.1% per 1000 blocks, error is negligible)
    const batch = Math.min(height - h, 1000);
    const batchReward = reward * BigInt(batch);
    coins += batchReward;
    h += batch;

    // Guard against overshoot
    if (coins > MONEY_SUPPLY) {
      coins = MONEY_SUPPLY;
      break;
    }
  }

  return coins;
}

// =============================================================================
// DYNAMIC BASE FEE (blockchain.cpp:4376-4391)
// =============================================================================

/**
 * Calculate dynamic base fee per byte.
 * Matches C++ Blockchain::get_dynamic_base_fee()
 *
 * Formula: fee = 0.95 * (base_reward * 3000) / (median^2)
 *
 * @param {bigint} baseReward - Block reward in atomic units
 * @param {bigint} medianBlockWeight - Effective median block weight
 * @param {number} version - Hard fork version (default 2)
 * @returns {bigint} Fee per byte in atomic units
 */
export function getDynamicBaseFee(baseReward, medianBlockWeight, version = 2) {
  const minWeight = getMinBlockWeight(version);
  if (medianBlockWeight < minWeight) {
    medianBlockWeight = minWeight;
  }

  // C++ uses 128-bit arithmetic: mul128 then two div128_64
  // In JS with BigInt this is straightforward
  let fee = baseReward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT;
  fee = fee / medianBlockWeight;
  fee = fee / medianBlockWeight;

  // Multiply by 0.95 (subtract 5%)
  fee = fee - fee / 20n;

  return fee;
}

// =============================================================================
// FEE QUANTIZATION MASK (blockchain.h:650-653)
// =============================================================================

/**
 * Get fee quantization mask.
 * Matches C++ Blockchain::get_fee_quantization_mask()
 *
 * In Salvium: 10^(8-8) = 1 (no quantization)
 *
 * @returns {bigint} Quantization mask
 */
export function getFeeQuantizationMask() {
  const exp = CRYPTONOTE_DISPLAY_DECIMAL_POINT - PER_KB_FEE_QUANTIZATION_DECIMALS;
  let mask = 1n;
  for (let i = 0; i < exp; i++) mask *= 10n;
  return mask;
}

// =============================================================================
// ROUND MONEY UP (cryptonote_format_utils.cpp)
// =============================================================================

/**
 * Round a fee value up to N significant figures.
 * Matches C++ cryptonote::round_money_up()
 *
 * Examples (figures=2):
 *   515 → 520,  2060 → 2100,  8251 → 8300,  103137 → 110000
 *
 * @param {bigint} amount - Amount to round
 * @param {number} figures - Number of significant figures
 * @returns {bigint} Rounded amount
 */
export function roundMoneyUp(amount, figures) {
  if (amount === 0n) return 0n;

  // Count magnitude (number of decimal digits - 1)
  let mag = amount;
  let magnitude = 0;
  while (mag >= 10n) {
    magnitude++;
    mag /= 10n;
  }

  if (magnitude < figures) return amount;

  // mask = 10^(magnitude - figures + 1)
  let mask = 1n;
  for (let i = 0; i < magnitude - figures + 1; i++) mask *= 10n;

  // Round up
  return ((amount + mask - 1n) / mask) * mask;
}

// =============================================================================
// 2021 SCALING FEE ESTIMATE (blockchain.cpp:4443-4476)
// =============================================================================

/**
 * Calculate the 4-tier dynamic fee estimate using 2021 scaling.
 * Matches C++ Blockchain::get_dynamic_base_fee_estimate_2021_scaling()
 *
 * Returns per-byte fee rates for each priority level:
 *   [0] = Fl (low/slow)
 *   [1] = Fn (normal)
 *   [2] = Fm (elevated)
 *   [3] = Fh (high/fast)
 *
 * These are used DIRECTLY as per-byte rates — no additional multiplier.
 *
 * @param {bigint} baseReward - Block reward in atomic units
 * @param {bigint} Mnw - Short-term median block weight (nonce weight)
 * @param {bigint} Mlw - Long-term effective median block weight
 * @returns {bigint[]} Array of 4 per-byte fee rates
 */
export function getDynamicFeeEstimate2021(baseReward, Mnw, Mlw) {
  const Mfw = Mnw < Mlw ? Mnw : Mlw; // min(Mnw, Mlw)

  // Fl = base_reward * REF_WEIGHT / (Mfw^2)
  const Fl = baseReward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (Mfw * Mfw);

  // Fn = 4 * base_reward * REF_WEIGHT / (Mfw^2)
  const Fn = 4n * baseReward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT / (Mfw * Mfw);

  // Fm = 16 * base_reward * REF_WEIGHT / (FULL_REWARD_ZONE_V5 * Mfw)
  const Fm = 16n * baseReward * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT
    / (CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5 * Mfw);

  // Fh = max(4*Fm, 4*Fm*Mfw / (32 * REF_WEIGHT * Mnw / FULL_REWARD_ZONE_V5))
  const denominator = 32n * DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT * Mnw
    / CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5;
  const Fh_scaled = denominator > 0n
    ? 4n * Fm * Mfw / denominator
    : 4n * Fm;
  const Fh = Fh_scaled > 4n * Fm ? Fh_scaled : 4n * Fm;

  const rnd = (v) => roundMoneyUp(v, CRYPTONOTE_SCALING_2021_FEE_ROUNDING_PLACES);
  return [rnd(Fl), rnd(Fn), rnd(Fm), rnd(Fh)];
}

// =============================================================================
// HIGH-LEVEL FEE ESTIMATION
// =============================================================================

/**
 * Compute the per-byte fee rate for a given priority from blockchain state.
 *
 * This is the main entry point for fee calculation. It:
 * 1. Estimates already_generated_coins from height
 * 2. Computes block reward from emission curve
 * 3. Computes 4-tier dynamic fee estimate
 * 4. Returns the fee for the requested priority
 *
 * @param {Object} blockchainState - Current blockchain parameters
 * @param {number} blockchainState.height - Current blockchain height
 * @param {number|bigint} blockchainState.blockWeightMedian - Median block weight
 *   (can be obtained from daemon getInfo().block_weight_median,
 *    or from block_weight_limit / 2)
 * @param {bigint} [blockchainState.alreadyGeneratedCoins] - If known exactly;
 *   otherwise estimated from height
 * @param {number} priority - Priority level 1-4 (default: 2/normal)
 * @returns {bigint} Per-byte fee rate for the given priority
 */
export function getDynamicFeePerByte(blockchainState, priority = 2) {
  const { height } = blockchainState;
  let median = BigInt(blockchainState.blockWeightMedian || 300000);
  const minWeight = getMinBlockWeight(2);
  if (median < minWeight) median = minWeight;

  // Get already_generated_coins (exact if provided, otherwise estimate)
  const coins = blockchainState.alreadyGeneratedCoins != null
    ? BigInt(blockchainState.alreadyGeneratedCoins)
    : estimateAlreadyGeneratedCoins(height);

  // Compute block reward from emission curve
  const baseReward = getBlockReward(coins);

  // For 2021 scaling, we need both short-term and long-term medians.
  // On a fresh/small chain they're equal. For mature chains the daemon
  // provides block_weight_median which is the effective (min of short/long).
  // We use median for both Mnw and Mlw (conservative: Mfw = min = median).
  const Mnw = median;
  const Mlw = median;

  // Compute 4-tier fees
  const fees = getDynamicFeeEstimate2021(baseReward, Mnw, Mlw);

  // Clamp priority 1-4
  const p = Math.max(1, Math.min(4, priority || 2));
  return fees[p - 1];
}

/**
 * Compute needed_fee for check_fee validation (what the daemon enforces).
 * Matches C++ Blockchain::check_fee()
 *
 * @param {number} txWeight - Transaction weight
 * @param {bigint} baseReward - Block reward
 * @param {bigint} medianBlockWeight - Effective median weight
 * @returns {bigint} Minimum fee the daemon will accept
 */
export function computeNeededFee(txWeight, baseReward, medianBlockWeight) {
  const feePerByte = getDynamicBaseFee(baseReward, medianBlockWeight);
  let neededFee = BigInt(txWeight) * feePerByte;

  // Quantize (mask = 1 in Salvium, so no-op)
  const mask = getFeeQuantizationMask();
  if (mask > 1n) {
    neededFee = ((neededFee + mask - 1n) / mask) * mask;
  }

  return neededFee;
}
