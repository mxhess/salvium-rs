/**
 * UTXO Selection Module
 *
 * Provides strategies for selecting UTXOs (Unspent Transaction Outputs)
 * when building transactions.
 *
 * @module transaction/utxo
 */

import {
  UTXO_STRATEGY,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE
} from './constants.js';

// Re-export UTXO_STRATEGY for convenience
export { UTXO_STRATEGY };

/**
 * Select UTXOs to spend for a transaction
 *
 * @param {Array<Object>} utxos - Available UTXOs with { amount, globalIndex, txHash, outputIndex, ... }
 * @param {bigint} targetAmount - Amount to spend (excluding fee)
 * @param {bigint} feePerInput - Estimated fee per input (for fee calculation)
 * @param {Object} options - Selection options
 * @param {string} options.strategy - Selection strategy (default: LARGEST_FIRST)
 * @param {number} options.minConfirmations - Minimum confirmations required (default: 10)
 * @param {number} options.currentHeight - Current blockchain height (for confirmation check)
 * @param {bigint} options.dustThreshold - Minimum output value to consider (default: 1000000n)
 * @param {number} options.maxInputs - Maximum inputs to use (default: 150)
 * @returns {Object} { selected: Array<Object>, totalAmount: bigint, changeAmount: bigint, estimatedFee: bigint }
 */
export function selectUTXOs(utxos, targetAmount, feePerInput, options = {}) {
  const {
    strategy = UTXO_STRATEGY.LARGEST_FIRST,
    minConfirmations = CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
    currentHeight = 0,
    dustThreshold = 1000000n,
    maxInputs = 150
  } = options;

  if (typeof targetAmount === 'number') {
    targetAmount = BigInt(targetAmount);
  }
  if (typeof feePerInput === 'number') {
    feePerInput = BigInt(feePerInput);
  }

  // Filter eligible UTXOs
  const eligible = utxos.filter(utxo => {
    const amount = typeof utxo.amount === 'bigint' ? utxo.amount : BigInt(utxo.amount);
    // Must be above dust threshold
    if (amount < dustThreshold) return false;
    // Must have enough confirmations
    if (currentHeight > 0 && utxo.blockHeight) {
      const confirmations = currentHeight - utxo.blockHeight;
      if (confirmations < minConfirmations) return false;
    }
    return true;
  });

  if (eligible.length === 0) {
    throw new Error('No eligible UTXOs available');
  }

  // Sort based on strategy
  let sorted;
  switch (strategy) {
    case UTXO_STRATEGY.LARGEST_FIRST:
      sorted = [...eligible].sort((a, b) => {
        const aAmount = typeof a.amount === 'bigint' ? a.amount : BigInt(a.amount);
        const bAmount = typeof b.amount === 'bigint' ? b.amount : BigInt(b.amount);
        return bAmount > aAmount ? 1 : bAmount < aAmount ? -1 : 0;
      });
      break;
    case UTXO_STRATEGY.SMALLEST_FIRST:
      sorted = [...eligible].sort((a, b) => {
        const aAmount = typeof a.amount === 'bigint' ? a.amount : BigInt(a.amount);
        const bAmount = typeof b.amount === 'bigint' ? b.amount : BigInt(b.amount);
        return aAmount > bAmount ? 1 : aAmount < bAmount ? -1 : 0;
      });
      break;
    case UTXO_STRATEGY.FIFO:
      sorted = [...eligible].sort((a, b) => {
        return (a.blockHeight || 0) - (b.blockHeight || 0);
      });
      break;
    case UTXO_STRATEGY.RANDOM:
      sorted = [...eligible];
      // Fisher-Yates shuffle
      for (let i = sorted.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [sorted[i], sorted[j]] = [sorted[j], sorted[i]];
      }
      break;
    default:
      sorted = eligible;
  }

  // Select UTXOs until we have enough
  const selected = [];
  let totalAmount = 0n;

  for (const utxo of sorted) {
    if (selected.length >= maxInputs) break;

    selected.push(utxo);
    const amount = typeof utxo.amount === 'bigint' ? utxo.amount : BigInt(utxo.amount);
    totalAmount += amount;

    // Calculate estimated fee with current selection
    const estimatedFee = feePerInput * BigInt(selected.length);
    const required = targetAmount + estimatedFee;

    if (totalAmount >= required) {
      break;
    }
  }

  // Check if we have enough
  const estimatedFee = feePerInput * BigInt(selected.length);
  const required = targetAmount + estimatedFee;

  if (totalAmount < required) {
    const shortfall = required - totalAmount;
    throw new Error(`Insufficient funds: need ${required} but only have ${totalAmount} (short ${shortfall})`);
  }

  const changeAmount = totalAmount - required;

  return {
    selected,
    totalAmount,
    changeAmount,
    estimatedFee
  };
}
