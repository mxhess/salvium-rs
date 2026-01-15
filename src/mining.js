/**
 * Mining utilities for Salvium
 *
 * This module provides block template handling, difficulty checking,
 * and mining infrastructure. The actual PoW hash (RandomX) must be
 * provided externally as it requires native/WASM implementation.
 *
 * Reference: cryptonote_basic/miner.cpp, cryptonote_basic/difficulty.cpp
 */

import { keccak256, cnFastHash } from './keccak.js';
import { encodeVarint, serializeBlockHeader, HF_VERSION_ENABLE_ORACLE } from './transaction.js';

// =============================================================================
// Constants
// =============================================================================

/**
 * Mining-related constants from cryptonote_config.h
 */
export const MINING_CONSTANTS = {
  // Block version that enables RandomX
  RX_BLOCK_VERSION: 12,

  // Hard fork version that enables n_outs (2 special txs: miner_tx + protocol_tx)
  HF_VERSION_ENABLE_N_OUTS: 1, // Salvium has this from start

  // Maximum extra nonce size in bytes
  MAX_EXTRA_NONCE_SIZE: 255,

  // Nonce size in bytes
  NONCE_SIZE: 4,

  // Target block time in seconds
  DIFFICULTY_TARGET: 120,

  // Difficulty window for calculations
  DIFFICULTY_WINDOW: 720,
  DIFFICULTY_WINDOW_V2: 60,
  DIFFICULTY_CUT: 60,
  DIFFICULTY_LAG: 15
};

// =============================================================================
// Block Template Parsing
// =============================================================================

/**
 * Parse a block template response from daemon RPC
 *
 * @param {Object} templateResponse - Response from get_block_template RPC
 * @returns {Object} Parsed block template
 */
export function parseBlockTemplate(templateResponse) {
  const {
    difficulty,
    wide_difficulty,
    difficulty_top64,
    height,
    reserved_offset,
    expected_reward,
    prev_hash,
    seed_height,
    seed_hash,
    next_seed_hash,
    blocktemplate_blob,
    blockhashing_blob
  } = templateResponse;

  return {
    // Difficulty as BigInt for precision
    difficulty: parseDifficulty(difficulty, wide_difficulty, difficulty_top64),

    // Block height
    height: BigInt(height),

    // Reserved space offset for extra nonce
    reservedOffset: reserved_offset,

    // Expected block reward in atomic units
    expectedReward: BigInt(expected_reward),

    // Previous block hash (hex string)
    prevHash: prev_hash,

    // RandomX seed information
    seedHeight: BigInt(seed_height || 0),
    seedHash: seed_hash || '',
    nextSeedHash: next_seed_hash || '',

    // Raw blobs (hex strings)
    blocktemplateBlob: blocktemplate_blob,
    blockhashingBlob: blockhashing_blob,

    // Parsed blobs (Uint8Array)
    blocktemplateBytes: hexToBytes(blocktemplate_blob),
    blockhashingBytes: hexToBytes(blockhashing_blob)
  };
}

/**
 * Parse difficulty from RPC response (handles 64-bit and 128-bit)
 *
 * @param {number|string} difficulty - 64-bit difficulty
 * @param {string} wide_difficulty - Full difficulty as hex string
 * @param {number} difficulty_top64 - Upper 64 bits
 * @returns {bigint} Full difficulty as BigInt
 */
export function parseDifficulty(difficulty, wide_difficulty, difficulty_top64) {
  // If wide_difficulty is provided, use it (most accurate)
  if (wide_difficulty) {
    // Remove 0x prefix if present
    const hex = wide_difficulty.startsWith('0x') ? wide_difficulty.slice(2) : wide_difficulty;
    return BigInt('0x' + hex);
  }

  // Otherwise combine difficulty and difficulty_top64
  if (difficulty_top64) {
    return (BigInt(difficulty_top64) << 64n) | BigInt(difficulty);
  }

  // Just use 64-bit difficulty
  return BigInt(difficulty);
}

// =============================================================================
// Block Hashing Blob Construction
// =============================================================================

/**
 * Compute tree hash (Merkle root) of transaction hashes
 * Matches Salvium's tree_hash() in crypto/tree-hash.c
 *
 * @param {Array<Uint8Array>} hashes - Array of 32-byte transaction hashes
 * @returns {Uint8Array} 32-byte tree root hash
 */
export function treeHash(hashes) {
  const count = hashes.length;

  if (count === 0) {
    return new Uint8Array(32);
  }

  if (count === 1) {
    return new Uint8Array(hashes[0]);
  }

  if (count === 2) {
    // Hash pair directly
    const combined = new Uint8Array(64);
    combined.set(hashes[0], 0);
    combined.set(hashes[1], 32);
    return cnFastHash(combined);
  }

  // For count >= 3, use CryptoNote tree hash algorithm
  // Find cnt = largest power of 2 <= count
  let cnt = 1;
  while (cnt * 2 <= count) {
    cnt *= 2;
  }

  // Initialize intermediate hashes
  let ints = new Array(cnt);

  // Copy hashes that don't need initial hashing
  const startIdx = 2 * cnt - count;
  for (let i = 0; i < startIdx; i++) {
    ints[i] = new Uint8Array(hashes[i]);
  }

  // Hash remaining pairs into intermediate array
  for (let i = startIdx, j = startIdx; j < cnt; i += 2, j++) {
    const combined = new Uint8Array(64);
    combined.set(hashes[i], 0);
    combined.set(hashes[i + 1], 32);
    ints[j] = cnFastHash(combined);
  }

  // Reduce tree until we have 2 elements
  while (cnt > 2) {
    cnt >>= 1;
    for (let i = 0, j = 0; j < cnt; i += 2, j++) {
      const combined = new Uint8Array(64);
      combined.set(ints[i], 0);
      combined.set(ints[i + 1], 32);
      ints[j] = cnFastHash(combined);
    }
  }

  // Final hash of 2 remaining elements
  const finalCombined = new Uint8Array(64);
  finalCombined.set(ints[0], 0);
  finalCombined.set(ints[1], 32);
  return cnFastHash(finalCombined);
}

/**
 * Construct block hashing blob from block data
 * This is what gets passed to the PoW hash function (RandomX)
 *
 * Format: block_header || tree_root_hash || varint(num_txs)
 *
 * @param {Object} block - Block object
 * @param {Array<Uint8Array>} txHashes - Transaction hashes (miner_tx, protocol_tx, regular txs)
 * @returns {Uint8Array} Block hashing blob
 */
export function constructBlockHashingBlob(block, txHashes) {
  // Serialize block header
  const headerBytes = serializeBlockHeader(block);

  // Compute tree hash of all transaction hashes
  const treeRoot = treeHash(txHashes);

  // Number of transactions (miner_tx + protocol_tx + regular txs)
  // For HF_VERSION_ENABLE_N_OUTS (always true in Salvium), count includes both special txs
  const numTxs = block.major_version >= 1 ? txHashes.length : txHashes.length;
  const numTxsVarint = encodeVarint(BigInt(numTxs));

  // Combine: header || tree_root || num_txs_varint
  const totalLen = headerBytes.length + 32 + numTxsVarint.length;
  const result = new Uint8Array(totalLen);
  let offset = 0;

  result.set(headerBytes, offset);
  offset += headerBytes.length;

  result.set(treeRoot, offset);
  offset += 32;

  result.set(numTxsVarint, offset);

  return result;
}

// =============================================================================
// Nonce Manipulation
// =============================================================================

/**
 * Set the nonce in a block hashing blob
 * Nonce is at the end of the block header (after prev_id)
 *
 * @param {Uint8Array} blob - Block hashing blob
 * @param {number} nonce - 32-bit nonce value
 * @param {number} nonceOffset - Offset of nonce in blob (from block template)
 * @returns {Uint8Array} Modified blob with new nonce
 */
export function setNonce(blob, nonce, nonceOffset) {
  const result = new Uint8Array(blob);

  // Write nonce as 4 bytes little-endian
  result[nonceOffset] = nonce & 0xff;
  result[nonceOffset + 1] = (nonce >>> 8) & 0xff;
  result[nonceOffset + 2] = (nonce >>> 16) & 0xff;
  result[nonceOffset + 3] = (nonce >>> 24) & 0xff;

  return result;
}

/**
 * Get the nonce from a block blob
 *
 * @param {Uint8Array} blob - Block blob
 * @param {number} nonceOffset - Offset of nonce in blob
 * @returns {number} 32-bit nonce value
 */
export function getNonce(blob, nonceOffset) {
  return (
    blob[nonceOffset] |
    (blob[nonceOffset + 1] << 8) |
    (blob[nonceOffset + 2] << 16) |
    (blob[nonceOffset + 3] << 24)
  ) >>> 0; // >>> 0 ensures unsigned
}

/**
 * Set extra nonce in block template (in reserved space)
 *
 * @param {Uint8Array} blob - Block template blob
 * @param {Uint8Array} extraNonce - Extra nonce data (max 255 bytes)
 * @param {number} reservedOffset - Offset of reserved space
 * @returns {Uint8Array} Modified blob
 */
export function setExtraNonce(blob, extraNonce, reservedOffset) {
  if (extraNonce.length > MINING_CONSTANTS.MAX_EXTRA_NONCE_SIZE) {
    throw new Error(`Extra nonce too large: ${extraNonce.length} > ${MINING_CONSTANTS.MAX_EXTRA_NONCE_SIZE}`);
  }

  const result = new Uint8Array(blob);
  result.set(extraNonce, reservedOffset);
  return result;
}

// =============================================================================
// Difficulty Checking
// =============================================================================

/**
 * Check if a hash meets the difficulty target
 *
 * The hash passes if (hash * difficulty) < 2^256
 * Equivalently: hash < 2^256 / difficulty
 *
 * Reference: cryptonote_basic/difficulty.cpp check_hash()
 *
 * @param {Uint8Array} hash - 32-byte PoW hash result
 * @param {bigint} difficulty - Target difficulty
 * @returns {boolean} true if hash meets difficulty
 */
export function checkHash(hash, difficulty) {
  if (difficulty === 0n) {
    return false;
  }

  // Convert hash to BigInt (little-endian as used in Salvium)
  // But for comparison we need big-endian interpretation
  let hashVal = 0n;
  for (let i = 31; i >= 0; i--) {
    hashVal = (hashVal << 8n) | BigInt(hash[i]);
  }

  // Target = 2^256 / difficulty
  // Hash passes if hashVal * difficulty < 2^256
  // Which is equivalent to hashVal < 2^256 / difficulty
  const max256 = (1n << 256n) - 1n;

  // Check: hash * difficulty <= max256
  // This is the exact check from Salvium's check_hash_128
  return hashVal * difficulty <= max256;
}

/**
 * Calculate the difficulty target as a 256-bit value
 *
 * @param {bigint} difficulty - Network difficulty
 * @returns {bigint} Target value (hash must be less than this)
 */
export function difficultyToTarget(difficulty) {
  if (difficulty === 0n) {
    return 0n;
  }
  // Target = 2^256 / difficulty
  return (1n << 256n) / difficulty;
}

/**
 * Calculate difficulty from a hash
 * This is the inverse of the difficulty check
 *
 * @param {Uint8Array} hash - 32-byte hash
 * @returns {bigint} Equivalent difficulty for this hash
 */
export function hashToDifficulty(hash) {
  let hashVal = 0n;
  for (let i = 31; i >= 0; i--) {
    hashVal = (hashVal << 8n) | BigInt(hash[i]);
  }

  if (hashVal === 0n) {
    return 0n;
  }

  return (1n << 256n) / hashVal;
}

/**
 * Convert difficulty to human-readable string
 *
 * @param {bigint} difficulty - Difficulty value
 * @returns {string} Formatted difficulty string
 */
export function formatDifficulty(difficulty) {
  const num = Number(difficulty);

  if (num >= 1e15) return (num / 1e15).toFixed(2) + ' P';
  if (num >= 1e12) return (num / 1e12).toFixed(2) + ' T';
  if (num >= 1e9) return (num / 1e9).toFixed(2) + ' G';
  if (num >= 1e6) return (num / 1e6).toFixed(2) + ' M';
  if (num >= 1e3) return (num / 1e3).toFixed(2) + ' K';

  return difficulty.toString();
}

// =============================================================================
// Block Submission
// =============================================================================

/**
 * Format a mined block for submission via submit_block RPC
 *
 * @param {Uint8Array} blocktemplateBlob - Original block template
 * @param {number} nonce - Winning nonce
 * @param {number} nonceOffset - Offset to place nonce (usually around 39-43)
 * @returns {string} Hex-encoded block blob ready for submission
 */
export function formatBlockForSubmission(blocktemplateBlob, nonce, nonceOffset) {
  // Set the winning nonce in the block template
  const finalBlob = setNonce(blocktemplateBlob, nonce, nonceOffset);

  // Return as hex string
  return bytesToHex(finalBlob);
}

/**
 * Calculate nonce offset in block template
 * Nonce is after: major_version(varint) + minor_version(varint) + timestamp(varint) + prev_id(32 bytes)
 *
 * @param {Uint8Array} blob - Block template blob
 * @returns {number} Nonce offset
 */
export function findNonceOffset(blob) {
  let offset = 0;

  // Skip major_version (varint)
  while (blob[offset] & 0x80) offset++;
  offset++;

  // Skip minor_version (varint)
  while (blob[offset] & 0x80) offset++;
  offset++;

  // Skip timestamp (varint)
  while (blob[offset] & 0x80) offset++;
  offset++;

  // Skip prev_id (32 bytes)
  offset += 32;

  // Nonce is here
  return offset;
}

// =============================================================================
// Mining Statistics
// =============================================================================

/**
 * Calculate hashrate from hash count and time
 *
 * @param {bigint|number} hashes - Number of hashes computed
 * @param {number} seconds - Time elapsed in seconds
 * @returns {number} Hashrate in H/s
 */
export function calculateHashrate(hashes, seconds) {
  if (seconds === 0) return 0;
  return Number(hashes) / seconds;
}

/**
 * Format hashrate to human-readable string
 *
 * @param {number} hashrate - Hashrate in H/s
 * @returns {string} Formatted hashrate
 */
export function formatHashrate(hashrate) {
  if (hashrate >= 1e12) return (hashrate / 1e12).toFixed(2) + ' TH/s';
  if (hashrate >= 1e9) return (hashrate / 1e9).toFixed(2) + ' GH/s';
  if (hashrate >= 1e6) return (hashrate / 1e6).toFixed(2) + ' MH/s';
  if (hashrate >= 1e3) return (hashrate / 1e3).toFixed(2) + ' KH/s';
  return hashrate.toFixed(2) + ' H/s';
}

/**
 * Estimate time to find a block given hashrate and difficulty
 *
 * @param {number} hashrate - Hashrate in H/s
 * @param {bigint} difficulty - Network difficulty
 * @returns {number} Estimated seconds to find a block
 */
export function estimateBlockTime(hashrate, difficulty) {
  if (hashrate === 0) return Infinity;
  // Average hashes needed = difficulty
  // Time = difficulty / hashrate
  return Number(difficulty) / hashrate;
}

/**
 * Format time duration to human-readable string
 *
 * @param {number} seconds - Duration in seconds
 * @returns {string} Formatted duration
 */
export function formatDuration(seconds) {
  if (!isFinite(seconds)) return '∞';

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  const parts = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 || parts.length === 0) parts.push(`${secs}s`);

  return parts.join(' ');
}

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex) {
  if (!hex) return new Uint8Array(0);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// =============================================================================
// RandomX Integration Interface
// =============================================================================

/**
 * Interface for RandomX hash function
 *
 * Since RandomX requires native/WASM implementation, this module provides
 * a placeholder interface. Users should provide their own RandomX implementation.
 *
 * @callback RandomXHashFunction
 * @param {Uint8Array} input - Data to hash (block hashing blob)
 * @param {Uint8Array} seedHash - RandomX seed hash (32 bytes)
 * @returns {Uint8Array} 32-byte hash result
 */

/**
 * Create a mining context with custom RandomX implementation
 *
 * @param {RandomXHashFunction} randomxHash - RandomX hash implementation
 * @returns {Object} Mining context with methods
 */
export function createMiningContext(randomxHash) {
  return {
    /**
     * Mine a single nonce
     *
     * @param {Uint8Array} hashingBlob - Block hashing blob
     * @param {Uint8Array} seedHash - RandomX seed hash
     * @param {number} nonce - Nonce to try
     * @param {number} nonceOffset - Nonce offset in blob
     * @param {bigint} difficulty - Target difficulty
     * @returns {Object} { found: boolean, hash: Uint8Array, nonce: number }
     */
    tryNonce(hashingBlob, seedHash, nonce, nonceOffset, difficulty) {
      const blob = setNonce(hashingBlob, nonce, nonceOffset);
      const hash = randomxHash(blob, seedHash);
      const found = checkHash(hash, difficulty);
      return { found, hash, nonce };
    },

    /**
     * Mine a range of nonces
     *
     * @param {Uint8Array} hashingBlob - Block hashing blob
     * @param {Uint8Array} seedHash - RandomX seed hash
     * @param {number} startNonce - Starting nonce
     * @param {number} count - Number of nonces to try
     * @param {number} nonceOffset - Nonce offset in blob
     * @param {bigint} difficulty - Target difficulty
     * @returns {Object|null} Winning result or null if not found
     */
    mineRange(hashingBlob, seedHash, startNonce, count, nonceOffset, difficulty) {
      for (let i = 0; i < count; i++) {
        const nonce = (startNonce + i) >>> 0;
        const result = this.tryNonce(hashingBlob, seedHash, nonce, nonceOffset, difficulty);
        if (result.found) {
          return result;
        }
      }
      return null;
    }
  };
}

export default {
  MINING_CONSTANTS,
  parseBlockTemplate,
  parseDifficulty,
  treeHash,
  constructBlockHashingBlob,
  setNonce,
  getNonce,
  setExtraNonce,
  checkHash,
  difficultyToTarget,
  hashToDifficulty,
  formatDifficulty,
  formatBlockForSubmission,
  findNonceOffset,
  calculateHashrate,
  formatHashrate,
  estimateBlockTime,
  formatDuration,
  createMiningContext
};
