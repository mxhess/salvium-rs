/**
 * RandomX Configuration Constants
 *
 * Reference: external/randomx/src/configuration.h
 */

// ============================================================================
// Argon2 Parameters for Cache Initialization
// ============================================================================

/** Cache size in KiB. Must be a power of 2. */
export const RANDOMX_ARGON_MEMORY = 262144;

/** Number of Argon2d iterations for Cache initialization. */
export const RANDOMX_ARGON_ITERATIONS = 3;

/** Number of parallel lanes for Cache initialization. */
export const RANDOMX_ARGON_LANES = 1;

/** Argon2d salt */
export const RANDOMX_ARGON_SALT = "RandomX\x03";

// ============================================================================
// Dataset Parameters
// ============================================================================

/** Number of random Cache accesses per Dataset item. Minimum is 2. */
export const RANDOMX_CACHE_ACCESSES = 8;

/** Target latency for SuperscalarHash (in cycles of the reference CPU). */
export const RANDOMX_SUPERSCALAR_LATENCY = 170;

/** Dataset base size in bytes. Must be a power of 2. */
export const RANDOMX_DATASET_BASE_SIZE = 2147483648;  // 2 GB

/** Dataset extra size. Must be divisible by 64. */
export const RANDOMX_DATASET_EXTRA_SIZE = 33554368;

/** Total dataset size */
export const RANDOMX_DATASET_SIZE = RANDOMX_DATASET_BASE_SIZE + RANDOMX_DATASET_EXTRA_SIZE;

/** Number of 64-byte dataset items */
export const RANDOMX_DATASET_ITEM_COUNT = Math.floor(RANDOMX_DATASET_SIZE / 64);

// ============================================================================
// Program Parameters
// ============================================================================

/** Number of instructions in a RandomX program. Must be divisible by 8. */
export const RANDOMX_PROGRAM_SIZE = 256;

/** Number of iterations during VM execution. */
export const RANDOMX_PROGRAM_ITERATIONS = 2048;

/** Number of chained VM executions per hash. */
export const RANDOMX_PROGRAM_COUNT = 8;

// ============================================================================
// Scratchpad Parameters
// ============================================================================

/** Scratchpad L3 size in bytes. Must be a power of 2. */
export const RANDOMX_SCRATCHPAD_L3 = 2097152;  // 2 MB

/** Scratchpad L2 size in bytes. */
export const RANDOMX_SCRATCHPAD_L2 = 262144;   // 256 KB

/** Scratchpad L1 size in bytes. */
export const RANDOMX_SCRATCHPAD_L1 = 16384;    // 16 KB

/** Scratchpad L3 mask for address calculation */
export const RANDOMX_SCRATCHPAD_L3_MASK = RANDOMX_SCRATCHPAD_L3 - 8;

/** Scratchpad L2 mask for address calculation */
export const RANDOMX_SCRATCHPAD_L2_MASK = RANDOMX_SCRATCHPAD_L2 - 8;

/** Scratchpad L1 mask for address calculation */
export const RANDOMX_SCRATCHPAD_L1_MASK = RANDOMX_SCRATCHPAD_L1 - 8;

// ============================================================================
// Jump Condition Parameters
// ============================================================================

/** Jump condition mask size in bits. */
export const RANDOMX_JUMP_BITS = 8;

/** Jump condition mask offset in bits. */
export const RANDOMX_JUMP_OFFSET = 8;

// ============================================================================
// Register Configuration
// ============================================================================

/** Number of integer registers */
export const REGISTER_COUNT_INT = 8;

/** Number of floating-point register pairs */
export const REGISTER_COUNT_FLT = 4;

// ============================================================================
// Instruction Frequencies (per 256 opcodes)
// ============================================================================

// Integer instructions
export const RANDOMX_FREQ_IADD_RS = 16;
export const RANDOMX_FREQ_IADD_M = 7;
export const RANDOMX_FREQ_ISUB_R = 16;
export const RANDOMX_FREQ_ISUB_M = 7;
export const RANDOMX_FREQ_IMUL_R = 16;
export const RANDOMX_FREQ_IMUL_M = 4;
export const RANDOMX_FREQ_IMULH_R = 4;
export const RANDOMX_FREQ_IMULH_M = 1;
export const RANDOMX_FREQ_ISMULH_R = 4;
export const RANDOMX_FREQ_ISMULH_M = 1;
export const RANDOMX_FREQ_IMUL_RCP = 8;
export const RANDOMX_FREQ_INEG_R = 2;
export const RANDOMX_FREQ_IXOR_R = 15;
export const RANDOMX_FREQ_IXOR_M = 5;
export const RANDOMX_FREQ_IROR_R = 8;
export const RANDOMX_FREQ_IROL_R = 2;
export const RANDOMX_FREQ_ISWAP_R = 4;

// Floating point instructions
export const RANDOMX_FREQ_FSWAP_R = 4;
export const RANDOMX_FREQ_FADD_R = 16;
export const RANDOMX_FREQ_FADD_M = 5;
export const RANDOMX_FREQ_FSUB_R = 16;
export const RANDOMX_FREQ_FSUB_M = 5;
export const RANDOMX_FREQ_FSCAL_R = 6;
export const RANDOMX_FREQ_FMUL_R = 32;
export const RANDOMX_FREQ_FDIV_M = 4;
export const RANDOMX_FREQ_FSQRT_R = 6;

// Control instructions
export const RANDOMX_FREQ_CBRANCH = 25;
export const RANDOMX_FREQ_CFROUND = 1;

// Store instruction
export const RANDOMX_FREQ_ISTORE = 16;

// No-op instruction
export const RANDOMX_FREQ_NOP = 0;

// ============================================================================
// Derived Constants
// ============================================================================

/** Mask for dataset item index */
export const RANDOMX_DATASET_ITEM_MASK = (RANDOMX_DATASET_ITEM_COUNT - 1) * 64;

/** Number of cache items (64 bytes each) */
export const RANDOMX_CACHE_ITEM_COUNT = Math.floor(RANDOMX_ARGON_MEMORY * 1024 / 64);

export default {
  RANDOMX_ARGON_MEMORY,
  RANDOMX_ARGON_ITERATIONS,
  RANDOMX_ARGON_LANES,
  RANDOMX_ARGON_SALT,
  RANDOMX_CACHE_ACCESSES,
  RANDOMX_SUPERSCALAR_LATENCY,
  RANDOMX_DATASET_BASE_SIZE,
  RANDOMX_DATASET_EXTRA_SIZE,
  RANDOMX_DATASET_SIZE,
  RANDOMX_DATASET_ITEM_COUNT,
  RANDOMX_PROGRAM_SIZE,
  RANDOMX_PROGRAM_ITERATIONS,
  RANDOMX_PROGRAM_COUNT,
  RANDOMX_SCRATCHPAD_L3,
  RANDOMX_SCRATCHPAD_L2,
  RANDOMX_SCRATCHPAD_L1,
  RANDOMX_SCRATCHPAD_L3_MASK,
  RANDOMX_SCRATCHPAD_L2_MASK,
  RANDOMX_SCRATCHPAD_L1_MASK,
  RANDOMX_JUMP_BITS,
  RANDOMX_JUMP_OFFSET,
  REGISTER_COUNT_INT,
  REGISTER_COUNT_FLT,
  RANDOMX_DATASET_ITEM_MASK,
  RANDOMX_CACHE_ITEM_COUNT
};
