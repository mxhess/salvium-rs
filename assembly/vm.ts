/**
 * RandomX Virtual Machine - AssemblyScript Implementation
 *
 * Full mode support with pre-computed dataset lookups.
 * Native u64/f64 operations for maximum performance.
 *
 * Reference: RandomX specification and reference implementation
 */

import { blake2b } from './blake2b';

// ============================================================================
// Constants
// ============================================================================

// Program parameters
const RANDOMX_PROGRAM_SIZE: u32 = 256;        // Instructions per program
const RANDOMX_PROGRAM_ITERATIONS: u32 = 2048; // Iterations per hash
const RANDOMX_PROGRAM_COUNT: u32 = 8;         // Programs per hash

// Scratchpad sizes
const RANDOMX_SCRATCHPAD_L3: u32 = 2097152;   // 2MB
const RANDOMX_SCRATCHPAD_L2: u32 = 262144;    // 256KB
const RANDOMX_SCRATCHPAD_L1: u32 = 16384;     // 16KB

// Scratchpad masks
const RANDOMX_SCRATCHPAD_L3_MASK: u64 = 2097152 - 64;  // 2MB - 64
const RANDOMX_SCRATCHPAD_L2_MASK: u64 = 262144 - 64;   // 256KB - 64
const RANDOMX_SCRATCHPAD_L1_MASK: u64 = 16384 - 64;    // 16KB - 64

// Dataset parameters
const RANDOMX_DATASET_ITEM_SIZE: u32 = 64;    // 64 bytes per item
const RANDOMX_DATASET_ITEM_COUNT: u64 = 34078719;  // Items in full dataset
const CACHE_LINE_ALIGN_MASK: u64 = ~63;

// For testing with small dataset
let datasetItemCount: u64 = 1024;  // Default to small dataset

// Register counts
const REGISTERS_COUNT: u32 = 8;
const REGISTERS_COUNT_FLT: u32 = 4;

// Instruction opcodes (simplified set)
const OP_IADD_RS: u8 = 0;
const OP_IADD_M: u8 = 1;
const OP_ISUB_R: u8 = 2;
const OP_ISUB_M: u8 = 3;
const OP_IMUL_R: u8 = 4;
const OP_IMUL_M: u8 = 5;
const OP_IMULH_R: u8 = 6;
const OP_IMULH_M: u8 = 7;
const OP_ISMULH_R: u8 = 8;
const OP_ISMULH_M: u8 = 9;
const OP_IMUL_RCP: u8 = 10;
const OP_INEG_R: u8 = 11;
const OP_IXOR_R: u8 = 12;
const OP_IXOR_M: u8 = 13;
const OP_IROR_R: u8 = 14;
const OP_IROL_R: u8 = 15;
const OP_ISWAP_R: u8 = 16;
const OP_FSWAP_R: u8 = 17;
const OP_FADD_R: u8 = 18;
const OP_FADD_M: u8 = 19;
const OP_FSUB_R: u8 = 20;
const OP_FSUB_M: u8 = 21;
const OP_FSCAL_R: u8 = 22;
const OP_FMUL_R: u8 = 23;
const OP_FDIV_M: u8 = 24;
const OP_FSQRT_R: u8 = 25;
const OP_CBRANCH: u8 = 26;
const OP_CFROUND: u8 = 27;
const OP_ISTORE: u8 = 28;
const OP_NOP: u8 = 29;

// ============================================================================
// VM State
// ============================================================================

// Integer registers r0-r7
let r0: u64 = 0;
let r1: u64 = 0;
let r2: u64 = 0;
let r3: u64 = 0;
let r4: u64 = 0;
let r5: u64 = 0;
let r6: u64 = 0;
let r7: u64 = 0;

// Floating-point registers f0-f3 (low, high pairs)
let f0_lo: f64 = 0.0;
let f0_hi: f64 = 0.0;
let f1_lo: f64 = 0.0;
let f1_hi: f64 = 0.0;
let f2_lo: f64 = 0.0;
let f2_hi: f64 = 0.0;
let f3_lo: f64 = 0.0;
let f3_hi: f64 = 0.0;

// Floating-point registers e0-e3 (low, high pairs)
let e0_lo: f64 = 0.0;
let e0_hi: f64 = 0.0;
let e1_lo: f64 = 0.0;
let e1_hi: f64 = 0.0;
let e2_lo: f64 = 0.0;
let e2_hi: f64 = 0.0;
let e3_lo: f64 = 0.0;
let e3_hi: f64 = 0.0;

// Floating-point registers a0-a3 (low, high pairs) - read-only during execution
let a0_lo: f64 = 0.0;
let a0_hi: f64 = 0.0;
let a1_lo: f64 = 0.0;
let a1_hi: f64 = 0.0;
let a2_lo: f64 = 0.0;
let a2_hi: f64 = 0.0;
let a3_lo: f64 = 0.0;
let a3_hi: f64 = 0.0;

// Memory addresses
let ma: u64 = 0;
let mx: u64 = 0;

// Address register configuration
let readReg0: u8 = 0;
let readReg1: u8 = 2;
let readReg2: u8 = 4;
let readReg3: u8 = 6;

// Dataset offset
let datasetOffset: u64 = 0;

// E-mask for float operations
let eMask0: u64 = 0;
let eMask1: u64 = 0;

// Memory pointers
let scratchpadPtr: usize = 0;
let datasetPtr: usize = 0;
let programPtr: usize = 0;

// Mode flag: 0 = light (use superscalar), 1 = full (use dataset)
let fullMode: u8 = 0;

// ============================================================================
// Register Access
// ============================================================================

@inline
function getR(idx: u8): u64 {
  switch (idx & 7) {
    case 0: return r0;
    case 1: return r1;
    case 2: return r2;
    case 3: return r3;
    case 4: return r4;
    case 5: return r5;
    case 6: return r6;
    case 7: return r7;
    default: return 0;
  }
}

@inline
function setR(idx: u8, val: u64): void {
  switch (idx & 7) {
    case 0: r0 = val; break;
    case 1: r1 = val; break;
    case 2: r2 = val; break;
    case 3: r3 = val; break;
    case 4: r4 = val; break;
    case 5: r5 = val; break;
    case 6: r6 = val; break;
    case 7: r7 = val; break;
  }
}

// ============================================================================
// Memory Operations
// ============================================================================

@inline
function readU64(ptr: usize, offset: u32): u64 {
  return load<u64>(ptr + offset);
}

@inline
function writeU64(ptr: usize, offset: u32, val: u64): void {
  store<u64>(ptr + offset, val);
}

@inline
function readF64(ptr: usize, offset: u32): f64 {
  return load<f64>(ptr + offset);
}

@inline
function writeF64(ptr: usize, offset: u32, val: f64): void {
  store<f64>(ptr + offset, val);
}

// ============================================================================
// Bit Operations
// ============================================================================

@inline
function rotr64(x: u64, n: u32): u64 {
  return (x >> n) | (x << (64 - n));
}

@inline
function rotl64(x: u64, n: u32): u64 {
  return (x << n) | (x >> (64 - n));
}

// Unsigned 64x64 -> high 64 bits
@inline
function mulhU64(a: u64, b: u64): u64 {
  const aLo: u64 = a & 0xFFFFFFFF;
  const aHi: u64 = a >> 32;
  const bLo: u64 = b & 0xFFFFFFFF;
  const bHi: u64 = b >> 32;

  const mid1: u64 = aHi * bLo;
  const mid2: u64 = aLo * bHi;
  const lo: u64 = aLo * bLo;
  const hi: u64 = aHi * bHi;

  const carry: u64 = ((lo >> 32) + (mid1 & 0xFFFFFFFF) + (mid2 & 0xFFFFFFFF)) >> 32;
  return hi + (mid1 >> 32) + (mid2 >> 32) + carry;
}

// Signed 64x64 -> high 64 bits
@inline
function mulhS64(a: u64, b: u64): u64 {
  const negate: bool = ((a ^ b) >> 63) != 0;
  if (<i64>a < 0) a = ~a + 1;
  if (<i64>b < 0) b = ~b + 1;
  let result = mulhU64(a, b);
  if (negate) result = ~result + (((a * b) == 0) ? 1 : 0);
  return result;
}

// Reciprocal for IMUL_RCP
@inline
function reciprocal(divisor: u64): u64 {
  if (divisor == 0) return 0;
  const p2exp63: u64 = 1 << 63;
  let quotient: u64 = p2exp63 / divisor;
  let remainder: u64 = p2exp63 % divisor;

  let shift: u32 = 0;
  while (remainder < divisor && shift < 63) {
    remainder <<= 1;
    quotient <<= 1;
    shift++;
    if (remainder >= divisor) {
      quotient++;
      remainder -= divisor;
    }
  }
  return quotient;
}

// ============================================================================
// Float Conversion
// ============================================================================

@inline
function u64ToF64(x: u64): f64 {
  return reinterpret<f64>(x);
}

@inline
function f64ToU64(x: f64): u64 {
  return reinterpret<u64>(x);
}

// Convert integer to small positive float (used for 'a' registers)
@inline
function getSmallPositiveFloat(x: u64): f64 {
  const exponent: u64 = ((x >> 59) & 0xF) + 0x3F8; // Exponent 0x3F8-0x407
  const mantissa: u64 = x & 0x7FFFFFFFFFFFF;       // 51 bits of mantissa
  return u64ToF64((exponent << 52) | mantissa);
}

// Mask float mantissa for E registers
@inline
function maskRegisterExponent(x: f64, mask: u64): f64 {
  const bits = f64ToU64(x);
  const masked = (bits & 0x807FFFFFFFFFFFFF) | mask;
  return u64ToF64(masked);
}

// ============================================================================
// Scratchpad Access
// ============================================================================

@inline
function spLoad64(addr: u32): u64 {
  return readU64(scratchpadPtr, addr & <u32>RANDOMX_SCRATCHPAD_L3_MASK);
}

@inline
function spStore64(addr: u32, val: u64): void {
  writeU64(scratchpadPtr, addr & <u32>RANDOMX_SCRATCHPAD_L3_MASK, val);
}

@inline
function spLoadF64(addr: u32): f64 {
  return readF64(scratchpadPtr, addr & <u32>RANDOMX_SCRATCHPAD_L3_MASK);
}

// ============================================================================
// Dataset Access (Full Mode)
// ============================================================================

/**
 * Read dataset item (64 bytes = 8 x u64)
 * In full mode, reads from pre-computed dataset
 * In light mode, would compute via superscalar (not implemented here)
 */
function readDatasetItem(itemIndex: u64): void {
  if (fullMode == 1) {
    // Mask index to stay within dataset bounds
    const maskedIndex: u64 = itemIndex % datasetItemCount;
    const offset: u32 = <u32>(maskedIndex * 64);

    r0 ^= readU64(datasetPtr, offset);
    r1 ^= readU64(datasetPtr, offset + 8);
    r2 ^= readU64(datasetPtr, offset + 16);
    r3 ^= readU64(datasetPtr, offset + 24);
    r4 ^= readU64(datasetPtr, offset + 32);
    r5 ^= readU64(datasetPtr, offset + 40);
    r6 ^= readU64(datasetPtr, offset + 48);
    r7 ^= readU64(datasetPtr, offset + 56);
  }
  // Light mode would call superscalar here
}

// ============================================================================
// Instruction Execution
// ============================================================================

/**
 * Execute a single instruction
 * Instruction format: opcode (1), dst (1), src (1), mod (1), imm32 (4)
 */
function executeInstruction(instrPtr: usize): void {
  const opcode: u8 = load<u8>(instrPtr);
  const dst: u8 = load<u8>(instrPtr + 1) & 7;
  const src: u8 = load<u8>(instrPtr + 2) & 7;
  const mod: u8 = load<u8>(instrPtr + 3);
  const imm32: u32 = load<u32>(instrPtr + 4);
  const imm64: u64 = <u64><i64><i32>imm32; // Sign-extend

  switch (opcode) {
    case OP_IADD_RS: {
      const shift: u8 = (mod >> 2) & 3;
      setR(dst, getR(dst) + (getR(src) << shift) + imm64);
      break;
    }
    case OP_IADD_M: {
      const addr: u32 = <u32>(getR(src) + imm64);
      setR(dst, getR(dst) + spLoad64(addr));
      break;
    }
    case OP_ISUB_R: {
      setR(dst, getR(dst) - getR(src));
      break;
    }
    case OP_ISUB_M: {
      const addr: u32 = <u32>(getR(src) + imm64);
      setR(dst, getR(dst) - spLoad64(addr));
      break;
    }
    case OP_IMUL_R: {
      setR(dst, getR(dst) * getR(src));
      break;
    }
    case OP_IMUL_M: {
      const addr: u32 = <u32>(getR(src) + imm64);
      setR(dst, getR(dst) * spLoad64(addr));
      break;
    }
    case OP_IMULH_R: {
      setR(dst, mulhU64(getR(dst), getR(src)));
      break;
    }
    case OP_IMULH_M: {
      const addr: u32 = <u32>(getR(src) + imm64);
      setR(dst, mulhU64(getR(dst), spLoad64(addr)));
      break;
    }
    case OP_ISMULH_R: {
      setR(dst, mulhS64(getR(dst), getR(src)));
      break;
    }
    case OP_ISMULH_M: {
      const addr: u32 = <u32>(getR(src) + imm64);
      setR(dst, mulhS64(getR(dst), spLoad64(addr)));
      break;
    }
    case OP_IMUL_RCP: {
      if (imm32 != 0) {
        setR(dst, getR(dst) * reciprocal(<u64>imm32));
      }
      break;
    }
    case OP_INEG_R: {
      setR(dst, ~getR(dst) + 1);
      break;
    }
    case OP_IXOR_R: {
      setR(dst, getR(dst) ^ getR(src));
      break;
    }
    case OP_IXOR_M: {
      const addr: u32 = <u32>(getR(src) + imm64);
      setR(dst, getR(dst) ^ spLoad64(addr));
      break;
    }
    case OP_IROR_R: {
      const shift: u8 = <u8>(getR(src) & 63);
      setR(dst, rotr64(getR(dst), shift));
      break;
    }
    case OP_IROL_R: {
      const shift: u8 = <u8>(getR(src) & 63);
      setR(dst, rotl64(getR(dst), shift));
      break;
    }
    case OP_ISWAP_R: {
      if (dst != src) {
        const tmp = getR(dst);
        setR(dst, getR(src));
        setR(src, tmp);
      }
      break;
    }
    case OP_ISTORE: {
      const addr: u32 = <u32>(getR(dst) + imm64);
      spStore64(addr, getR(src));
      break;
    }
    case OP_NOP:
    default:
      break;
  }
}

// ============================================================================
// Program Execution
// ============================================================================

/**
 * Execute one iteration of the program
 */
function executeIteration(): void {
  // Calculate scratchpad addresses
  const spMix: u64 = getR(readReg0) ^ getR(readReg1);
  const spAddr0: u32 = <u32>(mx ^ spMix) & <u32>RANDOMX_SCRATCHPAD_L3_MASK;
  const spAddr1: u32 = <u32>(ma ^ (spMix >> 32)) & <u32>RANDOMX_SCRATCHPAD_L3_MASK;

  // Read from scratchpad into integer registers
  r0 ^= spLoad64(spAddr0);
  r1 ^= spLoad64(spAddr0 + 8);
  r2 ^= spLoad64(spAddr0 + 16);
  r3 ^= spLoad64(spAddr0 + 24);
  r4 ^= spLoad64(spAddr0 + 32);
  r5 ^= spLoad64(spAddr0 + 40);
  r6 ^= spLoad64(spAddr0 + 48);
  r7 ^= spLoad64(spAddr0 + 56);

  // Read into float registers (simplified)
  f0_lo = spLoadF64(spAddr1);
  f0_hi = spLoadF64(spAddr1 + 8);
  f1_lo = spLoadF64(spAddr1 + 16);
  f1_hi = spLoadF64(spAddr1 + 24);
  f2_lo = spLoadF64(spAddr1 + 32);
  f2_hi = spLoadF64(spAddr1 + 40);
  f3_lo = spLoadF64(spAddr1 + 48);
  f3_hi = spLoadF64(spAddr1 + 56);

  // Execute all instructions
  for (let i: u32 = 0; i < RANDOMX_PROGRAM_SIZE; i++) {
    executeInstruction(programPtr + i * 8);
  }

  // Update memory addresses
  mx ^= getR(readReg2) ^ getR(readReg3);
  mx &= CACHE_LINE_ALIGN_MASK;

  // Dataset read
  const datasetIndex: u64 = (ma + datasetOffset) / 64;
  readDatasetItem(datasetIndex);

  // Swap mx and ma
  const tmp: u64 = mx;
  mx = ma;
  ma = tmp;

  // Write to scratchpad
  spStore64(spAddr1, r0);
  spStore64(spAddr1 + 8, r1);
  spStore64(spAddr1 + 16, r2);
  spStore64(spAddr1 + 24, r3);
  spStore64(spAddr1 + 32, r4);
  spStore64(spAddr1 + 40, r5);
  spStore64(spAddr1 + 48, r6);
  spStore64(spAddr1 + 56, r7);
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Initialize VM with memory pointers
 */
export function vm_init(
  scratchpad: usize,
  dataset: usize,
  program: usize,
  mode: u8
): void {
  scratchpadPtr = scratchpad;
  datasetPtr = dataset;
  programPtr = program;
  fullMode = mode;
}

/**
 * Set dataset item count (for bounds checking)
 */
export function vm_set_dataset_size(count: u64): void {
  datasetItemCount = count > 0 ? count : 1;
}

/**
 * Reset VM state for new hash
 */
export function vm_reset(): void {
  r0 = 0; r1 = 0; r2 = 0; r3 = 0;
  r4 = 0; r5 = 0; r6 = 0; r7 = 0;

  f0_lo = 0.0; f0_hi = 0.0;
  f1_lo = 0.0; f1_hi = 0.0;
  f2_lo = 0.0; f2_hi = 0.0;
  f3_lo = 0.0; f3_hi = 0.0;

  e0_lo = 0.0; e0_hi = 0.0;
  e1_lo = 0.0; e1_hi = 0.0;
  e2_lo = 0.0; e2_hi = 0.0;
  e3_lo = 0.0; e3_hi = 0.0;

  ma = 0;
  mx = 0;
}

/**
 * Set configuration from program entropy
 */
export function vm_set_config(
  maVal: u64,
  mxVal: u64,
  reg0: u8, reg1: u8, reg2: u8, reg3: u8,
  offset: u64,
  mask0: u64, mask1: u64
): void {
  ma = maVal & CACHE_LINE_ALIGN_MASK;
  mx = mxVal;
  readReg0 = reg0 & 7;
  readReg1 = reg1 & 7;
  readReg2 = reg2 & 7;
  readReg3 = reg3 & 7;
  datasetOffset = offset;
  eMask0 = mask0;
  eMask1 = mask1;
}

/**
 * Set 'a' registers (read-only during execution)
 */
export function vm_set_a_registers(
  a0l: f64, a0h: f64,
  a1l: f64, a1h: f64,
  a2l: f64, a2h: f64,
  a3l: f64, a3h: f64
): void {
  a0_lo = a0l; a0_hi = a0h;
  a1_lo = a1l; a1_hi = a1h;
  a2_lo = a2l; a2_hi = a2h;
  a3_lo = a3l; a3_hi = a3h;
}

/**
 * Execute the full program (all iterations)
 */
export function vm_execute(): void {
  for (let i: u32 = 0; i < RANDOMX_PROGRAM_ITERATIONS; i++) {
    executeIteration();
  }
}

/**
 * Get register file as bytes (for final hash)
 * Returns pointer to 256-byte buffer with all register values
 */
export function vm_get_register_file(outputPtr: usize): void {
  // Integer registers (64 bytes)
  writeU64(outputPtr, 0, r0);
  writeU64(outputPtr, 8, r1);
  writeU64(outputPtr, 16, r2);
  writeU64(outputPtr, 24, r3);
  writeU64(outputPtr, 32, r4);
  writeU64(outputPtr, 40, r5);
  writeU64(outputPtr, 48, r6);
  writeU64(outputPtr, 56, r7);

  // Float registers f (64 bytes)
  writeF64(outputPtr, 64, f0_lo);
  writeF64(outputPtr, 72, f0_hi);
  writeF64(outputPtr, 80, f1_lo);
  writeF64(outputPtr, 88, f1_hi);
  writeF64(outputPtr, 96, f2_lo);
  writeF64(outputPtr, 104, f2_hi);
  writeF64(outputPtr, 112, f3_lo);
  writeF64(outputPtr, 120, f3_hi);

  // Float registers e (64 bytes)
  writeF64(outputPtr, 128, e0_lo);
  writeF64(outputPtr, 136, e0_hi);
  writeF64(outputPtr, 144, e1_lo);
  writeF64(outputPtr, 152, e1_hi);
  writeF64(outputPtr, 160, e2_lo);
  writeF64(outputPtr, 168, e2_hi);
  writeF64(outputPtr, 176, e3_lo);
  writeF64(outputPtr, 184, e3_hi);

  // Float registers a (64 bytes)
  writeF64(outputPtr, 192, a0_lo);
  writeF64(outputPtr, 200, a0_hi);
  writeF64(outputPtr, 208, a1_lo);
  writeF64(outputPtr, 216, a1_hi);
  writeF64(outputPtr, 224, a2_lo);
  writeF64(outputPtr, 232, a2_hi);
  writeF64(outputPtr, 240, a3_lo);
  writeF64(outputPtr, 248, a3_hi);
}

/**
 * Set integer register directly (for initialization)
 */
export function vm_set_r(idx: u8, val: u64): void {
  setR(idx, val);
}

/**
 * Get integer register value
 */
export function vm_get_r(idx: u8): u64 {
  return getR(idx);
}
