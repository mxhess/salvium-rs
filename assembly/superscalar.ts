/**
 * SuperscalarHash WASM Implementation
 *
 * Native u64 implementation for dataset item generation.
 * This is the hot path for full mode dataset generation.
 *
 * Uses WASM SIMD (v128) for optimized cache block operations.
 * SIMD support: Chrome 91+, Firefox 89+, Safari 16.4+, Node 16.4+
 */

// Superscalar instruction opcodes
const ISUB_R: u8 = 0;
const IXOR_R: u8 = 1;
const IADD_RS: u8 = 2;
const IMUL_R: u8 = 3;
const IROR_C: u8 = 4;
const IADD_C7: u8 = 5;
const IXOR_C7: u8 = 6;
const IADD_C8: u8 = 7;
const IXOR_C8: u8 = 8;
const IADD_C9: u8 = 9;
const IXOR_C9: u8 = 10;
const IMULH_R: u8 = 11;
const ISMULH_R: u8 = 12;
const IMUL_RCP: u8 = 13;

// Constants for register initialization
const SUPERSCALAR_MUL0: u64 = 6364136223846793005;
const SUPERSCALAR_ADD1: u64 = 9298411001130361340;
const SUPERSCALAR_ADD2: u64 = 12065312585734608966;
const SUPERSCALAR_ADD3: u64 = 9306329213124626780;
const SUPERSCALAR_ADD4: u64 = 5281919268842080866;
const SUPERSCALAR_ADD5: u64 = 10536153434571861004;
const SUPERSCALAR_ADD6: u64 = 3398623926847679864;
const SUPERSCALAR_ADD7: u64 = 9549104520008361294;

// Cache parameters
const CACHE_LINE_SIZE: u32 = 64;

// Working registers (8 x u64)
let r0: u64 = 0;
let r1: u64 = 0;
let r2: u64 = 0;
let r3: u64 = 0;
let r4: u64 = 0;
let r5: u64 = 0;
let r6: u64 = 0;
let r7: u64 = 0;

// Superscalar state
let cachePtr: usize = 0;
let cacheLineCount: u32 = 0;

/**
 * Initialize superscalar module with cache pointer
 */
export function superscalar_init(ptr: usize, lineCount: u32): void {
  cachePtr = ptr;
  cacheLineCount = lineCount;
}

/**
 * Get register value
 */
@inline
function getReg(idx: u8): u64 {
  switch (idx) {
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

/**
 * Set register value
 */
@inline
function setReg(idx: u8, val: u64): void {
  switch (idx) {
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

/**
 * 64-bit rotate right
 */
@inline
function rotr64(x: u64, n: u32): u64 {
  return (x >> n) | (x << (64 - n));
}

/**
 * Sign extend 32-bit to 64-bit
 */
@inline
function signExtend(x: u32): u64 {
  return <u64><i64><i32>x;
}

/**
 * Unsigned 64x64 -> high 64 bits
 */
@inline
function mulh(a: u64, b: u64): u64 {
  // Split into 32-bit parts
  const a_lo: u64 = a & 0xFFFFFFFF;
  const a_hi: u64 = a >> 32;
  const b_lo: u64 = b & 0xFFFFFFFF;
  const b_hi: u64 = b >> 32;

  // Partial products
  const p0: u64 = a_lo * b_lo;
  const p1: u64 = a_lo * b_hi;
  const p2: u64 = a_hi * b_lo;
  const p3: u64 = a_hi * b_hi;

  // Sum with carry
  const carry: u64 = ((p0 >> 32) + (p1 & 0xFFFFFFFF) + (p2 & 0xFFFFFFFF)) >> 32;
  return p3 + (p1 >> 32) + (p2 >> 32) + carry;
}

/**
 * Signed 64x64 -> high 64 bits
 */
@inline
function smulh(a: u64, b: u64): u64 {
  const sa: i64 = <i64>a;
  const sb: i64 = <i64>b;

  // Use unsigned mulh and adjust for signs
  const unsignedResult = mulh(a, b);

  // Adjustment for negative numbers
  let result = unsignedResult;
  if (sa < 0) result -= b;
  if (sb < 0) result -= a;

  return result;
}

/**
 * Calculate reciprocal for division
 */
export function reciprocal(divisor: u32): u64 {
  if (divisor == 0) return 0;

  const d: u64 = <u64>divisor;
  const p2exp63: u64 = 1 << 63;
  const q: u64 = p2exp63 / d;
  const r: u64 = p2exp63 % d;

  // Find highest bit position
  let shift: u32 = 32;
  let k: u32 = 1 << 31;
  while ((k & divisor) == 0) {
    k >>= 1;
    shift--;
  }

  return (q << shift) + ((r << shift) / d);
}

/**
 * Initialize registers for dataset item
 */
export function init_registers(itemNumber: u64): void {
  r0 = (itemNumber + 1) * SUPERSCALAR_MUL0;
  r1 = r0 ^ SUPERSCALAR_ADD1;
  r2 = r0 ^ SUPERSCALAR_ADD2;
  r3 = r0 ^ SUPERSCALAR_ADD3;
  r4 = r0 ^ SUPERSCALAR_ADD4;
  r5 = r0 ^ SUPERSCALAR_ADD5;
  r6 = r0 ^ SUPERSCALAR_ADD6;
  r7 = r0 ^ SUPERSCALAR_ADD7;
}

/**
 * Execute a single superscalar instruction
 * Instruction format: [opcode:8, dst:8, src:8, mod:8, imm32:32]
 */
export function exec_instruction(opcode: u8, dst: u8, src: u8, mod: u8, imm32: u32): void {
  switch (opcode) {
    case ISUB_R:
      setReg(dst, getReg(dst) - getReg(src));
      break;

    case IXOR_R:
      setReg(dst, getReg(dst) ^ getReg(src));
      break;

    case IADD_RS: {
      const shift = (mod >> 2) & 3;
      setReg(dst, getReg(dst) + (getReg(src) << shift));
      break;
    }

    case IMUL_R:
      setReg(dst, getReg(dst) * getReg(src));
      break;

    case IROR_C:
      setReg(dst, rotr64(getReg(dst), imm32 & 63));
      break;

    case IADD_C7:
    case IADD_C8:
    case IADD_C9:
      setReg(dst, getReg(dst) + signExtend(imm32));
      break;

    case IXOR_C7:
    case IXOR_C8:
    case IXOR_C9:
      setReg(dst, getReg(dst) ^ signExtend(imm32));
      break;

    case IMULH_R:
      setReg(dst, mulh(getReg(dst), getReg(src)));
      break;

    case ISMULH_R:
      setReg(dst, smulh(getReg(dst), getReg(src)));
      break;

    case IMUL_RCP:
      // imm32 is actually the pre-computed reciprocal index or value
      // For WASM, we receive the pre-computed reciprocal directly
      setReg(dst, getReg(dst) * <u64>imm32);
      break;
  }
}

/**
 * Execute instruction with 64-bit immediate (for IMUL_RCP with full reciprocal)
 */
export function exec_imul_rcp(dst: u8, rcp: u64): void {
  setReg(dst, getReg(dst) * rcp);
}

// Temporary storage for mix block
let mixBlockPtr: usize = 0;

/**
 * Get cache block offset for given register value (without XORing)
 * Call this BEFORE program execution
 */
export function get_cache_block(registerValue: u64): void {
  const index: u32 = <u32>(registerValue % <u64>cacheLineCount);
  mixBlockPtr = cachePtr + <usize>index * CACHE_LINE_SIZE;
}

/**
 * XOR the previously fetched cache block into registers
 * Call this AFTER program execution
 */
export function xor_cache_block(): void {
  r0 ^= load<u64>(mixBlockPtr);
  r1 ^= load<u64>(mixBlockPtr + 8);
  r2 ^= load<u64>(mixBlockPtr + 16);
  r3 ^= load<u64>(mixBlockPtr + 24);
  r4 ^= load<u64>(mixBlockPtr + 32);
  r5 ^= load<u64>(mixBlockPtr + 40);
  r6 ^= load<u64>(mixBlockPtr + 48);
  r7 ^= load<u64>(mixBlockPtr + 56);
}

/**
 * Combined: get and XOR cache block (for simple cases)
 * @param registerValue - Value to compute cache index from
 */
export function mix_cache_block(registerValue: u64): void {
  get_cache_block(registerValue);
  xor_cache_block();
}

/**
 * Get address register value for cache lookup
 */
export function get_address_reg(regIdx: u8): u64 {
  return getReg(regIdx);
}

/**
 * Write registers to output buffer (64 bytes)
 */
export function write_registers(outPtr: usize): void {
  store<u64>(outPtr, r0);
  store<u64>(outPtr + 8, r1);
  store<u64>(outPtr + 16, r2);
  store<u64>(outPtr + 24, r3);
  store<u64>(outPtr + 32, r4);
  store<u64>(outPtr + 40, r5);
  store<u64>(outPtr + 48, r6);
  store<u64>(outPtr + 56, r7);
}

/**
 * Read registers from buffer (for testing/debugging)
 */
export function read_registers(inPtr: usize): void {
  r0 = load<u64>(inPtr);
  r1 = load<u64>(inPtr + 8);
  r2 = load<u64>(inPtr + 16);
  r3 = load<u64>(inPtr + 24);
  r4 = load<u64>(inPtr + 32);
  r5 = load<u64>(inPtr + 40);
  r6 = load<u64>(inPtr + 48);
  r7 = load<u64>(inPtr + 56);
}

/**
 * Get a single register value (for JS interop)
 */
export function get_reg(idx: u8): u64 {
  return getReg(idx);
}

/**
 * Set a single register value (for JS interop)
 */
export function set_reg(idx: u8, val: u64): void {
  setReg(idx, val);
}

// ============================================================================
// Optimized batch execution
// ============================================================================

// Program storage (up to 8 programs, each up to 512 instructions)
// Format: [count:u32, instructions...]
// Instruction: [opcode:u8, dst:u8, src:u8, mod:u8, imm32/rcp_index:u32]
const MAX_PROGRAMS: u32 = 8;
const MAX_INSTRUCTIONS: u32 = 512;
const INSTR_SIZE: u32 = 8; // bytes per instruction

let programsPtr: usize = 0;
let programOffsets: StaticArray<u32> = new StaticArray<u32>(9); // start offset for each program + end
let programAddressRegs: StaticArray<u8> = new StaticArray<u8>(8);
let reciprocalsPtr: usize = 0;
let reciprocalCount: u32 = 0;

/**
 * Set up program storage area
 */
export function setup_programs(ptr: usize, rcpPtr: usize, rcpCount: u32): void {
  programsPtr = ptr;
  reciprocalsPtr = rcpPtr;
  reciprocalCount = rcpCount;
}

/**
 * Set program metadata
 */
export function set_program_meta(progIdx: u8, offset: u32, instrCount: u32, addressReg: u8): void {
  unchecked(programOffsets[progIdx] = offset);
  unchecked(programOffsets[progIdx + 1] = offset + instrCount * INSTR_SIZE);
  unchecked(programAddressRegs[progIdx] = addressReg);
}

/**
 * Execute a single program from memory
 */
function executeProgram(progIdx: u8): void {
  const startOffset = unchecked(programOffsets[progIdx]);
  const endOffset = unchecked(programOffsets[progIdx + 1]);

  for (let offset = startOffset; offset < endOffset; offset += INSTR_SIZE) {
    const ptr = programsPtr + offset;
    const opcode = load<u8>(ptr);
    const dst = load<u8>(ptr + 1);
    const src = load<u8>(ptr + 2);
    const mod = load<u8>(ptr + 3);
    const imm32 = load<u32>(ptr + 4);

    switch (opcode) {
      case ISUB_R:
        setReg(dst, getReg(dst) - getReg(src));
        break;

      case IXOR_R:
        setReg(dst, getReg(dst) ^ getReg(src));
        break;

      case IADD_RS: {
        const shift = (mod >> 2) & 3;
        setReg(dst, getReg(dst) + (getReg(src) << shift));
        break;
      }

      case IMUL_R:
        setReg(dst, getReg(dst) * getReg(src));
        break;

      case IROR_C:
        setReg(dst, rotr64(getReg(dst), imm32 & 63));
        break;

      case IADD_C7:
      case IADD_C8:
      case IADD_C9:
        setReg(dst, getReg(dst) + signExtend(imm32));
        break;

      case IXOR_C7:
      case IXOR_C8:
      case IXOR_C9:
        setReg(dst, getReg(dst) ^ signExtend(imm32));
        break;

      case IMULH_R:
        setReg(dst, mulh(getReg(dst), getReg(src)));
        break;

      case ISMULH_R:
        setReg(dst, smulh(getReg(dst), getReg(src)));
        break;

      case IMUL_RCP: {
        // imm32 is index into reciprocals array
        const rcp = load<u64>(reciprocalsPtr + <usize>imm32 * 8);
        setReg(dst, getReg(dst) * rcp);
        break;
      }
    }
  }
}

/**
 * Generate a complete dataset item in a single WASM call
 * This is much faster than calling individual functions from JS
 */
export function init_dataset_item(itemNumber: u64, numPrograms: u8): void {
  // Initialize registers
  r0 = (itemNumber + 1) * SUPERSCALAR_MUL0;
  r1 = r0 ^ SUPERSCALAR_ADD1;
  r2 = r0 ^ SUPERSCALAR_ADD2;
  r3 = r0 ^ SUPERSCALAR_ADD3;
  r4 = r0 ^ SUPERSCALAR_ADD4;
  r5 = r0 ^ SUPERSCALAR_ADD5;
  r6 = r0 ^ SUPERSCALAR_ADD6;
  r7 = r0 ^ SUPERSCALAR_ADD7;

  let registerValue = itemNumber;

  for (let i: u8 = 0; i < numPrograms; i++) {
    // 1. Get cache block
    const index: u32 = <u32>(registerValue % <u64>cacheLineCount);
    mixBlockPtr = cachePtr + <usize>index * CACHE_LINE_SIZE;

    // 2. Execute program
    executeProgram(i);

    // 3. XOR cache block into registers
    r0 ^= load<u64>(mixBlockPtr);
    r1 ^= load<u64>(mixBlockPtr + 8);
    r2 ^= load<u64>(mixBlockPtr + 16);
    r3 ^= load<u64>(mixBlockPtr + 24);
    r4 ^= load<u64>(mixBlockPtr + 32);
    r5 ^= load<u64>(mixBlockPtr + 40);
    r6 ^= load<u64>(mixBlockPtr + 48);
    r7 ^= load<u64>(mixBlockPtr + 56);

    // 4. Update registerValue
    registerValue = getReg(unchecked(programAddressRegs[i]));
  }
}

/**
 * Generate MULTIPLE dataset items in a single WASM call
 * This minimizes JS/WASM boundary crossing overhead
 *
 * @param startItem - First item number to generate
 * @param count - Number of items to generate
 * @param outPtr - Output pointer (must have count * 64 bytes available)
 * @param numPrograms - Number of programs (typically 8)
 */
export function init_dataset_batch(startItem: u64, count: u32, outPtr: usize, numPrograms: u8): void {
  for (let item: u32 = 0; item < count; item++) {
    const itemNumber = startItem + <u64>item;

    // Initialize registers
    r0 = (itemNumber + 1) * SUPERSCALAR_MUL0;
    r1 = r0 ^ SUPERSCALAR_ADD1;
    r2 = r0 ^ SUPERSCALAR_ADD2;
    r3 = r0 ^ SUPERSCALAR_ADD3;
    r4 = r0 ^ SUPERSCALAR_ADD4;
    r5 = r0 ^ SUPERSCALAR_ADD5;
    r6 = r0 ^ SUPERSCALAR_ADD6;
    r7 = r0 ^ SUPERSCALAR_ADD7;

    let registerValue = itemNumber;

    for (let i: u8 = 0; i < numPrograms; i++) {
      // 1. Get cache block
      const index: u32 = <u32>(registerValue % <u64>cacheLineCount);
      const blockPtr = cachePtr + <usize>index * CACHE_LINE_SIZE;

      // 2. Execute program
      executeProgram(i);

      // 3. XOR cache block into registers
      r0 ^= load<u64>(blockPtr);
      r1 ^= load<u64>(blockPtr + 8);
      r2 ^= load<u64>(blockPtr + 16);
      r3 ^= load<u64>(blockPtr + 24);
      r4 ^= load<u64>(blockPtr + 32);
      r5 ^= load<u64>(blockPtr + 40);
      r6 ^= load<u64>(blockPtr + 48);
      r7 ^= load<u64>(blockPtr + 56);

      // 4. Update registerValue
      registerValue = getReg(unchecked(programAddressRegs[i]));
    }

    // Write output directly to buffer using SIMD (2x u64 per store)
    const itemOut = outPtr + <usize>item * 64;
    v128.store(itemOut, i64x2.replace_lane(i64x2.splat(r0), 1, r1));
    v128.store(itemOut + 16, i64x2.replace_lane(i64x2.splat(r2), 1, r3));
    v128.store(itemOut + 32, i64x2.replace_lane(i64x2.splat(r4), 1, r5));
    v128.store(itemOut + 48, i64x2.replace_lane(i64x2.splat(r6), 1, r7));
  }
}

/**
 * SIMD-optimized batch generation
 * Uses v128 for cache block XOR and output writes
 */
export function init_dataset_batch_simd(startItem: u64, count: u32, outPtr: usize, numPrograms: u8): void {
  for (let item: u32 = 0; item < count; item++) {
    const itemNumber = startItem + <u64>item;

    // Initialize registers
    r0 = (itemNumber + 1) * SUPERSCALAR_MUL0;
    r1 = r0 ^ SUPERSCALAR_ADD1;
    r2 = r0 ^ SUPERSCALAR_ADD2;
    r3 = r0 ^ SUPERSCALAR_ADD3;
    r4 = r0 ^ SUPERSCALAR_ADD4;
    r5 = r0 ^ SUPERSCALAR_ADD5;
    r6 = r0 ^ SUPERSCALAR_ADD6;
    r7 = r0 ^ SUPERSCALAR_ADD7;

    let registerValue = itemNumber;

    for (let i: u8 = 0; i < numPrograms; i++) {
      // 1. Get cache block pointer
      const index: u32 = <u32>(registerValue % <u64>cacheLineCount);
      const blockPtr = cachePtr + <usize>index * CACHE_LINE_SIZE;

      // 2. Execute program (scalar - instructions operate on individual registers)
      executeProgram(i);

      // 3. XOR cache block into registers using SIMD loads
      // Load 128 bits (2 x u64) at a time, then extract and XOR
      const v0 = v128.load(blockPtr);
      const v1 = v128.load(blockPtr + 16);
      const v2 = v128.load(blockPtr + 32);
      const v3 = v128.load(blockPtr + 48);

      r0 ^= i64x2.extract_lane(v0, 0);
      r1 ^= i64x2.extract_lane(v0, 1);
      r2 ^= i64x2.extract_lane(v1, 0);
      r3 ^= i64x2.extract_lane(v1, 1);
      r4 ^= i64x2.extract_lane(v2, 0);
      r5 ^= i64x2.extract_lane(v2, 1);
      r6 ^= i64x2.extract_lane(v3, 0);
      r7 ^= i64x2.extract_lane(v3, 1);

      // 4. Update registerValue
      registerValue = getReg(unchecked(programAddressRegs[i]));
    }

    // Write output using SIMD stores (4 x v128 instead of 8 x u64)
    const itemOut = outPtr + <usize>item * 64;
    v128.store(itemOut, i64x2.replace_lane(i64x2.splat(r0), 1, r1));
    v128.store(itemOut + 16, i64x2.replace_lane(i64x2.splat(r2), 1, r3));
    v128.store(itemOut + 32, i64x2.replace_lane(i64x2.splat(r4), 1, r5));
    v128.store(itemOut + 48, i64x2.replace_lane(i64x2.splat(r6), 1, r7));
  }
}
