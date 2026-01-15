/**
 * SuperscalarHash implementation for RandomX
 *
 * Used for generating dataset items from the cache.
 * Generates and executes programs on 8 registers.
 *
 * Reference: external/randomx/src/superscalar.cpp, blake2_generator.cpp
 */

import { blake2b } from '../blake2b.js';
import { RANDOMX_SUPERSCALAR_LATENCY, RANDOMX_CACHE_ACCESSES } from './config.js';

// ============================================================================
// Blake2Generator - generates pseudo-random bytes from a seed
// ============================================================================

export class Blake2Generator {
  constructor(seed, nonce = 0) {
    this.data = new Uint8Array(64);
    this.dataIndex = 64;

    // Copy seed (max 60 bytes)
    const seedBytes = typeof seed === 'string'
      ? new TextEncoder().encode(seed)
      : seed;
    const copyLen = Math.min(seedBytes.length, 60);
    this.data.set(seedBytes.subarray(0, copyLen), 0);

    // Store nonce at position 60 (32-bit LE)
    this.data[60] = nonce & 0xff;
    this.data[61] = (nonce >> 8) & 0xff;
    this.data[62] = (nonce >> 16) & 0xff;
    this.data[63] = (nonce >> 24) & 0xff;
  }

  checkData(bytesNeeded) {
    if (this.dataIndex + bytesNeeded > 64) {
      this.data = blake2b(this.data, 64);
      this.dataIndex = 0;
    }
  }

  getByte() {
    this.checkData(1);
    return this.data[this.dataIndex++];
  }

  getUInt32() {
    this.checkData(4);
    const value = this.data[this.dataIndex] |
      (this.data[this.dataIndex + 1] << 8) |
      (this.data[this.dataIndex + 2] << 16) |
      (this.data[this.dataIndex + 3] << 24);
    this.dataIndex += 4;
    return value >>> 0;  // Ensure unsigned
  }

  /**
   * Get multiple bytes at once
   * @param {number} count - Number of bytes to get
   * @returns {Uint8Array}
   */
  getBytes(count) {
    const result = new Uint8Array(count);
    for (let i = 0; i < count; i++) {
      result[i] = this.getByte();
    }
    return result;
  }
}

// ============================================================================
// Superscalar Instruction Types
// ============================================================================

export const SuperscalarInstructionType = {
  ISUB_R: 0,
  IXOR_R: 1,
  IADD_RS: 2,
  IMUL_R: 3,
  IROR_C: 4,
  IADD_C7: 5,
  IXOR_C7: 6,
  IADD_C8: 7,
  IXOR_C8: 8,
  IADD_C9: 9,
  IXOR_C9: 10,
  IMULH_R: 11,
  ISMULH_R: 12,
  IMUL_RCP: 13,
  INVALID: -1
};

// Register that needs displacement in IADD_RS (r5)
const RegisterNeedsDisplacement = 5;

// Maximum program size
const SuperscalarMaxSize = 512;

// ============================================================================
// Reciprocal calculation
// ============================================================================

/**
 * Calculate reciprocal for IMUL_RCP instruction
 * rcp = 2^x / divisor for highest x such that rcp < 2^64
 */
export function reciprocal(divisor) {
  if (divisor === 0) return 0n;

  const divisorBig = BigInt(divisor >>> 0);
  const p2exp63 = 1n << 63n;
  const q = p2exp63 / divisorBig;
  const r = p2exp63 % divisorBig;

  // Find highest bit position
  let shift = 32n;
  let k = 1n << 31n;
  while ((k & divisorBig) === 0n) {
    k >>= 1n;
    shift--;
  }

  return (q << shift) + ((r << shift) / divisorBig);
}

/**
 * Check if value is zero or power of 2
 */
function isZeroOrPowerOf2(x) {
  return (x & (x - 1)) === 0;
}

// ============================================================================
// 64-bit arithmetic helpers
// ============================================================================

const MASK64 = (1n << 64n) - 1n;

/**
 * Unsigned 64-bit multiplication high part
 */
function mulh(a, b) {
  return ((a * b) >> 64n) & MASK64;
}

/**
 * Signed 64-bit multiplication high part
 */
function smulh(a, b) {
  // Convert to signed
  const sa = a >= (1n << 63n) ? a - (1n << 64n) : a;
  const sb = b >= (1n << 63n) ? b - (1n << 64n) : b;
  const result = (sa * sb) >> 64n;
  return result < 0n ? result + (1n << 64n) : result;
}

/**
 * 64-bit rotate right
 */
function rotr64(x, n) {
  n = BigInt(n) % 64n;
  return ((x >> n) | (x << (64n - n))) & MASK64;
}

/**
 * Sign extend 32-bit to 64-bit (2's complement)
 */
function signExtend(x) {
  const val = BigInt(x >>> 0);
  return val >= (1n << 31n) ? val - (1n << 32n) + (1n << 64n) : val;
}

// ============================================================================
// Superscalar Instruction
// ============================================================================

class SuperscalarInstruction {
  constructor() {
    this.opcode = SuperscalarInstructionType.INVALID;
    this.dst = -1;
    this.src = -1;
    this.mod = 0;
    this.imm32 = 0;
  }

  getModShift() {
    return (this.mod >> 2) % 4;
  }
}

// ============================================================================
// Superscalar Program
// ============================================================================

class SuperscalarProgram {
  constructor() {
    this.instructions = [];
    this.addressRegister = 0;
  }

  addInstruction(opcode, dst, src, mod, imm32) {
    const instr = new SuperscalarInstruction();
    instr.opcode = opcode;
    instr.dst = dst;
    instr.src = src >= 0 ? src : dst;
    instr.mod = mod;
    instr.imm32 = imm32;
    this.instructions.push(instr);
  }

  getSize() {
    return this.instructions.length;
  }
}

// ============================================================================
// Instruction slot definitions
// ============================================================================

// Slot 3 instructions (3 bytes)
const SLOT_3 = [SuperscalarInstructionType.ISUB_R, SuperscalarInstructionType.IXOR_R];
const SLOT_3L = [SuperscalarInstructionType.ISUB_R, SuperscalarInstructionType.IXOR_R,
  SuperscalarInstructionType.IMULH_R, SuperscalarInstructionType.ISMULH_R];

// Slot 4 instructions (4 bytes)
const SLOT_4 = [SuperscalarInstructionType.IROR_C, SuperscalarInstructionType.IADD_RS];

// Slot 7 instructions (7 bytes)
const SLOT_7 = [SuperscalarInstructionType.IXOR_C7, SuperscalarInstructionType.IADD_C7];

// Slot 8 instructions (8 bytes = 7 + nop)
const SLOT_8 = [SuperscalarInstructionType.IXOR_C8, SuperscalarInstructionType.IADD_C8];

// Slot 9 instructions (9 bytes = 7 + 2 nop)
const SLOT_9 = [SuperscalarInstructionType.IXOR_C9, SuperscalarInstructionType.IADD_C9];

// Decode buffer configurations
const DECODE_BUFFERS = [
  [4, 8, 4],    // 4-8-4
  [7, 3, 3, 3], // 7-3-3-3
  [3, 7, 3, 3], // 3-7-3-3
  [4, 9, 3]     // 4-9-3
];

const DECODE_BUFFER_4444 = [4, 4, 4, 4];
const DECODE_BUFFER_3310 = [3, 3, 10];

// Instruction latencies
const LATENCY = {
  [SuperscalarInstructionType.ISUB_R]: 1,
  [SuperscalarInstructionType.IXOR_R]: 1,
  [SuperscalarInstructionType.IADD_RS]: 1,
  [SuperscalarInstructionType.IMUL_R]: 3,
  [SuperscalarInstructionType.IROR_C]: 1,
  [SuperscalarInstructionType.IADD_C7]: 1,
  [SuperscalarInstructionType.IXOR_C7]: 1,
  [SuperscalarInstructionType.IADD_C8]: 1,
  [SuperscalarInstructionType.IXOR_C8]: 1,
  [SuperscalarInstructionType.IADD_C9]: 1,
  [SuperscalarInstructionType.IXOR_C9]: 1,
  [SuperscalarInstructionType.IMULH_R]: 4,  // 3 ops with mov latency
  [SuperscalarInstructionType.ISMULH_R]: 4,
  [SuperscalarInstructionType.IMUL_RCP]: 4
};

// ============================================================================
// Program Generation
// ============================================================================

/**
 * Generate a superscalar program
 *
 * @param {Blake2Generator} gen - Random generator
 * @returns {SuperscalarProgram} - Generated program
 */
export function generateSuperscalar(gen) {
  const prog = new SuperscalarProgram();

  // Register state
  const registers = Array(8).fill(null).map(() => ({
    latency: 0,
    lastOpGroup: SuperscalarInstructionType.INVALID,
    lastOpPar: -1
  }));

  let cycle = 0;
  let mulCount = 0;
  let lastInstrType = SuperscalarInstructionType.INVALID;

  // Generate until we reach target latency or max size
  while (cycle < RANDOMX_SUPERSCALAR_LATENCY && prog.getSize() < SuperscalarMaxSize) {
    // Select decode buffer based on last instruction
    let buffer;
    if (lastInstrType === SuperscalarInstructionType.IMULH_R ||
        lastInstrType === SuperscalarInstructionType.ISMULH_R) {
      buffer = DECODE_BUFFER_3310;
    } else if (mulCount < cycle + 1) {
      buffer = DECODE_BUFFER_4444;
    } else if (lastInstrType === SuperscalarInstructionType.IMUL_RCP) {
      buffer = gen.getByte() & 1 ? [4, 8, 4] : [4, 9, 3];
    } else {
      buffer = DECODE_BUFFERS[gen.getByte() & 3];
    }

    // Fill each slot in the buffer
    for (let slot = 0; slot < buffer.length && prog.getSize() < SuperscalarMaxSize; slot++) {
      const slotSize = buffer[slot];
      const isLast = slot === buffer.length - 1;
      const isFirst = slot === 0;

      // Select instruction for this slot
      let instrType;
      let mod = 0;
      let imm32 = 0;
      let opGroup = SuperscalarInstructionType.INVALID;
      let opGroupPar = -1;
      let canReuse = false;
      let srcRequired = true;

      switch (slotSize) {
        case 3:
          if (isLast) {
            instrType = SLOT_3L[gen.getByte() & 3];
          } else {
            instrType = SLOT_3[gen.getByte() & 1];
          }
          break;
        case 4:
          if (buffer === DECODE_BUFFER_4444 && !isLast) {
            instrType = SuperscalarInstructionType.IMUL_R;
          } else {
            instrType = SLOT_4[gen.getByte() & 1];
          }
          break;
        case 7:
          instrType = SLOT_7[gen.getByte() & 1];
          break;
        case 8:
          instrType = SLOT_8[gen.getByte() & 1];
          break;
        case 9:
          instrType = SLOT_9[gen.getByte() & 1];
          break;
        case 10:
          instrType = SuperscalarInstructionType.IMUL_RCP;
          break;
        default:
          continue;
      }

      // Configure instruction parameters
      switch (instrType) {
        case SuperscalarInstructionType.ISUB_R:
          opGroup = SuperscalarInstructionType.IADD_RS;
          break;
        case SuperscalarInstructionType.IXOR_R:
          opGroup = SuperscalarInstructionType.IXOR_R;
          break;
        case SuperscalarInstructionType.IADD_RS:
          mod = gen.getByte();
          opGroup = SuperscalarInstructionType.IADD_RS;
          break;
        case SuperscalarInstructionType.IMUL_R:
          opGroup = SuperscalarInstructionType.IMUL_R;
          break;
        case SuperscalarInstructionType.IROR_C:
          do {
            imm32 = gen.getByte() & 63;
          } while (imm32 === 0);
          opGroup = SuperscalarInstructionType.IROR_C;
          opGroupPar = -1;
          srcRequired = false;
          break;
        case SuperscalarInstructionType.IADD_C7:
        case SuperscalarInstructionType.IADD_C8:
        case SuperscalarInstructionType.IADD_C9:
          imm32 = gen.getUInt32();
          opGroup = SuperscalarInstructionType.IADD_C7;
          opGroupPar = -1;
          srcRequired = false;
          break;
        case SuperscalarInstructionType.IXOR_C7:
        case SuperscalarInstructionType.IXOR_C8:
        case SuperscalarInstructionType.IXOR_C9:
          imm32 = gen.getUInt32();
          opGroup = SuperscalarInstructionType.IXOR_C7;
          opGroupPar = -1;
          srcRequired = false;
          break;
        case SuperscalarInstructionType.IMULH_R:
          canReuse = true;
          opGroup = SuperscalarInstructionType.IMULH_R;
          opGroupPar = gen.getUInt32();
          break;
        case SuperscalarInstructionType.ISMULH_R:
          canReuse = true;
          opGroup = SuperscalarInstructionType.ISMULH_R;
          opGroupPar = gen.getUInt32();
          break;
        case SuperscalarInstructionType.IMUL_RCP:
          do {
            imm32 = gen.getUInt32();
          } while (isZeroOrPowerOf2(imm32));
          opGroup = SuperscalarInstructionType.IMUL_RCP;
          opGroupPar = -1;
          srcRequired = false;
          break;
      }

      // Select source register
      let src = -1;
      if (srcRequired) {
        const available = [];
        for (let i = 0; i < 8; i++) {
          if (registers[i].latency <= cycle) {
            available.push(i);
          }
        }
        if (available.length > 0) {
          src = available[gen.getUInt32() % available.length];
          if (srcRequired && opGroupPar === -1) {
            opGroupPar = src;
          }
        }
      }

      // Select destination register
      let dst = -1;
      const availableDst = [];
      for (let i = 0; i < 8; i++) {
        if (registers[i].latency <= cycle &&
            (canReuse || i !== src) &&
            (opGroup !== SuperscalarInstructionType.IMUL_R ||
             registers[i].lastOpGroup !== SuperscalarInstructionType.IMUL_R) &&
            (registers[i].lastOpGroup !== opGroup || registers[i].lastOpPar !== opGroupPar) &&
            (instrType !== SuperscalarInstructionType.IADD_RS || i !== RegisterNeedsDisplacement)) {
          availableDst.push(i);
        }
      }

      if (availableDst.length > 0) {
        dst = availableDst[gen.getUInt32() % availableDst.length];
      } else {
        // No valid destination, skip this instruction
        continue;
      }

      // Add instruction to program
      prog.addInstruction(instrType, dst, src, mod, imm32);

      // Update register state
      const latency = LATENCY[instrType] || 1;
      registers[dst].latency = cycle + latency;
      registers[dst].lastOpGroup = opGroup;
      registers[dst].lastOpPar = opGroupPar;

      if (instrType === SuperscalarInstructionType.IMUL_R ||
          instrType === SuperscalarInstructionType.IMULH_R ||
          instrType === SuperscalarInstructionType.ISMULH_R ||
          instrType === SuperscalarInstructionType.IMUL_RCP) {
        mulCount++;
      }

      lastInstrType = instrType;
    }

    cycle++;
  }

  // Determine address register (highest ASIC latency)
  const asicLatencies = Array(8).fill(0);
  for (const instr of prog.instructions) {
    let latDst = asicLatencies[instr.dst] + 1;
    let latSrc = instr.dst !== instr.src ? asicLatencies[instr.src] + 1 : 0;
    asicLatencies[instr.dst] = Math.max(latDst, latSrc);
  }

  let maxLatency = 0;
  let addressReg = 0;
  for (let i = 0; i < 8; i++) {
    if (asicLatencies[i] > maxLatency) {
      maxLatency = asicLatencies[i];
      addressReg = i;
    }
  }
  prog.addressRegister = addressReg;

  return prog;
}

// ============================================================================
// Program Execution
// ============================================================================

/**
 * Execute a superscalar program on 8 registers
 *
 * @param {BigInt[]} r - Array of 8 64-bit registers
 * @param {SuperscalarProgram} prog - Program to execute
 */
export function executeSuperscalar(r, prog) {
  for (const instr of prog.instructions) {
    const { opcode, dst, src, imm32 } = instr;

    switch (opcode) {
      case SuperscalarInstructionType.ISUB_R:
        r[dst] = (r[dst] - r[src]) & MASK64;
        break;

      case SuperscalarInstructionType.IXOR_R:
        r[dst] = r[dst] ^ r[src];
        break;

      case SuperscalarInstructionType.IADD_RS:
        r[dst] = (r[dst] + (r[src] << BigInt(instr.getModShift()))) & MASK64;
        break;

      case SuperscalarInstructionType.IMUL_R:
        r[dst] = (r[dst] * r[src]) & MASK64;
        break;

      case SuperscalarInstructionType.IROR_C:
        r[dst] = rotr64(r[dst], imm32);
        break;

      case SuperscalarInstructionType.IADD_C7:
      case SuperscalarInstructionType.IADD_C8:
      case SuperscalarInstructionType.IADD_C9:
        r[dst] = (r[dst] + signExtend(imm32)) & MASK64;
        break;

      case SuperscalarInstructionType.IXOR_C7:
      case SuperscalarInstructionType.IXOR_C8:
      case SuperscalarInstructionType.IXOR_C9:
        r[dst] = r[dst] ^ signExtend(imm32);
        break;

      case SuperscalarInstructionType.IMULH_R:
        r[dst] = mulh(r[dst], r[src]);
        break;

      case SuperscalarInstructionType.ISMULH_R:
        r[dst] = smulh(r[dst], r[src]);
        break;

      case SuperscalarInstructionType.IMUL_RCP:
        r[dst] = (r[dst] * reciprocal(imm32)) & MASK64;
        break;
    }
  }
}

/**
 * Calculate SuperscalarHash for a cache item
 *
 * @param {BigInt[][]} cache - Cache memory (from Argon2d)
 * @param {number} itemNumber - Item index
 * @param {Uint8Array} seed - Seed for program generation
 * @returns {BigInt[]} - 8 register values (64 bytes total)
 */
export function superscalarHash(cache, itemNumber, seed) {
  // Initialize registers from item number
  const r = new Array(8);
  const itemBig = BigInt(itemNumber);
  for (let i = 0; i < 8; i++) {
    r[i] = itemBig + BigInt(i);
  }

  // Generate and execute programs (RANDOMX_CACHE_ACCESSES times)
  for (let i = 0; i < RANDOMX_CACHE_ACCESSES; i++) {
    // Generate program
    const gen = new Blake2Generator(seed, i);
    const prog = generateSuperscalar(gen);

    // Calculate cache index from address register
    const addressReg = prog.addressRegister;
    const cacheIndex = Number(r[addressReg] % BigInt(cache.length));

    // XOR cache item into registers
    const cacheItem = cache[cacheIndex];
    for (let j = 0; j < 8; j++) {
      r[j] ^= cacheItem[j * 16] || 0n;  // Each block has 128 qwords, use every 16th
    }

    // Execute program
    executeSuperscalar(r, prog);
  }

  return r;
}

export default {
  Blake2Generator,
  SuperscalarInstructionType,
  reciprocal,
  generateSuperscalar,
  executeSuperscalar,
  superscalarHash
};
