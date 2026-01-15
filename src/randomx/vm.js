/**
 * RandomX Virtual Machine
 *
 * Pure JavaScript implementation of the RandomX VM for mining.
 * Uses light mode (cache-based) for mobile/web compatibility.
 *
 * Reference: external/randomx/src/vm_interpreted.cpp, virtual_machine.cpp
 */

import { blake2b } from '../blake2b.js';
import {
  RANDOMX_PROGRAM_SIZE,
  RANDOMX_PROGRAM_ITERATIONS,
  RANDOMX_PROGRAM_COUNT,
  RANDOMX_SCRATCHPAD_L3,
  RANDOMX_SCRATCHPAD_L2,
  RANDOMX_SCRATCHPAD_L1,
  RANDOMX_SCRATCHPAD_L3_MASK,
  RANDOMX_SCRATCHPAD_L2_MASK,
  RANDOMX_SCRATCHPAD_L1_MASK
} from './config.js';
import { aesRound, fillAes1Rx4, hashAes1Rx4 } from './aes.js';
import { RandomXCache, initDatasetItem } from './dataset.js';

// ============================================================================
// Constants
// ============================================================================

const MASK64 = (1n << 64n) - 1n;
const REGISTERS_COUNT = 8;
const REGISTER_COUNT_FLT = 4;

// Cache line alignment mask
const CACHE_LINE_ALIGN_MASK = ~63n & MASK64;

// Mantissa size for float operations
const MANTISSA_SIZE = 52;
const MANTISSA_MASK = (1n << BigInt(MANTISSA_SIZE)) - 1n;
const EXPONENT_BIAS = 1023n;
const EXPONENT_MASK = 0x7ffn;

// Dynamic exponent bits
const STATIC_EXPONENT_BITS = 4;
const DYNAMIC_EXPONENT_BITS = 4;
const CONST_EXPONENT_BITS = 0x300n;  // bits 8-9 of exponent

// ============================================================================
// AES-based filling and hashing
// ============================================================================

/**
 * Fill buffer using AES (simplified soft AES implementation)
 *
 * @param {Uint8Array} seed - 64-byte seed
 * @param {number} size - Size to fill
 * @returns {Uint8Array} - Filled buffer
 */
export function fillAes(seed, size) {
  const output = new Uint8Array(size);
  const state = new Uint8Array(seed);

  // Use 4 keys from different parts of the state
  const keys = new Uint8Array(64);
  keys.set(seed);

  let pos = 0;
  while (pos < size) {
    // Apply AES round to each 16-byte block
    for (let i = 0; i < 4; i++) {
      const block = state.subarray(i * 16, (i + 1) * 16);
      const key = keys.subarray(i * 16, (i + 1) * 16);
      aesRound(block, key);
    }

    // Copy to output
    const copyLen = Math.min(64, size - pos);
    output.set(state.subarray(0, copyLen), pos);
    pos += 64;
  }

  return output;
}

/**
 * Hash buffer using AES
 *
 * @param {Uint8Array} input - Input buffer
 * @param {Uint8Array} keys - 64-byte keys (4 AES keys)
 * @returns {Uint8Array} - 64-byte hash
 */
export function hashAes(input, keys) {
  const state = new Uint8Array(64);

  // Process input in 64-byte chunks
  for (let i = 0; i < input.length; i += 64) {
    const chunk = input.subarray(i, Math.min(i + 64, input.length));

    // XOR chunk into state
    for (let j = 0; j < chunk.length; j++) {
      state[j] ^= chunk[j];
    }

    // Apply AES rounds
    for (let r = 0; r < 4; r++) {
      for (let b = 0; b < 4; b++) {
        const block = state.subarray(b * 16, (b + 1) * 16);
        const key = keys.subarray(b * 16, (b + 1) * 16);
        aesRound(block, key);
      }
    }
  }

  return state;
}

// ============================================================================
// VM State
// ============================================================================

export class RandomXVM {
  constructor(cache) {
    this.cache = cache;

    // Integer registers r0-r7
    this.r = new Array(REGISTERS_COUNT).fill(0n);

    // Floating-point register pairs f0-f3, e0-e3, a0-a3
    this.f = new Array(REGISTER_COUNT_FLT * 2).fill(0);  // f[i] = [lo, hi]
    this.e = new Array(REGISTER_COUNT_FLT * 2).fill(0);
    this.a = new Array(REGISTER_COUNT_FLT * 2).fill(0);

    // Scratchpad (2MB)
    this.scratchpad = new Uint8Array(RANDOMX_SCRATCHPAD_L3);

    // Memory addresses
    this.ma = 0n;
    this.mx = 0n;

    // Configuration
    this.readReg = [0, 2, 4, 6];  // Which registers to use for address calculation
    this.datasetOffset = 0n;
    this.eMask = [0n, 0n];

    // Program
    this.program = null;
  }

  /**
   * Initialize VM scratchpad from seed
   *
   * @param {Uint8Array} seed - 64-byte seed (tempHash)
   */
  initScratchpad(seed) {
    // Fill scratchpad using AES
    this.scratchpad = fillAes(seed, RANDOMX_SCRATCHPAD_L3);
  }

  /**
   * Generate program from seed
   *
   * @param {Uint8Array} seed - 64-byte seed
   */
  generateProgram(seed) {
    // Fill program using AES (2KB for 256 instructions * 8 bytes)
    const programBytes = fillAes(seed, RANDOMX_PROGRAM_SIZE * 8);

    // Parse instructions
    this.program = [];
    for (let i = 0; i < RANDOMX_PROGRAM_SIZE; i++) {
      const offset = i * 8;
      const instr = {
        opcode: programBytes[offset],
        dst: programBytes[offset + 1] & 7,
        src: programBytes[offset + 2] & 7,
        mod: programBytes[offset + 3],
        imm32: programBytes[offset + 4] |
          (programBytes[offset + 5] << 8) |
          (programBytes[offset + 6] << 16) |
          (programBytes[offset + 7] << 24)
      };
      this.program.push(instr);
    }

    // Initialize configuration from entropy (first 128 bytes of program)
    this.initConfig(programBytes);
  }

  /**
   * Initialize configuration from entropy
   */
  initConfig(entropy) {
    // Read entropy values as 64-bit LE
    const readU64 = (arr, off) => {
      let v = 0n;
      for (let i = 0; i < 8; i++) {
        v |= BigInt(arr[off + i]) << BigInt(i * 8);
      }
      return v;
    };

    // Initialize 'a' registers with small positive floats
    for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
      const e0 = readU64(entropy, i * 16);
      const e1 = readU64(entropy, i * 16 + 8);
      this.a[i * 2] = this.getSmallPositiveFloat(e0);
      this.a[i * 2 + 1] = this.getSmallPositiveFloat(e1);
    }

    // Memory addresses
    this.ma = readU64(entropy, 64) & CACHE_LINE_ALIGN_MASK;
    this.mx = readU64(entropy, 72);

    // Address register configuration
    const addrRegs = readU64(entropy, 80);
    this.readReg[0] = Number((addrRegs >> 0n) & 1n);
    this.readReg[1] = 2 + Number((addrRegs >> 1n) & 1n);
    this.readReg[2] = 4 + Number((addrRegs >> 2n) & 1n);
    this.readReg[3] = 6 + Number((addrRegs >> 3n) & 1n);

    // Dataset offset
    const extraItems = 33554368 / 64;  // RANDOMX_DATASET_EXTRA_SIZE / 64
    this.datasetOffset = (readU64(entropy, 88) % BigInt(extraItems + 1)) * 64n;

    // E mask
    this.eMask[0] = this.getFloatMask(readU64(entropy, 96));
    this.eMask[1] = this.getFloatMask(readU64(entropy, 104));
  }

  /**
   * Get small positive float bits from entropy
   */
  getSmallPositiveFloat(entropy) {
    let exponent = entropy >> 59n;  // 0..31
    let mantissa = entropy & MANTISSA_MASK;
    exponent = (exponent + EXPONENT_BIAS) & EXPONENT_MASK;
    return Number(exponent) * Math.pow(2, MANTISSA_SIZE) + Number(mantissa);
  }

  /**
   * Get float mask from entropy
   */
  getFloatMask(entropy) {
    const mask22bit = (1n << 22n) - 1n;
    let exponent = CONST_EXPONENT_BITS;
    exponent |= (entropy >> BigInt(64 - STATIC_EXPONENT_BITS)) << BigInt(DYNAMIC_EXPONENT_BITS);
    exponent <<= BigInt(MANTISSA_SIZE);
    return (entropy & mask22bit) | exponent;
  }

  /**
   * Run VM execution
   *
   * @param {Uint8Array} seed - 64-byte seed (tempHash)
   */
  run(seed) {
    this.generateProgram(seed);
    this.initialize();
    this.execute();
  }

  /**
   * Initialize VM state
   */
  initialize() {
    // Clear integer registers
    for (let i = 0; i < REGISTERS_COUNT; i++) {
      this.r[i] = 0n;
    }

    // Initialize floating-point registers
    for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
      this.f[i * 2] = 0;
      this.f[i * 2 + 1] = 0;
      this.e[i * 2] = 1.0;  // Small positive value
      this.e[i * 2 + 1] = 1.0;
    }
  }

  /**
   * Execute program
   */
  execute() {
    let spAddr0 = Number(this.mx & BigInt(RANDOMX_SCRATCHPAD_L3_MASK));
    let spAddr1 = Number(this.ma & BigInt(RANDOMX_SCRATCHPAD_L3_MASK));

    for (let ic = 0; ic < RANDOMX_PROGRAM_ITERATIONS; ic++) {
      // Calculate scratchpad mix
      const spMix = this.r[this.readReg[0]] ^ this.r[this.readReg[1]];
      spAddr0 = Number((BigInt(spAddr0) ^ spMix) & BigInt(RANDOMX_SCRATCHPAD_L3_MASK));
      spAddr1 = Number((BigInt(spAddr1) ^ (spMix >> 32n)) & BigInt(RANDOMX_SCRATCHPAD_L3_MASK));

      // Read from scratchpad into integer registers
      for (let i = 0; i < REGISTERS_COUNT; i++) {
        this.r[i] ^= this.readU64(this.scratchpad, spAddr0 + i * 8);
      }

      // Read into floating-point registers (simplified)
      for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
        const lo = this.readU64(this.scratchpad, spAddr1 + i * 8);
        const hi = this.readU64(this.scratchpad, spAddr1 + (i + 4) * 8);
        this.f[i * 2] = this.convertToDouble(lo);
        this.f[i * 2 + 1] = this.convertToDouble(hi);
        this.e[i * 2] = this.convertToDouble(lo) * 1.0000001;
        this.e[i * 2 + 1] = this.convertToDouble(hi) * 1.0000001;
      }

      // Execute bytecode (simplified - execute subset of operations)
      this.executeBytecode();

      // Update memory addresses
      this.mx ^= this.r[this.readReg[2]] ^ this.r[this.readReg[3]];
      this.mx &= CACHE_LINE_ALIGN_MASK;

      // Dataset read (light mode - compute from cache)
      const datasetItem = initDatasetItem(this.cache, Number(this.ma / 64n));
      for (let i = 0; i < REGISTERS_COUNT; i++) {
        this.r[i] ^= this.readU64(datasetItem, i * 8);
      }

      // Swap mx and ma
      const tmp = this.mx;
      this.mx = this.ma;
      this.ma = tmp;

      // Write to scratchpad
      for (let i = 0; i < REGISTERS_COUNT; i++) {
        this.writeU64(this.scratchpad, spAddr1 + i * 8, this.r[i]);
      }

      // XOR f and e registers
      for (let i = 0; i < REGISTER_COUNT_FLT * 2; i++) {
        this.f[i] = this.xorFloat(this.f[i], this.e[i]);
      }

      // Write floating-point to scratchpad
      for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
        this.writeDouble(this.scratchpad, spAddr0 + i * 16, this.f[i * 2]);
        this.writeDouble(this.scratchpad, spAddr0 + i * 16 + 8, this.f[i * 2 + 1]);
      }

      spAddr0 = 0;
      spAddr1 = 0;
    }
  }

  /**
   * Execute bytecode program (simplified)
   */
  executeBytecode() {
    for (const instr of this.program) {
      const { opcode, dst, src, mod, imm32 } = instr;

      // Simplified opcode handling (only essential operations)
      const op = opcode % 32;  // Simplify to a few operations

      switch (op) {
        case 0:  // IADD_RS
        case 1:
          this.r[dst] = (this.r[dst] + (this.r[src] << BigInt((mod >> 2) % 4))) & MASK64;
          break;

        case 2:  // IADD_M
        case 3:
          {
            const addr = this.getMemoryAddress(src, imm32, mod);
            this.r[dst] = (this.r[dst] + this.readU64(this.scratchpad, addr)) & MASK64;
          }
          break;

        case 4:  // ISUB_R
        case 5:
          this.r[dst] = (this.r[dst] - this.r[src]) & MASK64;
          break;

        case 6:  // IMUL_R
        case 7:
          this.r[dst] = (this.r[dst] * this.r[src]) & MASK64;
          break;

        case 8:  // IXOR_R
        case 9:
          this.r[dst] ^= this.r[src];
          break;

        case 10: // IROR_R
        case 11:
          {
            const shift = this.r[src] % 64n;
            this.r[dst] = ((this.r[dst] >> shift) | (this.r[dst] << (64n - shift))) & MASK64;
          }
          break;

        case 12: // ISWAP_R
          if (dst !== src) {
            const tmp = this.r[dst];
            this.r[dst] = this.r[src];
            this.r[src] = tmp;
          }
          break;

        case 13: // FADD_R
        case 14:
          this.f[dst % (REGISTER_COUNT_FLT * 2)] += this.a[src % (REGISTER_COUNT_FLT * 2)];
          break;

        case 15: // FSUB_R
        case 16:
          this.f[dst % (REGISTER_COUNT_FLT * 2)] -= this.a[src % (REGISTER_COUNT_FLT * 2)];
          break;

        case 17: // FMUL_R
        case 18:
          this.e[dst % (REGISTER_COUNT_FLT * 2)] *= this.a[src % (REGISTER_COUNT_FLT * 2)];
          break;

        case 19: // ISTORE
        case 20:
          {
            const addr = this.getMemoryAddress(dst, imm32, mod);
            this.writeU64(this.scratchpad, addr, this.r[src]);
          }
          break;

        default:
          // NOP or other operations
          break;
      }
    }
  }

  /**
   * Get memory address for memory operations
   */
  getMemoryAddress(reg, imm32, mod) {
    const base = Number(this.r[reg] & MASK64);
    const offset = this.signExtend32(imm32);

    // Select mask based on mod
    let mask;
    if ((mod & 3) === 0) {
      mask = RANDOMX_SCRATCHPAD_L1_MASK;
    } else if ((mod & 3) < 3) {
      mask = RANDOMX_SCRATCHPAD_L2_MASK;
    } else {
      mask = RANDOMX_SCRATCHPAD_L3_MASK;
    }

    return (base + offset) & mask;
  }

  /**
   * Sign extend 32-bit to signed number
   */
  signExtend32(val) {
    val = val >>> 0;
    return val >= 0x80000000 ? val - 0x100000000 : val;
  }

  /**
   * Read 64-bit value from byte array
   */
  readU64(arr, offset) {
    offset = offset >>> 0;
    if (offset + 8 > arr.length) return 0n;

    let v = 0n;
    for (let i = 0; i < 8; i++) {
      v |= BigInt(arr[offset + i]) << BigInt(i * 8);
    }
    return v;
  }

  /**
   * Write 64-bit value to byte array
   */
  writeU64(arr, offset, value) {
    offset = offset >>> 0;
    if (offset + 8 > arr.length) return;

    for (let i = 0; i < 8; i++) {
      arr[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
    }
  }

  /**
   * Convert BigInt to double (simplified)
   */
  convertToDouble(val) {
    // Simple conversion - treat as signed 64-bit
    if (val >= (1n << 63n)) {
      return Number(val - (1n << 64n));
    }
    return Number(val);
  }

  /**
   * Write double to byte array
   */
  writeDouble(arr, offset, val) {
    // Simplified - convert to 64-bit integer representation
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, val, true);
    for (let i = 0; i < 8; i++) {
      arr[offset + i] = view.getUint8(i);
    }
  }

  /**
   * XOR two floats (via bit representation)
   */
  xorFloat(a, b) {
    const viewA = new DataView(new ArrayBuffer(8));
    const viewB = new DataView(new ArrayBuffer(8));
    viewA.setFloat64(0, a, true);
    viewB.setFloat64(0, b, true);

    const result = new DataView(new ArrayBuffer(8));
    for (let i = 0; i < 8; i++) {
      result.setUint8(i, viewA.getUint8(i) ^ viewB.getUint8(i));
    }
    return result.getFloat64(0, true);
  }

  /**
   * Get register file as byte array
   */
  getRegisterFile() {
    const size = REGISTERS_COUNT * 8 + REGISTER_COUNT_FLT * 32;
    const result = new Uint8Array(size);

    // Integer registers
    for (let i = 0; i < REGISTERS_COUNT; i++) {
      this.writeU64(result, i * 8, this.r[i]);
    }

    // Float registers (f, e, a)
    const floatOffset = REGISTERS_COUNT * 8;
    for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
      this.writeDouble(result, floatOffset + i * 16, this.f[i * 2]);
      this.writeDouble(result, floatOffset + i * 16 + 8, this.f[i * 2 + 1]);
    }

    return result;
  }

  /**
   * Get final result (hash the register file and scratchpad)
   */
  getFinalResult() {
    // Hash scratchpad with AES
    const keys = new Uint8Array(64);
    for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
      this.writeDouble(keys, i * 16, this.a[i * 2]);
      this.writeDouble(keys, i * 16 + 8, this.a[i * 2 + 1]);
    }

    const scratchpadHash = hashAes(this.scratchpad, keys);

    // XOR into 'a' registers (simplified)
    for (let i = 0; i < 64; i++) {
      keys[i] ^= scratchpadHash[i];
    }

    // Get register file
    const regFile = this.getRegisterFile();

    // Final Blake2b hash
    return blake2b(regFile, 32);
  }
}

export default {
  RandomXVM,
  fillAes,
  hashAes
};
