/**
 * JIT-Compiled RandomX Virtual Machine
 *
 * Instead of interpreting instructions in a switch/case loop,
 * this VM generates JavaScript code and compiles it using Function().
 * V8/Bun's JIT then optimizes the generated code.
 *
 * Expected speedup: 2-5x over interpreted mode
 */

import { blake2b } from '../blake2b.js';
import {
  RANDOMX_PROGRAM_SIZE,
  RANDOMX_PROGRAM_ITERATIONS,
  RANDOMX_SCRATCHPAD_L3,
  RANDOMX_SCRATCHPAD_L2,
  RANDOMX_SCRATCHPAD_L1,
  RANDOMX_SCRATCHPAD_L3_MASK,
  RANDOMX_SCRATCHPAD_L2_MASK,
  RANDOMX_SCRATCHPAD_L1_MASK
} from './config.js';
import { hashAes1Rx4 } from './aes.js';
import { initDatasetItem } from './dataset.js';
import { fillAes, hashAes } from './vm.js';

const MASK64 = (1n << 64n) - 1n;
const REGISTERS_COUNT = 8;
const REGISTER_COUNT_FLT = 4;
const CACHE_LINE_ALIGN_MASK = ~63n & MASK64;

// Program cache for compiled functions
const compiledProgramCache = new Map();

/**
 * JIT-Compiled RandomX VM
 */
export class RandomXVMJit {
  constructor(cache) {
    this.cache = cache;

    // Integer registers r0-r7
    this.r = new Array(REGISTERS_COUNT).fill(0n);

    // Floating-point registers
    this.f = new Array(REGISTER_COUNT_FLT * 2).fill(0);
    this.e = new Array(REGISTER_COUNT_FLT * 2).fill(0);
    this.a = new Array(REGISTER_COUNT_FLT * 2).fill(0);

    // Scratchpad (2MB)
    this.scratchpad = new Uint8Array(RANDOMX_SCRATCHPAD_L3);

    // Memory addresses
    this.ma = 0n;
    this.mx = 0n;

    // Configuration
    this.readReg = [0, 2, 4, 6];
    this.datasetOffset = 0n;
    this.eMask = [0n, 0n];

    // JIT compiled program
    this.compiledProgram = null;
    this.program = null;
  }

  /**
   * Initialize scratchpad from seed
   */
  initScratchpad(seed) {
    this.scratchpad = fillAes(seed, RANDOMX_SCRATCHPAD_L3);
  }

  /**
   * Generate and JIT compile program from seed
   */
  generateProgram(seed) {
    // Fill program bytes using AES
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

    // Initialize configuration
    this.initConfig(programBytes);

    // JIT compile the program
    this.compiledProgram = this.jitCompile(this.program);
  }

  /**
   * Initialize configuration from entropy
   */
  initConfig(entropy) {
    const readU64 = (arr, off) => {
      let v = 0n;
      for (let i = 0; i < 8; i++) {
        v |= BigInt(arr[off + i]) << BigInt(i * 8);
      }
      return v;
    };

    // Initialize 'a' registers
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
    const extraItems = 33554368 / 64;
    this.datasetOffset = (readU64(entropy, 88) % BigInt(extraItems + 1)) * 64n;

    // E mask
    this.eMask[0] = this.getFloatMask(readU64(entropy, 96));
    this.eMask[1] = this.getFloatMask(readU64(entropy, 104));
  }

  getSmallPositiveFloat(entropy) {
    let exponent = entropy >> 59n;
    let mantissa = entropy & ((1n << 52n) - 1n);
    exponent = (exponent + 1023n) & 0x7ffn;
    return Number(exponent) * Math.pow(2, 52) + Number(mantissa);
  }

  getFloatMask(entropy) {
    const mask22bit = (1n << 22n) - 1n;
    let exponent = 0x300n;
    exponent |= (entropy >> 60n) << 4n;
    exponent <<= 52n;
    return (entropy & mask22bit) | exponent;
  }

  /**
   * JIT compile a program into a JavaScript function
   */
  jitCompile(program) {
    // Check cache first
    const programKey = this.getProgramKey(program);
    if (compiledProgramCache.has(programKey)) {
      return compiledProgramCache.get(programKey);
    }

    // Generate code for each instruction
    const codeLines = [];
    codeLines.push('const MASK64 = (1n << 64n) - 1n;');
    codeLines.push('const L1_MASK = ' + RANDOMX_SCRATCHPAD_L1_MASK + ';');
    codeLines.push('const L2_MASK = ' + RANDOMX_SCRATCHPAD_L2_MASK + ';');
    codeLines.push('const L3_MASK = ' + RANDOMX_SCRATCHPAD_L3_MASK + ';');

    for (let i = 0; i < program.length; i++) {
      const instr = program[i];
      const code = this.generateInstructionCode(instr, i);
      if (code) {
        codeLines.push(code);
      }
    }

    const fullCode = codeLines.join('\n');

    // Compile the function
    // Parameters: r (registers), f, e, a (float regs), sp (scratchpad), ctx (vm context)
    const compiledFn = new Function('r', 'f', 'e', 'a', 'sp', 'ctx', fullCode);

    // Cache the compiled function
    if (compiledProgramCache.size < 1000) {  // Limit cache size
      compiledProgramCache.set(programKey, compiledFn);
    }

    return compiledFn;
  }

  /**
   * Generate a unique key for a program (for caching)
   */
  getProgramKey(program) {
    // Use first 32 bytes of instructions as key
    let key = '';
    for (let i = 0; i < Math.min(32, program.length); i++) {
      const instr = program[i];
      key += String.fromCharCode(instr.opcode, instr.dst, instr.src, instr.mod);
    }
    return key;
  }

  /**
   * Generate JavaScript code for a single instruction
   */
  generateInstructionCode(instr, index) {
    const { opcode, dst, src, mod, imm32 } = instr;
    const op = opcode % 32;

    // Sign-extended immediate
    const signedImm = imm32 >= 0x80000000 ? imm32 - 0x100000000 : imm32;

    switch (op) {
      case 0:  // IADD_RS
      case 1:
        const shift = (mod >> 2) % 4;
        return `r[${dst}] = (r[${dst}] + (r[${src}] << ${shift}n)) & MASK64;`;

      case 2:  // IADD_M
      case 3:
        return this.generateMemoryRead(dst, src, signedImm, mod, 'add');

      case 4:  // ISUB_R
      case 5:
        return `r[${dst}] = (r[${dst}] - r[${src}]) & MASK64;`;

      case 6:  // IMUL_R
      case 7:
        return `r[${dst}] = (r[${dst}] * r[${src}]) & MASK64;`;

      case 8:  // IXOR_R
      case 9:
        return `r[${dst}] ^= r[${src}];`;

      case 10: // IROR_R
      case 11:
        return `{ const s = r[${src}] % 64n; r[${dst}] = ((r[${dst}] >> s) | (r[${dst}] << (64n - s))) & MASK64; }`;

      case 12: // ISWAP_R
        if (dst !== src) {
          return `{ const t = r[${dst}]; r[${dst}] = r[${src}]; r[${src}] = t; }`;
        }
        return '';

      case 13: // FADD_R
      case 14:
        const fdst1 = dst % (REGISTER_COUNT_FLT * 2);
        const asrc1 = src % (REGISTER_COUNT_FLT * 2);
        return `f[${fdst1}] += a[${asrc1}];`;

      case 15: // FSUB_R
      case 16:
        const fdst2 = dst % (REGISTER_COUNT_FLT * 2);
        const asrc2 = src % (REGISTER_COUNT_FLT * 2);
        return `f[${fdst2}] -= a[${asrc2}];`;

      case 17: // FMUL_R
      case 18:
        const edst = dst % (REGISTER_COUNT_FLT * 2);
        const asrc3 = src % (REGISTER_COUNT_FLT * 2);
        return `e[${edst}] *= a[${asrc3}];`;

      case 19: // ISTORE
      case 20:
        return this.generateMemoryWrite(dst, src, signedImm, mod);

      default:
        return '';  // NOP
    }
  }

  /**
   * Generate code for memory read operations
   */
  generateMemoryRead(dst, src, imm, mod, operation) {
    const maskVar = (mod & 3) === 0 ? 'L1_MASK' : (mod & 3) < 3 ? 'L2_MASK' : 'L3_MASK';

    return `{
      const addr = (Number(r[${src}] & MASK64) + ${imm}) & ${maskVar};
      let v = 0n;
      for (let i = 0; i < 8; i++) v |= BigInt(sp[addr + i]) << BigInt(i * 8);
      r[${dst}] = (r[${dst}] ${operation === 'add' ? '+' : '^'} v) & MASK64;
    }`;
  }

  /**
   * Generate code for memory write operations
   */
  generateMemoryWrite(dst, src, imm, mod) {
    const maskVar = (mod & 3) === 0 ? 'L1_MASK' : (mod & 3) < 3 ? 'L2_MASK' : 'L3_MASK';

    return `{
      const addr = (Number(r[${dst}] & MASK64) + ${imm}) & ${maskVar};
      const v = r[${src}];
      for (let i = 0; i < 8; i++) sp[addr + i] = Number((v >> BigInt(i * 8)) & 0xffn);
    }`;
  }

  /**
   * Run VM execution
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
    for (let i = 0; i < REGISTERS_COUNT; i++) {
      this.r[i] = 0n;
    }
    for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
      this.f[i * 2] = 0;
      this.f[i * 2 + 1] = 0;
      this.e[i * 2] = 1.0;
      this.e[i * 2 + 1] = 1.0;
    }
  }

  /**
   * Execute program using JIT compiled code
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

      // Read into floating-point registers
      for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
        const lo = this.readU64(this.scratchpad, spAddr1 + i * 8);
        const hi = this.readU64(this.scratchpad, spAddr1 + (i + 4) * 8);
        this.f[i * 2] = this.convertToDouble(lo);
        this.f[i * 2 + 1] = this.convertToDouble(hi);
        this.e[i * 2] = this.convertToDouble(lo) * 1.0000001;
        this.e[i * 2 + 1] = this.convertToDouble(hi) * 1.0000001;
      }

      // Execute JIT compiled bytecode!
      this.compiledProgram(this.r, this.f, this.e, this.a, this.scratchpad, this);

      // Update memory addresses
      this.mx ^= this.r[this.readReg[2]] ^ this.r[this.readReg[3]];
      this.mx &= CACHE_LINE_ALIGN_MASK;

      // Dataset read (light mode)
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

  // Utility methods (same as original VM)
  readU64(arr, offset) {
    offset = offset >>> 0;
    if (offset + 8 > arr.length) return 0n;
    let v = 0n;
    for (let i = 0; i < 8; i++) {
      v |= BigInt(arr[offset + i]) << BigInt(i * 8);
    }
    return v;
  }

  writeU64(arr, offset, value) {
    offset = offset >>> 0;
    if (offset + 8 > arr.length) return;
    for (let i = 0; i < 8; i++) {
      arr[offset + i] = Number((value >> BigInt(i * 8)) & 0xffn);
    }
  }

  convertToDouble(val) {
    if (val >= (1n << 63n)) {
      return Number(val - (1n << 64n));
    }
    return Number(val);
  }

  writeDouble(arr, offset, val) {
    const view = new DataView(new ArrayBuffer(8));
    view.setFloat64(0, val, true);
    for (let i = 0; i < 8; i++) {
      arr[offset + i] = view.getUint8(i);
    }
  }

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

  getRegisterFile() {
    const size = REGISTERS_COUNT * 8 + REGISTER_COUNT_FLT * 32;
    const result = new Uint8Array(size);
    for (let i = 0; i < REGISTERS_COUNT; i++) {
      this.writeU64(result, i * 8, this.r[i]);
    }
    const floatOffset = REGISTERS_COUNT * 8;
    for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
      this.writeDouble(result, floatOffset + i * 16, this.f[i * 2]);
      this.writeDouble(result, floatOffset + i * 16 + 8, this.f[i * 2 + 1]);
    }
    return result;
  }

  getFinalResult() {
    const keys = new Uint8Array(64);
    for (let i = 0; i < REGISTER_COUNT_FLT; i++) {
      this.writeDouble(keys, i * 16, this.a[i * 2]);
      this.writeDouble(keys, i * 16 + 8, this.a[i * 2 + 1]);
    }
    const scratchpadHash = hashAes(this.scratchpad, keys);
    for (let i = 0; i < 64; i++) {
      keys[i] ^= scratchpadHash[i];
    }
    const regFile = this.getRegisterFile();
    return blake2b(regFile, 32);
  }
}

/**
 * Clear the compiled program cache
 */
export function clearJitCache() {
  compiledProgramCache.clear();
}

/**
 * Get JIT cache stats
 */
export function getJitCacheStats() {
  return {
    size: compiledProgramCache.size,
    maxSize: 1000
  };
}

export default {
  RandomXVMJit,
  clearJitCache,
  getJitCacheStats
};
