/**
 * RandomX Full Mode VM - WASM Loader
 *
 * Uses the AssemblyScript-compiled WASM VM for full mode hashing.
 * Pre-computed dataset provides O(1) lookups instead of superscalar computation.
 */

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { blake2b } from '../blake2b.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = join(__dirname, '../../build/randomx.wasm');

// Scratchpad size
const SCRATCHPAD_SIZE = 2 * 1024 * 1024;  // 2MB

// Program size
const PROGRAM_SIZE = 256 * 8;  // 256 instructions * 8 bytes each

// Register file size for final hash
const REGISTER_FILE_SIZE = 256;

// Seed size for AES fill
const SEED_SIZE = 64;

/**
 * Load and instantiate the WASM VM
 */
async function loadWasm(memory) {
  const wasmBuffer = await readFile(WASM_PATH);
  const module = await WebAssembly.compile(wasmBuffer);
  const instance = await WebAssembly.instantiate(module, {
    env: {
      memory,
      abort: (msg, file, line, col) => {
        console.error(`WASM abort at ${line}:${col}`);
      }
    }
  });
  return instance.exports;
}

/**
 * Full Mode RandomX Context
 *
 * Uses pre-computed dataset for fast hashing.
 */
export class RandomXFullVM {
  constructor() {
    this.memory = null;
    this.exports = null;
    this.scratchpadPtr = 0;
    this.datasetPtr = 0;
    this.programPtr = 0;
    this.outputPtr = 0;
    this.seedPtr = 0;
    this.dataset = null;
  }

  /**
   * Initialize the VM with dataset
   *
   * @param {BigInt64Array} dataset - Pre-computed dataset (34M items * 8 u64 each)
   */
  async init(dataset) {
    // Calculate memory needs
    // Layout: [scratchpad 2MB] [program 2KB] [output 256B] [seed 64B] [dataset]
    // For real usage, dataset should be in shared memory or accessed via callback

    // For testing, we'll copy a small portion of dataset into WASM memory
    const testDatasetSize = Math.min(dataset.byteLength, 64 * 1024);  // 64KB max for testing

    const memorySize = SCRATCHPAD_SIZE + PROGRAM_SIZE + REGISTER_FILE_SIZE + SEED_SIZE + testDatasetSize + 4096;
    const pages = Math.ceil(memorySize / 65536);

    this.memory = new WebAssembly.Memory({
      initial: pages,
      maximum: pages
    });

    this.exports = await loadWasm(this.memory);

    // Memory layout
    this.scratchpadPtr = 0;
    this.programPtr = SCRATCHPAD_SIZE;
    this.outputPtr = SCRATCHPAD_SIZE + PROGRAM_SIZE;
    this.seedPtr = SCRATCHPAD_SIZE + PROGRAM_SIZE + REGISTER_FILE_SIZE;
    this.datasetPtr = SCRATCHPAD_SIZE + PROGRAM_SIZE + REGISTER_FILE_SIZE + SEED_SIZE;

    // Copy test dataset into WASM memory
    const memView = new Uint8Array(this.memory.buffer);
    const datasetBytes = new Uint8Array(dataset.buffer, dataset.byteOffset, testDatasetSize);
    memView.set(datasetBytes, this.datasetPtr);

    // Store full dataset reference for later
    this.dataset = dataset;

    this.exports.vm_init(
      this.scratchpadPtr,
      this.datasetPtr,
      this.programPtr,
      1   // Full mode
    );

    // Set dataset size for bounds checking
    const datasetItems = BigInt(testDatasetSize / 64);
    this.exports.vm_set_dataset_size(datasetItems);
  }

  /**
   * Fill scratchpad using AES (proper WASM implementation)
   *
   * @param {Uint8Array} seed - 64-byte seed
   */
  fillScratchpad(seed) {
    const memView = new Uint8Array(this.memory.buffer);

    // Copy seed to WASM memory
    memView.set(seed, this.seedPtr);

    // Call WASM AES fill function
    this.exports.fillScratchpad(this.seedPtr, this.scratchpadPtr, SCRATCHPAD_SIZE);
  }

  /**
   * Generate program from input and set configuration
   *
   * @param {Uint8Array} seed - 64-byte seed (from Blake2b of input)
   */
  generateProgram(seed) {
    const memView = new Uint8Array(this.memory.buffer);

    // Copy seed to a temporary location for program generation
    const tempSeedPtr = this.seedPtr;
    memView.set(seed, tempSeedPtr);

    // Generate program using AES fill (program is 2KB = 32 x 64 byte blocks)
    // Use fillScratchpad with smaller size for program generation
    this.exports.fillScratchpad(tempSeedPtr, this.programPtr, PROGRAM_SIZE);

    // Read program bytes as entropy for configuration
    const programView = new Uint8Array(this.memory.buffer, this.programPtr, PROGRAM_SIZE);

    // Read configuration from entropy (first 128 bytes)
    const readU64 = (arr, off) => {
      let v = 0n;
      for (let i = 0; i < 8; i++) {
        v |= BigInt(arr[off + i]) << BigInt(i * 8);
      }
      return v;
    };

    const ma = readU64(programView, 0);
    const mx = readU64(programView, 8);
    const addrReg = readU64(programView, 80);

    this.exports.vm_set_config(
      ma, mx,
      Number(addrReg & 7n),
      Number((addrReg >> 3n) & 7n),
      Number((addrReg >> 6n) & 7n),
      Number((addrReg >> 9n) & 7n),
      0n,  // dataset offset
      0x3F00000000000000n,  // eMask0
      0x3F00000000000000n   // eMask1
    );

    // Initialize 'a' registers from entropy (bytes 0-63)
    const getSmallFloat = (val) => {
      // Convert u64 to small positive float (0.5 to 2.0 range)
      const exponent = ((val >> 59n) & 0xFn) + 0x3F8n;
      const mantissa = val & 0x7FFFFFFFFFFFFn;
      const bits = (exponent << 52n) | mantissa;
      const buffer = new ArrayBuffer(8);
      const view = new DataView(buffer);
      view.setBigUint64(0, bits, true);
      return view.getFloat64(0, true);
    };

    this.exports.vm_set_a_registers(
      getSmallFloat(readU64(programView, 0)),
      getSmallFloat(readU64(programView, 8)),
      getSmallFloat(readU64(programView, 16)),
      getSmallFloat(readU64(programView, 24)),
      getSmallFloat(readU64(programView, 32)),
      getSmallFloat(readU64(programView, 40)),
      getSmallFloat(readU64(programView, 48)),
      getSmallFloat(readU64(programView, 56))
    );
  }

  /**
   * Calculate hash
   *
   * @param {Uint8Array|Buffer} input - Input data
   * @returns {Uint8Array} - 32-byte hash
   */
  calculateHash(input) {
    // Generate 64-byte seed from input
    const seed = blake2b(input, 64);

    // Reset VM state
    this.exports.vm_reset();

    // Fill scratchpad
    this.fillScratchpad(seed);

    // Generate program
    this.generateProgram(seed);

    // Execute VM
    this.exports.vm_execute();

    // Get register file
    this.exports.vm_get_register_file(this.outputPtr);

    // Read register file
    const regFile = new Uint8Array(this.memory.buffer, this.outputPtr, REGISTER_FILE_SIZE);

    // Final Blake2b hash
    return blake2b(regFile, 32);
  }
}

/**
 * Create a full mode VM with pre-computed dataset
 *
 * @param {BigInt64Array} dataset - Pre-computed dataset
 * @returns {Promise<RandomXFullVM>}
 */
export async function createFullVM(dataset) {
  const vm = new RandomXFullVM();
  await vm.init(dataset);
  return vm;
}

export default { RandomXFullVM, createFullVM };
