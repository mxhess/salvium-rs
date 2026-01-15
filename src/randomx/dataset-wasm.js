/**
 * WASM-backed Dataset Generation
 *
 * Uses AssemblyScript WASM for ~30x faster dataset item generation.
 * This makes full mode (2GB dataset) practical.
 */

import { RANDOMX_CACHE_ACCESSES, RANDOMX_DATASET_ITEM_COUNT } from './config.js';

// WASM module state (shared with argon2d-wasm.js)
let wasmInstance = null;
let wasmMemory = null;
let isInitialized = false;

// Cache state
let cachePtr = 0;
let cacheLineCount = 0;
let outputPtr = 0;

/**
 * Load and initialize WASM module
 */
async function ensureWasm() {
  if (wasmInstance) return;

  const { readFileSync } = await import('fs');
  const { fileURLToPath } = await import('url');
  const { dirname, join } = await import('path');

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);

  const wasmPath = join(__dirname, '../../build/randomx.wasm');
  const wasmBuffer = readFileSync(wasmPath);

  // Create memory (256MB cache + working space)
  wasmMemory = new WebAssembly.Memory({
    initial: 4096 + 512,  // ~288MB
    maximum: 8192         // 512MB max
  });

  const imports = {
    env: {
      memory: wasmMemory,
      abort: (msg, file, line, column) => {
        console.error(`WASM abort at ${file}:${line}:${column}`);
      }
    }
  };

  const wasmModule = await WebAssembly.instantiate(wasmBuffer, imports);
  wasmInstance = wasmModule.instance.exports;
}

/**
 * Initialize dataset generator with cache
 *
 * @param {Uint8Array} cacheMemory - The 256MB cache from Argon2d
 * @param {Array} programs - Pre-generated superscalar programs
 * @param {BigInt[]} reciprocals - Pre-computed reciprocals
 */
export async function initDatasetWasm(cacheMemory, programs, reciprocals) {
  await ensureWasm();

  const mem = new Uint8Array(wasmMemory.buffer);

  // Copy cache to WASM memory at offset 0
  cachePtr = 0;
  mem.set(cacheMemory, cachePtr);

  // Calculate cache line count
  cacheLineCount = cacheMemory.length / 64;

  // Initialize superscalar with cache pointer
  wasmInstance.superscalar_init(cachePtr, cacheLineCount);

  // Output buffer after cache
  outputPtr = cacheMemory.length + 1024;

  // Store programs and reciprocals for JS-side orchestration
  this._programs = programs;
  this._reciprocals = reciprocals;

  isInitialized = true;
}

/**
 * Generate a single dataset item using WASM
 *
 * @param {number} itemNumber - Dataset item index
 * @param {Array} programs - Pre-generated superscalar programs
 * @param {BigInt[]} reciprocals - Pre-computed reciprocals
 * @returns {Uint8Array} - 64-byte dataset item
 */
export async function initDatasetItemWasm(itemNumber, programs, reciprocals) {
  if (!isInitialized) {
    throw new Error('Dataset WASM not initialized. Call initDatasetWasm first.');
  }

  // Initialize registers for this item
  wasmInstance.init_registers(BigInt(itemNumber));

  // Process each cache access
  for (let i = 0; i < RANDOMX_CACHE_ACCESSES; i++) {
    const prog = programs[i];

    // Get address register value for cache lookup
    const registerValue = wasmInstance.get_address_reg(prog.addressRegister);

    // Mix cache block into registers
    wasmInstance.mix_cache_block(registerValue);

    // Execute superscalar program instructions
    for (const instr of prog.instructions) {
      if (instr.opcode === 13) {  // IMUL_RCP
        // Use pre-computed reciprocal (stored as index in imm32)
        const rcp = reciprocals[instr.imm32];
        wasmInstance.exec_imul_rcp(instr.dst, rcp);
      } else {
        wasmInstance.exec_instruction(
          instr.opcode,
          instr.dst,
          instr.src,
          instr.mod,
          instr.imm32
        );
      }
    }
  }

  // Write registers to output buffer
  wasmInstance.write_registers(outputPtr);

  // Read result
  const mem = new Uint8Array(wasmMemory.buffer);
  return mem.slice(outputPtr, outputPtr + 64);
}

/**
 * Generate dataset item synchronously (requires WASM to be loaded)
 */
export function initDatasetItemWasmSync(itemNumber, programs, reciprocals) {
  if (!wasmInstance) {
    throw new Error('WASM not loaded. Call ensureWasm() first.');
  }

  // Initialize registers for this item
  wasmInstance.init_registers(BigInt(itemNumber));

  // Process each cache access
  for (let i = 0; i < RANDOMX_CACHE_ACCESSES; i++) {
    const prog = programs[i];

    // Get address register value for cache lookup
    const registerValue = wasmInstance.get_address_reg(prog.addressRegister);

    // Mix cache block into registers
    wasmInstance.mix_cache_block(registerValue);

    // Execute superscalar program instructions
    for (const instr of prog.instructions) {
      if (instr.opcode === 13) {  // IMUL_RCP
        const rcp = reciprocals[instr.imm32];
        wasmInstance.exec_imul_rcp(instr.dst, rcp);
      } else {
        wasmInstance.exec_instruction(
          instr.opcode,
          instr.dst,
          instr.src,
          instr.mod,
          instr.imm32
        );
      }
    }
  }

  // Write registers to output buffer
  wasmInstance.write_registers(outputPtr);

  // Read result
  const mem = new Uint8Array(wasmMemory.buffer);
  return mem.slice(outputPtr, outputPtr + 64);
}

/**
 * Pre-load WASM module
 */
export async function preloadDatasetWasm() {
  await ensureWasm();
}

/**
 * Get WASM instance (for advanced use)
 */
export function getWasmInstance() {
  return wasmInstance;
}

/**
 * Get WASM memory (for advanced use)
 */
export function getWasmMemory() {
  return wasmMemory;
}

export default {
  initDatasetWasm,
  initDatasetItemWasm,
  initDatasetItemWasmSync,
  preloadDatasetWasm,
  getWasmInstance,
  getWasmMemory
};
