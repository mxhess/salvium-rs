/**
 * WASM Module Loader
 *
 * Loads our AssemblyScript-compiled WASM for maximum performance.
 * Used for dataset generation and other compute-intensive operations.
 */

import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// WASM module singleton
let wasmInstance = null;
let wasmMemory = null;

// Memory layout constants
const PAGE_SIZE = 65536; // 64KB per WASM page
const INITIAL_PAGES = 4500; // ~280MB for cache + working space
const MAX_PAGES = 8192; // 512MB max

/**
 * Load the AssemblyScript WASM module
 *
 * @returns {Promise<Object>} WASM exports
 */
export async function loadWasm() {
  if (wasmInstance) {
    return wasmInstance.exports;
  }

  // Find the WASM file
  const currentDir = dirname(fileURLToPath(import.meta.url));
  const wasmPath = join(currentDir, '../../build/randomx.wasm');

  // Create memory
  wasmMemory = new WebAssembly.Memory({
    initial: INITIAL_PAGES,
    maximum: MAX_PAGES,
    shared: false
  });

  // Load and instantiate
  const wasmBytes = await readFile(wasmPath);

  const imports = {
    env: {
      memory: wasmMemory,
      abort: (msg, file, line, col) => {
        console.error(`WASM abort at ${file}:${line}:${col}`);
        throw new Error('WASM abort');
      }
    }
  };

  const module = await WebAssembly.instantiate(wasmBytes, imports);
  wasmInstance = module.instance;

  return wasmInstance.exports;
}

/**
 * Get WASM memory buffer
 *
 * @returns {ArrayBuffer}
 */
export function getMemory() {
  if (!wasmMemory) {
    throw new Error('WASM not loaded');
  }
  return wasmMemory.buffer;
}

/**
 * Allocate memory in WASM heap
 *
 * @param {number} size - Bytes to allocate
 * @returns {number} Pointer to allocated memory
 */
export async function allocate(size) {
  const exports = await loadWasm();
  return exports.allocate(size);
}

/**
 * Free WASM heap memory
 *
 * @param {number} ptr - Pointer to free
 */
export async function deallocate(ptr) {
  const exports = await loadWasm();
  exports.deallocate(ptr);
}

/**
 * Copy data to WASM memory
 *
 * @param {Uint8Array} data - Data to copy
 * @param {number} ptr - Destination pointer
 */
export function copyToWasm(data, ptr) {
  const mem = new Uint8Array(getMemory());
  mem.set(data, ptr);
}

/**
 * Copy data from WASM memory
 *
 * @param {number} ptr - Source pointer
 * @param {number} size - Bytes to copy
 * @returns {Uint8Array}
 */
export function copyFromWasm(ptr, size) {
  const mem = new Uint8Array(getMemory());
  return new Uint8Array(mem.buffer, ptr, size).slice();
}

/**
 * Get a view into WASM memory (no copy)
 *
 * @param {number} ptr - Pointer
 * @param {number} size - Size
 * @returns {Uint8Array}
 */
export function getWasmView(ptr, size) {
  return new Uint8Array(getMemory(), ptr, size);
}

export default {
  loadWasm,
  getMemory,
  allocate,
  deallocate,
  copyToWasm,
  copyFromWasm,
  getWasmView
};
