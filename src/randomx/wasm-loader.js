/**
 * WASM Loader for RandomX
 *
 * Loads and initializes the WASM module with proper memory setup.
 */

import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

let wasmInstance = null;
let wasmMemory = null;

/**
 * Load and initialize WASM module
 */
export async function loadWasm() {
  if (wasmInstance) return wasmInstance;

  const wasmPath = join(__dirname, '../../build/randomx.wasm');
  const wasmBuffer = readFileSync(wasmPath);

  // Create memory (256MB + extra for working space)
  // 256MB = 262144 KB = 268435456 bytes = 4096 pages (64KB each)
  wasmMemory = new WebAssembly.Memory({
    initial: 4096 + 256,  // 256MB + 16MB working space
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

  return wasmInstance;
}

/**
 * Get WASM memory as Uint8Array
 */
export function getMemory() {
  if (!wasmMemory) throw new Error('WASM not loaded');
  return new Uint8Array(wasmMemory.buffer);
}

/**
 * Get WASM exports
 */
export function getWasm() {
  if (!wasmInstance) throw new Error('WASM not loaded');
  return wasmInstance;
}

export default {
  loadWasm,
  getMemory,
  getWasm
};
