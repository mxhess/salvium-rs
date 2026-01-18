/**
 * Mining Worker - AssemblyScript VM
 *
 * Uses the AssemblyScript-compiled WASM VM for maximum performance.
 * Full mode with pre-computed dataset.
 */

import { parentPort, workerData } from 'worker_threads';
import { readFile } from 'fs/promises';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { blake2b } from '../blake2b.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = join(__dirname, '../../build/randomx.wasm');

// Sizes
const SCRATCHPAD_SIZE = 2 * 1024 * 1024;
const PROGRAM_SIZE = 256 * 8;
const REGISTER_FILE_SIZE = 256;
const SEED_SIZE = 64;

// Worker state
let exports = null;
let memory = null;
let scratchpadPtr = 0;
let programPtr = 0;
let outputPtr = 0;
let seedPtr = 0;
let datasetPtr = 0;
let datasetView = null;
let seedHash = null;
let currentJob = null;
let mining = false;
let nonce = 0;
let hashCount = 0;
let jobGeneration = 0;

/**
 * Load WASM module
 */
async function loadWasm() {
  const wasmBuffer = await readFile(WASM_PATH);
  const module = await WebAssembly.compile(wasmBuffer);

  // Calculate memory needs
  const testDatasetSize = 64 * 1024;  // 64KB for testing
  const memorySize = SCRATCHPAD_SIZE + PROGRAM_SIZE + REGISTER_FILE_SIZE + SEED_SIZE + testDatasetSize + 4096;
  const pages = Math.ceil(memorySize / 65536);

  memory = new WebAssembly.Memory({ initial: pages, maximum: pages });

  const instance = await WebAssembly.instantiate(module, {
    env: {
      memory,
      abort: () => {}
    }
  });

  exports = instance.exports;

  // Set up memory layout
  scratchpadPtr = 0;
  programPtr = SCRATCHPAD_SIZE;
  outputPtr = SCRATCHPAD_SIZE + PROGRAM_SIZE;
  seedPtr = SCRATCHPAD_SIZE + PROGRAM_SIZE + REGISTER_FILE_SIZE;
  datasetPtr = SCRATCHPAD_SIZE + PROGRAM_SIZE + REGISTER_FILE_SIZE + SEED_SIZE;

  return exports;
}

/**
 * Initialize with dataset
 */
async function initWithDataset(sharedBuffer, seed) {
  if (!exports) {
    await loadWasm();
  }

  // Create view of shared dataset
  datasetView = new BigInt64Array(sharedBuffer);

  // Copy portion of dataset into WASM memory for now
  const memView = new Uint8Array(memory.buffer);
  const testDatasetSize = Math.min(sharedBuffer.byteLength, 64 * 1024);
  const datasetBytes = new Uint8Array(sharedBuffer, 0, testDatasetSize);
  memView.set(datasetBytes, datasetPtr);

  // Initialize VM
  exports.vm_init(scratchpadPtr, datasetPtr, programPtr, 1);
  exports.vm_set_dataset_size(BigInt(testDatasetSize / 64));

  seedHash = seed;
  parentPort.postMessage({ type: 'initialized', seedHash });
}

/**
 * Read u64 from byte array
 */
function readU64(arr, off) {
  let v = 0n;
  for (let i = 0; i < 8; i++) {
    v |= BigInt(arr[off + i]) << BigInt(i * 8);
  }
  return v;
}

/**
 * Convert u64 to small positive float
 */
function getSmallFloat(val) {
  const exponent = ((val >> 59n) & 0xFn) + 0x3F8n;
  const mantissa = val & 0x7FFFFFFFFFFFFn;
  const bits = (exponent << 52n) | mantissa;
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, bits, true);
  return view.getFloat64(0, true);
}

/**
 * Calculate hash using AssemblyScript VM
 */
function calculateHash(input) {
  const memView = new Uint8Array(memory.buffer);

  // Generate 64-byte seed from input
  const seed = blake2b(input, 64);

  // Reset VM
  exports.vm_reset();

  // Fill scratchpad with AES
  memView.set(seed, seedPtr);
  exports.fillScratchpad(seedPtr, scratchpadPtr, SCRATCHPAD_SIZE);

  // Generate program with AES
  memView.set(seed, seedPtr);
  exports.fillScratchpad(seedPtr, programPtr, PROGRAM_SIZE);

  // Read program for config
  const programView = new Uint8Array(memory.buffer, programPtr, PROGRAM_SIZE);
  const ma = readU64(programView, 0);
  const mx = readU64(programView, 8);
  const addrReg = readU64(programView, 80);

  exports.vm_set_config(
    ma, mx,
    Number(addrReg & 7n),
    Number((addrReg >> 3n) & 7n),
    Number((addrReg >> 6n) & 7n),
    Number((addrReg >> 9n) & 7n),
    0n, 0x3F00000000000000n, 0x3F00000000000000n
  );

  exports.vm_set_a_registers(
    getSmallFloat(readU64(programView, 0)),
    getSmallFloat(readU64(programView, 8)),
    getSmallFloat(readU64(programView, 16)),
    getSmallFloat(readU64(programView, 24)),
    getSmallFloat(readU64(programView, 32)),
    getSmallFloat(readU64(programView, 40)),
    getSmallFloat(readU64(programView, 48)),
    getSmallFloat(readU64(programView, 56))
  );

  // Execute VM
  exports.vm_execute();

  // Get register file
  exports.vm_get_register_file(outputPtr);
  const regFile = new Uint8Array(memory.buffer, outputPtr, REGISTER_FILE_SIZE);

  // Final Blake2b hash
  return blake2b(regFile, 32);
}

function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function targetToBytes(targetHex) {
  return hexToBytes(targetHex.padStart(64, '0'));
}

function checkTarget(hash, target) {
  for (let i = 0; i < 32; i++) {
    if (hash[i] < target[i]) return true;
    if (hash[i] > target[i]) return false;
  }
  return true;
}

/**
 * Start mining
 */
function startMining(job, startNonce) {
  const myGeneration = ++jobGeneration;
  currentJob = job;
  nonce = startNonce;
  mining = true;

  let blob, target;
  try {
    blob = hexToBytes(job.blob);
    target = targetToBytes(job.target);
  } catch (err) {
    parentPort.postMessage({ type: 'error', message: 'Failed to parse job: ' + err.message });
    return;
  }

  const nonceOffset = 39;
  const template = new Uint8Array(blob);
  const view = new DataView(template.buffer);

  const mine = () => {
    if (!mining || myGeneration !== jobGeneration) return;

    try {
      const batchSize = 5;

      for (let i = 0; i < batchSize && mining && myGeneration === jobGeneration; i++) {
        view.setUint32(nonceOffset, nonce, true);
        const hash = calculateHash(template);
        hashCount++;
        nonce++;

        if (checkTarget(hash, target)) {
          const nonceHex = (nonce - 1).toString(16).padStart(8, '0');
          const resultHex = bytesToHex(hash);
          parentPort.postMessage({
            type: 'share',
            nonce: nonceHex,
            result: resultHex,
            jobId: job.job_id
          });
        }
      }

      if (mining && myGeneration === jobGeneration) {
        setTimeout(mine, 1);
      }
    } catch (err) {
      parentPort.postMessage({ type: 'error', message: 'Mining error: ' + err.message });
    }
  };

  mine();
}

function stopMining() {
  mining = false;
}

// Message handler
parentPort.on('message', async (msg) => {
  switch (msg.type) {
    case 'init':
      if (msg.dataset) {
        await initWithDataset(msg.dataset, msg.seedHash);
      }
      break;

    case 'job':
      if (msg.dataset && msg.seedHash !== seedHash) {
        await initWithDataset(msg.dataset, msg.seedHash);
      }
      if (exports) {
        startMining(msg.job, msg.startNonce);
      } else {
        parentPort.postMessage({ type: 'error', message: 'VM not initialized' });
      }
      break;

    case 'stop':
      stopMining();
      parentPort.postMessage({ type: 'stopped', hashCount });
      break;

    case 'getHashCount':
      parentPort.postMessage({ type: 'hashCount', count: hashCount });
      hashCount = 0;
      break;
  }
});

// Proactive hash reporting
setInterval(() => {
  if (hashCount > 0) {
    parentPort.postMessage({ type: 'hashCount', count: hashCount });
    hashCount = 0;
  }
}, 5000);

// Ready
parentPort.postMessage({ type: 'ready', workerId: workerData?.workerId, mode: 'asm' });
