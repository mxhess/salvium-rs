/**
 * Debug full mode worker - run in main thread
 */

import { randomx_init_cache, randomx_superscalarhash, randomx_machine_id } from '../src/randomx/vendor/index.js';
import { RANDOMX_DATASET_ITEM_COUNT } from '../src/randomx/full-mode.js';

const VM_WASM_PAGES = 33;
const SCRATCH_SIZE = 16 * 1024;
const JIT_BASELINE = 0;
const JIT_RELAXED_SIMD = 1;
const JIT_FMA = 2;

const TEST_SEED = '33d64e8899b07bcc1234567890abcdef1234567890abcdef1234567890abcdef';

function detectJitFeature() {
  const machineId = randomx_machine_id();
  if (machineId.includes('+fma')) return JIT_FMA | JIT_RELAXED_SIMD;
  if (machineId.includes('+relaxed-simd')) return JIT_RELAXED_SIMD;
  return JIT_BASELINE;
}

function hexToBytes(hex) {
  if (hex.startsWith('0x')) hex = hex.slice(2);
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

async function main() {
  console.log('=== Full Mode Debug Test ===\n');

  // Initialize cache
  console.log('Initializing cache...');
  const seedBytes = Buffer.from(TEST_SEED, 'hex');
  const cache = randomx_init_cache(seedBytes);
  const ssHash = randomx_superscalarhash(cache);
  console.log('Cache ready');

  // Create small dataset (1000 items)
  console.log('Creating dataset (1000 items)...');
  const TEST_ITEMS = 1000;
  const datasetSize = RANDOMX_DATASET_ITEM_COUNT * 8 * 8;
  const sharedBuffer = new SharedArrayBuffer(datasetSize);
  const datasetView = new BigInt64Array(sharedBuffer);
  
  for (let i = 0; i < TEST_ITEMS; i++) {
    const item = ssHash(BigInt(i));
    const offset = i * 8;
    for (let j = 0; j < 8; j++) {
      datasetView[offset + j] = item[j];
    }
  }
  console.log('Dataset ready');

  // Create VM
  console.log('Creating VM...');
  const jitFeature = detectJitFeature();
  console.log('JIT feature:', jitFeature);

  try {
    const memory = new WebAssembly.Memory({ initial: VM_WASM_PAGES, maximum: VM_WASM_PAGES });
    console.log('Memory created');
    
    const vmImports = { env: { memory } };
    const vmInstance = new WebAssembly.Instance(cache.vm, vmImports);
    console.log('VM instance created');
    
    const vmExports = vmInstance.exports;
    const scratchPtr = vmExports.i(jitFeature);
    console.log('Scratch ptr:', scratchPtr);
    
    const scratch = new Uint8Array(memory.buffer, scratchPtr, SCRATCH_SIZE);

    // Dataset lookup that falls back to ssHash for items beyond our test range
    const datasetLookup = (itemIndex) => {
      const idx = Number(itemIndex);
      if (idx < TEST_ITEMS) {
        const offset = idx * 8;
        return [
          datasetView[offset],
          datasetView[offset + 1],
          datasetView[offset + 2],
          datasetView[offset + 3],
          datasetView[offset + 4],
          datasetView[offset + 5],
          datasetView[offset + 6],
          datasetView[offset + 7]
        ];
      }
      // Fall back to superscalar for items beyond test range
      return ssHash(itemIndex);
    };

    const jitImports = {
      e: {
        m: memory,
        d: datasetLookup
      }
    };

    // Hash function
    const hashFn = (input, isHex) => {
      if (typeof input === 'string') {
        input = new TextEncoder().encode(input);
      }
      vmExports.I(isHex);
      if (input.length <= SCRATCH_SIZE) {
        scratch.set(input);
        vmExports.H(input.length);
      } else {
        let p = 0;
        while (p < input.length) {
          const chunk = input.subarray(p, p + SCRATCH_SIZE);
          p += SCRATCH_SIZE;
          scratch.set(chunk);
          vmExports.H(chunk.length);
        }
      }
      let jitSize;
      while (true) {
        jitSize = vmExports.R();
        if (jitSize === 0) break;
        const jitModule = new WebAssembly.Module(scratch.subarray(0, jitSize));
        const jitInstance = new WebAssembly.Instance(jitModule, jitImports);
        jitInstance.exports.d();
      }
    };

    const vm = {
      calculate_hash: (input) => {
        hashFn(input, false);
        return new Uint8Array(scratch.subarray(0, 32));
      }
    };

    console.log('VM created successfully\n');

    // Test hashing with a real job blob
    const testBlob = '0707a5e28db705ede4b8bef6e9dbf2f0d2e2d0d0e5d0d4b8e0d5d0c8c0d0d4b8e5e0c0d0d0c0b8e0e0d0d0b8c0e0d4d0b8';
    console.log('Testing hash with blob:', testBlob.substring(0, 32) + '...');
    
    const blobBytes = hexToBytes(testBlob);
    console.log('Blob bytes length:', blobBytes.length);
    
    console.log('Computing hash...');
    const startTime = performance.now();
    const hash = vm.calculate_hash(blobBytes);
    const elapsed = performance.now() - startTime;
    
    console.log('Hash computed in', elapsed.toFixed(2), 'ms');
    console.log('Hash:', Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join(''));
    
    // Test multiple hashes
    console.log('\nComputing 5 hashes...');
    const start = performance.now();
    for (let i = 0; i < 5; i++) {
      const template = new Uint8Array(blobBytes);
      const view = new DataView(template.buffer);
      view.setUint32(39, i, true);  // Set nonce
      vm.calculate_hash(template);
      console.log('  Hash', i+1, 'done');
    }
    const total = performance.now() - start;
    console.log('5 hashes in', total.toFixed(2), 'ms');
    console.log('Average:', (total / 5).toFixed(2), 'ms/hash');
    console.log('Hashrate:', (5 / (total / 1000)).toFixed(2), 'H/s');

  } catch (err) {
    console.error('Error:', err);
    console.error('Stack:', err.stack);
  }
}

main().catch(console.error);
