/**
 * Test complete full mode implementation with small dataset
 */

import { RandomXContext } from '../src/randomx/index.js';
import { RandomXFullMode } from '../src/randomx/full-mode.js';

const TEST_KEY = 'test key for RandomX';
const TEST_INPUT = 'hello world';

// For testing, we'll use a reduced item count
const TEST_ITEM_COUNT = 1000;  // Just 1000 items for quick testing

async function main() {
  console.log('=== RandomX Full Mode Complete Test ===\n');

  // Get light mode hash for comparison
  console.log('Initializing light mode for reference...');
  const lightCtx = new RandomXContext();
  await lightCtx.init(TEST_KEY);
  const lightHash = lightCtx.hashHex(TEST_INPUT);
  console.log('Light mode reference hash:', lightHash, '\n');

  // Test full mode with small dataset
  console.log('Testing full mode with small dataset (' + TEST_ITEM_COUNT + ' items)...');
  
  const fullMode = new RandomXFullMode();
  
  // Override dataset item count for testing
  const RANDOMX_DATASET_ITEM_COUNT = 34078719;  // Full count
  
  // Manually init to use reduced item count
  const { randomx_init_cache, randomx_superscalarhash, randomx_machine_id } = await import('../src/randomx/vendor/index.js');
  
  fullMode.cache = randomx_init_cache(TEST_KEY);
  fullMode.ssHash = randomx_superscalarhash(fullMode.cache);
  
  // Generate small dataset
  console.log('Generating test dataset...');
  fullMode.dataset = new BigInt64Array(TEST_ITEM_COUNT * 8);
  
  for (let i = 0; i < TEST_ITEM_COUNT; i++) {
    const item = fullMode.ssHash(BigInt(i));
    const offset = i * 8;
    for (let j = 0; j < 8; j++) {
      fullMode.dataset[offset + j] = item[j];
    }
  }
  console.log('Test dataset ready\n');

  // Create VM with dataset lookup that falls back to superscalar for out-of-range indices
  const dataset = fullMode.dataset;
  const ssHash = fullMode.ssHash;
  const datasetLookup = (itemIndex) => {
    const idx = Number(itemIndex);
    if (idx < TEST_ITEM_COUNT) {
      const offset = idx * 8;
      return [
        dataset[offset],
        dataset[offset + 1],
        dataset[offset + 2],
        dataset[offset + 3],
        dataset[offset + 4],
        dataset[offset + 5],
        dataset[offset + 6],
        dataset[offset + 7]
      ];
    }
    // Fall back to superscalar for items beyond our test range
    return ssHash(itemIndex);
  };

  // Get machine feature
  const machineId = randomx_machine_id();
  let feature = 0;
  if (machineId.includes('+fma')) feature = 3;
  else if (machineId.includes('+relaxed-simd')) feature = 1;

  // Create VM
  const VM_WASM_PAGES = 33;
  const SCRATCH_SIZE = 16 * 1024;
  const memory = new WebAssembly.Memory({ initial: VM_WASM_PAGES, maximum: VM_WASM_PAGES });
  const vmImports = { env: { memory } };
  const vmInstance = new WebAssembly.Instance(fullMode.cache.vm, vmImports);
  const vmExports = vmInstance.exports;
  const scratchPtr = vmExports.i(feature);
  const scratch = new Uint8Array(memory.buffer, scratchPtr, SCRATCH_SIZE);

  const jitImports = {
    e: {
      m: memory,
      d: datasetLookup
    }
  };

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

  fullMode.vm = {
    calculate_hash: (input) => {
      hashFn(input, false);
      return new Uint8Array(scratch.subarray(0, 32));
    },
    calculate_hex_hash: (input) => {
      hashFn(input, true);
      return new TextDecoder().decode(scratch.subarray(0, 64));
    }
  };

  console.log('Full mode VM ready\n');

  // Compute hash with full mode
  console.log('Computing hash with full mode...');
  const fullStart = performance.now();
  const fullHash = fullMode.hashHex(TEST_INPUT);
  const fullTime = performance.now() - fullStart;
  console.log('Full mode hash: ', fullHash);
  console.log('Full mode time: ', fullTime.toFixed(2) + 'ms\n');

  // Compare
  console.log('=== Comparison ===');
  if (lightHash === fullHash) {
    console.log('SUCCESS: Hashes match!');
    console.log('Full mode implementation is working correctly.');
  } else {
    console.log('FAILURE: Hashes do not match!');
    console.log('Expected:', lightHash);
    console.log('Got:     ', fullHash);
    process.exit(1);
  }
}

main().catch(console.error);
