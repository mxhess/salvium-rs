/**
 * Benchmark: Interpreted VM vs Vendored JIT
 */

import { randomx_init_cache, randomx_create_vm } from '../src/randomx/vendor/index.js';
import { RandomXVM } from '../src/randomx/vm.js';
import { RandomXCache } from '../src/randomx/dataset.js';
import { blake2b } from '../src/blake2b.js';

const TEST_SEED = Buffer.from('33d64e8899b07bcc1234567890abcdef1234567890abcdef1234567890abcdef', 'hex');
const TEST_INPUT = Buffer.from('This is a test input for RandomX hashing benchmark');

async function benchmarkVendored(numHashes) {
  console.log(`\n=== Vendored JIT (${numHashes} hashes) ===`);

  const cache = randomx_init_cache(TEST_SEED);
  const vm = randomx_create_vm(cache);

  const start = performance.now();
  for (let i = 0; i < numHashes; i++) {
    const input = Buffer.concat([TEST_INPUT, Buffer.from([i])]);
    vm.calculate_hash(input);
  }
  const elapsed = performance.now() - start;

  console.log(`Time: ${elapsed.toFixed(2)}ms`);
  console.log(`Per hash: ${(elapsed / numHashes).toFixed(2)}ms`);
  console.log(`Hashrate: ${(numHashes / (elapsed / 1000)).toFixed(2)} H/s`);

  return elapsed;
}

async function benchmarkInterpreted(numHashes) {
  console.log(`\n=== Interpreted JS (${numHashes} hashes) ===`);

  // Initialize cache using the proper RandomXCache class
  const cache = new RandomXCache();
  console.log('Initializing cache (this may take a moment)...');
  const cacheStart = performance.now();
  cache.init(TEST_SEED);
  console.log(`Cache init: ${(performance.now() - cacheStart).toFixed(0)}ms`);

  const vm = new RandomXVM(cache);

  const start = performance.now();
  for (let i = 0; i < numHashes; i++) {
    const input = Buffer.concat([TEST_INPUT, Buffer.from([i])]);

    // Generate seed from input
    const seed = blake2b(input, 64);

    vm.initScratchpad(seed);
    vm.run(seed);
    const hash = vm.getFinalResult();
  }
  const elapsed = performance.now() - start;

  console.log(`Time: ${elapsed.toFixed(2)}ms`);
  console.log(`Per hash: ${(elapsed / numHashes).toFixed(2)}ms`);
  console.log(`Hashrate: ${(numHashes / (elapsed / 1000)).toFixed(2)} H/s`);

  return elapsed;
}

async function main() {
  console.log('RandomX VM Benchmark');
  console.log('====================');

  const numHashes = 5;

  try {
    await benchmarkVendored(numHashes);
  } catch (err) {
    console.log('Vendored error:', err.message);
  }

  try {
    await benchmarkInterpreted(numHashes);
  } catch (err) {
    console.log('Interpreted error:', err.message);
  }
}

main().catch(console.error);
