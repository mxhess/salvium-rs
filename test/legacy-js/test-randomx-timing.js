/**
 * Test RandomX Timing
 *
 * Measures initialization and hashing times separately.
 */

import { randomx_init_cache, randomx_create_vm } from '../src/randomx/vendor/index.js';

async function main() {
  console.log('RandomX Timing Test');
  console.log('===================\n');

  // Measure cache initialization
  console.log('1. Cache initialization (256MB)...');
  const seedHash = new TextEncoder().encode('test seed hash');

  const cacheStart = Date.now();
  const cache = randomx_init_cache(seedHash);
  const cacheTime = Date.now() - cacheStart;
  console.log(`   Cache init time: ${(cacheTime / 1000).toFixed(2)}s\n`);

  // Measure VM creation
  console.log('2. VM creation...');
  const vmStart = Date.now();
  const vm = randomx_create_vm(cache);
  const vmTime = Date.now() - vmStart;
  console.log(`   VM creation time: ${vmTime}ms\n`);

  // Measure hashing
  console.log('3. Hashing (10 hashes)...');
  const template = new Uint8Array(76);
  const view = new DataView(template.buffer);

  const hashStart = Date.now();
  for (let i = 0; i < 10; i++) {
    view.setUint32(39, i, true);
    const hash = vm.calculate_hash(template);
    if (i === 0) {
      const hashHex = Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
      console.log(`   First hash: ${hashHex.substring(0, 16)}...`);
    }
  }
  const hashTime = Date.now() - hashStart;
  const hps = 10 / (hashTime / 1000);
  console.log(`   10 hashes in ${hashTime}ms (${hps.toFixed(2)} H/s)\n`);

  console.log('Summary:');
  console.log(`   - Cache init: ${(cacheTime / 1000).toFixed(2)}s (one-time cost)`);
  console.log(`   - VM creation: ${vmTime}ms (one-time cost)`);
  console.log(`   - Hash rate: ~${hps.toFixed(1)} H/s`);
}

main().catch(console.error);
