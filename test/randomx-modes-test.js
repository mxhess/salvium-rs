/**
 * Test both light mode and full mode RandomX
 */

import {
  RandomXContext,
  RandomXWorkerPool,
  RandomXFullMode,
  RandomXFullModePool,
  getAvailableCores,
  DATASET_SIZE,
  DATASET_ITEMS_COUNT
} from '../src/randomx/index.js';

async function testLightMode() {
  console.log('\n=== Testing Light Mode ===');

  const ctx = new RandomXContext();
  console.log('Creating RandomX context...');

  // Test with empty key and "This is a test" input
  const startInit = Date.now();
  await ctx.init(new Uint8Array(0)); // Empty key
  console.log(`Cache initialized in ${Date.now() - startInit}ms`);

  const hash = ctx.hashHex('This is a test');
  console.log('Hash result:', hash);
  console.log('Hash length:', hash.length, '(expected 64)');

  // Expected output from vendored randomx.js library
  // Note: This differs from canonical RandomX test vectors due to config differences
  const expected = '893c1fd44093e8fef463cd2467d2695123d794b6f3ad5c0c1765c24c5407c713';
  if (hash === expected) {
    console.log('✓ Hash matches expected value!');
  } else {
    console.log('✗ Hash mismatch!');
    console.log('  Expected:', expected);
    console.log('  Got:', hash);
  }

  // Also test consistency - hash the same input twice
  const hash2 = ctx.hashHex('This is a test');
  if (hash === hash2) {
    console.log('✓ Hash is deterministic (consistent output)');
  } else {
    console.log('✗ Hash is NOT deterministic!');
    return false;
  }

  return hash === expected;
}

async function testFullModeInit() {
  console.log('\n=== Testing Full Mode Initialization ===');

  const fullMode = new RandomXFullMode();
  console.log('Dataset constants:');
  console.log('  - Item count:', DATASET_ITEMS_COUNT.toLocaleString());
  console.log('  - Dataset size:', (DATASET_SIZE / (1024 * 1024 * 1024)).toFixed(2), 'GB');

  // Only test allocation, not full dataset generation
  console.log('Initializing full mode (cache only, no dataset generation)...');

  const startInit = Date.now();
  await fullMode.init('test key', {
    useSharedMemory: true,
    onProgress: (stage, pct, msg) => {
      console.log(`  [${stage}] ${pct}% - ${msg}`);
    }
  });
  console.log(`Full mode initialized in ${Date.now() - startInit}ms`);

  console.log('Full mode info:', fullMode.info);
  console.log('Using SharedArrayBuffer:', fullMode.isShared);

  return true;
}

async function testCores() {
  console.log('\n=== Testing Core Detection ===');
  const cores = getAvailableCores();
  console.log('Available CPU cores:', cores);
  return true;
}

async function main() {
  console.log('RandomX Modes Test');
  console.log('==================');

  let allPassed = true;

  try {
    allPassed = await testLightMode() && allPassed;
  } catch (e) {
    console.error('Light mode test failed:', e);
    allPassed = false;
  }

  try {
    await testCores();
  } catch (e) {
    console.error('Core detection failed:', e);
  }

  try {
    await testFullModeInit();
  } catch (e) {
    console.error('Full mode test failed:', e);
    allPassed = false;
  }

  console.log('\n==================');
  if (allPassed) {
    console.log('All tests passed!');
    process.exit(0);
  } else {
    console.log('Some tests failed!');
    process.exit(1);
  }
}

main().catch(console.error);
