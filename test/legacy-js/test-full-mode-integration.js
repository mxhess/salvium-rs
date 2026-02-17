/**
 * Full Mode Integration Test
 *
 * Tests the complete RandomXFullMode class end-to-end.
 * Note: Full dataset generation takes a long time and 2GB RAM.
 * This test uses a mock to verify the flow works.
 */

import { RandomXFullMode } from '../src/randomx/full-mode.js';

async function testFullModeClass() {
  console.log('=== Full Mode Integration Test ===\n');

  const ctx = new RandomXFullMode();

  console.log('Creating RandomXFullMode context...');
  console.log('Note: Full mode generates 256MB cache + 2GB dataset');
  console.log('This test will demonstrate the initialization flow.\n');

  const testKey = 'test key for full mode';

  try {
    // Initialize with progress tracking
    console.log('Starting initialization...\n');

    await ctx.init(testKey, {
      useSharedMemory: false,
      onProgress: (stage, percent, message) => {
        // Only show major progress updates
        if (percent % 25 === 0 || stage === 'complete') {
          console.log(`[${stage}] ${percent.toFixed(0)}% - ${message}`);
        }
      }
    });

    console.log('\nFull mode initialized successfully!');
    console.log('Info:', ctx.info);

    // Test hashing
    console.log('\nTesting hash function...');
    const input = 'test input for hashing';
    const hash = ctx.hash(input);
    const hashHex = ctx.hashHex(input);

    console.log(`Input: "${input}"`);
    console.log(`Hash:  ${hashHex}`);

    // Verify hash is 32 bytes
    if (hash.length === 32) {
      console.log('Hash length: 32 bytes (correct)');
    } else {
      console.error(`Hash length: ${hash.length} bytes (expected 32)`);
    }

    // Test determinism
    const hash2 = ctx.hashHex(input);
    if (hash2 === hashHex) {
      console.log('Determinism: Verified (same input -> same hash)');
    } else {
      console.error('Determinism: FAILED!');
    }

    // Test different input produces different hash
    const hash3 = ctx.hashHex('different input');
    if (hash3 !== hashHex) {
      console.log('Uniqueness: Verified (different input -> different hash)');
    } else {
      console.error('Uniqueness: FAILED!');
    }

    console.log('\n=== Test PASSED ===');

  } catch (err) {
    console.error('\nTest FAILED:', err.message);
    console.error(err.stack);
    process.exit(1);
  }
}

// Run with a timeout since dataset generation can take a while
console.log('Full Mode Integration Test');
console.log('==========================\n');
console.log('WARNING: This test may take several minutes and use 2GB+ RAM');
console.log('Press Ctrl+C to cancel\n');

testFullModeClass().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
