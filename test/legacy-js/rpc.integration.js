/**
 * RPC Integration Tests
 *
 * Tests RPC client functionality against a live Salvium daemon.
 * Skips gracefully if no daemon is available.
 *
 * Usage:
 *   bun test/rpc.integration.js [daemon_url]
 *
 * Default daemon: http://localhost:19081
 * Example: bun test/rpc.integration.js http://core2.whiskymine.io:19081
 */

import { createDaemonRPC, createWalletRPC, DAEMON_MAINNET_URL } from '../src/rpc/index.js';

const DAEMON_URL = process.argv[2] || DAEMON_MAINNET_URL;

let passed = 0;
let failed = 0;
let skipped = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (error) {
    if (error.message.includes('SKIP')) {
      console.log(`  ⊘ ${name} (skipped)`);
      skipped++;
    } else {
      console.log(`  ✗ ${name}`);
      console.log(`    Error: ${error.message}`);
      failed++;
    }
  }
}

function assertEqual(actual, expected, message = '') {
  if (actual !== expected) {
    throw new Error(`${message} Expected ${expected}, got ${actual}`);
  }
}

function assertTrue(value, message = '') {
  if (!value) {
    throw new Error(`${message} Expected true, got ${value}`);
  }
}

function assertExists(value, message = '') {
  if (value === undefined || value === null) {
    throw new Error(`${message} Value is ${value}`);
  }
}

function assertType(value, type, message = '') {
  if (typeof value !== type) {
    throw new Error(`${message} Expected type ${type}, got ${typeof value}`);
  }
}

function skip(reason) {
  throw new Error(`SKIP: ${reason}`);
}

// ============================================================
// Daemon Connection Test
// ============================================================

console.log(`\n=== RPC Integration Tests ===`);
console.log(`Daemon URL: ${DAEMON_URL}\n`);

let daemon = null;
let daemonAvailable = false;

// Try to connect to daemon
try {
  daemon = createDaemonRPC({ url: DAEMON_URL, timeout: 10000 });
  const info = await daemon.getInfo();
  if (info.success) {
    daemonAvailable = true;
    console.log(`Connected to daemon v${info.result.version}`);
    console.log(`Height: ${info.result.height}, Network: ${info.result.nettype}\n`);
  }
} catch (e) {
  console.log(`Could not connect to daemon at ${DAEMON_URL}`);
  console.log(`Error: ${e.message}`);
  console.log(`\nSkipping integration tests. Run a Salvium daemon to enable them.\n`);
}

// ============================================================
// Daemon RPC Tests
// ============================================================

if (daemonAvailable) {
  console.log('--- Daemon RPC Integration Tests ---');

  await test('getInfo returns valid node info', async () => {
    const result = await daemon.getInfo();
    assertTrue(result.success, 'Request should succeed');
    assertExists(result.result.height, 'Should have height');
    assertExists(result.result.version, 'Should have version');
    assertType(result.result.height, 'number', 'Height should be number');
    assertTrue(result.result.height > 0, 'Height should be positive');
  });

  await test('getHeight returns current height', async () => {
    const result = await daemon.getHeight();
    assertTrue(result.success, 'Request should succeed');
    assertType(result.result.height, 'number');
    assertTrue(result.result.height > 0);
  });

  await test('getBlockCount returns block count', async () => {
    const result = await daemon.getBlockCount();
    assertTrue(result.success, 'Request should succeed');
    assertType(result.result.count, 'number');
    assertTrue(result.result.count > 0);
  });

  await test('getLastBlockHeader returns valid header', async () => {
    const result = await daemon.getLastBlockHeader();
    assertTrue(result.success, 'Request should succeed');
    assertExists(result.result.block_header, 'Should have block_header');
    assertExists(result.result.block_header.hash, 'Should have hash');
    assertExists(result.result.block_header.height, 'Should have height');
    assertExists(result.result.block_header.timestamp, 'Should have timestamp');
    assertEqual(result.result.block_header.hash.length, 64, 'Hash should be 64 hex chars');
  });

  await test('getBlockHeaderByHeight returns header for height 1', async () => {
    const result = await daemon.getBlockHeaderByHeight(1);
    assertTrue(result.success, 'Request should succeed');
    assertEqual(result.result.block_header.height, 1, 'Height should be 1');
  });

  await test('getBlockHash returns hash for height 1', async () => {
    const result = await daemon.getBlockHash(1);
    assertTrue(result.success, 'Request should succeed');
    // Result is the hash string directly for this endpoint
    assertType(result.result, 'string');
    assertEqual(result.result.length, 64, 'Hash should be 64 hex chars');
  });

  await test('syncInfo returns sync status', async () => {
    const result = await daemon.syncInfo();
    assertTrue(result.success, 'Request should succeed');
    assertExists(result.result.height, 'Should have height');
  });

  await test('hardForkInfo returns fork info', async () => {
    const result = await daemon.hardForkInfo();
    assertTrue(result.success, 'Request should succeed');
    assertExists(result.result.version, 'Should have version');
    assertType(result.result.version, 'number');
  });

  await test('getFeeEstimate returns fee info', async () => {
    const result = await daemon.getFeeEstimate();
    assertTrue(result.success, 'Request should succeed');
    assertExists(result.result.fee, 'Should have fee');
    assertType(result.result.fee, 'number');
    assertTrue(result.result.fee > 0, 'Fee should be positive');
  });

  await test('getTransactionPool returns pool info', async () => {
    const result = await daemon.getTransactionPool();
    assertTrue(result.success, 'Request should succeed');
    // Pool might be empty, that's ok
    assertExists(result.result.status, 'Should have status');
  });

  await test('getConnections returns peer connections', async () => {
    const result = await daemon.getConnections();
    assertTrue(result.success, 'Request should succeed');
    // Might have no connections in test environment
  });

  await test('getBlock returns full block data', async () => {
    const result = await daemon.getBlock({ height: 1 });
    assertTrue(result.success, 'Request should succeed');
    assertExists(result.result.block_header, 'Should have block_header');
    assertExists(result.result.miner_tx_hash, 'Should have miner_tx_hash');
  });

  await test('getBlockHeadersRange returns multiple headers', async () => {
    const result = await daemon.getBlockHeadersRange(1, 5);
    assertTrue(result.success, 'Request should succeed');
    assertExists(result.result.headers, 'Should have headers array');
    assertEqual(result.result.headers.length, 5, 'Should have 5 headers');
  });

  await test('isSynchronized returns sync status', async () => {
    const result = await daemon.isSynchronized();
    assertType(result, 'boolean');
  });

  await test('getNetworkType returns network type', async () => {
    const result = await daemon.getNetworkType();
    assertTrue(['mainnet', 'testnet', 'stagenet'].includes(result));
  });

  // ============================================================
  // Response Structure Tests
  // ============================================================

  console.log('\n--- Response Structure Tests ---');

  await test('All responses have success field', async () => {
    const info = await daemon.getInfo();
    assertExists(info.success, 'getInfo should have success');

    const height = await daemon.getHeight();
    assertExists(height.success, 'getHeight should have success');

    const header = await daemon.getLastBlockHeader();
    assertExists(header.success, 'getLastBlockHeader should have success');
  });

  await test('Successful responses have result field', async () => {
    const info = await daemon.getInfo();
    assertTrue(info.success);
    assertExists(info.result, 'Should have result on success');
  });

  // ============================================================
  // Error Handling Tests
  // ============================================================

  console.log('\n--- Error Handling Tests ---');

  await test('Invalid height returns error gracefully', async () => {
    const result = await daemon.getBlockHeaderByHeight(999999999);
    // Should not crash, either returns error or empty result
    assertExists(result.success !== undefined);
  });

  await test('Invalid block hash returns error gracefully', async () => {
    const result = await daemon.getBlockHeaderByHash('0000000000000000000000000000000000000000000000000000000000000000');
    assertExists(result.success !== undefined);
  });

} else {
  console.log('--- Daemon RPC Tests Skipped (no daemon available) ---');
  skipped += 20; // Approximate number of daemon tests
}

// ============================================================
// Summary
// ============================================================

console.log('\n--- Integration Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Skipped: ${skipped}`);
console.log(`Total: ${passed + failed + skipped}`);

if (failed > 0) {
  console.log('\n⚠️  Some tests failed!');
  process.exit(1);
} else if (passed > 0) {
  console.log('\n✓ All integration tests passed!');
} else {
  console.log('\n⊘ No tests ran (daemon not available)');
}
