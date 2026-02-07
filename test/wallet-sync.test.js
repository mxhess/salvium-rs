#!/usr/bin/env bun
/**
 * Wallet Sync Engine Tests
 *
 * Tests for wallet-sync.js:
 * - WalletSync class
 * - Event system
 * - Progress tracking
 * - Mock daemon interaction
 */

import {
  WalletSync,
  createWalletSync,
  SYNC_STATUS,
  DEFAULT_BATCH_SIZE,
  SYNC_UNLOCK_BLOCKS
} from '../src/wallet-sync.js';
import { MemoryStorage, WalletOutput } from '../src/wallet-store.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

// ============================================================================
// Mock Daemon
// ============================================================================

class MockDaemon {
  constructor(options = {}) {
    this.height = options.height || 1000;
    this.blocks = options.blocks || [];
    this.transactions = options.transactions || {};
    this.callLog = [];
  }

  async getInfo() {
    this.callLog.push('getInfo');
    return {
      success: true,
      result: {
        height: this.height,
        status: 'OK'
      }
    };
  }

  async getBlockHeadersRange(start, end) {
    this.callLog.push(`getBlockHeadersRange(${start}, ${end})`);
    const headers = [];
    for (let h = start; h <= end && h < this.height; h++) {
      headers.push({
        height: h,
        hash: `block_hash_${h}`,
        timestamp: 1700000000 + h * 120
      });
    }
    return {
      success: true,
      result: { headers }
    };
  }

  async getBlock(opts) {
    const height = opts.height;
    this.callLog.push(`getBlock(${height})`);
    return {
      success: true,
      result: {
        block_header: {
          height,
          hash: `block_hash_${height}`,
          timestamp: 1700000000 + height * 120
        },
        tx_hashes: this.blocks[height]?.txHashes || [],
        miner_tx_hash: `miner_tx_${height}`
      }
    };
  }

  async getTransactions(txHashes, opts) {
    this.callLog.push(`getTransactions([${txHashes.join(',')}])`);
    const txs = txHashes.map(hash => ({
      tx_hash: hash,
      as_hex: this.transactions[hash] || '00'
    }));
    return {
      success: true,
      result: { txs }
    };
  }

  async getBlocksByHeight(heights) {
    this.callLog.push(`getBlocksByHeight([${heights.join(',')}])`);
    // Return failure to trigger individual block fetch fallback
    return { success: false };
  }

  async getTransactionPool() {
    this.callLog.push('getTransactionPool');
    return {
      success: true,
      result: { transactions: [] }
    };
  }
}

console.log('=== Wallet Sync Engine Tests ===\n');

// ============================================================================
// Constants Tests
// ============================================================================

console.log('--- Constants ---');

test('SYNC_STATUS has correct values', () => {
  assertEqual(SYNC_STATUS.IDLE, 'idle');
  assertEqual(SYNC_STATUS.SYNCING, 'syncing');
  assertEqual(SYNC_STATUS.COMPLETE, 'complete');
  assertEqual(SYNC_STATUS.ERROR, 'error');
});

test('DEFAULT_BATCH_SIZE is 100', () => {
  assertEqual(DEFAULT_BATCH_SIZE, 100);
});

test('SYNC_UNLOCK_BLOCKS is 10', () => {
  assertEqual(SYNC_UNLOCK_BLOCKS, 10);
});

// ============================================================================
// WalletSync Construction Tests
// ============================================================================

console.log('\n--- WalletSync Construction ---');

test('creates sync engine with options', () => {
  const storage = new MemoryStorage();
  const daemon = new MockDaemon();
  const keys = {
    viewSecretKey: new Uint8Array(32),
    spendSecretKey: new Uint8Array(32),
    spendPublicKey: new Uint8Array(32)
  };

  const sync = new WalletSync({
    storage,
    daemon,
    keys,
    batchSize: 50
  });

  assertEqual(sync.storage, storage);
  assertEqual(sync.daemon, daemon);
  // Keys are normalized to hex strings in constructor
  assertEqual(sync.keys.viewSecretKey, '0000000000000000000000000000000000000000000000000000000000000000');
  assertEqual(sync.keys.spendSecretKey, '0000000000000000000000000000000000000000000000000000000000000000');
  assertEqual(sync.keys.spendPublicKey, '0000000000000000000000000000000000000000000000000000000000000000');
  assertEqual(sync.batchSize, 50);
  assertEqual(sync.status, SYNC_STATUS.IDLE);
});

test('uses default batch size when not specified', () => {
  const sync = new WalletSync({});
  assertEqual(sync.batchSize, DEFAULT_BATCH_SIZE);
});

test('createWalletSync factory works', () => {
  const sync = createWalletSync({
    storage: new MemoryStorage(),
    daemon: new MockDaemon()
  });
  assert(sync instanceof WalletSync);
});

// ============================================================================
// Event System Tests
// ============================================================================

console.log('\n--- Event System ---');

test('on adds event listener', () => {
  const sync = new WalletSync({});
  let called = false;

  sync.on('test', () => { called = true; });
  sync._emit('test');

  assert(called, 'Listener should be called');
});

test('off removes event listener', () => {
  const sync = new WalletSync({});
  let callCount = 0;
  const handler = () => { callCount++; };

  sync.on('test', handler);
  sync._emit('test');
  assertEqual(callCount, 1);

  sync.off('test', handler);
  sync._emit('test');
  assertEqual(callCount, 1); // Should not increase
});

test('multiple listeners can be added', () => {
  const sync = new WalletSync({});
  const calls = [];

  sync.on('test', () => calls.push('a'));
  sync.on('test', () => calls.push('b'));
  sync._emit('test');

  assertEqual(calls.length, 2);
  assert(calls.includes('a'));
  assert(calls.includes('b'));
});

test('event passes arguments to listener', () => {
  const sync = new WalletSync({});
  let receivedArgs = null;

  sync.on('test', (a, b, c) => { receivedArgs = [a, b, c]; });
  sync._emit('test', 1, 'two', { three: 3 });

  assertEqual(receivedArgs[0], 1);
  assertEqual(receivedArgs[1], 'two');
  assertEqual(receivedArgs[2].three, 3);
});

test('listener errors are caught and logged', () => {
  const sync = new WalletSync({});
  let secondCalled = false;

  sync.on('test', () => { throw new Error('Intentional error'); });
  sync.on('test', () => { secondCalled = true; });

  // Should not throw and should continue to next listener
  sync._emit('test');
  assert(secondCalled, 'Second listener should still be called');
});

// ============================================================================
// Progress Tracking Tests
// ============================================================================

console.log('\n--- Progress Tracking ---');

test('getProgress returns correct structure', () => {
  const sync = new WalletSync({});
  sync.startHeight = 0;
  sync.currentHeight = 500;
  sync.targetHeight = 1000;
  sync.status = SYNC_STATUS.SYNCING;

  const progress = sync.getProgress();

  assertEqual(progress.status, SYNC_STATUS.SYNCING);
  assertEqual(progress.currentHeight, 500);
  assertEqual(progress.targetHeight, 1000);
  assertEqual(progress.startHeight, 0);
  assertEqual(progress.blocksProcessed, 500);
  assertEqual(progress.blocksRemaining, 500);
  assertEqual(progress.percentComplete, 50);
});

test('getProgress handles zero total blocks', () => {
  const sync = new WalletSync({});
  sync.startHeight = 100;
  sync.currentHeight = 100;
  sync.targetHeight = 100;

  const progress = sync.getProgress();
  assertEqual(progress.percentComplete, 0);
});

test('getProgress caps percent at 100', () => {
  const sync = new WalletSync({});
  sync.startHeight = 0;
  sync.currentHeight = 1100; // Beyond target
  sync.targetHeight = 1000;

  const progress = sync.getProgress();
  assertEqual(progress.percentComplete, 100);
});

// ============================================================================
// Sync Control Tests
// ============================================================================

console.log('\n--- Sync Control ---');

await testAsync('start syncs from stored height', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  await storage.setSyncHeight(50);

  const daemon = new MockDaemon({ height: 100 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 200 // Larger than range to complete in one batch
  });

  await sync.start();

  assertEqual(sync.status, SYNC_STATUS.COMPLETE);
  assertEqual(sync.startHeight, 50);
  assert(daemon.callLog.includes('getInfo'));

  await storage.close();
});

await testAsync('start uses provided startHeight', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  await storage.setSyncHeight(50); // This should be ignored

  const daemon = new MockDaemon({ height: 100 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 200
  });

  await sync.start(75);

  assertEqual(sync.startHeight, 75);

  await storage.close();
});

await testAsync('start throws if already syncing', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const daemon = new MockDaemon({ height: 1000000 }); // Very high to keep syncing
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 1
  });

  // Start sync but don't await
  const syncPromise = sync.start(0);

  // Try to start again immediately
  let threw = false;
  try {
    await sync.start(0);
  } catch (e) {
    threw = true;
    assert(e.message.includes('Already syncing'));
  }

  // Stop the original sync
  sync.stop();
  try {
    await syncPromise;
  } catch (e) {
    // Expected - sync was stopped
  }

  assert(threw, 'Should throw when already syncing');

  await storage.close();
});

await testAsync('stop sets flag to halt sync', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const sync = new WalletSync({
    storage,
    daemon: new MockDaemon({ height: 100 }),
    keys: {},
    batchSize: 10
  });

  // Verify stop sets the flag
  assertEqual(sync._stopRequested, false);
  sync.stop();
  assertEqual(sync._stopRequested, true);

  await storage.close();
});

await testAsync('rescan clears storage and restarts', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  // Add some data
  await storage.putOutput(new WalletOutput({ keyImage: 'ki1' }));
  await storage.setSyncHeight(500);

  const daemon = new MockDaemon({ height: 100 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 200
  });

  await sync.rescan(0);

  // Storage should be cleared
  const outputs = await storage.getOutputs();
  assertEqual(outputs.length, 0);

  // Sync should complete from 0
  assertEqual(sync.startHeight, 0);

  await storage.close();
});

// ============================================================================
// Event Emission Tests
// ============================================================================

console.log('\n--- Event Emissions ---');

await testAsync('emits syncStart event', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const daemon = new MockDaemon({ height: 100 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 200
  });

  let startEvent = null;
  sync.on('syncStart', (data) => { startEvent = data; });

  await sync.start(10);

  assert(startEvent !== null, 'syncStart should be emitted');
  assertEqual(startEvent.startHeight, 10);
  assertEqual(startEvent.targetHeight, 100);

  await storage.close();
});

await testAsync('emits syncComplete event', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const daemon = new MockDaemon({ height: 100 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 200
  });

  let completeEvent = null;
  sync.on('syncComplete', (data) => { completeEvent = data; });

  await sync.start(0);

  assert(completeEvent !== null, 'syncComplete should be emitted');
  assert(completeEvent.height >= 99, 'Should complete near target height');

  await storage.close();
});

await testAsync('emits syncProgress events', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const daemon = new MockDaemon({ height: 50 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 10 // Small batches to get multiple progress events
  });

  const progressEvents = [];
  sync.on('syncProgress', (data) => { progressEvents.push(data); });

  await sync.start(0);

  assert(progressEvents.length > 0, 'Should emit progress events');
  // Verify progress increases
  for (let i = 1; i < progressEvents.length; i++) {
    assert(
      progressEvents[i].currentHeight >= progressEvents[i - 1].currentHeight,
      'Progress should increase'
    );
  }

  await storage.close();
});

await testAsync('emits newBlock events', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const daemon = new MockDaemon({ height: 10 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 20
  });

  const blockEvents = [];
  sync.on('newBlock', (data) => { blockEvents.push(data); });

  await sync.start(0);

  assert(blockEvents.length > 0, 'Should emit newBlock events');
  assert(blockEvents[0].height !== undefined);
  assert(blockEvents[0].hash !== undefined);
  assert(blockEvents[0].timestamp !== undefined);

  await storage.close();
});

await testAsync('emits syncError on daemon failure', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const daemon = {
    async getInfo() {
      return { success: false, error: { message: 'Connection failed' } };
    }
  };

  const sync = new WalletSync({
    storage,
    daemon,
    keys: {},
    batchSize: 100
  });

  let errorEvent = null;
  sync.on('syncError', (error) => { errorEvent = error; });

  try {
    await sync.start(0);
  } catch (e) {
    // Expected
  }

  assert(errorEvent !== null, 'syncError should be emitted');
  assertEqual(sync.status, SYNC_STATUS.ERROR);

  await storage.close();
});

// ============================================================================
// Mempool Scanning Tests
// ============================================================================

console.log('\n--- Mempool Scanning ---');

await testAsync('scanMempool returns empty array when pool is empty', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const daemon = new MockDaemon({ height: 100 });
  const sync = new WalletSync({
    storage,
    daemon,
    keys: {
      viewSecretKey: new Uint8Array(32),
      spendPublicKey: new Uint8Array(32)
    }
  });

  const pending = await sync.scanMempool();
  assertEqual(pending.length, 0);

  await storage.close();
});

// ============================================================================
// Summary
// ============================================================================

console.log('\n--- Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  console.log('\n✗ Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All wallet sync tests passed!');
  process.exit(0);
}
