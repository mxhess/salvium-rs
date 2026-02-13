#!/usr/bin/env bun
/**
 * Persistent Wallet Tests
 *
 * Tests for persistent-wallet.js:
 * - PersistentWallet class
 * - Storage integration
 * - Balance calculation
 * - Transaction creation
 */

import {
  PersistentWallet,
  createPersistentWallet,
  restorePersistentWallet,
  openPersistentWallet
} from '../src/persistent-wallet.js';

import { MemoryStorage, WalletOutput, WalletTransaction } from '../src/wallet-store.js';
import { generateSeed, deriveKeys } from '../src/carrot.js';
import { mnemonicToSeed, seedToMnemonic } from '../src/mnemonic.js';
import { initCrypto } from '../src/crypto/index.js';

await initCrypto();

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

// Mock daemon for testing
class MockDaemon {
  constructor(options = {}) {
    this.height = options.height || 1000;
  }

  async getInfo() {
    return {
      success: true,
      result: { height: this.height, status: 'OK' }
    };
  }

  async getBlockHeadersRange(start, end) {
    return { success: true, result: { headers: [] } };
  }

  async getBlock(opts) {
    return {
      success: true,
      result: { tx_hashes: [], miner_tx_hash: 'miner' }
    };
  }

  async getTransactions() {
    return { success: true, result: { txs: [] } };
  }

  async sendRawTransaction(blob) {
    return { success: true, result: { status: 'OK' } };
  }

  async getOutputDistribution() {
    return {
      success: true,
      result: { distributions: [{ amount: 1000000 }] }
    };
  }

  async getOuts(indices) {
    return {
      success: true,
      result: {
        outs: indices.map(i => ({
          key: 'aa'.repeat(32),
          mask: 'bb'.repeat(32)
        }))
      }
    };
  }
}

console.log('=== Persistent Wallet Tests ===\n');

// ============================================================================
// Construction Tests
// ============================================================================

console.log('--- Construction ---');

test('creates PersistentWallet with options', () => {
  const seed = generateSeed();
  const keys = deriveKeys(seed);

  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  assert(wallet !== undefined);
  assert(!wallet.isOpen());
});

test('creates with custom storage instance', () => {
  const storage = new MemoryStorage();
  const seed = generateSeed();

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon()
  });

  assertEqual(wallet._storage, storage);
});

test('creates with custom daemon instance', () => {
  const daemon = new MockDaemon({ height: 5000 });
  const seed = generateSeed();

  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon
  });

  assertEqual(wallet._daemon, daemon);
});

// ============================================================================
// Lifecycle Tests
// ============================================================================

console.log('\n--- Lifecycle ---');

await testAsync('open initializes wallet', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  assert(!wallet.isOpen());
  await wallet.open();
  assert(wallet.isOpen());

  await wallet.close();
});

await testAsync('close cleans up', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  await wallet.open();
  assert(wallet.isOpen());

  await wallet.close();
  assert(!wallet.isOpen());
});

await testAsync('open is idempotent', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  await wallet.open();
  await wallet.open(); // Should not throw
  assert(wallet.isOpen());

  await wallet.close();
});

await testAsync('close is idempotent', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  await wallet.open();
  await wallet.close();
  await wallet.close(); // Should not throw
  assert(!wallet.isOpen());
});

// ============================================================================
// Balance Tests
// ============================================================================

console.log('\n--- Balance ---');

await testAsync('getBalance returns 0 for empty wallet', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  await wallet.open();
  const balance = await wallet.getBalance('SAL1');
  assertEqual(balance, 0n);

  await wallet.close();
});

await testAsync('getBalance sums unspent outputs', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  // Add some outputs
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki1',
    amount: 1000000000n,
    assetType: 'SAL1',
    isSpent: false,
    blockHeight: 100
  }));
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki2',
    amount: 2000000000n,
    assetType: 'SAL1',
    isSpent: false,
    blockHeight: 101
  }));
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki3',
    amount: 500000000n,
    assetType: 'SAL1',
    isSpent: true, // Spent, should not count
    blockHeight: 102
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 200 })
  });

  await wallet.open();
  const balance = await wallet.getBalance('SAL1');

  // 1000000000 + 2000000000 = 3000000000
  assertEqual(balance, 3000000000n);

  await wallet.close();
});

await testAsync('getBalance filters by asset type', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({
    keyImage: 'ki1',
    amount: 1000n,
    assetType: 'SAL',
    isSpent: false,
    blockHeight: 100
  }));
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki2',
    amount: 2000n,
    assetType: 'USD',
    isSpent: false,
    blockHeight: 101
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 200 })
  });

  await wallet.open();

  const salBalance = await wallet.getBalance('SAL');
  const usdBalance = await wallet.getBalance('USD');

  assertEqual(salBalance, 1000n);
  assertEqual(usdBalance, 2000n);

  await wallet.close();
});

await testAsync('getUnlockedBalance excludes locked outputs', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  // Unlocked output (old enough)
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki1',
    amount: 1000n,
    assetType: 'SAL1',
    isSpent: false,
    blockHeight: 100,
    unlockTime: 0n
  }));

  // Locked output (too recent)
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki2',
    amount: 2000n,
    assetType: 'SAL1',
    isSpent: false,
    blockHeight: 195, // Only 5 blocks old at height 200
    unlockTime: 0n
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 200 })
  });

  await wallet.open();

  const balance = await wallet.getBalance('SAL1');
  const unlocked = await wallet.getUnlockedBalance('SAL1');

  assertEqual(balance, 3000n);
  assertEqual(unlocked, 1000n); // Only the old output

  await wallet.close();
});

await testAsync('getBalances returns all asset types', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({
    keyImage: 'ki1', amount: 100n, assetType: 'SAL', isSpent: false, blockHeight: 10
  }));
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki2', amount: 200n, assetType: 'USD', isSpent: false, blockHeight: 10
  }));
  await storage.putOutput(new WalletOutput({
    keyImage: 'ki3', amount: 300n, assetType: 'EUR', isSpent: false, blockHeight: 10
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 200 })
  });

  await wallet.open();
  const balances = await wallet.getBalances();

  assert(balances.has('SAL'));
  assert(balances.has('USD'));
  assert(balances.has('EUR'));
  assertEqual(balances.get('SAL').balance, 100n);
  assertEqual(balances.get('USD').balance, 200n);
  assertEqual(balances.get('EUR').balance, 300n);

  await wallet.close();
});

// ============================================================================
// Output Tests
// ============================================================================

console.log('\n--- Outputs ---');

await testAsync('getOutputs returns all outputs', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', amount: 100n }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki2', amount: 200n }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon()
  });

  await wallet.open();
  const outputs = await wallet.getOutputs();

  assertEqual(outputs.length, 2);

  await wallet.close();
});

await testAsync('getUnspentOutputs filters spent', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({ keyImage: 'ki1', amount: 100n, isSpent: false }));
  await storage.putOutput(new WalletOutput({ keyImage: 'ki2', amount: 200n, isSpent: true }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon()
  });

  await wallet.open();
  const outputs = await wallet.getUnspentOutputs();

  assertEqual(outputs.length, 1);
  assertEqual(outputs[0].keyImage, 'ki1');

  await wallet.close();
});

await testAsync('freezeOutput prevents spending', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({
    keyImage: 'ki1',
    amount: 100n,
    isSpent: false,
    isFrozen: false,
    blockHeight: 10
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 200 })
  });

  await wallet.open();

  // Before freeze
  let spendable = await wallet.getSpendableOutputs();
  assertEqual(spendable.length, 1);

  // Freeze
  await wallet.freezeOutput('ki1');

  // After freeze
  spendable = await wallet.getSpendableOutputs();
  assertEqual(spendable.length, 0);

  await wallet.close();
});

await testAsync('thawOutput allows spending again', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putOutput(new WalletOutput({
    keyImage: 'ki1',
    amount: 100n,
    isSpent: false,
    isFrozen: true,
    blockHeight: 10
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 200 })
  });

  await wallet.open();

  // Before thaw
  let spendable = await wallet.getSpendableOutputs();
  assertEqual(spendable.length, 0);

  // Thaw
  await wallet.thawOutput('ki1');

  // After thaw
  spendable = await wallet.getSpendableOutputs();
  assertEqual(spendable.length, 1);

  await wallet.close();
});

// ============================================================================
// Transaction Tests
// ============================================================================

console.log('\n--- Transactions ---');

await testAsync('getTransactions returns all transactions', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putTransaction(new WalletTransaction({ txHash: 'tx1', blockHeight: 100 }));
  await storage.putTransaction(new WalletTransaction({ txHash: 'tx2', blockHeight: 101 }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon()
  });

  await wallet.open();
  const txs = await wallet.getTransactions();

  assertEqual(txs.length, 2);

  await wallet.close();
});

await testAsync('getTransaction returns specific tx', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putTransaction(new WalletTransaction({
    txHash: 'specific_tx',
    blockHeight: 500,
    incomingAmount: 1000000n
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon()
  });

  await wallet.open();
  const tx = await wallet.getTransaction('specific_tx');

  assertEqual(tx.txHash, 'specific_tx');
  assertEqual(tx.blockHeight, 500);
  assertEqual(tx.incomingAmount, 1000000n);

  await wallet.close();
});

await testAsync('getTransaction returns null for nonexistent', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  await wallet.open();
  const tx = await wallet.getTransaction('nonexistent');

  assertEqual(tx, null);

  await wallet.close();
});

await testAsync('setTransactionNote updates note', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putTransaction(new WalletTransaction({
    txHash: 'tx_with_note',
    blockHeight: 100
  }));

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon()
  });

  await wallet.open();

  await wallet.setTransactionNote('tx_with_note', 'Payment for coffee');
  const tx = await wallet.getTransaction('tx_with_note');

  assertEqual(tx.note, 'Payment for coffee');

  await wallet.close();
});

// ============================================================================
// Sync Height Tests
// ============================================================================

console.log('\n--- Sync Height ---');

await testAsync('getSyncHeight returns stored height', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();
  await storage.setSyncHeight(5000);

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon()
  });

  await wallet.open();
  const height = await wallet.getSyncHeight();

  assertEqual(height, 5000);

  await wallet.close();
});

await testAsync('getDaemonHeight returns daemon height', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon({ height: 12345 })
  });

  await wallet.open();
  const height = await wallet.getDaemonHeight();

  assertEqual(height, 12345);

  await wallet.close();
});

await testAsync('isSynced returns true when caught up', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();
  await storage.setSyncHeight(1000);

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 1000 })
  });

  await wallet.open();
  const synced = await wallet.isSynced();

  assert(synced);

  await wallet.close();
});

await testAsync('isSynced returns false when behind', async () => {
  const seed = generateSeed();
  const storage = new MemoryStorage();
  await storage.open();
  await storage.setSyncHeight(500);

  const wallet = new PersistentWallet({
    seed,
    storage,
    daemon: new MockDaemon({ height: 1000 })
  });

  await wallet.open();
  const synced = await wallet.isSynced();

  assert(!synced);

  await wallet.close();
});

// ============================================================================
// Error Handling Tests
// ============================================================================

console.log('\n--- Error Handling ---');

await testAsync('operations throw when not open', async () => {
  const seed = generateSeed();
  const wallet = new PersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  let threw = false;
  try {
    await wallet.getBalance('SAL1');
  } catch (e) {
    threw = true;
    assert(e.message.includes('not open'));
  }
  assert(threw, 'Should throw when not open');
});

// ============================================================================
// Factory Function Tests
// ============================================================================

console.log('\n--- Factory Functions ---');

await testAsync('createPersistentWallet creates and opens', async () => {
  const seed = generateSeed();
  const wallet = await createPersistentWallet({
    seed,
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  assert(wallet instanceof PersistentWallet);
  assert(wallet.isOpen());

  await wallet.close();
});

await testAsync('restorePersistentWallet restores from mnemonic', async () => {
  const seed = generateSeed();
  const mnemonic = seedToMnemonic(seed);

  const wallet = await restorePersistentWallet(mnemonic, {
    storage: { type: 'memory' },
    daemon: new MockDaemon()
  });

  assert(wallet instanceof PersistentWallet);
  assert(wallet.isOpen());

  await wallet.close();
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
  console.log('\n✓ All persistent wallet tests passed!');
  process.exit(0);
}
