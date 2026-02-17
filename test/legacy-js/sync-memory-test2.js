#!/usr/bin/env bun
// Test WalletSync memory usage

import { createDaemonRPC } from '../src/rpc/index.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { WalletSync } from '../src/wallet-sync.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys } from '../src/carrot.js';

// Use a test mnemonic (won't find any outputs, but tests the scanning process)
const testMnemonic = 'abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey';
const result = mnemonicToSeed(testMnemonic, { language: 'english' });
const keys = deriveKeys(result.seed);

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function testWalletSync() {
  console.log('=== Testing WalletSync memory ===\n');

  if (global.gc) global.gc();
  console.log('Baseline:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');

  const storage = new MemoryStorage();
  await storage.open();

  const sync = new WalletSync({
    storage,
    daemon,
    keys: {
      viewSecretKey: keys.viewSecretKey,
      spendPublicKey: keys.spendPublicKey,
      spendSecretKey: keys.spendSecretKey
    },
    batchSize: 100
  });

  let lastHeight = 0;
  sync.on('syncProgress', (data) => {
    if (data.currentHeight - lastHeight >= 100) {
      if (global.gc) global.gc();
      console.log(`Height ${data.currentHeight}: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
      lastHeight = data.currentHeight;
    }
  });

  sync.on('syncError', (err) => {
    console.error('Sync error:', err.message);
  });

  console.log('Starting sync from block 0 (will stop at 500)...\n');

  // Start sync but stop after 500 blocks
  const syncPromise = sync.start(0);

  // Stop after reaching height 500
  const checkInterval = setInterval(() => {
    if (sync.currentHeight >= 500) {
      sync.stop();
      clearInterval(checkInterval);
    }
  }, 100);

  try {
    await syncPromise;
  } catch (e) {
    // Sync stopped
  }

  if (global.gc) global.gc();
  console.log('\nFinal:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Sync height:', sync.currentHeight);

  await storage.close();
}

testWalletSync().catch(console.error);
