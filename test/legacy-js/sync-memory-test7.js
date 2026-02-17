#!/usr/bin/env bun
// WalletSync with very frequent memory output

import { createDaemonRPC } from '../src/rpc/index.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { WalletSync } from '../src/wallet-sync.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys } from '../src/carrot.js';

const testMnemonic = 'abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey';
const result = mnemonicToSeed(testMnemonic, { language: 'english' });
const keys = deriveKeys(result.seed);

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== WalletSync memory test with frequent output ===\n');

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
    batchSize: 100  // Small batches for debugging
  });

  let lastHeight = 0;
  let blockCount = 0;

  // Print every 50 blocks instead of every 1000
  sync.on('syncProgress', (data) => {
    blockCount++;
    if (data.currentHeight - lastHeight >= 50) {
      if (global.gc) global.gc();
      const mem = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      console.log(`Height ${data.currentHeight}: ${mem} MB`);
      lastHeight = data.currentHeight;

      // Fail fast
      if (mem > 200) {
        console.log('MEMORY > 200MB - stopping');
        sync.stop();
      }
    }
  });

  sync.on('syncError', (err) => {
    console.error('Sync error:', err.message);
  });

  console.log('Starting sync...\n');

  const syncPromise = sync.start(0);

  // Stop at 1000 blocks
  const checkInterval = setInterval(() => {
    if (sync.currentHeight >= 1000) {
      console.log('Reached 1000 blocks - stopping');
      sync.stop();
      clearInterval(checkInterval);
    }
  }, 100);

  try {
    await syncPromise;
  } catch (e) {
    console.log('Sync ended:', e.message);
  }

  if (global.gc) global.gc();
  console.log('\nFinal:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Sync height:', sync.currentHeight);

  await storage.close();
}

test().catch(console.error);
