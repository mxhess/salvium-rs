#!/usr/bin/env bun
// Debug actual WalletSync to find the exact issue

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
  console.log('=== Debug WalletSync ===\n');

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
    batchSize: 50  // Small batches
  });

  let lastPrint = 0;
  let blockCount = 0;

  // Print EVERY 10 blocks
  sync.on('syncProgress', (data) => {
    blockCount++;
    if (data.currentHeight - lastPrint >= 10) {
      if (global.gc) global.gc();
      const mem = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      console.log(`H:${data.currentHeight} M:${mem}MB`);
      lastPrint = data.currentHeight;

      if (mem > 50) {
        console.log('MEMORY > 50MB');
        sync.stop();
      }
    }
  });

  sync.on('newBlock', (data) => {
    // Just count
  });

  sync.on('syncError', (err) => {
    console.error('ERROR:', err.message);
  });

  console.log('Starting...\n');

  const syncPromise = sync.start(0);

  // Stop at 1200 blocks
  const checkInterval = setInterval(() => {
    if (sync.currentHeight >= 1200) {
      console.log('Reached 1200 - stopping');
      sync.stop();
      clearInterval(checkInterval);
    }
  }, 500);

  try {
    await syncPromise;
  } catch (e) {
    console.log('Ended:', e.message);
  }

  if (global.gc) global.gc();
  console.log('\nFinal:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Height:', sync.currentHeight);

  await storage.close();
}

test().catch(console.error);
