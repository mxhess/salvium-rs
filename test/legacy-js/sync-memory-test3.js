#!/usr/bin/env bun
// Test WalletSync memory at scale

import { createDaemonRPC } from '../src/rpc/index.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { WalletSync } from '../src/wallet-sync.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys } from '../src/carrot.js';

const testMnemonic = 'abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey';
const result = mnemonicToSeed(testMnemonic, { language: 'english' });
const keys = deriveKeys(result.seed);

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function testWalletSync() {
  console.log('=== Testing WalletSync memory at scale ===\n');

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
    batchSize: 500
  });

  let lastHeight = 0;
  sync.on('syncProgress', (data) => {
    if (data.currentHeight - lastHeight >= 1000) {
      if (global.gc) global.gc();
      console.log(`Height ${data.currentHeight}: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB`);
      lastHeight = data.currentHeight;
    }
  });

  console.log('Syncing to 10000 blocks...\n');

  const syncPromise = sync.start(0);

  const checkInterval = setInterval(() => {
    if (sync.currentHeight >= 10000) {
      sync.stop();
      clearInterval(checkInterval);
    }
  }, 100);

  try {
    await syncPromise;
  } catch (e) {}

  if (global.gc) global.gc();
  console.log('\nFinal:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Sync height:', sync.currentHeight);

  await storage.close();
}

testWalletSync().catch(console.error);
