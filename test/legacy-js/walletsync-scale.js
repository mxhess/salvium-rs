#!/usr/bin/env bun
// WalletSync scale test - 5000+ blocks

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
  console.log('=== WalletSync Scale Test (5000 blocks) ===\n');

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

  let lastPrint = 0;

  sync.on('syncProgress', (data) => {
    if (data.currentHeight - lastPrint >= 500) {
      if (global.gc) global.gc();
      const mem = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
      console.log(`Height ${data.currentHeight}: ${mem} MB`);
      lastPrint = data.currentHeight;

      if (mem > 100) {
        console.log('MEMORY > 100MB - stopping');
        sync.stop();
      }
    }
  });

  sync.on('syncError', (err) => {
    console.error('ERROR:', err.message);
  });

  console.log('Starting sync to 5000 blocks...\n');

  const syncPromise = sync.start(0);

  const checkInterval = setInterval(() => {
    if (sync.currentHeight >= 5000) {
      console.log('Reached 5000 blocks - stopping');
      sync.stop();
      clearInterval(checkInterval);
    }
  }, 1000);

  try {
    await syncPromise;
  } catch (e) {
    // Expected when stopped
  }

  if (global.gc) global.gc();
  console.log('\nFinal:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Height:', sync.currentHeight);

  await storage.close();
}

test().catch(console.error);
