#!/usr/bin/env bun
import { DaemonRPC } from '../src/rpc/daemon.js';
import { burn } from '../src/wallet/transfer.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const walletAJson = JSON.parse(readFileSync('/home/mxhess/testnet-wallet/wallet-a.json', 'utf-8'));
const keysA = {
  viewSecretKey: walletAJson.viewSecretKey,
  spendSecretKey: walletAJson.spendSecretKey,
  viewPublicKey: walletAJson.viewPublicKey,
  spendPublicKey: walletAJson.spendPublicKey,
  address: walletAJson.address,
};

// Load cached sync state
const CACHE_FILE = '/home/mxhess/testnet-wallet/wallet-a-sync.json';
const storage = new MemoryStorage();
try {
  const cached = JSON.parse(readFileSync(CACHE_FILE, 'utf-8'));
  storage.load(cached);
  const cachedHeight = await storage.getSyncHeight();
  console.log(`Resuming sync from block ${cachedHeight}...`);
} catch {
  console.log('Starting fresh sync...');
}

const sync = createWalletSync({
  daemon,
  keys: keysA,
  storage,
  network: 'testnet'
});

await sync.start();
await Bun.write(CACHE_FILE, JSON.stringify(storage.dump()));

console.log('\n--- Burn Test: 1 SAL ---');
try {
  const result = await burn({
    wallet: { keys: keysA, storage, carrotKeys: walletAJson.carrotKeys },
    daemon,
    amount: 1_00_000_000n, // 1 SAL
    options: { priority: 'default', network: 'testnet', dryRun: false }
  });
  console.log(`TX Hash: ${result.txHash}`);
  console.log(`Fee: ${Number(result.fee) / 1e8} SAL`);
  console.log(`Burned: ${Number(result.burnAmount) / 1e8} SAL`);
  console.log(`Inputs: ${result.inputCount}, Outputs: ${result.outputCount}`);
  console.log(`Serialized: ${result.serializedHex.length / 2} bytes`);
  console.log('BROADCAST OK');
} catch (e) {
  console.error(`FAILED: ${e.message}`);
  if (e.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
}
