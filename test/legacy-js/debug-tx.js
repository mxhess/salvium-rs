#!/usr/bin/env bun
import { DaemonRPC } from '../src/rpc/daemon.js';
import { transfer } from '../src/wallet/transfer.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';
import { randomScalar, scalarMultBase } from '../src/crypto/index.js';
import { createAddress } from '../src/address.js';

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const walletAJson = JSON.parse(readFileSync('/home/mxhess/testnet-wallet/wallet-a.json', 'utf-8'));
const keysA = {
  viewSecretKey: walletAJson.viewSecretKey,
  spendSecretKey: walletAJson.spendSecretKey,
  viewPublicKey: walletAJson.viewPublicKey,
  spendPublicKey: walletAJson.spendPublicKey,
  address: walletAJson.address,
  // CARROT keys (if present)
  generateImageKey: walletAJson.generateImageKey || null,
};

// Load cached sync state or start fresh
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

// Save sync state
await Bun.write(CACHE_FILE, JSON.stringify(storage.dump()));

const info = await daemon.getInfo();
const height = info.result?.height;
console.log('Height:', height);
const allOutputs = await storage.getOutputs({ isSpent: false });
const spendable = allOutputs.filter(o => o.isSpendable(height));
console.log('Spendable:', spendable.length);

if (spendable.length === 0) {
  console.log('No spendable outputs — cannot build transfer.');
  process.exit(0);
}

// Generate a random destination address
const bViewSec = randomScalar();
const bSpendSec = randomScalar();
const bViewPub = scalarMultBase(bViewSec);
const bSpendPub = scalarMultBase(bSpendSec);
const toAddress = createAddress({
  network: 'testnet', format: 'legacy', type: 'standard',
  spendPublicKey: bSpendPub, viewPublicKey: bViewPub
});

const result = await transfer({
  wallet: { keys: keysA, storage, carrotKeys: walletAJson.carrotKeys },
  daemon,
  destinations: [{ address: toAddress, amount: 100_0000_0000n }],
  options: { priority: 'default', network: 'testnet', dryRun: false }
});
console.log('TX hex length:', result.serializedHex.length / 2, 'bytes');
const resp = await fetch('http://node12.whiskymine.io:29081/sendrawtransaction', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ tx_as_hex: result.serializedHex, do_not_relay: true })
});
const data = await resp.json();
console.log('Daemon check:', JSON.stringify(data, null, 2));
