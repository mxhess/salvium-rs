import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { Wallet } from '../src/wallet.js';
import { readFileSync } from 'fs';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const info = await daemon.getInfo();
const height = info.result?.height || info.data?.height;
console.log('Height:', height);

// Use the new wallet-a.json with correct CARROT address
const wj = JSON.parse(readFileSync(process.env.HOME + '/testnet-wallet/wallet-a.json'));
const wallet = Wallet.fromJSON({ ...wj, network: 'testnet' });
const storage = new MemoryStorage();

console.log('\nWallet CN Address:', wallet.getLegacyAddress());
console.log('Wallet CARROT Address:', wallet.getCarrotAddress());

console.log('\nSyncing with CARROT keys...');
const sync = createWalletSync({
  daemon,
  keys: wj,
  storage,
  network: 'testnet',
  carrotKeys: wallet.carrotKeys
});

await sync.start();

const outputs = await storage.getOutputs({ isSpent: false });
console.log('\nTotal outputs:', outputs.length);

// Group by asset type
const byAsset = {};
for (const o of outputs) {
  byAsset[o.assetType] = (byAsset[o.assetType] || 0) + 1;
}
console.log('By asset:', byAsset);

// Group by output type
const byType = {};
for (const o of outputs) {
  const t = o.outputType || (o.isCarrot ? 'CARROT' : 'CN');
  byType[t] = (byType[t] || 0) + 1;
}
console.log('By type:', byType);

// Show recent
console.log('\nMost recent outputs:');
for (const o of outputs.slice(-10)) {
  console.log('  h=' + o.blockHeight, 'asset=' + o.assetType, 'carrot=' + o.isCarrot, 'amt=' + (Number(o.amount)/1e8).toFixed(2));
}
