#!/usr/bin/env bun
/**
 * Debug a single CN transfer on the fresh testnet.
 * Captures full daemon response and TX details.
 */
import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { transfer } from '../src/wallet/transfer.js';
import { getRctType, getTxVersion, getActiveAssetType } from '../src/consensus.js';
import { TX_TYPE } from '../src/transaction/constants.js';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const info = await daemon.getInfo();
const h = info.result.height;
console.log('Height:', h);
console.log('HF version:', info.result.version);
console.log('Active asset type:', getActiveAssetType(h, 'testnet'));
console.log('RCT type:', getRctType(h, 'testnet'));
console.log('TX version:', getTxVersion(TX_TYPE.TRANSFER, h, 'testnet'));
console.log('Block weight median:', info.result.block_weight_median);
console.log('Block weight limit:', info.result.block_weight_limit);
console.log();

const raw = JSON.parse(await Bun.file(process.env.HOME + '/testnet-wallet/wallet-a.json').text());
const keys = {
  viewSecretKey: raw.viewSecretKey,
  spendSecretKey: raw.spendSecretKey,
  viewPublicKey: raw.viewPublicKey,
  spendPublicKey: raw.spendPublicKey,
};

const storage = new MemoryStorage();
const sync = createWalletSync({ daemon, keys, carrotKeys: raw.carrotKeys, storage, network: 'testnet' });
await sync.start();

const allOutputs = await storage.getOutputs({ isSpent: false });
const spendable = allOutputs.filter(o => o.isSpendable(h));
console.log('Total outputs:', allOutputs.length);
console.log('Spendable:', spendable.length);
console.log('First output sample:', JSON.stringify({
  amount: spendable[0]?.amount.toString(),
  assetType: spendable[0]?.assetType,
  blockHeight: spendable[0]?.blockHeight,
  globalIndex: spendable[0]?.globalIndex,
  outputIndex: spendable[0]?.outputIndex,
}));
console.log();

// Destination: wallet B
const bData = JSON.parse(await Bun.file(process.env.HOME + '/testnet-wallet/wallet-b.json').text());
const destAddr = bData.address;
console.log('Dest:', destAddr);

// Intercept daemon.sendRawTransaction
const origSend = daemon.sendRawTransaction.bind(daemon);
daemon.sendRawTransaction = async function(txHex, opts) {
  console.log('\n--- Submitting TX ---');
  console.log('TX hex length:', txHex.length);
  console.log('Opts:', JSON.stringify(opts));
  const resp = await origSend(txHex, opts);
  console.log('Full daemon response:', JSON.stringify(resp, null, 2));
  return resp;
};

try {
  const result = await transfer({
    wallet: { keys, storage, carrotKeys: raw.carrotKeys },
    daemon,
    destinations: [{ address: destAddr, amount: 500_000_000n }], // 5 SAL
    options: { priority: 'default', network: 'testnet' }
  });
  console.log('\nSUCCESS!');
  console.log('TX Hash:', result.txHash);
  console.log('Fee:', result.fee?.toString());
  console.log('Inputs:', result.inputCount, 'Outputs:', result.outputCount);
} catch (e) {
  console.log('\nFAILED:', e.message);
}
