#!/usr/bin/env bun
import { DaemonRPC } from '../src/rpc/daemon.js';
import { transfer } from '../src/wallet/transfer.js';
import { WalletSync } from '../src/wallet-sync.js';
import { createWallet } from '../src/wallet/wallet.js';
import { readFileSync, unlinkSync } from 'fs';

const daemon = new DaemonRPC('http://web.whiskymine.io:29081');
const walletAJson = JSON.parse(readFileSync('/home/mxhess/testnet-wallet/wallet.json', 'utf-8'));
const keysA = {
  viewSecretKey: walletAJson.viewSecretKey,
  spendSecretKey: walletAJson.spendSecretKey,
  viewPublicKey: walletAJson.viewPublicKey,
  spendPublicKey: walletAJson.spendPublicKey,
  address: walletAJson.address
};
try { unlinkSync('/home/mxhess/testnet-wallet/wallet-sync-debug.json'); } catch {}
const sync = new WalletSync({ daemon, keys: keysA, network: 'testnet' });
const storage = await sync.sync({ savePath: '/home/mxhess/testnet-wallet/wallet-sync-debug.json' });
const info = await daemon.getInfo();
const height = info.result?.height;
console.log('Height:', height);
const allOutputs = await storage.getOutputs({ isSpent: false });
const spendable = allOutputs.filter(o => o.isSpendable(height));
console.log('Spendable:', spendable.length);
// Generate a random address
import { generateKeys } from '../src/crypto/index.js';
import { encodeAddress } from '../src/address.js';
const { TESTNET_CONFIG } from '../src/consensus.js';
const bKeys = generateKeys();
const toAddress = encodeAddress(TESTNET_CONFIG.ADDRESS_PREFIX, bKeys.viewPublicKey, bKeys.spendPublicKey);
const result = await transfer({
  wallet: { keys: keysA, storage },
  daemon,
  destinations: [{ address: toAddress, amount: 100_0000_0000n }],
  options: { priority: 'default', network: 'testnet', dryRun: true }
});
console.log('TX hex length:', result.serializedHex.length / 2, 'bytes');
const resp = await fetch('http://web.whiskymine.io:29081/sendrawtransaction', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ tx_as_hex: result.serializedHex, do_not_relay: true })
});
const data = await resp.json();
console.log('Daemon check:', JSON.stringify(data, null, 2));
