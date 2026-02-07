#!/usr/bin/env bun
import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { transfer } from '../src/wallet/transfer.js';
import { estimateTransactionFee } from '../src/transaction.js';

await setCryptoBackend('wasm');

const daemon = new DaemonRPC({ url: 'http://web.whiskymine.io:29081' });
const raw = JSON.parse(await Bun.file(process.env.HOME + '/testnet-wallet/wallet-a.json').text());
const keys = {
  viewSecretKey: raw.viewSecretKey,
  spendSecretKey: raw.spendSecretKey,
  viewPublicKey: raw.viewPublicKey,
  spendPublicKey: raw.spendPublicKey,
};
const info = await daemon.getInfo();
const h = info.result.height;
const blockchainState = {
  height: h,
  blockWeightMedian: info.result.block_weight_median || info.result.block_weight_limit / 2 || 300000,
};

console.log('Height:', h);
console.log('Fee estimate (1in/2out):', estimateTransactionFee(1, 2, { priority: 'default', blockchainState }).toString());

const storage = new MemoryStorage();
const sync = createWalletSync({ daemon, keys, carrotKeys: raw.carrotKeys, storage, network: 'testnet' });
await sync.start();

const allOutputs = await storage.getOutputs({ isSpent: false });
const spendable = allOutputs.filter(o => o.isSpendable(h));
console.log('Spendable:', spendable.length, 'outputs');

const destAddr = 'SaLvTyLQTea5p6mtmELxnSXjMybo41Hvd2uCKqE74ernauQNzLAumqCMRePX1c3TPSBsqqcWfJKyrdk6VF7NVMjtQbSqERvwmbp3E';

// Patch to capture full daemon response
const origSend = daemon.sendRawTransaction.bind(daemon);
daemon.sendRawTransaction = async function(...args) {
  const resp = await origSend(...args);
  const r = resp.result || resp.data;
  if (r.status !== 'OK') {
    const flags = {};
    for (const k of ['double_spend', 'fee_too_low', 'invalid_input', 'invalid_output', 'low_mixin', 'overspend', 'sanity_check_failed', 'too_few_outputs', 'too_big', 'tx_extra_too_big']) {
      if (r[k]) flags[k] = true;
    }
    console.log('  daemon rejection:', JSON.stringify(flags), 'reason:', r.reason || '(none)');
  }
  return resp;
};

// Test different amounts
for (const amt of [5_000_000n, 50_000_000n, 500_000_000n, 5_000_000_000n]) {
  try {
    const result = await transfer({
      wallet: { keys, storage, carrotKeys: raw.carrotKeys },
      daemon,
      destinations: [{ address: destAddr, amount: amt }],
      options: { priority: 'default', network: 'testnet' }
    });
    if (result.spentKeyImages) {
      for (const ki of result.spentKeyImages) await storage.markOutputSpent(ki);
    }
    console.log('OK', (Number(amt)/1e8).toFixed(8), 'SAL, fee:', result.fee?.toString());
  } catch (e) {
    console.log('FAIL', (Number(amt)/1e8).toFixed(8), 'SAL:', e.message.slice(0, 150));
  }
}
