#!/usr/bin/env bun
// Mimic WalletSync more closely to find memory issue

import { createDaemonRPC } from '../src/rpc/index.js';
import { MemoryStorage, WalletOutput, WalletTransaction } from '../src/wallet-store.js';
import { parseTransaction, extractTxPubKey, extractPaymentId } from '../src/transaction.js';
import { generateKeyDerivation, derivePublicKey, deriveViewTag, computeSharedSecret, ecdhDecodeFull } from '../src/scanning.js';
import { generateKeyImage } from '../src/crypto/index.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex } from '../src/address.js';

const testMnemonic = 'abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey';
const result = mnemonicToSeed(testMnemonic, { language: 'english' });
const keys = deriveKeys(result.seed);

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== Mimicking WalletSync to find memory issue ===\n');

  const storage = new MemoryStorage();
  await storage.open();

  if (global.gc) global.gc();
  console.log('Baseline:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');

  let txCount = 0;

  for (let start = 0; start < 1500; start += 100) {
    const resp = await daemon.getBlockHeadersRange(start, start + 99);

    for (const header of (resp.result?.headers || [])) {
      if (header.num_txes === 0) continue;

      const block = await daemon.getBlock({ height: header.height });
      const txHashes = block.result?.tx_hashes || [];
      if (txHashes.length === 0) continue;

      const txsResp = await daemon.getTransactions(txHashes, { decode_as_json: true });

      for (const txData of (txsResp.result?.txs || [])) {
        txCount++;
        const txHash = txData.tx_hash;

        // Check if already processed (like WalletSync does)
        const existing = await storage.getTransaction(txHash);
        if (existing) continue;

        try {
          const tx = parseTransaction(hexToBytes(txData.as_hex));
          const txPubKey = extractTxPubKey(tx);
          const paymentId = extractPaymentId(tx);

          if (!txPubKey) continue;

          // Scan outputs
          const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
          if (!derivation) continue;

          const outputs = tx.prefix?.vout || [];
          let foundOwn = false;

          for (let i = 0; i < outputs.length; i++) {
            let outputKey = outputs[i].target?.key || outputs[i].key;
            if (!outputKey) continue;
            if (typeof outputKey === 'string') outputKey = hexToBytes(outputKey);

            const expected = derivePublicKey(derivation, i, keys.spendPublicKey);
            if (!expected) continue;

            if (bytesToHex(outputKey) === bytesToHex(expected)) {
              foundOwn = true;
              // Would create WalletOutput here
            }
          }

          // Check spent outputs (like WalletSync)
          const inputs = tx.prefix?.vin || [];
          for (const input of inputs) {
            if (!input.key?.k_image) continue;
            const keyImage = typeof input.key.k_image === 'string'
              ? input.key.k_image : bytesToHex(input.key.k_image);
            // Would check storage here
          }

        } catch (e) {
          console.log(`Error at height ${header.height}: ${e.message}`);
        }
      }
    }

    if (global.gc) global.gc();
    const mem = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log(`Height ${start + 100}: ${mem} MB (${txCount} txs)`);

    if (mem > 100) {
      console.log('MEMORY > 100MB - stopping');
      break;
    }
  }

  await storage.close();
  console.log('\nDone');
}

test().catch(console.error);
