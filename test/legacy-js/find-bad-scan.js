#!/usr/bin/env bun
// Find if scanning causes memory explosion

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction, extractTxPubKey } from '../src/transaction.js';
import { generateKeyDerivation, derivePublicKey, deriveViewTag } from '../src/scanning.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex } from '../src/address.js';

const testMnemonic = 'abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey';
const result = mnemonicToSeed(testMnemonic, { language: 'english' });
const keys = deriveKeys(result.seed);

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== Testing scanning memory ===\n');

  if (global.gc) global.gc();
  console.log('Baseline:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');

  let totalScanned = 0;

  // Test from 900 to 1100 where the issue occurs
  for (let start = 900; start < 1100; start += 50) {
    const resp = await daemon.getBlockHeadersRange(start, start + 49);

    for (const header of (resp.result?.headers || [])) {
      if (header.num_txes === 0) continue;

      const block = await daemon.getBlock({ height: header.height });
      const txHashes = block.result?.tx_hashes || [];
      if (txHashes.length === 0) continue;

      const txsResp = await daemon.getTransactions(txHashes, { decode_as_json: true });

      for (const txData of (txsResp.result?.txs || [])) {
        const tx = parseTransaction(hexToBytes(txData.as_hex));
        const txPubKey = extractTxPubKey(tx);
        if (!txPubKey) continue;

        // This is where WalletSync differs from find-bad-tx
        const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
        if (!derivation) continue;

        const outputs = tx.prefix?.vout || [];
        for (let i = 0; i < outputs.length; i++) {
          totalScanned++;

          // Get output key
          let outputKey = outputs[i].target?.key || outputs[i].key;
          if (!outputKey) continue;
          if (typeof outputKey === 'string') outputKey = hexToBytes(outputKey);

          // View tag check
          if (outputs[i].viewTag !== undefined) {
            const vt = deriveViewTag(derivation, i);
          }

          // Derive expected key
          const expected = derivePublicKey(derivation, i, keys.spendPublicKey);
        }
      }
    }

    if (global.gc) global.gc();
    const mem = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log(`Height ${start + 50}: ${mem} MB (${totalScanned} outputs scanned)`);

    if (mem > 100) {
      console.log('MEMORY > 100MB - stopping');
      break;
    }
  }

  console.log('\nDone');
}

test().catch(console.error);
