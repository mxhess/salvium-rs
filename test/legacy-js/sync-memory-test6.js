#!/usr/bin/env bun
// Isolate memory leak in WalletSync - step by step

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
  console.log('=== Isolating WalletSync memory leak ===\n');

  if (global.gc) global.gc();
  console.log('Baseline:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');

  let totalTxs = 0;
  let totalOutputs = 0;

  for (let start = 0; start < 2000; start += 500) {
    const resp = await daemon.getBlockHeadersRange(start, start + 499);
    const headers = resp.result?.headers || [];

    for (const header of headers) {
      if (header.num_txes === 0) continue;

      const block = await daemon.getBlock({ height: header.height });
      const txHashes = block.result?.tx_hashes || [];
      if (txHashes.length === 0) continue;

      const txsResp = await daemon.getTransactions(txHashes, { decode_as_json: true });
      const txs = txsResp.result?.txs || [];

      for (const txData of txs) {
        totalTxs++;

        // Step 1: Parse transaction
        const tx = parseTransaction(hexToBytes(txData.as_hex));

        // Step 2: Extract tx pubkey
        const txPubKey = extractTxPubKey(tx);
        if (!txPubKey) continue;

        // Step 3: Generate key derivation
        const derivation = generateKeyDerivation(txPubKey, keys.viewSecretKey);
        if (!derivation) continue;

        // Step 4: Scan each output
        const outputs = tx.prefix?.vout || [];
        for (let i = 0; i < outputs.length; i++) {
          totalOutputs++;
          const output = outputs[i];

          // Get output key
          let outputKey = null;
          if (output.target?.key) {
            outputKey = typeof output.target.key === 'string'
              ? hexToBytes(output.target.key)
              : output.target.key;
          } else if (output.key) {
            outputKey = typeof output.key === 'string'
              ? hexToBytes(output.key)
              : output.key;
          }
          if (!outputKey) continue;

          // Derive expected public key
          const expectedPubKey = derivePublicKey(derivation, i, keys.spendPublicKey);
          if (!expectedPubKey) continue;

          // Compare
          const match = bytesToHex(outputKey) === bytesToHex(expectedPubKey);
          // (won't match for test wallet, but this exercises the code)
        }
      }
    }

    if (global.gc) global.gc();
    const mem = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log(`Height ${start + 500}: ${mem} MB (${totalTxs} txs, ${totalOutputs} outputs)`);

    // Fail fast if memory growing too much
    if (mem > 500) {
      console.log('MEMORY EXCEEDED 500MB - ABORTING');
      break;
    }
  }

  console.log('\nDone');
}

test().catch(console.error);
