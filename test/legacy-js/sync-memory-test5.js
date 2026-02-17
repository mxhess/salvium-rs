#!/usr/bin/env bun
// Test scanning memory

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { scanTransaction } from '../src/scanning.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys } from '../src/carrot.js';
import { hexToBytes } from '../src/address.js';

const testMnemonic = 'abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey abbey';
const result = mnemonicToSeed(testMnemonic, { language: 'english' });
const keys = deriveKeys(result.seed);

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== Testing scanning memory ===\n');

  if (global.gc) global.gc();
  console.log('Baseline:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');

  let totalScanned = 0;

  for (let start = 0; start < 5000; start += 500) {
    const resp = await daemon.getBlockHeadersRange(start, start + 499);

    for (const header of (resp.result?.headers || [])) {
      if (header.num_txes > 0) {
        const block = await daemon.getBlock({ height: header.height });
        const txHashes = block.result?.tx_hashes || [];

        if (txHashes.length > 0) {
          const txsResp = await daemon.getTransactions(txHashes, { decode_as_json: true });

          for (const txData of (txsResp.result?.txs || [])) {
            // Parse transaction
            const tx = parseTransaction(hexToBytes(txData.as_hex));

            // Extract tx pubkey from extra
            let txPubKey = null;
            for (const field of (tx.prefix?.extra || [])) {
              if (field.type === 0x01 && field.key) {
                txPubKey = field.key;
                break;
              }
            }

            if (!txPubKey) continue;

            // Scan each output
            const outputs = tx.prefix?.vout || [];
            for (let i = 0; i < outputs.length; i++) {
              const output = outputs[i];
              const outputKey = output.key;
              if (!outputKey) continue;

              // This is where scanning happens
              const scanResult = scanTransaction(
                txPubKey,
                keys.viewSecretKey,
                keys.spendPublicKey,
                [{ publicKey: outputKey, index: i }],
                tx.rct?.ecdhInfo?.[i],
                tx.rct?.outPk?.[i]
              );

              totalScanned++;
            }
          }
        }
      }
    }

    if (global.gc) global.gc();
    console.log(`Height ${start + 500}: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB (${totalScanned} outputs scanned)`);
  }

  console.log('\nDone');
}

test().catch(console.error);
