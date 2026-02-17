#!/usr/bin/env bun
// Find the transaction that causes memory explosion

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { hexToBytes } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== Finding problematic transaction ===\n');

  // Start around where it blew up
  for (let height = 940; height < 1050; height++) {
    const block = await daemon.getBlock({ height });
    const txHashes = block.result?.tx_hashes || [];

    if (txHashes.length === 0) continue;

    const txsResp = await daemon.getTransactions(txHashes, { decode_as_json: true });
    const txs = txsResp.result?.txs || [];

    for (const txData of txs) {
      const beforeMem = process.memoryUsage().heapUsed;

      try {
        const txBytes = hexToBytes(txData.as_hex);
        console.log(`Height ${height}, tx ${txData.tx_hash.slice(0,16)}..., size: ${txBytes.length} bytes`);

        const tx = parseTransaction(txBytes);

        const afterMem = process.memoryUsage().heapUsed;
        const memDiff = Math.round((afterMem - beforeMem) / 1024 / 1024);

        if (memDiff > 10) {
          console.log(`  WARNING: Memory grew by ${memDiff} MB!`);
          console.log(`  RCT type: ${tx.rct?.type}`);
          console.log(`  Outputs: ${tx.prefix?.vout?.length}`);
          console.log(`  Inputs: ${tx.prefix?.vin?.length}`);
        }
      } catch (e) {
        console.log(`  ERROR: ${e.message}`);
      }
    }
  }

  console.log('\nDone');
}

test().catch(console.error);
