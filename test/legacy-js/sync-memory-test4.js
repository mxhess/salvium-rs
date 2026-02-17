#!/usr/bin/env bun
// Test RPC memory accumulation

import { createDaemonRPC } from '../src/rpc/index.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== Testing RPC memory ===\n');

  if (global.gc) global.gc();
  console.log('Baseline:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');

  // Fetch headers in batches like wallet-sync does
  for (let start = 0; start < 5000; start += 500) {
    const resp = await daemon.getBlockHeadersRange(start, start + 499);

    // For blocks with txs, fetch the transactions
    let txCount = 0;
    for (const header of (resp.result?.headers || [])) {
      if (header.num_txes > 0) {
        const block = await daemon.getBlock({ height: header.height });
        const txHashes = block.result?.tx_hashes || [];
        if (txHashes.length > 0) {
          const txs = await daemon.getTransactions(txHashes, { decode_as_json: true });
          txCount += txHashes.length;
        }
      }
    }

    if (global.gc) global.gc();
    console.log(`Height ${start + 500}: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB (${txCount} txs fetched)`);
  }

  console.log('\nDone');
}

test().catch(console.error);
