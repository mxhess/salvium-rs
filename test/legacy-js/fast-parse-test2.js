#!/usr/bin/env bun
// Fast test using getblocks endpoint that returns tx data

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { hexToBytes } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 60000 });

async function test() {
  console.log('=== Fast transaction parsing test ===\n');

  const startHeight = 5000;
  const batchSize = 100;
  const numBatches = 50;  // 5000 blocks total

  let totalTxs = 0;
  let parsedTxs = 0;
  let failedTxs = 0;
  const failures = [];
  const startTime = Date.now();

  for (let batch = 0; batch < numBatches; batch++) {
    const height = startHeight + (batch * batchSize);

    // Get block hashes for this range
    const headers = await daemon.getBlockHeadersRange(height, height + batchSize - 1);
    if (!headers.result?.headers) continue;

    // Collect tx hashes
    const txHashes = [];
    for (const h of headers.result.headers) {
      if (h.num_txes > 0) {
        // Need to get the block to get tx hashes
        const block = await daemon.getBlock(h.hash);
        if (block.result?.tx_hashes) {
          txHashes.push(...block.result.tx_hashes);
        }
      }
    }

    if (txHashes.length > 0) {
      // Get transactions
      const txResp = await daemon.getTransactions(txHashes, { decode_as_json: false });
      if (txResp.result?.txs) {
        for (const txData of txResp.result.txs) {
          totalTxs++;
          try {
            const tx = parseTransaction(hexToBytes(txData.as_hex));
            parsedTxs++;
          } catch (e) {
            failedTxs++;
            if (failures.length < 10) failures.push(e.message);
          }
        }
      }
    }

    const elapsed = (Date.now() - startTime) / 1000;
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log(`Batch ${batch + 1}/${numBatches}: height ${height + batchSize}, ${totalTxs} txs (${failedTxs} failed), ${memMB} MB`);
  }

  const elapsed = (Date.now() - startTime) / 1000;
  const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);

  console.log(`\n=== Results ===`);
  console.log(`Total transactions: ${totalTxs}`);
  console.log(`Successfully parsed: ${parsedTxs}`);
  console.log(`Failed: ${failedTxs}`);
  console.log(`Success rate: ${totalTxs > 0 ? (parsedTxs / totalTxs * 100).toFixed(2) : 0}%`);
  console.log(`Time: ${elapsed.toFixed(1)} seconds`);
  console.log(`Memory: ${memMB} MB`);

  if (failures.length > 0) {
    console.log(`\nFirst failures:`);
    failures.forEach((f, i) => console.log(`  ${i + 1}. ${f}`));
  }
}

test().catch(console.error);
