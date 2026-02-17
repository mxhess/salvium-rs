#!/usr/bin/env bun
// Fast test - parse transactions from a specific height range using efficient RPC

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { hexToBytes } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 60000 });

async function test() {
  console.log('=== Fast transaction parsing test ===\n');

  // Use getblocks.bin which is much faster - returns blocks with transactions
  const startHeight = 5000;  // Start from block with transactions
  const blockCount = 1000;

  console.log(`Fetching ${blockCount} blocks starting at height ${startHeight}...`);

  let totalTxs = 0;
  let parsedTxs = 0;
  let failedTxs = 0;
  const failures = [];

  const startTime = Date.now();

  // Fetch blocks using the binary endpoint (more efficient)
  const resp = await daemon.call('get_blocks.bin', {
    heights: Array.from({ length: blockCount }, (_, i) => startHeight + i),
    prune: false
  }, 'binary');

  if (!resp.result?.blocks) {
    console.log('No blocks returned, trying JSON endpoint...');

    // Fallback: get transactions directly from mempool + recent blocks
    const pool = await daemon.getTransactionPool();
    const poolTxs = pool.result?.transactions || [];
    console.log(`Got ${poolTxs.length} pool transactions`);

    for (const txData of poolTxs) {
      totalTxs++;
      try {
        const tx = parseTransaction(hexToBytes(txData.tx_blob));
        parsedTxs++;
      } catch (e) {
        failedTxs++;
        if (failures.length < 5) failures.push(e.message);
      }
    }
  } else {
    console.log(`Got ${resp.result.blocks.length} blocks`);

    for (const block of resp.result.blocks) {
      // Parse miner tx
      if (block.miner_tx) {
        totalTxs++;
        try {
          const tx = parseTransaction(hexToBytes(block.miner_tx));
          parsedTxs++;
        } catch (e) {
          failedTxs++;
          if (failures.length < 5) failures.push(`miner_tx: ${e.message}`);
        }
      }

      // Parse regular txs
      for (const txBlob of (block.txs || [])) {
        totalTxs++;
        try {
          const tx = parseTransaction(hexToBytes(txBlob));
          parsedTxs++;
        } catch (e) {
          failedTxs++;
          if (failures.length < 5) failures.push(e.message);
        }
      }
    }
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
    console.log(`\nFirst ${failures.length} failures:`);
    failures.forEach((f, i) => console.log(`  ${i + 1}. ${f}`));
  }
}

test().catch(console.error);
