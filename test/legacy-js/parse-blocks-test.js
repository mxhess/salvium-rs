#!/usr/bin/env bun
// Test parsing many blocks to ensure transaction parsing is robust

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { hexToBytes } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== Block parsing test ===\n');

  const info = await daemon.getInfo();
  const currentHeight = info.result.height;
  console.log(`Current chain height: ${currentHeight}`);

  const startHeight = 0;
  const endHeight = Math.min(10000, currentHeight);
  const batchSize = 100;

  let totalTxs = 0;
  let parsedTxs = 0;
  let failedTxs = 0;
  let startTime = Date.now();

  console.log(`\nParsing blocks ${startHeight} to ${endHeight}...\n`);

  for (let height = startHeight; height < endHeight; height += batchSize) {
    const endBatch = Math.min(height + batchSize, endHeight);

    // Get block headers for this batch
    const headers = await daemon.getBlockHeadersRange(height, endBatch - 1);
    if (!headers.result?.headers) continue;

    // Collect all tx hashes from these blocks
    const txHashes = [];
    for (const header of headers.result.headers) {
      // Get full block
      const block = await daemon.getBlock(header.hash);
      if (block.result?.tx_hashes) {
        txHashes.push(...block.result.tx_hashes);
      }
    }

    if (txHashes.length === 0) continue;

    // Get transactions in batches of 100
    for (let i = 0; i < txHashes.length; i += 100) {
      const batch = txHashes.slice(i, i + 100);
      const txResp = await daemon.getTransactions(batch, { decode_as_json: false });

      if (!txResp.result?.txs) continue;

      for (const txData of txResp.result.txs) {
        totalTxs++;

        try {
          const tx = parseTransaction(hexToBytes(txData.as_hex));
          parsedTxs++;

          // Basic validation
          if (!tx.prefix) throw new Error('Missing prefix');
          if (tx.prefix.version === 2 && !tx.rct) throw new Error('Missing RCT for v2 tx');

        } catch (e) {
          failedTxs++;
          if (failedTxs <= 10) {
            console.log(`  FAILED tx at height ~${height}: ${e.message}`);
          }
        }
      }
    }

    // Progress update
    const elapsed = (Date.now() - startTime) / 1000;
    const rate = totalTxs / elapsed;
    const memMB = Math.round(process.memoryUsage().heapUsed / 1024 / 1024);
    console.log(`Height ${endBatch}: ${totalTxs} txs (${parsedTxs} ok, ${failedTxs} failed), ${rate.toFixed(1)} tx/s, ${memMB} MB`);

    // Memory check
    if (memMB > 500) {
      console.log('\nWARNING: Memory usage > 500 MB, stopping');
      break;
    }

    // Force GC if available
    if (global.gc) global.gc();
  }

  const elapsed = (Date.now() - startTime) / 1000;
  console.log(`\n=== Results ===`);
  console.log(`Total transactions: ${totalTxs}`);
  console.log(`Successfully parsed: ${parsedTxs}`);
  console.log(`Failed: ${failedTxs}`);
  console.log(`Success rate: ${(parsedTxs / totalTxs * 100).toFixed(2)}%`);
  console.log(`Time: ${elapsed.toFixed(1)} seconds`);
  console.log(`Rate: ${(totalTxs / elapsed).toFixed(1)} tx/s`);
}

test().catch(console.error);
