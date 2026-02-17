#!/usr/bin/env bun
// Isolate memory usage in sync process

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { hexToBytes } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function testBlockFetching() {
  console.log('=== Testing block fetching memory ===\n');

  if (global.gc) global.gc();
  const baseline = process.memoryUsage().heapUsed;
  console.log('Baseline:', Math.round(baseline / 1024 / 1024), 'MB');

  // Test 1: Fetch block headers only
  console.log('\nFetching 1000 block headers...');
  const headers = await daemon.getBlockHeadersRange(0, 999);
  if (global.gc) global.gc();
  console.log('After headers:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Headers count:', headers.result?.headers?.length);

  // Count blocks with transactions
  let blocksWithTx = 0;
  for (const h of headers.result?.headers || []) {
    if (h.num_txes > 0) blocksWithTx++;
  }
  console.log('Blocks with transactions:', blocksWithTx);

  // Test 2: Fetch and parse transactions from blocks with txs
  console.log('\nFetching transactions from blocks with txs...');
  let txCount = 0;
  let parseCount = 0;

  for (const header of (headers.result?.headers || []).slice(0, 200)) {
    if (header.num_txes === 0) continue;

    const block = await daemon.getBlock({ height: header.height });
    const txHashes = block.result?.tx_hashes || [];

    if (txHashes.length > 0) {
      const txsResp = await daemon.getTransactions(txHashes, { decode_as_json: true });
      txCount += txHashes.length;

      for (const txData of (txsResp.result?.txs || [])) {
        // Parse but don't store
        const tx = parseTransaction(hexToBytes(txData.as_hex));
        parseCount++;
      }
    }

    // Report every 50 blocks
    if (header.height % 50 === 0) {
      if (global.gc) global.gc();
      console.log(`  Height ${header.height}: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB (${parseCount} txs parsed)`);
    }
  }

  if (global.gc) global.gc();
  console.log('\nAfter parsing (not storing):', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Total transactions parsed:', parseCount);

  // Test 3: Store parsed transactions
  console.log('\nNow storing parsed transactions...');
  const stored = [];

  for (const header of (headers.result?.headers || []).slice(0, 200)) {
    if (header.num_txes === 0) continue;

    const block = await daemon.getBlock({ height: header.height });
    const txHashes = block.result?.tx_hashes || [];

    if (txHashes.length > 0) {
      const txsResp = await daemon.getTransactions(txHashes, { decode_as_json: true });

      for (const txData of (txsResp.result?.txs || [])) {
        const tx = parseTransaction(hexToBytes(txData.as_hex));
        stored.push(tx);
      }
    }

    if (header.height % 50 === 0) {
      if (global.gc) global.gc();
      console.log(`  Height ${header.height}: ${Math.round(process.memoryUsage().heapUsed / 1024 / 1024)} MB (${stored.length} txs stored)`);
    }
  }

  if (global.gc) global.gc();
  console.log('\nAfter storing:', Math.round(process.memoryUsage().heapUsed / 1024 / 1024), 'MB');
  console.log('Stored count:', stored.length);
}

testBlockFetching().catch(console.error);
