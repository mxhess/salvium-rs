#!/usr/bin/env bun
// Check block headers to understand tx distribution

import { createDaemonRPC } from '../src/rpc/index.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  // Check a sample of blocks
  const ranges = [
    [1000, 1100],
    [10000, 10100],
    [50000, 50100],
    [100000, 100100],
    [200000, 200100],
    [300000, 300100],
    [400000, 400050]
  ];

  for (const [start, end] of ranges) {
    const headers = await daemon.getBlockHeadersRange(start, end);
    let totalTxs = 0;
    let blocksWithTxs = 0;

    for (const h of headers.result?.headers || []) {
      if (h.num_txes > 0) {
        blocksWithTxs++;
        totalTxs += h.num_txes;
      }
    }

    console.log(`Blocks ${start}-${end}: ${blocksWithTxs} blocks with txs, ${totalTxs} total txs`);
  }

  // Get one specific block with transactions
  console.log('\nLooking for a block with transactions...');
  const headers = await daemon.getBlockHeadersRange(1000, 2000);
  for (const h of headers.result?.headers || []) {
    if (h.num_txes > 0) {
      console.log(`  Block ${h.height}: ${h.num_txes} txs, hash=${h.hash.slice(0, 16)}...`);
      const block = await daemon.getBlock(h.hash);
      console.log(`    tx_hashes: ${block.result?.tx_hashes?.length || 0}`);
      if (block.result?.tx_hashes?.length > 0) {
        console.log(`    First tx: ${block.result.tx_hashes[0]}`);
      }
      break;
    }
  }
}

test().catch(console.error);
