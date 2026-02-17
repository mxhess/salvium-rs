#!/usr/bin/env bun
// Parse a sample of known transactions to verify parsing works

import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction } from '../src/transaction.js';
import { hexToBytes, bytesToHex } from '../src/address.js';

const daemon = createDaemonRPC({ url: 'http://seed01.salvium.io:19081', timeout: 30000 });

async function test() {
  console.log('=== Parse sample transactions ===\n');

  // Known transaction hashes to test
  const txHashes = [
    'a5e85d03e9200229a72fc3cfe94e5b139c8c2ad982dc3fd174898be63269e670'  // Known good tx
  ];

  // Search multiple block ranges to find transactions
  const ranges = [
    [100000, 100500],
    [200000, 200500],
    [300000, 300500],
    [400000, 400100]
  ];

  for (const [start, end] of ranges) {
    console.log(`Searching blocks ${start}-${end}...`);
    const headers = await daemon.getBlockHeadersRange(start, end);

    for (const h of headers.result?.headers || []) {
      if (h.num_txes > 0) {
        const block = await daemon.getBlock(h.hash);
        if (block.result?.tx_hashes) {
          txHashes.push(...block.result.tx_hashes);
        }
      }
      if (txHashes.length >= 50) break;
    }
    if (txHashes.length >= 50) break;
  }

  console.log(`Testing ${txHashes.length} transactions\n`);

  if (txHashes.length === 0) {
    console.log('No transactions found in recent blocks');
    return;
  }

  // Parse them
  const txResp = await daemon.getTransactions(txHashes, { decode_as_json: true });

  let success = 0;
  let failed = 0;

  for (const txData of txResp.result.txs) {
    try {
      const tx = parseTransaction(hexToBytes(txData.as_hex));

      // Compare with daemon JSON
      const json = JSON.parse(txData.as_json);

      // Validate
      if (tx.prefix.vin.length !== json.vin.length) {
        throw new Error(`Input count mismatch: ${tx.prefix.vin.length} vs ${json.vin.length}`);
      }
      if (tx.prefix.vout.length !== json.vout.length) {
        throw new Error(`Output count mismatch: ${tx.prefix.vout.length} vs ${json.vout.length}`);
      }
      if (tx.rct?.type !== json.rct_signatures?.type) {
        throw new Error(`RCT type mismatch: ${tx.rct?.type} vs ${json.rct_signatures?.type}`);
      }

      success++;
      console.log(`✓ TX ${txData.tx_hash.slice(0, 16)}... type=${tx.rct?.type} in=${tx.prefix.vin.length} out=${tx.prefix.vout.length}`);

    } catch (e) {
      failed++;
      console.log(`✗ TX ${txData.tx_hash.slice(0, 16)}... ERROR: ${e.message}`);
    }
  }

  console.log(`\n=== Results ===`);
  console.log(`Success: ${success}/${txHashes.length}`);
  console.log(`Failed: ${failed}/${txHashes.length}`);
}

test().catch(console.error);
