#!/usr/bin/env bun
/**
 * Debug CARROT commitment storage
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';
import { commit } from '../src/crypto/index.js';

function hexToBytes(hex) {
  if (typeof hex !== 'string') return hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const daemon = new DaemonRPC({ url: 'http://web.whiskymine.io:29081' });

// Load cached sync state
const CACHE_FILE = '/home/mxhess/testnet-wallet/wallet-a-sync.json';
const storage = new MemoryStorage();
try {
  const cached = JSON.parse(readFileSync(CACHE_FILE, 'utf-8'));
  storage.load(cached);
} catch {
  console.log('No cached wallet state');
  process.exit(1);
}

// Get outputs and find some with null commitment but non-null mask
const allOutputs = await storage.getOutputs({ isSpent: false });
const problemOutputs = allOutputs.filter(o => o.mask && !o.commitment);
console.log(`Outputs with mask but no commitment: ${problemOutputs.length}`);

// Analyze first few - fetch one at a time
for (const output of problemOutputs.slice(0, 3)) {
  console.log(`\n=== TX ${output.txHash.slice(0, 16)}..., output ${output.outputIndex} ===`);
  console.log(`  isCarrot: ${output.isCarrot}`);
  console.log(`  mask: ${output.mask.slice(0, 32)}...`);
  console.log(`  commitment: ${output.commitment}`);
  console.log(`  Fetching TX...`);

  try {
    const txResp = await daemon.getTransactions([output.txHash], true, false);
    console.log(`  Response: ${JSON.stringify(txResp).slice(0, 200)}`);

    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    if (txData?.as_json) {
      const txJson = JSON.parse(txData.as_json);
      console.log(`  rctType: ${txJson.rct_signatures?.type}`);

      const outPk = txJson.rct_signatures?.outPk;
      console.log(`  outPk array length: ${outPk?.length || 0}`);
      console.log(`  vout array length: ${txJson.vout?.length || 0}`);

      if (outPk) {
        for (let i = 0; i < Math.min(outPk.length, 5); i++) {
          console.log(`    outPk[${i}]: ${outPk[i]?.slice(0, 32)}...`);
        }
      }

      // The commitment for this output should be outPk[outputIndex]
      if (outPk && outPk[output.outputIndex]) {
        const blockchainCommitment = outPk[output.outputIndex];
        console.log(`  Expected commitment outPk[${output.outputIndex}]: ${blockchainCommitment.slice(0, 32)}...`);

        // Verify using stored mask and amount
        const maskBytes = hexToBytes(output.mask);
        const computedCommitment = commit(BigInt(output.amount), maskBytes);
        console.log(`  Computed from mask+amount: ${bytesToHex(computedCommitment).slice(0, 32)}...`);
        console.log(`  Match: ${bytesToHex(computedCommitment) === blockchainCommitment}`);
      } else {
        console.log(`  WARNING: outPk[${output.outputIndex}] is undefined or null`);
      }
    } else {
      console.log(`  No as_json in response`);
    }
  } catch (e) {
    console.log(`  Error: ${e.message}`);
  }
}

// Also check outputs that DO have stored commitments
const goodOutputs = allOutputs.filter(o => o.mask && o.commitment);
console.log(`\n\nOutputs with both mask and commitment: ${goodOutputs.length}`);
for (const output of goodOutputs.slice(0, 3)) {
  console.log(`\n=== TX ${output.txHash.slice(0, 16)}..., output ${output.outputIndex} ===`);
  console.log(`  isCarrot: ${output.isCarrot}`);

  const maskBytes = hexToBytes(output.mask);
  const computedCommitment = commit(BigInt(output.amount), maskBytes);
  console.log(`  stored commitment: ${output.commitment.slice(0, 32)}...`);
  console.log(`  computed commitment: ${bytesToHex(computedCommitment).slice(0, 32)}...`);
  console.log(`  Match: ${bytesToHex(computedCommitment) === output.commitment}`);
}
