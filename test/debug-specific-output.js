#!/usr/bin/env bun
/**
 * Debug specific CARROT output commitment mismatch
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';
import { commit } from '../src/crypto/index.js';
import { parseTransaction } from '../src/transaction/parsing.js';

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
const cached = JSON.parse(readFileSync(CACHE_FILE, 'utf-8'));
storage.load(cached);

const allOutputs = await storage.getOutputs({ isSpent: false });

// Find CARROT outputs with commitments that DON'T match mask*G + amount*H
const mismatchOutputs = [];
for (const o of allOutputs) {
  if (!o.mask || !o.commitment) continue;
  const maskBytes = hexToBytes(o.mask);
  const computed = commit(BigInt(o.amount), maskBytes);
  if (bytesToHex(computed) !== o.commitment) {
    mismatchOutputs.push(o);
  }
}

console.log(`Total outputs: ${allOutputs.length}`);
console.log(`Outputs with commitment mismatch: ${mismatchOutputs.length}`);
console.log(`  CARROT: ${mismatchOutputs.filter(o => o.isCarrot).length}`);
console.log(`  Non-CARROT: ${mismatchOutputs.filter(o => !o.isCarrot).length}`);

// Analyze first few mismatches
for (const output of mismatchOutputs.slice(0, 3)) {
  console.log(`\n=== Output ${output.txHash.slice(0, 16)}..., idx ${output.outputIndex} ===`);
  console.log(`  isCarrot: ${output.isCarrot}`);
  console.log(`  assetType: ${output.assetType}`);
  console.log(`  blockHeight: ${output.blockHeight}`);
  console.log(`  amount: ${output.amount}`);
  console.log(`  mask: ${output.mask.slice(0, 32)}...`);
  console.log(`  stored commitment: ${output.commitment.slice(0, 32)}...`);

  const maskBytes = hexToBytes(output.mask);
  const computed = commit(BigInt(output.amount), maskBytes);
  console.log(`  computed commitment: ${bytesToHex(computed).slice(0, 32)}...`);

  // Try to fetch the TX from daemon
  try {
    const txResp = await daemon.getTransactions([output.txHash], true, false);
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];

    if (txData?.as_hex) {
      // Parse from binary
      const txBytes = hexToBytes(txData.as_hex);
      const parsed = parseTransaction(txBytes);
      console.log(`  Parsed rctType: ${parsed.rct?.type}`);
      console.log(`  Parsed outPk count: ${parsed.rct?.outPk?.length || 0}`);
      if (parsed.rct?.outPk?.[output.outputIndex]) {
        const parsedCommitment = bytesToHex(parsed.rct.outPk[output.outputIndex]);
        console.log(`  Parsed outPk[${output.outputIndex}]: ${parsedCommitment.slice(0, 32)}...`);
        console.log(`  outPk matches stored: ${parsedCommitment === output.commitment}`);

        // Verify: does outPk from blockchain match computed?
        console.log(`  outPk matches computed: ${parsedCommitment === bytesToHex(computed)}`);
      }
    } else if (txData?.as_json) {
      const txJson = JSON.parse(txData.as_json);
      console.log(`  JSON rctType: ${txJson.rct_signatures?.type}`);
      const outPk = txJson.rct_signatures?.outPk;
      if (outPk?.[output.outputIndex]) {
        console.log(`  JSON outPk[${output.outputIndex}]: ${outPk[output.outputIndex].slice(0, 32)}...`);
      }
    } else {
      console.log(`  TX has no as_hex or as_json`);
    }
  } catch (e) {
    console.log(`  Error: ${e.message}`);
  }
}

// Also count: how many outputs have CORRECT commitments?
const matchOutputs = allOutputs.filter(o => {
  if (!o.mask || !o.commitment) return false;
  const maskBytes = hexToBytes(o.mask);
  const computed = commit(BigInt(o.amount), maskBytes);
  return bytesToHex(computed) === o.commitment;
});
console.log(`\nOutputs with CORRECT commitment: ${matchOutputs.length}`);
console.log(`  CARROT: ${matchOutputs.filter(o => o.isCarrot).length}`);
console.log(`  Non-CARROT: ${matchOutputs.filter(o => !o.isCarrot).length}`);
