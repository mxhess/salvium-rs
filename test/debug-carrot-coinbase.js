#!/usr/bin/env bun
/**
 * Check if CARROT outputs without commitments are coinbase
 */

import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';

// Load cached sync state
const CACHE_FILE = '/home/mxhess/testnet-wallet/wallet-a-sync.json';
const storage = new MemoryStorage();
const cached = JSON.parse(readFileSync(CACHE_FILE, 'utf-8'));
storage.load(cached);

const allOutputs = await storage.getOutputs({ isSpent: false });
const carrotNoCommit = allOutputs.filter(o => o.isCarrot && o.mask && !o.commitment);
const carrotWithCommit = allOutputs.filter(o => o.isCarrot && o.mask && o.commitment);

console.log(`CARROT outputs without commitment: ${carrotNoCommit.length}`);
console.log(`CARROT outputs with commitment: ${carrotWithCommit.length}`);

// Check block heights - coinbase usually at regular intervals
const heights = carrotNoCommit.map(o => o.blockHeight);
const heightSet = new Set(heights);
console.log(`\nUnique block heights: ${heightSet.size}`);
console.log(`Block height range: ${Math.min(...heights)} - ${Math.max(...heights)}`);

// Check txHash distribution - coinbase would be one per block
const txHashes = carrotNoCommit.map(o => o.txHash);
const uniqueTxs = new Set(txHashes);
console.log(`\nUnique transactions: ${uniqueTxs.size}`);
console.log(`Outputs per tx avg: ${(carrotNoCommit.length / uniqueTxs.size).toFixed(2)}`);

// Check if each block has one CARROT coinbase TX
const byBlock = new Map();
for (const o of carrotNoCommit) {
  if (!byBlock.has(o.blockHeight)) {
    byBlock.set(o.blockHeight, new Set());
  }
  byBlock.get(o.blockHeight).add(o.txHash);
}

let singleTxBlocks = 0;
for (const [height, txs] of byBlock) {
  if (txs.size === 1) singleTxBlocks++;
}
console.log(`\nBlocks with single CARROT tx: ${singleTxBlocks} / ${byBlock.size}`);

// Sample some to look at structure
console.log('\n=== Sample CARROT outputs without commitment ===');
for (const o of carrotNoCommit.slice(0, 3)) {
  console.log(`  Block ${o.blockHeight}, TX ${o.txHash.slice(0, 16)}..., idx ${o.outputIndex}`);
  console.log(`    amount: ${o.amount}`);
  console.log(`    mask: ${o.mask.slice(0, 32)}...`);
  console.log(`    txPubKey: ${o.txPubKey?.slice(0, 32)}...`);
}
