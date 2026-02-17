#!/usr/bin/env bun
/**
 * Compute the difference between outPk and mask*G + amount*H for SAL1 outputs.
 * If there's a constant asset tag offset, the difference should be the same for all outputs.
 */
import { setCryptoBackend, commit, pointNegate, pointAddCompressed } from '../src/crypto/index.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { readFileSync } from 'fs';

await setCryptoBackend('wasm');

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const storage = new MemoryStorage();
storage.load(JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a-sync.json`, 'utf-8')));
const allOutputs = await storage.getOutputs({ isSpent: false });
const carrotOutputs = allOutputs.filter(o => o.isCarrot && o.commitment && o.mask);

console.log(`SAL1 CARROT outputs: ${carrotOutputs.length}\n`);

// Compute: diff = outPk - (mask*G + amount*H) = outPk - C
// If there's a constant asset offset, all diffs should be the same
const diffs = [];
for (const o of carrotOutputs.slice(0, 5)) {
  const maskBytes = hexToBytes(o.mask);
  const C = commit(BigInt(o.amount), maskBytes);
  const outPk = hexToBytes(o.commitment);

  // diff = outPk - C = outPk + (-C)
  const negC = pointNegate(C);
  const diff = pointAddCompressed(outPk, negC);
  diffs.push(bytesToHex(diff));
  console.log(`Output ${o.txHash.slice(0,12)}... idx=${o.outputIndex}:`);
  console.log(`  outPk:  ${bytesToHex(outPk).slice(0,32)}...`);
  console.log(`  C:      ${bytesToHex(C).slice(0,32)}...`);
  console.log(`  diff:   ${bytesToHex(diff)}`);
}

// Check if all diffs are the same
if (diffs.length > 1) {
  const allSame = diffs.every(d => d === diffs[0]);
  console.log(`\nAll diffs same: ${allSame}`);
  if (allSame) {
    console.log(`Constant asset offset: ${diffs[0]}`);
    // This is the asset tag point for SAL1
    // Check if it matches hash_to_point("SAL1") or similar
  }
}
