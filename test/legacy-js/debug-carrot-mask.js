#!/usr/bin/env bun
/**
 * Debug CARROT commitment mask derivation for real outputs.
 * Traces through the full computation to find where it diverges from C++.
 */
import { setCryptoBackend, commit } from '../src/crypto/index.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { deriveCarrotCommitmentMask } from '../src/carrot-scanning.js';
import { readFileSync } from 'fs';

await setCryptoBackend('wasm');

function hexToBytes(hex) {
  if (typeof hex !== 'string') return hex;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Load wallet keys
const walletJson = JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a.json`, 'utf-8'));
const accountSpendPubkey = hexToBytes(
  walletJson.carrotKeys?.accountSpendPubkey || walletJson.spendPublicKey
);
console.log(`Account spend pubkey: ${bytesToHex(accountSpendPubkey).slice(0,32)}...`);

// Load synced outputs
const CACHE_FILE = `${process.env.HOME}/testnet-wallet/wallet-a-sync.json`;
const storage = new MemoryStorage();
storage.load(JSON.parse(readFileSync(CACHE_FILE, 'utf-8')));

const allOutputs = await storage.getOutputs({ isSpent: false });
const carrotOutputs = allOutputs.filter(o => o.isCarrot && o.commitment && o.mask);

console.log(`\nCARROT outputs with commitment and mask: ${carrotOutputs.length}\n`);

for (const o of carrotOutputs.slice(0, 5)) {
  console.log(`=== TX ${o.txHash.slice(0,16)}... idx=${o.outputIndex} block=${o.blockHeight} ===`);
  console.log(`  amount: ${o.amount}`);
  console.log(`  assetType: ${o.assetType}`);
  console.log(`  enoteType: ${o.carrotEnoteType}`);
  console.log(`  commitment: ${o.commitment.slice(0,32)}...`);
  console.log(`  mask: ${o.mask.slice(0,32)}...`);
  console.log(`  sharedSecret: ${o.carrotSharedSecret?.slice(0,32)}...`);

  // Verify stored mask+amount vs stored commitment
  const maskBytes = hexToBytes(o.mask);
  const computed = commit(BigInt(o.amount), maskBytes);
  const computedHex = bytesToHex(computed);
  console.log(`  computed commitment: ${computedHex.slice(0,32)}...`);
  console.log(`  MATCH: ${computedHex === o.commitment}`);

  // If we have sharedSecret, re-derive the mask ourselves
  if (o.carrotSharedSecret) {
    const ctx = hexToBytes(o.carrotSharedSecret);
    const amt = BigInt(o.amount);

    // Try PAYMENT (0)
    const maskP = deriveCarrotCommitmentMask(ctx, amt, accountSpendPubkey, 0);
    const commitP = bytesToHex(commit(amt, maskP));
    const matchP = commitP === o.commitment;

    // Try CHANGE (1)
    const maskC = deriveCarrotCommitmentMask(ctx, amt, accountSpendPubkey, 1);
    const commitC = bytesToHex(commit(amt, maskC));
    const matchC = commitC === o.commitment;

    console.log(`  Re-derived PAYMENT mask: ${bytesToHex(maskP).slice(0,32)}...`);
    console.log(`  Re-derived PAYMENT commit: ${commitP.slice(0,32)}... match=${matchP}`);
    console.log(`  Re-derived CHANGE mask:   ${bytesToHex(maskC).slice(0,32)}...`);
    console.log(`  Re-derived CHANGE commit:  ${commitC.slice(0,32)}... match=${matchC}`);
    console.log(`  Stored mask matches PAYMENT: ${o.mask === bytesToHex(maskP)}`);
    console.log(`  Stored mask matches CHANGE:  ${o.mask === bytesToHex(maskC)}`);
    console.log(`  Stored mask matches neither: ${o.mask !== bytesToHex(maskP) && o.mask !== bytesToHex(maskC)}`);
  }
  console.log();
}
