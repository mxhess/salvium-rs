#!/usr/bin/env bun
/**
 * Compare CryptoNote (working) vs CARROT (broken) commitment verification.
 * Find what's different.
 */
import { setCryptoBackend, commit, scalarMultBase } from '../src/crypto/index.js';
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

// Find CryptoNote outputs with commitment + mask
const cnOutputs = allOutputs.filter(o => !o.isCarrot && o.commitment && o.mask);
const carrotOutputs = allOutputs.filter(o => o.isCarrot && o.commitment && o.mask);

console.log(`CryptoNote outputs with commitment+mask: ${cnOutputs.length}`);
console.log(`CARROT outputs with commitment+mask: ${carrotOutputs.length}`);

// Test CryptoNote outputs
console.log('\n=== CryptoNote outputs ===');
let cnPass = 0, cnFail = 0;
for (const o of cnOutputs.slice(0, 5)) {
  const mask = hexToBytes(o.mask);
  const c = commit(BigInt(o.amount), mask);
  const matches = bytesToHex(c) === o.commitment;
  if (matches) cnPass++; else cnFail++;
  console.log(`TX ${o.txHash?.slice(0,12)} idx=${o.outputIndex} amount=${o.amount} match=${matches} rctType=${o.rctType || '?'}`);
  if (!matches) {
    console.log(`  computed: ${bytesToHex(c)}`);
    console.log(`  stored:   ${o.commitment}`);
  }
}
console.log(`CryptoNote: ${cnPass} pass, ${cnFail} fail`);

// Test CARROT outputs
console.log('\n=== CARROT outputs ===');
let crPass = 0, crFail = 0;
for (const o of carrotOutputs.slice(0, 5)) {
  const mask = hexToBytes(o.mask);
  const c = commit(BigInt(o.amount), mask);
  const matches = bytesToHex(c) === o.commitment;
  if (matches) crPass++; else crFail++;
  console.log(`TX ${o.txHash?.slice(0,12)} idx=${o.outputIndex} amount=${o.amount} match=${matches} enoteType=${o.carrotEnoteType ?? o.enoteType ?? '?'}`);
  if (!matches) {
    console.log(`  computed: ${bytesToHex(c)}`);
    console.log(`  stored:   ${o.commitment}`);
    console.log(`  mask:     ${o.mask}`);
    console.log(`  secret:   ${o.carrotSharedSecret?.slice(0,32) || 'N/A'}...`);
  }
}
console.log(`CARROT: ${crPass} pass, ${crFail} fail`);

// For CryptoNote outputs, show how the mask was derived
console.log('\n=== CryptoNote mask derivation method ===');
for (const o of cnOutputs.slice(0, 2)) {
  console.log(`TX ${o.txHash?.slice(0,12)} idx=${o.outputIndex}`);
  console.log(`  mask: ${o.mask}`);
  console.log(`  derivation: ${o.derivation || 'N/A'}`);
  console.log(`  txPubKey: ${o.txPubKey || 'N/A'}`);
  console.log(`  All fields: ${Object.keys(o).join(', ')}`);
}

// For CARROT outputs, show how the mask was derived
console.log('\n=== CARROT mask derivation inputs ===');
for (const o of carrotOutputs.slice(0, 2)) {
  console.log(`TX ${o.txHash?.slice(0,12)} idx=${o.outputIndex}`);
  console.log(`  mask: ${o.mask}`);
  console.log(`  sharedSecret: ${o.carrotSharedSecret || 'N/A'}`);
  console.log(`  enoteType: ${o.carrotEnoteType ?? o.enoteType ?? 'NOT SET'}`);
  console.log(`  All fields: ${Object.keys(o).join(', ')}`);
}
