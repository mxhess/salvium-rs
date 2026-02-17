#!/usr/bin/env bun
/**
 * Try ALL permutations of inputs to deriveCarrotCommitmentMask
 * to find which combination produces the correct commitment.
 */
import { setCryptoBackend, blake2b, commit, scalarMultBase, scalarMultPoint, pointAddCompressed } from '../src/crypto/index.js';
import { getCryptoBackend } from '../src/crypto/provider.js';
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

const backend = getCryptoBackend();
const w = JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a.json`, 'utf-8'));
const storage = new MemoryStorage();
storage.load(JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a-sync.json`, 'utf-8')));
const allOutputs = await storage.getOutputs({ isSpent: false });
const target = allOutputs.find(o => o.isCarrot && o.commitment && o.txHash?.startsWith('d2ad187c'));

const amount = BigInt(target.amount);
const outPk = hexToBytes(target.commitment);
const ctx = hexToBytes(target.carrotSharedSecret); // s_sender_receiver_CTX

// Our accountSpendPubkey (CARROT K_s)
const Ks = hexToBytes(w.carrotKeys.accountSpendPubkey);

// CryptoNote spend pubkey (different from CARROT K_s!)
const cnSpendPub = hexToBytes(w.spendPublicKey);

// We don't have s_sr_unctx stored, but let's check if it was stored elsewhere
// The carrotSharedSecret should be the CONTEXTUALIZED one

function deriveAndCompare(label, key, Ks_param, enoteType) {
  const domain = 'Carrot commitment mask';
  const domainBytes = new TextEncoder().encode(domain);
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) { amountBytes[i] = Number(a & 0xffn); a >>= 8n; }
  const typeBytes = new Uint8Array([enoteType]);

  const transcript = new Uint8Array(1 + domainBytes.length + 8 + 32 + 1);
  let off = 0;
  transcript[off++] = domainBytes.length;
  transcript.set(domainBytes, off); off += domainBytes.length;
  transcript.set(amountBytes, off); off += 8;
  transcript.set(Ks_param, off); off += 32;
  transcript.set(typeBytes, off);

  const hash64 = blake2b(transcript, 64, key);
  const mask = backend.scReduce64(hash64);
  const c = commit(amount, mask);
  const match = bytesToHex(c) === bytesToHex(outPk);

  if (match) {
    console.log(`*** MATCH *** ${label}: type=${enoteType}`);
    console.log(`  mask: ${bytesToHex(mask)}`);
  }
  return match;
}

console.log('Target: TX=' + target.txHash.slice(0,16) + ' idx=' + target.outputIndex);
console.log(`Amount: ${amount}`);
console.log(`OutPk: ${bytesToHex(outPk)}\n`);

console.log('=== Trying combinations ===');

// Standard CARROT K_s with CTX secret
for (const type of [0, 1, 2]) {
  deriveAndCompare(`ctx + CARROT_Ks`, ctx, Ks, type);
}

// CryptoNote spend pubkey with CTX secret
for (const type of [0, 1, 2]) {
  deriveAndCompare(`ctx + CN_SpendPub`, ctx, cnSpendPub, type);
}

// What if the CryptoNote VIEW pubkey is used?
const cnViewPub = hexToBytes(w.viewPublicKey);
for (const type of [0, 1, 2]) {
  deriveAndCompare(`ctx + CN_ViewPub`, ctx, cnViewPub, type);
}

// What if the CARROT view pubkey is used?
const carrotViewPub = hexToBytes(w.carrotKeys.primaryAddressViewPubkey);
for (const type of [0, 1, 2]) {
  deriveAndCompare(`ctx + CARROT_ViewPub`, ctx, carrotViewPub, type);
}

// What if there's an accountViewPubkey?
if (w.carrotKeys.accountViewPubkey) {
  const avp = hexToBytes(w.carrotKeys.accountViewPubkey);
  for (const type of [0, 1, 2]) {
    deriveAndCompare(`ctx + AccountViewPub`, ctx, avp, type);
  }
}

// What if the key for blake2b is wrong? Try unkeyed
for (const type of [0, 1, 2]) {
  const domain = 'Carrot commitment mask';
  const domainBytes = new TextEncoder().encode(domain);
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) { amountBytes[i] = Number(a & 0xffn); a >>= 8n; }
  const typeBytes = new Uint8Array([enoteType]);
  const transcript = new Uint8Array(1 + domainBytes.length + 8 + 32 + 1);
  let off = 0;
  transcript[off++] = domainBytes.length;
  transcript.set(domainBytes, off); off += domainBytes.length;
  transcript.set(amountBytes, off); off += 8;
  transcript.set(Ks, off); off += 32;
  transcript.set(new Uint8Array([type]), off);

  // Try unkeyed blake2b
  const hash64 = blake2b(transcript, 64, null);
  const mask = backend.scReduce64(hash64);
  const c = commit(amount, mask);
  if (bytesToHex(c) === bytesToHex(outPk)) {
    console.log(`*** MATCH *** unkeyed + CARROT_Ks type=${type}`);
  }
}

// What if the transcript order is different? (key, amount, type)
for (const type of [0, 1]) {
  const domain = 'Carrot commitment mask';
  const domainBytes = new TextEncoder().encode(domain);
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) { amountBytes[i] = Number(a & 0xffn); a >>= 8n; }

  // Try: [len][domain][K_s][amount][type]
  const t1 = new Uint8Array(1 + domainBytes.length + 32 + 8 + 1);
  let off = 0;
  t1[off++] = domainBytes.length;
  t1.set(domainBytes, off); off += domainBytes.length;
  t1.set(Ks, off); off += 32;
  t1.set(amountBytes, off); off += 8;
  t1[off] = type;
  const h1 = blake2b(t1, 64, ctx);
  const m1 = backend.scReduce64(h1);
  const c1 = commit(amount, m1);
  if (bytesToHex(c1) === bytesToHex(outPk)) {
    console.log(`*** MATCH *** reordered [Ks,amount,type] type=${type}`);
  }

  // Try: [len][domain][type][amount][K_s]
  const t2 = new Uint8Array(1 + domainBytes.length + 1 + 8 + 32);
  off = 0;
  t2[off++] = domainBytes.length;
  t2.set(domainBytes, off); off += domainBytes.length;
  t2[off++] = type;
  t2.set(amountBytes, off); off += 8;
  t2.set(Ks, off);
  const h2 = blake2b(t2, 64, ctx);
  const m2 = backend.scReduce64(h2);
  const c2 = commit(amount, m2);
  if (bytesToHex(c2) === bytesToHex(outPk)) {
    console.log(`*** MATCH *** reordered [type,amount,Ks] type=${type}`);
  }
}

// What if the commit function args are swapped?
const mask0 = hexToBytes('803b135e5613cdf4905268b48e408213b336ac491d81b67ce1adaf8d6673d004');
const cSwapped = commit(mask0, new Uint8Array(8)); // WRONG but let's check
// Actually, try commit with args in different order
// Our commit(amount, mask) = mask*G + amount*H
// What if C++ does commit(mask, amount)?
const amountAsScalar = new Uint8Array(32);
let a = amount;
for (let i = 0; i < 32 && a > 0n; i++) { amountAsScalar[i] = Number(a & 0xffn); a >>= 8n; }
const cReversed = commit(mask0, amountAsScalar);
console.log(`\ncommit with swapped args: ${bytesToHex(cReversed)}`);
console.log(`Match: ${bytesToHex(cReversed) === bytesToHex(outPk)}`);

console.log('\nDone - no match found' + (false ? '' : ''));
