#!/usr/bin/env bun
/**
 * Check if outPk = 8 * commit(amount, mask), or other systematic relationships.
 * Also dump the full blake2b transcript for manual comparison.
 */
import { setCryptoBackend, blake2b, commit, scalarMultPoint, scalarMultBase, pointAddCompressed } from '../src/crypto/index.js';
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
const storage = new MemoryStorage();
storage.load(JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a-sync.json`, 'utf-8')));
const allOutputs = await storage.getOutputs({ isSpent: false });
const carrotOutputs = allOutputs.filter(o => o.isCarrot && o.commitment && o.mask);

console.log(`CARROT outputs with commitment+mask: ${carrotOutputs.length}\n`);

const o = carrotOutputs[0];
const amount = BigInt(o.amount);
const mask = hexToBytes(o.mask);
const outPk = hexToBytes(o.commitment);

console.log(`TX: ${o.txHash?.slice(0,16)}... idx=${o.outputIndex}`);
console.log(`Amount: ${amount}`);
console.log(`Mask:   ${bytesToHex(mask)}`);
console.log(`OutPk:  ${bytesToHex(outPk)}`);

// Standard commitment
const C = commit(amount, mask);
console.log(`\nC = commit(amount, mask): ${bytesToHex(C)}`);
console.log(`C == outPk: ${bytesToHex(C) === bytesToHex(outPk)}`);

// Check 8*C
const eight = new Uint8Array(32);
eight[0] = 8;
const C8 = scalarMultPoint(eight, C);
console.log(`\n8*C = scalarmult8(C): ${bytesToHex(C8)}`);
console.log(`8*C == outPk: ${bytesToHex(C8) === bytesToHex(outPk)}`);

// Check if outPk = mask*G + amount*H is using a different mask
// Try with WASM scReduce64 instead of JS BigInt scReduce
const domain = 'Carrot commitment mask';
const domainBytes = new TextEncoder().encode(domain);
const Ks = hexToBytes('74861e06908f0af207df6f20b78164836b5e831bef870b63e690cdc595d50544');
const ctx = hexToBytes(o.carrotSharedSecret);

// Build transcript manually
const amountBytes = new Uint8Array(8);
let a = amount;
for (let i = 0; i < 8; i++) { amountBytes[i] = Number(a & 0xffn); a >>= 8n; }

for (const enoteType of [0, 1]) {
  const typeBytes = new Uint8Array([enoteType]);
  const transcript = new Uint8Array(1 + domainBytes.length + 8 + 32 + 1);
  let off = 0;
  transcript[off++] = domainBytes.length;
  transcript.set(domainBytes, off); off += domainBytes.length;
  transcript.set(amountBytes, off); off += 8;
  transcript.set(Ks, off); off += 32;
  transcript.set(typeBytes, off); off += 1;

  console.log(`\n=== enoteType=${enoteType} ===`);
  console.log(`Transcript (${transcript.length} bytes): ${bytesToHex(transcript)}`);

  // blake2b keyed hash, 64-byte output, key = ctx
  const hash64 = blake2b(transcript, 64, ctx);
  console.log(`blake2b(transcript, 64, key=ctx): first32=${bytesToHex(hash64).slice(0,64)}...`);

  // JS BigInt scReduce
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  let n = 0n;
  for (let i = 63; i >= 0; i--) n = (n << 8n) | BigInt(hash64[i]);
  n = n % L;
  const jsReduced = new Uint8Array(32);
  let tmp = n;
  for (let i = 0; i < 32; i++) { jsReduced[i] = Number(tmp & 0xffn); tmp >>= 8n; }

  // WASM scReduce64
  const wasmReduced = backend.scReduce64(new Uint8Array(hash64));

  console.log(`JS scReduce:   ${bytesToHex(jsReduced)}`);
  console.log(`WASM scReduce: ${bytesToHex(wasmReduced)}`);
  console.log(`Match: ${bytesToHex(jsReduced) === bytesToHex(wasmReduced)}`);

  // Commit with both
  const cJS = commit(amount, jsReduced);
  const cWASM = commit(amount, wasmReduced);
  console.log(`commit(amount, jsReduced):   ${bytesToHex(cJS)}`);
  console.log(`commit(amount, wasmReduced): ${bytesToHex(cWASM)}`);
  console.log(`JS matches outPk:   ${bytesToHex(cJS) === bytesToHex(outPk)}`);
  console.log(`WASM matches outPk: ${bytesToHex(cWASM) === bytesToHex(outPk)}`);

  // Check 8*C
  const cJS8 = scalarMultPoint(eight, cJS);
  console.log(`8*commit(JS) matches outPk: ${bytesToHex(cJS8) === bytesToHex(outPk)}`);
}

// Also: what if we need amount as varint/compact form instead of 8-byte LE?
console.log(`\n=== Extra: amount encoding tests ===`);
console.log(`Amount hex (8-byte LE): ${bytesToHex(amountBytes)}`);
// Try as 4-byte LE (fits in uint32)
const amount4 = new Uint8Array(4);
a = amount;
for (let i = 0; i < 4; i++) { amount4[i] = Number(a & 0xffn); a >>= 8n; }
console.log(`Amount hex (4-byte LE): ${bytesToHex(amount4)}`);

// What if Salvium uses 32-byte amount in transcript?
const amount32 = new Uint8Array(32);
a = BigInt(o.amount);
for (let i = 0; i < 32 && a > 0n; i++) { amount32[i] = Number(a & 0xffn); a >>= 8n; }
console.log(`Amount hex (32-byte LE): ${bytesToHex(amount32)}`);
