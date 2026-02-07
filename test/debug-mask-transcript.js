#!/usr/bin/env bun
/**
 * Byte-level transcript comparison for CARROT commitment mask derivation.
 * Build the exact transcript and compare with C++ expected format.
 */
import { setCryptoBackend, blake2b, commit } from '../src/crypto/index.js';
import { getCryptoBackend } from '../src/crypto/provider.js';

await setCryptoBackend('wasm');

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Values from the trace:
const ctx = hexToBytes('893fb15716d2367f3812a9098c7f366f912ef8346e74e4d03027eef53ee5f21c');
const amount = 2366447376n;
const Ks = hexToBytes('74861e06908f0af207df6f20b78164836b5e831bef870b63e690cdc595d50544');
const expectedCommitment = hexToBytes('fdd6e627997742579544cc64529aeb73a7b3770555bbc73056786adccfea15e4');

// Build transcript manually exactly as C++ SpFixedTranscript would
const domain = 'Carrot commitment mask';
const domainBytes = new TextEncoder().encode(domain);

// Amount in 8-byte LE
const amountBytes = new Uint8Array(8);
let a = amount;
for (let i = 0; i < 8; i++) { amountBytes[i] = Number(a & 0xffn); a >>= 8n; }

// C++ transcript format:
// [domain_len: 1 byte] [domain: 22 bytes] [amount: 8 bytes LE] [K_s: 32 bytes] [enote_type: 1 byte]
for (const enoteType of [0, 1]) {
  const typeBytes = new Uint8Array([enoteType]);

  const transcript = new Uint8Array(1 + 22 + 8 + 32 + 1);
  let offset = 0;
  transcript[offset++] = domainBytes.length; // 22
  transcript.set(domainBytes, offset); offset += domainBytes.length;
  transcript.set(amountBytes, offset); offset += 8;
  transcript.set(Ks, offset); offset += 32;
  transcript.set(typeBytes, offset); offset += 1;

  console.log(`=== enoteType=${enoteType} ===`);
  console.log(`Transcript (${transcript.length} bytes):`);
  console.log(`  [0] domain_len: ${transcript[0]}`);
  console.log(`  [1..22] domain: "${domain}"`);
  console.log(`  [23..30] amount: ${bytesToHex(amountBytes)} (= ${amount})`);
  console.log(`  [31..62] K_s: ${bytesToHex(Ks)}`);
  console.log(`  [63] enoteType: ${enoteType}`);
  console.log(`  Full hex: ${bytesToHex(transcript)}`);

  // blake2b keyed hash (64-byte output)
  const hash64 = blake2b(transcript, 64, ctx);
  console.log(`blake2b(transcript, 64, key=ctx): ${bytesToHex(hash64)}`);

  // sc_reduce to get the mask
  const backend = getCryptoBackend();
  const mask = backend.scReduce64(hash64);
  console.log(`sc_reduce64 → mask: ${bytesToHex(mask)}`);

  // Compute commitment
  const c = commit(amount, mask);
  console.log(`commit(${amount}, mask) = ${bytesToHex(c)}`);
  console.log(`Expected (outPk):     ${bytesToHex(expectedCommitment)}`);
  console.log(`Match: ${bytesToHex(c) === bytesToHex(expectedCommitment)}`);
  console.log();
}

// Also try: what if the amount bytes are in the wrong order? (big-endian vs little-endian)
console.log(`=== Try with amount in BIG-ENDIAN ===`);
const amountBE = new Uint8Array(8);
a = amount;
for (let i = 7; i >= 0; i--) { amountBE[i] = Number(a & 0xffn); a >>= 8n; }
console.log(`Amount LE: ${bytesToHex(amountBytes)}`);
console.log(`Amount BE: ${bytesToHex(amountBE)}`);

const transcriptBE = new Uint8Array(1 + 22 + 8 + 32 + 1);
let off = 0;
transcriptBE[off++] = domainBytes.length;
transcriptBE.set(domainBytes, off); off += domainBytes.length;
transcriptBE.set(amountBE, off); off += 8;
transcriptBE.set(Ks, off); off += 32;
transcriptBE[off++] = 0; // PAYMENT

const hash64BE = blake2b(transcriptBE, 64, ctx);
const maskBE = getCryptoBackend().scReduce64(hash64BE);
const cBE = commit(amount, maskBE);
console.log(`commit with BE amount: ${bytesToHex(cBE)}`);
console.log(`Match: ${bytesToHex(cBE) === bytesToHex(expectedCommitment)}`);

// What if there's an extra null terminator on the domain?
console.log(`\n=== Try with null-terminated domain ===`);
const domainNT = new Uint8Array(23);
domainNT.set(domainBytes, 0); // byte 22 is automatically 0 (null terminator)

const transcriptNT = new Uint8Array(1 + 23 + 8 + 32 + 1);
off = 0;
transcriptNT[off++] = 23; // domain len includes null
transcriptNT.set(domainNT, off); off += 23;
transcriptNT.set(amountBytes, off); off += 8;
transcriptNT.set(Ks, off); off += 32;
transcriptNT[off++] = 0;

const hash64NT = blake2b(transcriptNT, 64, ctx);
const maskNT = getCryptoBackend().scReduce64(hash64NT);
const cNT = commit(amount, maskNT);
console.log(`commit with NT domain: ${bytesToHex(cNT)}`);
console.log(`Match: ${bytesToHex(cNT) === bytesToHex(expectedCommitment)}`);
