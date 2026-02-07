#!/usr/bin/env bun
/**
 * Deep trace: step through CARROT scanning for one real output,
 * logging every intermediate value to compare with C++.
 */
import { setCryptoBackend, blake2b, commit } from '../src/crypto/index.js';
import {
  makeCarrotSenderReceiverSecret, computeCarrotViewTag,
  deriveCarrotCommitmentMask, decryptCarrotAmount,
  scanCarrotOutput
} from '../src/carrot-scanning.js';
import { blake2b as jsBlake2b } from '../src/blake2b.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { parseTransaction } from '../src/transaction/parsing.js';
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

const daemon = new DaemonRPC({ url: 'http://web.whiskymine.io:29081' });

// Load wallet keys
const walletJson = JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a.json`, 'utf-8'));
const viewIncomingKey = hexToBytes(walletJson.carrotKeys.viewIncomingKey);
const accountSpendPubkey = hexToBytes(walletJson.carrotKeys.accountSpendPubkey);
console.log(`viewIncomingKey: ${bytesToHex(viewIncomingKey)}`);
console.log(`accountSpendPubkey: ${bytesToHex(accountSpendPubkey)}`);

// Get the first problematic TX
const txHash = 'd2ad187cc0dde491';  // First 16 chars, need full hash
// Load from sync cache to get full hash
const { MemoryStorage } = await import('../src/wallet-store.js');
const storage = new MemoryStorage();
storage.load(JSON.parse(readFileSync(`${process.env.HOME}/testnet-wallet/wallet-a-sync.json`, 'utf-8')));
const allOutputs = await storage.getOutputs({ isSpent: false });
const target = allOutputs.find(o => o.isCarrot && o.commitment && o.txHash?.startsWith('d2ad187cc0dde491'));
if (!target) { console.log('Target output not found'); process.exit(1); }

console.log(`\nTarget TX: ${target.txHash}`);
console.log(`Output index: ${target.outputIndex}`);
console.log(`Stored amount: ${target.amount}`);
console.log(`Stored commitment: ${target.commitment}`);
console.log(`Stored mask: ${target.mask}`);
console.log(`Stored shared secret: ${target.carrotSharedSecret}`);

// Fetch the actual transaction from daemon
const txResp = await daemon.getTransactions([target.txHash], true, false);
const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
const parsed = parseTransaction(hexToBytes(txData.as_hex));

console.log(`\nParsed TX:`);
console.log(`  rctType: ${parsed.rct?.type}`);
console.log(`  outputs: ${parsed.prefix?.vout?.length}`);
console.log(`  ecdhInfo[${target.outputIndex}].amount: ${bytesToHex(parsed.rct?.ecdhInfo?.[target.outputIndex]?.amount || new Uint8Array(8))}`);
console.log(`  outPk[${target.outputIndex}]: ${bytesToHex(parsed.rct?.outPk?.[target.outputIndex] || new Uint8Array(32))}`);

// Extract the enoteEphemeralPubkey (D_e) from tx_extra
const txPubKey = parsed.prefix?.extra?.find(e => e.type === 0x01)?.key;
console.log(`  txPubKey (D_e): ${txPubKey ? bytesToHex(txPubKey) : 'null'}`);

// Now manually trace through the CARROT scanning
const outputData = parsed.prefix.vout[target.outputIndex];
const onetimeAddress = outputData.key;
const viewTag = outputData.viewTag;
console.log(`\n=== CARROT Scanning Trace ===`);
console.log(`  onetimeAddress (Ko): ${bytesToHex(onetimeAddress)}`);
console.log(`  viewTag (3 bytes): ${bytesToHex(viewTag)}`);
console.log(`  enoteEphemeralPubkey (D_e): ${bytesToHex(txPubKey)}`);

// Step 1: X25519 ECDH
// s_sr_unctx = k_vi * D_e
// We can't directly compute X25519 without exposing the internal, but we can check
// if scanCarrotOutput gets the same shared secret
const encAmount = parsed.rct?.ecdhInfo?.[target.outputIndex]?.amount;
const amountCommitment = parsed.rct?.outPk?.[target.outputIndex];
console.log(`  amountCommitment (outPk): ${bytesToHex(amountCommitment)}`);
console.log(`  encryptedAmount: ${bytesToHex(encAmount)}`);

// Build input context
const inputs = parsed.prefix?.vin || [];
const firstKi = inputs[0]?.keyImage;
let inputContext;
if (firstKi) {
  inputContext = new Uint8Array(33);
  inputContext[0] = 0x52; // 'R'
  inputContext.set(typeof firstKi === 'string' ? hexToBytes(firstKi) : firstKi, 1);
  console.log(`  inputContext: R + ${bytesToHex(firstKi).slice(0,32)}...`);
} else {
  console.log(`  inputContext: coinbase`);
}

// Try scanning manually to capture intermediate values
// We can't easily instrument scanCarrotOutput without modifying it,
// but we can verify the stored shared secret is correct by re-deriving
// the mask and amount

const ctx = hexToBytes(target.carrotSharedSecret);
console.log(`\n=== Verify amount decryption ===`);
const decryptedAmount = decryptCarrotAmount(encAmount, ctx, onetimeAddress);
console.log(`  Decrypted amount: ${decryptedAmount}`);
console.log(`  Stored amount: ${target.amount}`);
console.log(`  Match: ${decryptedAmount === target.amount}`);

console.log(`\n=== Verify mask derivation ===`);
for (const type of [0, 1]) {
  const mask = deriveCarrotCommitmentMask(ctx, decryptedAmount, accountSpendPubkey, type);
  const c = commit(decryptedAmount, mask);
  console.log(`  enoteType=${type}: mask=${bytesToHex(mask).slice(0,32)}...`);
  console.log(`    commit=${bytesToHex(c).slice(0,32)}...`);
  console.log(`    matches outPk: ${bytesToHex(c) === bytesToHex(amountCommitment)}`);
}

// Also try with the stored amount (might differ from decrypted)
if (decryptedAmount !== target.amount) {
  console.log(`\n=== Try with stored amount (${target.amount}) ===`);
  for (const type of [0, 1]) {
    const mask = deriveCarrotCommitmentMask(ctx, BigInt(target.amount), accountSpendPubkey, type);
    const c = commit(BigInt(target.amount), mask);
    console.log(`  enoteType=${type}: commit=${bytesToHex(c).slice(0,32)}... matches=${bytesToHex(c) === bytesToHex(amountCommitment)}`);
  }
}

// Test blake2b itself: compute a known hash to verify
console.log(`\n=== Blake2b sanity check ===`);
const testData = new Uint8Array([1, 2, 3, 4]);
const testKey = new Uint8Array(32).fill(0x42);
const wasmHash = blake2b(testData, 32, testKey);
const jsHash = jsBlake2b(testData, 32, testKey);
console.log(`  WASM blake2b: ${bytesToHex(wasmHash)}`);
console.log(`  JS blake2b:   ${bytesToHex(jsHash)}`);
console.log(`  Match: ${bytesToHex(wasmHash) === bytesToHex(jsHash)}`);

// One more thing: check which blake2b carrot-scanning actually uses
// (it imports from crypto/index.js which goes through the provider)
console.log(`\n=== Check which blake2b carrot-scanning uses ===`);
// The makeTranscript + blake2b path in deriveBytes8:
// transcript = [len] domain [Ko]
const domain = "Carrot encryption mask a";
const domainBytes = new TextEncoder().encode(domain);
const transcript = new Uint8Array(1 + domainBytes.length + onetimeAddress.length);
transcript[0] = domainBytes.length;
transcript.set(domainBytes, 1);
transcript.set(onetimeAddress, 1 + domainBytes.length);
console.log(`  transcript (${transcript.length} bytes): ${bytesToHex(transcript).slice(0,80)}...`);
const amountMask = blake2b(transcript, 8, ctx);
console.log(`  blake2b(transcript, 8, ctx) = ${bytesToHex(amountMask)}`);

// XOR with encrypted amount
const decrypted = new Uint8Array(8);
for (let i = 0; i < 8; i++) decrypted[i] = encAmount[i] ^ amountMask[i];
let manualAmount = 0n;
for (let i = 7; i >= 0; i--) manualAmount = (manualAmount << 8n) | BigInt(decrypted[i]);
console.log(`  Encrypted amount: ${bytesToHex(encAmount)}`);
console.log(`  XOR mask:         ${bytesToHex(amountMask)}`);
console.log(`  Decrypted bytes:  ${bytesToHex(decrypted)}`);
console.log(`  Decrypted value:  ${manualAmount}`);
