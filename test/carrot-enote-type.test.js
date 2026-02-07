#!/usr/bin/env bun
/**
 * Unit test: verify CARROT enoteType PAYMENT/CHANGE mask derivation
 * matches C++ try_get_carrot_amount behavior.
 *
 * No daemon needed - pure crypto verification.
 */

import { deriveCarrotCommitmentMask } from '../src/carrot-scanning.js';
import { commit, scalarMultBase } from '../src/crypto/index.js';

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++)
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

let passed = 0, failed = 0;
function assert(condition, msg) {
  if (condition) { passed++; console.log(`  ✓ ${msg}`); }
  else { failed++; console.log(`  ✗ ${msg}`); }
}

console.log('=== CARROT enoteType PAYMENT/CHANGE test ===\n');

// Generate deterministic test inputs
const sharedSecret = new Uint8Array(32);
sharedSecret[0] = 0xAA; sharedSecret[1] = 0xBB;
const amount = 12345678n;
const spendPubkey = scalarMultBase(new Uint8Array(32).fill(0x42));

// 1. PAYMENT (type 0) and CHANGE (type 1) must produce DIFFERENT masks
const maskPayment = deriveCarrotCommitmentMask(sharedSecret, amount, spendPubkey, 0);
const maskChange  = deriveCarrotCommitmentMask(sharedSecret, amount, spendPubkey, 1);

assert(bytesToHex(maskPayment) !== bytesToHex(maskChange),
  'PAYMENT and CHANGE masks are different');

// 2. Each mask produces a valid commitment
const commitPayment = commit(amount, maskPayment);
const commitChange  = commit(amount, maskChange);

assert(commitPayment.length === 32, 'PAYMENT commitment is 32 bytes');
assert(commitChange.length === 32, 'CHANGE commitment is 32 bytes');
assert(bytesToHex(commitPayment) !== bytesToHex(commitChange),
  'PAYMENT and CHANGE commitments differ');

// 3. Simulate try-both logic (like C++ try_get_carrot_amount)
// Create an output with CHANGE type commitment
const blockchainCommitment = bytesToHex(commitChange);

// Try PAYMENT first
const testMaskP = deriveCarrotCommitmentMask(sharedSecret, amount, spendPubkey, 0);
const testCommitP = bytesToHex(commit(amount, testMaskP));
const paymentMatches = testCommitP === blockchainCommitment;

// Try CHANGE
const testMaskC = deriveCarrotCommitmentMask(sharedSecret, amount, spendPubkey, 1);
const testCommitC = bytesToHex(commit(amount, testMaskC));
const changeMatches = testCommitC === blockchainCommitment;

assert(!paymentMatches, 'PAYMENT type does NOT match CHANGE commitment');
assert(changeMatches, 'CHANGE type DOES match CHANGE commitment');

// 4. Determinism: same inputs -> same mask
const mask2 = deriveCarrotCommitmentMask(sharedSecret, amount, spendPubkey, 0);
assert(bytesToHex(maskPayment) === bytesToHex(mask2), 'Mask derivation is deterministic');

// 5. Different amounts -> different masks
const maskDiffAmt = deriveCarrotCommitmentMask(sharedSecret, 99999999n, spendPubkey, 0);
assert(bytesToHex(maskPayment) !== bytesToHex(maskDiffAmt),
  'Different amounts produce different masks');

console.log(`\nPassed: ${passed}, Failed: ${failed}`);
if (failed > 0) process.exit(1);
console.log('All tests passed!');
