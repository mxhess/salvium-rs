#!/usr/bin/env bun
/**
 * Debug X25519 implementation
 * Tests the X25519 scalar multiplication against known test vectors
 */

import { x25519ScalarMult, edwardsToMontgomeryU } from '../src/carrot-scanning.js';
import { hexToBytes, bytesToHex } from '../src/address.js';

// RFC 7748 Section 5.2 test vectors
// These are the EXACT values from the RFC
// The scalars already have bits 0-2 and 255 cleared (but bit 254 set)
const rfcTestVectors = [
  {
    // First iteration of the RFC loop
    // input k = 0x0900... (but this is also u, so we use it as both)
    // After one iteration: output = 422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079
    scalar: '0900000000000000000000000000000000000000000000000000000000000000',
    u: '0900000000000000000000000000000000000000000000000000000000000000',
    // Expected after clamp and scalar mult
    expected: '422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079'
  }
];

// RFC 7748 Section 6.1 test vector (Alice's public key)
// Here the private key is random and NEEDS clamping
// After clamping: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c6a
// (note last byte changes from 2a to 6a because bit 254 is set)
const aliceTest = {
  // Alice's secret key (before clamping)
  scalar: '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a',
  // The standard basepoint u=9
  u: '0900000000000000000000000000000000000000000000000000000000000000',
  // Expected public key (with standard RFC clamping that sets bit 254)
  expectedRfc: '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
};

console.log('=== X25519 Test Vectors ===\n');

// Test 1: RFC 5.2 - First iteration (k=9, u=9)
console.log('Test 1: RFC 7748 Section 5.2 - First iteration');
console.log('  Scalar:', rfcTestVectors[0].scalar);
console.log('  U:', rfcTestVectors[0].u);
const result1 = x25519ScalarMult(hexToBytes(rfcTestVectors[0].scalar), hexToBytes(rfcTestVectors[0].u));
const result1Hex = bytesToHex(result1);
console.log('  Expected:', rfcTestVectors[0].expected);
console.log('  Got:     ', result1Hex);
console.log('  Match:', result1Hex === rfcTestVectors[0].expected ? 'YES' : 'NO');

console.log('\n---\n');

// Test 2: Alice's public key (needs to understand clamping difference)
console.log('Test 2: Alice key generation (RFC vs Salvium clamping)');
console.log('  Scalar (raw):', aliceTest.scalar);

// Standard RFC clamping: clear bits 0-2, clear bit 255, SET bit 254
const aliceScalar = hexToBytes(aliceTest.scalar);
const rfcClamped = new Uint8Array(aliceScalar);
rfcClamped[0] &= 248;
rfcClamped[31] &= 127;
rfcClamped[31] |= 64;  // Set bit 254
console.log('  RFC clamped scalar:', bytesToHex(rfcClamped));

// Salvium/mx25519 clamping: clear bits 0-2, clear bit 255, do NOT set bit 254
const salviumClamped = new Uint8Array(aliceScalar);
salviumClamped[0] &= 248;
salviumClamped[31] &= 127;
// Do NOT set bit 254
console.log('  Salvium clamped scalar:', bytesToHex(salviumClamped));

// Test with Salvium clamping (what my implementation does internally)
const result2 = x25519ScalarMult(hexToBytes(aliceTest.scalar), hexToBytes(aliceTest.u));
const result2Hex = bytesToHex(result2);
console.log('  RFC expected (with bit 254 set):', aliceTest.expectedRfc);
console.log('  Got (Salvium clamping):          ', result2Hex);

console.log('\n---\n');

// Test 3: Simple scalar=1 test to verify basic operation
console.log('Test 3: Simple test - scalar=1 * basepoint should equal basepoint');
const scalarOne = new Uint8Array(32);
scalarOne[0] = 1;  // scalar = 1 (little-endian)
const basepoint = hexToBytes('0900000000000000000000000000000000000000000000000000000000000000');
const result3 = x25519ScalarMult(scalarOne, basepoint);
const result3Hex = bytesToHex(result3);
console.log('  Scalar: 1');
console.log('  U: 9');
console.log('  Expected: 9 (basepoint)');
console.log('  Got:', result3Hex);
// Note: with clamping, scalar 1 becomes 0 (bits 0-2 cleared), so result should be 0

console.log('\n---\n');

// Test 4: scalar=8 test (first non-zero clamped value)
console.log('Test 4: scalar=8 * basepoint (8 is smallest non-zero after clamping)');
const scalar8 = new Uint8Array(32);
scalar8[0] = 8;  // scalar = 8 (little-endian)
const result4 = x25519ScalarMult(scalar8, basepoint);
const result4Hex = bytesToHex(result4);
console.log('  Scalar: 8');
console.log('  U: 9 (basepoint)');
console.log('  Got:', result4Hex);
// Expected: 8 * 9 on Curve25519

console.log('\n---\n');

// Test 5: Debug the Montgomery ladder step by step
console.log('Test 5: Debug info for scalar=9, u=9');
const scalar9 = hexToBytes('0900000000000000000000000000000000000000000000000000000000000000');
const u9 = hexToBytes('0900000000000000000000000000000000000000000000000000000000000000');

// Convert to BigInt to check values
let scalarVal = 0n;
let uVal = 0n;
for (let i = 31; i >= 0; i--) {
  scalarVal = (scalarVal << 8n) | BigInt(scalar9[i]);
  uVal = (uVal << 8n) | BigInt(u9[i]);
}
console.log('  Scalar as BigInt:', scalarVal);
console.log('  U as BigInt:', uVal);

// After clamping
const clampedScalar9 = new Uint8Array(scalar9);
clampedScalar9[0] &= 248;
clampedScalar9[31] &= 127;
let clampedVal = 0n;
for (let i = 31; i >= 0; i--) {
  clampedVal = (clampedVal << 8n) | BigInt(clampedScalar9[i]);
}
console.log('  Clamped scalar:', clampedVal);

console.log('\n=== End of Tests ===');
