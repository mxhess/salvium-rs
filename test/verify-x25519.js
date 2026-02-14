#!/usr/bin/env bun
/**
 * Verify X25519 implementation matches Salvium's mx25519
 *
 * This test verifies that:
 * 1. Edwards scalar mult followed by ed-to-mont conversion
 * 2. Direct X25519 scalar mult
 *
 * produce the same result (matching Salvium's x25519.cpp test)
 */

import { x25519ScalarMult, edwardsToMontgomeryU } from '../src/carrot-scanning.js';
import { scalarMultBase, scalarMultPoint } from '../src/crypto/index.js';
import { hexToBytes, bytesToHex } from '../src/address.js';

// X25519 basepoint u=9 (corresponds to Ed25519 generator G)
const X25519_BASEPOINT = new Uint8Array(32);
X25519_BASEPOINT[0] = 9;

// Ed25519 generator G (compressed)
const ED25519_G = hexToBytes('5866666666666666666666666666666666666666666666666666666666666666');

console.log('=== Verify X25519 Implementation ===\n');

// Test 1: Verify ed25519 G converts to X25519 basepoint 9
console.log('Test 1: Ed25519 G -> X25519 basepoint');
const gConverted = edwardsToMontgomeryU(ED25519_G);
console.log('  Ed25519 G:', bytesToHex(ED25519_G));
console.log('  Expected X25519 basepoint: 0900000000000000000000000000000000000000000000000000000000000000');
console.log('  Got:', bytesToHex(gConverted));
console.log('  Match:', bytesToHex(gConverted) === '0900000000000000000000000000000000000000000000000000000000000000' ? 'YES' : 'NO');

console.log('\n---\n');

// Test 2: Compare Edwards scalar mult + conversion vs X25519 scalar mult
// Using various scalars
const testScalars = [
  // Simple scalars (multiples of 8 for cofactor clearing)
  '0800000000000000000000000000000000000000000000000000000000000000', // 8
  '1000000000000000000000000000000000000000000000000000000000000000', // 16
  '1800000000000000000000000000000000000000000000000000000000000000', // 24
  // Larger scalars
  '0001000000000000000000000000000000000000000000000000000000000000', // 256
  '0010000000000000000000000000000000000000000000000000000000000000', // 4096
  // Random-looking scalar (but with bits 0-2 cleared)
  'a0b3c4d5e6f708192a3b4c5d6e7f80910a1b2c3d4e5f60718293a4b5c6d7e8f8',
];

console.log('Test 2: Compare Edwards vs X25519 scalar mult');
let allMatch = true;

for (const scalarHex of testScalars) {
  const scalar = hexToBytes(scalarHex);

  // Method 1: Edwards scalar mult, then convert to Montgomery
  // scalar * G on Edwards curve
  const edResult = scalarMultBase(scalar);
  const edConverted = edwardsToMontgomeryU(edResult);

  // Method 2: Direct X25519 scalar mult
  // scalar * 9 on Montgomery curve
  const x25519Result = x25519ScalarMult(scalar, X25519_BASEPOINT);

  const match = bytesToHex(edConverted) === bytesToHex(x25519Result);
  allMatch = allMatch && match;

  console.log(`  Scalar: ${scalarHex.slice(0, 16)}...`);
  console.log(`    Edwards -> Mont: ${bytesToHex(edConverted).slice(0, 32)}...`);
  console.log(`    X25519:          ${bytesToHex(x25519Result).slice(0, 32)}...`);
  console.log(`    Match: ${match ? 'YES' : 'NO'}`);
}

console.log(`\n  All tests: ${allMatch ? 'PASSED' : 'FAILED'}`);

console.log('\n---\n');

// Test 3: Test with the RFC 7748 point (Alice's public key)
// From x25519.cpp test: edwards point and its x25519 equivalent
console.log('Test 3: RFC 7748 Alice public key conversion');
const aliceEdwards = hexToBytes('8120f299c37ae1ca64a179f638a6c6fafde968f1c33705e28c413c7579d9884f');
const aliceX25519Expected = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';

const aliceConverted = edwardsToMontgomeryU(aliceEdwards);
console.log('  Edwards point:', bytesToHex(aliceEdwards));
console.log('  Expected X25519:', aliceX25519Expected);
console.log('  Got:', bytesToHex(aliceConverted));
console.log('  Match:', bytesToHex(aliceConverted) === aliceX25519Expected ? 'YES' : 'NO');

console.log('\n---\n');

// Test 4: Verify scalar mult with a non-basepoint
console.log('Test 4: Scalar mult with non-basepoint');
const scalar = hexToBytes('0800000000000000000000000000000000000000000000000000000000000000');
const point = hexToBytes('8120f299c37ae1ca64a179f638a6c6fafde968f1c33705e28c413c7579d9884f');
const pointX25519 = edwardsToMontgomeryU(point);

// Edwards: scalar * point
const edResult = scalarMultPoint(scalar, point);
const edConverted = edwardsToMontgomeryU(edResult);

// X25519: scalar * pointX25519
const x25519Result = x25519ScalarMult(scalar, pointX25519);

console.log('  Scalar: 8');
console.log('  Point (Edwards):', bytesToHex(point).slice(0, 32) + '...');
console.log('  Point (X25519):', bytesToHex(pointX25519).slice(0, 32) + '...');
console.log('  Edwards result -> Mont:', bytesToHex(edConverted).slice(0, 32) + '...');
console.log('  X25519 result:', bytesToHex(x25519Result).slice(0, 32) + '...');
console.log('  Match:', bytesToHex(edConverted) === bytesToHex(x25519Result) ? 'YES' : 'NO');

console.log('\n=== End of Verification ===');
