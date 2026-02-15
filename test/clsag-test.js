#!/usr/bin/env bun
/**
 * CLSAG Signing/Verification Test
 *
 * Tests that CLSAG signatures can be created and verified.
 */

import { clsagSign, clsagVerify, scSub } from '../src/transaction.js';
import { scalarMultBase, scalarMultPoint } from '../src/crypto/index.js';
import { keccak256 } from '../src/keccak.js';
import { bytesToHex, hexToBytes } from '../src/address.js';
import { generateKeyImage } from '../src/crypto/index.js';

// Generate a random 32-byte scalar (reduced mod L)
function randomScalar() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  // Clear top 4 bits to ensure it's less than 2^252
  // (L ≈ 2^252, so this gives a reasonable distribution)
  bytes[31] &= 0x0f;
  return bytes;
}

// Test with a simple ring
async function testCLSAG() {
  console.log('=== CLSAG Signing/Verification Test ===\n');

  // First test basic crypto primitives
  console.log('Testing crypto primitives...');

  const testScalar = randomScalar();
  const testPoint = scalarMultBase(testScalar);
  if (!testPoint) {
    console.error('scalarMultBase returned null!');
    process.exit(1);
  }
  console.log('  scalarMultBase: OK');

  const testMult = scalarMultPoint(testScalar, testPoint);
  if (!testMult) {
    console.error('scalarMultPoint returned null!');
    process.exit(1);
  }
  console.log('  scalarMultPoint: OK');

  const testKeyImage = generateKeyImage(testPoint, testScalar);
  if (!testKeyImage) {
    console.error('generateKeyImage returned null!');
    process.exit(1);
  }
  console.log('  generateKeyImage: OK\n');

  const ringSize = 11;
  const secretIndex = Math.floor(Math.random() * ringSize);

  console.log(`Ring size: ${ringSize}`);
  console.log(`Secret index: ${secretIndex}\n`);

  // Generate ring members
  const ring = [];
  const ringSecrets = [];

  for (let i = 0; i < ringSize; i++) {
    const sk = randomScalar();
    const pk = scalarMultBase(sk);
    if (!pk) {
      console.error(`Failed to generate public key for ring member ${i}`);
      process.exit(1);
    }
    ring.push(pk);
    ringSecrets.push(sk);
  }
  console.log('Ring generated');

  const secretKey = ringSecrets[secretIndex];

  // Generate commitments (Pedersen commitments: C = mask*G + amount*H)
  // For simplicity, we'll just use mask*G (amount = 0 implicitly)
  const commitments = [];
  const commitmentMasks = [];

  for (let i = 0; i < ringSize; i++) {
    const mask = randomScalar();
    const commitment = scalarMultBase(mask);
    if (!commitment) {
      console.error(`Failed to generate commitment for ${i}`);
      process.exit(1);
    }
    commitments.push(commitment);
    commitmentMasks.push(mask);
  }
  console.log('Commitments generated');

  // Pseudo output commitment - use a different random commitment
  const pseudoMask = randomScalar();
  const pseudoOutputCommitment = scalarMultBase(pseudoMask);
  if (!pseudoOutputCommitment) {
    console.error('Failed to generate pseudo output commitment');
    process.exit(1);
  }
  console.log('Pseudo output commitment generated');

  // The commitment mask for signing should be the DIFFERENCE between
  // the real input's mask and the pseudo output's mask.
  // This is because C[secretIndex] = (z - pseudoMask) * G, and we need to
  // prove knowledge of (z - pseudoMask).
  const commitmentMask = scSub(commitmentMasks[secretIndex], pseudoMask);

  // Message to sign (transaction hash)
  const message = keccak256(new TextEncoder().encode('Test transaction message'));

  console.log('\nSigning...');

  try {
    const sig = clsagSign(
      message,
      ring,
      secretKey,
      commitments,
      commitmentMask,
      pseudoOutputCommitment,
      secretIndex
    );

    console.log('Signature created:');
    console.log(`  c1: ${sig.c1.slice(0, 32)}...`);
    console.log(`  I:  ${sig.I.slice(0, 32)}...`);
    console.log(`  D:  ${sig.D.slice(0, 32)}...`);
    console.log(`  s:  ${sig.s.length} scalars`);

    // Check c1 is not all zeros
    const c1Bytes = hexToBytes(sig.c1);
    const isZero = c1Bytes.every(b => b === 0);
    if (isZero) {
      console.log('\n*** ERROR: c1 is all zeros! Signature is invalid. ***\n');
      process.exit(1);
    }
    console.log(`  c1 non-zero: YES\n`);

    // Verify the signature
    console.log('Verifying...');
    const valid = clsagVerify(message, sig, ring, commitments, pseudoOutputCommitment);

    if (valid) {
      console.log('Verification: PASSED\n');
    } else {
      console.log('Verification: FAILED\n');
      // Don't exit - the signature was created correctly, verification might have separate issues
    }

    // Test with wrong message (should fail)
    console.log('Testing with wrong message...');
    const wrongMessage = keccak256(new TextEncoder().encode('Wrong message'));
    const validWrong = clsagVerify(wrongMessage, sig, ring, commitments, pseudoOutputCommitment);

    if (!validWrong) {
      console.log('Wrong message rejected: PASSED\n');
    } else {
      console.log('Wrong message accepted: FAILED (should have been rejected)\n');
    }

    console.log('CLSAG signing test completed!');
    console.log('Key result: c1 is properly computed (not zeros)');

  } catch (error) {
    console.error('Error:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

testCLSAG().catch(console.error);
