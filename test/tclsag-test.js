/**
 * TCLSAG (Twin CLSAG) Signing and Verification Tests
 *
 * Tests the TCLSAG signing and verification functions used in RCTTypeSalviumOne transactions.
 */

import { tclsagSign, tclsagVerify, clsagSign, clsagVerify } from '../src/transaction.js';
import { scalarMultBase, scalarMultPoint, pointAddCompressed, getGeneratorT } from '../src/ed25519.js';
import { scRandom, scAdd, scMul, commit, bytesToBigInt } from '../src/transaction/serialization.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

const T = getGeneratorT();

/** Compute TCLSAG public key: P = x*G + y*T */
function tclsagPublicKey(x, y) {
  const xG = scalarMultBase(x);
  const yT = scalarMultPoint(y, T);
  return pointAddCompressed(xG, yT);
}

console.log('=== TCLSAG Signing and Verification Tests ===\n');

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    const result = fn();
    if (result) {
      console.log(`  ✓ ${name}`);
      passed++;
    } else {
      console.log(`  ✗ ${name} - returned false`);
      failed++;
    }
  } catch (e) {
    console.log(`  ✗ ${name} - ${e.message}`);
    failed++;
  }
}

// =============================================================================
// Test 1: Function signatures exist
// =============================================================================
console.log('1. Function Signatures');
test('tclsagSign is a function', () => typeof tclsagSign === 'function');
test('tclsagVerify is a function', () => typeof tclsagVerify === 'function');
test('Generator T accessible', () => {
  const T = getGeneratorT();
  return T.length === 32;
});
console.log();

// =============================================================================
// Test 2: TCLSAG Sign -> Verify Round Trip (Ring Size 1)
// =============================================================================
console.log('2. TCLSAG Sign/Verify Round Trip (Ring Size 1)');
{
  // Generate keys — TCLSAG public key is P = x*G + y*T
  const secretKeyX = scRandom(); // Spend key component
  const secretKeyY = scRandom(); // Auxiliary component
  const publicKey = tclsagPublicKey(secretKeyX, secretKeyY);

  // Generate commitment (amount * G + mask * T for TCLSAG style, but we use standard for test)
  const amount = 1000000n;
  const mask = scRandom();
  const commitment = commit(amount, mask);

  // Pseudo output commitment (for input balancing)
  const pseudoMask = scRandom();
  const pseudoOut = commit(amount, pseudoMask);

  // Commitment mask difference: z = mask - pseudoMask
  const z = hexToBytes(bytesToHex(mask)); // Copy
  const pseudoMaskBig = bytesToBigInt(pseudoMask);
  const maskBig = bytesToBigInt(mask);
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const zBig = ((maskBig - pseudoMaskBig) % L + L) % L;
  const commitmentMask = new Uint8Array(32);
  let temp = zBig;
  for (let i = 0; i < 32; i++) {
    commitmentMask[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }

  // Message
  const message = scRandom();

  // Ring of size 1
  const ring = [publicKey];
  const commitments = [commitment];
  const secretIndex = 0;

  // Sign
  const sig = tclsagSign(
    message,
    ring,
    secretKeyX,
    secretKeyY,
    commitments,
    commitmentMask,
    pseudoOut,
    secretIndex
  );

  test('Signature has sx array', () => Array.isArray(sig.sx) && sig.sx.length === 1);
  test('Signature has sy array', () => Array.isArray(sig.sy) && sig.sy.length === 1);
  test('Signature has c1', () => typeof sig.c1 === 'string' && sig.c1.length === 64);
  test('Signature has I (key image)', () => typeof sig.I === 'string' && sig.I.length === 64);
  test('Signature has D (commitment key image)', () => typeof sig.D === 'string' && sig.D.length === 64);

  // Verify
  const valid = tclsagVerify(message, sig, ring, commitments, pseudoOut);
  test('Signature verifies correctly', () => valid === true);
}
console.log();

// =============================================================================
// Test 3: TCLSAG Sign -> Verify Round Trip (Ring Size 3)
// =============================================================================
console.log('3. TCLSAG Sign/Verify Round Trip (Ring Size 3)');
{
  // Generate real keys — P = x*G + y*T
  const secretKeyX = scRandom();
  const secretKeyY = scRandom();
  const publicKey = tclsagPublicKey(secretKeyX, secretKeyY);

  // Generate decoy keys (also TCLSAG-style with T component)
  const decoy1 = tclsagPublicKey(scRandom(), scRandom());
  const decoy2 = tclsagPublicKey(scRandom(), scRandom());

  // Generate commitments
  const amount = 5000000n;
  const mask = scRandom();
  const commitment = commit(amount, mask);

  const decoyCommitment1 = commit(amount, scRandom());
  const decoyCommitment2 = commit(amount, scRandom());

  // Pseudo output
  const pseudoMask = scRandom();
  const pseudoOut = commit(amount, pseudoMask);

  // Commitment mask
  const maskBig = bytesToBigInt(mask);
  const pseudoMaskBig = bytesToBigInt(pseudoMask);
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const zBig = ((maskBig - pseudoMaskBig) % L + L) % L;
  const commitmentMask = new Uint8Array(32);
  let temp = zBig;
  for (let i = 0; i < 32; i++) {
    commitmentMask[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }

  const message = scRandom();

  // Ring with real key at index 1
  const ring = [decoy1, publicKey, decoy2];
  const commitments = [decoyCommitment1, commitment, decoyCommitment2];
  const secretIndex = 1;

  // Sign
  const sig = tclsagSign(
    message,
    ring,
    secretKeyX,
    secretKeyY,
    commitments,
    commitmentMask,
    pseudoOut,
    secretIndex
  );

  test('Ring size 3: sx array has 3 elements', () => sig.sx.length === 3);
  test('Ring size 3: sy array has 3 elements', () => sig.sy.length === 3);

  // Verify
  const valid = tclsagVerify(message, sig, ring, commitments, pseudoOut);
  test('Ring size 3: Signature verifies', () => valid === true);

  // Verify with wrong message fails
  const wrongMessage = scRandom();
  const invalidMsg = tclsagVerify(wrongMessage, sig, ring, commitments, pseudoOut);
  test('Ring size 3: Wrong message fails verification', () => invalidMsg === false);

  // Verify with tampered signature fails
  const tamperedSig = { ...sig, sx: [...sig.sx] };
  tamperedSig.sx[0] = bytesToHex(scRandom());
  const invalidTamper = tclsagVerify(message, tamperedSig, ring, commitments, pseudoOut);
  test('Ring size 3: Tampered signature fails verification', () => invalidTamper === false);
}
console.log();

// =============================================================================
// Test 4: TCLSAG with different secret indices
// =============================================================================
console.log('4. TCLSAG with Different Secret Indices');
{
  const ringSize = 4;
  const amount = 1000000n;

  for (let secretIndex = 0; secretIndex < ringSize; secretIndex++) {
    const secretKeyX = scRandom();
    const secretKeyY = scRandom();
    const publicKey = tclsagPublicKey(secretKeyX, secretKeyY);

    const mask = scRandom();
    const commitment = commit(amount, mask);

    // Build ring with our key at secretIndex
    const ring = [];
    const commitmentList = [];
    for (let i = 0; i < ringSize; i++) {
      if (i === secretIndex) {
        ring.push(publicKey);
        commitmentList.push(commitment);
      } else {
        ring.push(tclsagPublicKey(scRandom(), scRandom()));
        commitmentList.push(commit(amount, scRandom()));
      }
    }

    const pseudoMask = scRandom();
    const pseudoOut = commit(amount, pseudoMask);

    // Commitment mask
    const maskBig = bytesToBigInt(mask);
    const pseudoMaskBig = bytesToBigInt(pseudoMask);
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const zBig = ((maskBig - pseudoMaskBig) % L + L) % L;
    const commitmentMask = new Uint8Array(32);
    let temp = zBig;
    for (let j = 0; j < 32; j++) {
      commitmentMask[j] = Number(temp & 0xffn);
      temp >>= 8n;
    }

    const message = scRandom();

    const sig = tclsagSign(
      message, ring, secretKeyX, secretKeyY, commitmentList,
      commitmentMask, pseudoOut, secretIndex
    );

    const valid = tclsagVerify(message, sig, ring, commitmentList, pseudoOut);
    test(`Secret index ${secretIndex}: Verifies`, () => valid === true);
  }
}
console.log();

// =============================================================================
// Test 5: Key Image Consistency
// =============================================================================
console.log('5. Key Image Consistency');
{
  const secretKeyX = scRandom();
  const secretKeyY = scRandom();
  const publicKey = tclsagPublicKey(secretKeyX, secretKeyY);

  const amount = 1000000n;
  const mask = scRandom();
  const commitment = commit(amount, mask);

  const pseudoMask = scRandom();
  const pseudoOut = commit(amount, pseudoMask);

  const maskBig = bytesToBigInt(mask);
  const pseudoMaskBig = bytesToBigInt(pseudoMask);
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const zBig = ((maskBig - pseudoMaskBig) % L + L) % L;
  const commitmentMask = new Uint8Array(32);
  let temp = zBig;
  for (let i = 0; i < 32; i++) {
    commitmentMask[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }

  // Sign twice with same keys
  const msg1 = scRandom();
  const msg2 = scRandom();

  const sig1 = tclsagSign(msg1, [publicKey], secretKeyX, secretKeyY, [commitment], commitmentMask, pseudoOut, 0);
  const sig2 = tclsagSign(msg2, [publicKey], secretKeyX, secretKeyY, [commitment], commitmentMask, pseudoOut, 0);

  test('Key image I is same for same secret key', () => sig1.I === sig2.I);
  test('Commitment key image D is same for same mask', () => sig1.D === sig2.D);
  test('c1 differs for different messages', () => sig1.c1 !== sig2.c1);
}
console.log();

// =============================================================================
// Test 6: Compare CLSAG vs TCLSAG structure
// =============================================================================
console.log('6. CLSAG vs TCLSAG Structure Comparison');
{
  const secretKey = scRandom();
  const secretKeyY = scRandom(); // Only used by TCLSAG
  // CLSAG public key: P = x*G
  const clsagPubKey = scalarMultBase(secretKey);
  // TCLSAG public key: P = x*G + y*T
  const tclsagPubKey = tclsagPublicKey(secretKey, secretKeyY);

  const amount = 1000000n;
  const mask = scRandom();
  const commitment = commit(amount, mask);

  const pseudoMask = scRandom();
  const pseudoOut = commit(amount, pseudoMask);

  const maskBig = bytesToBigInt(mask);
  const pseudoMaskBig = bytesToBigInt(pseudoMask);
  const L = 2n ** 252n + 27742317777372353535851937790883648493n;
  const zBig = ((maskBig - pseudoMaskBig) % L + L) % L;
  const commitmentMask = new Uint8Array(32);
  let temp = zBig;
  for (let i = 0; i < 32; i++) {
    commitmentMask[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }

  const message = scRandom();

  const clsagSig = clsagSign(message, [clsagPubKey], secretKey, [commitment], commitmentMask, pseudoOut, 0);
  const tclsagSig = tclsagSign(message, [tclsagPubKey], secretKey, secretKeyY, [commitment], commitmentMask, pseudoOut, 0);

  test('CLSAG has single s array', () => Array.isArray(clsagSig.s));
  test('TCLSAG has sx array', () => Array.isArray(tclsagSig.sx));
  test('TCLSAG has sy array', () => Array.isArray(tclsagSig.sy));
  test('Both have key image I', () => clsagSig.I && tclsagSig.I);
  test('Both have commitment key image D', () => clsagSig.D && tclsagSig.D);

  // Key images use H_p(P) which differs between CLSAG (P=x*G) and TCLSAG (P=x*G+y*T)
  // so they won't match when y != 0. But key image formula I = x*H_p(P) is the same.
  test('Both have non-empty key images', () => clsagSig.I.length === 64 && tclsagSig.I.length === 64);

  // CLSAG should verify with clsagVerify
  test('CLSAG sig verifies with clsagVerify', () => clsagVerify(message, clsagSig, [clsagPubKey], [commitment], pseudoOut));

  // TCLSAG should verify with tclsagVerify
  test('TCLSAG sig verifies with tclsagVerify', () => tclsagVerify(message, tclsagSig, [tclsagPubKey], [commitment], pseudoOut));
}
console.log();

// =============================================================================
// Summary
// =============================================================================
console.log('=== TCLSAG Test Summary ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);
console.log();
if (failed === 0) {
  console.log('✓ All TCLSAG tests passed!');
} else {
  console.log(`✗ ${failed} test(s) failed`);
  process.exit(1);
}
