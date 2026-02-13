#!/usr/bin/env bun
/**
 * Signature Self-Consistency Tests (WASM Backend)
 *
 * Verifies CLSAG, TCLSAG, and Bulletproofs+ sign/prove + verify roundtrips.
 * Previously tested cross-backend (JS vs WASM) compatibility, now WASM-only
 * since JS backend no longer supports scalar/point/signature operations.
 */

import { initCrypto, setCryptoBackend, getCryptoBackend } from '../src/crypto/index.js';
import { clsagSign, clsagVerify, tclsagSign, tclsagVerify, scSub } from '../src/transaction.js';
import {
  scalarMultBase, scalarMultPoint, pointAddCompressed,
  getGeneratorT, randomScalar as providerRandomScalar
} from '../src/crypto/provider.js';
import { scRandom, commit, bytesToBigInt } from '../src/transaction/serialization.js';
import { keccak256 } from '../src/crypto/provider.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

await initCrypto();

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    console.log(`  \u2713 ${msg}`);
    passed++;
  } else {
    console.log(`  \u2717 ${msg}`);
    failed++;
  }
}

function randomScalar() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  bytes[31] &= 0x0f;
  return bytes;
}

/**
 * Generate a CLSAG-compatible test ring.
 */
function generateClsagTestData(ringSize, secretIndex) {
  const ringSecrets = [];
  const ring = [];
  const commitmentMasks = [];
  const commitments = [];

  for (let i = 0; i < ringSize; i++) {
    const sk = randomScalar();
    ring.push(scalarMultBase(sk));
    ringSecrets.push(sk);

    const mask = randomScalar();
    commitments.push(scalarMultBase(mask));
    commitmentMasks.push(mask);
  }

  const secretKey = ringSecrets[secretIndex];
  const pseudoMask = randomScalar();
  const pseudoOutput = scalarMultBase(pseudoMask);
  const commitmentMask = scSub(commitmentMasks[secretIndex], pseudoMask);
  const message = keccak256(new Uint8Array(32));

  return { message, ring, secretKey, commitments, commitmentMask, pseudoOutput, secretIndex };
}

/**
 * Generate a TCLSAG-compatible test ring.
 */
function generateTclsagTestData(ringSize, secretIndex) {
  const T = getGeneratorT();
  const secretKeyX = scRandom();
  const secretKeyY = scRandom();

  function tclsagPublicKey(x, y) {
    return pointAddCompressed(scalarMultBase(x), scalarMultPoint(y, T));
  }

  const ring = [];
  const commitmentMasks = [];
  const commitments = [];
  const amount = 1000000n;

  for (let i = 0; i < ringSize; i++) {
    if (i === secretIndex) {
      ring.push(tclsagPublicKey(secretKeyX, secretKeyY));
    } else {
      ring.push(tclsagPublicKey(scRandom(), scRandom()));
    }
    const mask = scRandom();
    commitments.push(commit(amount, mask));
    commitmentMasks.push(mask);
  }

  const pseudoMask = scRandom();
  const pseudoOutput = commit(amount, pseudoMask);

  const L = BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');
  const maskBig = bytesToBigInt(commitmentMasks[secretIndex]);
  const pseudoBig = bytesToBigInt(pseudoMask);
  const zBig = ((maskBig - pseudoBig) % L + L) % L;
  const commitmentMask = new Uint8Array(32);
  let temp = zBig;
  for (let i = 0; i < 32; i++) {
    commitmentMask[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }

  const message = scRandom();

  return { message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutput, secretIndex };
}

// ─── CLSAG Self-Consistency Tests ───────────────────────────────────────────

async function testClsagSelfConsistency() {
  console.log('\n=== CLSAG Self-Consistency (WASM) ===\n');

  const ringSize = 11;
  const secretIndex = 4;
  const data = generateClsagTestData(ringSize, secretIndex);

  // Sign with WASM
  const sig = clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  assert(sig && sig.c1, 'WASM signs CLSAG');

  // Verify with WASM
  const valid = clsagVerify(data.message, sig, data.ring, data.commitments, data.pseudoOutput);
  assert(valid === true, 'WASM CLSAG sig verifies');

  // Key image is 32 bytes
  const I = sig.I instanceof Uint8Array ? sig.I : hexToBytes(sig.I);
  assert(I.length === 32, 'Key image is 32 bytes');

  // D (commitment key image) is 32 bytes
  const D = sig.D instanceof Uint8Array ? sig.D : hexToBytes(sig.D);
  assert(D.length === 32, 'Commitment key image (D) is 32 bytes');

  // Signing twice produces same key image (deterministic)
  const sig2 = clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  const I2 = sig2.I instanceof Uint8Array ? bytesToHex(sig2.I) : sig2.I;
  const I1 = sig.I instanceof Uint8Array ? bytesToHex(sig.I) : sig.I;
  assert(I1 === I2, 'Key image is deterministic across signings');

  // Wrong message fails verification
  const wrongMessage = keccak256(new Uint8Array([1, 2, 3]));
  const wrongValid = clsagVerify(wrongMessage, sig, data.ring, data.commitments, data.pseudoOutput);
  assert(wrongValid === false, 'Wrong message fails CLSAG verification');
}

// ─── TCLSAG Self-Consistency Tests ──────────────────────────────────────────

async function testTclsagSelfConsistency() {
  console.log('\n=== TCLSAG Self-Consistency (WASM) ===\n');

  const ringSize = 4;
  const secretIndex = 2;
  const data = generateTclsagTestData(ringSize, secretIndex);

  // Sign with WASM
  const sig = tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  assert(sig && sig.c1, 'WASM signs TCLSAG');

  // Verify with WASM
  const valid = tclsagVerify(data.message, sig, data.ring, data.commitments, data.pseudoOutput);
  assert(valid === true, 'WASM TCLSAG sig verifies');

  // Key image is 32 bytes
  const I = sig.I instanceof Uint8Array ? sig.I : hexToBytes(sig.I);
  assert(I.length === 32, 'TCLSAG key image is 32 bytes');

  // Deterministic key image
  const sig2 = tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  const I1 = sig.I instanceof Uint8Array ? bytesToHex(sig.I) : sig.I;
  const I2 = sig2.I instanceof Uint8Array ? bytesToHex(sig2.I) : sig2.I;
  assert(I1 === I2, 'TCLSAG key image is deterministic');

  // Wrong message fails verification
  const wrongValid = tclsagVerify(scRandom(), sig, data.ring, data.commitments, data.pseudoOutput);
  assert(wrongValid === false, 'Wrong message fails TCLSAG verification');
}

// ─── Bulletproofs+ Self-Consistency Tests ───────────────────────────────────

async function testBpPlusSelfConsistency() {
  console.log('\n=== Bulletproofs+ Self-Consistency (WASM) ===\n');

  const { bulletproofPlusProve, verifyRangeProof, serializeProof, parseProof } =
    await import('../src/bulletproofs_plus.js');

  const amounts = [1000n, 2000n];
  const L = BigInt('0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed');
  function randomBigIntScalar() {
    const bytes = new Uint8Array(64);
    crypto.getRandomValues(bytes);
    let result = 0n;
    for (let i = 0; i < 64; i++) {
      result |= BigInt(bytes[i]) << BigInt(i * 8);
    }
    return result % L;
  }
  const masks = [randomBigIntScalar(), randomBigIntScalar()];

  // Prove with WASM
  const proof = bulletproofPlusProve(amounts, masks);
  assert(proof != null, 'WASM proves BP+');

  if (proof) {
    // Handle both return formats (native WASM vs JS fallback)
    let commitmentBytes, proofBytes;
    if (proof.proofBytes) {
      // WASM native format
      commitmentBytes = proof.V;
      proofBytes = proof.proofBytes;
    } else if (proof.A) {
      // JS fallback format
      proofBytes = serializeProof(proof);
      commitmentBytes = proof.V.map(v => v.toBytes());
    }

    if (commitmentBytes && proofBytes) {
      // Verify with WASM
      const valid = verifyRangeProof(commitmentBytes, proofBytes);
      assert(valid === true, 'WASM BP+ proof verifies');

      // Serialize/parse roundtrip
      if (proof.A) {
        const serialized = serializeProof(proof);
        const parsed = parseProof(serialized);
        assert(parsed != null, 'BP+ proof serialize/parse roundtrip');
      }
    }
  }
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log('============================================================');
  console.log('Signature Self-Consistency Tests (WASM Backend)');
  console.log('============================================================');

  try {
    await testClsagSelfConsistency();
  } catch (e) {
    console.log(`\nCLSAG test failed: ${e.message}`);
    console.log(e.stack);
    failed++;
  }

  try {
    await testTclsagSelfConsistency();
  } catch (e) {
    console.log(`\nTCLSAG test failed: ${e.message}`);
    console.log(e.stack);
    failed++;
  }

  try {
    await testBpPlusSelfConsistency();
  } catch (e) {
    console.log(`\nBP+ test failed: ${e.message}`);
    console.log(e.stack);
    failed++;
  }

  console.log('\n============================================================');
  console.log(`Signature Test Summary`);
  console.log(`============================================================`);
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Total:  ${passed + failed}`);

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('\n\u2713 All signature tests passed!');
  }
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
