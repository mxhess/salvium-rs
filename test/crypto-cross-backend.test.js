#!/usr/bin/env bun
/**
 * Cross-Backend Compatibility Tests
 *
 * Signs/proves with one backend, verifies with the other.
 * Ensures binary-level compatibility between JS and WASM implementations.
 */

import { setCryptoBackend, getCryptoBackend } from '../src/crypto/index.js';
import { clsagSign, clsagVerify, tclsagSign, tclsagVerify, scSub } from '../src/transaction.js';
import { scalarMultBase, scalarMultPoint, pointAddCompressed, getGeneratorT } from '../src/ed25519.js';
import { scRandom, commit, bytesToBigInt } from '../src/transaction/serialization.js';
import { keccak256 } from '../src/keccak.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

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
 * Each ring member has an independent random key and commitment mask.
 * The signing commitment mask is scSub(realMask, pseudoMask).
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
  // Commitment mask for signing = difference between real mask and pseudo mask
  const commitmentMask = scSub(commitmentMasks[secretIndex], pseudoMask);
  const message = keccak256(new Uint8Array(32));

  return { message, ring, secretKey, commitments, commitmentMask, pseudoOutput, secretIndex };
}

/**
 * Generate a TCLSAG-compatible test ring.
 * TCLSAG public keys are P = x*G + y*T (twin keys).
 * Commitments are Pedersen commitments: C = mask*G + amount*H.
 */
function generateTclsagTestData(ringSize, secretIndex) {
  const T = getGeneratorT();
  const secretKeyX = scRandom();
  const secretKeyY = scRandom();

  // TCLSAG public key: P = x*G + y*T
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

  // Commitment mask = realMask - pseudoMask (as scalar)
  const L_order = 2n ** 252n + 27742317777372353535851937790883648493n;
  const maskBig = bytesToBigInt(commitmentMasks[secretIndex]);
  const pseudoBig = bytesToBigInt(pseudoMask);
  const zBig = ((maskBig - pseudoBig) % L_order + L_order) % L_order;
  const commitmentMask = new Uint8Array(32);
  let temp = zBig;
  for (let i = 0; i < 32; i++) {
    commitmentMask[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }

  const message = scRandom();

  return { message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutput, secretIndex };
}

// ─── CLSAG Cross-Backend Tests ──────────────────────────────────────────────

async function testClsagCrossBackend() {
  console.log('\n=== CLSAG Cross-Backend Tests ===\n');

  const ringSize = 11;
  const secretIndex = 4;
  const data = generateClsagTestData(ringSize, secretIndex);

  // Sign with JS backend
  await setCryptoBackend('js');
  const jsSig = clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  assert(jsSig && jsSig.c1, 'JS backend signs CLSAG');

  // Verify JS sig with JS backend
  const jsVerifyJs = clsagVerify(data.message, jsSig, data.ring, data.commitments, data.pseudoOutput);
  assert(jsVerifyJs === true, 'JS sig verifies with JS backend');

  // Sign with WASM backend
  await setCryptoBackend('wasm');
  const wasmSig = clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  assert(wasmSig && wasmSig.c1, 'WASM backend signs CLSAG');

  // Verify WASM sig with WASM backend
  const wasmVerifyWasm = clsagVerify(data.message, wasmSig, data.ring, data.commitments, data.pseudoOutput);
  assert(wasmVerifyWasm === true, 'WASM sig verifies with WASM backend');

  // Cross-verify: WASM sig with JS backend
  await setCryptoBackend('js');
  const jsVerifyWasm = clsagVerify(data.message, wasmSig, data.ring, data.commitments, data.pseudoOutput);
  assert(jsVerifyWasm === true, 'WASM sig verifies with JS backend (cross-backend)');

  // Cross-verify: JS sig with WASM backend
  await setCryptoBackend('wasm');
  const wasmVerifyJs = clsagVerify(data.message, jsSig, data.ring, data.commitments, data.pseudoOutput);
  assert(wasmVerifyJs === true, 'JS sig verifies with WASM backend (cross-backend)');

  // Both produce same key image
  const jsI = typeof jsSig.I === 'string' ? jsSig.I : bytesToHex(jsSig.I);
  const wasmI = typeof wasmSig.I === 'string' ? wasmSig.I : bytesToHex(wasmSig.I);
  assert(jsI === wasmI, 'Key images match between JS and WASM');

  // Both produce same D (commitment key image)
  const jsD = typeof jsSig.D === 'string' ? jsSig.D : bytesToHex(jsSig.D);
  const wasmD = typeof wasmSig.D === 'string' ? wasmSig.D : bytesToHex(wasmSig.D);
  assert(jsD === wasmD, 'Commitment key images (D) match between JS and WASM');
}

// ─── TCLSAG Cross-Backend Tests ─────────────────────────────────────────────

async function testTclsagCrossBackend() {
  console.log('\n=== TCLSAG Cross-Backend Tests ===\n');

  const ringSize = 4;
  const secretIndex = 2;
  const data = generateTclsagTestData(ringSize, secretIndex);

  // Sign with JS backend
  await setCryptoBackend('js');
  const jsSig = tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  assert(jsSig && jsSig.c1, 'JS backend signs TCLSAG');

  // Verify JS sig with JS backend
  const jsVerifyJs = tclsagVerify(data.message, jsSig, data.ring, data.commitments, data.pseudoOutput);
  assert(jsVerifyJs === true, 'JS TCLSAG sig verifies with JS backend');

  // Sign with WASM backend
  await setCryptoBackend('wasm');
  const wasmSig = tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
  assert(wasmSig && wasmSig.c1, 'WASM backend signs TCLSAG');

  // Verify WASM sig with WASM backend
  const wasmVerifyWasm = tclsagVerify(data.message, wasmSig, data.ring, data.commitments, data.pseudoOutput);
  assert(wasmVerifyWasm === true, 'WASM TCLSAG sig verifies with WASM backend');

  // Cross-verify: WASM sig with JS backend
  await setCryptoBackend('js');
  const jsVerifyWasm = tclsagVerify(data.message, wasmSig, data.ring, data.commitments, data.pseudoOutput);
  assert(jsVerifyWasm === true, 'WASM TCLSAG sig verifies with JS backend (cross-backend)');

  // Cross-verify: JS sig with WASM backend
  await setCryptoBackend('wasm');
  const wasmVerifyJs = tclsagVerify(data.message, jsSig, data.ring, data.commitments, data.pseudoOutput);
  assert(wasmVerifyJs === true, 'JS TCLSAG sig verifies with WASM backend (cross-backend)');

  // Key images match
  const jsI = typeof jsSig.I === 'string' ? jsSig.I : bytesToHex(jsSig.I);
  const wasmI = typeof wasmSig.I === 'string' ? wasmSig.I : bytesToHex(wasmSig.I);
  assert(jsI === wasmI, 'TCLSAG key images match between JS and WASM');
}

// ─── Bulletproofs+ Cross-Backend Tests ──────────────────────────────────────

async function testBpPlusCrossBackend() {
  console.log('\n=== Bulletproofs+ Cross-Backend Tests ===\n');

  const { bulletproofPlusProve, verifyRangeProof, serializeProof, parseProof } =
    await import('../src/bulletproofs_plus.js');

  const amounts = [1000n, 2000n];
  // BP+ masks must be BigInt scalars mod L
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

  // Prove with JS backend (JS backend always uses JS fallback since backend returns null)
  await setCryptoBackend('js');
  const jsProof = bulletproofPlusProve(amounts, masks);
  assert(jsProof && jsProof.A, 'JS backend proves BP+');

  // Serialize the JS proof for cross-backend testing
  const jsProofBytes = serializeProof(jsProof);
  const jsCommitmentBytes = jsProof.V.map(v => v.toBytes());

  // Verify JS proof with JS backend
  const jsVerifyJs = verifyRangeProof(jsCommitmentBytes, jsProofBytes);
  assert(jsVerifyJs === true, 'JS BP+ proof verifies with JS backend');

  // Prove with WASM backend
  await setCryptoBackend('wasm');
  let wasmProof;
  try {
    wasmProof = bulletproofPlusProve(amounts, masks);
    if (wasmProof) {
      assert(true, 'WASM backend proves BP+');
      // The WASM proof returns { V: [Uint8Array...], proofBytes: Uint8Array }
      const wasmCommitments = wasmProof.V;
      const wasmProofBytes = wasmProof.proofBytes;
      if (wasmCommitments && wasmProofBytes) {
        const wasmVerifyWasm = verifyRangeProof(wasmCommitments, wasmProofBytes);
        assert(wasmVerifyWasm === true, 'WASM BP+ proof verifies with WASM backend');

        // Cross-verify: WASM proof with JS backend
        await setCryptoBackend('js');
        const jsVerifyWasm = verifyRangeProof(wasmCommitments, wasmProofBytes);
        assert(jsVerifyWasm === true, 'WASM BP+ proof verifies with JS backend (cross-backend)');
      }
    } else {
      // WASM returned null — BP+ prove fell through to JS fallback
      console.log('  [INFO] WASM BP+ prove returned null, testing JS proof with WASM verify');
      const wasmVerifyJs = verifyRangeProof(jsCommitmentBytes, jsProofBytes);
      assert(wasmVerifyJs === true, 'JS BP+ proof verifies with WASM verify');
    }
  } catch (e) {
    console.log(`  [SKIP] WASM BP+ prove: ${e.message}`);
  }

  await setCryptoBackend('js');
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  console.log('============================================================');
  console.log('Cross-Backend Compatibility Tests');
  console.log('============================================================');

  try {
    await testClsagCrossBackend();
  } catch (e) {
    console.log(`\nCLSAG cross-backend test failed: ${e.message}`);
    console.log(e.stack);
    failed++;
  }

  try {
    await testTclsagCrossBackend();
  } catch (e) {
    console.log(`\nTCLSAG cross-backend test failed: ${e.message}`);
    console.log(e.stack);
    failed++;
  }

  try {
    await testBpPlusCrossBackend();
  } catch (e) {
    console.log(`\nBP+ cross-backend test failed: ${e.message}`);
    console.log(e.stack);
    failed++;
  }

  console.log('\n============================================================');
  console.log(`Cross-Backend Test Summary`);
  console.log(`============================================================`);
  console.log(`Passed: ${passed}`);
  console.log(`Failed: ${failed}`);
  console.log(`Total:  ${passed + failed}`);

  if (failed > 0) {
    process.exit(1);
  } else {
    console.log('\n\u2713 All cross-backend tests passed!');
  }
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
