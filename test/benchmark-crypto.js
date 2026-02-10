#!/usr/bin/env bun
/**
 * Crypto Benchmark: JS vs WASM Backend
 *
 * Measures performance of CLSAG, TCLSAG, and Bulletproofs+
 * operations across both backends to quantify speedup.
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { clsagSign, clsagVerify, tclsagSign, tclsagVerify, scSub } from '../src/transaction.js';
import { scalarMultBase, scalarMultPoint, pointAddCompressed, getGeneratorT } from '../src/ed25519.js';
import { scRandom, commit, bytesToBigInt } from '../src/transaction/serialization.js';
import { keccak256 } from '../src/keccak.js';
import { bulletproofPlusProve, serializeProof, verifyRangeProof } from '../src/bulletproofs_plus.js';

const L_order = 2n ** 252n + 27742317777372353535851937790883648493n;

function generateClsagTestData(ringSize, secretIndex) {
  const ringSecrets = [];
  const ring = [];
  const commitmentMasks = [];
  const commitments = [];

  for (let i = 0; i < ringSize; i++) {
    const sk = scRandom();
    ring.push(scalarMultBase(sk));
    ringSecrets.push(sk);
    const mask = scRandom();
    commitments.push(scalarMultBase(mask));
    commitmentMasks.push(mask);
  }

  const secretKey = ringSecrets[secretIndex];
  const pseudoMask = scRandom();
  const pseudoOutput = scalarMultBase(pseudoMask);
  const commitmentMask = scSub(commitmentMasks[secretIndex], pseudoMask);
  const message = keccak256(new Uint8Array(32));

  return { message, ring, secretKey, commitments, commitmentMask, pseudoOutput, secretIndex };
}

function generateTclsagTestData(ringSize, secretIndex) {
  const T = getGeneratorT();
  const secretKeyX = scRandom();
  const secretKeyY = scRandom();

  function tclsagPubKey(x, y) {
    return pointAddCompressed(scalarMultBase(x), scalarMultPoint(y, T));
  }

  const ring = [];
  const commitmentMasks = [];
  const commitments = [];
  const amount = 1000000n;

  for (let i = 0; i < ringSize; i++) {
    ring.push(i === secretIndex ? tclsagPubKey(secretKeyX, secretKeyY) : tclsagPubKey(scRandom(), scRandom()));
    const mask = scRandom();
    commitments.push(commit(amount, mask));
    commitmentMasks.push(mask);
  }

  const pseudoMask = scRandom();
  const pseudoOutput = commit(amount, pseudoMask);
  const maskBig = bytesToBigInt(commitmentMasks[secretIndex]);
  const pseudoBig = bytesToBigInt(pseudoMask);
  const zBig = ((maskBig - pseudoBig) % L_order + L_order) % L_order;
  const commitmentMask = new Uint8Array(32);
  let temp = zBig;
  for (let i = 0; i < 32; i++) { commitmentMask[i] = Number(temp & 0xffn); temp >>= 8n; }

  const message = scRandom();

  return { message, ring, secretKeyX, secretKeyY, commitments, commitmentMask, pseudoOutput, secretIndex };
}

async function bench(name, fn, iterations = 1) {
  // Warmup
  await fn();
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    await fn();
  }
  const elapsed = performance.now() - start;
  const avg = elapsed / iterations;
  return { name, avg, iterations, total: elapsed };
}

async function main() {
  console.log('============================================================');
  console.log('Crypto Performance Benchmark: JS vs WASM');
  console.log('============================================================\n');

  const results = [];

  // ─── CLSAG (ring size 16) ────────────────────────────────────────────────
  console.log('Benchmarking CLSAG (ring=16)...');
  {
    const ringSize = 16;
    const data = generateClsagTestData(ringSize, 7);

    // JS
    await setCryptoBackend('js');
    const jsSign = await bench(`CLSAG sign (ring=${ringSize}) [JS]`, () => {
      clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, data.secretIndex);
    }, 3);
    results.push(jsSign);

    const jsSig = clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, data.secretIndex);
    const jsVerify = await bench(`CLSAG verify (ring=${ringSize}) [JS]`, () => {
      clsagVerify(data.message, jsSig, data.ring, data.commitments, data.pseudoOutput);
    }, 3);
    results.push(jsVerify);

    // WASM
    await setCryptoBackend('wasm');
    const wasmSign = await bench(`CLSAG sign (ring=${ringSize}) [WASM]`, () => {
      clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, data.secretIndex);
    }, 10);
    results.push(wasmSign);

    const wasmSig = clsagSign(data.message, data.ring, data.secretKey, data.commitments, data.commitmentMask, data.pseudoOutput, data.secretIndex);
    const wasmVerify = await bench(`CLSAG verify (ring=${ringSize}) [WASM]`, () => {
      clsagVerify(data.message, wasmSig, data.ring, data.commitments, data.pseudoOutput);
    }, 10);
    results.push(wasmVerify);
  }

  // ─── TCLSAG (ring size 11) ──────────────────────────────────────────────
  console.log('Benchmarking TCLSAG (ring=11)...');
  {
    const ringSize = 11;
    const secretIndex = 5;
    const data = generateTclsagTestData(ringSize, secretIndex);

    // JS
    await setCryptoBackend('js');
    const jsSign = await bench(`TCLSAG sign (ring=${ringSize}) [JS]`, () => {
      tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
    }, 3);
    results.push(jsSign);

    const jsSig = tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
    const jsVerify = await bench(`TCLSAG verify (ring=${ringSize}) [JS]`, () => {
      tclsagVerify(data.message, jsSig, data.ring, data.commitments, data.pseudoOutput);
    }, 3);
    results.push(jsVerify);

    // WASM
    await setCryptoBackend('wasm');
    const wasmSign = await bench(`TCLSAG sign (ring=${ringSize}) [WASM]`, () => {
      tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
    }, 10);
    results.push(wasmSign);

    const wasmSig = tclsagSign(data.message, data.ring, data.secretKeyX, data.secretKeyY, data.commitments, data.commitmentMask, data.pseudoOutput, secretIndex);
    const wasmVerify = await bench(`TCLSAG verify (ring=${ringSize}) [WASM]`, () => {
      tclsagVerify(data.message, wasmSig, data.ring, data.commitments, data.pseudoOutput);
    }, 10);
    results.push(wasmVerify);
  }

  // ─── Bulletproofs+ (2 outputs) ───────────────────────────────────────────
  console.log('Benchmarking Bulletproofs+ (2 outputs)...');
  {
    const amounts = [1000n, 2000n];
    function randomBigIntScalar() {
      const bytes = new Uint8Array(64);
      crypto.getRandomValues(bytes);
      let result = 0n;
      for (let i = 0; i < 64; i++) result |= BigInt(bytes[i]) << BigInt(i * 8);
      return result % L_order;
    }
    const masks = [randomBigIntScalar(), randomBigIntScalar()];

    // JS
    await setCryptoBackend('js');
    const jsProve = await bench(`BP+ prove (2 outputs) [JS]`, () => {
      bulletproofPlusProve(amounts, masks);
    }, 1);
    results.push(jsProve);

    const jsProof = bulletproofPlusProve(amounts, masks);
    const jsProofBytes = serializeProof(jsProof);
    const jsCommitments = jsProof.V.map(v => v.toBytes());
    const jsVerify = await bench(`BP+ verify (2 outputs) [JS]`, () => {
      verifyRangeProof(jsCommitments, jsProofBytes);
    }, 1);
    results.push(jsVerify);

    // WASM
    await setCryptoBackend('wasm');
    try {
      const wasmProve = await bench(`BP+ prove (2 outputs) [WASM]`, () => {
        bulletproofPlusProve(amounts, masks);
      }, 5);
      results.push(wasmProve);

      const wasmProof = bulletproofPlusProve(amounts, masks);
      if (wasmProof && wasmProof.V && wasmProof.proofBytes) {
        const wasmVerify = await bench(`BP+ verify (2 outputs) [WASM]`, () => {
          verifyRangeProof(wasmProof.V, wasmProof.proofBytes);
        }, 5);
        results.push(wasmVerify);
      }
    } catch (e) {
      console.log(`  [SKIP] WASM BP+ not yet working: ${e.message}`);
    }
  }

  // ─── Results Table ───────────────────────────────────────────────────────
  console.log('\n============================================================');
  console.log('Results');
  console.log('============================================================\n');

  console.log('Operation'.padEnd(42) + 'Avg (ms)'.padStart(12) + 'Iters'.padStart(8));
  console.log('-'.repeat(62));
  for (const r of results) {
    console.log(r.name.padEnd(42) + r.avg.toFixed(2).padStart(12) + String(r.iterations).padStart(8));
  }

  // Compute speedup ratios
  console.log('\n--- Speedup Summary ---\n');
  const pairs = [
    ['CLSAG sign'],
    ['CLSAG verify'],
    ['TCLSAG sign'],
    ['TCLSAG verify'],
    ['BP+ prove'],
    ['BP+ verify'],
  ];
  for (const [op] of pairs) {
    const jsResult = results.find(r => r.name.startsWith(op) && r.name.includes('[JS]'));
    const wasmResult = results.find(r => r.name.startsWith(op) && r.name.includes('[WASM]'));
    if (jsResult && wasmResult) {
      const speedup = jsResult.avg / wasmResult.avg;
      console.log(`${op}: ${speedup.toFixed(1)}x speedup (${jsResult.avg.toFixed(1)}ms -> ${wasmResult.avg.toFixed(1)}ms)`);
    }
  }

  await setCryptoBackend('js');
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
