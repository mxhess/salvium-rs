#!/usr/bin/env bun
/**
 * Tests for expandTransaction and verifyRctSignatures
 *
 * Covers:
 * - expandTransaction: key image injection into sig structs (C++ expand_transaction_2)
 * - verifyRctSignatures: CLSAG and TCLSAG signature verification pipeline
 * - Packing helpers: flat byte array serialization for WASM boundary
 * - Tamper detection: wrong message, wrong key image, tampered sig fields
 * - Multi-input transactions
 * - Integration with validateTransactionFull step 8
 */

import { describe, test, expect } from 'bun:test';
import { initCrypto } from '../src/crypto/index.js';
import {
  expandTransaction,
  clsagSign, clsagVerify,
  tclsagSign, tclsagVerify,
  getPreMlsagHash,
  scRandom, scSub,
  commit, zeroCommit, genCommitmentMask,
  getTxPrefixHash, serializeRctBase,
  RCT_TYPE,
  offsetsToIndices
} from '../src/transaction.js';
import { verifyRctSignatures, validateTransactionFull } from '../src/validation.js';
import {
  scalarMultBase, scalarMultPoint, pointAddCompressed, getGeneratorT,
} from '../src/crypto/index.js';
import { generateKeyImage } from '../src/keyimage.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

await initCrypto();

// =============================================================================
// Helpers
// =============================================================================

const T = getGeneratorT();

/** Build a TCLSAG-style public key: P = x*G + y*T */
function tclsagPublicKey(x, y) {
  return pointAddCompressed(scalarMultBase(x), scalarMultPoint(y, T));
}

/** Create a serializable prefix for a given set of inputs/outputs */
function makePrefix(inputs, outputs) {
  return {
    version: 2,
    unlockTime: 0n,
    txType: 2, // TRANSFER
    vin: inputs.map(inp => ({
      amount: 0n,
      assetType: 'SAL',
      keyOffsets: [100n, 5n],
      keyImage: inp.keyImage,
    })),
    vout: outputs.map(() => ({
      amount: 0n,
      target: scalarMultBase(scRandom()),
      assetType: 'SAL',
      viewTag: 0x42,
    })),
    extra: { txPubKey: scalarMultBase(scRandom()) },
    amount_burnt: 0n,
    return_address: { spend: new Uint8Array(32), view: new Uint8Array(32) },
    source_asset_type: 'SAL',
    destination_asset_type: 'SAL',
  };
}

/** Create rct base (without sigs) for message hash computation */
function makeRctBase(type, numOutputs, pseudoOuts) {
  return {
    type,
    fee: 10000n,
    ecdhInfo: Array.from({ length: numOutputs }, () => new Uint8Array(8)),
    outPk: Array.from({ length: numOutputs }, () => commit(1000000n, scRandom())),
    p_r: new Uint8Array(32),
    pseudoOuts: pseudoOuts,
    bulletproofPlus: [{
      A: new Uint8Array(32),
      A1: new Uint8Array(32),
      B: new Uint8Array(32),
      r1: new Uint8Array(32),
      s1: new Uint8Array(32),
      d1: new Uint8Array(32),
      L: [new Uint8Array(32)],
      R: [new Uint8Array(32)],
    }],
  };
}

/** Build a complete signed CLSAG transaction with N inputs */
function buildSignedClsagTx(numInputs, ringSize = 2) {
  const inputs = [];
  const mixRingAll = [];
  const allSigs = [];
  const allPseudoOuts = [];

  for (let i = 0; i < numInputs; i++) {
    const sk = scRandom();
    const pk = scalarMultBase(sk);
    const keyImage = generateKeyImage(pk, sk);

    const realMask = scRandom();
    const pseudoMask = scRandom();
    const realCommitment = commit(1000000n, realMask);
    const pseudoOutput = commit(1000000n, pseudoMask);

    // Build ring
    const ring = [];
    const commitments = [];
    const mixRingEntry = [];
    let secretIndex;

    for (let j = 0; j < ringSize; j++) {
      if (j === ringSize - 1) {
        // Real key at last position
        ring.push(pk);
        commitments.push(realCommitment);
        mixRingEntry.push({ dest: pk, mask: realCommitment });
        secretIndex = j;
      } else {
        const decoyPk = scalarMultBase(scRandom());
        const decoyComm = commit(500000n, scRandom());
        ring.push(decoyPk);
        commitments.push(decoyComm);
        mixRingEntry.push({ dest: decoyPk, mask: decoyComm });
      }
    }

    inputs.push({ keyImage, sk, ring, commitments, realMask, pseudoMask, secretIndex });
    mixRingAll.push(mixRingEntry);
    allPseudoOuts.push(pseudoOutput);
  }

  const prefix = makePrefix(inputs, [{}]); // 1 output
  const rct = makeRctBase(RCT_TYPE.CLSAG, 1, allPseudoOuts);

  // Compute message
  const txPrefixHash = getTxPrefixHash(prefix);
  const rctBaseBytes = serializeRctBase(rct);
  const bpProof = rct.bulletproofPlus[0];
  const message = getPreMlsagHash(txPrefixHash, rctBaseBytes, bpProof);

  // Sign each input
  rct.CLSAGs = [];
  for (let i = 0; i < numInputs; i++) {
    const inp = inputs[i];
    const maskDiff = scSub(inp.realMask, inp.pseudoMask);
    const sig = clsagSign(
      message, inp.ring, inp.sk, inp.commitments,
      maskDiff, allPseudoOuts[i], inp.secretIndex
    );
    rct.CLSAGs.push(sig);
  }

  return { tx: { prefix, rct }, mixRing: mixRingAll, message, inputs };
}

/** Build a complete signed TCLSAG transaction with N inputs */
function buildSignedTclsagTx(numInputs, ringSize = 2) {
  const inputs = [];
  const mixRingAll = [];
  const allPseudoOuts = [];

  for (let i = 0; i < numInputs; i++) {
    const skX = scRandom();
    const skY = scRandom();
    const pk = tclsagPublicKey(skX, skY);
    const keyImage = generateKeyImage(pk, skX);

    const realMask = scRandom();
    const pseudoMask = scRandom();
    const realCommitment = commit(1000000n, realMask);
    const pseudoOutput = commit(1000000n, pseudoMask);

    const ring = [];
    const commitments = [];
    const mixRingEntry = [];
    let secretIndex;

    for (let j = 0; j < ringSize; j++) {
      if (j === ringSize - 1) {
        ring.push(pk);
        commitments.push(realCommitment);
        mixRingEntry.push({ dest: pk, mask: realCommitment });
        secretIndex = j;
      } else {
        const decoyPk = tclsagPublicKey(scRandom(), scRandom());
        const decoyComm = commit(500000n, scRandom());
        ring.push(decoyPk);
        commitments.push(decoyComm);
        mixRingEntry.push({ dest: decoyPk, mask: decoyComm });
      }
    }

    inputs.push({ keyImage, skX, skY, ring, commitments, realMask, pseudoMask, secretIndex });
    mixRingAll.push(mixRingEntry);
    allPseudoOuts.push(pseudoOutput);
  }

  const prefix = makePrefix(inputs, [{}]);
  const rct = makeRctBase(RCT_TYPE.SalviumOne, 1, allPseudoOuts);

  const txPrefixHash = getTxPrefixHash(prefix);
  const rctBaseBytes = serializeRctBase(rct);
  const bpProof = rct.bulletproofPlus[0];
  const message = getPreMlsagHash(txPrefixHash, rctBaseBytes, bpProof);

  rct.TCLSAGs = [];
  for (let i = 0; i < numInputs; i++) {
    const inp = inputs[i];
    const maskDiff = scSub(inp.realMask, inp.pseudoMask);
    const sig = tclsagSign(
      message, inp.ring, inp.skX, inp.skY, inp.commitments,
      maskDiff, allPseudoOuts[i], inp.secretIndex
    );
    rct.TCLSAGs.push(sig);
  }

  return { tx: { prefix, rct }, mixRing: mixRingAll, message, inputs };
}

// =============================================================================
// expandTransaction tests
// =============================================================================

describe('expandTransaction', () => {
  test('populates I from prefix key images for TCLSAG', () => {
    const ki1 = new Uint8Array(32).fill(0xAA);
    const ki2 = new Uint8Array(32).fill(0xBB);
    const tx = {
      prefix: {
        vin: [{ keyImage: ki1 }, { keyImage: ki2 }],
      },
      rct: {
        TCLSAGs: [
          { sx: [], sy: [], c1: new Uint8Array(32), D: new Uint8Array(32) },
          { sx: [], sy: [], c1: new Uint8Array(32), D: new Uint8Array(32) },
        ],
      },
    };

    const result = expandTransaction(tx);
    expect(result).toBe(tx);
    expect(bytesToHex(result.rct.TCLSAGs[0].I)).toBe(bytesToHex(ki1));
    expect(bytesToHex(result.rct.TCLSAGs[1].I)).toBe(bytesToHex(ki2));
  });

  test('populates I from prefix key images for CLSAG', () => {
    const ki = new Uint8Array(32).fill(0xCC);
    const tx = {
      prefix: { vin: [{ keyImage: ki }] },
      rct: {
        CLSAGs: [{ s: [], c1: new Uint8Array(32), D: new Uint8Array(32) }],
      },
    };
    expandTransaction(tx);
    expect(bytesToHex(tx.rct.CLSAGs[0].I)).toBe(bytesToHex(ki));
  });

  test('handles missing prefix gracefully', () => {
    const tx = { rct: { TCLSAGs: [] } };
    expect(expandTransaction(tx)).toBe(tx);
  });

  test('handles missing rct gracefully', () => {
    const tx = { prefix: { vin: [] } };
    expect(expandTransaction(tx)).toBe(tx);
  });

  test('handles empty vin and sigs', () => {
    const tx = { prefix: { vin: [] }, rct: { TCLSAGs: [], CLSAGs: [] } };
    expect(expandTransaction(tx)).toBe(tx);
  });

  test('does not overwrite existing I if keyImage is falsy', () => {
    const existingI = new Uint8Array(32).fill(0xFF);
    const tx = {
      prefix: { vin: [{ keyImage: null }] },
      rct: {
        CLSAGs: [{ s: [], c1: new Uint8Array(32), D: new Uint8Array(32), I: existingI }],
      },
    };
    expandTransaction(tx);
    expect(bytesToHex(tx.rct.CLSAGs[0].I)).toBe(bytesToHex(existingI));
  });

  test('handles more sigs than inputs (extra sigs ignored)', () => {
    const ki = new Uint8Array(32).fill(0xDD);
    const tx = {
      prefix: { vin: [{ keyImage: ki }] },
      rct: {
        TCLSAGs: [
          { sx: [], sy: [], c1: new Uint8Array(32), D: new Uint8Array(32) },
          { sx: [], sy: [], c1: new Uint8Array(32), D: new Uint8Array(32) },
        ],
      },
    };
    expandTransaction(tx);
    expect(bytesToHex(tx.rct.TCLSAGs[0].I)).toBe(bytesToHex(ki));
    expect(tx.rct.TCLSAGs[1].I).toBeUndefined();
  });

  test('populates I from hex string key images', () => {
    const kiHex = 'aa'.repeat(32);
    const tx = {
      prefix: { vin: [{ keyImage: kiHex }] },
      rct: {
        CLSAGs: [{ s: [], c1: new Uint8Array(32), D: new Uint8Array(32) }],
      },
    };
    expandTransaction(tx);
    expect(tx.rct.CLSAGs[0].I).toBe(kiHex);
  });
});

// =============================================================================
// verifyRctSignatures — CLSAG
// =============================================================================

describe('verifyRctSignatures (CLSAG)', () => {
  test('verifies valid single-input CLSAG signature', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('verifies valid single-input CLSAG with ring size 4', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 4);
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('verifies valid 2-input CLSAG transaction', () => {
    const { tx, mixRing } = buildSignedClsagTx(2, 2);
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('verifies valid 3-input CLSAG transaction', () => {
    const { tx, mixRing } = buildSignedClsagTx(3, 3);
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('rejects tampered c1 (challenge)', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    // Tamper with c1
    const tampered = typeof tx.rct.CLSAGs[0].c1 === 'string'
      ? bytesToHex(scRandom())
      : scRandom();
    tx.rct.CLSAGs[0].c1 = tampered;
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('RCT signature verification failed for input 0');
  });

  test('rejects tampered s response scalar', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 3);
    const sig = tx.rct.CLSAGs[0];
    // Tamper with first s value
    if (typeof sig.s[0] === 'string') {
      sig.s[0] = bytesToHex(scRandom());
    } else {
      sig.s[0] = scRandom();
    }
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects wrong pseudo output', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    // Replace pseudo output with a different commitment
    tx.rct.pseudoOuts[0] = commit(999999n, scRandom());
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects wrong mix ring member', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    // Replace a ring member with a random key
    mixRing[0][0].dest = scalarMultBase(scRandom());
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects wrong ring commitment', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    // Replace a ring commitment
    mixRing[0][0].mask = commit(123456n, scRandom());
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects wrong key image', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    // Replace key image in prefix
    tx.prefix.vin[0].keyImage = generateKeyImage(
      scalarMultBase(scRandom()), scRandom()
    );
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('detects failure on second input in multi-input tx', () => {
    const { tx, mixRing } = buildSignedClsagTx(3, 2);
    // Tamper only with input 1 (second input)
    const sig = tx.rct.CLSAGs[1];
    if (typeof sig.c1 === 'string') {
      sig.c1 = bytesToHex(scRandom());
    } else {
      sig.c1 = scRandom();
    }
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
    expect(result.errors[0]).toContain('input 1');
  });

  test('rejects all-zero signature data', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    tx.rct.CLSAGs[0] = {
      s: [new Uint8Array(32), new Uint8Array(32)],
      c1: new Uint8Array(32),
      D: new Uint8Array(32),
      I: new Uint8Array(32),
    };
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });
});

// =============================================================================
// verifyRctSignatures — TCLSAG
// =============================================================================

describe('verifyRctSignatures (TCLSAG)', () => {
  test('verifies valid single-input TCLSAG signature', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 2);
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('verifies valid single-input TCLSAG with ring size 4', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 4);
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('verifies valid 2-input TCLSAG transaction', () => {
    const { tx, mixRing } = buildSignedTclsagTx(2, 2);
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  });

  test('rejects tampered sx response scalar', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 2);
    const sig = tx.rct.TCLSAGs[0];
    if (typeof sig.sx[0] === 'string') {
      sig.sx[0] = bytesToHex(scRandom());
    } else {
      sig.sx[0] = scRandom();
    }
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects tampered sy response scalar', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 2);
    const sig = tx.rct.TCLSAGs[0];
    if (typeof sig.sy[0] === 'string') {
      sig.sy[0] = bytesToHex(scRandom());
    } else {
      sig.sy[0] = scRandom();
    }
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects tampered c1', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 2);
    const sig = tx.rct.TCLSAGs[0];
    sig.c1 = typeof sig.c1 === 'string' ? bytesToHex(scRandom()) : scRandom();
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects wrong pseudo output', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 2);
    tx.rct.pseudoOuts[0] = commit(999999n, scRandom());
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });

  test('rejects wrong key image in prefix', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 2);
    tx.prefix.vin[0].keyImage = generateKeyImage(
      scalarMultBase(scRandom()), scRandom()
    );
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(false);
  });
});

// =============================================================================
// validateTransactionFull integration (step 8)
// =============================================================================

describe('validateTransactionFull step 8 (RCT sig verification)', () => {
  test('skips RCT verification when mixRing not provided', () => {
    const { tx } = buildSignedClsagTx(1, 2);
    // validateTransactionFull without mixRing should not try sig verification
    const result = validateTransactionFull(tx, { hfVersion: 8, height: 1000 });
    // Should pass or fail on other checks, but NOT on RCT sigs
    const rctSigErrors = result.errors.filter(e => e.includes('RCT signature'));
    expect(rctSigErrors.length).toBe(0);
  });

  test('validates RCT signatures when mixRing is provided', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    const result = validateTransactionFull(tx, {
      hfVersion: 8,
      height: 1000,
      mixRing,
    });
    // Should not have RCT signature errors
    const rctSigErrors = result.errors.filter(e => e.includes('RCT signature'));
    expect(rctSigErrors.length).toBe(0);
  });

  test('reports RCT sig failure when mixRing has tampered data', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    // Tamper with ring member
    mixRing[0][0].dest = scalarMultBase(scRandom());
    const result = validateTransactionFull(tx, {
      hfVersion: 8,
      height: 1000,
      mixRing,
    });
    const rctSigErrors = result.errors.filter(e => e.includes('RCT signature'));
    expect(rctSigErrors.length).toBeGreaterThan(0);
  });
});

// =============================================================================
// expandTransaction + verifyRctSignatures round-trip
// =============================================================================

describe('expandTransaction + verify round-trip', () => {
  test('CLSAG: expand then verify succeeds', () => {
    const { tx, mixRing } = buildSignedClsagTx(1, 2);
    // Simulate what a parser would produce (no I field in sigs)
    const sigWithoutI = { ...tx.rct.CLSAGs[0] };
    delete sigWithoutI.I;
    tx.rct.CLSAGs[0] = sigWithoutI;

    // expandTransaction should inject I
    expandTransaction(tx);
    expect(tx.rct.CLSAGs[0].I).toBeDefined();

    // Verify should still work
    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
  });

  test('TCLSAG: expand then verify succeeds', () => {
    const { tx, mixRing } = buildSignedTclsagTx(1, 2);
    const sigWithoutI = { ...tx.rct.TCLSAGs[0] };
    delete sigWithoutI.I;
    tx.rct.TCLSAGs[0] = sigWithoutI;

    expandTransaction(tx);
    expect(tx.rct.TCLSAGs[0].I).toBeDefined();

    const result = verifyRctSignatures(tx, mixRing);
    expect(result.valid).toBe(true);
  });
});

// =============================================================================
// Message hash consistency
// =============================================================================

describe('getPreMlsagHash consistency', () => {
  test('same inputs produce same hash', () => {
    const pfx = new Uint8Array(32).fill(0x11);
    const base = new Uint8Array(64).fill(0x22);
    const bp = {
      A: new Uint8Array(32), A1: new Uint8Array(32),
      B: new Uint8Array(32), r1: new Uint8Array(32),
      s1: new Uint8Array(32), d1: new Uint8Array(32),
      L: [new Uint8Array(32)], R: [new Uint8Array(32)],
    };
    const h1 = getPreMlsagHash(pfx, base, bp);
    const h2 = getPreMlsagHash(pfx, base, bp);
    expect(bytesToHex(h1)).toBe(bytesToHex(h2));
  });

  test('different prefix hash produces different message', () => {
    const base = new Uint8Array(64).fill(0x22);
    const bp = {
      A: new Uint8Array(32), A1: new Uint8Array(32),
      B: new Uint8Array(32), r1: new Uint8Array(32),
      s1: new Uint8Array(32), d1: new Uint8Array(32),
      L: [new Uint8Array(32)], R: [new Uint8Array(32)],
    };
    const h1 = getPreMlsagHash(new Uint8Array(32).fill(0x11), base, bp);
    const h2 = getPreMlsagHash(new Uint8Array(32).fill(0x33), base, bp);
    expect(bytesToHex(h1)).not.toBe(bytesToHex(h2));
  });

  test('different rctBase produces different message', () => {
    const pfx = new Uint8Array(32).fill(0x11);
    const bp = {
      A: new Uint8Array(32), A1: new Uint8Array(32),
      B: new Uint8Array(32), r1: new Uint8Array(32),
      s1: new Uint8Array(32), d1: new Uint8Array(32),
      L: [new Uint8Array(32)], R: [new Uint8Array(32)],
    };
    const h1 = getPreMlsagHash(pfx, new Uint8Array(64).fill(0x22), bp);
    const h2 = getPreMlsagHash(pfx, new Uint8Array(64).fill(0x44), bp);
    expect(bytesToHex(h1)).not.toBe(bytesToHex(h2));
  });
});
