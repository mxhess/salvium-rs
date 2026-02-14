#!/usr/bin/env bun
/**
 * Testnet Integration: RCT Signature Verification
 *
 * Fetches real transactions from the Salvium testnet daemon, parses them,
 * retrieves ring member data via getOuts, and verifies TCLSAG/CLSAG
 * signatures using verifyRctSignatures.
 *
 * Usage:
 *   bun test/rct-verify-testnet.test.js [--daemon URL]
 *
 * Default daemon: http://node12.whiskymine.io:29081
 *
 * Requires a running testnet daemon with user transactions on-chain.
 */

import { describe, test, expect, beforeAll } from 'bun:test';
import { initCrypto } from '../src/crypto/index.js';
import { createDaemonRPC } from '../src/rpc/index.js';
import { parseTransaction, offsetsToIndices, expandTransaction } from '../src/transaction.js';
import { verifyRctSignatures, validateTransactionFull } from '../src/validation.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { RCT_TYPE, TXIN_TYPE } from '../src/transaction/constants.js';

// ─── Config ────────────────────────────────────────────────────────────────

const DAEMON_URL = process.argv.find((a, i) =>
  i > 0 && (process.argv[i - 1] === '--daemon' || process.argv[i - 1] === '-d')
) || 'http://node12.whiskymine.io:29081';

const TIMEOUT = 30000; // 30s per test

// ─── State ─────────────────────────────────────────────────────────────────

let daemon;
let daemonAvailable = false;
let chainHeight = 0;

// Known testnet TX hashes with user transactions (post-CARROT HF10, type 9 TCLSAG)
// These are discovered dynamically in beforeAll
let testTxHashes = [];

// ─── Setup ─────────────────────────────────────────────────────────────────

beforeAll(async () => {
  await initCrypto();

  daemon = createDaemonRPC({ url: DAEMON_URL, timeout: 15000 });

  try {
    const info = await daemon.getInfo();
    if (info.success || info.result) {
      daemonAvailable = true;
      chainHeight = info.result?.height ?? info.height ?? 0;
      console.log(`  Daemon: ${DAEMON_URL} (height ${chainHeight})`);
    }
  } catch (e) {
    console.log(`  Daemon not available at ${DAEMON_URL}: ${e.message}`);
    console.log('  Skipping testnet tests.');
    return;
  }

  // Scan recent blocks for user transactions
  if (daemonAvailable && chainHeight > 0) {
    const scanStart = Math.max(0, chainHeight - 200);
    console.log(`  Scanning blocks ${scanStart}-${chainHeight - 1} for user TXs...`);

    for (let h = scanStart; h < chainHeight && testTxHashes.length < 5; h++) {
      try {
        const block = await daemon.getBlock({ height: h });
        const hashes = block.result?.tx_hashes || [];
        if (hashes.length > 0) {
          testTxHashes.push(...hashes);
        }
      } catch (_) { /* skip failed blocks */ }
    }

    console.log(`  Found ${testTxHashes.length} user TX(s) to verify.`);
  }
}, 60000);

// ─── Helpers ───────────────────────────────────────────────────────────────

function skipIfNoDaemon() {
  if (!daemonAvailable) {
    console.log('    (skipped: daemon not available)');
    return true;
  }
  return false;
}

function skipIfNoTxs() {
  if (!daemonAvailable || testTxHashes.length === 0) {
    console.log('    (skipped: no user transactions found on testnet)');
    return true;
  }
  return false;
}

/**
 * Fetch ring members for a parsed transaction from the daemon.
 * Returns mixRing: Array of [{ dest, mask }] per input.
 */
async function fetchMixRing(parsedTx) {
  const mixRing = [];

  for (const input of parsedTx.prefix.vin) {
    // Skip coinbase inputs
    if (input.type === TXIN_TYPE.GEN || input.type === undefined) {
      continue;
    }

    const keyOffsets = input.keyOffsets || [];
    const absoluteIndices = offsetsToIndices(keyOffsets);
    const assetType = input.assetType || 'SAL';

    const outsReq = absoluteIndices.map(idx => ({
      amount: 0,
      index: Number(idx),
    }));

    const outsResp = await daemon.getOuts(outsReq, { asset_type: assetType });
    if (!outsResp.success && !outsResp.result) {
      throw new Error(`getOuts failed: ${JSON.stringify(outsResp.error || outsResp)}`);
    }

    const outs = outsResp.result?.outs || outsResp.outs || [];
    if (outs.length !== absoluteIndices.length) {
      throw new Error(
        `getOuts returned ${outs.length} outputs, expected ${absoluteIndices.length}`
      );
    }

    const ringMembers = outs.map(out => ({
      dest: typeof out.key === 'string' ? hexToBytes(out.key) : out.key,
      mask: typeof out.mask === 'string' ? hexToBytes(out.mask) : out.mask,
    }));

    mixRing.push(ringMembers);
  }

  return mixRing;
}

// =============================================================================
// Tests
// =============================================================================

describe('Testnet daemon connectivity', () => {
  test('daemon is reachable', () => {
    if (skipIfNoDaemon()) return;
    expect(daemonAvailable).toBe(true);
    expect(chainHeight).toBeGreaterThan(0);
  });

  test('daemon has user transactions', () => {
    if (skipIfNoDaemon()) return;
    // This is informational — having 0 TXs means the real verification tests skip
    console.log(`    Found ${testTxHashes.length} TX(s): ${testTxHashes.slice(0, 3).map(h => h.slice(0, 12) + '...').join(', ')}`);
  });
});

describe('Parse & verify real testnet transactions', () => {
  test('parse first testnet TX via binary blob', async () => {
    if (skipIfNoTxs()) return;

    const txHash = testTxHashes[0];
    const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    expect(txData).toBeDefined();
    expect(txData.as_hex).toBeDefined();

    const parsed = parseTransaction(hexToBytes(txData.as_hex));
    expect(parsed.prefix).toBeDefined();
    expect(parsed.rct).toBeDefined();
    expect(parsed.prefix.vin.length).toBeGreaterThan(0);
    expect(parsed.rct.type).toBeGreaterThanOrEqual(5); // CLSAG or higher

    console.log(`    TX ${txHash.slice(0, 16)}...`);
    console.log(`      RCT type: ${parsed.rct.type} (${parsed.rct.type === 9 ? 'TCLSAG/SalviumOne' : 'CLSAG'})`);
    console.log(`      Inputs: ${parsed.prefix.vin.length}`);
    console.log(`      Outputs: ${parsed.prefix.vout.length}`);
    console.log(`      Ring size: ${parsed.prefix.vin[0].keyOffsets?.length || 'N/A'}`);
  }, TIMEOUT);

  test('expandTransaction populates key images into sig structs', async () => {
    if (skipIfNoTxs()) return;

    const txHash = testTxHashes[0];
    const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    const parsed = parseTransaction(hexToBytes(txData.as_hex));

    // Before expand: TCLSAG/CLSAG sigs should NOT have I field
    const sigArray = parsed.rct.TCLSAGs || parsed.rct.CLSAGs || [];
    if (sigArray.length > 0) {
      // Parser produces sigs without I (just like C++ serialization)
      const hadI = sigArray[0].I !== undefined;
      console.log(`    Sig had I before expand: ${hadI}`);
    }

    expandTransaction(parsed);

    // After expand: should have I from prefix
    for (let i = 0; i < sigArray.length && i < parsed.prefix.vin.length; i++) {
      expect(sigArray[i].I).toBeDefined();
      const keyImage = parsed.prefix.vin[i].keyImage;
      if (keyImage && sigArray[i].I) {
        const kiHex = typeof keyImage === 'string' ? keyImage : bytesToHex(keyImage);
        const sigIHex = typeof sigArray[i].I === 'string' ? sigArray[i].I : bytesToHex(sigArray[i].I);
        expect(sigIHex).toBe(kiHex);
      }
    }
    console.log(`    Key images injected into ${sigArray.length} sig(s)`);
  }, TIMEOUT);

  test('fetch ring members via getOuts', async () => {
    if (skipIfNoTxs()) return;

    const txHash = testTxHashes[0];
    const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    const parsed = parseTransaction(hexToBytes(txData.as_hex));

    const mixRing = await fetchMixRing(parsed);

    const keyInputs = parsed.prefix.vin.filter(v => v.type === TXIN_TYPE.KEY);
    expect(mixRing.length).toBe(keyInputs.length);

    for (let i = 0; i < mixRing.length; i++) {
      const ringSize = keyInputs[i].keyOffsets.length;
      expect(mixRing[i].length).toBe(ringSize);

      // Each ring member should have 32-byte dest and mask
      for (const member of mixRing[i]) {
        expect(member.dest).toBeInstanceOf(Uint8Array);
        expect(member.dest.length).toBe(32);
        expect(member.mask).toBeInstanceOf(Uint8Array);
        expect(member.mask.length).toBe(32);
      }
    }

    console.log(`    Fetched ring members for ${mixRing.length} input(s), ring size ${mixRing[0]?.length}`);
  }, TIMEOUT);
});

describe('verifyRctSignatures on real testnet TXs', () => {
  test('verify first testnet transaction signatures', async () => {
    if (skipIfNoTxs()) return;

    const txHash = testTxHashes[0];
    console.log(`    Verifying TX: ${txHash}`);

    // 1. Fetch TX
    const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    const rawBytes = hexToBytes(txData.as_hex);
    const parsed = parseTransaction(rawBytes);

    // 2. Fetch ring members
    const mixRing = await fetchMixRing(parsed);

    // 3. Verify (pass rawBytes for correct prefix hash on daemon-fetched TXs)
    const result = verifyRctSignatures(parsed, mixRing, rawBytes);

    console.log(`    Result: ${result.valid ? 'VALID' : 'INVALID'}`);
    if (!result.valid) {
      console.log(`    Errors: ${result.errors.join(', ')}`);
    }

    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);
  }, TIMEOUT);

  test('verify multiple testnet transactions', async () => {
    if (skipIfNoTxs()) return;

    // Verify up to 5 transactions
    const txsToVerify = testTxHashes.slice(0, 5);
    let verified = 0;
    let failed = 0;

    for (const txHash of txsToVerify) {
      try {
        const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
        const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
        if (!txData?.as_hex) {
          console.log(`    Skipping ${txHash.slice(0, 12)}... (no hex data)`);
          continue;
        }

        const rawBytes = hexToBytes(txData.as_hex);
        const parsed = parseTransaction(rawBytes);

        // Skip coinbase-only transactions
        const keyInputs = parsed.prefix.vin.filter(v => v.type === TXIN_TYPE.KEY);
        if (keyInputs.length === 0) {
          console.log(`    Skipping ${txHash.slice(0, 12)}... (coinbase only)`);
          continue;
        }

        const mixRing = await fetchMixRing(parsed);
        const result = verifyRctSignatures(parsed, mixRing, rawBytes);

        const rctTypeName = parsed.rct.type === 9 ? 'TCLSAG' : 'CLSAG';
        const ringSize = keyInputs[0].keyOffsets?.length || 0;

        if (result.valid) {
          verified++;
          console.log(`    OK ${txHash.slice(0, 16)}... (${rctTypeName}, ${keyInputs.length} in, ring ${ringSize})`);
        } else {
          failed++;
          console.log(`    FAIL ${txHash.slice(0, 16)}... : ${result.errors.join('; ')}`);
        }
      } catch (e) {
        failed++;
        console.log(`    ERROR ${txHash.slice(0, 12)}... : ${e.message}`);
      }
    }

    console.log(`    Summary: ${verified} verified, ${failed} failed out of ${txsToVerify.length}`);
    expect(verified).toBeGreaterThan(0);
    expect(failed).toBe(0);
  }, 120000); // 2 min for multiple TXs

  test('tampered transaction should fail verification', async () => {
    if (skipIfNoTxs()) return;

    const txHash = testTxHashes[0];
    const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    const rawBytes = hexToBytes(txData.as_hex);
    const parsed = parseTransaction(rawBytes);
    const mixRing = await fetchMixRing(parsed);

    // Tamper with a ring member (replace first decoy with random bytes)
    const tamperedMixRing = mixRing.map(ring => ring.map(m => ({ ...m })));
    // Flip one byte in the first ring member's dest key
    const destCopy = new Uint8Array(tamperedMixRing[0][0].dest);
    destCopy[0] ^= 0xFF;
    tamperedMixRing[0][0].dest = destCopy;

    const result = verifyRctSignatures(parsed, tamperedMixRing, rawBytes);
    expect(result.valid).toBe(false);
    console.log(`    Tampered TX correctly rejected: ${result.errors[0]}`);
  }, TIMEOUT);
});

describe('End-to-end: parse → expand → fetch ring → verify', () => {
  test('full pipeline on real transaction', async () => {
    if (skipIfNoTxs()) return;

    const txHash = testTxHashes[0];
    console.log(`    Full pipeline for TX: ${txHash.slice(0, 24)}...`);

    // Step 1: Fetch raw TX from daemon
    const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    expect(txData.as_hex).toBeDefined();

    // Step 2: Parse binary blob
    const rawBytes = hexToBytes(txData.as_hex);
    const parsed = parseTransaction(rawBytes);
    expect(parsed.prefix.vin.length).toBeGreaterThan(0);

    // Step 3: Expand (inject key images into sig structs)
    expandTransaction(parsed);
    const sigArray = parsed.rct.TCLSAGs || parsed.rct.CLSAGs;
    if (sigArray && sigArray.length > 0) {
      expect(sigArray[0].I).toBeDefined();
    }

    // Step 4: Fetch ring members
    const mixRing = await fetchMixRing(parsed);
    expect(mixRing.length).toBeGreaterThan(0);

    // Step 5: Verify signatures
    const result = verifyRctSignatures(parsed, mixRing, rawBytes);
    expect(result.valid).toBe(true);
    expect(result.errors).toEqual([]);

    // Step 6: Cross-check — use validateTransactionFull with mixRing context
    const fullResult = validateTransactionFull(parsed, {
      hfVersion: 10,
      height: txData.block_height || 1200,
      mixRing,
      rawBytes,
    });
    const rctErrors = fullResult.errors.filter(e => e.includes('RCT signature'));
    expect(rctErrors.length).toBe(0);

    console.log(`    Pipeline complete — TX is valid`);
    console.log(`    validateTransactionFull: ${fullResult.errors.length} non-RCT warnings/errors`);
  }, TIMEOUT);
});

describe('offsetsToIndices correctness', () => {
  test('converts relative offsets to absolute indices on real TX', async () => {
    if (skipIfNoTxs()) return;

    const txHash = testTxHashes[0];
    const txResp = await daemon.getTransactions([txHash], { decode_as_json: true });
    const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
    const parsed = parseTransaction(hexToBytes(txData.as_hex));

    const keyInputs = parsed.prefix.vin.filter(v => v.type === TXIN_TYPE.KEY);
    for (const input of keyInputs) {
      const offsets = input.keyOffsets;
      const indices = offsetsToIndices(offsets);

      // Indices should be monotonically increasing
      for (let i = 1; i < indices.length; i++) {
        expect(Number(indices[i])).toBeGreaterThan(Number(indices[i - 1]));
      }

      // First index equals first offset
      expect(Number(indices[0])).toBe(Number(offsets[0]));

      // Verify re-construction: indices back to offsets
      for (let i = 0; i < indices.length; i++) {
        const expectedOffset = i === 0
          ? Number(indices[0])
          : Number(indices[i]) - Number(indices[i - 1]);
        expect(expectedOffset).toBe(Number(offsets[i]));
      }

      console.log(`    Ring indices: [${indices.slice(0, 4).map(Number).join(', ')}${indices.length > 4 ? ', ...' : ''}] (${indices.length} members)`);
    }
  }, TIMEOUT);
});
