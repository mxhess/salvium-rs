#!/usr/bin/env bun
/**
 * Comprehensive Burn-In Test for Salvium JS
 *
 * Runs hundreds of transactions across CN and CARROT eras to validate
 * the full transaction lifecycle: transfers, stakes, burns, sweeps.
 *
 * Volume targets:
 *   CN phase:     ~150 transfers A->B, 100+ outputs in B, multi-sweep
 *   CARROT phase: 1000+ micro transfers, mega-sweep (30 inputs x N rounds)
 *
 * Prerequisites:
 * - Fresh testnet chain (reset to height 0)
 * - Mining to wallet A's CN address (pre-1100) then CARROT address (post-1100)
 * - Wallet A json at ~/testnet-wallet/wallet-a.json
 *
 * Usage:
 *   bun test/burn-in.test.js                # Full run (CN + CARROT phases)
 *   bun test/burn-in.test.js --phase cn     # Only CN phase
 *   bun test/burn-in.test.js --phase carrot # Only CARROT phase (resumes sync)
 *
 * All transactions are BROADCAST (not dry-run). Wallet B is persisted to disk.
 * Full TX log saved to ~/testnet-wallet/burn-in-log.json
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { getHfVersionForHeight, NETWORK_ID } from '../src/consensus.js';
import { existsSync } from 'node:fs';
import { getHeight, waitForHeight, fmt, short, loadWalletFromFile } from './test-helpers.js';

await setCryptoBackend('wasm');

// =============================================================================
// Configuration
// =============================================================================

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const NETWORK = 'testnet';
const CARROT_FORK_HEIGHT = 1100;
const SPENDABLE_AGE = 10;
const DEFAULT_RING_SIZE = 16;

const WALLET_A_FILE = process.env.WALLET_A || `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const WALLET_B_FILE = process.env.WALLET_B || `${process.env.HOME}/testnet-wallet/wallet-b.json`;
const SYNC_CACHE_A = WALLET_A_FILE.replace(/\.json$/, '-sync.json');
const SYNC_CACHE_B = WALLET_B_FILE.replace(/\.json$/, '-sync.json');
const TX_LOG_FILE = `${process.env.HOME}/testnet-wallet/burn-in-log.json`;

// =============================================================================
// State
// =============================================================================

const txLog = [];
let totalFees = 0n;
let totalBurned = 0n;
let totalStaked = 0n;

const stats = {
  transfers: { attempted: 0, succeeded: 0, failed: 0 },
  stakes:    { attempted: 0, succeeded: 0, failed: 0 },
  burns:     { attempted: 0, succeeded: 0, failed: 0 },
  sweeps:    { attempted: 0, succeeded: 0, failed: 0 },
};

const daemon = new DaemonRPC({ url: DAEMON_URL });

/** Current era asset type — recomputed before each phase */
let assetType = 'SAL';
async function refreshAssetType() {
  const h = await getHeight(daemon);
  const hfVer = getHfVersionForHeight(h, NETWORK_ID.TESTNET);
  assetType = hfVer >= 6 ? 'SAL1' : 'SAL';
  return assetType;
}

// =============================================================================
// Helpers
// =============================================================================

function logTx(type, from, to, amount, fee, txHash, height) {
  txLog.push({ type, from, to, amount: amount.toString(), fee: fee.toString(), txHash, height, time: Date.now() });
  totalFees += fee;
}

async function syncAndReport(wallet, label, cacheFile = null) {
  const currentHeight = await getHeight(daemon);

  if (cacheFile && existsSync(cacheFile)) {
    try {
      const cached = JSON.parse(await Bun.file(cacheFile).text());
      const cachedSyncHeight = cached.syncHeight || 0;
      if (cachedSyncHeight > currentHeight) {
        console.log(`  ${label}: Cache stale (cached=${cachedSyncHeight}, chain=${currentHeight}), resetting`);
      } else {
        wallet.loadSyncCache(cached);
      }
    } catch { /* ignore bad cache */ }
  }

  await wallet.syncWithDaemon();

  if (cacheFile) {
    await Bun.write(cacheFile, wallet.dumpSyncCacheJSON());
  }

  const { balance, unlockedBalance } = await wallet.getStorageBalance({ assetType });
  console.log(`  ${label}: balance=${fmt(balance, assetType)}, spendable=${fmt(unlockedBalance, assetType)}`);
  return { balance, unlockedBalance };
}

/**
 * Report output count from wallet's internal storage.
 */
async function outputCount(wallet) {
  if (!wallet._storage) return 0;
  const all = await wallet._storage.getOutputs({ isSpent: false });
  return all.length;
}

// =============================================================================
// Transaction Wrappers (thin wrappers for stats/logging only)
// =============================================================================

async function doTransfer(wallet, fromLabel, toAddress, amount) {
  stats.transfers.attempted++;
  const h = await getHeight(daemon);
  try {
    const result = await wallet.transfer(
      [{ address: toAddress, amount }],
      { priority: 'default', assetType }
    );
    stats.transfers.succeeded++;
    logTx('transfer', fromLabel, toAddress.slice(0, 10), amount, result.fee, result.txHash, h);
    return result;
  } catch (e) {
    stats.transfers.failed++;
    console.log(`    FAILED [${fromLabel}->${short(toAddress)}, ${fmt(amount, assetType)}]: ${e.message}`);
    return null;
  }
}

async function doStake(wallet, label, amount) {
  stats.stakes.attempted++;
  const h = await getHeight(daemon);
  try {
    const result = await wallet.stake(amount, { priority: 'default', assetType });
    stats.stakes.succeeded++;
    logTx('stake', label, 'protocol', amount, result.fee, result.txHash, h);
    totalStaked += amount;
    return result;
  } catch (e) {
    stats.stakes.failed++;
    console.log(`    FAILED [stake ${fmt(amount, assetType)}]: ${e.message}`);
    return null;
  }
}

async function doBurn(wallet, label, amount) {
  stats.burns.attempted++;
  const h = await getHeight(daemon);
  try {
    const result = await wallet.burn(amount, { priority: 'default', assetType });
    stats.burns.succeeded++;
    logTx('burn', label, 'burned', amount, result.fee, result.txHash, h);
    totalBurned += amount;
    return result;
  } catch (e) {
    stats.burns.failed++;
    console.log(`    FAILED [burn ${fmt(amount, assetType)}]: ${e.message}`);
    return null;
  }
}

async function doSweep(wallet, label, toAddress) {
  stats.sweeps.attempted++;
  const h = await getHeight(daemon);
  try {
    const result = await wallet.sweep(toAddress, { priority: 'default', assetType });
    stats.sweeps.succeeded++;
    logTx('sweep', label, toAddress.slice(0, 10), result.amount, result.fee, result.txHash, h);
    return result;
  } catch (e) {
    stats.sweeps.failed++;
    console.log(`    FAILED [sweep ${label}]: ${e.message}`);
    return null;
  }
}

/**
 * Repeatedly sweep a wallet until all outputs are consolidated.
 * Each sweep takes up to 30 inputs (MAX_SWEEP_INPUTS in transfer.js).
 * Stops when output count reaches 2 or fewer (sweep always creates
 * 2 outputs: destination + change), or when output count stops decreasing.
 */
async function megaSweep(wallet, label, toAddress, maxRounds = 50) {
  let round = 0;
  let totalSwept = 0n;
  let totalSweepFees = 0n;
  let prevOutputCount = Infinity;

  while (round < maxRounds) {
    const nOutputs = await outputCount(wallet);

    // Sweep always creates 2 outputs (dest + change), so <= 2 is fully consolidated
    if (nOutputs <= 2) {
      console.log(`    Sweep done: ${nOutputs} output(s) remain (fully consolidated)`);
      break;
    }

    // Detect degenerate loop: output count not decreasing means we're cycling
    if (nOutputs >= prevOutputCount) {
      console.log(`    Sweep done: output count not decreasing (${nOutputs} >= ${prevOutputCount}), stopping`);
      break;
    }

    prevOutputCount = nOutputs;
    round++;
    console.log(`    Sweep round ${round}: ${nOutputs} unspent outputs...`);

    const result = await doSweep(wallet, label, toAddress);
    if (!result) {
      console.log(`    Sweep round ${round} failed, stopping`);
      break;
    }

    totalSwept += result.amount;
    totalSweepFees += result.fee;
    console.log(`    Round ${round}: consolidated ${result.inputCount} inputs, fee=${fmt(result.fee, assetType)}, amount=${fmt(result.amount, assetType)}`);

    // Save cache after each round
    await Bun.write(
      label === 'A' ? SYNC_CACHE_A : SYNC_CACHE_B,
      wallet.dumpSyncCacheJSON()
    );

    // Wait for the sweep TX to confirm + maturity before next round
    const h = await getHeight(daemon);
    await waitForHeight(daemon, h + SPENDABLE_AGE + 2, `sweep round ${round} maturity`);
    await wallet.syncWithDaemon();
  }

  console.log(`  Mega-sweep complete: ${round} rounds, swept=${fmt(totalSwept, assetType)}, fees=${fmt(totalSweepFees, assetType)}`);
  return { rounds: round, totalSwept, totalSweepFees };
}

// =============================================================================
// Batch Helpers
// =============================================================================

/**
 * Send a batch of transfers within a single maturity window.
 * Re-syncs after every `resyncInterval` transfers to pick up change outputs.
 */
async function batchTransfers(wallet, fromLabel, toAddress, targetCount, minAmt, maxAmt, cacheFile = null) {
  console.log(`  Sending up to ${targetCount} transfers ${fromLabel} -> ${short(toAddress)}`);
  let success = 0;
  let consecutiveFails = 0;

  for (let i = 0; i < targetCount; i++) {
    const amount = BigInt(Math.floor(Math.random() * Number(maxAmt - minAmt)) + Number(minAmt));
    const result = await doTransfer(wallet, fromLabel, toAddress, amount);

    if (result) {
      success++;
      consecutiveFails = 0;
      if ((i + 1) % 10 === 0 || i === targetCount - 1) {
        console.log(`    ${i + 1}/${targetCount} sent (${success} ok, ${i + 1 - success} failed)`);
      }
    } else {
      consecutiveFails++;
      if (consecutiveFails >= 5) {
        console.log(`    Stopping after ${consecutiveFails} consecutive failures (likely out of spendable outputs)`);
        break;
      }
    }
  }

  console.log(`  Batch done: ${success}/${targetCount} succeeded`);
  return success;
}

/**
 * Send a large number of micro transfers in waves.
 * After each wave of `waveSize`, wait for maturity, re-sync, and continue.
 */
async function microFlood(wallet, fromLabel, toAddress, totalCount, minAmt, maxAmt, waveSize, cacheFile) {
  console.log(`  Flooding ${totalCount} micro transfers ${fromLabel} -> ${short(toAddress)} (waves of ${waveSize})`);
  let sent = 0, failed = 0, consecutiveFails = 0;
  let totalSent = 0n, totalFloodFees = 0n;

  for (let wave = 0; wave * waveSize < totalCount; wave++) {
    const waveStart = wave * waveSize;
    const waveEnd = Math.min(waveStart + waveSize, totalCount);

    if (wave > 0) {
      // Wait for change outputs to mature
      const bh = await getHeight(daemon);
      await waitForHeight(daemon, bh + SPENDABLE_AGE + 2, `wave ${wave + 1} maturity`);
      await syncAndReport(wallet, fromLabel, cacheFile);
    }

    for (let i = waveStart; i < waveEnd; i++) {
      const amount = BigInt(Math.floor(Math.random() * Number(maxAmt - minAmt)) + Number(minAmt));
      try {
        const result = await wallet.transfer(
          [{ address: toAddress, amount }],
          { priority: 'default', assetType }
        );
        sent++;
        consecutiveFails = 0;
        totalSent += amount;
        totalFloodFees += result.fee;
        stats.transfers.attempted++;
        stats.transfers.succeeded++;
        const h = await getHeight(daemon);
        logTx('transfer', fromLabel, toAddress.slice(0, 10), amount, result.fee, result.txHash, h);

        if ((sent + failed) % 25 === 0 || i === waveEnd - 1) {
          console.log(`    ${sent + failed}/${totalCount} (${sent} ok, ${failed} fail) | sent=${fmt(totalSent, assetType)} | fees=${fmt(totalFloodFees, assetType)}`);
        }
      } catch (e) {
        failed++;
        consecutiveFails++;
        stats.transfers.attempted++;
        stats.transfers.failed++;
        if ((sent + failed) % 25 === 0) {
          console.log(`    ${sent + failed}/${totalCount} (${sent} ok, ${failed} fail) | err: ${e.message.slice(0, 60)}`);
        }
        if (consecutiveFails >= 10) {
          console.log(`    Stopping wave after ${consecutiveFails} consecutive failures`);
          break;
        }
      }
    }

    if (consecutiveFails >= 10) break;
  }

  console.log(`  Flood done: ${sent}/${totalCount} succeeded, total=${fmt(totalSent, assetType)}, fees=${fmt(totalFloodFees, assetType)}`);
  return { sent, failed, totalSent, totalFloodFees };
}

function banner(title) {
  console.log('\n' + '='.repeat(72));
  console.log(`  ${title}`);
  console.log('='.repeat(72));
}

function section(title) {
  console.log(`\n--- ${title} ---`);
}

async function saveTxLog() {
  const data = {
    timestamp: new Date().toISOString(),
    stats,
    totalFees: totalFees.toString(),
    totalBurned: totalBurned.toString(),
    totalStaked: totalStaked.toString(),
    txCount: txLog.length,
    txLog,
  };
  await Bun.write(TX_LOG_FILE, JSON.stringify(data, null, 2));
}

// =============================================================================
// Wallet Loading
// =============================================================================

async function loadOrCreateWalletB() {
  if (existsSync(WALLET_B_FILE)) {
    const wallet = await loadWalletFromFile(WALLET_B_FILE, NETWORK);
    console.log(`  Wallet B loaded from ${WALLET_B_FILE}`);
    return wallet;
  }

  const wallet = Wallet.create({ network: NETWORK });
  await Bun.write(WALLET_B_FILE, JSON.stringify(wallet.toJSON(), null, 2));
  console.log(`  Wallet B CREATED and saved to ${WALLET_B_FILE}`);
  return wallet;
}

// =============================================================================
// PHASE 1: CN ERA
// =============================================================================

async function phaseCN(walletA, walletB) {
  banner('PHASE 1: CN ERA (pre-CARROT, height < 1100)');
  await refreshAssetType();

  // Post-HF10: CARROT outputs require CARROT addresses. Using legacy addresses
  // at CARROT heights causes a pubkey mismatch (legacy CN view key != CARROT view key),
  // making outputs undetectable by the receiver's CARROT scanner.
  const h = await getHeight(daemon);
  const postCarrot = h >= CARROT_FORK_HEIGHT;
  const addrA = postCarrot ? walletA.getCarrotAddress() : walletA.getLegacyAddress();
  const addrB = postCarrot ? walletB.getCarrotAddress() : walletB.getLegacyAddress();
  console.log(`  A address: ${short(addrA)}`);
  console.log(`  B address: ${short(addrB)}`);

  const COINBASE_MATURITY = 60;
  const MIN_HEIGHT_FOR_RING = COINBASE_MATURITY + DEFAULT_RING_SIZE + 5;
  await waitForHeight(daemon, MIN_HEIGHT_FOR_RING, 'ring + coinbase maturity');

  // Sync wallet A
  let syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  if (syncA.unlockedBalance === 0n) {
    console.log('  Waiting for more blocks (no spendable balance)...');
    await waitForHeight(daemon, MIN_HEIGHT_FOR_RING + 10, 'more coinbase');
    syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  }

  // ---- Round 1: 50 A -> B transfers (medium, 0.5-5 SAL) ----
  section('CN Round 1: A -> B transfers (0.5-5 SAL)');
  await batchTransfers(walletA, 'A', addrB, 50, 50_000_000n, 500_000_000n, SYNC_CACHE_A);

  let h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'A->B confirms');

  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  let syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  // ---- Round 2: B -> A transfers ----
  if (syncB.unlockedBalance > 0n) {
    section('CN Round 2: B -> A transfers (0.1-1 SAL)');
    await batchTransfers(walletB, 'B', addrA, 15, 10_000_000n, 100_000_000n, SYNC_CACHE_B);
  } else {
    section('CN Round 2: B -> A transfers');
    console.log('  SKIPPED: wallet B has no spendable outputs');
  }

  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'B->A settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  // ---- Round 3: 100 micro transfers to flood B with outputs ----
  section('CN Round 3: Micro flood A -> B (100 x 0.1-0.9 SAL)');
  await microFlood(walletA, 'A', addrB, 100, 10_000_000n, 90_000_000n, 50, SYNC_CACHE_A);

  // ---- Stakes ----
  section('CN Stakes');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-stake settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 5_00_000_000) + 1_00_000_000);
    console.log(`  Stake ${i + 1}/3: ${fmt(amt, assetType)}`);
    await doStake(walletA, 'A', amt);
    if (i < 2) {
      const sh = await getHeight(daemon);
      await waitForHeight(daemon, sh + 2, 'stake spacing');
    }
  }

  // ---- Burns ----
  section('CN Burns');
  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 1_00_000_000) + 10_000_000);
    console.log(`  Burn ${i + 1}/3: ${fmt(amt, assetType)}`);
    await doBurn(walletA, 'A', amt);
  }

  // ---- Large transfers A -> B (10-50 SAL) ----
  section('CN Round 4: Large A -> B transfers (10-50 SAL)');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-large settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await batchTransfers(walletA, 'A', addrB, 10, 1_000_000_000n, 5_000_000_000n, SYNC_CACHE_A);

  // ---- Mega-sweep B -> B (consolidate 100+ outputs) ----
  section('CN Mega-Sweep B -> B');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'pre-sweep maturity');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  const bOutputsPre = await outputCount(walletB);
  console.log(`  B has ${bOutputsPre} unspent outputs before sweep`);

  if (bOutputsPre > 1) {
    await megaSweep(walletB, 'B', addrB);
  } else {
    console.log('  SKIPPED: not enough outputs to sweep');
  }

  // ---- Multi-input stress: B -> A with whatever remains ----
  section('CN Round 5: B -> A stress transfers');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'post-sweep maturity');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  if (syncB.unlockedBalance > 0n) {
    await batchTransfers(walletB, 'B', addrA, 20, 5_000_000n, 100_000_000n, SYNC_CACHE_B);
  } else {
    console.log('  SKIPPED: B has no spendable outputs');
  }

  // ---- Sweep A -> A (consolidate A's change outputs) ----
  section('CN Sweep A -> A');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'pre-sweep-A maturity');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  const aOutputsPre = await outputCount(walletA);
  console.log(`  A has ${aOutputsPre} unspent outputs`);
  if (aOutputsPre > 1) {
    await megaSweep(walletA, 'A', addrA);
  }

  // ---- CN Phase Accounting ----
  section('CN Phase Accounting');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'accounting settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  console.log(`  A outputs: ${await outputCount(walletA)}`);
  console.log(`  B outputs: ${await outputCount(walletB)}`);
  console.log(`  Total fees: ${fmt(totalFees, assetType)}`);
  console.log(`  Total burned: ${fmt(totalBurned, assetType)}`);
  console.log(`  Total staked: ${fmt(totalStaked, assetType)}`);
  console.log(`  TX count: ${txLog.length}`);

  await saveTxLog();
}

// =============================================================================
// PHASE 2: CARROT ERA
// =============================================================================

async function phaseCARROT(walletA, walletB) {
  banner('PHASE 2: CARROT ERA (height >= 1100)');
  await refreshAssetType();

  const addrA = walletA.getCarrotAddress() || walletA.getLegacyAddress();
  const addrB = walletB.getCarrotAddress() || walletB.getLegacyAddress();
  console.log(`  A CARROT: ${short(addrA)}`);
  console.log(`  B CARROT: ${short(addrB)}`);
  console.log(`  Waiting for CARROT fork + coinbase maturity...`);
  console.log(`  (Switch mining to wallet A CARROT address after height 1100)`);
  console.log(`  CARROT address: ${walletA.getCarrotAddress()}`);

  await waitForHeight(daemon, CARROT_FORK_HEIGHT + SPENDABLE_AGE + 5, 'CARROT maturity');

  let syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  let syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  // ---- Round 1: 50 A -> B CARROT transfers (0.5-5 SAL) ----
  section('CARROT Round 1: A -> B transfers (0.5-5 SAL)');
  await batchTransfers(walletA, 'A', addrB, 50, 50_000_000n, 500_000_000n, SYNC_CACHE_A);

  let h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'CARROT A->B confirms');

  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  // ---- Round 2: B -> A CARROT transfers ----
  if (syncB.unlockedBalance > 0n) {
    section('CARROT Round 2: B -> A transfers (0.1-1 SAL)');
    await batchTransfers(walletB, 'B', addrA, 15, 10_000_000n, 100_000_000n, SYNC_CACHE_B);
  } else {
    section('CARROT Round 2: B -> A transfers');
    console.log('  SKIPPED: wallet B has no spendable outputs');
  }

  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'B->A settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  // ---- CARROT Stakes ----
  section('CARROT Stakes');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-stake settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 5_00_000_000) + 1_00_000_000);
    console.log(`  Stake ${i + 1}/3: ${fmt(amt, assetType)}`);
    await doStake(walletA, 'A', amt);
    if (i < 2) {
      const sh = await getHeight(daemon);
      await waitForHeight(daemon, sh + 2, 'stake spacing');
    }
  }

  // ---- CARROT Burns ----
  section('CARROT Burns');
  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 1_00_000_000) + 10_000_000);
    console.log(`  Burn ${i + 1}/3: ${fmt(amt, assetType)}`);
    await doBurn(walletA, 'A', amt);
  }

  // ---- Large transfers A -> B ----
  section('CARROT Round 3: Large A -> B transfers (10-50 SAL)');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-large settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await batchTransfers(walletA, 'A', addrB, 10, 1_000_000_000n, 5_000_000_000n, SYNC_CACHE_A);

  // ---- Mega-sweep B -> B before the micro flood ----
  section('CARROT Pre-Flood Sweep B -> B');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'pre-flood sweep maturity');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  const preFloodOutputs = await outputCount(walletB);
  console.log(`  B has ${preFloodOutputs} outputs before flood`);
  if (preFloodOutputs > 1) {
    await megaSweep(walletB, 'B', addrB);
    h = await getHeight(daemon);
    await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'post-pre-sweep maturity');
    syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  }

  // ---- Round 4: MEGA MICRO FLOOD — 1000+ transfers A -> B ----
  section('CARROT Round 4: MEGA MICRO FLOOD A -> B (1000 x 0.01-0.09 SAL)');
  console.log('  This creates 1000+ tiny outputs in wallet B for mega-sweep testing');
  await microFlood(walletA, 'A', addrB, 1000, 1_000_000n, 9_000_000n, 50, SYNC_CACHE_A);

  // ---- Round 5: MEGA SWEEP B -> B (1000+ outputs) ----
  section('CARROT Round 5: MEGA SWEEP B -> B (1000+ outputs)');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'mega-sweep maturity');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  const megaOutputs = await outputCount(walletB);
  console.log(`  B has ${megaOutputs} unspent outputs before mega-sweep`);

  if (megaOutputs > 1) {
    await megaSweep(walletB, 'B', addrB);
  } else {
    console.log('  SKIPPED: not enough outputs');
  }

  // ---- Round 6: B -> A multi-input stress ----
  section('CARROT Round 6: B -> A stress transfers');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'post-mega-sweep maturity');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  if (syncB.unlockedBalance > 0n) {
    // Progressively larger amounts to force multi-input assembly
    const amounts = [
      ...Array(5).fill(100_000_000n),    // 5 x 1 SAL
      ...Array(5).fill(500_000_000n),    // 5 x 5 SAL
      ...Array(3).fill(1_000_000_000n),  // 3 x 10 SAL
      ...Array(2).fill(2_000_000_000n),  // 2 x 20 SAL
    ];
    let ok = 0;
    for (const amt of amounts) {
      const { unlockedBalance } = await walletB.getStorageBalance({ assetType });
      if (unlockedBalance < amt + 50_000_000n) {
        console.log(`    Skipping ${fmt(amt, assetType)}: insufficient balance`);
        continue;
      }
      const result = await doTransfer(walletB, 'B', addrA, amt);
      if (result) {
        ok++;
        console.log(`    ${fmt(amt, assetType)} OK (${result.inputCount} inputs)`);
      }
    }
    console.log(`  Stress transfers: ${ok}/${amounts.length}`);
  } else {
    console.log('  SKIPPED: B has no spendable outputs');
  }

  // ---- Final sweeps: both wallets to self ----
  section('CARROT Final Sweep A -> A');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'final-sweep-A maturity');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  const aOutputs = await outputCount(walletA);
  console.log(`  A has ${aOutputs} outputs`);
  if (aOutputs > 1) {
    await megaSweep(walletA, 'A', addrA);
  }

  section('CARROT Final Sweep B -> B');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'final-sweep-B maturity');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  const bOutputs = await outputCount(walletB);
  console.log(`  B has ${bOutputs} outputs`);
  if (bOutputs > 1) {
    await megaSweep(walletB, 'B', addrB);
  }

  // ---- CARROT Phase Accounting ----
  section('CARROT Phase Accounting');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'accounting settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  console.log(`  A outputs: ${await outputCount(walletA)}`);
  console.log(`  B outputs: ${await outputCount(walletB)}`);
  console.log(`  Total fees: ${fmt(totalFees, assetType)}`);
  console.log(`  Total burned: ${fmt(totalBurned, assetType)}`);
  console.log(`  Total staked: ${fmt(totalStaked, assetType)}`);
  console.log(`  TX count: ${txLog.length}`);

  await saveTxLog();
}

// =============================================================================
// FINAL RECONCILIATION
// =============================================================================

async function reconcile(walletA, walletB) {
  banner('FINAL RECONCILIATION');
  await refreshAssetType();

  const h = await getHeight(daemon);
  await waitForHeight(daemon, h + 5, 'final settle');

  const syncA = await syncAndReport(walletA, 'A (final)', SYNC_CACHE_A);
  const syncB = await syncAndReport(walletB, 'B (final)', SYNC_CACHE_B);

  // Sum transfer amounts by direction
  let totalA2B = 0n, totalB2A = 0n;
  let cnTransfers = 0, carrotTransfers = 0;
  for (const tx of txLog) {
    const amt = BigInt(tx.amount);
    if (tx.type === 'transfer') {
      if (tx.from === 'A') totalA2B += amt;
      if (tx.from === 'B') totalB2A += amt;
      if (tx.height < CARROT_FORK_HEIGHT) cnTransfers++;
      else carrotTransfers++;
    }
  }

  const cnSweeps = txLog.filter(t => t.type === 'sweep' && t.height < CARROT_FORK_HEIGHT).length;
  const carrotSweeps = txLog.filter(t => t.type === 'sweep' && t.height >= CARROT_FORK_HEIGHT).length;

  console.log('\n  Transaction Summary');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Total transactions:   ${txLog.length}`);
  console.log(`  CN-era transfers:     ${cnTransfers}`);
  console.log(`  CARROT-era transfers: ${carrotTransfers}`);
  console.log(`  CN-era sweeps:        ${cnSweeps}`);
  console.log(`  CARROT-era sweeps:    ${carrotSweeps}`);
  console.log(`  Transfers: ${stats.transfers.succeeded}/${stats.transfers.attempted} ok (${stats.transfers.failed} failed)`);
  console.log(`  Stakes:    ${stats.stakes.succeeded}/${stats.stakes.attempted} ok (${stats.stakes.failed} failed)`);
  console.log(`  Burns:     ${stats.burns.succeeded}/${stats.burns.attempted} ok (${stats.burns.failed} failed)`);
  console.log(`  Sweeps:    ${stats.sweeps.succeeded}/${stats.sweeps.attempted} ok (${stats.sweeps.failed} failed)`);

  console.log('\n  Balance Sheet');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Wallet A balance:   ${fmt(syncA.balance, assetType)} (${await outputCount(walletA)} outputs)`);
  console.log(`  Wallet B balance:   ${fmt(syncB.balance, assetType)} (${await outputCount(walletB)} outputs)`);
  console.log(`  Total A -> B:       ${fmt(totalA2B, assetType)}`);
  console.log(`  Total B -> A:       ${fmt(totalB2A, assetType)}`);
  console.log(`  Total fees:         ${fmt(totalFees, assetType)}`);
  console.log(`  Total burned:       ${fmt(totalBurned, assetType)}`);
  console.log(`  Total staked:       ${fmt(totalStaked, assetType)}`);

  // Success rate
  const totalAttempted = stats.transfers.attempted + stats.stakes.attempted + stats.burns.attempted + stats.sweeps.attempted;
  const totalSucceeded = stats.transfers.succeeded + stats.stakes.succeeded + stats.burns.succeeded + stats.sweeps.succeeded;
  const totalFailed = totalAttempted - totalSucceeded;
  const successRate = totalAttempted > 0 ? ((totalSucceeded / totalAttempted) * 100).toFixed(1) : '0.0';

  console.log('\n  Result');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Success rate: ${totalSucceeded}/${totalAttempted} (${successRate}%)`);

  if (totalFailed === 0) {
    console.log('  ALL TRANSACTIONS SUCCEEDED');
  } else {
    console.log(`  WARNING: ${totalFailed} transactions failed`);
    const failTypes = {};
    for (const tx of txLog) {
      if (tx.failed) {
        failTypes[tx.type] = (failTypes[tx.type] || 0) + 1;
      }
    }
    if (Object.keys(failTypes).length > 0) {
      console.log(`  Failure breakdown: ${JSON.stringify(failTypes)}`);
    }
  }

  await saveTxLog();
  console.log(`\n  TX log saved to ${TX_LOG_FILE}`);
}

// =============================================================================
// MAIN
// =============================================================================

async function main() {
  console.log();
  console.log('+----------------------------------------------------------------------+');
  console.log('|         SALVIUM-JS COMPREHENSIVE BURN-IN TEST                        |');
  console.log('+----------------------------------------------------------------------+');
  console.log();

  const h = await getHeight(daemon);
  console.log(`  Daemon:       ${DAEMON_URL}`);
  console.log(`  Network:      ${NETWORK}`);
  console.log(`  Height:       ${h}`);
  console.log(`  CARROT fork:  ${CARROT_FORK_HEIGHT}`);
  console.log();

  // Load wallets
  section('Loading Wallets');
  const walletA = await loadWalletFromFile(WALLET_A_FILE, NETWORK);
  walletA.setDaemon(daemon);
  console.log(`  A CN addr:     ${short(walletA.getLegacyAddress())}`);
  console.log(`  A CARROT addr: ${short(walletA.getCarrotAddress())}`);

  const walletB = await loadOrCreateWalletB();
  walletB.setDaemon(daemon);
  console.log(`  B CN addr:     ${short(walletB.getLegacyAddress())}`);
  console.log(`  B CARROT addr: ${short(walletB.getCarrotAddress())}`);

  // Parse --phase argument
  const phaseArg = process.argv.find(a => a.startsWith('--phase='))?.split('=')[1]
    || (process.argv.includes('--phase') ? process.argv[process.argv.indexOf('--phase') + 1] : null)
    || 'all';

  console.log(`\n  Phase: ${phaseArg}`);

  if (phaseArg === 'all' || phaseArg === 'cn') {
    await phaseCN(walletA, walletB);
  }

  if (phaseArg === 'all' || phaseArg === 'carrot') {
    await phaseCARROT(walletA, walletB);
  }

  await reconcile(walletA, walletB);

  console.log('\nBurn-in test complete.\n');
}

main().catch(e => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
