#!/usr/bin/env bun
/**
 * Comprehensive Stake Burn-In Test for Salvium JS
 *
 * Two wallets, mining from genesis, transfers to diversify inputs, multiple
 * stakes of varied sizes, crossing the CARROT hard fork (height 1100),
 * verifying stake returns after the 20-block testnet lock period, and full
 * reconciliation.
 *
 * Prerequisites:
 * - Fresh testnet chain (reset to height 0)
 * - Mining to wallet A's CN address (pre-1100) then CARROT address (post-1100)
 * - Wallet A json at ~/testnet-wallet/wallet-a.json
 *
 * Usage:
 *   bun test/stake-integration.test.js                    # Full run
 *   bun test/stake-integration.test.js --phase cn         # CN only
 *   bun test/stake-integration.test.js --phase carrot     # CARROT only (resumes sync)
 *
 * All transactions are BROADCAST (not dry-run). Wallet B is persisted to disk.
 * Full TX log saved to ~/testnet-wallet/stake-test-log.json
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
const COINBASE_MATURITY = 60;
const STAKE_LOCK_PERIOD = 20; // testnet — from src/consensus.js:194

const WALLET_A_FILE = process.env.WALLET_A || `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const WALLET_B_FILE = process.env.WALLET_B || `${process.env.HOME}/testnet-wallet/wallet-b.json`;
const SYNC_CACHE_A = WALLET_A_FILE.replace(/\.json$/, '-sync.json');
const SYNC_CACHE_B = WALLET_B_FILE.replace(/\.json$/, '-sync.json');
const TX_LOG_FILE = `${process.env.HOME}/testnet-wallet/stake-test-log.json`;

// =============================================================================
// State
// =============================================================================

const txLog = [];
let totalFees = 0n;
let totalStaked = 0n;
let totalReturned = 0n;
let totalYield = 0n;

const stats = {
  transfers: { attempted: 0, succeeded: 0, failed: 0 },
  stakes:    { attempted: 0, succeeded: 0, failed: 0 },
};

const daemon = new DaemonRPC({ url: DAEMON_URL });

/**
 * Stake registry — tracks every stake issued.
 * Map<txHash, { amount, height, unlockHeight, era, wallet }>
 */
const stakeRegistry = new Map();

/**
 * Return registry — tracks protocol_tx outputs matched to stakes.
 * Map<txHash, { amount, height, matchedStake, yield }>
 */
const returnRegistry = new Map();

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

async function outputCount(wallet) {
  if (!wallet._storage) return 0;
  const all = await wallet._storage.getOutputs({ isSpent: false });
  return all.length;
}

// =============================================================================
// Transaction Wrappers
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

async function doStake(wallet, label, amount, era) {
  stats.stakes.attempted++;
  const h = await getHeight(daemon);
  try {
    const result = await wallet.stake(amount, { priority: 'default', assetType });
    stats.stakes.succeeded++;
    logTx('stake', label, 'protocol', amount, result.fee, result.txHash, h);
    totalStaked += amount;

    // Register in stake registry for later verification
    const unlockHeight = h + STAKE_LOCK_PERIOD;
    stakeRegistry.set(result.txHash, {
      amount,
      height: h,
      unlockHeight,
      era: era || (h < CARROT_FORK_HEIGHT ? 'CN' : 'CARROT'),
      wallet: label,
    });
    console.log(`    Staked ${fmt(amount, assetType)} at height ${h}, unlock at ${unlockHeight} [${result.txHash.slice(0, 16)}...]`);

    return result;
  } catch (e) {
    stats.stakes.failed++;
    console.log(`    FAILED [stake ${fmt(amount, assetType)}]: ${e.message}`);
    return null;
  }
}

// =============================================================================
// Batch Helpers
// =============================================================================

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

function banner(title) {
  console.log('\n' + '='.repeat(72));
  console.log(`  ${title}`);
  console.log('='.repeat(72));
}

function section(title) {
  console.log(`\n--- ${title} ---`);
}

async function saveTxLog() {
  const stakeEntries = {};
  for (const [hash, entry] of stakeRegistry) {
    stakeEntries[hash] = { ...entry, amount: entry.amount.toString() };
  }
  const returnEntries = {};
  for (const [hash, entry] of returnRegistry) {
    returnEntries[hash] = { ...entry, amount: entry.amount.toString(), yield: entry.yield.toString() };
  }
  const data = {
    timestamp: new Date().toISOString(),
    stats,
    totalFees: totalFees.toString(),
    totalStaked: totalStaked.toString(),
    totalReturned: totalReturned.toString(),
    totalYield: totalYield.toString(),
    stakeRegistry: stakeEntries,
    returnRegistry: returnEntries,
    txCount: txLog.length,
    txLog,
  };
  await Bun.write(TX_LOG_FILE, JSON.stringify(data, null, 2));
}

// =============================================================================
// Stake Return Verification
// =============================================================================

/**
 * After mining past a stake's unlock height, scan wallet transactions for
 * protocol_tx outputs that correspond to stake returns.
 *
 * A return is matched when:
 *   - The transaction is a protocol_tx
 *   - It appears at or shortly after the stake's unlockHeight
 *   - The return amount >= the staked amount (includes yield)
 */
async function verifyStakeReturns(wallet, label) {
  if (!wallet._storage) {
    console.log(`  ${label}: No storage — cannot verify returns`);
    return;
  }

  const transactions = await wallet._storage.getTransactions();
  const currentHeight = await getHeight(daemon);

  let matched = 0;
  let unmatched = 0;

  for (const [txHash, stake] of stakeRegistry) {
    if (stake.wallet !== label) continue;

    // Skip stakes whose unlock height hasn't been reached yet
    if (currentHeight < stake.unlockHeight + SPENDABLE_AGE) {
      console.log(`    [${txHash.slice(0, 16)}...] Not yet unlocked (need height ${stake.unlockHeight + SPENDABLE_AGE}, at ${currentHeight})`);
      continue;
    }

    // Already matched?
    if (returnRegistry.has(txHash)) {
      matched++;
      continue;
    }

    // Look for protocol_tx outputs near unlockHeight
    // The return typically arrives in a block at unlockHeight or within a few blocks after
    const returnCandidates = transactions.filter(tx =>
      tx.isProtocolTx &&
      tx.blockHeight >= stake.unlockHeight &&
      tx.blockHeight <= stake.unlockHeight + 10
    );

    if (returnCandidates.length > 0) {
      // Find the best candidate: an output whose amount >= staked amount
      let bestCandidate = null;
      let bestAmount = 0n;

      for (const candidate of returnCandidates) {
        // Sum received outputs in this protocol_tx
        const outputs = candidate.outputs || [];
        let candidateAmount = 0n;
        for (const out of outputs) {
          candidateAmount += out.amount || 0n;
        }

        // Also check the transaction-level amount field
        if (candidateAmount === 0n && candidate.amount) {
          candidateAmount = candidate.amount;
        }

        if (candidateAmount >= stake.amount && candidateAmount > bestAmount) {
          bestCandidate = candidate;
          bestAmount = candidateAmount;
        }
      }

      if (bestCandidate) {
        const yieldAmount = bestAmount - stake.amount;
        returnRegistry.set(txHash, {
          amount: bestAmount,
          height: bestCandidate.blockHeight,
          matchedStake: txHash,
          yield: yieldAmount,
        });
        totalReturned += bestAmount;
        totalYield += yieldAmount;
        matched++;
        console.log(`    [${txHash.slice(0, 16)}...] RETURN FOUND at height ${bestCandidate.blockHeight}: ` +
          `staked=${fmt(stake.amount, assetType)}, returned=${fmt(bestAmount, assetType)}, yield=${fmt(yieldAmount, assetType)}`);
      } else {
        unmatched++;
        console.log(`    [${txHash.slice(0, 16)}...] UNMATCHED: ${returnCandidates.length} protocol_tx found near unlock height ${stake.unlockHeight} but none >= staked amount ${fmt(stake.amount, assetType)}`);
      }
    } else {
      unmatched++;
      console.log(`    [${txHash.slice(0, 16)}...] NO RETURN: no protocol_tx found near unlock height ${stake.unlockHeight} (checked ${stake.unlockHeight}-${stake.unlockHeight + 10})`);
    }
  }

  const total = matched + unmatched;
  if (total > 0) {
    console.log(`  ${label} stake return verification: ${matched}/${total} matched`);
  }
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
  banner('PHASE 1: CN ERA — Stake Burn-In (pre-CARROT, height < 1100)');
  await refreshAssetType();

  let h = await getHeight(daemon);
  const postCarrot = h >= CARROT_FORK_HEIGHT;
  const addrA = postCarrot ? walletA.getCarrotAddress() : walletA.getLegacyAddress();
  const addrB = postCarrot ? walletB.getCarrotAddress() : walletB.getLegacyAddress();
  console.log(`  A address: ${short(addrA)}`);
  console.log(`  B address: ${short(addrB)}`);

  // ---- Wait for coinbase maturity + ring decoys ----
  const MIN_HEIGHT_FOR_RING = COINBASE_MATURITY + DEFAULT_RING_SIZE + 5;
  await waitForHeight(daemon, MIN_HEIGHT_FOR_RING, 'ring + coinbase maturity');

  let syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  if (syncA.unlockedBalance === 0n) {
    console.log('  Waiting for more blocks (no spendable balance)...');
    await waitForHeight(daemon, MIN_HEIGHT_FOR_RING + 10, 'more coinbase');
    syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  }

  // ---- Transfers A->B (input diversification) ----
  section('CN Transfers: A -> B (0.5-5 SAL) — input diversification');
  await batchTransfers(walletA, 'A', addrB, 20, 50_000_000n, 500_000_000n, SYNC_CACHE_A);

  h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'A->B confirms');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  let syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  // ---- Transfers B->A (create change outputs in both) ----
  if (syncB.unlockedBalance > 0n) {
    section('CN Transfers: B -> A (0.1-1 SAL) — change diversification');
    await batchTransfers(walletB, 'B', addrA, 10, 10_000_000n, 100_000_000n, SYNC_CACHE_B);
  } else {
    section('CN Transfers: B -> A');
    console.log('  SKIPPED: wallet B has no spendable outputs');
  }

  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'B->A settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  // ---- CN Stakes — Round 1 (wallet A, 3 varied sizes) ----
  section('CN Stakes — Round 1 (wallet A: small, medium, large)');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-stake settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  const cnStakeAmounts1 = [
    // Small: 1-3 SAL
    BigInt(Math.floor(Math.random() * 200_000_000) + 100_000_000),
    // Medium: 5-10 SAL
    BigInt(Math.floor(Math.random() * 500_000_000) + 500_000_000),
    // Large: 15-25 SAL
    BigInt(Math.floor(Math.random() * 1_000_000_000) + 1_500_000_000),
  ];

  for (let i = 0; i < cnStakeAmounts1.length; i++) {
    const labels = ['small', 'medium', 'large'];
    console.log(`  Stake ${i + 1}/3 (${labels[i]}): ${fmt(cnStakeAmounts1[i], assetType)}`);
    await doStake(walletA, 'A', cnStakeAmounts1[i], 'CN');
    if (i < cnStakeAmounts1.length - 1) {
      const sh = await getHeight(daemon);
      await waitForHeight(daemon, sh + 2, 'stake spacing');
    }
  }

  // ---- Mine past lock period, verify Round 1 returns ----
  section('CN Stake Returns — Round 1 Verification');
  h = await getHeight(daemon);
  const round1UnlockTarget = h + STAKE_LOCK_PERIOD + SPENDABLE_AGE + 5;
  await waitForHeight(daemon, round1UnlockTarget, 'Round 1 unlock + spendable age');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await verifyStakeReturns(walletA, 'A');

  // ---- CN Stakes — Round 2 (wallet B, if it has balance) ----
  section('CN Stakes — Round 2 (wallet B)');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  if (syncB.unlockedBalance > 200_000_000n) {
    const cnStakeAmountsB = [
      BigInt(Math.floor(Math.random() * 100_000_000) + 50_000_000),
      BigInt(Math.floor(Math.random() * 200_000_000) + 100_000_000),
    ];

    for (let i = 0; i < cnStakeAmountsB.length; i++) {
      console.log(`  B Stake ${i + 1}/2: ${fmt(cnStakeAmountsB[i], assetType)}`);
      await doStake(walletB, 'B', cnStakeAmountsB[i], 'CN');
      if (i < cnStakeAmountsB.length - 1) {
        const sh = await getHeight(daemon);
        await waitForHeight(daemon, sh + 2, 'B stake spacing');
      }
    }
  } else {
    console.log('  SKIPPED: wallet B has insufficient balance for staking');
  }

  // ---- More transfers to keep inputs flowing ----
  section('CN Transfers: A -> B (keep inputs flowing)');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-transfer settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await batchTransfers(walletA, 'A', addrB, 10, 50_000_000n, 300_000_000n, SYNC_CACHE_A);

  // ---- Mine past Round 2 lock, verify B's returns ----
  section('CN Stake Returns — Round 2 Verification');
  h = await getHeight(daemon);
  const round2UnlockTarget = h + STAKE_LOCK_PERIOD + SPENDABLE_AGE + 5;
  await waitForHeight(daemon, round2UnlockTarget, 'Round 2 unlock + spendable age');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  await verifyStakeReturns(walletB, 'B');

  // Also re-verify A in case more returns arrived
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await verifyStakeReturns(walletA, 'A');

  // ---- CN Phase Accounting ----
  section('CN Phase Accounting');
  console.log(`  A outputs: ${await outputCount(walletA)}`);
  console.log(`  B outputs: ${await outputCount(walletB)}`);
  console.log(`  Total fees:     ${fmt(totalFees, assetType)}`);
  console.log(`  Total staked:   ${fmt(totalStaked, assetType)}`);
  console.log(`  Total returned: ${fmt(totalReturned, assetType)}`);
  console.log(`  Total yield:    ${fmt(totalYield, assetType)}`);
  console.log(`  Stakes issued:  ${stakeRegistry.size}`);
  console.log(`  Returns found:  ${returnRegistry.size}`);
  console.log(`  TX count:       ${txLog.length}`);

  await saveTxLog();
}

// =============================================================================
// PHASE 2: CARROT ERA
// =============================================================================

async function phaseCARROT(walletA, walletB) {
  banner('PHASE 2: CARROT ERA — Stake Burn-In (height >= 1100)');
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

  // ---- CARROT Transfers A->B (input diversification) ----
  section('CARROT Transfers: A -> B (0.5-5 SAL) — input diversification');
  await batchTransfers(walletA, 'A', addrB, 20, 50_000_000n, 500_000_000n, SYNC_CACHE_A);

  let h = await getHeight(daemon);
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'CARROT A->B confirms');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  // ---- CARROT Transfers B->A ----
  if (syncB.unlockedBalance > 0n) {
    section('CARROT Transfers: B -> A (0.1-1 SAL) — change diversification');
    await batchTransfers(walletB, 'B', addrA, 10, 10_000_000n, 100_000_000n, SYNC_CACHE_B);
  } else {
    section('CARROT Transfers: B -> A');
    console.log('  SKIPPED: wallet B has no spendable outputs');
  }

  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'B->A settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  // ---- CARROT Stakes — Round 1 (wallet A, 3 varied sizes) ----
  section('CARROT Stakes — Round 1 (wallet A: small, medium, large)');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-stake settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  const carrotStakeAmounts1 = [
    // Small: 1-3 SAL
    BigInt(Math.floor(Math.random() * 200_000_000) + 100_000_000),
    // Medium: 5-10 SAL
    BigInt(Math.floor(Math.random() * 500_000_000) + 500_000_000),
    // Large: 15-25 SAL
    BigInt(Math.floor(Math.random() * 1_000_000_000) + 1_500_000_000),
  ];

  for (let i = 0; i < carrotStakeAmounts1.length; i++) {
    const labels = ['small', 'medium', 'large'];
    console.log(`  Stake ${i + 1}/3 (${labels[i]}): ${fmt(carrotStakeAmounts1[i], assetType)}`);
    await doStake(walletA, 'A', carrotStakeAmounts1[i], 'CARROT');
    if (i < carrotStakeAmounts1.length - 1) {
      const sh = await getHeight(daemon);
      await waitForHeight(daemon, sh + 2, 'stake spacing');
    }
  }

  // ---- Mine past lock period, verify CARROT Round 1 returns ----
  section('CARROT Stake Returns — Round 1 Verification');
  h = await getHeight(daemon);
  const carrotR1Unlock = h + STAKE_LOCK_PERIOD + SPENDABLE_AGE + 5;
  await waitForHeight(daemon, carrotR1Unlock, 'CARROT Round 1 unlock + spendable age');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await verifyStakeReturns(walletA, 'A');

  // ---- CARROT Stakes — Round 2 (wallet B) ----
  section('CARROT Stakes — Round 2 (wallet B)');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);

  if (syncB.unlockedBalance > 200_000_000n) {
    const carrotStakeAmountsB = [
      BigInt(Math.floor(Math.random() * 100_000_000) + 50_000_000),
      BigInt(Math.floor(Math.random() * 200_000_000) + 100_000_000),
    ];

    for (let i = 0; i < carrotStakeAmountsB.length; i++) {
      console.log(`  B Stake ${i + 1}/2: ${fmt(carrotStakeAmountsB[i], assetType)}`);
      await doStake(walletB, 'B', carrotStakeAmountsB[i], 'CARROT');
      if (i < carrotStakeAmountsB.length - 1) {
        const sh = await getHeight(daemon);
        await waitForHeight(daemon, sh + 2, 'B stake spacing');
      }
    }
  } else {
    console.log('  SKIPPED: wallet B has insufficient balance for staking');
  }

  // ---- More transfers to diversify further ----
  section('CARROT Transfers: A -> B (diversify further)');
  h = await getHeight(daemon);
  await waitForHeight(daemon, h + 3, 'pre-transfer settle');
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await batchTransfers(walletA, 'A', addrB, 10, 50_000_000n, 300_000_000n, SYNC_CACHE_A);

  // ---- Mine past Round 2 lock, verify B's CARROT returns ----
  section('CARROT Stake Returns — Round 2 Verification');
  h = await getHeight(daemon);
  const carrotR2Unlock = h + STAKE_LOCK_PERIOD + SPENDABLE_AGE + 5;
  await waitForHeight(daemon, carrotR2Unlock, 'CARROT Round 2 unlock + spendable age');
  syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  await verifyStakeReturns(walletB, 'B');

  // Also re-verify A in case more returns arrived
  syncA = await syncAndReport(walletA, 'A', SYNC_CACHE_A);
  await verifyStakeReturns(walletA, 'A');

  // ---- CARROT Phase Accounting ----
  section('CARROT Phase Accounting');
  console.log(`  A outputs: ${await outputCount(walletA)}`);
  console.log(`  B outputs: ${await outputCount(walletB)}`);
  console.log(`  Total fees:     ${fmt(totalFees, assetType)}`);
  console.log(`  Total staked:   ${fmt(totalStaked, assetType)}`);
  console.log(`  Total returned: ${fmt(totalReturned, assetType)}`);
  console.log(`  Total yield:    ${fmt(totalYield, assetType)}`);
  console.log(`  Stakes issued:  ${stakeRegistry.size}`);
  console.log(`  Returns found:  ${returnRegistry.size}`);
  console.log(`  TX count:       ${txLog.length}`);

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

  // Final return verification pass
  section('Final Stake Return Verification');
  await verifyStakeReturns(walletA, 'A');
  await verifyStakeReturns(walletB, 'B');

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

  const cnStakes = txLog.filter(t => t.type === 'stake' && t.height < CARROT_FORK_HEIGHT).length;
  const carrotStakes = txLog.filter(t => t.type === 'stake' && t.height >= CARROT_FORK_HEIGHT).length;

  console.log('\n  Transaction Summary');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Total transactions:   ${txLog.length}`);
  console.log(`  CN-era transfers:     ${cnTransfers}`);
  console.log(`  CARROT-era transfers: ${carrotTransfers}`);
  console.log(`  CN-era stakes:        ${cnStakes}`);
  console.log(`  CARROT-era stakes:    ${carrotStakes}`);
  console.log(`  Transfers: ${stats.transfers.succeeded}/${stats.transfers.attempted} ok (${stats.transfers.failed} failed)`);
  console.log(`  Stakes:    ${stats.stakes.succeeded}/${stats.stakes.attempted} ok (${stats.stakes.failed} failed)`);

  // Per-stake verification
  console.log('\n  Per-Stake Verification');
  console.log('  ' + '-'.repeat(50));

  let stakesVerified = 0;
  let stakesUnverified = 0;

  for (const [txHash, stake] of stakeRegistry) {
    const returnEntry = returnRegistry.get(txHash);
    if (returnEntry) {
      stakesVerified++;
      console.log(`  [${stake.era}] ${stake.wallet} ${fmt(stake.amount, assetType)} @ h${stake.height} -> ` +
        `returned ${fmt(returnEntry.amount, assetType)} @ h${returnEntry.height} (yield: ${fmt(returnEntry.yield, assetType)})`);
    } else {
      stakesUnverified++;
      const reason = (await getHeight(daemon)) < stake.unlockHeight + SPENDABLE_AGE
        ? 'not yet unlocked'
        : 'no return detected';
      console.log(`  [${stake.era}] ${stake.wallet} ${fmt(stake.amount, assetType)} @ h${stake.height} -> ${reason}`);
    }
  }

  console.log(`\n  Verified: ${stakesVerified}/${stakeRegistry.size}`);
  if (stakesUnverified > 0) {
    console.log(`  Unverified: ${stakesUnverified} (may need more blocks)`);
  }

  // Balance sheet
  console.log('\n  Balance Sheet');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Wallet A balance:   ${fmt(syncA.balance, assetType)} (${await outputCount(walletA)} outputs)`);
  console.log(`  Wallet B balance:   ${fmt(syncB.balance, assetType)} (${await outputCount(walletB)} outputs)`);
  console.log(`  Total A -> B:       ${fmt(totalA2B, assetType)}`);
  console.log(`  Total B -> A:       ${fmt(totalB2A, assetType)}`);
  console.log(`  Total fees:         ${fmt(totalFees, assetType)}`);
  console.log(`  Total staked:       ${fmt(totalStaked, assetType)}`);
  console.log(`  Total returned:     ${fmt(totalReturned, assetType)}`);
  console.log(`  Total yield:        ${fmt(totalYield, assetType)}`);

  // Success rate
  const totalAttempted = stats.transfers.attempted + stats.stakes.attempted;
  const totalSucceeded = stats.transfers.succeeded + stats.stakes.succeeded;
  const totalFailed = totalAttempted - totalSucceeded;
  const successRate = totalAttempted > 0 ? ((totalSucceeded / totalAttempted) * 100).toFixed(1) : '0.0';

  console.log('\n  Result');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Success rate: ${totalSucceeded}/${totalAttempted} (${successRate}%)`);
  console.log(`  Transfer success: ${stats.transfers.succeeded}/${stats.transfers.attempted}`);
  console.log(`  Stake success:    ${stats.stakes.succeeded}/${stats.stakes.attempted}`);
  console.log(`  Stake returns:    ${returnRegistry.size}/${stakeRegistry.size} verified`);

  if (totalFailed === 0 && returnRegistry.size === stakeRegistry.size) {
    console.log('  ALL TRANSACTIONS AND STAKE RETURNS VERIFIED');
  } else if (totalFailed === 0) {
    console.log('  ALL TRANSACTIONS SUCCEEDED (some stake returns may still be pending)');
  } else {
    console.log(`  WARNING: ${totalFailed} transactions failed`);
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
  console.log('|        SALVIUM-JS STAKE BURN-IN TEST                                 |');
  console.log('+----------------------------------------------------------------------+');
  console.log();

  const h = await getHeight(daemon);
  console.log(`  Daemon:          ${DAEMON_URL}`);
  console.log(`  Network:         ${NETWORK}`);
  console.log(`  Height:          ${h}`);
  console.log(`  CARROT fork:     ${CARROT_FORK_HEIGHT}`);
  console.log(`  Stake lock:      ${STAKE_LOCK_PERIOD} blocks`);
  console.log(`  Spendable age:   ${SPENDABLE_AGE} blocks`);
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

  console.log('\nStake burn-in test complete.\n');
}

main().catch(e => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
