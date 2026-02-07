#!/usr/bin/env bun
/**
 * Comprehensive Burn-In Test for Salvium JS
 *
 * Runs hundreds of transactions across CN and CARROT eras to validate
 * the full transaction lifecycle: transfers, stakes, burns, sweeps.
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
 * The test will:
 * 1. Phase CN (blocks 20-1099): transfers A↔B, stakes, burns, sweeps using CN addresses
 * 2. Phase CARROT (blocks 1112+): same using CARROT addresses
 * 3. Final reconciliation: balance sheet, accounting, failure report
 *
 * All transactions are BROADCAST (not dry-run). Wallet B is persisted to disk.
 * Full TX log saved to ~/testnet-wallet/burn-in-log.json
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer, sweep, stake, burn } from '../src/wallet/transfer.js';
import { bytesToHex } from '../src/address.js';
import { existsSync } from 'node:fs';

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

// =============================================================================
// Helpers
// =============================================================================

function fmt(atomic) {
  return `${(Number(atomic) / 1e8).toFixed(8)} SAL`;
}

function short(addr) {
  return addr ? addr.slice(0, 20) + '...' : 'N/A';
}

async function getHeight() {
  const info = await daemon.getInfo();
  return info.result?.height || info.data?.height || 0;
}

async function waitForHeight(target, label = '') {
  let h = await getHeight();
  if (h >= target) return h;
  const tag = label ? ` [${label}]` : '';
  process.stdout.write(`  Waiting for height ${target}${tag}... (at ${h})`);
  while (h < target) {
    await new Promise(r => setTimeout(r, 3000));
    h = await getHeight();
    process.stdout.write(`\r  Waiting for height ${target}${tag}... (at ${h})     `);
  }
  process.stdout.write('\n');
  return h;
}

async function syncWallet(label, keys, storage, cacheFile, carrotKeys) {
  const currentHeight = await getHeight();

  // Detect stale cache (chain was reset)
  if (cacheFile && existsSync(cacheFile)) {
    try {
      const cached = JSON.parse(await Bun.file(cacheFile).text());
      const cachedSyncHeight = cached.syncHeight || 0;
      if (cachedSyncHeight > currentHeight) {
        console.log(`  ${label}: Cache stale (cached=${cachedSyncHeight}, chain=${currentHeight}), resetting`);
      } else {
        storage.load(cached);
      }
    } catch { /* ignore bad cache */ }
  }

  const sync = createWalletSync({ daemon, keys, carrotKeys, storage, network: NETWORK });
  await sync.start();

  if (cacheFile) {
    await Bun.write(cacheFile, storage.dumpJSON());
  }

  const allOutputs = await storage.getOutputs({ isSpent: false });
  const spendable = allOutputs.filter(o => o.isSpendable(currentHeight));
  let balance = 0n, spendableBalance = 0n;
  for (const o of allOutputs) balance += o.amount;
  for (const o of spendable) spendableBalance += o.amount;

  const assetCounts = {};
  for (const o of spendable) {
    const a = o.assetType || 'SAL';
    assetCounts[a] = (assetCounts[a] || 0) + 1;
  }

  console.log(`  ${label}: ${allOutputs.length} outputs, ${spendable.length} spendable, balance=${fmt(balance)}, spendable=${fmt(spendableBalance)} ${JSON.stringify(assetCounts)}`);
  return { storage, balance, spendableBalance, spendable, allOutputs };
}

function logTx(type, from, to, amount, fee, txHash, height) {
  txLog.push({ type, from, to, amount: amount.toString(), fee: fee.toString(), txHash, height, time: Date.now() });
  totalFees += fee;
}

// =============================================================================
// Wallet Loading
// =============================================================================

/**
 * Convert a key value to hex string.
 * Handles: hex strings (passthrough), Uint8Array, and JSON-serialized
 * indexed objects like {"0": 175, "1": 212, ...} from JSON.stringify(Uint8Array).
 */
function toHex(val) {
  if (typeof val === 'string') return val;
  if (val instanceof Uint8Array) return bytesToHex(val);
  if (val && typeof val === 'object' && '0' in val) {
    // Indexed object from JSON.stringify(Uint8Array)
    const len = Object.keys(val).length;
    const arr = new Uint8Array(len);
    for (let i = 0; i < len; i++) arr[i] = val[i];
    return bytesToHex(arr);
  }
  return val;
}

function loadWalletKeys(data) {
  return {
    keys: {
      viewSecretKey: toHex(data.viewSecretKey),
      spendSecretKey: toHex(data.spendSecretKey),
      viewPublicKey: toHex(data.viewPublicKey),
      spendPublicKey: toHex(data.spendPublicKey),
    },
    carrotKeys: data.carrotKeys || null,
    address: data.address,
    carrotAddress: data.carrotAddress || null,
  };
}

async function loadOrCreateWalletB() {
  if (existsSync(WALLET_B_FILE)) {
    const data = JSON.parse(await Bun.file(WALLET_B_FILE).text());
    console.log(`  Wallet B loaded from ${WALLET_B_FILE}`);
    // Re-save if keys are in indexed-object format (from old Uint8Array serialization)
    if (data.spendPublicKey && typeof data.spendPublicKey !== 'string') {
      console.log(`  Wallet B: converting keys from indexed-object to hex format...`);
      data.spendPublicKey = toHex(data.spendPublicKey);
      data.viewPublicKey = toHex(data.viewPublicKey);
      data.spendSecretKey = toHex(data.spendSecretKey);
      data.viewSecretKey = toHex(data.viewSecretKey);
      if (data.seed) data.seed = toHex(data.seed);
      await Bun.write(WALLET_B_FILE, JSON.stringify(data, null, 2));
      console.log(`  Wallet B: re-saved with hex keys`);
    }
    return loadWalletKeys(data);
  }

  const wb = Wallet.create({ network: NETWORK });
  const data = {
    version: 3,
    type: 'full',
    network: NETWORK,
    spendPublicKey: toHex(wb.spendPublicKey),
    viewPublicKey: toHex(wb.viewPublicKey),
    address: wb.getAddress(),
    carrotAddress: wb.getCarrotAddress(),
    carrotKeys: wb.carrotKeys || null,
    spendSecretKey: toHex(wb.spendSecretKey),
    viewSecretKey: toHex(wb.viewSecretKey),
    seed: toHex(wb.seed),
  };
  await Bun.write(WALLET_B_FILE, JSON.stringify(data, null, 2));
  console.log(`  Wallet B CREATED and saved to ${WALLET_B_FILE}`);
  return loadWalletKeys(data);
}

// =============================================================================
// Transaction Wrappers
// =============================================================================

async function doTransfer(fromLabel, keys, storage, carrotKeys, toAddress, amount) {
  stats.transfers.attempted++;
  const h = await getHeight();
  try {
    const result = await transfer({
      wallet: { keys, storage, carrotKeys },
      daemon,
      destinations: [{ address: toAddress, amount }],
      options: { priority: 'default', network: NETWORK }
    });

    stats.transfers.succeeded++;
    logTx('transfer', fromLabel, toAddress.slice(0, 10), amount, result.fee, result.txHash, h);

    if (result.spentKeyImages) {
      for (const ki of result.spentKeyImages) await storage.markOutputSpent(ki);
    }
    return result;
  } catch (e) {
    stats.transfers.failed++;
    console.log(`    FAILED [${fromLabel}→${short(toAddress)}, ${fmt(amount)}]: ${e.message}`);
    return null;
  }
}

async function doStake(label, keys, storage, carrotKeys, amount) {
  stats.stakes.attempted++;
  const h = await getHeight();
  try {
    const result = await stake({
      wallet: { keys, storage, carrotKeys },
      daemon,
      amount,
      options: { priority: 'default', network: NETWORK }
    });
    stats.stakes.succeeded++;
    logTx('stake', label, 'protocol', amount, result.fee, result.txHash, h);
    totalStaked += amount;
    if (result.spentKeyImages) {
      for (const ki of result.spentKeyImages) await storage.markOutputSpent(ki);
    }
    return result;
  } catch (e) {
    stats.stakes.failed++;
    console.log(`    FAILED [stake ${fmt(amount)}]: ${e.message}`);
    return null;
  }
}

async function doBurn(label, keys, storage, carrotKeys, amount) {
  stats.burns.attempted++;
  const h = await getHeight();
  try {
    const result = await burn({
      wallet: { keys, storage, carrotKeys },
      daemon,
      amount,
      options: { priority: 'default', network: NETWORK }
    });
    stats.burns.succeeded++;
    logTx('burn', label, 'burned', amount, result.fee, result.txHash, h);
    totalBurned += amount;
    if (result.spentKeyImages) {
      for (const ki of result.spentKeyImages) await storage.markOutputSpent(ki);
    }
    return result;
  } catch (e) {
    stats.burns.failed++;
    console.log(`    FAILED [burn ${fmt(amount)}]: ${e.message}`);
    return null;
  }
}

async function doSweep(label, keys, storage, carrotKeys, toAddress) {
  stats.sweeps.attempted++;
  const h = await getHeight();
  try {
    const result = await sweep({
      wallet: { keys, storage, carrotKeys },
      daemon,
      address: toAddress,
      options: { priority: 'default', network: NETWORK }
    });
    stats.sweeps.succeeded++;
    logTx('sweep', label, toAddress.slice(0, 10), result.amount, result.fee, result.txHash, h);
    if (result.spentKeyImages) {
      for (const ki of result.spentKeyImages) await storage.markOutputSpent(ki);
    }
    return result;
  } catch (e) {
    stats.sweeps.failed++;
    console.log(`    FAILED [sweep ${label}]: ${e.message}`);
    return null;
  }
}

// =============================================================================
// Batch Helpers
// =============================================================================

/**
 * Send a batch of transfers, adaptive to available spendable outputs.
 * Returns number of successful transfers.
 */
async function batchTransfers(fromLabel, keys, storage, carrotKeys, toAddress, targetCount, minAmt, maxAmt) {
  console.log(`  Sending up to ${targetCount} transfers ${fromLabel} -> ${short(toAddress)}`);
  let success = 0;
  let consecutiveFails = 0;

  for (let i = 0; i < targetCount; i++) {
    const amount = BigInt(Math.floor(Math.random() * Number(maxAmt - minAmt)) + Number(minAmt));
    const result = await doTransfer(fromLabel, keys, storage, carrotKeys, toAddress, amount);

    if (result) {
      success++;
      consecutiveFails = 0;
      // Progress every 10
      if ((i + 1) % 10 === 0 || i === targetCount - 1) {
        console.log(`    ${i + 1}/${targetCount} sent (${success} ok, ${i + 1 - success} failed)`);
      }
    } else {
      consecutiveFails++;
      // If 5 consecutive failures, likely out of outputs — stop
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
 * Print a phase separator banner
 */
function banner(title) {
  console.log('\n' + '='.repeat(72));
  console.log(`  ${title}`);
  console.log('='.repeat(72));
}

/**
 * Print a section header
 */
function section(title) {
  console.log(`\n--- ${title} ---`);
}

/**
 * Save the TX log to disk
 */
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
// PHASE 1: CN ERA
// =============================================================================

async function phaseCN(walletA, walletB) {
  banner('PHASE 1: CN ERA (pre-CARROT, height < 1100)');

  const addrA = walletA.address;
  const addrB = walletB.address;
  console.log(`  A address: ${short(addrA)}`);
  console.log(`  B address: ${short(addrB)}`);

  // Wait for enough blocks for coinbase maturity (60) + ring size (16) + buffer
  // Coinbase outputs have unlock_time = height + 60, so decoys must be 60+ blocks old
  const COINBASE_MATURITY = 60;
  const MIN_HEIGHT_FOR_RING = COINBASE_MATURITY + DEFAULT_RING_SIZE + 5; // 81
  await waitForHeight(MIN_HEIGHT_FOR_RING, 'ring + coinbase maturity');

  // Sync wallet A
  const storageA = new MemoryStorage();
  let syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  if (syncA.spendableBalance === 0n) {
    console.log('  Waiting for more blocks (no spendable balance)...');
    await waitForHeight(MIN_HEIGHT_FOR_RING + 10, 'more coinbase');
    syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  }

  // ---- Round 1: A -> B transfers ----
  section(`CN Round 1: A -> B transfers (${syncA.spendable.length} outputs available)`);
  const count1 = Math.min(30, syncA.spendable.length);
  await batchTransfers('A', walletA.keys, storageA, walletA.carrotKeys, addrB,
    count1, 50_000_000n, 500_000_000n); // 0.5 - 5 SAL

  // Wait for confirms
  let h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'A->B confirms');

  // Sync both wallets
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  const storageB = new MemoryStorage();
  let syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  // ---- Round 2: B -> A transfers ----
  if (syncB.spendable.length > 0) {
    section(`CN Round 2: B -> A transfers (${syncB.spendable.length} outputs available)`);
    const count2 = Math.min(10, syncB.spendable.length);
    await batchTransfers('B', walletB.keys, storageB, walletB.carrotKeys, addrA,
      count2, 10_000_000n, 100_000_000n); // 0.1 - 1 SAL
  } else {
    section('CN Round 2: B -> A transfers');
    console.log('  SKIPPED: wallet B has no spendable outputs');
  }

  // Wait for B->A to settle, re-sync A
  h = await getHeight();
  await waitForHeight(h + 3, 'B->A settle');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  // ---- Round 3: Sub-SAL transfers (0.1 - 0.9 SAL) ----
  section(`CN Round 3: Sub-SAL transfers A -> B`);
  const microCount = Math.min(30, syncA.spendable.length);
  await batchTransfers('A', walletA.keys, storageA, walletA.carrotKeys, addrB,
    microCount, 10_000_000n, 90_000_000n); // 0.1 - 0.9 SAL

  // ---- Stakes ----
  section('CN Stakes');
  h = await getHeight();
  await waitForHeight(h + 3, 'pre-stake settle');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 5_00_000_000) + 1_00_000_000); // 1-6 SAL
    console.log(`  Stake ${i + 1}/3: ${fmt(amt)}`);
    await doStake('A', walletA.keys, storageA, walletA.carrotKeys, amt);
    // Wait 2 blocks between stakes to ensure each lands in a separate block
    // (daemon bug: multiple CARROT returns in same block fails validation)
    if (i < 2) {
      const sh = await getHeight();
      await waitForHeight(sh + 2, 'stake spacing');
    }
  }

  // ---- Burns ----
  section('CN Burns');
  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 1_00_000_000) + 10_000_000); // 0.1-1.1 SAL
    console.log(`  Burn ${i + 1}/3: ${fmt(amt)}`);
    await doBurn('A', walletA.keys, storageA, walletA.carrotKeys, amt);
  }

  // ---- Sweep B -> B ----
  section('CN Sweep B -> B');
  h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'pre-sweep confirms');
  syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);
  if (syncB.spendable.length > 0) {
    await doSweep('B', walletB.keys, storageB, walletB.carrotKeys, addrB);
  } else {
    console.log('  SKIPPED: no spendable outputs in B');
  }

  // ---- Round 4: Larger A -> B transfers ----
  section('CN Round 4: A -> B transfers (1-10 SAL)');
  h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'change maturity');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  const count4 = Math.min(20, syncA.spendable.length);
  await batchTransfers('A', walletA.keys, storageA, walletA.carrotKeys, addrB,
    count4, 100_000_000n, 1_000_000_000n); // 1 - 10 SAL

  // ---- Round 5: Many micro transfers to B (stress multi-input assembly) ----
  // B now has many small UTXOs from rounds 1-4. Send many sub-SAL amounts back to A.
  section('CN Round 5: Multi-input stress B -> A (many sub-SAL UTXOs)');
  h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'micro B maturity');
  syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);
  console.log(`  B has ${syncB.spendable.length} spendable outputs, balance=${fmt(syncB.spendableBalance)}`);

  if (syncB.spendable.length > 0) {
    // Send many small txs from B -> A using B's tiny UTXOs
    const bCount = Math.min(20, syncB.spendable.length);
    await batchTransfers('B', walletB.keys, storageB, walletB.carrotKeys, addrA,
      bCount, 5_000_000n, 50_000_000n); // 0.05 - 0.5 SAL
  } else {
    console.log('  SKIPPED: B has no spendable outputs');
  }

  // ---- CN Phase Accounting ----
  section('CN Phase Accounting');
  h = await getHeight();
  await waitForHeight(h + 3, 'accounting settle');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  console.log(`  Wallet A: ${fmt(syncA.balance)} (${syncA.allOutputs.length} outputs)`);
  console.log(`  Wallet B: ${fmt(syncB.balance)} (${syncB.allOutputs.length} outputs)`);
  console.log(`  Total fees: ${fmt(totalFees)}`);
  console.log(`  Total burned: ${fmt(totalBurned)}`);
  console.log(`  Total staked: ${fmt(totalStaked)}`);
  console.log(`  TX count: ${txLog.length}`);

  await saveTxLog();
  return { storageA, storageB };
}

// =============================================================================
// PHASE 2: CARROT ERA
// =============================================================================

async function phaseCARROT(walletA, walletB, storageA, storageB) {
  banner('PHASE 2: CARROT ERA (height >= 1100)');

  // Use CARROT addresses
  const addrA = walletA.carrotAddress || walletA.address;
  const addrB = walletB.carrotAddress || walletB.address;
  console.log(`  A CARROT: ${short(addrA)}`);
  console.log(`  B CARROT: ${short(addrB)}`);
  console.log(`  Waiting for CARROT fork + coinbase maturity...`);
  console.log(`  (Switch mining to wallet A CARROT address after height 1100)`);
  console.log(`  CARROT address: ${walletA.carrotAddress}`);

  await waitForHeight(CARROT_FORK_HEIGHT + SPENDABLE_AGE + 5, 'CARROT maturity');

  // Re-sync both wallets through the fork
  if (!storageA) storageA = new MemoryStorage();
  if (!storageB) storageB = new MemoryStorage();

  let syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  let syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  // ---- Round 1: A -> B CARROT transfers ----
  section(`CARROT Round 1: A -> B transfers (${syncA.spendable.length} outputs available)`);
  const count1 = Math.min(30, syncA.spendable.length);
  await batchTransfers('A', walletA.keys, storageA, walletA.carrotKeys, addrB,
    count1, 50_000_000n, 500_000_000n);

  // Wait for confirms
  let h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'CARROT A->B confirms');

  // Sync both
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  // ---- Round 2: B -> A CARROT transfers ----
  if (syncB.spendable.length > 0) {
    section(`CARROT Round 2: B -> A transfers (${syncB.spendable.length} outputs available)`);
    const count2 = Math.min(10, syncB.spendable.length);
    await batchTransfers('B', walletB.keys, storageB, walletB.carrotKeys, addrA,
      count2, 10_000_000n, 100_000_000n);
  } else {
    section('CARROT Round 2: B -> A transfers');
    console.log('  SKIPPED: wallet B has no spendable outputs');
  }

  // Wait, re-sync A
  h = await getHeight();
  await waitForHeight(h + 3, 'B->A settle');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  // ---- Round 3: CARROT micro transfers ----
  section('CARROT Round 3: Micro transfers A -> B');
  const microCount = Math.min(20, syncA.spendable.length);
  await batchTransfers('A', walletA.keys, storageA, walletA.carrotKeys, addrB,
    microCount, 1_000_000n, 10_000_000n);

  // ---- CARROT Stakes ----
  section('CARROT Stakes');
  h = await getHeight();
  await waitForHeight(h + 3, 'pre-stake settle');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 5_00_000_000) + 1_00_000_000);
    console.log(`  Stake ${i + 1}/3: ${fmt(amt)}`);
    await doStake('A', walletA.keys, storageA, walletA.carrotKeys, amt);
    // Wait 2 blocks between stakes to ensure each lands in a separate block
    // (daemon bug: multiple CARROT returns in same block fails validation)
    if (i < 2) {
      const sh = await getHeight();
      await waitForHeight(sh + 2, 'stake spacing');
    }
  }

  // ---- CARROT Burns ----
  section('CARROT Burns');
  for (let i = 0; i < 3; i++) {
    const amt = BigInt(Math.floor(Math.random() * 1_00_000_000) + 10_000_000);
    console.log(`  Burn ${i + 1}/3: ${fmt(amt)}`);
    await doBurn('A', walletA.keys, storageA, walletA.carrotKeys, amt);
  }

  // ---- CARROT Sweep B -> B ----
  section('CARROT Sweep B -> B');
  h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'pre-sweep confirms');
  syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);
  if (syncB.spendable.length > 0) {
    await doSweep('B', walletB.keys, storageB, walletB.carrotKeys, addrB);
  } else {
    console.log('  SKIPPED: no spendable outputs in B');
  }

  // ---- Round 4: More CARROT transfers with change ----
  section('CARROT Round 4: A -> B transfers (1-10 SAL)');
  h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'change maturity');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  const count4 = Math.min(20, syncA.spendable.length);
  await batchTransfers('A', walletA.keys, storageA, walletA.carrotKeys, addrB,
    count4, 100_000_000n, 1_000_000_000n);

  // ---- Round 5: Multi-input stress B -> A ----
  section('CARROT Round 5: Multi-input stress B -> A (many sub-SAL UTXOs)');
  h = await getHeight();
  await waitForHeight(h + SPENDABLE_AGE + 2, 'micro B maturity');
  syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);
  console.log(`  B has ${syncB.spendable.length} spendable outputs, balance=${fmt(syncB.spendableBalance)}`);

  if (syncB.spendable.length > 0) {
    const bCount = Math.min(20, syncB.spendable.length);
    await batchTransfers('B', walletB.keys, storageB, walletB.carrotKeys, addrA,
      bCount, 5_000_000n, 50_000_000n); // 0.05 - 0.5 SAL
  } else {
    console.log('  SKIPPED: B has no spendable outputs');
  }

  // ---- CARROT Phase Accounting ----
  section('CARROT Phase Accounting');
  h = await getHeight();
  await waitForHeight(h + 3, 'accounting settle');
  syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  console.log(`  Wallet A: ${fmt(syncA.balance)} (${syncA.allOutputs.length} outputs)`);
  console.log(`  Wallet B: ${fmt(syncB.balance)} (${syncB.allOutputs.length} outputs)`);
  console.log(`  Total fees: ${fmt(totalFees)}`);
  console.log(`  Total burned: ${fmt(totalBurned)}`);
  console.log(`  Total staked: ${fmt(totalStaked)}`);
  console.log(`  TX count: ${txLog.length}`);

  await saveTxLog();
  return { storageA, storageB };
}

// =============================================================================
// FINAL RECONCILIATION
// =============================================================================

async function reconcile(walletA, walletB, storageA, storageB) {
  banner('FINAL RECONCILIATION');

  // Wait a few blocks for everything to settle
  const h = await getHeight();
  await waitForHeight(h + 5, 'final settle');

  if (!storageA) storageA = new MemoryStorage();
  if (!storageB) storageB = new MemoryStorage();

  const syncA = await syncWallet('A (final)', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  const syncB = await syncWallet('B (final)', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

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

  console.log('\n  Transaction Summary');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Total transactions:  ${txLog.length}`);
  console.log(`  CN-era transfers:    ${cnTransfers}`);
  console.log(`  CARROT-era transfers: ${carrotTransfers}`);
  console.log(`  Transfers: ${stats.transfers.succeeded}/${stats.transfers.attempted} ok (${stats.transfers.failed} failed)`);
  console.log(`  Stakes:    ${stats.stakes.succeeded}/${stats.stakes.attempted} ok (${stats.stakes.failed} failed)`);
  console.log(`  Burns:     ${stats.burns.succeeded}/${stats.burns.attempted} ok (${stats.burns.failed} failed)`);
  console.log(`  Sweeps:    ${stats.sweeps.succeeded}/${stats.sweeps.attempted} ok (${stats.sweeps.failed} failed)`);

  console.log('\n  Balance Sheet');
  console.log('  ' + '-'.repeat(50));
  console.log(`  Wallet A balance:   ${fmt(syncA.balance)} (${syncA.allOutputs.length} outputs)`);
  console.log(`  Wallet B balance:   ${fmt(syncB.balance)} (${syncB.allOutputs.length} outputs)`);
  console.log(`  Total A -> B:       ${fmt(totalA2B)}`);
  console.log(`  Total B -> A:       ${fmt(totalB2A)}`);
  console.log(`  Total fees:         ${fmt(totalFees)}`);
  console.log(`  Total burned:       ${fmt(totalBurned)}`);
  console.log(`  Total staked:       ${fmt(totalStaked)}`);

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
    // List failures
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

  const h = await getHeight();
  console.log(`  Daemon:       ${DAEMON_URL}`);
  console.log(`  Network:      ${NETWORK}`);
  console.log(`  Height:       ${h}`);
  console.log(`  CARROT fork:  ${CARROT_FORK_HEIGHT}`);
  console.log();

  // Load wallets
  section('Loading Wallets');
  const walletAJson = JSON.parse(await Bun.file(WALLET_A_FILE).text());
  const walletA = loadWalletKeys(walletAJson);
  console.log(`  A CN addr:     ${short(walletA.address)}`);
  console.log(`  A CARROT addr: ${short(walletA.carrotAddress)}`);

  const walletB = await loadOrCreateWalletB();
  console.log(`  B CN addr:     ${short(walletB.address)}`);
  console.log(`  B CARROT addr: ${short(walletB.carrotAddress)}`);

  // Parse --phase argument
  const phaseArg = process.argv.find(a => a.startsWith('--phase='))?.split('=')[1]
    || (process.argv.includes('--phase') ? process.argv[process.argv.indexOf('--phase') + 1] : null)
    || 'all';

  console.log(`\n  Phase: ${phaseArg}`);

  let storageA, storageB;

  if (phaseArg === 'all' || phaseArg === 'cn') {
    const result = await phaseCN(walletA, walletB);
    storageA = result.storageA;
    storageB = result.storageB;
  }

  if (phaseArg === 'all' || phaseArg === 'carrot') {
    const result = await phaseCARROT(walletA, walletB, storageA, storageB);
    storageA = result.storageA;
    storageB = result.storageB;
  }

  await reconcile(walletA, walletB, storageA, storageB);

  console.log('\nBurn-in test complete.\n');
}

main().catch(e => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
