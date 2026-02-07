#!/usr/bin/env bun
/**
 * Micro-Transfer Stress Test
 *
 * Sends 1000 transfers of random 0.1-0.9 SAL from A to B,
 * then attempts large transfers back from B to A forcing
 * the wallet to assemble many small UTXO inputs.
 *
 * Usage:
 *   bun test/stress-micro.test.js [--count 1000] [--phase send|spend|all]
 *
 *   --count N    Number of micro transfers to send (default: 1000)
 *   --phase send   Only send A->B micro transfers
 *   --phase spend  Only spend B->A (assumes micro sends already done)
 *   --phase all    Both phases (default)
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer, sweep } from '../src/wallet/transfer.js';
import { bytesToHex } from '../src/address.js';
import { existsSync } from 'node:fs';

await setCryptoBackend('wasm');

// =============================================================================
// Configuration
// =============================================================================

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const NETWORK = 'testnet';
const SPENDABLE_AGE = 10;
const CARROT_FORK_HEIGHT = 1100;

const WALLET_A_FILE = process.env.WALLET_A || `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const WALLET_B_FILE = process.env.WALLET_B || `${process.env.HOME}/testnet-wallet/wallet-b.json`;
const SYNC_CACHE_A = WALLET_A_FILE.replace(/\.json$/, '-sync.json');
const SYNC_CACHE_B = WALLET_B_FILE.replace(/\.json$/, '-sync.json');
const LOG_FILE = `${process.env.HOME}/testnet-wallet/stress-micro-log.json`;

// Parse args
const args = process.argv.slice(2);
function getArg(name, def) {
  const idx = args.indexOf(`--${name}`);
  if (idx >= 0 && args[idx + 1]) return args[idx + 1];
  const eq = args.find(a => a.startsWith(`--${name}=`));
  if (eq) return eq.split('=')[1];
  return def;
}

const MICRO_COUNT = parseInt(getArg('count', '1000'), 10);
const PHASE = getArg('phase', 'all');

// =============================================================================
// Helpers
// =============================================================================

const daemon = new DaemonRPC({ url: DAEMON_URL });

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

function toHex(val) {
  if (typeof val === 'string') return val;
  if (val instanceof Uint8Array) return bytesToHex(val);
  if (val && typeof val === 'object' && '0' in val) {
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

async function syncWallet(label, keys, storage, cacheFile, carrotKeys) {
  const currentHeight = await getHeight();

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

// =============================================================================
// Phase 1: Send 1000 micro transfers A -> B
// =============================================================================

async function phaseSend(walletA, walletB) {
  const h = await getHeight();
  const useCarrot = h >= CARROT_FORK_HEIGHT;
  const addrB = useCarrot ? (walletB.carrotAddress || walletB.address) : walletB.address;
  const era = useCarrot ? 'CARROT' : 'CN';

  console.log(`\n${'='.repeat(72)}`);
  console.log(`  PHASE: SEND ${MICRO_COUNT} MICRO TRANSFERS A -> B (${era})`);
  console.log(`${'='.repeat(72)}`);
  console.log(`  Destination: ${short(addrB)}`);
  console.log(`  Amount range: 0.10 - 0.90 SAL each`);
  console.log(`  Expected total: ~${(MICRO_COUNT * 0.5).toFixed(0)} SAL\n`);

  const storageA = new MemoryStorage();
  let syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);

  let sent = 0, failed = 0, consecutiveFails = 0;
  let totalSent = 0n, totalFees = 0n;
  const batchSize = 50; // re-sync every 50 to pick up change outputs

  for (let batch = 0; batch * batchSize < MICRO_COUNT; batch++) {
    const batchStart = batch * batchSize;
    const batchEnd = Math.min(batchStart + batchSize, MICRO_COUNT);

    if (batch > 0) {
      // Wait for change outputs to mature
      const bh = await getHeight();
      await waitForHeight(bh + SPENDABLE_AGE + 2, `batch ${batch + 1} maturity`);
      syncA = await syncWallet('A', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
    }

    for (let i = batchStart; i < batchEnd; i++) {
      // Random 0.10 to 0.90 SAL
      const amount = BigInt(Math.floor(Math.random() * 80_000_000) + 10_000_000);

      try {
        const result = await transfer({
          wallet: { keys: walletA.keys, storage: storageA, carrotKeys: walletA.carrotKeys },
          daemon,
          destinations: [{ address: addrB, amount }],
          options: { priority: 'default', network: NETWORK }
        });

        sent++;
        consecutiveFails = 0;
        totalSent += amount;
        totalFees += result.fee;

        if (result.spentKeyImages) {
          for (const ki of result.spentKeyImages) await storageA.markOutputSpent(ki);
        }

        if ((sent + failed) % 10 === 0 || i === batchEnd - 1) {
          console.log(`    ${sent + failed}/${MICRO_COUNT} sent (${sent} ok, ${failed} failed) | total: ${fmt(totalSent)} | fees: ${fmt(totalFees)}`);
        }
      } catch (e) {
        failed++;
        consecutiveFails++;
        if ((sent + failed) % 10 === 0) {
          console.log(`    ${sent + failed}/${MICRO_COUNT} sent (${sent} ok, ${failed} failed) | last error: ${e.message.slice(0, 60)}`);
        }
        if (consecutiveFails >= 10) {
          console.log(`    Stopping batch after ${consecutiveFails} consecutive failures`);
          console.log(`    Last error: ${e.message}`);
          break;
        }
      }
    }

    if (consecutiveFails >= 10) break;
  }

  console.log(`\n  Send phase complete:`);
  console.log(`    Sent: ${sent}/${MICRO_COUNT}`);
  console.log(`    Failed: ${failed}`);
  console.log(`    Total transferred: ${fmt(totalSent)}`);
  console.log(`    Total fees: ${fmt(totalFees)}`);

  // Save progress
  await Bun.write(LOG_FILE, JSON.stringify({
    phase: 'send',
    timestamp: new Date().toISOString(),
    sent, failed,
    totalSent: totalSent.toString(),
    totalFees: totalFees.toString(),
    era,
  }, null, 2));

  return { sent, failed, totalSent, totalFees };
}

// =============================================================================
// Phase 2: Spend from B using many tiny UTXOs
// =============================================================================

async function phaseSpend(walletA, walletB) {
  const h = await getHeight();
  const useCarrot = h >= CARROT_FORK_HEIGHT;
  const addrA = useCarrot ? (walletA.carrotAddress || walletA.address) : walletA.address;
  const addrB = useCarrot ? (walletB.carrotAddress || walletB.address) : walletB.address;
  const era = useCarrot ? 'CARROT' : 'CN';

  console.log(`\n${'='.repeat(72)}`);
  console.log(`  PHASE: SPEND B -> A (multi-input UTXO assembly, ${era})`);
  console.log(`${'='.repeat(72)}`);

  // Wait for all micro outputs to mature
  await waitForHeight(h + SPENDABLE_AGE + 2, 'micro output maturity');

  const storageB = new MemoryStorage();
  let syncB = await syncWallet('B', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  console.log(`\n  B has ${syncB.spendable.length} spendable outputs totaling ${fmt(syncB.spendableBalance)}`);

  if (syncB.spendable.length === 0) {
    console.log('  ERROR: B has no spendable outputs. Run --phase send first.');
    return { sent: 0, failed: 0 };
  }

  // Strategy: try progressively larger transfers to force multi-input assembly
  // Start small (1 SAL), then increase to force combining many tiny UTXOs
  const testAmounts = [];

  // 10 transfers of 1 SAL (should need 2-10 inputs each)
  for (let i = 0; i < 10; i++) testAmounts.push(100_000_000n);

  // 10 transfers of 2 SAL (should need 4-20 inputs each)
  for (let i = 0; i < 10; i++) testAmounts.push(200_000_000n);

  // 5 transfers of 5 SAL (should need 10-50 inputs each)
  for (let i = 0; i < 5; i++) testAmounts.push(500_000_000n);

  // 5 transfers of 10 SAL (should need 20-100 inputs each)
  for (let i = 0; i < 5; i++) testAmounts.push(1_000_000_000n);

  // 3 transfers of 20 SAL (heavy multi-input)
  for (let i = 0; i < 3; i++) testAmounts.push(2_000_000_000n);

  // 2 transfers of 50 SAL
  for (let i = 0; i < 2; i++) testAmounts.push(5_000_000_000n);

  // 1 sweep to clean up everything
  console.log(`\n  Will attempt ${testAmounts.length} transfers of increasing size, then 1 sweep`);
  console.log(`  Amounts: 10x1 SAL, 10x2 SAL, 5x5 SAL, 5x10 SAL, 3x20 SAL, 2x50 SAL`);

  let sent = 0, failed = 0, totalSent = 0n, totalFees = 0n;
  let consecutiveFails = 0;

  for (let i = 0; i < testAmounts.length; i++) {
    const amount = testAmounts[i];

    // Check if we still have enough balance
    const currentOutputs = await storageB.getOutputs({ isSpent: false });
    const currentH = await getHeight();
    const currentSpendable = currentOutputs.filter(o => o.isSpendable(currentH));
    let currentBalance = 0n;
    for (const o of currentSpendable) currentBalance += o.amount;

    if (currentBalance < amount + 50_000_000n) { // need amount + ~fee buffer
      console.log(`    Skipping ${fmt(amount)}: insufficient balance (${fmt(currentBalance)} available)`);
      continue;
    }

    try {
      const result = await transfer({
        wallet: { keys: walletB.keys, storage: storageB, carrotKeys: walletB.carrotKeys },
        daemon,
        destinations: [{ address: addrA, amount }],
        options: { priority: 'default', network: NETWORK }
      });

      sent++;
      consecutiveFails = 0;
      totalSent += amount;
      totalFees += result.fee;

      if (result.spentKeyImages) {
        for (const ki of result.spentKeyImages) await storageB.markOutputSpent(ki);
      }

      console.log(`    [${sent + failed}/${testAmounts.length}] ${fmt(amount)} OK (${result.inputCount} inputs, fee=${fmt(result.fee)})`);
    } catch (e) {
      failed++;
      consecutiveFails++;
      console.log(`    [${sent + failed}/${testAmounts.length}] ${fmt(amount)} FAILED: ${e.message.slice(0, 80)}`);

      if (consecutiveFails >= 5) {
        console.log(`    Stopping after ${consecutiveFails} consecutive failures`);
        break;
      }
    }
  }

  // Final sweep B -> B to consolidate remaining UTXOs
  console.log(`\n  Attempting final sweep B -> B...`);
  const sweepH = await getHeight();
  await waitForHeight(sweepH + 3, 'pre-sweep settle');
  syncB = await syncWallet('B (pre-sweep)', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  if (syncB.spendable.length > 0) {
    try {
      const result = await sweep({
        wallet: { keys: walletB.keys, storage: storageB, carrotKeys: walletB.carrotKeys },
        daemon,
        address: addrB,
        options: { priority: 'default', network: NETWORK }
      });
      console.log(`  Sweep OK: consolidated ${syncB.spendable.length} outputs, fee=${fmt(result.fee)}`);
      totalFees += result.fee;
    } catch (e) {
      console.log(`  Sweep FAILED: ${e.message}`);
    }
  }

  console.log(`\n  Spend phase complete:`);
  console.log(`    Transfers: ${sent}/${testAmounts.length} succeeded (${failed} failed)`);
  console.log(`    Total transferred B->A: ${fmt(totalSent)}`);
  console.log(`    Total fees: ${fmt(totalFees)}`);

  // Final balances
  const fh = await getHeight();
  await waitForHeight(fh + SPENDABLE_AGE + 2, 'final settle');
  const storageA = new MemoryStorage();
  const syncA = await syncWallet('A (final)', walletA.keys, storageA, SYNC_CACHE_A, walletA.carrotKeys);
  syncB = await syncWallet('B (final)', walletB.keys, storageB, SYNC_CACHE_B, walletB.carrotKeys);

  // Save log
  await Bun.write(LOG_FILE, JSON.stringify({
    phase: 'spend',
    timestamp: new Date().toISOString(),
    sent, failed,
    totalSent: totalSent.toString(),
    totalFees: totalFees.toString(),
    walletABalance: syncA.balance.toString(),
    walletBBalance: syncB.balance.toString(),
  }, null, 2));

  return { sent, failed, totalSent, totalFees };
}

// =============================================================================
// MAIN
// =============================================================================

async function main() {
  console.log();
  console.log('+----------------------------------------------------------------------+');
  console.log('|         MICRO-TRANSFER STRESS TEST                                   |');
  console.log('+----------------------------------------------------------------------+');

  const h = await getHeight();
  console.log(`  Daemon:       ${DAEMON_URL}`);
  console.log(`  Network:      ${NETWORK}`);
  console.log(`  Height:       ${h}`);
  console.log(`  Phase:        ${PHASE}`);
  console.log(`  Micro count:  ${MICRO_COUNT}`);
  console.log(`  Era:          ${h >= CARROT_FORK_HEIGHT ? 'CARROT' : 'CN'}`);

  const walletA = loadWalletKeys(JSON.parse(await Bun.file(WALLET_A_FILE).text()));
  const walletB = loadWalletKeys(JSON.parse(await Bun.file(WALLET_B_FILE).text()));

  console.log(`  A addr: ${short(h >= CARROT_FORK_HEIGHT ? walletA.carrotAddress : walletA.address)}`);
  console.log(`  B addr: ${short(h >= CARROT_FORK_HEIGHT ? walletB.carrotAddress : walletB.address)}`);

  if (PHASE === 'all' || PHASE === 'send') {
    await phaseSend(walletA, walletB);
  }

  if (PHASE === 'all' || PHASE === 'spend') {
    await phaseSpend(walletA, walletB);
  }

  console.log('\nStress test complete.\n');
}

main().catch(e => {
  console.error('\nFATAL:', e);
  process.exit(1);
});
