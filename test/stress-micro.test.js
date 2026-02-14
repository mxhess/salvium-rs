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
import { existsSync } from 'node:fs';
import { getHeight, waitForHeight, fmt, short, loadWalletFromFile } from './test-helpers.js';

await setCryptoBackend('wasm');

// =============================================================================
// Configuration
// =============================================================================

const DAEMON_URL = process.env.DAEMON_URL || 'http://node12.whiskymine.io:29081';
const NETWORK = 'testnet';
const SPENDABLE_AGE = 10;

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

  const { balance, unlockedBalance } = await wallet.getStorageBalance();
  console.log(`  ${label}: balance=${fmt(balance)}, spendable=${fmt(unlockedBalance)}`);
  return { balance, unlockedBalance };
}

// =============================================================================
// Phase 1: Send 1000 micro transfers A -> B
// =============================================================================

async function phaseSend(walletA, walletB) {
  const h = await getHeight(daemon);
  const addrB = walletB.getAddress();
  const era = walletA.isCarrotEnabled() ? 'CARROT' : 'CN';

  console.log(`\n${'='.repeat(72)}`);
  console.log(`  PHASE: SEND ${MICRO_COUNT} MICRO TRANSFERS A -> B (${era})`);
  console.log(`${'='.repeat(72)}`);
  console.log(`  Destination: ${short(addrB)}`);
  console.log(`  Amount range: 0.10 - 0.90 SAL each`);
  console.log(`  Expected total: ~${(MICRO_COUNT * 0.5).toFixed(0)} SAL\n`);

  await syncAndReport(walletA, 'A', SYNC_CACHE_A);

  let sent = 0, failed = 0, consecutiveFails = 0;
  let totalSent = 0n, totalFees = 0n;
  const batchSize = 50;

  for (let batch = 0; batch * batchSize < MICRO_COUNT; batch++) {
    const batchStart = batch * batchSize;
    const batchEnd = Math.min(batchStart + batchSize, MICRO_COUNT);

    if (batch > 0) {
      const bh = await getHeight(daemon);
      await waitForHeight(daemon, bh + SPENDABLE_AGE + 2, `batch ${batch + 1} maturity`);
      await syncAndReport(walletA, 'A', SYNC_CACHE_A);
    }

    for (let i = batchStart; i < batchEnd; i++) {
      const amount = BigInt(Math.floor(Math.random() * 80_000_000) + 10_000_000);

      try {
        const result = await walletA.transfer(
          [{ address: addrB, amount }],
          { priority: 'default' }
        );

        sent++;
        consecutiveFails = 0;
        totalSent += amount;
        totalFees += result.fee;

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
  const h = await getHeight(daemon);
  const addrA = walletA.getAddress();
  const addrB = walletB.getAddress();
  const era = walletA.isCarrotEnabled() ? 'CARROT' : 'CN';

  console.log(`\n${'='.repeat(72)}`);
  console.log(`  PHASE: SPEND B -> A (multi-input UTXO assembly, ${era})`);
  console.log(`${'='.repeat(72)}`);

  // Wait for all micro outputs to mature
  await waitForHeight(daemon, h + SPENDABLE_AGE + 2, 'micro output maturity');

  const syncB = await syncAndReport(walletB, 'B', SYNC_CACHE_B);
  console.log(`\n  B has spendable balance: ${fmt(syncB.unlockedBalance)}`);

  if (syncB.unlockedBalance === 0n) {
    console.log('  ERROR: B has no spendable outputs. Run --phase send first.');
    return { sent: 0, failed: 0 };
  }

  // Strategy: try progressively larger transfers to force multi-input assembly
  const testAmounts = [];
  for (let i = 0; i < 10; i++) testAmounts.push(100_000_000n);    // 10x 1 SAL
  for (let i = 0; i < 10; i++) testAmounts.push(200_000_000n);    // 10x 2 SAL
  for (let i = 0; i < 5; i++) testAmounts.push(500_000_000n);     // 5x 5 SAL
  for (let i = 0; i < 5; i++) testAmounts.push(1_000_000_000n);   // 5x 10 SAL
  for (let i = 0; i < 3; i++) testAmounts.push(2_000_000_000n);   // 3x 20 SAL
  for (let i = 0; i < 2; i++) testAmounts.push(5_000_000_000n);   // 2x 50 SAL

  console.log(`\n  Will attempt ${testAmounts.length} transfers of increasing size, then 1 sweep`);
  console.log(`  Amounts: 10x1 SAL, 10x2 SAL, 5x5 SAL, 5x10 SAL, 3x20 SAL, 2x50 SAL`);

  let sent = 0, failed = 0, totalSent = 0n, totalFees = 0n;
  let consecutiveFails = 0;

  for (let i = 0; i < testAmounts.length; i++) {
    const amount = testAmounts[i];

    // Check balance via storage
    const { unlockedBalance } = await walletB.getStorageBalance();
    if (unlockedBalance < amount + 50_000_000n) {
      console.log(`    Skipping ${fmt(amount)}: insufficient balance (${fmt(unlockedBalance)} available)`);
      continue;
    }

    try {
      const result = await walletB.transfer(
        [{ address: addrA, amount }],
        { priority: 'default' }
      );

      sent++;
      consecutiveFails = 0;
      totalSent += amount;
      totalFees += result.fee;

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
  const sweepH = await getHeight(daemon);
  await waitForHeight(daemon, sweepH + 3, 'pre-sweep settle');
  await syncAndReport(walletB, 'B (pre-sweep)', SYNC_CACHE_B);

  const { unlockedBalance: preSweepBal } = await walletB.getStorageBalance();
  if (preSweepBal > 0n) {
    try {
      const result = await walletB.sweep(addrB, { priority: 'default' });
      console.log(`  Sweep OK: fee=${fmt(result.fee)}`);
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
  const fh = await getHeight(daemon);
  await waitForHeight(daemon, fh + SPENDABLE_AGE + 2, 'final settle');
  await syncAndReport(walletA, 'A (final)', SYNC_CACHE_A);
  const finalB = await syncAndReport(walletB, 'B (final)', SYNC_CACHE_B);

  await Bun.write(LOG_FILE, JSON.stringify({
    phase: 'spend',
    timestamp: new Date().toISOString(),
    sent, failed,
    totalSent: totalSent.toString(),
    totalFees: totalFees.toString(),
    walletBBalance: finalB.balance.toString(),
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

  const h = await getHeight(daemon);
  const walletA = await loadWalletFromFile(WALLET_A_FILE, NETWORK);
  const walletB = await loadWalletFromFile(WALLET_B_FILE, NETWORK);
  walletA.setDaemon(daemon);
  walletB.setDaemon(daemon);

  // Set sync height for address selection
  walletA._syncHeight = h;
  walletB._syncHeight = h;

  console.log(`  Daemon:       ${DAEMON_URL}`);
  console.log(`  Network:      ${NETWORK}`);
  console.log(`  Height:       ${h}`);
  console.log(`  Phase:        ${PHASE}`);
  console.log(`  Micro count:  ${MICRO_COUNT}`);
  console.log(`  Era:          ${walletA.isCarrotEnabled() ? 'CARROT' : 'CN'}`);
  console.log(`  A addr: ${short(walletA.getAddress())}`);
  console.log(`  B addr: ${short(walletB.getAddress())}`);

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
