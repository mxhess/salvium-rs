#!/usr/bin/env bun
/**
 * Integration Test: Transfer & Sweep
 *
 * Tests the full transaction lifecycle between two wallets.
 *
 * Env vars:
 *   DAEMON_URL    - RPC endpoint (default: http://web.whiskymine.io:29081)
 *   WALLET_FILE   - Path to wallet JSON (default: ~/testnet-wallet/wallet.json)
 *   NETWORK       - mainnet|testnet|stagenet (default: testnet)
 *   DRY_RUN       - 1 = build but don't broadcast (default: 1)
 *
 * Usage: bun test/integration-transfer.test.js
 *        DRY_RUN=0 bun test/integration-transfer.test.js
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { existsSync } from 'node:fs';
import { getHeight, waitForHeight, fmt, loadWalletFromFile } from './test-helpers.js';

await setCryptoBackend('wasm');

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const WALLET_FILE = process.env.WALLET_FILE || `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const NETWORK = process.env.NETWORK || 'testnet';
const DRY_RUN = process.env.DRY_RUN !== '0';
const SYNC_CACHE = process.env.SYNC_CACHE === '0' ? null
  : (process.env.SYNC_CACHE || WALLET_FILE.replace(/\.json$/, '-sync.json'));

async function syncAndReport(wallet, label, cacheFile = null) {
  // Load sync cache
  if (cacheFile && existsSync(cacheFile)) {
    try {
      const cached = JSON.parse(await Bun.file(cacheFile).text());
      const cachedHeight = cached.syncHeight || 0;
      wallet.loadSyncCache(cached);
      console.log(`Syncing ${label}... (resuming from block ${cachedHeight})`);
    } catch (e) {
      console.log(`Syncing ${label}... (cache unreadable, starting fresh)`);
    }
  } else {
    console.log(`Syncing ${label}...`);
  }

  const prevHeight = wallet.getSyncHeight();
  await wallet.syncWithDaemon();

  // Save sync state
  if (cacheFile) {
    await Bun.write(cacheFile, wallet.dumpSyncCacheJSON());
    const newHeight = wallet.getSyncHeight();
    if (newHeight > prevHeight) {
      console.log(`  Synced ${newHeight - prevHeight} new blocks (saved to ${cacheFile})`);
    }
  }

  const { balance, unlockedBalance } = await wallet.getStorageBalance();
  console.log(`  Balance: ${fmt(balance)} (${fmt(unlockedBalance)} spendable)`);
  return { balance, unlockedBalance };
}

async function testTransfer(wallet, toAddress, amount, label) {
  console.log(`\n--- ${label} ---`);
  console.log(`  Amount: ${Number(amount) / 1e8} SAL`);
  console.log(`  To: ${toAddress.slice(0, 30)}...`);

  try {
    const result = await wallet.transfer(
      [{ address: toAddress, amount }],
      { priority: 'default', dryRun: DRY_RUN }
    );

    console.log(`  TX Hash: ${result.txHash}`);
    console.log(`  Fee: ${Number(result.fee) / 1e8} SAL`);
    console.log(`  Inputs: ${result.inputCount}, Outputs: ${result.outputCount}`);
    console.log(`  Serialized: ${result.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);
    return result;
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    if (e.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
    return null;
  }
}

async function main() {
  console.log('=== Transfer Integration Test ===\n');
  console.log(`Daemon:  ${DAEMON_URL}`);
  console.log(`Network: ${NETWORK}`);
  console.log(`Dry run: ${DRY_RUN}\n`);

  const daemon = new DaemonRPC({ url: DAEMON_URL });

  const info = await daemon.getInfo();
  if (!info.success) throw new Error('Cannot reach daemon');
  const height = info.result?.height || info.data?.height;
  console.log(`Daemon height: ${height}\n`);

  // Load wallet A from file
  console.log(`Loading wallet A from ${WALLET_FILE}`);
  const walletA = await loadWalletFromFile(WALLET_FILE, NETWORK);
  walletA.setDaemon(daemon);
  console.log(`  Address: ${walletA.getLegacyAddress()}\n`);

  // Create wallet B in memory (ephemeral)
  const walletB = Wallet.create({ network: NETWORK });
  walletB.setDaemon(daemon);
  const addressB = walletB.getAddress();
  console.log(`Wallet B (ephemeral):`);
  console.log(`  Address: ${addressB}`);
  console.log(`  Address format: ${addressB.startsWith('SC1') ? 'CARROT' : 'legacy'}`);
  console.log(`  CARROT keys: ${walletB.carrotKeys ? 'yes' : 'no'}\n`);

  // Sync wallet A
  const syncA = await syncAndReport(walletA, 'Wallet A', SYNC_CACHE);

  if (syncA.unlockedBalance === 0n) {
    console.log('\nWallet A has no spendable balance. Mine more blocks.');
    return;
  }

  // Test 1: Transfer 100 SAL (A → B)
  const amount1 = 10_000_000_000n;
  const result1 = await testTransfer(walletA, addressB, amount1, 'Transfer: 100 SAL (A → B)');

  if (!result1) {
    console.log('\nFirst transfer failed, stopping.');
    return;
  }

  // Test 2: Many fractional transfers
  console.log('\n=== Many fractional transfers (A → B) ===');
  console.log('  (This tests input selection with many small UTXOs)');
  const numTransfers = 15;
  let successCount = 0;
  for (let i = 0; i < numTransfers; i++) {
    const amount = BigInt(Math.floor(Math.random() * 9_50_000_000 + 50_000_000));
    const result = await testTransfer(walletA, addressB, amount, `Fractional transfer ${i + 1}/${numTransfers}`);
    if (result) successCount++;

    if (i - successCount >= 3) {
      console.log(`  Too many failures (${i + 1 - successCount}), stopping early`);
      break;
    }
  }
  console.log(`\n${successCount}/${numTransfers} fractional transfers succeeded`);

  // Verify wallet B received the transfers
  console.log('\n=== Verify Wallet B Received Funds ===');

  if (!DRY_RUN) {
    console.log('  Waiting for transfers to be mined...');
    const startHeight = height;
    let currentH = startHeight;
    const maxWait = 120;
    const startTime = Date.now();
    while (currentH < startHeight + 2 && (Date.now() - startTime) < maxWait * 1000) {
      await new Promise(r => setTimeout(r, 5000));
      currentH = await getHeight(daemon);
      console.log(`  Height: ${currentH} (waiting for ${startHeight + 2})...`);
    }
    if (currentH >= startHeight + 2) {
      console.log(`  Blocks mined. Syncing wallet B.`);
    } else {
      console.log(`  Timeout waiting for blocks. Syncing wallet B anyway.`);
    }
  }

  const syncB = await syncAndReport(walletB, 'Wallet B');
  const expectedMin = DRY_RUN ? 0n : amount1;
  if (DRY_RUN) {
    console.log(`  (dry run — no transfers broadcast, balance expected to be 0)`);
    console.log(`  Balance: ${fmt(syncB.balance)}`);
  } else if (syncB.balance >= expectedMin) {
    console.log(`  Wallet B received funds: ${fmt(syncB.balance)}`);
  } else {
    console.log(`  Wallet B balance too low: ${fmt(syncB.balance)} (expected >= ${fmt(expectedMin)})`);
  }

  // Test 3: Stake 500 SAL
  console.log('\n=== Stake Test ===');
  const stakeAmt = 500_00_000_000n;
  console.log(`\n--- Stake: 500 SAL ---`);
  console.log(`  Lock period: 20 blocks (testnet)`);
  try {
    const stakeResult = await walletA.stake(stakeAmt, { priority: 'default', dryRun: DRY_RUN });
    console.log(`  TX Hash: ${stakeResult.txHash}`);
    console.log(`  Fee: ${Number(stakeResult.fee) / 1e8} SAL`);
    console.log(`  Staked: ${Number(stakeResult.stakeAmount) / 1e8} SAL`);
    console.log(`  Lock: ${stakeResult.lockPeriod} blocks`);
    console.log(`  Inputs: ${stakeResult.inputCount}, Outputs: ${stakeResult.outputCount}`);
    console.log(`  Serialized: ${stakeResult.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    if (e.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
  }

  // Test 4: Burn 1 SAL
  console.log('\n=== Burn Test ===');
  const burnAmt = 1_00_000_000n;
  console.log(`\n--- Burn: 1 SAL ---`);
  try {
    const burnResult = await walletA.burn(burnAmt, { priority: 'default', dryRun: DRY_RUN });
    console.log(`  TX Hash: ${burnResult.txHash}`);
    console.log(`  Fee: ${Number(burnResult.fee) / 1e8} SAL`);
    console.log(`  Burned: ${Number(burnResult.burnAmount) / 1e8} SAL`);
    console.log(`  Inputs: ${burnResult.inputCount}, Outputs: ${burnResult.outputCount}`);
    console.log(`  Serialized: ${burnResult.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    if (e.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
  }

  // Test 5: Sweep all remaining to self (wallet A)
  console.log('\n=== Sweep Test (A → A) ===');
  console.log('  (Recombines fractional UTXOs from previous transfers)');
  try {
    const sweepResult = await walletA.sweep(walletA.getAddress(), { priority: 'default', dryRun: DRY_RUN });
    console.log(`  TX Hash: ${sweepResult.txHash}`);
    console.log(`  Fee: ${Number(sweepResult.fee) / 1e8} SAL`);
    console.log(`  Amount: ${Number(sweepResult.amount) / 1e8} SAL`);
    console.log(`  Inputs: ${sweepResult.inputCount} (fractional UTXOs combined)`);
    console.log(`  Serialized: ${sweepResult.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    if (e.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
  }

  // Final summary
  console.log('\n=== Test Complete ===');
  console.log(`Summary:`);
  console.log(`  - Initial transfer (100 SAL): ${result1 ? 'OK' : 'FAILED'}`);
  console.log(`  - Fractional transfers: ${successCount}/${numTransfers} succeeded`);
  console.log(`  - Stake, Burn, Sweep: see above`);
  if (!DRY_RUN) {
    console.log(`  - Re-sync wallet B to verify it received all transfers`);
  }
}

main().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
