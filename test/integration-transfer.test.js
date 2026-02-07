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
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer, sweep, stake, burn, convert } from '../src/wallet/transfer.js';

import { existsSync } from 'node:fs';

// Initialize WASM backend for correct hash-to-point (matches C++ ge_fromfe_frombytes_vartime)
await setCryptoBackend('wasm');

const DAEMON_URL = process.env.DAEMON_URL || 'http://web.whiskymine.io:29081';
const WALLET_FILE = process.env.WALLET_FILE || `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const NETWORK = process.env.NETWORK || 'testnet';
const DRY_RUN = process.env.DRY_RUN !== '0';
// Optional sync cache — set to a file path to persist wallet sync state between runs.
// Set SYNC_CACHE=0 to disable. Default: alongside wallet file.
const SYNC_CACHE = process.env.SYNC_CACHE === '0' ? null
  : (process.env.SYNC_CACHE || WALLET_FILE.replace(/\.json$/, '-sync.json'));

let daemon;

async function syncWallet(label, keys, cacheFile = null, carrotKeys = null) {
  const storage = new MemoryStorage();

  // Try loading cached sync state
  let cachedHeight = 0;
  if (cacheFile && existsSync(cacheFile)) {
    try {
      const cached = JSON.parse(await Bun.file(cacheFile).text());
      storage.load(cached);
      cachedHeight = await storage.getSyncHeight();
      console.log(`Syncing ${label}... (resuming from block ${cachedHeight})`);
    } catch (e) {
      console.log(`Syncing ${label}... (cache unreadable, starting fresh)`);
    }
  } else {
    console.log(`Syncing ${label}...`);
  }

  const sync = createWalletSync({
    daemon,
    keys,
    carrotKeys,
    storage,
    network: NETWORK
  });

  await sync.start();

  // Save sync state for next run
  if (cacheFile) {
    await Bun.write(cacheFile, storage.dumpJSON());
    const newHeight = await storage.getSyncHeight();
    if (newHeight > cachedHeight) {
      console.log(`  Synced ${newHeight - cachedHeight} new blocks (saved to ${cacheFile})`);
    }
  }

  const infoResp = await daemon.getInfo();
  const currentHeight = infoResp.result?.height || infoResp.data?.height || 0;

  const allOutputs = await storage.getOutputs({ isSpent: false });
  const spendable = allOutputs.filter(o => o.isSpendable(currentHeight));
  let balance = 0n;
  for (const o of allOutputs) balance += o.amount;
  let spendableBalance = 0n;
  for (const o of spendable) spendableBalance += o.amount;

  // Detect dominant asset type
  const assetCounts = {};
  for (const o of spendable) {
    const a = o.assetType || 'SAL';
    assetCounts[a] = (assetCounts[a] || 0) + 1;
  }
  const detectedAsset = Object.entries(assetCounts).sort((a, b) => b[1] - a[1])[0]?.[0] || 'SAL';

  console.log(`  ${allOutputs.length} unspent (${spendable.length} spendable)`);
  console.log(`  Asset types: ${JSON.stringify(assetCounts)}`);
  console.log(`  Balance: ${Number(balance) / 1e8} ${detectedAsset} (${Number(spendableBalance) / 1e8} ${detectedAsset} spendable)`);

  return { sync, storage, balance, spendableBalance, outputs: allOutputs, spendable };
}

async function testTransfer(keys, storage, toAddress, amount, label, carrotKeys = null) {
  console.log(`\n--- ${label} ---`);
  console.log(`  Amount: ${Number(amount) / 1e8} SAL`);
  console.log(`  To: ${toAddress.slice(0, 30)}...`);

  try {
    const result = await transfer({
      wallet: { keys, storage, carrotKeys },
      daemon,
      destinations: [{ address: toAddress, amount }],
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
    });

    console.log(`  TX Hash: ${result.txHash}`);
    console.log(`  Fee: ${Number(result.fee) / 1e8} SAL`);
    console.log(`  Inputs: ${result.inputCount}, Outputs: ${result.outputCount}`);
    console.log(`  Serialized: ${result.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);

    // Mark spent outputs so subsequent transfers don't re-use them
    if (!DRY_RUN && result.spentKeyImages) {
      for (const keyImage of result.spentKeyImages) {
        await storage.markOutputSpent(keyImage);
      }
    }

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

  daemon = new DaemonRPC({ url: DAEMON_URL });

  const info = await daemon.getInfo();
  if (!info.success) throw new Error('Cannot reach daemon');
  const height = info.result?.height || info.data?.height;
  console.log(`Daemon height: ${height}\n`);

  // Load wallet A from file
  console.log(`Loading wallet A from ${WALLET_FILE}`);
  const walletAJson = JSON.parse(await Bun.file(WALLET_FILE).text());
  const keysA = {
    viewSecretKey: walletAJson.viewSecretKey,
    spendSecretKey: walletAJson.spendSecretKey,
    viewPublicKey: walletAJson.viewPublicKey,
    spendPublicKey: walletAJson.spendPublicKey,
  };
  const carrotKeysA = walletAJson.carrotKeys || null;
  console.log(`  Address: ${walletAJson.address}\n`);

  // Create wallet B in memory (not saved)
  const walletB = Wallet.create({ network: NETWORK });
  const keysB = {
    viewSecretKey: walletB.viewSecretKey,
    spendSecretKey: walletB.spendSecretKey,
    viewPublicKey: walletB.viewPublicKey,
    spendPublicKey: walletB.spendPublicKey,
  };
  const carrotKeysB = walletB.carrotKeys || null;
  // At CARROT heights, use CARROT address so outputs are created with CARROT keys
  // (K^0_v, K_s) for X25519 ECDH. Legacy addresses use CN keys which can't be scanned
  // by the CARROT scanner.
  const addressB = walletB.getCarrotAddress() || walletB.getAddress();
  console.log(`Wallet B (ephemeral):`);
  console.log(`  Address: ${addressB}`);
  console.log(`  Address format: ${addressB.startsWith('SC1') ? 'CARROT' : 'legacy'}`);
  console.log(`  CARROT keys: ${carrotKeysB ? 'yes' : 'no'}\n`);

  // Sync wallet A
  const syncA = await syncWallet('Wallet A', keysA, SYNC_CACHE, carrotKeysA);

  if (syncA.spendableBalance === 0n) {
    console.log('\nWallet A has no spendable balance. Mine more blocks.');
    return;
  }

  // Test 1: Transfer 100 SAL (A → B)
  const amount1 = 10_000_000_000n; // 100 SAL (1 SAL = 1e8 atomic)
  const result1 = await testTransfer(keysA, syncA.storage, addressB, amount1, 'Transfer: 100 SAL (A → B)', carrotKeysA);

  if (!result1) {
    console.log('\nFirst transfer failed, stopping.');
    return;
  }

  // Test 2: Many fractional transfers to test input selection and create many UTXOs
  console.log('\n=== Many fractional transfers (A → B) ===');
  console.log('  (This tests input selection with many small UTXOs)');
  const numTransfers = 15;
  let successCount = 0;
  for (let i = 0; i < numTransfers; i++) {
    // Random amounts between 0.5 and 10 SAL to create diverse UTXO sizes
    const amount = BigInt(Math.floor(Math.random() * 9_50_000_000 + 50_000_000)); // 0.5–10 SAL random
    const result = await testTransfer(keysA, syncA.storage, addressB, amount, `Fractional transfer ${i + 1}/${numTransfers}`, carrotKeysA);
    if (result) successCount++;

    // If we've had too many failures, stop early
    if (i - successCount >= 3) {
      console.log(`  Too many failures (${i + 1 - successCount}), stopping early`);
      break;
    }
  }
  console.log(`\n${successCount}/${numTransfers} fractional transfers succeeded`);

  // Verify wallet B received the transfers
  console.log('\n=== Verify Wallet B Received Funds ===');

  // Wait for transfers to be mined before syncing wallet B
  if (!DRY_RUN) {
    console.log('  Waiting for transfers to be mined...');
    const startHeight = height;
    let currentH = startHeight;
    const maxWait = 120; // seconds
    const startTime = Date.now();
    while (currentH < startHeight + 2 && (Date.now() - startTime) < maxWait * 1000) {
      await new Promise(r => setTimeout(r, 5000));
      const resp = await daemon.getInfo();
      currentH = resp.result?.height || resp.data?.height || currentH;
      console.log(`  Height: ${currentH} (waiting for ${startHeight + 2})...`);
    }
    if (currentH >= startHeight + 2) {
      console.log(`  Blocks mined. Syncing wallet B.`);
    } else {
      console.log(`  Timeout waiting for blocks. Syncing wallet B anyway.`);
    }
  }

  const syncB = await syncWallet('Wallet B', keysB, null, carrotKeysB);  // No cache for ephemeral wallet
  const expectedMin = DRY_RUN ? 0n : amount1; // In dry run, no transfers were broadcast
  if (DRY_RUN) {
    console.log(`  (dry run — no transfers broadcast, balance expected to be 0)`);
    console.log(`  Balance: ${Number(syncB.balance) / 1e8} SAL`);
  } else if (syncB.balance >= expectedMin) {
    console.log(`  ✓ Wallet B received funds: ${Number(syncB.balance) / 1e8} SAL`);
  } else {
    console.log(`  ✗ Wallet B balance too low: ${Number(syncB.balance) / 1e8} SAL (expected >= ${Number(expectedMin) / 1e8})`);
  }

  // Test 3: Stake 500 SAL
  console.log('\n=== Stake Test ===');
  const stakeAmt = 500_00_000_000n; // 500 SAL
  console.log(`\n--- Stake: 500 SAL ---`);
  console.log(`  Lock period: 20 blocks (testnet)`);
  try {
    const stakeResult = await stake({
      wallet: { keys: keysA, storage: syncA.storage, carrotKeys: carrotKeysA },
      daemon,
      amount: stakeAmt,
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
    });
    console.log(`  TX Hash: ${stakeResult.txHash}`);
    console.log(`  Fee: ${Number(stakeResult.fee) / 1e8} SAL`);
    console.log(`  Staked: ${Number(stakeResult.stakeAmount) / 1e8} SAL`);
    console.log(`  Lock: ${stakeResult.lockPeriod} blocks`);
    console.log(`  Inputs: ${stakeResult.inputCount}, Outputs: ${stakeResult.outputCount}`);
    console.log(`  Serialized: ${stakeResult.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);

    // Mark spent outputs so sweep doesn't re-use them
    if (!DRY_RUN && stakeResult.spentKeyImages) {
      for (const keyImage of stakeResult.spentKeyImages) {
        await syncA.storage.markOutputSpent(keyImage);
      }
    }
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    if (e.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
  }

  // Test 4: Burn 1 SAL
  console.log('\n=== Burn Test ===');
  const burnAmt = 1_00_000_000n; // 1 SAL
  console.log(`\n--- Burn: 1 SAL ---`);
  try {
    const burnResult = await burn({
      wallet: { keys: keysA, storage: syncA.storage, carrotKeys: carrotKeysA },
      daemon,
      amount: burnAmt,
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
    });
    console.log(`  TX Hash: ${burnResult.txHash}`);
    console.log(`  Fee: ${Number(burnResult.fee) / 1e8} SAL`);
    console.log(`  Burned: ${Number(burnResult.burnAmount) / 1e8} SAL`);
    console.log(`  Inputs: ${burnResult.inputCount}, Outputs: ${burnResult.outputCount}`);
    console.log(`  Serialized: ${burnResult.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);

    // Mark spent outputs
    if (!DRY_RUN && burnResult.spentKeyImages) {
      for (const keyImage of burnResult.spentKeyImages) {
        await syncA.storage.markOutputSpent(keyImage);
      }
    }
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    if (e.stack) console.error(e.stack.split('\n').slice(1, 4).join('\n'));
  }

  // Test 5: Convert (commented out - requires another asset type to exist on testnet)
  // console.log('\n=== Convert Test ===');
  // const convertAmt = 10_00_000_000n; // 10 SAL
  // console.log(`\n--- Convert: 10 SAL → OTHER_ASSET ---`);
  // try {
  //   const convertResult = await convert({
  //     wallet: { keys: keysA, storage: syncA.storage },
  //     daemon,
  //     amount: convertAmt,
  //     sourceAssetType: 'SAL',
  //     destAssetType: 'OTHER_ASSET',  // Replace with actual asset type
  //     destAddress: walletAJson.address,
  //     options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
  //   });
  //   console.log(`  TX Hash: ${convertResult.txHash}`);
  //   console.log(`  Fee: ${Number(convertResult.fee) / 1e8} SAL`);
  //   console.log(`  Converted: ${Number(convertResult.convertAmount) / 1e8} ${convertResult.sourceAssetType} → ${convertResult.destAssetType}`);
  //   console.log(`  ${DRY_RUN ? '(dry run — not broadcast)' : 'BROADCAST OK'}`);
  //
  //   if (!DRY_RUN && convertResult.spentKeyImages) {
  //     for (const keyImage of convertResult.spentKeyImages) {
  //       await syncA.storage.markOutputSpent(keyImage);
  //     }
  //   }
  // } catch (e) {
  //   console.error(`  FAILED: ${e.message}`);
  // }

  // Test 6: Sweep all remaining to self (wallet A) - recombines fractional UTXOs
  console.log('\n=== Sweep Test (A → A) ===');
  console.log('  (Recombines fractional UTXOs from previous transfers)');
  try {
    const sweepResult = await sweep({
      wallet: { keys: keysA, storage: syncA.storage, carrotKeys: carrotKeysA },
      daemon,
      address: walletAJson.address,
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
    });
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
