#!/usr/bin/env bun
/**
 * Salvium Test Harness
 *
 * Comprehensive automated testing across hard fork heights.
 *
 * Test Suite:
 *   1. Micro transfers (A→B) - creates many small UTXOs (20-50 transfers)
 *   2. Large multi-input transfer (B→A) - assembles many inputs into one TX
 *   3. Multiple large transfers from micro inputs (B→A) - stress test
 *   4. Same-wallet sweep (B→B) - consolidate all outputs
 *   5. Stake transaction - locks funds, returns via PROTOCOL tx after maturity
 *   6. Burn transaction - test burn functionality
 *   7. Bidirectional transfers - verify both directions work
 *
 * Hard Forks:
 *   - HF6 (height 815): SAL → SAL1 asset type
 *   - HF10 (height 1100): CARROT address format
 *
 * Usage:
 *   bun test/test-harness.js                    # Monitor mode
 *   bun test/test-harness.js --status           # Show status
 *   bun test/test-harness.js --run-all          # Run full test suite
 *   bun test/test-harness.js --micro            # Run micro transfers only
 *   bun test/test-harness.js --large            # Run large multi-input transfer
 *   bun test/test-harness.js --multi-large      # Multiple large transfers
 *   bun test/test-harness.js --sweep            # Run sweep only
 *   bun test/test-harness.js --stake            # Run stake test
 *   bun test/test-harness.js --burn             # Run burn test
 *   bun test/test-harness.js --bidir            # Run bidirectional test
 *   DRY_RUN=0 bun test/test-harness.js --run-all  # Live broadcast
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer, sweep, burn, stake } from '../src/wallet/transfer.js';
import { getHfVersionForHeight } from '../src/consensus.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';

await setCryptoBackend('wasm');

// Configuration
const CONFIG = {
  daemonUrl: process.env.DAEMON_URL || 'http://node12.whiskymine.io:29081',
  network: 'testnet',
  walletAPath: process.env.HOME + '/testnet-wallet/wallet-a.json',
  walletBPath: process.env.HOME + '/testnet-wallet/wallet-b-new.json',
  stateFile: process.env.HOME + '/testnet-wallet/test-harness-state.json',
  pollInterval: 30000,
  unlockBlocks: 60,
  hfMilestones: { 6: 815, 10: 1100 },
  tests: {
    // Micro transfer config
    microCount: parseInt(process.env.MICRO_COUNT || '30'),
    microAmounts: [0.09, 0.11, 0.15, 0.19, 0.22, 0.27, 0.33, 0.41, 0.48, 0.55,
                   0.61, 0.69, 0.74, 0.82, 0.88, 0.13, 0.17, 0.23, 0.29, 0.37],
    // Large transfer amounts
    largeAmount: 20_00000000n,  // 20 units
    multiLargeCount: 3,         // Number of large transfers in multi-large test
    multiLargeAmount: 10_00000000n, // 10 units each
    // Burn amount
    burnAmount: 1_00000000n,    // 1 unit
    // Stake amount
    stakeAmount: 10_00000000n,  // 10 units (minimum stake varies by HF)
    // Bidirectional
    bidirAmount: 2_00000000n    // 2 units
  }
};

const DRY_RUN = process.env.DRY_RUN !== '0';

// State
let state = {
  lastHeight: 0,
  lastHf: 0,
  testsRun: [],
  milestoneTests: {
    hf1: { micro: false, largeTx: false, multiLarge: false, sweep: false, stake: false, burn: false, bidir: false },
    hf6: { micro: false, largeTx: false, multiLarge: false, sweep: false, stake: false, burn: false, bidir: false },
    hf10: { micro: false, largeTx: false, multiLarge: false, sweep: false, stake: false, burn: false, bidir: false }
  },
  lastTestHeight: 0,
  errors: []
};

function loadState() {
  if (existsSync(CONFIG.stateFile)) {
    try { state = JSON.parse(readFileSync(CONFIG.stateFile, 'utf8')); } catch (e) {}
  }
}

function saveState() {
  writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2));
}

function log(msg, level = 'info') {
  const ts = new Date().toISOString().slice(11, 19);
  const prefix = { info: '   ', warn: '⚠  ', error: '✗  ', success: '✓  ' }[level] || '   ';
  console.log(`[${ts}] ${prefix}${msg}`);
}

const daemon = new DaemonRPC({ url: CONFIG.daemonUrl });

async function getChainInfo() {
  const info = await daemon.getInfo();
  const height = info.result?.height || info.data?.height;
  const hf = getHfVersionForHeight(height, 1);
  return { height, hf, assetType: hf >= 6 ? 'SAL1' : 'SAL', useCarrot: hf >= 10 };
}

function getHfKey(hf) {
  return hf >= 10 ? 'hf10' : hf >= 6 ? 'hf6' : 'hf1';
}

// Wallet helpers
async function loadWallet(path) {
  const wj = JSON.parse(readFileSync(path));
  const wallet = Wallet.fromJSON({ ...wj, network: CONFIG.network });
  return { wj, wallet };
}

async function syncWallet(wj, wallet, height, assetType) {
  // Determine which wallet this is by checking the spend public key
  const walletASpendKey = '8fb838fefda2e24b81ac623bd0b5c05b3e48d0d45953e9c7b89834d040593842';
  const isWalletA = wj.spendPublicKey === walletASpendKey;
  const walletPath = isWalletA ? CONFIG.walletAPath : CONFIG.walletBPath;
  const cache = walletPath.replace('.json', '-sync.json');

  const storage = new MemoryStorage();
  if (existsSync(cache)) {
    try { storage.load(JSON.parse(readFileSync(cache, 'utf8'))); } catch (e) {}
  }

  const sync = createWalletSync({
    daemon, keys: wj, storage, network: CONFIG.network, carrotKeys: wallet.carrotKeys
  });
  await sync.start();
  writeFileSync(cache, JSON.stringify(storage.dump()));

  const outputs = await storage.getOutputs({ isSpent: false });
  const unlocked = outputs.filter(o => o.blockHeight <= height - CONFIG.unlockBlocks && o.assetType === assetType);
  const locked = outputs.filter(o => o.blockHeight > height - CONFIG.unlockBlocks && o.assetType === assetType);
  const balance = unlocked.reduce((s, o) => s + BigInt(o.amount), 0n);

  return { storage, unlocked, locked, balance, cache };
}

// ============ TEST FUNCTIONS ============

/**
 * Test 1: Micro Transfers (A→B)
 * Creates many small UTXOs in wallet B for testing multi-input scenarios
 */
async function testMicroTransfers(chain) {
  log(`\n${'─'.repeat(50)}`);
  log(`TEST: Micro Transfers (${CONFIG.tests.microCount}x A→B)`);
  log(`${'─'.repeat(50)}`);

  const walletA = await loadWallet(CONFIG.walletAPath);
  const walletB = await loadWallet(CONFIG.walletBPath);
  const { storage: storageA, balance: balA } = await syncWallet(walletA.wj, walletA.wallet, chain.height, chain.assetType);

  const addrB = chain.useCarrot ? walletB.wallet.getCarrotAddress() : walletB.wallet.getLegacyAddress();
  const { assetType, useCarrot } = chain;

  const minRequired = BigInt(CONFIG.tests.microCount) * 1_00000000n; // ~1 per transfer + fees
  if (balA < minRequired) {
    log(`Insufficient balance: ${(Number(balA)/1e8).toFixed(2)} < ${Number(minRequired)/1e8} ${assetType}`, 'warn');
    return { success: false, count: 0, total: 0n };
  }

  let success = 0, failed = 0, totalSent = 0n;

  for (let i = 0; i < CONFIG.tests.microCount; i++) {
    const amt = BigInt(Math.floor(CONFIG.tests.microAmounts[i % CONFIG.tests.microAmounts.length] * 1e8));

    try {
      const result = await transfer({
        wallet: { keys: walletA.wj, storage: storageA },
        daemon,
        destinations: [{ address: addrB, amount: amt }],
        options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType, useCarrot }
      });

      if (!DRY_RUN) {
        for (const ki of result.spentKeyImages || []) await storageA.markOutputSpent(ki);
      }
      success++;
      totalSent += amt;
      log(`  [${i+1}/${CONFIG.tests.microCount}] ${(Number(amt)/1e8).toFixed(2)} ${assetType} → TX: ${result.txHash.slice(0,12)}...`, 'success');
    } catch (e) {
      failed++;
      log(`  [${i+1}/${CONFIG.tests.microCount}] ${(Number(amt)/1e8).toFixed(2)} ${assetType} FAILED: ${e.message.slice(0,40)}`, 'error');
    }
  }

  // Save cache
  const cache = CONFIG.walletAPath.replace('.json', '-sync.json');
  writeFileSync(cache, JSON.stringify(storageA.dump()));

  log(`\nMicro transfers: ${success}/${CONFIG.tests.microCount}, total: ${(Number(totalSent)/1e8).toFixed(2)} ${assetType}`);
  return { success: success > CONFIG.tests.microCount / 2, count: success, total: totalSent };
}

/**
 * Test 2: Large Multi-Input Transfer (B→A)
 * Uses many small inputs to create one large transfer
 */
async function testLargeMultiInput(chain) {
  log(`\n${'─'.repeat(50)}`);
  log(`TEST: Large Multi-Input Transfer (B→A, ${Number(CONFIG.tests.largeAmount)/1e8} ${chain.assetType})`);
  log(`${'─'.repeat(50)}`);

  const walletA = await loadWallet(CONFIG.walletAPath);
  const walletB = await loadWallet(CONFIG.walletBPath);
  const { storage: storageB, balance: balB, unlocked } = await syncWallet(walletB.wj, walletB.wallet, chain.height, chain.assetType);

  const addrA = chain.useCarrot ? walletA.wallet.getCarrotAddress() : walletA.wallet.getLegacyAddress();
  const { assetType, useCarrot } = chain;

  log(`  Wallet B: ${(Number(balB)/1e8).toFixed(2)} ${assetType} in ${unlocked.length} outputs`);

  const required = CONFIG.tests.largeAmount + 5_00000000n; // amount + fee buffer
  if (balB < required) {
    log(`Insufficient balance: need ${Number(required)/1e8} ${assetType}`, 'warn');
    return { success: false, inputs: 0 };
  }

  if (unlocked.length < 3) {
    log(`Need more outputs for multi-input test (have ${unlocked.length})`, 'warn');
    return { success: false, inputs: 0 };
  }

  try {
    const result = await transfer({
      wallet: { keys: walletB.wj, storage: storageB },
      daemon,
      destinations: [{ address: addrA, amount: CONFIG.tests.largeAmount }],
      options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType, useCarrot }
    });

    if (!DRY_RUN) {
      for (const ki of result.spentKeyImages || []) await storageB.markOutputSpent(ki);
      writeFileSync(CONFIG.walletBPath.replace('.json', '-sync.json'), JSON.stringify(storageB.dump()));
    }

    log(`  ${result.inputCount} inputs → ${result.outputCount} outputs`, 'success');
    log(`  TX: ${result.txHash}`, 'success');
    log(`  Fee: ${(Number(result.fee)/1e8).toFixed(4)} ${assetType}`, 'info');
    return { success: true, inputs: result.inputCount, txHash: result.txHash };
  } catch (e) {
    log(`  FAILED: ${e.message}`, 'error');
    return { success: false, inputs: 0, error: e.message };
  }
}

/**
 * Test 3: Multiple Large Transfers from Micro Inputs (B→A)
 * Stress tests input selection with consecutive large transfers
 */
async function testMultipleLargeTransfers(chain) {
  log(`\n${'─'.repeat(50)}`);
  log(`TEST: Multiple Large Transfers (${CONFIG.tests.multiLargeCount}x ${Number(CONFIG.tests.multiLargeAmount)/1e8} ${chain.assetType} B→A)`);
  log(`${'─'.repeat(50)}`);

  const walletA = await loadWallet(CONFIG.walletAPath);
  const walletB = await loadWallet(CONFIG.walletBPath);
  let { storage: storageB, balance: balB, unlocked } = await syncWallet(walletB.wj, walletB.wallet, chain.height, chain.assetType);

  const addrA = chain.useCarrot ? walletA.wallet.getCarrotAddress() : walletA.wallet.getLegacyAddress();
  const { assetType, useCarrot } = chain;

  log(`  Starting balance: ${(Number(balB)/1e8).toFixed(2)} ${assetType} in ${unlocked.length} outputs`);

  let success = 0, totalInputs = 0;

  for (let i = 0; i < CONFIG.tests.multiLargeCount; i++) {
    // Re-sync to get updated state
    const syncResult = await syncWallet(walletB.wj, walletB.wallet, chain.height, chain.assetType);
    storageB = syncResult.storage;
    const currentBal = syncResult.balance;

    const required = CONFIG.tests.multiLargeAmount + 3_00000000n;
    if (currentBal < required) {
      log(`  [${i+1}/${CONFIG.tests.multiLargeCount}] Skipped - insufficient balance`, 'warn');
      continue;
    }

    try {
      const result = await transfer({
        wallet: { keys: walletB.wj, storage: storageB },
        daemon,
        destinations: [{ address: addrA, amount: CONFIG.tests.multiLargeAmount }],
        options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType, useCarrot }
      });

      if (!DRY_RUN) {
        for (const ki of result.spentKeyImages || []) await storageB.markOutputSpent(ki);
        writeFileSync(CONFIG.walletBPath.replace('.json', '-sync.json'), JSON.stringify(storageB.dump()));
      }

      success++;
      totalInputs += result.inputCount;
      log(`  [${i+1}/${CONFIG.tests.multiLargeCount}] ${result.inputCount} inputs → TX: ${result.txHash.slice(0,16)}...`, 'success');
    } catch (e) {
      log(`  [${i+1}/${CONFIG.tests.multiLargeCount}] FAILED: ${e.message.slice(0,50)}`, 'error');
    }
  }

  log(`\nMultiple large: ${success}/${CONFIG.tests.multiLargeCount}, total inputs: ${totalInputs}`);
  return { success: success > 0, count: success, totalInputs };
}

/**
 * Test 4: Same-Wallet Sweep (B→B)
 * Consolidates all outputs in wallet B
 */
async function testSweep(chain) {
  log(`\n${'─'.repeat(50)}`);
  log(`TEST: Same-Wallet Sweep (B→B consolidation)`);
  log(`${'─'.repeat(50)}`);

  const walletB = await loadWallet(CONFIG.walletBPath);
  const { storage: storageB, balance: balB, unlocked } = await syncWallet(walletB.wj, walletB.wallet, chain.height, chain.assetType);

  const addrB = chain.useCarrot ? walletB.wallet.getCarrotAddress() : walletB.wallet.getLegacyAddress();
  const { assetType, useCarrot } = chain;

  log(`  Wallet B: ${(Number(balB)/1e8).toFixed(2)} ${assetType} in ${unlocked.length} outputs`);

  if (unlocked.length < 2) {
    log(`  Need at least 2 outputs for sweep (have ${unlocked.length})`, 'warn');
    return { success: false, inputs: 0 };
  }

  try {
    const result = await sweep({
      wallet: { keys: walletB.wj, storage: storageB },
      daemon,
      address: addrB,
      options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType, useCarrot }
    });

    if (!DRY_RUN) {
      for (const ki of result.spentKeyImages || []) await storageB.markOutputSpent(ki);
      writeFileSync(CONFIG.walletBPath.replace('.json', '-sync.json'), JSON.stringify(storageB.dump()));
    }

    const swept = result.amount || result.sweepAmount || 0n;
    log(`  Swept ${result.inputCount} inputs → ${result.outputCount} outputs`, 'success');
    log(`  Amount: ${(Number(swept)/1e8).toFixed(4)} ${assetType}`, 'success');
    log(`  TX: ${result.txHash}`, 'success');
    log(`  Size: ${result.serializedHex.length / 2} bytes`, 'info');
    return { success: true, inputs: result.inputCount, amount: swept, txHash: result.txHash };
  } catch (e) {
    log(`  FAILED: ${e.message}`, 'error');
    return { success: false, inputs: 0, error: e.message };
  }
}

/**
 * Test 5: Burn Transaction
 * Burns a small amount
 */
async function testBurn(chain) {
  log(`\n${'─'.repeat(50)}`);
  log(`TEST: Burn Transaction (${Number(CONFIG.tests.burnAmount)/1e8} ${chain.assetType})`);
  log(`${'─'.repeat(50)}`);

  const walletA = await loadWallet(CONFIG.walletAPath);
  const { storage: storageA, balance: balA } = await syncWallet(walletA.wj, walletA.wallet, chain.height, chain.assetType);
  const { assetType } = chain;

  log(`  Wallet A: ${(Number(balA)/1e8).toFixed(2)} ${assetType}`);

  const required = CONFIG.tests.burnAmount + 1_00000000n;
  if (balA < required) {
    log(`  Insufficient balance for burn`, 'warn');
    return { success: false };
  }

  try {
    const result = await burn({
      wallet: { keys: walletA.wj, storage: storageA },
      daemon,
      amount: CONFIG.tests.burnAmount,
      options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType }
    });

    if (!DRY_RUN) {
      for (const ki of result.spentKeyImages || []) await storageA.markOutputSpent(ki);
      writeFileSync(CONFIG.walletAPath.replace('.json', '-sync.json'), JSON.stringify(storageA.dump()));
    }

    log(`  Burned ${(Number(CONFIG.tests.burnAmount)/1e8).toFixed(4)} ${assetType}`, 'success');
    log(`  TX: ${result.txHash}`, 'success');
    return { success: true, txHash: result.txHash };
  } catch (e) {
    log(`  FAILED: ${e.message}`, 'error');
    return { success: false, error: e.message };
  }
}

/**
 * Test 6: Stake Transaction
 * Stakes funds (locked until maturity, returns via PROTOCOL tx)
 */
async function testStake(chain) {
  log(`\n${'─'.repeat(50)}`);
  log(`TEST: Stake Transaction (${Number(CONFIG.tests.stakeAmount)/1e8} ${chain.assetType})`);
  log(`${'─'.repeat(50)}`);

  const walletA = await loadWallet(CONFIG.walletAPath);
  const { storage: storageA, balance: balA } = await syncWallet(walletA.wj, walletA.wallet, chain.height, chain.assetType);
  const { assetType } = chain;

  log(`  Wallet A: ${(Number(balA)/1e8).toFixed(2)} ${assetType}`);

  const required = CONFIG.tests.stakeAmount + 2_00000000n; // stake + fee buffer
  if (balA < required) {
    log(`  Insufficient balance for stake (need ${Number(required)/1e8})`, 'warn');
    return { success: false };
  }

  try {
    const result = await stake({
      wallet: { keys: walletA.wj, storage: storageA },
      daemon,
      amount: CONFIG.tests.stakeAmount,
      options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType }
    });

    if (!DRY_RUN) {
      for (const ki of result.spentKeyImages || []) await storageA.markOutputSpent(ki);
      writeFileSync(CONFIG.walletAPath.replace('.json', '-sync.json'), JSON.stringify(storageA.dump()));
    }

    log(`  Staked ${(Number(CONFIG.tests.stakeAmount)/1e8).toFixed(2)} ${assetType}`, 'success');
    log(`  Lock period: ${result.lockPeriod} blocks`, 'info');
    log(`  TX: ${result.txHash}`, 'success');
    log(`  Note: Returns via PROTOCOL tx after ${result.lockPeriod} blocks`, 'info');
    return { success: true, txHash: result.txHash, lockPeriod: result.lockPeriod };
  } catch (e) {
    log(`  FAILED: ${e.message}`, 'error');
    return { success: false, error: e.message };
  }
}

/**
 * Test 7: Bidirectional Transfers
 * Tests both A→B and B→A
 */
async function testBidirectional(chain) {
  log(`\n${'─'.repeat(50)}`);
  log(`TEST: Bidirectional Transfers (A↔B)`);
  log(`${'─'.repeat(50)}`);

  const walletA = await loadWallet(CONFIG.walletAPath);
  const walletB = await loadWallet(CONFIG.walletBPath);
  const { storage: storageA, balance: balA } = await syncWallet(walletA.wj, walletA.wallet, chain.height, chain.assetType);
  const { storage: storageB, balance: balB } = await syncWallet(walletB.wj, walletB.wallet, chain.height, chain.assetType);

  const addrA = chain.useCarrot ? walletA.wallet.getCarrotAddress() : walletA.wallet.getLegacyAddress();
  const addrB = chain.useCarrot ? walletB.wallet.getCarrotAddress() : walletB.wallet.getLegacyAddress();
  const { assetType, useCarrot } = chain;
  const amount = CONFIG.tests.bidirAmount;

  log(`  Wallet A: ${(Number(balA)/1e8).toFixed(2)} ${assetType}`);
  log(`  Wallet B: ${(Number(balB)/1e8).toFixed(2)} ${assetType}`);

  let successAB = false, successBA = false;

  // A → B
  if (balA >= amount + 1_00000000n) {
    try {
      const result = await transfer({
        wallet: { keys: walletA.wj, storage: storageA },
        daemon,
        destinations: [{ address: addrB, amount }],
        options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType, useCarrot }
      });
      if (!DRY_RUN) {
        for (const ki of result.spentKeyImages || []) await storageA.markOutputSpent(ki);
      }
      log(`  A→B: ${(Number(amount)/1e8).toFixed(2)} ${assetType} → TX: ${result.txHash.slice(0,16)}...`, 'success');
      successAB = true;
    } catch (e) {
      log(`  A→B FAILED: ${e.message}`, 'error');
    }
  } else {
    log(`  A→B skipped: insufficient balance`, 'warn');
  }

  // B → A
  if (balB >= amount + 1_00000000n) {
    try {
      const result = await transfer({
        wallet: { keys: walletB.wj, storage: storageB },
        daemon,
        destinations: [{ address: addrA, amount }],
        options: { priority: 'default', network: CONFIG.network, dryRun: DRY_RUN, assetType, useCarrot }
      });
      if (!DRY_RUN) {
        for (const ki of result.spentKeyImages || []) await storageB.markOutputSpent(ki);
      }
      log(`  B→A: ${(Number(amount)/1e8).toFixed(2)} ${assetType} → TX: ${result.txHash.slice(0,16)}...`, 'success');
      successBA = true;
    } catch (e) {
      log(`  B→A FAILED: ${e.message}`, 'error');
    }
  } else {
    log(`  B→A skipped: insufficient balance`, 'warn');
  }

  // Save caches
  writeFileSync(CONFIG.walletAPath.replace('.json', '-sync.json'), JSON.stringify(storageA.dump()));
  writeFileSync(CONFIG.walletBPath.replace('.json', '-sync.json'), JSON.stringify(storageB.dump()));

  return { success: successAB && successBA, ab: successAB, ba: successBA };
}

// ============ FULL TEST SUITE ============

async function runFullTestSuite(chain, options = {}) {
  const { skipMicro = false, skipLarge = false, skipMultiLarge = false, skipSweep = false, skipStake = false, skipBurn = false, skipBidir = false } = options;

  log(`\n${'═'.repeat(50)}`);
  log(`FULL TEST SUITE - HF${chain.hf} (${chain.assetType}, ${chain.useCarrot ? 'CARROT' : 'CN'})`);
  log(`Height: ${chain.height} | Dry Run: ${DRY_RUN}`);
  log(`${'═'.repeat(50)}`);

  const hfKey = getHfKey(chain.hf);
  const results = {};

  // 1. Micro transfers
  if (!skipMicro) {
    results.micro = await testMicroTransfers(chain);
    state.milestoneTests[hfKey].micro = results.micro.success;
    saveState();
  }

  // 2. Large multi-input
  if (!skipLarge) {
    results.largeTx = await testLargeMultiInput(chain);
    state.milestoneTests[hfKey].largeTx = results.largeTx.success;
    saveState();
  }

  // 3. Multiple large transfers
  if (!skipMultiLarge) {
    results.multiLarge = await testMultipleLargeTransfers(chain);
    state.milestoneTests[hfKey].multiLarge = results.multiLarge.success;
    saveState();
  }

  // 4. Sweep
  if (!skipSweep) {
    results.sweep = await testSweep(chain);
    state.milestoneTests[hfKey].sweep = results.sweep.success;
    saveState();
  }

  // 5. Stake
  if (!skipStake) {
    results.stake = await testStake(chain);
    state.milestoneTests[hfKey].stake = results.stake.success;
    saveState();
  }

  // 6. Burn
  if (!skipBurn) {
    results.burn = await testBurn(chain);
    state.milestoneTests[hfKey].burn = results.burn.success;
    saveState();
  }

  // 7. Bidirectional
  if (!skipBidir) {
    results.bidir = await testBidirectional(chain);
    state.milestoneTests[hfKey].bidir = results.bidir.success;
    saveState();
  }

  // Summary
  log(`\n${'═'.repeat(50)}`);
  log(`TEST SUITE SUMMARY - HF${chain.hf}`);
  log(`${'═'.repeat(50)}`);
  log(`Micro transfers:    ${results.micro?.success ? '✓' : '✗'} (${results.micro?.count || 0} txs)`);
  log(`Large multi-input:  ${results.largeTx?.success ? '✓' : '✗'} (${results.largeTx?.inputs || 0} inputs)`);
  log(`Multiple large:     ${results.multiLarge?.success ? '✓' : '✗'} (${results.multiLarge?.count || 0}/${CONFIG.tests.multiLargeCount})`);
  log(`Sweep:              ${results.sweep?.success ? '✓' : '✗'} (${results.sweep?.inputs || 0} consolidated)`);
  log(`Stake:              ${results.stake?.success ? '✓' : '✗'}${results.stake?.lockPeriod ? ` (lock: ${results.stake.lockPeriod} blocks)` : ''}`);
  log(`Burn:               ${results.burn?.success ? '✓' : '✗'}`);
  log(`Bidirectional:      ${results.bidir?.success ? '✓' : '✗'} (A→B:${results.bidir?.ab?'✓':'✗'} B→A:${results.bidir?.ba?'✓':'✗'})`);

  state.testsRun.push({
    timestamp: new Date().toISOString(),
    height: chain.height,
    hf: chain.hf,
    assetType: chain.assetType,
    results
  });
  state.lastTestHeight = chain.height;
  saveState();

  return results;
}

// ============ STATUS ============

async function showStatus() {
  const chain = await getChainInfo();

  console.log('\n' + '═'.repeat(50));
  console.log('SALVIUM TEST HARNESS STATUS');
  console.log('═'.repeat(50));
  console.log(`\nBlockchain:`);
  console.log(`  Height:     ${chain.height}`);
  console.log(`  Hard Fork:  ${chain.hf}`);
  console.log(`  Asset:      ${chain.assetType}`);
  console.log(`  Format:     ${chain.useCarrot ? 'CARROT' : 'CryptoNote'}`);
  console.log(`  Mode:       ${DRY_RUN ? 'DRY RUN' : 'LIVE BROADCAST'}`);

  console.log(`\nUpcoming Milestones:`);
  if (chain.height < CONFIG.hfMilestones[6]) {
    console.log(`  HF6 (SAL1):    Height ${CONFIG.hfMilestones[6]} (${CONFIG.hfMilestones[6] - chain.height} blocks)`);
  } else {
    console.log(`  HF6 (SAL1):    ✓ Active`);
  }
  if (chain.height < CONFIG.hfMilestones[10]) {
    console.log(`  HF10 (CARROT): Height ${CONFIG.hfMilestones[10]} (${CONFIG.hfMilestones[10] - chain.height} blocks)`);
  } else {
    console.log(`  HF10 (CARROT): ✓ Active`);
  }

  console.log(`\nTest Status by HF:`);
  for (const [hf, tests] of Object.entries(state.milestoneTests)) {
    const keys = ['micro', 'largeTx', 'multiLarge', 'sweep', 'stake', 'burn', 'bidir'];
    const passed = keys.filter(k => tests[k]).length;
    const marks = keys.map(k => tests[k] ? '✓' : '✗').join(' ');
    console.log(`  ${hf.toUpperCase().padEnd(4)}: ${passed}/7 [${marks}]`);
    console.log(`        (micro | large | multi | sweep | stake | burn | bidir)`);
  }

  console.log(`\nTest History: ${state.testsRun.length} runs`);
  if (state.testsRun.length > 0) {
    const last = state.testsRun[state.testsRun.length - 1];
    console.log(`  Last: ${last.timestamp.slice(0,19)} at height ${last.height} (HF${last.hf})`);
  }
  console.log('');
}

// ============ POLL LOOP ============

async function pollLoop() {
  log('Starting test harness monitor...');
  log(`Mode: ${DRY_RUN ? 'DRY RUN' : 'LIVE BROADCAST'}`);
  log(`Poll interval: ${CONFIG.pollInterval/1000}s\n`);

  while (true) {
    try {
      const chain = await getChainInfo();
      const hfKey = getHfKey(chain.hf);
      const allComplete = Object.values(state.milestoneTests[hfKey]).every(v => v);

      if (chain.hf !== state.lastHf) {
        log(`\n*** HARD FORK TRANSITION: HF${state.lastHf} → HF${chain.hf} ***`, 'warn');
        state.lastHf = chain.hf;
        saveState();
      }

      if (!allComplete && chain.height - state.lastTestHeight >= CONFIG.unlockBlocks) {
        log(`Tests pending for ${hfKey.toUpperCase()}, running suite...`, 'info');
        await runFullTestSuite(chain);
      } else {
        const status = allComplete ? 'complete' : `${CONFIG.unlockBlocks - (chain.height - state.lastTestHeight)} blocks until next test`;
        log(`Height: ${chain.height} | HF${chain.hf} | ${chain.assetType} | ${status}`);
      }

      state.lastHeight = chain.height;
      saveState();
    } catch (e) {
      log(`Error: ${e.message}`, 'error');
      state.errors.push({ timestamp: new Date().toISOString(), error: e.message });
      saveState();
    }

    await new Promise(r => setTimeout(r, CONFIG.pollInterval));
  }
}

// ============ MAIN ============

async function main() {
  loadState();
  const args = process.argv.slice(2);
  const chain = await getChainInfo();

  if (args.includes('--status')) {
    await showStatus();
  } else if (args.includes('--run-all')) {
    await runFullTestSuite(chain);
  } else if (args.includes('--micro')) {
    await testMicroTransfers(chain);
  } else if (args.includes('--large')) {
    await testLargeMultiInput(chain);
  } else if (args.includes('--multi-large')) {
    await testMultipleLargeTransfers(chain);
  } else if (args.includes('--sweep')) {
    await testSweep(chain);
  } else if (args.includes('--stake')) {
    await testStake(chain);
  } else if (args.includes('--burn')) {
    await testBurn(chain);
  } else if (args.includes('--bidir')) {
    await testBidirectional(chain);
  } else {
    await showStatus();
    console.log('Starting monitor mode... (Ctrl+C to stop)\n');
    await pollLoop();
  }
}

main().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
