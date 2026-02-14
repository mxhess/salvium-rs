#!/usr/bin/env bun
/**
 * Integration Test: Subaddresses, Integrated Addresses & Multi-Wallet Transfers
 *
 * Comprehensive testing of:
 *   - Subaddress generation and detection
 *   - Integrated addresses with payment IDs
 *   - Transfers between main addresses, subaddresses, and integrated addresses
 *   - Multi-wallet bidirectional transfers
 *   - Hundreds of fractional transfers to stress test input selection
 *   - Edge cases (dust, exact amounts, many inputs)
 *
 * Env vars:
 *   DAEMON_URL     - RPC endpoint (default: http://node12.whiskymine.io:29081)
 *   WALLET_FILE    - Path to wallet A JSON (default: ~/testnet-wallet/wallet.json)
 *   WALLET_B_FILE  - Path to wallet B JSON (created if missing)
 *   NETWORK        - mainnet|testnet|stagenet (default: testnet)
 *   DRY_RUN        - 1 = build but don't broadcast (default: 1)
 *   NUM_FRACTIONAL - Number of fractional transfers each direction (default: 50)
 *
 * Usage:
 *   bun test/integration-subaddress.test.js
 *   DRY_RUN=0 NUM_FRACTIONAL=100 bun test/integration-subaddress.test.js
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { createWalletSync } from '../src/wallet-sync.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { transfer, sweep } from '../src/wallet/transfer.js';
import { parseAddress, toIntegratedAddress, isSubaddress, isIntegrated, getPaymentId } from '../src/address.js';
import { generatePaymentId } from '../src/subaddress.js';
import { bytesToHex } from '../src/address.js';

import { existsSync, writeFileSync, readFileSync } from 'node:fs';

// Initialize WASM backend
await setCryptoBackend('wasm');

const DAEMON_URL = process.env.DAEMON_URL || 'http://node12.whiskymine.io:29081';
const WALLET_FILE = process.env.WALLET_FILE || `${process.env.HOME}/testnet-wallet/wallet.json`;
const WALLET_B_FILE = process.env.WALLET_B_FILE || `${process.env.HOME}/testnet-wallet/wallet-b.json`;
const NETWORK = process.env.NETWORK || 'testnet';
const DRY_RUN = process.env.DRY_RUN !== '0';
const NUM_FRACTIONAL = parseInt(process.env.NUM_FRACTIONAL || '50', 10);

const SYNC_CACHE_A = WALLET_FILE.replace(/\.json$/, '-sync.json');
const SYNC_CACHE_B = WALLET_B_FILE.replace(/\.json$/, '-sync.json');

let daemon;
let testResults = {
  passed: 0,
  failed: 0,
  skipped: 0,
  tests: []
};

function logTest(name, passed, details = '') {
  const status = passed ? '✓' : '✗';
  console.log(`  ${status} ${name}${details ? ': ' + details : ''}`);
  testResults.tests.push({ name, passed, details });
  if (passed) testResults.passed++;
  else testResults.failed++;
}

function logSkip(name, reason) {
  console.log(`  ○ ${name}: SKIPPED (${reason})`);
  testResults.tests.push({ name, passed: null, details: reason });
  testResults.skipped++;
}

async function loadOrCreateWallet(filePath, label) {
  if (existsSync(filePath)) {
    console.log(`Loading ${label} from ${filePath}`);
    const json = JSON.parse(readFileSync(filePath, 'utf8'));
    // Use fromJSON to properly restore wallet with all keys
    const wallet = Wallet.fromJSON({ ...json, network: NETWORK });
    return {
      keys: {
        viewSecretKey: json.viewSecretKey,
        spendSecretKey: json.spendSecretKey,
        viewPublicKey: json.viewPublicKey,
        spendPublicKey: json.spendPublicKey,
      },
      address: json.address,
      wallet,
      isNew: false
    };
  } else {
    console.log(`Creating new ${label} at ${filePath}`);
    const wallet = Wallet.create({ network: NETWORK });
    const json = {
      viewSecretKey: wallet.viewSecretKey,
      spendSecretKey: wallet.spendSecretKey,
      viewPublicKey: wallet.viewPublicKey,
      spendPublicKey: wallet.spendPublicKey,
      address: wallet.getAddress(),
      network: NETWORK,
      createdAt: new Date().toISOString()
    };
    writeFileSync(filePath, JSON.stringify(json, null, 2));
    return {
      keys: {
        viewSecretKey: json.viewSecretKey,
        spendSecretKey: json.spendSecretKey,
        viewPublicKey: json.viewPublicKey,
        spendPublicKey: json.spendPublicKey,
      },
      address: json.address,
      wallet,
      isNew: true
    };
  }
}

async function syncWallet(label, keys, cacheFile = null) {
  const storage = new MemoryStorage();

  let cachedHeight = 0;
  if (cacheFile && existsSync(cacheFile)) {
    try {
      const cached = JSON.parse(readFileSync(cacheFile, 'utf8'));
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
    storage,
    network: NETWORK
  });

  await sync.start();

  if (cacheFile) {
    writeFileSync(cacheFile, JSON.stringify(storage.dump()));
    const newHeight = await storage.getSyncHeight();
    if (newHeight > cachedHeight) {
      console.log(`  Synced ${newHeight - cachedHeight} new blocks`);
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

  // Count by subaddress
  const subaddrCounts = {};
  for (const o of spendable) {
    const key = o.subaddressIndex ? `${o.subaddressIndex.major},${o.subaddressIndex.minor}` : '0,0';
    subaddrCounts[key] = (subaddrCounts[key] || 0) + 1;
  }

  console.log(`  ${allOutputs.length} unspent (${spendable.length} spendable)`);
  console.log(`  Balance: ${Number(balance) / 1e8} SAL (${Number(spendableBalance) / 1e8} spendable)`);
  if (Object.keys(subaddrCounts).length > 1) {
    console.log(`  Subaddress distribution: ${JSON.stringify(subaddrCounts)}`);
  }

  return { sync, storage, balance, spendableBalance, outputs: allOutputs, spendable, currentHeight };
}

async function doTransfer(label, keys, storage, toAddress, amount, options = {}) {
  const { silent = false, expectFail = false } = options;

  if (!silent) {
    console.log(`\n--- ${label} ---`);
    console.log(`  Amount: ${Number(amount) / 1e8} SAL`);
    console.log(`  To: ${toAddress.slice(0, 40)}...`);
  }

  try {
    const result = await transfer({
      wallet: { keys, storage },
      daemon,
      destinations: [{ address: toAddress, amount }],
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
    });

    if (!silent) {
      console.log(`  TX: ${result.txHash.slice(0, 16)}... Fee: ${Number(result.fee) / 1e8} SAL`);
      console.log(`  ${DRY_RUN ? '(dry run)' : 'BROADCAST OK'}`);
    }

    // Mark spent outputs
    if (!DRY_RUN && result.spentKeyImages) {
      for (const keyImage of result.spentKeyImages) {
        await storage.markOutputSpent(keyImage);
      }
    }

    if (expectFail) {
      return { success: false, error: 'Expected failure but succeeded' };
    }
    return { success: true, result };
  } catch (e) {
    if (!silent) {
      console.error(`  FAILED: ${e.message}`);
    }
    if (expectFail) {
      return { success: true, expectedError: e.message };
    }
    return { success: false, error: e.message };
  }
}

// ============================================================================
// TEST SECTIONS
// ============================================================================

async function testSubaddressGeneration(walletA, walletB) {
  console.log('\n=== Subaddress Generation Tests ===');

  // Test wallet A subaddresses
  const subA_0_0 = walletA.wallet.getSubaddress(0, 0);
  const subA_0_1 = walletA.wallet.getSubaddress(0, 1);
  const subA_0_2 = walletA.wallet.getSubaddress(0, 2);
  const subA_1_0 = walletA.wallet.getSubaddress(1, 0);

  logTest('Subaddress (0,0) equals main address', subA_0_0 === walletA.address);
  logTest('Subaddress (0,1) differs from main', subA_0_1 !== walletA.address);
  logTest('Subaddress (0,2) differs from (0,1)', subA_0_2 !== subA_0_1);
  logTest('Subaddress (1,0) differs from (0,1)', subA_1_0 !== subA_0_1);

  // Verify subaddresses parse correctly
  const parsedSub = parseAddress(subA_0_1);
  logTest('Subaddress parses as valid', parsedSub.valid);
  logTest('Subaddress type is subaddress', parsedSub.type === 'subaddress');
  logTest('isSubaddress() returns true', isSubaddress(subA_0_1));

  // Test wallet B subaddresses
  const subB_0_1 = walletB.wallet.getSubaddress(0, 1);
  logTest('Wallet B subaddress differs from A', subB_0_1 !== subA_0_1);

  return {
    walletA: {
      main: walletA.address,
      sub_0_1: subA_0_1,
      sub_0_2: subA_0_2,
      sub_1_0: subA_1_0
    },
    walletB: {
      main: walletB.address,
      sub_0_1: subB_0_1,
      sub_0_2: walletB.wallet.getSubaddress(0, 2),
      sub_1_0: walletB.wallet.getSubaddress(1, 0)
    }
  };
}

async function testIntegratedAddresses(walletA, walletB) {
  console.log('\n=== Integrated Address Tests ===');

  // Generate payment IDs
  const paymentId1 = generatePaymentId();
  const paymentId2 = generatePaymentId();

  logTest('Payment ID is 8 bytes', paymentId1.length === 8);
  logTest('Payment IDs are unique', bytesToHex(paymentId1) !== bytesToHex(paymentId2));

  // Create integrated addresses
  const integratedA = walletA.wallet.getIntegratedAddress(paymentId1);
  const integratedB = walletB.wallet.getIntegratedAddress(paymentId2);

  logTest('Integrated address A created', integratedA.length > 0);
  logTest('Integrated address B created', integratedB.length > 0);

  // Parse integrated addresses
  const parsedInt = parseAddress(integratedA);
  logTest('Integrated address parses as valid', parsedInt.valid);
  logTest('Integrated address type is integrated', parsedInt.type === 'integrated');
  logTest('isIntegrated() returns true', isIntegrated(integratedA));

  // Extract payment ID
  const extractedId = getPaymentId(integratedA);
  logTest('Payment ID extractable', extractedId !== null);
  logTest('Extracted ID matches original', bytesToHex(extractedId) === bytesToHex(paymentId1));

  return {
    walletA: {
      integrated: integratedA,
      paymentId: bytesToHex(paymentId1)
    },
    walletB: {
      integrated: integratedB,
      paymentId: bytesToHex(paymentId2)
    }
  };
}

async function testAddressCombinations(keysA, storageA, keysB, storageB, addresses) {
  console.log('\n=== Transfer Address Combinations ===');

  const testAmount = 1_00_000_000n; // 1 SAL

  // A → B combinations
  const tests = [
    { from: 'A', to: 'B.main', toAddr: addresses.walletB.main, label: 'A main → B main' },
    { from: 'A', to: 'B.sub_0_1', toAddr: addresses.walletB.sub_0_1, label: 'A main → B subaddress(0,1)' },
    { from: 'A', to: 'B.sub_1_0', toAddr: addresses.walletB.sub_1_0, label: 'A main → B subaddress(1,0)' },
    { from: 'A', to: 'B.integrated', toAddr: addresses.integratedB.integrated, label: 'A main → B integrated' },
  ];

  for (const t of tests) {
    const result = await doTransfer(t.label, keysA, storageA, t.toAddr, testAmount);
    logTest(t.label, result.success, result.error || '');
  }

  // Test that we can send to our own subaddress (self-transfer)
  const selfResult = await doTransfer(
    'A main → A subaddress(0,1)',
    keysA, storageA,
    addresses.walletA.sub_0_1,
    testAmount
  );
  logTest('Self-transfer to subaddress', selfResult.success, selfResult.error || '');
}

async function testBidirectionalTransfers(keysA, storageA, keysB, storageB, addressA, addressB) {
  console.log('\n=== Bidirectional Transfers (A ↔ B) ===');

  const amount = 5_00_000_000n; // 5 SAL

  // First, we need B to have funds. If B has no funds, we transfer from A first
  const infoResp = await daemon.getInfo();
  const height = infoResp.result?.height || infoResp.data?.height;
  const bOutputs = await storageB.getOutputs({ isSpent: false });
  const bSpendable = bOutputs.filter(o => o.isSpendable(height));
  let bBalance = 0n;
  for (const o of bSpendable) bBalance += o.amount;

  if (bBalance < amount + 1_00_000_000n) {
    console.log(`  Wallet B balance (${Number(bBalance)/1e8} SAL) too low, funding from A first...`);
    const fundResult = await doTransfer('Fund B from A', keysA, storageA, addressB, 50_00_000_000n);
    if (!fundResult.success) {
      logSkip('B → A transfer', 'Cannot fund wallet B');
      return;
    }
    if (DRY_RUN) {
      logSkip('B → A transfer', 'Dry run - B has no real funds');
      return;
    }
    // In live mode, we'd need to wait for confirmation and re-sync
  }

  // Now try B → A
  const resultBA = await doTransfer('B → A', keysB, storageB, addressA, amount);
  if (resultBA.success) {
    logTest('B → A transfer', true);
  } else if (resultBA.error?.includes('No spendable') || resultBA.error?.includes('Insufficient')) {
    logSkip('B → A transfer', 'B has no spendable funds yet');
  } else {
    logTest('B → A transfer', false, resultBA.error);
  }
}

async function testFractionalTransfers(keysA, storageA, keysB, storageB, addressA, addressB, subAddrA, subAddrB) {
  console.log(`\n=== Fractional Transfers (${NUM_FRACTIONAL} each direction) ===`);
  console.log('  Creating many small UTXOs to stress test input selection...');

  let successA2B = 0;
  let successB2A = 0;
  let failuresA2B = 0;
  let failuresB2A = 0;

  // A → B: Mix of main and subaddress destinations
  console.log('\n  A → B transfers:');
  for (let i = 0; i < NUM_FRACTIONAL; i++) {
    // Random amount between 0.3 and 0.7 SAL
    const amount = BigInt(Math.floor(Math.random() * 40_000_000 + 30_000_000));

    // Alternate between main address and subaddress
    const toAddr = i % 3 === 0 ? subAddrB : (i % 3 === 1 ? addressB : subAddrB);

    const result = await doTransfer(
      `A→B #${i + 1}`,
      keysA, storageA, toAddr, amount,
      { silent: true }
    );

    if (result.success) {
      successA2B++;
      if ((i + 1) % 10 === 0) process.stdout.write(`    ${i + 1}/${NUM_FRACTIONAL} done (${successA2B} OK)\n`);
    } else {
      failuresA2B++;
      if (failuresA2B >= 5) {
        console.log(`    Too many failures (${failuresA2B}), stopping A→B at ${i + 1}`);
        break;
      }
    }
  }
  console.log(`  A → B: ${successA2B}/${NUM_FRACTIONAL} succeeded`);

  // B → A: Only if B has funds
  const infoResp = await daemon.getInfo();
  const height = infoResp.result?.height || infoResp.data?.height;
  const bOutputs = await storageB.getOutputs({ isSpent: false });
  const bSpendable = bOutputs.filter(o => o.isSpendable(height));

  if (bSpendable.length === 0 || DRY_RUN) {
    console.log(`  B → A: SKIPPED (${DRY_RUN ? 'dry run' : 'no funds in B'})`);
  } else {
    console.log('\n  B → A transfers:');
    for (let i = 0; i < Math.min(NUM_FRACTIONAL, bSpendable.length); i++) {
      const amount = BigInt(Math.floor(Math.random() * 40_000_000 + 30_000_000));
      const toAddr = i % 2 === 0 ? addressA : subAddrA;

      const result = await doTransfer(
        `B→A #${i + 1}`,
        keysB, storageB, toAddr, amount,
        { silent: true }
      );

      if (result.success) {
        successB2A++;
        if ((i + 1) % 10 === 0) process.stdout.write(`    ${i + 1} done (${successB2A} OK)\n`);
      } else {
        failuresB2A++;
        if (failuresB2A >= 5) {
          console.log(`    Too many failures (${failuresB2A}), stopping B→A at ${i + 1}`);
          break;
        }
      }
    }
    console.log(`  B → A: ${successB2A} succeeded`);
  }

  logTest(`Fractional A→B (${successA2B}/${NUM_FRACTIONAL})`, successA2B > NUM_FRACTIONAL * 0.8);
  if (!DRY_RUN && bSpendable.length > 0) {
    logTest(`Fractional B→A (${successB2A})`, successB2A > 0);
  }

  return { successA2B, successB2A };
}

async function testEdgeCases(keysA, storageA, addressB) {
  console.log('\n=== Edge Case Tests ===');

  // Dust amount (very small)
  const dustAmount = 1000n; // 0.00001 SAL - below practical dust threshold
  const dustResult = await doTransfer('Dust transfer (0.00001 SAL)', keysA, storageA, addressB, dustAmount);
  // Dust should either succeed or fail with clear error
  logTest('Dust transfer handled', dustResult.success || dustResult.error?.includes('too small') || dustResult.error?.includes('dust'));

  // Minimum practical amount
  const minAmount = 1_000_000n; // 0.01 SAL
  const minResult = await doTransfer('Minimum amount (0.01 SAL)', keysA, storageA, addressB, minAmount);
  logTest('Minimum amount transfer', minResult.success, minResult.error || '');

  // Slightly above minimum
  const smallAmount = 5_000_000n; // 0.05 SAL
  const smallResult = await doTransfer('Small amount (0.05 SAL)', keysA, storageA, addressB, smallAmount);
  logTest('Small amount transfer', smallResult.success, smallResult.error || '');

  // Round number
  const roundAmount = 100_00_000_000n; // 100 SAL
  const roundResult = await doTransfer('Round amount (100 SAL)', keysA, storageA, addressB, roundAmount);
  logTest('Round amount transfer', roundResult.success, roundResult.error || '');

  // Odd number with many decimal places
  const oddAmount = 123_456_789n; // 1.23456789 SAL
  const oddResult = await doTransfer('Odd amount (1.23456789 SAL)', keysA, storageA, addressB, oddAmount);
  logTest('Odd amount transfer', oddResult.success, oddResult.error || '');
}

async function testMultiDestination(keysA, storageA, addresses) {
  console.log('\n=== Multi-Destination Transfers ===');

  // Send to multiple addresses in single TX
  const destinations = [
    { address: addresses.walletB.main, amount: 1_00_000_000n },     // 1 SAL to main
    { address: addresses.walletB.sub_0_1, amount: 2_00_000_000n },  // 2 SAL to subaddress
    { address: addresses.walletB.sub_0_2, amount: 1_50_000_000n },  // 1.5 SAL to another subaddress
  ];

  console.log('\n--- Multi-destination: 3 outputs ---');
  console.log(`  To: ${addresses.walletB.main.slice(0, 30)}... (1 SAL)`);
  console.log(`  To: ${addresses.walletB.sub_0_1.slice(0, 30)}... (2 SAL)`);
  console.log(`  To: ${addresses.walletB.sub_0_2.slice(0, 30)}... (1.5 SAL)`);

  try {
    const result = await transfer({
      wallet: { keys: keysA, storage: storageA },
      daemon,
      destinations,
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
    });

    console.log(`  TX: ${result.txHash.slice(0, 16)}...`);
    console.log(`  Fee: ${Number(result.fee) / 1e8} SAL`);
    console.log(`  Outputs: ${result.outputCount} (expected 4: 3 dest + 1 change)`);
    console.log(`  ${DRY_RUN ? '(dry run)' : 'BROADCAST OK'}`);

    logTest('Multi-destination transfer', true);
    logTest('Correct output count', result.outputCount >= 3); // At least 3 destinations, maybe +1 change

    if (!DRY_RUN && result.spentKeyImages) {
      for (const keyImage of result.spentKeyImages) {
        await storageA.markOutputSpent(keyImage);
      }
    }
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    logTest('Multi-destination transfer', false, e.message);
  }
}

async function testSweepRecombination(keysA, storageA, addressA) {
  console.log('\n=== Sweep Recombination Test ===');
  console.log('  Combining all fractional UTXOs back into fewer outputs...');

  const infoResp = await daemon.getInfo();
  const height = infoResp.result?.height || infoResp.data?.height;
  const outputs = await storageA.getOutputs({ isSpent: false });
  const spendable = outputs.filter(o => o.isSpendable(height));

  console.log(`  Found ${spendable.length} spendable outputs to sweep`);

  if (spendable.length < 5) {
    logSkip('Sweep recombination', 'Too few outputs to meaningfully test');
    return;
  }

  try {
    const result = await sweep({
      wallet: { keys: keysA, storage: storageA },
      daemon,
      address: addressA,
      options: { priority: 'default', network: NETWORK, dryRun: DRY_RUN }
    });

    console.log(`  TX: ${result.txHash.slice(0, 16)}...`);
    console.log(`  Fee: ${Number(result.fee) / 1e8} SAL`);
    console.log(`  Amount: ${Number(result.amount) / 1e8} SAL`);
    console.log(`  Inputs: ${result.inputCount} combined into 1 output`);
    console.log(`  Serialized: ${result.serializedHex.length / 2} bytes`);
    console.log(`  ${DRY_RUN ? '(dry run)' : 'BROADCAST OK'}`);

    logTest('Sweep recombination', true);
    logTest('Many inputs combined', result.inputCount >= 5);
  } catch (e) {
    console.error(`  FAILED: ${e.message}`);
    logTest('Sweep recombination', false, e.message);
  }
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║  Subaddress & Multi-Wallet Integration Test                  ║');
  console.log('╚══════════════════════════════════════════════════════════════╝\n');
  console.log(`Daemon:     ${DAEMON_URL}`);
  console.log(`Network:    ${NETWORK}`);
  console.log(`Dry run:    ${DRY_RUN}`);
  console.log(`Fractional: ${NUM_FRACTIONAL} transfers each direction\n`);

  daemon = new DaemonRPC({ url: DAEMON_URL });

  const info = await daemon.getInfo();
  if (!info.success) throw new Error('Cannot reach daemon');
  const height = info.result?.height || info.data?.height;
  console.log(`Daemon height: ${height}\n`);

  // Load or create wallets
  const walletA = await loadOrCreateWallet(WALLET_FILE, 'Wallet A');
  console.log(`  Address: ${walletA.address}\n`);

  const walletB = await loadOrCreateWallet(WALLET_B_FILE, 'Wallet B');
  console.log(`  Address: ${walletB.address}`);
  if (walletB.isNew) {
    console.log(`  (New wallet created - will need funding before B→A transfers work)`);
  }
  console.log();

  // Sync both wallets
  const syncA = await syncWallet('Wallet A', walletA.keys, SYNC_CACHE_A);
  const syncB = await syncWallet('Wallet B', walletB.keys, SYNC_CACHE_B);

  if (syncA.spendableBalance === 0n) {
    console.log('\nWallet A has no spendable balance. Mine more blocks.');
    return;
  }

  // Run test suites
  const subaddresses = await testSubaddressGeneration(walletA, walletB);
  const integratedAddrs = await testIntegratedAddresses(walletA, walletB);

  const addresses = {
    ...subaddresses,
    integratedA: integratedAddrs.walletA,
    integratedB: integratedAddrs.walletB
  };

  await testAddressCombinations(
    walletA.keys, syncA.storage,
    walletB.keys, syncB.storage,
    addresses
  );

  await testBidirectionalTransfers(
    walletA.keys, syncA.storage,
    walletB.keys, syncB.storage,
    walletA.address, walletB.address
  );

  await testFractionalTransfers(
    walletA.keys, syncA.storage,
    walletB.keys, syncB.storage,
    walletA.address, walletB.address,
    addresses.walletA.sub_0_1, addresses.walletB.sub_0_1
  );

  await testEdgeCases(walletA.keys, syncA.storage, walletB.address);

  await testMultiDestination(walletA.keys, syncA.storage, addresses);

  await testSweepRecombination(walletA.keys, syncA.storage, walletA.address);

  // Final summary
  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║  TEST SUMMARY                                                ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log(`  Passed:  ${testResults.passed}`);
  console.log(`  Failed:  ${testResults.failed}`);
  console.log(`  Skipped: ${testResults.skipped}`);
  console.log(`  Total:   ${testResults.passed + testResults.failed + testResults.skipped}`);

  if (testResults.failed > 0) {
    console.log('\n  Failed tests:');
    for (const t of testResults.tests) {
      if (t.passed === false) {
        console.log(`    ✗ ${t.name}: ${t.details}`);
      }
    }
  }

  if (!DRY_RUN) {
    console.log('\n  Next steps:');
    console.log('    1. Wait for confirmations (10 blocks)');
    console.log('    2. Re-run to verify funds arrived at subaddresses');
    console.log('    3. Run again to test B→A transfers with real funds');
  }

  console.log('\n=== Test Complete ===');
}

main().catch(e => {
  console.error('Fatal:', e);
  process.exit(1);
});
