#!/usr/bin/env bun
/**
 * Integration Sync Test
 *
 * Tests wallet sync against a real Salvium daemon.
 *
 * Usage (Full Wallet):
 *   WALLET_SEED="your 25 word mnemonic" bun test/integration-sync.test.js
 *   MASTER_KEY="64-char-hex" bun test/integration-sync.test.js
 *
 * Usage (View-Only - CARROT):
 *   VIEW_BALANCE_SECRET="hex" ACCOUNT_SPEND_PUBKEY="hex" bun test/integration-sync.test.js
 *
 * Usage (View-Only - Legacy):
 *   VIEW_SECRET_KEY="hex" SPEND_PUBLIC_KEY="hex" bun test/integration-sync.test.js
 *
 * Options:
 *   DAEMON_URL       - Daemon RPC URL (default: http://seed01.salvium.io:19081)
 *   START_HEIGHT     - Block height to start sync from (default: 0)
 *   MAX_BLOCKS       - Maximum blocks to sync (default: sync to chain tip)
 *   EXPECTED_BALANCE - Expected minimum balance to verify (optional)
 *   CRYPTO_BACKEND   - Crypto backend: 'wasm' (default) or 'js' or 'ffi'
 *   STORAGE_BACKEND  - Storage backend: 'memory' (default) or 'ffi' (SQLCipher via Rust FFI)
 *   STORAGE_PATH     - Database path for ffi storage (default: /tmp/salvium-sync-test.db)
 *   STORAGE_KEY      - Hex-encoded 32-byte encryption key for ffi storage (default: zeros)
 */

import { createDaemonRPC } from '../src/rpc/index.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys, deriveCarrotKeys, deriveCarrotViewOnlyKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex, createAddress, generateCarrotSubaddress } from '../src/address.js';
import { NETWORK, ADDRESS_FORMAT, ADDRESS_TYPE } from '../src/constants.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { WalletSync, SYNC_STATUS } from '../src/wallet-sync.js';

// Conditionally import FfiStorage (only when STORAGE_BACKEND=ffi)
let FfiStorage = null;
if (process.env.STORAGE_BACKEND === 'ffi') {
  FfiStorage = (await import('../src/wallet-store-ffi.js')).FfiStorage;
}
import { cnSubaddress, generateCNSubaddressMap, generateCarrotSubaddressMap, SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR } from '../src/subaddress.js';
import { initCrypto, getCryptoBackend, getCurrentBackendType, setCryptoBackend } from '../src/crypto/index.js';

// ============================================================================
// Configuration
// ============================================================================

const DAEMON_URL = process.env.DAEMON_URL || 'http://seed01.salvium.io:19081';
const START_HEIGHT = parseInt(process.env.START_HEIGHT || '0', 10);
const MAX_BLOCKS = process.env.MAX_BLOCKS ? parseInt(process.env.MAX_BLOCKS, 10) : null; // null = sync to tip
const EXPECTED_BALANCE = process.env.EXPECTED_BALANCE ? BigInt(process.env.EXPECTED_BALANCE) : null;

// ============================================================================
// Get wallet keys
// ============================================================================

function getWalletKeys() {
  // Option 1: From mnemonic seed (full wallet)
  if (process.env.WALLET_SEED) {
    console.log('Using wallet from mnemonic seed');
    const mnemonic = process.env.WALLET_SEED.trim();
    const result = mnemonicToSeed(mnemonic, { language: 'auto' });
    if (!result.valid) {
      console.error('Invalid mnemonic:', result.error);
      process.exit(1);
    }
    return { ...deriveKeys(result.seed), isViewOnly: false };
  }

  // Option 2: From master key / raw seed hex (full wallet)
  if (process.env.MASTER_KEY) {
    console.log('Using wallet from master key (raw hex seed)');
    const masterKey = process.env.MASTER_KEY.trim();
    if (masterKey.length !== 64) {
      console.error('MASTER_KEY must be 64 hex characters (32 bytes)');
      process.exit(1);
    }
    return { ...deriveKeys(hexToBytes(masterKey)), isViewOnly: false };
  }

  // Option 3: View-only from view-balance secret (CARROT)
  if (process.env.VIEW_BALANCE_SECRET) {
    console.log('Using CARROT view-only wallet from view-balance secret');
    if (!process.env.ACCOUNT_SPEND_PUBKEY) {
      console.error('VIEW_BALANCE_SECRET requires ACCOUNT_SPEND_PUBKEY');
      process.exit(1);
    }
    const viewBalanceSecret = hexToBytes(process.env.VIEW_BALANCE_SECRET.trim());
    const accountSpendPubkey = hexToBytes(process.env.ACCOUNT_SPEND_PUBKEY.trim());
    // For CARROT view-only, we need to derive the legacy CN keys differently
    // We can't derive spendSecretKey, but we can still scan with viewIncomingKey
    return {
      viewSecretKey: null, // No legacy view key available
      spendSecretKey: null,
      spendPublicKey: accountSpendPubkey,
      viewPublicKey: null,
      viewBalanceSecret,
      accountSpendPubkey,
      isViewOnly: true,
      isCarrotViewOnly: true
    };
  }

  // Option 4: View-only from legacy hex keys
  if (process.env.VIEW_SECRET_KEY) {
    console.log('Using legacy view-only wallet from hex keys');
    if (!process.env.SPEND_PUBLIC_KEY) {
      console.error('VIEW_SECRET_KEY requires SPEND_PUBLIC_KEY');
      process.exit(1);
    }
    return {
      viewSecretKey: hexToBytes(process.env.VIEW_SECRET_KEY.trim()),
      spendSecretKey: process.env.SPEND_SECRET_KEY ? hexToBytes(process.env.SPEND_SECRET_KEY.trim()) : null,
      spendPublicKey: hexToBytes(process.env.SPEND_PUBLIC_KEY.trim()),
      isViewOnly: !process.env.SPEND_SECRET_KEY
    };
  }

  return null;
}

// ============================================================================
// Main test
// ============================================================================

async function runIntegrationTest() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║           Salvium Wallet Sync Integration Test             ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  // Initialize crypto backend (WASM by default, CRYPTO_BACKEND=ffi to override)
  // Note: JS backend no longer supports scalar/point ops (Phase 6 deprecation),
  // so we always init WASM unless FFI is explicitly requested.
  const requestedBackend = process.env.CRYPTO_BACKEND || 'wasm';
  if (requestedBackend === 'ffi') {
    await setCryptoBackend('ffi');
  } else {
    await initCrypto();  // Loads WASM (required for key derivation)
  }
  console.log(`Crypto backend: ${getCurrentBackendType()}\n`);

  // Get keys
  const keys = getWalletKeys();
  if (!keys) {
    console.error('ERROR: No wallet keys provided.\n');
    console.log('Usage:');
    console.log('  WALLET_SEED="your 25 word mnemonic" bun test/integration-sync.test.js');
    console.log('  VIEW_SECRET_KEY="hex" SPEND_PUBLIC_KEY="hex" bun test/integration-sync.test.js');
    process.exit(1);
  }

  // Display CryptoNote keys
  console.log('--- CryptoNote Keys ---');
  console.log(`Spend secret key: ${keys.spendSecretKey ? bytesToHex(keys.spendSecretKey) : 'null'}`);
  console.log(`Spend public key: ${keys.spendPublicKey ? bytesToHex(keys.spendPublicKey) : 'null'}`);
  console.log(`View secret key:  ${keys.viewSecretKey ? bytesToHex(keys.viewSecretKey) : 'null'}`);
  console.log(`View public key:  ${keys.viewPublicKey ? bytesToHex(keys.viewPublicKey) : 'null'}`);

  // Derive and display CARROT keys
  let carrotKeys = null;
  if (keys.isCarrotViewOnly) {
    // CARROT view-only: derive from view-balance secret
    carrotKeys = deriveCarrotViewOnlyKeys(keys.viewBalanceSecret, keys.accountSpendPubkey);
    console.log('\n--- CARROT View-Only Keys ---');
    console.log(`View-balance secret:     ${carrotKeys.viewBalanceSecret}`);
    console.log(`Generate-image key:      ${carrotKeys.generateImageKey}`);
    console.log(`View-incoming key:       ${carrotKeys.viewIncomingKey}`);
    console.log(`Generate-address secret: ${carrotKeys.generateAddressSecret}`);
    console.log('\n--- CARROT Account Pubkeys ---');
    console.log(`Account spend pubkey (K_s):      ${carrotKeys.accountSpendPubkey}`);
    console.log(`Primary addr view (k_vi*G):      ${carrotKeys.primaryAddressViewPubkey}`);
    console.log(`Account view pubkey (k_vi*K_s):  ${carrotKeys.accountViewPubkey}`);
  } else if (keys.spendSecretKey) {
    // Full wallet: derive from master secret (spend secret key)
    carrotKeys = deriveCarrotKeys(keys.spendSecretKey);
    console.log('\n--- CARROT Account Secrets ---');
    console.log(`Master secret:           ${carrotKeys.masterSecret}`);
    console.log(`Prove-spend key:         ${carrotKeys.proveSpendKey}`);
    console.log(`View-balance secret:     ${carrotKeys.viewBalanceSecret}`);
    console.log(`Generate-image key:      ${carrotKeys.generateImageKey}`);
    console.log(`View-incoming key:       ${carrotKeys.viewIncomingKey}`);
    console.log(`Generate-address secret: ${carrotKeys.generateAddressSecret}`);
    console.log('\n--- CARROT Account Pubkeys ---');
    console.log(`Account spend pubkey (K_s):      ${carrotKeys.accountSpendPubkey}`);
    console.log(`Primary addr view (k_vi*G):      ${carrotKeys.primaryAddressViewPubkey}`);
    console.log(`Account view pubkey (k_vi*K_s):  ${carrotKeys.accountViewPubkey}`);
  }

  // Generate Legacy (CryptoNote) address
  const legacyAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });

  console.log('\n--- Legacy (CryptoNote) Addresses ---');
  if (legacyAddress) {
    console.log(`Main address: ${legacyAddress}`);
    // Generate a few CN subaddresses
    for (let minor = 1; minor <= 3; minor++) {
      const subKeys = cnSubaddress(keys.spendPublicKey, keys.viewSecretKey, 0, minor);
      const subAddr = createAddress({
        network: NETWORK.MAINNET,
        format: ADDRESS_FORMAT.LEGACY,
        type: ADDRESS_TYPE.SUBADDRESS,
        spendPublicKey: subKeys.spendPublicKey,
        viewPublicKey: subKeys.viewPublicKey
      });
      console.log(`Subaddress [0,${minor}]: ${subAddr}`);
    }
  } else {
    console.log('Warning: Could not generate legacy address');
  }

  // Generate CARROT addresses
  if (carrotKeys) {
    console.log('\n--- CARROT Addresses ---');
    // Main address uses primaryAddressViewPubkey (k_vi * G)
    const carrotMainAddress = createAddress({
      network: NETWORK.MAINNET,
      format: ADDRESS_FORMAT.CARROT,
      type: ADDRESS_TYPE.STANDARD,
      spendPublicKey: hexToBytes(carrotKeys.accountSpendPubkey),
      viewPublicKey: hexToBytes(carrotKeys.primaryAddressViewPubkey)
    });
    if (carrotMainAddress) {
      console.log(`Main address: ${carrotMainAddress}`);
      // Generate a few CARROT subaddresses (use accountViewPubkey = k_vi * K_s)
      for (let minor = 1; minor <= 3; minor++) {
        const carrotSub = generateCarrotSubaddress({
          network: NETWORK.MAINNET,
          accountSpendPubkey: hexToBytes(carrotKeys.accountSpendPubkey),
          accountViewPubkey: hexToBytes(carrotKeys.accountViewPubkey),
          generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret),
          major: 0,
          minor
        });
        if (carrotSub && carrotSub.address) {
          console.log(`Subaddress [0,${minor}]: ${carrotSub.address}`);
        }
      }
    } else {
      console.log('Warning: Could not generate CARROT address');
    }
  }

  const walletType = keys.isViewOnly
    ? (keys.isCarrotViewOnly ? 'Yes (CARROT view-only)' : 'Yes (Legacy view-only)')
    : 'No (full wallet)';
  console.log(`\nWallet type: ${walletType}\n`);

  // Connect to daemon
  console.log(`Connecting to daemon: ${DAEMON_URL}`);
  const daemon = createDaemonRPC({ url: DAEMON_URL, timeout: 30000 });

  const info = await daemon.getInfo();
  if (!info.success) {
    console.error('ERROR: Failed to connect to daemon:', info.error?.message);
    process.exit(1);
  }

  const daemonHeight = info.result.height;
  console.log(`Daemon height: ${daemonHeight}`);
  console.log(`Network: ${info.result.nettype || 'mainnet'}`);
  console.log(`Status: ${info.result.status}\n`);

  // Calculate sync range
  const startHeight = START_HEIGHT;
  const endHeight = MAX_BLOCKS ? Math.min(startHeight + MAX_BLOCKS, daemonHeight) : daemonHeight;
  const blocksToSync = endHeight - startHeight;
  console.log(`Sync range: ${startHeight} -> ${endHeight} (${blocksToSync} blocks)`);
  if (blocksToSync > 10000) {
    console.log(`Note: This may take a while...\n`);
  } else {
    console.log('');
  }

  // Create storage and sync engine
  const storageBackend = process.env.STORAGE_BACKEND || 'memory';
  let storage;
  if (storageBackend === 'ffi' && FfiStorage) {
    const dbPath = process.env.STORAGE_PATH || '/tmp/salvium-sync-test.db';
    const keyHex = process.env.STORAGE_KEY || '00'.repeat(32);
    const keyBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) keyBytes[i] = parseInt(keyHex.substr(i * 2, 2), 16);
    storage = new FfiStorage({ path: dbPath, key: keyBytes });
    console.log(`Storage backend: ffi (SQLCipher) → ${dbPath}`);
  } else {
    storage = new MemoryStorage();
    console.log('Storage backend: memory');
  }
  await storage.open();
  await storage.setSyncHeight(startHeight);

  // Generate subaddress maps (matching C++ wallet lookahead: 50 major x 200 minor)
  console.log(`Generating subaddress maps (${SUBADDRESS_LOOKAHEAD_MAJOR} x ${SUBADDRESS_LOOKAHEAD_MINOR})...`);
  const subaddressGenStart = Date.now();

  // CN subaddresses
  let cnSubaddresses = new Map();
  if (keys.viewSecretKey && keys.spendPublicKey) {
    cnSubaddresses = generateCNSubaddressMap(
      keys.spendPublicKey,
      keys.viewSecretKey,
      SUBADDRESS_LOOKAHEAD_MAJOR,
      SUBADDRESS_LOOKAHEAD_MINOR
    );
    console.log(`  CN subaddresses: ${cnSubaddresses.size}`);
  }

  // CARROT subaddresses
  let carrotSubaddresses = new Map();
  if (carrotKeys) {
    carrotSubaddresses = generateCarrotSubaddressMap(
      hexToBytes(carrotKeys.accountSpendPubkey),
      hexToBytes(carrotKeys.accountViewPubkey),
      hexToBytes(carrotKeys.generateAddressSecret),
      SUBADDRESS_LOOKAHEAD_MAJOR,
      SUBADDRESS_LOOKAHEAD_MINOR
    );
    console.log(`  CARROT subaddresses: ${carrotSubaddresses.size}`);
  }

  const subaddressGenTime = ((Date.now() - subaddressGenStart) / 1000).toFixed(2);
  console.log(`  Generated in ${subaddressGenTime}s\n`);

  // Prepare CARROT keys if available
  let carrotKeysForSync = null;
  if (carrotKeys) {
    carrotKeysForSync = {
      viewIncomingKey: hexToBytes(carrotKeys.viewIncomingKey),
      accountSpendPubkey: hexToBytes(carrotKeys.accountSpendPubkey),
      generateImageKey: hexToBytes(carrotKeys.generateImageKey),
      generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret),  // Needed for subaddress key images
      viewBalanceSecret: hexToBytes(carrotKeys.viewBalanceSecret)  // Needed for internal (self-send) scanning + return map
    };
  }

  const sync = new WalletSync({
    storage,
    daemon,
    keys: {
      viewSecretKey: keys.viewSecretKey,
      spendPublicKey: keys.spendPublicKey,
      spendSecretKey: keys.spendSecretKey
    },
    carrotKeys: carrotKeysForSync,
    subaddresses: cnSubaddresses,
    carrotSubaddresses: carrotSubaddresses,
    batchSize: 100  // Will adapt automatically based on performance
  });

  // Track progress
  let lastReportHeight = 0;
  let lastReportTime = Date.now();
  let blocksWithTxs = 0;
  let outputsFound = 0;
  let cnOutputs = 0;
  let carrotOutputs = 0;
  const REPORT_INTERVAL = 1000; // Report every 1000 blocks

  sync.on('syncStart', (data) => {
    console.log(`Sync started at height ${data.startHeight}`);
    lastReportHeight = data.startHeight;
    lastReportTime = Date.now();
  });

  sync.on('syncProgress', (data) => {
    // Report every REPORT_INTERVAL blocks
    if (data.currentHeight - lastReportHeight >= REPORT_INTERVAL) {
      const now = Date.now();
      const elapsed = (now - lastReportTime) / 1000;
      const blocksProcessed = data.currentHeight - lastReportHeight;
      const blocksPerSec = elapsed > 0 ? (blocksProcessed / elapsed).toFixed(1) : '?';
      const percent = data.percentComplete.toFixed(1);
      console.log(`  Height ${data.currentHeight} (${percent}%) - ${blocksPerSec} blk/s - ${outputsFound} outputs (${cnOutputs} CN, ${carrotOutputs} CARROT)`);
      lastReportHeight = data.currentHeight;
      lastReportTime = now;
    }
  });

  sync.on('newBlock', (block) => {
    if (block.txCount > 0) {
      blocksWithTxs++;
    }
    // Debug: log every 1000 blocks
    if (block.height % 1000 === 0) {
      console.log(`  Block ${block.height} processed`);
    }
  });

  sync.on('outputFound', (output) => {
    outputsFound++;
    if (output.isCarrot) {
      carrotOutputs++;
      console.log(`  🥕 CARROT output: ${output.amount} atomic units at height ${output.blockHeight}`);
    } else {
      cnOutputs++;
      console.log(`  📜 CN output: ${output.amount} atomic units at height ${output.blockHeight}`);
    }
  });

  // Track batch size adaptation
  let lastBatchSize = null;
  sync.on('batchComplete', (data) => {
    // Only log when batch size changes
    if (lastBatchSize !== data.batchSize) {
      const direction = lastBatchSize === null ? 'initial' : (data.batchSize > lastBatchSize ? '↑' : '↓');
      console.log(`  [Batch] ${direction} size=${data.batchSize} (${data.elapsed}ms, ${data.blocksPerSec.toFixed(1)} blk/s)`);
      lastBatchSize = data.batchSize;
    }
  });

  // Debug: sample a few blocks to see transaction structure
  let debugSampleCount = 0;
  const MAX_DEBUG_SAMPLES = 3;
  sync.on('debugTx', (data) => {
    if (debugSampleCount < MAX_DEBUG_SAMPLES) {
      debugSampleCount++;
      console.log(`\n--- DEBUG TX #${debugSampleCount} (height ${data.height}) ---`);
      console.log(`TX Hash: ${data.txHash}`);
      console.log(`TX PubKey: ${data.txPubKey || 'null'}`);
      console.log(`Output count: ${data.outputCount}`);
      if (data.firstOutputKey) {
        console.log(`First output key: ${data.firstOutputKey}`);
      }
      if (data.derivation) {
        console.log(`Derivation: ${data.derivation}`);
      }
      if (data.expectedPubKey) {
        console.log(`Expected pubkey[0]: ${data.expectedPubKey}`);
      }
      console.log(`---\n`);
    }
  });

  sync.on('syncComplete', (data) => {
    console.log(`Sync completed at height ${data.height}`);
  });

  sync.on('syncError', (error) => {
    console.error(`Sync error: ${error.message}`);
  });

  // Run sync
  console.log('Starting sync...\n');
  const startTime = Date.now();

  try {
    await sync.start(startHeight);
  } catch (error) {
    console.error('Sync failed:', error.message);
  }

  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  // Get results
  const outputs = await storage.getOutputs();
  const transactions = await storage.getTransactions();
  const syncHeight = await storage.getSyncHeight();

  // Calculate balance with locked/unlocked split
  let balance = 0n;
  let unlockedBalance = 0n;
  let unspentCount = 0;
  let unlockedCount = 0;

  if (storageBackend === 'ffi' && storage.getBalance) {
    // Rust-computed balance — single FFI call, no output round-trip
    const bal = storage.getBalance({ currentHeight: syncHeight, assetType: 'SAL1' });
    balance = bal.balance;
    unlockedBalance = bal.unlockedBalance;
    // Count unspent outputs for display
    for (const output of outputs) {
      if (!output.isSpent) {
        unspentCount++;
        if (output.isUnlocked?.(syncHeight) ?? true) unlockedCount++;
      }
    }
  } else {
    // Manual balance computation for MemoryStorage
    for (const output of outputs) {
      if (!output.isSpent) {
        const amount = typeof output.amount === 'bigint' ? output.amount : BigInt(output.amount);
        balance += amount;
        unspentCount++;

        // Use WalletOutput.isUnlocked() which correctly handles both
        // string ('miner','protocol') and numeric (1,2) txType values
        if (output.isUnlocked(syncHeight)) {
          unlockedBalance += amount;
          unlockedCount++;
        }
      }
    }
  }
  const lockedBalance = balance - unlockedBalance;

  // Report results
  console.log('\n' + '='.repeat(60));
  console.log('SYNC RESULTS');
  console.log('='.repeat(60));
  console.log(`Time elapsed:       ${elapsed}s`);
  console.log(`Blocks synced:      ${syncHeight - startHeight}`);
  console.log(`Blocks with txs:    ${blocksWithTxs}`);
  console.log(`Final sync height:  ${syncHeight}`);
  console.log('');
  console.log(`Outputs found:      ${outputs.length}`);
  console.log(`Unspent outputs:    ${unspentCount} (${unlockedCount} unlocked, ${unspentCount - unlockedCount} locked)`);
  console.log(`Transactions:       ${transactions.length}`);
  console.log('');
  console.log(`Total balance:      ${balance} atomic (${(Number(balance) / 1e8).toFixed(8)} SAL1)`);
  console.log(`Unlocked balance:   ${unlockedBalance} atomic (${(Number(unlockedBalance) / 1e8).toFixed(8)} SAL1)`);
  console.log(`Locked balance:     ${lockedBalance} atomic (${(Number(lockedBalance) / 1e8).toFixed(8)} SAL1)`);

  // === DIAGNOSTIC: null keyImage outputs ===
  const nullKiOutput = await storage.getOutput(null);
  const nullKiUndefined = await storage.getOutput(undefined);
  console.log(`\n--- KEY IMAGE DIAGNOSTIC ---`);
  console.log(`Output stored under null key:      ${nullKiOutput ? `YES h=${nullKiOutput.blockHeight} amt=${(Number(nullKiOutput.amount)/1e8).toFixed(8)}` : 'none'}`);
  console.log(`Output stored under undefined key: ${nullKiUndefined ? `YES h=${nullKiUndefined.blockHeight} amt=${(Number(nullKiUndefined.amount)/1e8).toFixed(8)}` : 'none'}`);

  let nullKiCount = 0;
  let nullKiUnspentTotal = 0n;
  for (const o of outputs) {
    if (!o.keyImage) {
      nullKiCount++;
      if (!o.isSpent) {
        nullKiUnspentTotal += BigInt(o.amount);
        console.log(`  null-ki UNSPENT: h=${o.blockHeight} amt=${(Number(o.amount)/1e8).toFixed(8)} carrot=${o.isCarrot} type=${o.txType} tx=${o.txHash?.slice(0,16)}`);
      }
    }
  }
  console.log(`Total outputs with null keyImage: ${nullKiCount}`);
  console.log(`Unspent balance from null-ki outputs: ${(Number(nullKiUnspentTotal)/1e8).toFixed(8)} SAL`);

  // === DIAGNOSTIC: all unspent outputs ===
  const unspentOutputs = outputs.filter(o => !o.isSpent);
  console.log(`\n--- ALL UNSPENT OUTPUTS (${unspentOutputs.length}) ---`);
  // Sort by height
  unspentOutputs.sort((a, b) => (a.blockHeight || 0) - (b.blockHeight || 0));
  for (const o of unspentOutputs) {
    const ki = o.keyImage ? o.keyImage.slice(0,16)+'...' : 'NULL';
    console.log(`  h=${o.blockHeight} amt=${(Number(o.amount)/1e8).toFixed(8)} ki=${ki} carrot=${o.isCarrot} type=${o.txType} sub=${o.subaddressIndex?.major},${o.subaddressIndex?.minor}`);
  }

  // === DIAGNOSTIC: check outgoing TX key images ===
  console.log(`\n--- OUTGOING TX KEY IMAGE CHECK ---`);
  const outgoingTxHashes = [
    '1496ec38a7a73b2829de0a09caff9b15ba11325fe6e7af29cc65f9201902a482', // 12k send
    'c550084f2be972803a4d3f885eee5f84f8e781e3d8b6bc2acd073926e8e4407f', // consolidation
    'e5c9b8104747b07113726e720dfb02c1867986bf54fda925eb2bef1bc9bbe9b2', // consolidation
    '1563a8c75ba3a002fb34574155aa8a51cc3643da01e879fac24a2b710017634c', // STAKE
  ];
  for (const txHash of outgoingTxHashes) {
    const tx = transactions.find(t => t.txHash === txHash);
    if (tx) {
      console.log(`  TX ${txHash.slice(0,16)}: found in wallet, incoming=${tx.isIncoming} outgoing=${tx.isOutgoing} in=${(Number(tx.incomingAmount)/1e8).toFixed(4)} out=${(Number(tx.outgoingAmount)/1e8).toFixed(4)}`);
    } else {
      console.log(`  TX ${txHash.slice(0,16)}: NOT found in wallet transactions`);
    }
  }

  // List outputs
  if (outputs.length > 0) {
    console.log('\n--- Outputs ---');
    for (const output of outputs.slice(0, 10)) {
      const status = output.isSpent ? 'SPENT' : 'UNSPENT';
      console.log(`  Height ${output.blockHeight}: ${output.amount} (${status})`);
    }
    if (outputs.length > 10) {
      console.log(`  ... and ${outputs.length - 10} more`);
    }
  }

  // Stake/Yield Analysis
  const STAKE_LOCK_PERIOD = 21600; // 30*24*30 blocks on mainnet

  // Find stake outputs (outputs with unlock_time = height + ~21600)
  const stakeOutputs = [];
  for (const output of outputs) {
    const unlockTime = Number(output.unlockTime || 0);
    if (unlockTime > 0) {
      const lockDuration = unlockTime - output.blockHeight;
      if (Math.abs(lockDuration - STAKE_LOCK_PERIOD) <= 100) {
        stakeOutputs.push({
          ...output,
          unlockHeight: unlockTime
        });
      }
    }
  }

  // Find protocol tx outputs (yields/returns)
  const protocolOutputs = outputs.filter(o => {
    const tx = transactions.find(t => t.txHash === o.txHash);
    return tx && (tx.isProtocolTx || tx.txType === 'protocol');
  });

  // Group outputs by height for matching
  const outputsByHeight = new Map();
  for (const output of outputs) {
    if (!outputsByHeight.has(output.blockHeight)) {
      outputsByHeight.set(output.blockHeight, []);
    }
    outputsByHeight.get(output.blockHeight).push(output);
  }

  if (stakeOutputs.length > 0 || protocolOutputs.length > 0) {
    console.log('\n--- Stake/Yield Analysis ---');
    console.log(`Stakes found:        ${stakeOutputs.length}`);
    console.log(`Protocol outputs:    ${protocolOutputs.length}`);

    let totalStaked = 0n;
    let totalYield = 0n;

    for (let i = 0; i < stakeOutputs.length; i++) {
      const stake = stakeOutputs[i];
      const stakeAmt = Number(stake.amount) / 1e8;

      // Find return at unlock height
      let returnOutput = null;
      for (let h = stake.unlockHeight; h <= stake.unlockHeight + 5; h++) {
        const candidates = outputsByHeight.get(h) || [];
        for (const c of candidates) {
          const tx = transactions.find(t => t.txHash === c.txHash);
          if (tx && (tx.isProtocolTx || tx.txType === 'protocol') && c.amount >= stake.amount) {
            returnOutput = c;
            break;
          }
        }
        if (returnOutput) break;
      }

      totalStaked += stake.amount;
      const yieldAmt = returnOutput ? returnOutput.amount - stake.amount : 0n;
      totalYield += yieldAmt;

      const returnInfo = returnOutput
        ? `Return: ${(Number(returnOutput.amount) / 1e8).toFixed(4)} SAL, Yield: ${(Number(yieldAmt) / 1e8).toFixed(4)} SAL`
        : 'No return found';
      console.log(`  Stake #${i + 1}: ${stakeAmt.toFixed(4)} SAL @ block ${stake.blockHeight} -> unlock ${stake.unlockHeight} | ${returnInfo}`);
    }

    if (stakeOutputs.length > 0) {
      console.log(`\nTotal staked:        ${(Number(totalStaked) / 1e8).toFixed(8)} SAL`);
      console.log(`Total yield:         ${(Number(totalYield) / 1e8).toFixed(8)} SAL`);
    }
  }

  // Verify expected balance
  if (EXPECTED_BALANCE !== null) {
    console.log('\n--- Verification ---');
    if (balance >= EXPECTED_BALANCE) {
      console.log(`✓ Balance ${balance} >= expected ${EXPECTED_BALANCE}`);
    } else {
      console.log(`✗ Balance ${balance} < expected ${EXPECTED_BALANCE}`);
      process.exit(1);
    }
  }

  // Cleanup
  await storage.close();

  console.log('\n✓ Integration test completed successfully!');
}

// Run
runIntegrationTest().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
