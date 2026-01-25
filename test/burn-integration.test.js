#!/usr/bin/env bun
/**
 * BURN Transaction Integration Test
 *
 * Tests creating and broadcasting a BURN transaction on a real network.
 *
 * Usage:
 *   WALLET_SEED="your 25 word mnemonic" BURN_AMOUNT=0.01 bun test/burn-integration.test.js
 *
 * Options:
 *   WALLET_SEED   - 25 word mnemonic (required)
 *   BURN_AMOUNT   - Amount to burn in SAL (default: 0.01)
 *   DAEMON_URL    - Daemon RPC URL (default: http://seed01.salvium.io:19081)
 *   DRY_RUN       - If "true", build tx but don't broadcast (default: true)
 *   ASSET_TYPE    - Asset to burn: SAL or SAL1 (default: SAL)
 */

import { createDaemonRPC } from '../src/rpc/index.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys, deriveCarrotKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex, createAddress } from '../src/address.js';
import { NETWORK, ADDRESS_FORMAT, ADDRESS_TYPE } from '../src/constants.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { WalletSync } from '../src/wallet-sync.js';
import { generateCNSubaddressMap, generateCarrotSubaddressMap, SUBADDRESS_LOOKAHEAD_MAJOR, SUBADDRESS_LOOKAHEAD_MINOR } from '../src/subaddress.js';
import { buildBurnTransaction, serializeTransaction, TX_TYPE } from '../src/transaction.js';

// ============================================================================
// Configuration
// ============================================================================

const DAEMON_URL = process.env.DAEMON_URL || 'http://seed01.salvium.io:19081';
const BURN_AMOUNT_SAL = parseFloat(process.env.BURN_AMOUNT || '0.01');
const BURN_AMOUNT = BigInt(Math.floor(BURN_AMOUNT_SAL * 1e8)); // Convert to atomic units
const DRY_RUN = process.env.DRY_RUN !== 'false'; // Default to dry run for safety
const ASSET_TYPE = process.env.ASSET_TYPE || 'SAL';
const FEE = 100000000n; // 0.001 SAL fee (standard)

// ============================================================================
// Main
// ============================================================================

async function runBurnIntegrationTest() {
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║           BURN Transaction Integration Test                ║');
  console.log('╚════════════════════════════════════════════════════════════╝\n');

  // Validate input
  if (!process.env.WALLET_SEED) {
    console.error('ERROR: WALLET_SEED environment variable required.\n');
    console.log('Usage:');
    console.log('  WALLET_SEED="your 25 word mnemonic" bun test/burn-integration.test.js');
    console.log('');
    console.log('Options:');
    console.log('  BURN_AMOUNT=0.01    Amount to burn in SAL (default: 0.01)');
    console.log('  DRY_RUN=true        Build tx but do not broadcast (default: true)');
    console.log('  ASSET_TYPE=SAL      Asset to burn: SAL or SAL1 (default: SAL)');
    process.exit(1);
  }

  // Parse mnemonic
  const mnemonic = process.env.WALLET_SEED.trim();
  const result = mnemonicToSeed(mnemonic, { language: 'auto' });
  if (!result.valid) {
    console.error('Invalid mnemonic:', result.error);
    process.exit(1);
  }

  const keys = deriveKeys(result.seed);
  const carrotKeys = deriveCarrotKeys(keys.spendSecretKey);

  console.log('--- Configuration ---');
  console.log(`Daemon URL:    ${DAEMON_URL}`);
  console.log(`Burn amount:   ${BURN_AMOUNT_SAL} ${ASSET_TYPE} (${BURN_AMOUNT} atomic)`);
  console.log(`Fee:           ${Number(FEE) / 1e8} SAL`);
  console.log(`Mode:          ${DRY_RUN ? 'DRY RUN (will NOT broadcast)' : 'LIVE (will broadcast!)'}`);

  // Generate wallet address for display
  const mainAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });
  console.log(`Wallet:        ${mainAddress.slice(0, 20)}...${mainAddress.slice(-10)}\n`);

  // Connect to daemon
  console.log('Connecting to daemon...');
  const daemon = createDaemonRPC({ url: DAEMON_URL, timeout: 30000 });

  const info = await daemon.getInfo();
  if (!info.success) {
    console.error('ERROR: Failed to connect to daemon:', info.error?.message);
    process.exit(1);
  }

  const daemonHeight = info.result.height;
  console.log(`Daemon height: ${daemonHeight}`);
  console.log(`Network:       ${info.result.nettype || 'mainnet'}\n`);

  // Create storage and sync
  console.log('Syncing wallet to find UTXOs...');
  const storage = new MemoryStorage();
  await storage.open();

  // Generate subaddress maps
  const cnSubaddresses = generateCNSubaddressMap(
    keys.spendPublicKey,
    keys.viewSecretKey,
    SUBADDRESS_LOOKAHEAD_MAJOR,
    SUBADDRESS_LOOKAHEAD_MINOR
  );

  const carrotSubaddresses = generateCarrotSubaddressMap(
    hexToBytes(carrotKeys.accountSpendPubkey),
    hexToBytes(carrotKeys.accountViewPubkey),
    hexToBytes(carrotKeys.generateAddressSecret),
    SUBADDRESS_LOOKAHEAD_MAJOR,
    SUBADDRESS_LOOKAHEAD_MINOR
  );

  const carrotKeysForSync = {
    viewIncomingKey: hexToBytes(carrotKeys.viewIncomingKey),
    accountSpendPubkey: hexToBytes(carrotKeys.accountSpendPubkey),
    generateImageKey: hexToBytes(carrotKeys.generateImageKey),
    generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret)
  };

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
    batchSize: 100
  });

  // Track sync progress
  let outputsFound = 0;
  sync.on('outputFound', () => outputsFound++);
  sync.on('syncProgress', (data) => {
    if (data.currentHeight % 5000 === 0) {
      console.log(`  Height ${data.currentHeight} (${data.percentComplete.toFixed(1)}%) - ${outputsFound} outputs`);
    }
  });

  const syncStart = Date.now();
  await sync.start(0);
  const syncTime = ((Date.now() - syncStart) / 1000).toFixed(1);

  // Get wallet state
  const outputs = await storage.getOutputs();
  const unspentOutputs = outputs.filter(o => !o.isSpent);
  let balance = 0n;
  for (const o of unspentOutputs) {
    balance += o.amount;
  }

  console.log(`\nSync complete in ${syncTime}s`);
  console.log(`Total outputs:   ${outputs.length}`);
  console.log(`Unspent outputs: ${unspentOutputs.length}`);
  console.log(`Balance:         ${Number(balance) / 1e8} SAL\n`);

  // Check if we have enough funds
  const requiredAmount = BURN_AMOUNT + FEE;
  if (balance < requiredAmount) {
    console.error(`ERROR: Insufficient funds. Need ${Number(requiredAmount) / 1e8} SAL, have ${Number(balance) / 1e8} SAL`);
    await storage.close();
    process.exit(1);
  }

  // Select inputs (simple selection - just use enough outputs)
  console.log('Selecting inputs...');
  const selectedInputs = [];
  let selectedAmount = 0n;

  for (const output of unspentOutputs) {
    if (selectedAmount >= requiredAmount) break;

    // Fetch ring members from daemon
    const ringSize = 11;
    const globalIndex = output.globalIndex || 0;

    // Get ring members (decoys) from the daemon
    const outsResponse = await daemon.getOuts({
      outputs: [{ amount: 0, index: globalIndex }],
      get_txid: true
    });

    if (!outsResponse.success || !outsResponse.result.outs) {
      console.warn(`  Skipping output - couldn't fetch ring data`);
      continue;
    }

    // For a real implementation, we'd fetch proper decoys from the daemon
    // This is simplified - real implementation needs proper decoy selection
    const ring = [];
    const ringCommitments = [];
    const ringIndices = [];

    // Add the real output and generate fake decoys for testing
    // In production, use daemon.getOutputDistribution and proper decoy selection
    for (let i = 0; i < ringSize; i++) {
      if (i === 0) {
        // Real output
        ring.push(output.outputPublicKey);
        ringCommitments.push(output.commitment || output.outputPublicKey);
        ringIndices.push(globalIndex);
      } else {
        // Placeholder - in production, fetch real decoys
        ring.push(output.outputPublicKey);
        ringCommitments.push(output.commitment || output.outputPublicKey);
        ringIndices.push(globalIndex + i);
      }
    }

    selectedInputs.push({
      secretKey: output.outputSecretKey || keys.spendSecretKey,
      publicKey: output.outputPublicKey,
      amount: output.amount,
      mask: output.mask || new Uint8Array(32),
      ring,
      ringCommitments,
      ringIndices,
      realIndex: 0
    });

    selectedAmount += output.amount;
    console.log(`  Selected output: ${Number(output.amount) / 1e8} SAL`);
  }

  console.log(`Total selected: ${Number(selectedAmount) / 1e8} SAL\n`);

  if (selectedInputs.length === 0) {
    console.error('ERROR: Could not select any valid inputs');
    await storage.close();
    process.exit(1);
  }

  // Build the BURN transaction
  console.log('Building BURN transaction...');

  try {
    const tx = buildBurnTransaction(
      {
        inputs: selectedInputs,
        burnAmount: BURN_AMOUNT,
        changeAddress: {
          viewPublicKey: keys.viewPublicKey,
          spendPublicKey: keys.spendPublicKey,
          isSubaddress: false
        },
        fee: FEE
      },
      {
        assetType: ASSET_TYPE
      }
    );

    console.log('\n--- Transaction Built ---');
    console.log(`TX Type:             ${tx.prefix.txType} (BURN)`);
    console.log(`Amount Burnt:        ${Number(tx.prefix.amount_burnt) / 1e8} ${ASSET_TYPE}`);
    console.log(`Source Asset:        ${tx.prefix.source_asset_type}`);
    console.log(`Destination Asset:   ${tx.prefix.destination_asset_type}`);
    console.log(`Inputs:              ${tx.prefix.inputs.length}`);
    console.log(`Outputs:             ${tx.prefix.outputs.length} (change only)`);
    console.log(`CLSAG Signatures:    ${tx.rct?.CLSAGs?.length || 0}`);

    // Serialize for broadcasting
    const txBlob = serializeTransaction(tx);
    const txHex = bytesToHex(txBlob);
    console.log(`Serialized size:     ${txBlob.length} bytes`);
    console.log(`TX Hex (first 100):  ${txHex.slice(0, 100)}...`);

    if (DRY_RUN) {
      console.log('\n[DRY RUN] Transaction NOT broadcast.');
      console.log('To broadcast for real, run with DRY_RUN=false');
    } else {
      console.log('\nBroadcasting transaction...');
      const submitResult = await daemon.sendRawTransaction(txHex);

      if (submitResult.success && !submitResult.result.not_relayed) {
        console.log('\n✓ Transaction submitted successfully!');
        console.log(`TX Hash: ${submitResult.result.tx_hash || 'pending'}`);
      } else {
        console.error('\n✗ Transaction failed to submit');
        console.error('Reason:', submitResult.result?.reason || submitResult.error?.message || 'Unknown');
      }
    }

  } catch (error) {
    console.error('\nERROR building transaction:', error.message);
    if (error.stack) {
      console.error(error.stack);
    }
    process.exit(1);
  }

  await storage.close();
  console.log('\n✓ Integration test completed!');
}

// Run
runBurnIntegrationTest().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
