#!/usr/bin/env bun
/**
 * Quick CARROT scanning test
 * Tests CARROT output detection on a specific block
 *
 * Usage:
 *   WALLET_SEED="your 25 word mnemonic" bun test/quick-carrot-test.js
 *   MASTER_KEY="64-char-hex" bun test/quick-carrot-test.js
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { mnemonicToSeed } from '../src/mnemonic.js';
import { deriveKeys, deriveCarrotKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { carrotEcdhKeyExchange, computeCarrotViewTag, makeInputContextCoinbase } from '../src/carrot-scanning.js';

// Get wallet seed from environment
if (!process.env.WALLET_SEED && !process.env.MASTER_KEY) {
  console.error('ERROR: WALLET_SEED or MASTER_KEY environment variable required.\n');
  console.log('Usage:');
  console.log('  WALLET_SEED="your 25 word mnemonic" bun test/quick-carrot-test.js');
  console.log('  MASTER_KEY="64-char-hex" bun test/quick-carrot-test.js');
  process.exit(1);
}

console.log('=== Quick CARROT Scanning Test ===\n');

// 1. Generate wallet keys
console.log('Generating wallet keys...');

let seedResult;
if (process.env.WALLET_SEED) {
  const mnemonic = process.env.WALLET_SEED.trim();
  seedResult = mnemonicToSeed(mnemonic, { language: 'auto' });
  if (!seedResult.valid) {
    console.error('Invalid mnemonic:', seedResult.error);
    process.exit(1);
  }
} else {
  const masterKey = process.env.MASTER_KEY.trim();
  if (masterKey.length !== 64) {
    console.error('MASTER_KEY must be 64 hex characters');
    process.exit(1);
  }
  seedResult = { seed: hexToBytes(masterKey), valid: true };
}
const cnKeys = deriveKeys(seedResult.seed);

// Derive CARROT keys - master secret is the spend secret key
const carrotKeys = deriveCarrotKeys(cnKeys.spendSecretKey);

// Keys are returned as hex strings from deriveCarrotKeys
console.log('View-incoming key (k_vi):', carrotKeys.viewIncomingKey);
console.log('Account spend pubkey (K_s):', carrotKeys.accountSpendPubkey);

// Convert keys to bytes for crypto operations
const viewIncomingKeyBytes = hexToBytes(carrotKeys.viewIncomingKey);
const accountSpendPubkeyBytes = hexToBytes(carrotKeys.accountSpendPubkey);

// 2. Connect to daemon and get a specific block
const daemon = new DaemonRPC({ url: 'http://core2.whiskymine.io:19081' });
const infoResult = await daemon.getInfo();
const info = infoResult.result || infoResult;
console.log('\nConnected to daemon, height:', info.height);

// Test with a post-hardfork block (CARROT started at block 334750)
const testHeight = 405000;
console.log(`\nFetching block ${testHeight}...`);

// Get block in JSON format
const blockResult = await daemon.getBlock({ height: testHeight });

if (!blockResult.success || !blockResult.result?.json) {
  console.log('Failed to fetch block:', blockResult.error);
  process.exit(1);
}

const block = JSON.parse(blockResult.result.json);
const minerTx = block.miner_tx;

console.log('\n=== Block', testHeight, 'Miner TX Analysis ===');
console.log('TX type:', minerTx.type);
console.log('Output count:', minerTx.vout?.length || 0);

// Parse the extra field to get txPubKey
let txPubKey = null;
if (Array.isArray(minerTx.extra) && minerTx.extra.length >= 33) {
  // First byte is tag (0x01 for tx_pubkey)
  if (minerTx.extra[0] === 1) {
    txPubKey = new Uint8Array(minerTx.extra.slice(1, 33));
    console.log('txPubKey (D_e):', bytesToHex(txPubKey));
  }
}

// Check the first output
if (minerTx.vout && minerTx.vout.length > 0) {
  const output = minerTx.vout[0];
  const target = output.target;

  console.log('\nFirst output:');
  console.log('  Amount:', output.amount);
  console.log('  Target type:', target ? Object.keys(target).join(',') : 'null');

  // CARROT outputs use carrot_v1 format
  if (target?.carrot_v1) {
    const carrotOutput = target.carrot_v1;
    console.log('  Key:', carrotOutput.key);
    console.log('  Asset type:', carrotOutput.asset_type);
    console.log('  View tag (hex):', carrotOutput.view_tag);
    console.log('  Encrypted janus anchor:', carrotOutput.encrypted_janus_anchor);

    // This is a CARROT output! Let's test the view tag computation
    if (txPubKey) {
      console.log('\n--- Testing CARROT View Tag Computation ---');

      // Compute the shared secret: s_sr = k_vi * D_e
      const sharedSecret = carrotEcdhKeyExchange(
        viewIncomingKeyBytes,
        txPubKey
      );
      console.log('Shared secret (s_sr):', bytesToHex(sharedSecret));

      // Build input context for coinbase
      const inputContext = makeInputContextCoinbase(testHeight);
      console.log('Input context:', bytesToHex(inputContext));

      // Get the one-time address from the output
      const onetimeAddress = hexToBytes(carrotOutput.key);
      console.log('One-time address (Ko):', carrotOutput.key);

      // Compute expected view tag
      const expectedViewTag = computeCarrotViewTag(sharedSecret, inputContext, onetimeAddress);
      const expectedViewTagHex = bytesToHex(expectedViewTag);
      console.log('Expected view tag (hex):', expectedViewTagHex);
      console.log('Actual view tag (hex):', carrotOutput.view_tag);

      // Check if it matches
      const viewTagMatch = expectedViewTagHex === carrotOutput.view_tag;
      console.log('View tag match:', viewTagMatch ? 'YES' : 'NO');
    }
  } else if (target?.tagged_key) {
    // Pre-CARROT CryptoNote format
    console.log('  (CryptoNote format - pre-hardfork)');
    console.log('  Key:', target.tagged_key.key);
    console.log('  View tag:', target.tagged_key.view_tag);
  }
}

// Also test with a transaction that has key images (non-coinbase)
console.log('\n\n=== Testing Non-Coinbase TX ===');

// Get a block with regular transactions
const testHeight2 = 405590; // The block with the 10 SAL transaction
console.log(`Fetching block ${testHeight2}...`);

const blockResult2 = await daemon.getBlock({ height: testHeight2 });

if (blockResult2.success && blockResult2.result?.json) {
  const block2 = JSON.parse(blockResult2.result.json);
  console.log('TX hashes count:', block2.tx_hashes?.length || 0);

  // If there are transactions, fetch the first one
  if (block2.tx_hashes && block2.tx_hashes.length > 0) {
    console.log('First TX hash:', block2.tx_hashes[0]);

    // Fetch the actual transaction
    const txResult = await daemon.getTransactions([block2.tx_hashes[0]], { decode_as_json: true });
    if (txResult.success && txResult.txs?.length > 0) {
      const txData = txResult.txs[0];
      const tx = JSON.parse(txData.as_json);

      console.log('\nFirst regular TX:');
      console.log('  Type:', tx.type);
      console.log('  Output count:', tx.vout?.length || 0);
      console.log('  Has rct_signatures:', !!tx.rct_signatures);

      // Check if we have p_r in rct_signatures
      if (tx.rct_signatures?.p_r) {
        console.log('  p_r (enote_ephemeral_pubkey):', tx.rct_signatures.p_r);
      }

      if (tx.vout && tx.vout[0]?.target?.tagged_key) {
        console.log('  First output view_tag:', tx.vout[0].target.tagged_key.view_tag);
      }
    }
  }
}

console.log('\n=== End of Test ===');
