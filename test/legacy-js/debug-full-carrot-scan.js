#!/usr/bin/env bun
/**
 * Debug full CARROT scan flow
 *
 * Usage:
 *   SPEND_SECRET="64-char-hex" TX_HASH="tx-hash" bun test/debug-full-carrot-scan.js
 *
 * Environment variables:
 *   SPEND_SECRET - 64-character hex spend secret key (required)
 *   TX_HASH - Transaction hash to scan (required)
 *   DAEMON_URL - Daemon RPC URL (default: http://seed01.salvium.io:19081)
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { deriveKeys, deriveCarrotKeys } from '../src/carrot.js';
import { generateCarrotSubaddressMap } from '../src/subaddress.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import {
  carrotEcdhKeyExchange,
  computeCarrotViewTag,
  makeInputContext,
  makeCarrotSenderReceiverSecret,
  recoverAddressSpendPubkey
} from '../src/carrot-scanning.js';

const SPEND_SECRET = process.env.SPEND_SECRET;
const TX_HASH = process.env.TX_HASH;
const DAEMON_URL = process.env.DAEMON_URL || 'http://seed01.salvium.io:19081';

if (!SPEND_SECRET || !TX_HASH) {
  console.error('ERROR: SPEND_SECRET and TX_HASH environment variables required.\n');
  console.log('Usage:');
  console.log('  SPEND_SECRET="64-char-hex" TX_HASH="tx-hash" bun test/debug-full-carrot-scan.js');
  process.exit(1);
}

console.log('=== Full CARROT Scan Debug ===\n');

// 1. Derive keys
const spendSecret = hexToBytes(SPEND_SECRET);
const cnKeys = deriveKeys(spendSecret);
const carrotKeys = deriveCarrotKeys(spendSecret);

console.log('1. Wallet Keys:');
console.log('   k_vi:', carrotKeys.viewIncomingKey);
console.log('   K_s:', carrotKeys.accountSpendPubkey);

// 2. Generate subaddress map
console.log('\n2. Generating subaddress map...');
const subaddressMap = generateCarrotSubaddressMap(
  hexToBytes(carrotKeys.accountSpendPubkey),
  hexToBytes(carrotKeys.accountViewPubkey),
  hexToBytes(carrotKeys.generateAddressSecret),
  50, 200
);
console.log('   Map size:', subaddressMap.size);

// Check if subaddress (0,1) is in the map
let found01 = null;
for (const [key, idx] of subaddressMap.entries()) {
  if (idx.major === 0 && idx.minor === 1) {
    found01 = key;
    break;
  }
}
console.log('   Subaddress (0,1) K_s:', found01 || 'NOT FOUND');

// 3. Fetch transaction
console.log('\n3. Fetching transaction...');
const daemon = new DaemonRPC({ url: DAEMON_URL });
const txResult = await daemon.getTransactions([TX_HASH], { decode_as_json: true });
const tx = JSON.parse(txResult.result.txs[0].as_json);

// Extract D_e from tx_extra
const extra = new Uint8Array(tx.extra);
let D_e = null;
if (extra[0] === 0x01) {
  D_e = extra.slice(1, 33);
}
console.log('   D_e:', bytesToHex(D_e));

// Extract first key image
const firstKeyImage = tx.vin[0].key.k_image;
console.log('   First key image:', firstKeyImage);

// Build input context
const inputContext = makeInputContext(firstKeyImage);
console.log('   Input context:', bytesToHex(inputContext));

// 4. Process output 1 (the 10 SAL output)
console.log('\n4. Processing Output 1:');
const output = tx.vout[1];
const carrot = output.target.carrot_v1;

const Ko = hexToBytes(carrot.key);
const viewTagActual = hexToBytes(carrot.view_tag);
const commitment = tx.rct_signatures.outPk ? hexToBytes(tx.rct_signatures.outPk[1]) : null;

console.log('   Ko:', carrot.key);
console.log('   View tag:', carrot.view_tag);
console.log('   Commitment:', commitment ? bytesToHex(commitment) : 'NULL');

// 5. Compute shared secret
console.log('\n5. Computing shared secret:');
const k_vi = hexToBytes(carrotKeys.viewIncomingKey);
const s_sr_unctx = carrotEcdhKeyExchange(k_vi, D_e);
console.log('   s_sr_unctx:', bytesToHex(s_sr_unctx));

// 6. Compute view tag
console.log('\n6. Verifying view tag:');
const viewTagExpected = computeCarrotViewTag(s_sr_unctx, inputContext, Ko);
console.log('   Expected:', bytesToHex(viewTagExpected));
console.log('   Actual:', carrot.view_tag);
console.log('   Match:', bytesToHex(viewTagExpected) === carrot.view_tag ? 'YES ✓' : 'NO ✗');

if (bytesToHex(viewTagExpected) !== carrot.view_tag) {
  console.log('\n   VIEW TAG MISMATCH - stopping here');
  process.exit(1);
}

// 7. Compute contextualized shared secret
console.log('\n7. Computing contextualized shared secret:');
const s_sr_ctx = makeCarrotSenderReceiverSecret(s_sr_unctx, D_e, inputContext);
console.log('   s_sr_ctx:', bytesToHex(s_sr_ctx));

// 8. Recover address spend pubkey
console.log('\n8. Recovering address spend pubkey:');
const K_s_recovered = recoverAddressSpendPubkey(Ko, s_sr_ctx, commitment || new Uint8Array(32));
const K_s_recovered_hex = bytesToHex(K_s_recovered);
console.log('   Recovered K_s:', K_s_recovered_hex);
console.log('   Main address K_s:', carrotKeys.accountSpendPubkey);
console.log('   Match main:', K_s_recovered_hex === carrotKeys.accountSpendPubkey ? 'YES' : 'NO');

// 9. Check subaddress map
console.log('\n9. Checking subaddress map:');
const subaddrIdx = subaddressMap.get(K_s_recovered_hex);
if (subaddrIdx) {
  console.log('   FOUND! Subaddress index:', subaddrIdx);
} else {
  console.log('   NOT FOUND in subaddress map');
  console.log('   Looking for similar keys...');

  // Check first few entries
  let count = 0;
  for (const [key, idx] of subaddressMap.entries()) {
    if (count < 5 || (idx.major === 0 && idx.minor <= 5)) {
      console.log(`     (${idx.major},${idx.minor}): ${key.slice(0, 32)}...`);
    }
    count++;
  }
}

console.log('\n=== End Debug ===');
