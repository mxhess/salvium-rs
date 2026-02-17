#!/usr/bin/env bun
/**
 * Verify CARROT detection with real transaction
 *
 * Usage:
 *   SPEND_SECRET="64-char-hex" TX_HASH="tx-hash" bun test/verify-real-carrot.js
 *
 * Environment variables:
 *   SPEND_SECRET - 64-character hex spend secret key (required)
 *   TX_HASH - Transaction hash to verify (required)
 *   DAEMON_URL - Daemon RPC URL (default: http://seed01.salvium.io:19081)
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { deriveKeys, deriveCarrotKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import {
  x25519ScalarMult,
  carrotEcdhKeyExchange,
  computeCarrotViewTag,
  makeInputContext
} from '../src/carrot-scanning.js';

const SPEND_SECRET = process.env.SPEND_SECRET;
const TX_HASH = process.env.TX_HASH;
const DAEMON_URL = process.env.DAEMON_URL || 'http://seed01.salvium.io:19081';

if (!SPEND_SECRET || !TX_HASH) {
  console.error('ERROR: SPEND_SECRET and TX_HASH environment variables required.\n');
  console.log('Usage:');
  console.log('  SPEND_SECRET="64-char-hex" TX_HASH="tx-hash" bun test/verify-real-carrot.js');
  process.exit(1);
}

console.log('=== Verify Real CARROT Transaction ===\n');

// 1. Derive wallet keys
console.log('1. Deriving wallet keys...');
const spendSecret = hexToBytes(SPEND_SECRET);
const cnKeys = deriveKeys(spendSecret);
const carrotKeys = deriveCarrotKeys(spendSecret);

console.log('   Spend secret: [from env]');
console.log('   View-incoming key (k_vi):', carrotKeys.viewIncomingKey);
console.log('   Account spend pubkey (K_s):', carrotKeys.accountSpendPubkey);

// 2. Fetch the transaction
console.log('\n2. Fetching transaction...');
const daemon = new DaemonRPC({ url: DAEMON_URL });

const txResult = await daemon.getTransactions([TX_HASH], { decode_as_json: true });
if (!txResult.success || !txResult.result?.txs?.length) {
  console.log('Failed to fetch transaction:', txResult);
  process.exit(1);
}

const txData = txResult.result.txs[0];
const tx = JSON.parse(txData.as_json);

console.log('   TX type:', tx.type);
console.log('   Output count:', tx.vout?.length);
console.log('   Has rct_signatures:', !!tx.rct_signatures);

// 3. Extract D_e (enote ephemeral pubkey)
console.log('\n3. Extracting D_e...');

// For CARROT, D_e is stored in tx_extra as tx_pubkey (tag 0x01)
// The rct_signatures.p_r is something else (possibly for different purpose)
let D_e = null;
let D_e_additional = []; // For per-output pubkeys

if (Array.isArray(tx.extra)) {
  const extra = new Uint8Array(tx.extra);
  let i = 0;
  while (i < extra.length) {
    const tag = extra[i];
    if (tag === 0x01 && i + 33 <= extra.length) {
      // TX_EXTRA_TAG_PUBKEY - shared D_e
      D_e = extra.slice(i + 1, i + 33);
      console.log('   D_e from tx_extra:', bytesToHex(D_e));
      i += 33;
    } else if (tag === 0x04 && i + 2 <= extra.length) {
      // TX_EXTRA_TAG_ADDITIONAL_PUBKEYS - per-output D_e
      const count = extra[i + 1];
      console.log('   Additional pubkeys count:', count);
      for (let j = 0; j < count && i + 2 + (j + 1) * 32 <= extra.length; j++) {
        const pk = extra.slice(i + 2 + j * 32, i + 2 + (j + 1) * 32);
        D_e_additional.push(pk);
        console.log('     D_e[' + j + ']:', bytesToHex(pk));
      }
      i += 2 + count * 32;
    } else if (tag === 0x02 && i + 2 <= extra.length) {
      // TX_EXTRA_NONCE
      const len = extra[i + 1];
      i += 2 + len;
    } else {
      break;
    }
  }
}

// Also show p_r for reference
if (tx.rct_signatures?.p_r) {
  console.log('   p_r (for reference):', tx.rct_signatures.p_r);
}

if (!D_e && D_e_additional.length === 0) {
  console.log('   ERROR: Could not find D_e');
  process.exit(1);
}

// 4. Extract first key image for input context
console.log('\n4. Building input context...');
let firstKeyImage = null;
if (tx.vin && tx.vin[0]?.key?.k_image) {
  firstKeyImage = tx.vin[0].key.k_image;
  console.log('   First key image:', firstKeyImage);
}

const inputContext = makeInputContext(firstKeyImage);
console.log('   Input context:', bytesToHex(inputContext));

// 5. Check each output
console.log('\n5. Scanning outputs...');

const k_vi = hexToBytes(carrotKeys.viewIncomingKey);

for (let i = 0; i < tx.vout.length; i++) {
  const output = tx.vout[i];
  const target = output.target;

  console.log(`\n   Output ${i}:`);
  console.log('     Target type:', Object.keys(target || {}));

  if (target?.carrot_v1) {
    const carrot = target.carrot_v1;
    console.log('     Ko:', carrot.key);
    console.log('     View tag:', carrot.view_tag);
    console.log('     Asset:', carrot.asset_type);

    const Ko = hexToBytes(carrot.key);

    // Use shared D_e or per-output D_e if available
    const outputD_e = D_e_additional.length > i ? D_e_additional[i] : D_e;
    console.log('     Using D_e:', bytesToHex(outputD_e));

    // Compute shared secret
    const s_sr = carrotEcdhKeyExchange(k_vi, outputD_e);
    console.log('     Computed s_sr:', bytesToHex(s_sr));

    // Compute expected view tag
    const expectedViewTag = computeCarrotViewTag(s_sr, inputContext, Ko);
    console.log('     Expected view tag:', bytesToHex(expectedViewTag));
    console.log('     Actual view tag:', carrot.view_tag);

    const match = bytesToHex(expectedViewTag) === carrot.view_tag;
    console.log('     VIEW TAG MATCH:', match ? 'YES ✓' : 'NO ✗');

    if (match) {
      console.log('\n   >>> OUTPUT DETECTED! This is our CARROT output! <<<');
    }
  }
}

console.log('\n=== End of Test ===');
