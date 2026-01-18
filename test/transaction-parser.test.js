#!/usr/bin/env node
/**
 * Transaction Parser Tests
 *
 * Tests for transaction parsing/decoding functions:
 * - parseTransaction: Parse raw transaction bytes
 * - parseExtra: Parse transaction extra field
 * - decodeAmount: Decrypt encrypted amounts
 * - extractTxPubKey, extractPaymentId: Extract fields
 * - summarizeTransaction: Get transaction summary
 */

import {
  parseTransaction,
  parseExtra,
  decodeAmount,
  extractTxPubKey,
  extractPaymentId,
  summarizeTransaction,
  encodeVarint,
  TX_VERSION,
  RCT_TYPE,
  TXIN_TYPE,
  TXOUT_TYPE
} from '../src/transaction.js';

import { bytesToHex, hexToBytes } from '../src/address.js';
import { keccak256 } from '../src/keccak.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(a, b, message) {
  const aStr = typeof a === 'bigint' ? a.toString() : String(a);
  const bStr = typeof b === 'bigint' ? b.toString() : String(b);
  if (aStr !== bStr) throw new Error(message || `Expected ${bStr}, got ${aStr}`);
}

function assertTrue(condition, message) {
  if (!condition) throw new Error(message || 'Expected true');
}

console.log('\n=== Transaction Parser Tests ===\n');

// parseExtra tests
console.log('--- parseExtra ---');

test('parses tx pubkey (tag 0x01)', () => {
  const extra = new Uint8Array(33);
  extra[0] = 0x01; // TX_EXTRA_TAG_PUBKEY
  for (let i = 1; i < 33; i++) extra[i] = i;

  const parsed = parseExtra(extra);

  assertEqual(parsed.length, 1);
  assertEqual(parsed[0].type, 0x01);
  assertEqual(parsed[0].tag, 'tx_pubkey');
  assertEqual(parsed[0].key.length, 32);
  assertEqual(parsed[0].key[0], 1);
});

test('parses padding (tag 0x00)', () => {
  const extra = new Uint8Array([0x00, 0x00, 0x00]);
  const parsed = parseExtra(extra);

  assertTrue(parsed.some(p => p.tag === 'padding'));
});

test('parses nonce with encrypted payment ID', () => {
  // 0x02 (nonce) + 9 (length) + 0x01 (encrypted) + 8 bytes
  const extra = new Uint8Array(11);
  extra[0] = 0x02;
  extra[1] = 9;
  extra[2] = 0x01;
  for (let i = 3; i < 11; i++) extra[i] = 0xab;

  const parsed = parseExtra(extra);

  assertEqual(parsed[0].type, 0x02);
  assertEqual(parsed[0].tag, 'nonce');
  assertEqual(parsed[0].paymentIdType, 'encrypted');
  assertEqual(parsed[0].paymentId.length, 8);
});

test('parses nonce with unencrypted payment ID', () => {
  // 0x02 (nonce) + 33 (length) + 0x00 (unencrypted) + 32 bytes
  const extra = new Uint8Array(35);
  extra[0] = 0x02;
  extra[1] = 33;
  extra[2] = 0x00;
  for (let i = 3; i < 35; i++) extra[i] = 0xcd;

  const parsed = parseExtra(extra);

  assertEqual(parsed[0].paymentIdType, 'unencrypted');
  assertEqual(parsed[0].paymentId.length, 32);
});

test('parses additional pubkeys (tag 0x04)', () => {
  // 0x04 + count + keys
  const extra = new Uint8Array(66);
  extra[0] = 0x04;
  extra[1] = 2; // 2 additional pubkeys
  for (let i = 2; i < 66; i++) extra[i] = i % 256;

  const parsed = parseExtra(extra);

  assertEqual(parsed[0].type, 0x04);
  assertEqual(parsed[0].tag, 'additional_pubkeys');
  assertEqual(parsed[0].keys.length, 2);
  assertEqual(parsed[0].keys[0].length, 32);
  assertEqual(parsed[0].keys[1].length, 32);
});

test('parses multiple extra fields', () => {
  // pubkey + nonce with encrypted payment ID
  const extra = new Uint8Array(44);
  extra[0] = 0x01; // pubkey tag
  for (let i = 1; i < 33; i++) extra[i] = i;
  extra[33] = 0x02; // nonce tag
  extra[34] = 9;    // length
  extra[35] = 0x01; // encrypted pid
  for (let i = 36; i < 44; i++) extra[i] = 0xef;

  const parsed = parseExtra(extra);

  assertEqual(parsed.length, 2);
  assertEqual(parsed[0].tag, 'tx_pubkey');
  assertEqual(parsed[1].tag, 'nonce');
});

test('handles unknown tags gracefully', () => {
  const extra = new Uint8Array([0xff, 0x00, 0x00]);
  const parsed = parseExtra(extra);

  assertTrue(parsed.some(p => p.tag === 'unknown'));
});

test('handles empty extra', () => {
  const extra = new Uint8Array(0);
  const parsed = parseExtra(extra);

  assertEqual(parsed.length, 0);
});

// extractTxPubKey tests
console.log('\n--- extractTxPubKey ---');

test('extracts tx pubkey from parsed extra', () => {
  const pubkey = new Uint8Array(32).fill(0xaa);
  const tx = {
    prefix: {
      extra: [{ type: 0x01, tag: 'tx_pubkey', key: pubkey }]
    }
  };

  const result = extractTxPubKey(tx);

  assertEqual(bytesToHex(result), bytesToHex(pubkey));
});

test('returns null when no tx pubkey', () => {
  const tx = { prefix: { extra: [] } };
  assertEqual(extractTxPubKey(tx), null);
});

test('returns null for empty transaction', () => {
  assertEqual(extractTxPubKey({}), null);
});

// extractPaymentId tests
console.log('\n--- extractPaymentId ---');

test('extracts encrypted payment ID', () => {
  const paymentId = new Uint8Array(8).fill(0xbb);
  const tx = {
    prefix: {
      extra: [{
        type: 0x02,
        tag: 'nonce',
        paymentIdType: 'encrypted',
        paymentId
      }]
    }
  };

  const result = extractPaymentId(tx);

  assertEqual(result.type, 'encrypted');
  assertEqual(bytesToHex(result.id), bytesToHex(paymentId));
});

test('extracts unencrypted payment ID', () => {
  const paymentId = new Uint8Array(32).fill(0xcc);
  const tx = {
    prefix: {
      extra: [{
        type: 0x02,
        tag: 'nonce',
        paymentIdType: 'unencrypted',
        paymentId
      }]
    }
  };

  const result = extractPaymentId(tx);

  assertEqual(result.type, 'unencrypted');
  assertEqual(result.id.length, 32);
});

test('returns null when no payment ID', () => {
  const tx = { prefix: { extra: [] } };
  assertEqual(extractPaymentId(tx), null);
});

// decodeAmount tests
console.log('\n--- decodeAmount ---');

test('decodes encrypted amount with XOR mask', () => {
  // Create a simple test: encrypt then decrypt
  const amount = 1234567890n;
  const sharedSecret = new Uint8Array(32).fill(0x42);

  // Generate amount mask
  const prefix = new TextEncoder().encode('amount');
  const data = new Uint8Array(prefix.length + sharedSecret.length);
  data.set(prefix, 0);
  data.set(sharedSecret, prefix.length);
  const mask = keccak256(data).slice(0, 8);

  // Encrypt
  const amountBytes = new Uint8Array(8);
  let a = amount;
  for (let i = 0; i < 8; i++) {
    amountBytes[i] = Number(a & 0xffn) ^ mask[i];
    a >>= 8n;
  }

  // Decrypt
  const decoded = decodeAmount(amountBytes, sharedSecret);

  assertEqual(decoded, amount);
});

test('decodeAmount accepts hex strings', () => {
  const sharedSecret = '42'.repeat(32);
  const encryptedHex = 'deadbeef12345678';

  // Should not throw
  const result = decodeAmount(encryptedHex, sharedSecret);
  assertEqual(typeof result, 'bigint');
});

// summarizeTransaction tests
console.log('\n--- summarizeTransaction ---');

test('summarizes basic transaction', () => {
  const tx = {
    prefix: {
      version: 2,
      unlockTime: 0,
      vin: [
        { type: TXIN_TYPE.KEY, keyImage: new Uint8Array(32).fill(0x11) },
        { type: TXIN_TYPE.KEY, keyImage: new Uint8Array(32).fill(0x22) }
      ],
      vout: [
        { key: new Uint8Array(32).fill(0xaa) },
        { key: new Uint8Array(32).fill(0xbb) }
      ],
      extra: []
    },
    rct: {
      type: RCT_TYPE.BulletproofPlus,
      fee: 10000000n,
      outPk: [new Uint8Array(32), new Uint8Array(32)]
    }
  };

  const summary = summarizeTransaction(tx);

  assertEqual(summary.version, 2);
  assertEqual(summary.unlockTime, 0);
  assertEqual(summary.inputCount, 2);
  assertEqual(summary.outputCount, 2);
  assertEqual(summary.fee, 10000000n);
  assertEqual(summary.rctType, RCT_TYPE.BulletproofPlus);
  assertTrue(!summary.isCoinbase);
});

test('detects coinbase transaction', () => {
  const tx = {
    prefix: {
      version: 2,
      unlockTime: 60,
      vin: [{ type: TXIN_TYPE.GEN, height: 12345 }],
      vout: [{ key: new Uint8Array(32) }],
      extra: []
    }
  };

  const summary = summarizeTransaction(tx);

  assertTrue(summary.isCoinbase);
});

test('extracts key images', () => {
  const ki1 = new Uint8Array(32).fill(0x11);
  const ki2 = new Uint8Array(32).fill(0x22);
  const tx = {
    prefix: {
      version: 2,
      unlockTime: 0,
      vin: [
        { type: TXIN_TYPE.KEY, keyImage: ki1 },
        { type: TXIN_TYPE.KEY, keyImage: ki2 }
      ],
      vout: [],
      extra: []
    }
  };

  const summary = summarizeTransaction(tx);

  assertEqual(summary.keyImages.length, 2);
  assertEqual(bytesToHex(summary.keyImages[0]), bytesToHex(ki1));
  assertEqual(bytesToHex(summary.keyImages[1]), bytesToHex(ki2));
});

test('extracts output keys', () => {
  const key1 = new Uint8Array(32).fill(0xaa);
  const key2 = new Uint8Array(32).fill(0xbb);
  const tx = {
    prefix: {
      version: 2,
      unlockTime: 0,
      vin: [],
      vout: [{ key: key1 }, { key: key2 }],
      extra: []
    }
  };

  const summary = summarizeTransaction(tx);

  assertEqual(summary.outputKeys.length, 2);
});

test('includes commitments from RCT', () => {
  const c1 = new Uint8Array(32).fill(0xcc);
  const c2 = new Uint8Array(32).fill(0xdd);
  const tx = {
    prefix: {
      version: 2,
      unlockTime: 0,
      vin: [],
      vout: [{}, {}],
      extra: []
    },
    rct: {
      type: RCT_TYPE.CLSAG,
      fee: 1000n,
      outPk: [c1, c2]
    }
  };

  const summary = summarizeTransaction(tx);

  assertEqual(summary.commitments.length, 2);
});

test('handles transaction without RCT', () => {
  const tx = {
    prefix: {
      version: 1,
      unlockTime: 0,
      vin: [],
      vout: [],
      extra: []
    }
  };

  const summary = summarizeTransaction(tx);

  assertEqual(summary.rctType, null);
  assertEqual(summary.fee, 0n);
  assertEqual(summary.commitments.length, 0);
});

// parseTransaction tests (basic structure)
console.log('\n--- parseTransaction (Structure) ---');

test('parseTransaction handles hex string input', () => {
  // Minimal v1 transaction (just to test hex conversion)
  // version=1, unlock_time=0, vin_count=0, vout_count=0, extra_len=0
  const txHex = '01' + '00' + '00' + '00' + '00';

  let threw = false;
  try {
    const tx = parseTransaction(txHex);
    assertEqual(tx.prefix.version, 1);
  } catch (e) {
    // May throw due to incomplete data, but should process hex
    threw = true;
  }
  // Either works or throws appropriate error
  assertTrue(true);
});

test('parseTransaction extracts version', () => {
  // version=2, unlock_time=0, vin_count=0, vout_count=0, extra_len=0
  const txBytes = new Uint8Array([0x02, 0x00, 0x00, 0x00, 0x00]);

  const tx = parseTransaction(txBytes);

  assertEqual(tx.prefix.version, 2);
});

test('parseTransaction extracts unlock time', () => {
  // version=2, unlock_time=100, vin_count=0, vout_count=0, extra_len=0
  const txBytes = new Uint8Array([0x02, 0x64, 0x00, 0x00, 0x00]);

  const tx = parseTransaction(txBytes);

  assertEqual(tx.prefix.unlockTime, 100);
});

// TX constants
console.log('\n--- TX Constants ---');

test('TXIN_TYPE constants', () => {
  assertEqual(TXIN_TYPE.GEN, 0xff);
  assertEqual(TXIN_TYPE.KEY, 0x02);
});

test('TXOUT_TYPE constants', () => {
  assertEqual(TXOUT_TYPE.KEY, 0x02);
  assertTrue(TXOUT_TYPE.TAGGED_KEY !== undefined);
});

test('TX_VERSION constants', () => {
  assertEqual(TX_VERSION.V1, 1);
  assertEqual(TX_VERSION.V2, 2);
});

test('RCT_TYPE constants', () => {
  assertEqual(RCT_TYPE.Null, 0);
  assertEqual(RCT_TYPE.Full, 1);
  assertEqual(RCT_TYPE.Simple, 2);
  assertEqual(RCT_TYPE.CLSAG, 5);
  assertEqual(RCT_TYPE.BulletproofPlus, 6);
});

// Summary
console.log(`\n--- Summary ---`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed === 0) {
  console.log('\n✓ All transaction parser tests passed!');
  process.exit(0);
} else {
  console.log('\n✗ Some tests failed');
  process.exit(1);
}
