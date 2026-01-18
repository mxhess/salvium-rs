#!/usr/bin/env bun
/**
 * Multisig Tests
 *
 * Tests for multisig.js:
 * - Constants
 * - KEX rounds calculation
 * - KexMessage serialization
 * - MultisigSigner
 * - MultisigAccount
 * - MultisigTxSet
 * - MultisigPartialSig
 * - MultisigWallet
 * - Helper functions
 */

import {
  MULTISIG_MAX_SIGNERS,
  MULTISIG_MIN_THRESHOLD,
  MULTISIG_NONCE_COMPONENTS,
  MULTISIG_MSG_TYPE,
  kexRoundsRequired,
  getMultisigBlindedSecretKey,
  computeDHSecret,
  generateMultisigNonces,
  KexMessage,
  MultisigSigner,
  MultisigAccount,
  MultisigTxSet,
  MultisigPartialSig,
  MultisigWallet,
  createMultisigWallet,
  isMultisig
} from '../src/multisig.js';

import { bytesToHex } from '../src/address.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

// Helper to create test keys
function createTestKeys() {
  return {
    spendSecretKey: new Uint8Array(32).fill(0x11),
    viewSecretKey: new Uint8Array(32).fill(0x22)
  };
}

console.log('=== Multisig Tests ===\n');

// ============================================================================
// Constants Tests
// ============================================================================

console.log('--- Constants ---');

test('MULTISIG_MAX_SIGNERS is 16', () => {
  assertEqual(MULTISIG_MAX_SIGNERS, 16);
});

test('MULTISIG_MIN_THRESHOLD is 2', () => {
  assertEqual(MULTISIG_MIN_THRESHOLD, 2);
});

test('MULTISIG_NONCE_COMPONENTS is 2', () => {
  assertEqual(MULTISIG_NONCE_COMPONENTS, 2);
});

test('MULTISIG_MSG_TYPE has correct values', () => {
  assertEqual(MULTISIG_MSG_TYPE.KEX_INIT, 'kex_init');
  assertEqual(MULTISIG_MSG_TYPE.KEX_ROUND, 'kex_round');
  assertEqual(MULTISIG_MSG_TYPE.KEX_VERIFY, 'kex_verify');
  assertEqual(MULTISIG_MSG_TYPE.TX_SET, 'tx_set');
  assertEqual(MULTISIG_MSG_TYPE.PARTIAL_SIG, 'partial_sig');
  assertEqual(MULTISIG_MSG_TYPE.FINAL_TX, 'final_tx');
});

// ============================================================================
// KEX Rounds Required Tests
// ============================================================================

console.log('\n--- KEX Rounds Required ---');

test('kexRoundsRequired returns N for any M-of-N', () => {
  // According to implementation, kexRoundsRequired returns signers count
  assertEqual(kexRoundsRequired(2, 2), 2);
  assertEqual(kexRoundsRequired(2, 3), 3);
  assertEqual(kexRoundsRequired(3, 3), 3);
  assertEqual(kexRoundsRequired(2, 4), 4);
  assertEqual(kexRoundsRequired(3, 4), 4);
  assertEqual(kexRoundsRequired(4, 4), 4);
});

test('kexRoundsRequired handles edge cases', () => {
  // 5-of-5
  assertEqual(kexRoundsRequired(5, 5), 5);
  // 2-of-10
  assertEqual(kexRoundsRequired(2, 10), 10);
});

// ============================================================================
// KexMessage Tests
// ============================================================================

console.log('\n--- KexMessage ---');

test('creates KexMessage with default values', () => {
  const msg = new KexMessage();

  assertEqual(msg.round, 0);
  assertEqual(msg.signerIndex, 0);
  assertEqual(msg.publicKey, null);
  assertEqual(msg.commonPubkey, null);
  assertEqual(msg.dhPubkeys.length, 0);
  assertEqual(msg.signature, null);
});

test('KexMessage serialize/deserialize round-trips', () => {
  const msg = new KexMessage();
  msg.round = 1;
  msg.signerIndex = 0;
  msg.publicKey = new Uint8Array(32).fill(0xaa);
  msg.commonPubkey = new Uint8Array(32).fill(0xbb);
  msg.dhPubkeys = [
    new Uint8Array(32).fill(0xcc),
    new Uint8Array(32).fill(0xdd)
  ];

  const serialized = msg.serialize();
  const restored = KexMessage.deserialize(serialized);

  assertEqual(restored.round, msg.round);
  assertEqual(restored.signerIndex, msg.signerIndex);
  assertEqual(bytesToHex(restored.publicKey), bytesToHex(msg.publicKey));
  assertEqual(bytesToHex(restored.commonPubkey), bytesToHex(msg.commonPubkey));
  assertEqual(restored.dhPubkeys.length, 2);
});

test('KexMessage toString/fromString round-trips', () => {
  const msg = new KexMessage();
  msg.round = 2;
  msg.signerIndex = 1;
  msg.publicKey = new Uint8Array(32).fill(0x11);
  msg.commonPubkey = new Uint8Array(32).fill(0x22);

  const str = msg.toString();
  const restored = KexMessage.fromString(str);

  assertEqual(restored.round, msg.round);
  assertEqual(restored.signerIndex, msg.signerIndex);
});

// ============================================================================
// MultisigSigner Tests
// ============================================================================

console.log('\n--- MultisigSigner ---');

test('creates MultisigSigner with defaults', () => {
  const signer = new MultisigSigner();

  assertEqual(signer.index, 0);
  assertEqual(signer.publicSpendKey, null);
  assertEqual(signer.publicViewKey, null);
  assertEqual(signer.label, '');
});

test('creates MultisigSigner with config', () => {
  const signer = new MultisigSigner({
    index: 1,
    publicSpendKey: new Uint8Array(32).fill(0xaa),
    publicViewKey: new Uint8Array(32).fill(0xbb),
    label: 'Signer 1'
  });

  assertEqual(signer.index, 1);
  assert(signer.publicSpendKey instanceof Uint8Array);
  assert(signer.publicViewKey instanceof Uint8Array);
  assertEqual(signer.label, 'Signer 1');
});

// ============================================================================
// MultisigAccount Tests
// ============================================================================

console.log('\n--- MultisigAccount ---');

test('creates MultisigAccount with threshold and signerCount', () => {
  const keys = createTestKeys();
  const account = new MultisigAccount({
    threshold: 2,
    signerCount: 3,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  assertEqual(account.threshold, 2);
  assertEqual(account.signerCount, 3);
  assertEqual(account.kexRound, 0);
  assertEqual(account.kexComplete, false);
});

test('MultisigAccount validates threshold minimum', () => {
  const keys = createTestKeys();
  let threw = false;
  try {
    new MultisigAccount({
      threshold: 1,  // Below minimum
      signerCount: 2,
      spendSecretKey: keys.spendSecretKey,
      viewSecretKey: keys.viewSecretKey
    });
  } catch (e) {
    threw = true;
    assert(e.message.includes('threshold') || e.message.includes('2'));
  }
  assert(threw, 'Should throw for threshold < 2');
});

test('MultisigAccount validates threshold <= signerCount', () => {
  const keys = createTestKeys();
  let threw = false;
  try {
    new MultisigAccount({
      threshold: 5,
      signerCount: 3,  // Less than threshold
      spendSecretKey: keys.spendSecretKey,
      viewSecretKey: keys.viewSecretKey
    });
  } catch (e) {
    threw = true;
    assert(e.message.includes('Threshold') || e.message.includes('exceed'));
  }
  assert(threw, 'Should throw for threshold > signerCount');
});

test('MultisigAccount validates max signers', () => {
  const keys = createTestKeys();
  let threw = false;
  try {
    new MultisigAccount({
      threshold: 2,
      signerCount: 20,  // Exceeds max
      spendSecretKey: keys.spendSecretKey,
      viewSecretKey: keys.viewSecretKey
    });
  } catch (e) {
    threw = true;
    assert(e.message.includes('16') || e.message.includes('max'));
  }
  assert(threw, 'Should throw for signerCount > max');
});

test('MultisigAccount initializeKex requires keys', () => {
  const account = new MultisigAccount({
    threshold: 2,
    signerCount: 2
  });

  let threw = false;
  try {
    account.initializeKex();
  } catch (e) {
    threw = true;
    assert(e.message.includes('key') || e.message.includes('Base'));
  }
  assert(threw, 'Should throw without keys');
});

test('MultisigAccount initializeKex returns KexMessage', () => {
  const keys = createTestKeys();
  const account = new MultisigAccount({
    threshold: 2,
    signerCount: 2,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  const msg = account.initializeKex();

  assert(msg instanceof KexMessage, 'Should return KexMessage');
  assertEqual(msg.round, 1);
  assert(msg.publicKey !== null);
  assert(msg.commonPubkey !== null);
  assertEqual(account.kexRound, 1);
});

test('MultisigAccount isKexComplete returns false initially', () => {
  const keys = createTestKeys();
  const account = new MultisigAccount({
    threshold: 2,
    signerCount: 2,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  assertEqual(account.isKexComplete(), false);
});

// ============================================================================
// MultisigTxSet Tests
// ============================================================================

console.log('\n--- MultisigTxSet ---');

test('creates empty MultisigTxSet', () => {
  const txSet = new MultisigTxSet();

  assertEqual(txSet.txs.length, 0);
  assertEqual(txSet.signingAttempts.length, 0);
  assertEqual(txSet.keyImages.length, 0);
});

test('addTransaction adds to txs array', () => {
  const txSet = new MultisigTxSet();

  txSet.addTransaction({ inputs: [], outputs: [], fee: 1000n });
  txSet.addTransaction({ inputs: [], outputs: [], fee: 2000n });

  assertEqual(txSet.txs.length, 2);
});

test('MultisigTxSet serialize/deserialize round-trips', () => {
  const txSet = new MultisigTxSet();
  txSet.addTransaction({
    inputs: [{ amount: 1000 }],
    outputs: [{ amount: 900 }]
  });
  txSet.keyImages.push(new Uint8Array(32).fill(0xaa));

  const serialized = txSet.serialize();
  const restored = MultisigTxSet.deserialize(serialized);

  assertEqual(restored.txs.length, 1);
  assertEqual(restored.keyImages.length, 1);
});

test('MultisigTxSet toString/fromString round-trips', () => {
  const txSet = new MultisigTxSet();
  txSet.addTransaction({ value: 123 });

  const str = txSet.toString();
  const restored = MultisigTxSet.fromString(str);

  assertEqual(restored.txs.length, 1);
  assertEqual(restored.txs[0].value, 123);
});

// ============================================================================
// MultisigPartialSig Tests
// ============================================================================

console.log('\n--- MultisigPartialSig ---');

test('creates MultisigPartialSig with defaults', () => {
  const sig = new MultisigPartialSig();

  assertEqual(sig.signerIndex, 0);
  assertEqual(sig.txIndex, 0);
  assertEqual(sig.responses.length, 0);
  assertEqual(sig.pubNonces.length, 0);
});

test('MultisigPartialSig serialize/deserialize round-trips', () => {
  const sig = new MultisigPartialSig();
  sig.signerIndex = 1;
  sig.txIndex = 0;
  sig.responses = [new Uint8Array(32).fill(0x11)];
  sig.pubNonces = [[new Uint8Array(32).fill(0x22), new Uint8Array(32).fill(0x33)]];

  const serialized = sig.serialize();
  const restored = MultisigPartialSig.deserialize(serialized);

  assertEqual(restored.signerIndex, 1);
  assertEqual(restored.txIndex, 0);
  assertEqual(restored.responses.length, 1);
  assertEqual(restored.pubNonces.length, 1);
});

test('MultisigPartialSig toString/fromString round-trips', () => {
  const sig = new MultisigPartialSig();
  sig.signerIndex = 2;
  sig.txIndex = 1;

  const str = sig.toString();
  const restored = MultisigPartialSig.fromString(str);

  assertEqual(restored.signerIndex, 2);
  assertEqual(restored.txIndex, 1);
});

// ============================================================================
// Helper Functions Tests
// ============================================================================

console.log('\n--- Helper Functions ---');

test('getMultisigBlindedSecretKey returns 32-byte key', () => {
  const secretKey = new Uint8Array(32).fill(0xab);
  const blinded = getMultisigBlindedSecretKey(secretKey);

  assertEqual(blinded.length, 32);
  assert(blinded instanceof Uint8Array);
});

test('getMultisigBlindedSecretKey is deterministic', () => {
  const secretKey = new Uint8Array(32).fill(0xcd);
  const blinded1 = getMultisigBlindedSecretKey(secretKey);
  const blinded2 = getMultisigBlindedSecretKey(secretKey);

  assertEqual(bytesToHex(blinded1), bytesToHex(blinded2));
});

test('getMultisigBlindedSecretKey differs for different keys', () => {
  const key1 = new Uint8Array(32).fill(0x11);
  const key2 = new Uint8Array(32).fill(0x22);

  const blinded1 = getMultisigBlindedSecretKey(key1);
  const blinded2 = getMultisigBlindedSecretKey(key2);

  assert(bytesToHex(blinded1) !== bytesToHex(blinded2));
});

test('computeDHSecret accepts key parameters', () => {
  // Note: computeDHSecret may return null for invalid curve points
  // Test that function accepts parameters without throwing
  const secretKey = new Uint8Array(32).fill(0x01);
  const publicKey = new Uint8Array(32).fill(0x02);

  // This may return null for arbitrary bytes that aren't valid points
  // Just verify it doesn't throw
  const result = computeDHSecret(secretKey, publicKey);

  // Result can be null for invalid points or Uint8Array for valid
  assert(result === null || result instanceof Uint8Array,
    'Should return null or Uint8Array');
});

test('generateMultisigNonces creates correct number', () => {
  const nonces = generateMultisigNonces(3);

  assertEqual(nonces.length, 3);
  // Each nonce should be a pair [alpha1, alpha2]
  assertEqual(nonces[0].length, 2);
  assertEqual(nonces[1].length, 2);
  assertEqual(nonces[2].length, 2);
});

test('generateMultisigNonces creates unique values', () => {
  const nonces = generateMultisigNonces(2);

  const hex1 = bytesToHex(nonces[0][0]);
  const hex2 = bytesToHex(nonces[0][1]);
  const hex3 = bytesToHex(nonces[1][0]);
  const hex4 = bytesToHex(nonces[1][1]);

  // All should be different
  const unique = new Set([hex1, hex2, hex3, hex4]);
  assertEqual(unique.size, 4);
});

// ============================================================================
// isMultisig Tests
// ============================================================================

console.log('\n--- isMultisig ---');

test('isMultisig returns false for regular object', () => {
  assertEqual(isMultisig({}), false);
  assertEqual(isMultisig(null), false);
  assertEqual(isMultisig({ balance: 100 }), false);
});

test('isMultisig returns true for MultisigWallet', () => {
  const keys = createTestKeys();
  const wallet = new MultisigWallet({
    threshold: 2,
    signerCount: 2,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  assertEqual(isMultisig(wallet), true);
});

test('isMultisig returns true for object with isMultisig flag', () => {
  assertEqual(isMultisig({ isMultisig: true }), true);
  assertEqual(isMultisig({ isMultisig: false }), false);
});

// ============================================================================
// MultisigWallet Tests
// ============================================================================

console.log('\n--- MultisigWallet ---');

test('creates MultisigWallet with config', () => {
  const keys = createTestKeys();
  const wallet = new MultisigWallet({
    threshold: 2,
    signerCount: 3,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  assertEqual(wallet.getThreshold(), 2);
  assertEqual(wallet.getSignerCount(), 3);
  assertEqual(wallet.isReady(), false);
});

test('MultisigWallet getFirstKexMessage returns string', () => {
  const keys = createTestKeys();
  const wallet = new MultisigWallet({
    threshold: 2,
    signerCount: 2,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  const msg = wallet.getFirstKexMessage();

  assertEqual(typeof msg, 'string');
  assert(msg.length > 0);
});

test('MultisigWallet isReady returns false before KEX complete', () => {
  const keys = createTestKeys();
  const wallet = new MultisigWallet({
    threshold: 2,
    signerCount: 2,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  wallet.getFirstKexMessage();
  assertEqual(wallet.isReady(), false);
});

// ============================================================================
// createMultisigWallet Tests
// ============================================================================

console.log('\n--- createMultisigWallet ---');

test('createMultisigWallet returns MultisigWallet', () => {
  const keys = createTestKeys();
  const wallet = createMultisigWallet({
    threshold: 2,
    signerCount: 2,
    spendSecretKey: keys.spendSecretKey,
    viewSecretKey: keys.viewSecretKey
  });

  assert(wallet instanceof MultisigWallet);
});

test('createMultisigWallet validates parameters', () => {
  let threw = false;
  try {
    createMultisigWallet({
      threshold: 5,
      signerCount: 3  // Invalid: threshold > signerCount
    });
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw for invalid parameters');
});

// ============================================================================
// Summary
// ============================================================================

console.log('\n--- Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  console.log('\n✗ Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All multisig tests passed!');
  process.exit(0);
}
