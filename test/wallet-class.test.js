#!/usr/bin/env node
/**
 * Wallet Class Tests
 *
 * Tests for the unified Wallet class:
 * - Wallet creation (random, from seed, from mnemonic)
 * - View-only and watch-only wallets
 * - Address generation (main, subaddress, integrated)
 * - Balance tracking
 * - JSON serialization/deserialization
 */

import {
  Wallet,
  WALLET_TYPE,
  createWallet,
  restoreWallet,
  createViewOnlyWallet
} from '../src/wallet.js';

import { bytesToHex, hexToBytes } from '../src/address.js';
import { NETWORK, ADDRESS_FORMAT } from '../src/constants.js';

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

console.log('\n=== Wallet Class Tests ===\n');

// Wallet creation
console.log('--- Wallet Creation ---');

test('Wallet.create() generates new wallet', () => {
  const wallet = Wallet.create();

  assert(wallet.seed, 'Should have seed');
  assert(wallet.spendSecretKey, 'Should have spend secret key');
  assert(wallet.spendPublicKey, 'Should have spend public key');
  assert(wallet.viewSecretKey, 'Should have view secret key');
  assert(wallet.viewPublicKey, 'Should have view public key');
});

test('Wallet.create() sets correct type', () => {
  const wallet = Wallet.create();
  assertEqual(wallet.type, WALLET_TYPE.FULL);
});

test('Wallet.create() defaults to mainnet', () => {
  const wallet = Wallet.create();
  assertEqual(wallet.network, NETWORK.MAINNET);
});

test('Wallet.create() accepts network option', () => {
  const wallet = Wallet.create({ network: NETWORK.TESTNET });
  assertEqual(wallet.network, NETWORK.TESTNET);
});

test('Wallet.create() derives both legacy and CARROT keys', () => {
  const wallet = Wallet.create();
  // Primary keys are legacy CN keys
  assert(wallet._spendSecretKey, 'Should have legacy spend secret key');
  assert(wallet._viewSecretKey, 'Should have legacy view secret key');
  // CARROT keys also present
  assert(wallet._carrotKeys, 'Should have CARROT keys');
  assert(wallet._carrotKeys.proveSpendKey, 'Should have prove spend key');
  assert(wallet._carrotKeys.accountSpendPubkey, 'Should have account spend pubkey');
  // Both addresses work
  const legacy = wallet.getLegacyAddress();
  const carrot = wallet.getCarrotAddress();
  assertTrue(legacy.startsWith('SaLv'), 'Legacy address has SaLv prefix');
  assertTrue(carrot.startsWith('SC1'), 'CARROT address has SC1 prefix');
});

test('createWallet() convenience function works', () => {
  const wallet = createWallet();
  assertTrue(wallet instanceof Wallet);
  assertTrue(wallet.canSign());
});

test('Wallet.create() generates unique wallets', () => {
  const wallet1 = Wallet.create();
  const wallet2 = Wallet.create();

  assertTrue(wallet1.getAddress() !== wallet2.getAddress(), 'Should generate different addresses');
});

// Wallet restoration
console.log('\n--- Wallet Restoration ---');

test('Wallet.fromSeed() restores identical wallet', () => {
  const original = Wallet.create();
  const restored = Wallet.fromSeed(original.seed);

  assertEqual(original.getAddress(), restored.getAddress());
  assertEqual(bytesToHex(original.spendSecretKey), bytesToHex(restored.spendSecretKey));
  assertEqual(bytesToHex(original.viewSecretKey), bytesToHex(restored.viewSecretKey));
});

test('Wallet.fromSeed() accepts hex string', () => {
  const original = Wallet.create();
  const seedHex = bytesToHex(original.seed);
  const restored = Wallet.fromSeed(seedHex);

  assertEqual(original.getAddress(), restored.getAddress());
});

test('Wallet.fromMnemonic() restores wallet', () => {
  const original = Wallet.create();
  const mnemonic = original.getMnemonic();
  const restored = Wallet.fromMnemonic(mnemonic);

  assertEqual(original.getAddress(), restored.getAddress());
});

test('restoreWallet() convenience function works', () => {
  const original = Wallet.create();
  const restored = restoreWallet(original.getMnemonic());

  assertEqual(original.getAddress(), restored.getAddress());
});

test('Wallet.fromMnemonic() throws on invalid mnemonic', () => {
  let threw = false;
  try {
    Wallet.fromMnemonic('invalid mnemonic words that are not valid');
  } catch (e) {
    threw = true;
    assertTrue(e.message.includes('Invalid mnemonic'));
  }
  assertTrue(threw, 'Should throw on invalid mnemonic');
});

// View-only wallet
console.log('\n--- View-Only Wallet ---');

test('Wallet.fromViewKey() creates view-only wallet', () => {
  const fullWallet = Wallet.create();
  const viewWallet = Wallet.fromViewKey(fullWallet.viewSecretKey, fullWallet.spendPublicKey);

  assertEqual(viewWallet.type, WALLET_TYPE.VIEW_ONLY);
});

test('view-only wallet can scan', () => {
  const fullWallet = Wallet.create();
  const viewWallet = Wallet.fromViewKey(fullWallet.viewSecretKey, fullWallet.spendPublicKey);

  assertTrue(viewWallet.canScan());
});

test('view-only wallet cannot sign', () => {
  const fullWallet = Wallet.create();
  const viewWallet = Wallet.fromViewKey(fullWallet.viewSecretKey, fullWallet.spendPublicKey);

  assertTrue(!viewWallet.canSign());
});

test('view-only wallet has no spend secret key', () => {
  const fullWallet = Wallet.create();
  const viewWallet = Wallet.fromViewKey(fullWallet.viewSecretKey, fullWallet.spendPublicKey);

  assertEqual(viewWallet.spendSecretKey, null);
});

test('createViewOnlyWallet() convenience function works', () => {
  const fullWallet = Wallet.create();
  const viewWallet = createViewOnlyWallet(
    bytesToHex(fullWallet.viewSecretKey),
    bytesToHex(fullWallet.spendPublicKey)
  );

  assertTrue(!viewWallet.canSign());
  assertTrue(viewWallet.canScan());
});

// Watch-only wallet
console.log('\n--- Watch-Only Wallet ---');

test('Wallet.fromAddress() creates watch-only wallet', () => {
  const fullWallet = Wallet.create();
  const watchWallet = Wallet.fromAddress(fullWallet.getAddress());

  assertEqual(watchWallet.type, WALLET_TYPE.WATCH);
});

test('watch-only wallet cannot sign', () => {
  const fullWallet = Wallet.create();
  const watchWallet = Wallet.fromAddress(fullWallet.getAddress());

  assertTrue(!watchWallet.canSign());
});

test('watch-only wallet cannot scan', () => {
  const fullWallet = Wallet.create();
  const watchWallet = Wallet.fromAddress(fullWallet.getAddress());

  assertTrue(!watchWallet.canScan());
});

test('watch-only wallet preserves address', () => {
  const fullWallet = Wallet.create();
  const address = fullWallet.getAddress();
  const watchWallet = Wallet.fromAddress(address);

  assertEqual(watchWallet.getAddress(), address);
});

// Mnemonic
console.log('\n--- Mnemonic ---');

test('getMnemonic() returns 25 words', () => {
  const wallet = Wallet.create();
  const mnemonic = wallet.getMnemonic();
  const words = mnemonic.split(' ');

  assertEqual(words.length, 25);
});

test('getMnemonic() with different language', () => {
  const wallet = Wallet.create();
  const mnemonicEn = wallet.getMnemonic('english');
  // Just verify it returns something for english
  assertTrue(mnemonicEn.length > 0);
});

test('getMnemonic() returns null for view-only wallet', () => {
  const fullWallet = Wallet.create();
  const viewWallet = Wallet.fromViewKey(fullWallet.viewSecretKey, fullWallet.spendPublicKey);

  assertEqual(viewWallet.getMnemonic(), null);
});

// Address generation
console.log('\n--- Address Generation ---');

test('getAddress() returns valid mainnet address', () => {
  const wallet = Wallet.create();
  const address = wallet.getAddress();

  assertTrue(address.length > 90, 'Address should be long');
  // Salvium mainnet addresses start with "SaLv"
  assertTrue(address.startsWith('SaLv'), 'Should have mainnet prefix (SaLv)');
});

test('getAddress() caches result', () => {
  const wallet = Wallet.create();
  const addr1 = wallet.getAddress();
  const addr2 = wallet.getAddress();

  assertEqual(addr1, addr2);
  assertTrue(addr1 === addr2, 'Should return same object (cached)');
});

test('getSubaddress(0,0) returns main address', () => {
  const wallet = Wallet.create();
  const main = wallet.getAddress();
  const sub00 = wallet.getSubaddress(0, 0);

  assertEqual(main, sub00);
});

test('getSubaddress() generates different addresses', () => {
  const wallet = Wallet.create();
  const sub01 = wallet.getSubaddress(0, 1);
  const sub02 = wallet.getSubaddress(0, 2);
  const sub10 = wallet.getSubaddress(1, 0);

  assertTrue(sub01 !== sub02, 'Different minor indices should differ');
  assertTrue(sub01 !== sub10, 'Different major indices should differ');
});

test('getSubaddress() caches results', () => {
  const wallet = Wallet.create();
  const sub1 = wallet.getSubaddress(0, 5);
  const sub2 = wallet.getSubaddress(0, 5);

  assertTrue(sub1 === sub2, 'Should return cached subaddress');
});

test('getSubaddress() throws for watch-only wallet', () => {
  const fullWallet = Wallet.create();
  const watchWallet = Wallet.fromAddress(fullWallet.getAddress());

  let threw = false;
  try {
    watchWallet.getSubaddress(0, 1);
  } catch (e) {
    threw = true;
    assertTrue(e.message.includes('View secret key required'));
  }
  assertTrue(threw, 'Should throw for watch-only wallet');
});

// Balance tracking
console.log('\n--- Balance Tracking ---');

test('getBalance() returns correct structure', () => {
  const wallet = Wallet.create();
  const balance = wallet.getBalance({ assetType: 'SAL1' });

  assertEqual(typeof balance.balance, 'bigint');
  assertEqual(typeof balance.unlockedBalance, 'bigint');
  assertEqual(typeof balance.lockedBalance, 'bigint');
});

test('getBalance() throws without assetType', () => {
  const wallet = Wallet.create();
  let threw = false;
  try { wallet.getBalance(); } catch (e) { threw = true; }
  assertTrue(threw);
});

test('new wallet has zero balance', () => {
  const wallet = Wallet.create();
  const balance = wallet.getBalance({ assetType: 'SAL1' });

  assertEqual(balance.balance, 0n);
  assertEqual(balance.unlockedBalance, 0n);
  assertEqual(balance.lockedBalance, 0n);
});

test('getUTXOs() returns empty array for new wallet', () => {
  const wallet = Wallet.create();
  const utxos = wallet.getUTXOs({ assetType: 'SAL1' });

  assertTrue(Array.isArray(utxos));
  assertEqual(utxos.length, 0);
});

// Sync state
console.log('\n--- Sync State ---');

test('getSyncHeight() returns 0 for new wallet', () => {
  const wallet = Wallet.create();
  assertEqual(wallet.getSyncHeight(), 0);
});

test('setSyncHeight() updates height', () => {
  const wallet = Wallet.create();
  wallet.setSyncHeight(12345);
  assertEqual(wallet.getSyncHeight(), 12345);
});

// JSON serialization
console.log('\n--- JSON Serialization ---');

test('toJSON() includes all required fields', () => {
  const wallet = Wallet.create();
  const json = wallet.toJSON();

  assert(json.type, 'Should have type');
  assert(json.network, 'Should have network');
  assertEqual(json.version, 3, 'Should be version 3');
  assert(json.spendPublicKey, 'Should have spend public key');
  assert(json.viewPublicKey, 'Should have view public key');
  assert(json.address, 'Should have legacy address');
  assert(json.carrotAddress, 'Should have carrot address');
  assert(json.carrotKeys, 'Should have carrot keys');
});

test('toJSON() includes secrets by default', () => {
  const wallet = Wallet.create();
  const json = wallet.toJSON();

  assert(json.seed, 'Should have seed');
  assert(json.spendSecretKey, 'Should have spend secret key');
  assert(json.viewSecretKey, 'Should have view secret key');
});

test('toJSON(false) excludes secrets', () => {
  const wallet = Wallet.create();
  const json = wallet.toJSON(false);

  assertTrue(!json.seed, 'Should not have seed');
  assertTrue(!json.spendSecretKey, 'Should not have spend secret key');
  assertTrue(!json.viewSecretKey, 'Should not have view secret key');
});

test('fromJSON() restores full wallet', () => {
  const original = Wallet.create();
  const json = original.toJSON();
  const restored = Wallet.fromJSON(json);

  assertEqual(restored.type, WALLET_TYPE.FULL);
  assertEqual(restored.getAddress(), original.getAddress());
  assertEqual(bytesToHex(restored.seed), bytesToHex(original.seed));
});

test('fromJSON() restores view-only wallet', () => {
  const fullWallet = Wallet.create();
  const viewWallet = Wallet.fromViewKey(fullWallet.viewSecretKey, fullWallet.spendPublicKey);
  const json = viewWallet.toJSON();
  const restored = Wallet.fromJSON(json);

  assertEqual(restored.type, WALLET_TYPE.VIEW_ONLY);
  assertTrue(restored.canScan());
  assertTrue(!restored.canSign());
});

test('fromJSON() preserves sync height', () => {
  const wallet = Wallet.create();
  wallet.setSyncHeight(99999);
  const json = wallet.toJSON();
  const restored = Wallet.fromJSON(json);

  assertEqual(restored.getSyncHeight(), 99999);
});

// Capabilities
console.log('\n--- Capabilities ---');

test('full wallet can sign', () => {
  const wallet = Wallet.create();
  assertTrue(wallet.canSign());
});

test('full wallet can scan', () => {
  const wallet = Wallet.create();
  assertTrue(wallet.canScan());
});

test('WALLET_TYPE constants exist', () => {
  assertEqual(WALLET_TYPE.FULL, 'full');
  assertEqual(WALLET_TYPE.VIEW_ONLY, 'view_only');
  assertEqual(WALLET_TYPE.WATCH, 'watch');
});

// Summary
console.log(`\n--- Summary ---`);
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed === 0) {
  console.log('\n✓ All wallet class tests passed!');
  process.exit(0);
} else {
  console.log('\n✗ Some tests failed');
  process.exit(1);
}
