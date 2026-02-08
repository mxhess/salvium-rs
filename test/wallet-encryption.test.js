#!/usr/bin/env bun
/**
 * Post-Quantum Wallet Encryption Tests
 *
 * Tests ML-KEM-768 + Argon2id + AES-256-GCM hybrid encryption for wallet data at rest.
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { Wallet } from '../src/wallet.js';
import {
  encryptWalletJSON,
  decryptWalletJSON,
  reEncryptWalletJSON,
  isEncryptedWallet,
  encryptData,
  decryptData,
  ENCRYPTION_VERSION,
} from '../src/wallet-encryption.js';
import { MemoryStorage, WalletOutput } from '../src/wallet-store.js';

await setCryptoBackend('wasm');

let passed = 0;
let failed = 0;

function assert(condition, msg) {
  if (condition) {
    passed++;
  } else {
    failed++;
    console.error(`  FAIL: ${msg}`);
  }
}

// Use fast argon2 params for testing
const FAST_PARAMS = { argon2: { t: 1, m: 1024, p: 1 } };

// Create a test wallet
const wallet = Wallet.create({ network: 'testnet' });
const plainJSON = wallet.toJSON(true);

console.log('\n--- Wallet Encryption Tests ---\n');

// Test 1: encryptWalletJSON / decryptWalletJSON roundtrip
console.log('Test 1: Encrypt/decrypt roundtrip');
{
  const enc = encryptWalletJSON(plainJSON, 'testpass', FAST_PARAMS);
  const dec = decryptWalletJSON(enc, 'testpass');
  assert(dec.seed === plainJSON.seed, 'seed roundtrip');
  assert(dec.spendSecretKey === plainJSON.spendSecretKey, 'spendSecretKey roundtrip');
  assert(dec.viewSecretKey === plainJSON.viewSecretKey, 'viewSecretKey roundtrip');
  assert(dec.mnemonic === plainJSON.mnemonic, 'mnemonic roundtrip');
  assert(dec.address === plainJSON.address, 'address roundtrip');
  assert(dec.spendPublicKey === plainJSON.spendPublicKey, 'spendPublicKey roundtrip');
  assert(dec.network === plainJSON.network, 'network roundtrip');
}

// Test 2: Wrong password throws
console.log('Test 2: Wrong password throws');
{
  const enc = encryptWalletJSON(plainJSON, 'correct', FAST_PARAMS);
  let threw = false;
  try {
    decryptWalletJSON(enc, 'wrong');
  } catch (e) {
    threw = true;
    assert(e.message.includes('incorrect password'), 'error message mentions password');
  }
  assert(threw, 'wrong password throws');
}

// Test 3: isEncryptedWallet detection
console.log('Test 3: isEncryptedWallet detection');
{
  const enc = encryptWalletJSON(plainJSON, 'pass', FAST_PARAMS);
  assert(isEncryptedWallet(enc) === true, 'encrypted wallet detected');
  assert(isEncryptedWallet(plainJSON) === false, 'plain wallet not detected');
  assert(isEncryptedWallet(null) === false, 'null not detected');
  assert(isEncryptedWallet({}) === false, 'empty object not detected');
}

// Test 4: Public fields visible without password
console.log('Test 4: Public fields visible without decryption');
{
  const enc = encryptWalletJSON(plainJSON, 'pass', FAST_PARAMS);
  assert(enc.address === plainJSON.address, 'address visible');
  assert(enc.carrotAddress === plainJSON.carrotAddress, 'carrotAddress visible');
  assert(enc.spendPublicKey === plainJSON.spendPublicKey, 'spendPublicKey visible');
  assert(enc.viewPublicKey === plainJSON.viewPublicKey, 'viewPublicKey visible');
  assert(enc.network === plainJSON.network, 'network visible');
  assert(enc.version === plainJSON.version, 'version visible');
}

// Test 5: Secrets are NOT in encrypted output
console.log('Test 5: Secrets hidden in encrypted output');
{
  const enc = encryptWalletJSON(plainJSON, 'pass', FAST_PARAMS);
  assert(enc.seed === undefined, 'seed hidden');
  assert(enc.mnemonic === undefined, 'mnemonic hidden');
  assert(enc.spendSecretKey === undefined, 'spendSecretKey hidden');
  assert(enc.viewSecretKey === undefined, 'viewSecretKey hidden');
}

// Test 6: CARROT keys — public visible, secrets hidden
console.log('Test 6: CARROT key separation');
{
  const enc = encryptWalletJSON(plainJSON, 'pass', FAST_PARAMS);
  assert(enc.carrotKeys?.accountSpendPubkey !== undefined, 'CARROT public key visible');
  assert(enc.carrotKeys?.primaryAddressViewPubkey !== undefined, 'CARROT view pub visible');
  // Secret CARROT keys should not be on the top-level carrotKeys
  assert(enc.carrotKeys?.viewIncomingKey === undefined, 'CARROT viewIncomingKey hidden');
  assert(enc.carrotKeys?.generateImageKey === undefined, 'CARROT generateImageKey hidden');
  assert(enc.carrotKeys?.proveSpendKey === undefined, 'CARROT proveSpendKey hidden');

  // After decryption, all CARROT keys restored
  const dec = decryptWalletJSON(enc, 'pass');
  assert(dec.carrotKeys?.viewIncomingKey === plainJSON.carrotKeys?.viewIncomingKey, 'CARROT secrets restored');
}

// Test 7: Wallet.toEncryptedJSON / fromEncryptedJSON roundtrip
console.log('Test 7: Wallet class encrypt/decrypt methods');
{
  const enc = wallet.toEncryptedJSON('walletpass', FAST_PARAMS);
  assert(Wallet.isEncrypted(enc), 'Wallet.isEncrypted works');

  const restored = Wallet.fromEncryptedJSON(enc, 'walletpass');
  assert(restored.getLegacyAddress() === wallet.getLegacyAddress(), 'address matches');
  assert(restored.getCarrotAddress() === wallet.getCarrotAddress(), 'CARROT address matches');
  assert(restored.canSign(), 'restored wallet can sign');
  assert(restored.canScan(), 'restored wallet can scan');
}

// Test 8: Encryption envelope format
console.log('Test 8: Envelope format');
{
  const enc = encryptWalletJSON(plainJSON, 'pass', FAST_PARAMS);
  assert(enc.encrypted === true, 'encrypted flag set');
  assert(enc.encryptionVersion === ENCRYPTION_VERSION, 'version present');
  assert(typeof enc.encryption === 'object', 'encryption metadata present');
  assert(typeof enc.encryption.kdfSalt === 'string', 'kdfSalt is hex');
  assert(typeof enc.encryption.kemSalt === 'string', 'kemSalt is hex');
  assert(typeof enc.encryption.kyberCiphertext === 'string', 'kyberCiphertext is hex');
  assert(typeof enc.encryption.iv === 'string', 'iv is hex');
  assert(typeof enc.encryption.ciphertext === 'string', 'ciphertext is hex');
  assert(enc.encryption.iv.length === 24, 'iv is 12 bytes (24 hex)');
  assert(enc.encryption.argon2.t === 1, 'argon2 params stored');
}

// Test 9: Unencrypted passthrough
console.log('Test 9: Unencrypted passthrough');
{
  const result = decryptWalletJSON(plainJSON, 'anypassword');
  assert(result === plainJSON, 'plain JSON returned as-is');
}

// Test 10: Different passwords produce different ciphertexts
console.log('Test 10: Different passwords produce different output');
{
  const enc1 = encryptWalletJSON(plainJSON, 'pass1', FAST_PARAMS);
  const enc2 = encryptWalletJSON(plainJSON, 'pass2', FAST_PARAMS);
  assert(enc1.encryption.ciphertext !== enc2.encryption.ciphertext, 'different ciphertexts');
  assert(enc1.encryption.kdfSalt !== enc2.encryption.kdfSalt, 'different salts');
}

// Test 11: reEncryptWalletJSON changes password
console.log('Test 11: Password change via reEncryptWalletJSON');
{
  const enc = encryptWalletJSON(plainJSON, 'oldpass', FAST_PARAMS);
  const reEnc = reEncryptWalletJSON(enc, 'oldpass', 'newpass', FAST_PARAMS);

  // Old password no longer works
  let threw = false;
  try { decryptWalletJSON(reEnc, 'oldpass'); } catch { threw = true; }
  assert(threw, 'old password rejected after change');

  // New password works
  const dec = decryptWalletJSON(reEnc, 'newpass');
  assert(dec.seed === plainJSON.seed, 'seed intact after password change');
  assert(dec.mnemonic === plainJSON.mnemonic, 'mnemonic intact after password change');
  assert(dec.spendSecretKey === plainJSON.spendSecretKey, 'spendSecretKey intact');
  assert(dec.viewSecretKey === plainJSON.viewSecretKey, 'viewSecretKey intact');
  assert(dec.carrotKeys?.masterSecret === plainJSON.carrotKeys?.masterSecret, 'CARROT masterSecret intact');
}

// Test 12: Wallet.changePassword static method
console.log('Test 12: Wallet.changePassword');
{
  const enc = wallet.toEncryptedJSON('pin123', FAST_PARAMS);
  const reEnc = Wallet.changePassword(enc, 'pin123', 'pin456', FAST_PARAMS);

  assert(Wallet.isEncrypted(reEnc), 're-encrypted envelope is encrypted');
  assert(reEnc.address === enc.address, 'public address unchanged');
  assert(reEnc.carrotAddress === enc.carrotAddress, 'CARROT address unchanged');

  // Fresh salts (not reusing old crypto material)
  assert(reEnc.encryption.kdfSalt !== enc.encryption.kdfSalt, 'fresh kdfSalt');
  assert(reEnc.encryption.kemSalt !== enc.encryption.kemSalt, 'fresh kemSalt');

  // Restore with new password
  const restored = Wallet.fromEncryptedJSON(reEnc, 'pin456');
  assert(restored.getLegacyAddress() === wallet.getLegacyAddress(), 'address matches after change');
  assert(restored.getCarrotAddress() === wallet.getCarrotAddress(), 'CARROT address matches after change');
  assert(restored.canSign(), 'can sign after password change');
}

// Test 13: Wrong old password in changePassword throws
console.log('Test 13: changePassword with wrong old password throws');
{
  const enc = encryptWalletJSON(plainJSON, 'correct', FAST_PARAMS);
  let threw = false;
  try { reEncryptWalletJSON(enc, 'wrong', 'newpass', FAST_PARAMS); } catch { threw = true; }
  assert(threw, 'wrong old password throws on re-encrypt');
}

// Test 14: Wallet.create() generates dataKey
console.log('Test 14: dataKey generated on create');
{
  const w = Wallet.create({ network: 'testnet' });
  assert(w._dataKey !== null, 'dataKey is not null');
  assert(w._dataKey instanceof Uint8Array, 'dataKey is Uint8Array');
  assert(w._dataKey.length === 32, 'dataKey is 32 bytes');

  // Different wallets get different dataKeys
  const w2 = Wallet.create({ network: 'testnet' });
  const dk1 = Array.from(w._dataKey).map(b => b.toString(16).padStart(2, '0')).join('');
  const dk2 = Array.from(w2._dataKey).map(b => b.toString(16).padStart(2, '0')).join('');
  assert(dk1 !== dk2, 'different wallets have different dataKeys');
}

// Test 15: dataKey encrypted in wallet JSON
console.log('Test 15: dataKey encrypted in wallet envelope');
{
  const enc = wallet.toEncryptedJSON('pass', FAST_PARAMS);
  assert(enc.dataKey === undefined, 'dataKey not in plaintext envelope');
  const encStr = JSON.stringify(enc);
  const dkHex = Array.from(wallet._dataKey).map(b => b.toString(16).padStart(2, '0')).join('');
  assert(!encStr.includes(dkHex), 'dataKey hex not leaked in envelope');

  // Restored after decryption
  const restored = Wallet.fromEncryptedJSON(enc, 'pass');
  const restoredHex = Array.from(restored._dataKey).map(b => b.toString(16).padStart(2, '0')).join('');
  assert(restoredHex === dkHex, 'dataKey restored after decrypt');
}

// Test 16: encryptData / decryptData roundtrip
console.log('Test 16: encryptData/decryptData roundtrip');
{
  const key = wallet._dataKey;
  const original = '{"hello":"world","amount":12345}';
  const enc = encryptData(key, original);

  assert(enc.encrypted === true, 'encrypted flag set');
  assert(typeof enc.iv === 'string', 'iv is hex string');
  assert(typeof enc.ciphertext === 'string', 'ciphertext is hex string');

  const decBytes = decryptData(key, enc);
  const dec = new TextDecoder().decode(decBytes);
  assert(dec === original, 'roundtrip preserves data');
}

// Test 17: decryptData with wrong key throws
console.log('Test 17: decryptData wrong key throws');
{
  const key = wallet._dataKey;
  const enc = encryptData(key, 'secret data');
  const wrongKey = new Uint8Array(32);
  wrongKey.fill(0xff);
  let threw = false;
  try { decryptData(wrongKey, enc); } catch { threw = true; }
  assert(threw, 'wrong key throws');
}

// Test 18: Encrypted sync cache roundtrip
console.log('Test 18: Encrypted sync cache roundtrip');
{
  const w = Wallet.create({ network: 'testnet' });
  w._ensureStorage();

  // Add some test outputs to the storage
  await w._storage.putOutput(new WalletOutput({
    keyImage: 'ab'.repeat(32),
    publicKey: 'cd'.repeat(32),
    txHash: 'ef'.repeat(32),
    outputIndex: 0,
    blockHeight: 100,
    amount: 500000000n,
    commitment: '11'.repeat(32),
    mask: '22'.repeat(32),
    carrotSharedSecret: '33'.repeat(32),
    isCarrot: true,
  }));
  w._storage._syncHeight = 100;

  // Dump encrypted
  const encryptedJSON = w.dumpSyncCacheJSON();
  const parsed = JSON.parse(encryptedJSON);
  assert(parsed.encrypted === true, 'sync cache is encrypted');
  assert(parsed.iv !== undefined, 'sync cache has iv');
  assert(parsed.ciphertext !== undefined, 'sync cache has ciphertext');

  // Verify secrets are not in the encrypted string
  assert(!encryptedJSON.includes('ab'.repeat(32)), 'keyImage not leaked in encrypted cache');
  assert(!encryptedJSON.includes('22'.repeat(32)), 'mask not leaked in encrypted cache');
  assert(!encryptedJSON.includes('33'.repeat(32)), 'carrotSharedSecret not leaked in encrypted cache');
  assert(!encryptedJSON.includes('500000000'), 'amount not leaked in encrypted cache');

  // Load back into a new wallet with the same dataKey
  const w2 = Wallet.create({ network: 'testnet' });
  w2._dataKey = w._dataKey; // Same data key
  w2.loadSyncCache(parsed);

  const outputs = await w2._storage.getOutputs({});
  assert(outputs.length === 1, 'output restored from encrypted cache');
  assert(outputs[0].keyImage === 'ab'.repeat(32), 'keyImage matches');
  assert(outputs[0].amount === 500000000n, 'amount matches');
  assert(outputs[0].mask === '22'.repeat(32), 'mask matches');
  assert(outputs[0].carrotSharedSecret === '33'.repeat(32), 'sharedSecret matches');
  assert(w2._syncHeight === 100, 'syncHeight restored');
}

// Test 19: Loading encrypted cache without dataKey throws
console.log('Test 19: Encrypted cache without dataKey throws');
{
  const w = Wallet.create({ network: 'testnet' });
  w._ensureStorage();
  w._storage._syncHeight = 50;
  const encJSON = w.dumpSyncCacheJSON();
  const parsed = JSON.parse(encJSON);

  // Create wallet with no dataKey
  const w2 = Wallet.create({ network: 'testnet' });
  w2._dataKey = null;
  let threw = false;
  try { w2.loadSyncCache(parsed); } catch (e) {
    threw = true;
    assert(e.message.includes('no data key'), 'error mentions data key');
  }
  assert(threw, 'loading encrypted cache without dataKey throws');
}

// Test 20: Backward compat — plain sync cache still loads
console.log('Test 20: Plain sync cache backward compatibility');
{
  const w = Wallet.create({ network: 'testnet' });
  w._ensureStorage();

  // Build a plain (unencrypted) cache manually
  const plainCache = { version: 1, syncHeight: 42, outputs: [], transactions: [], spentKeyImages: [], blockHashes: {}, state: {} };
  w.loadSyncCache(plainCache);
  assert(w._syncHeight === 42, 'plain cache loaded successfully');
}

// Test 21: dataKey survives password change
console.log('Test 21: dataKey survives password change');
{
  const w = Wallet.create({ network: 'testnet' });
  const originalDK = Array.from(w._dataKey).map(b => b.toString(16).padStart(2, '0')).join('');

  const enc1 = w.toEncryptedJSON('old', FAST_PARAMS);
  const enc2 = Wallet.changePassword(enc1, 'old', 'new', FAST_PARAMS);
  const restored = Wallet.fromEncryptedJSON(enc2, 'new');
  const restoredDK = Array.from(restored._dataKey).map(b => b.toString(16).padStart(2, '0')).join('');

  assert(restoredDK === originalDK, 'dataKey unchanged after password change');
}

console.log(`\nPassed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);
if (failed > 0) {
  console.log('\nSome tests FAILED!');
  process.exit(1);
} else {
  console.log('\nAll wallet encryption tests passed!');
}
