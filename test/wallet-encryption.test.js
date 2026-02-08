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
  ENCRYPTION_VERSION,
} from '../src/wallet-encryption.js';

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

console.log(`\nPassed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);
if (failed > 0) {
  console.log('\nSome tests FAILED!');
  process.exit(1);
} else {
  console.log('\nAll wallet encryption tests passed!');
}
