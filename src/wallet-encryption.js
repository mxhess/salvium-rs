/**
 * Post-Quantum Wallet Encryption
 *
 * Hybrid encryption for wallet data at rest:
 *   1. Argon2id(password, salt1) → classicalKey (32 bytes)
 *   2. Argon2id(password, salt2) → 64-byte seed → ML-KEM-768 keypair
 *      encapsulate(pk) → (kyberCT, quantumKey 32 bytes)
 *   3. HKDF-SHA256(classicalKey || quantumKey) → encryptionKey (32 bytes)
 *   4. AES-256-GCM(encryptionKey, iv, secrets) → ciphertext
 *
 * The Kyber keypair is derived deterministically from the password (not the
 * wallet seed) so no extra key material needs to be managed, and a seed
 * compromise alone does not break encryption.
 *
 * @module wallet-encryption
 */

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { gcm } from '@noble/ciphers/aes.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { randomBytes, concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { bytesToHex, hexToBytes } from './address.js';

export const ENCRYPTION_VERSION = 1;

// Default Argon2id parameters (OWASP minimums)
const ARGON2_DEFAULTS = { t: 3, m: 65536, p: 4 };

// Domain separation
const KEM_DOMAIN = utf8ToBytes('salvium-wallet-kem-v1');
const HKDF_INFO  = utf8ToBytes('salvium-wallet-encryption-key-v1');

// Fields that contain secrets and must be encrypted
const SENSITIVE_KEYS = ['seed', 'mnemonic', 'spendSecretKey', 'viewSecretKey'];

// CARROT public-only keys (stay plaintext for wallet identification)
const CARROT_PUBLIC_KEYS = ['accountSpendPubkey', 'primaryAddressViewPubkey', 'accountViewPubkey'];

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function deriveClassicalKey(password, salt, params) {
  return argon2id(utf8ToBytes(password), salt, {
    t: params.t, m: params.m, p: params.p, dkLen: 32,
  });
}

function deriveKyberKeypair(password, kemSalt, params) {
  const seed = argon2id(utf8ToBytes(password), concatBytes(kemSalt, KEM_DOMAIN), {
    t: params.t, m: params.m, p: params.p, dkLen: 64,
  });
  return ml_kem768.keygen(seed);
}

function combineKeys(classicalKey, quantumKey) {
  return hkdf(sha256, concatBytes(classicalKey, quantumKey), undefined, HKDF_INFO, 32);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Encrypt sensitive wallet fields with hybrid PQ encryption.
 *
 * @param {Object} walletJSON - Plain wallet JSON (from wallet.toJSON(true))
 * @param {string} password - User-chosen password
 * @param {Object} [options]
 * @param {Object} [options.argon2] - Override { t, m, p }
 * @returns {Object} Encrypted wallet envelope (JSON-serializable)
 */
export function encryptWalletJSON(walletJSON, password, options = {}) {
  const params = { ...ARGON2_DEFAULTS, ...options.argon2 };

  // 1. Collect sensitive fields
  const secrets = {};
  for (const key of SENSITIVE_KEYS) {
    if (walletJSON[key] !== undefined) secrets[key] = walletJSON[key];
  }
  if (walletJSON.carrotKeys) {
    const carrotSecrets = {};
    for (const [k, v] of Object.entries(walletJSON.carrotKeys)) {
      if (!CARROT_PUBLIC_KEYS.includes(k)) carrotSecrets[k] = v;
    }
    if (Object.keys(carrotSecrets).length > 0) secrets.carrotSecrets = carrotSecrets;
  }

  const plaintext = utf8ToBytes(JSON.stringify(secrets));

  // 2. Random salts
  const kdfSalt = randomBytes(32);
  const kemSalt = randomBytes(32);

  // 3. Classical key from password
  const classicalKey = deriveClassicalKey(password, kdfSalt, params);

  // 4. ML-KEM-768 encapsulation
  const { publicKey: kyberPK } = deriveKyberKeypair(password, kemSalt, params);
  const { cipherText: kyberCT, sharedSecret: quantumKey } = ml_kem768.encapsulate(kyberPK);

  // 5. Combined encryption key
  const encryptionKey = combineKeys(classicalKey, quantumKey);

  // 6. AES-256-GCM encrypt
  const iv = randomBytes(12);
  const ciphertext = gcm(encryptionKey, iv).encrypt(plaintext);

  // 7. Build public (unencrypted) portion
  const publicData = {};
  for (const k of ['version', 'type', 'network', 'spendPublicKey', 'viewPublicKey',
                    'address', 'carrotAddress', 'syncHeight', 'accounts', 'nextSubaddressIndex']) {
    if (walletJSON[k] !== undefined) publicData[k] = walletJSON[k];
  }
  if (walletJSON.carrotKeys) {
    publicData.carrotKeys = {};
    for (const k of CARROT_PUBLIC_KEYS) {
      if (walletJSON.carrotKeys[k]) publicData.carrotKeys[k] = walletJSON.carrotKeys[k];
    }
  }

  return {
    encrypted: true,
    encryptionVersion: ENCRYPTION_VERSION,
    ...publicData,
    encryption: {
      kdfSalt:          bytesToHex(kdfSalt),
      kemSalt:          bytesToHex(kemSalt),
      kyberCiphertext:  bytesToHex(kyberCT),
      iv:               bytesToHex(iv),
      ciphertext:       bytesToHex(ciphertext),
      argon2:           { t: params.t, m: params.m, p: params.p },
    },
  };
}

/**
 * Decrypt an encrypted wallet envelope.
 *
 * @param {Object} envelope - Encrypted wallet JSON
 * @param {string} password - User password
 * @returns {Object} Plain wallet JSON (same format as toJSON)
 * @throws {Error} On wrong password or corrupted data
 */
export function decryptWalletJSON(envelope, password) {
  if (!envelope.encrypted) return envelope;

  const enc = envelope.encryption;
  if (!enc) throw new Error('Missing encryption metadata');

  const params = enc.argon2 || ARGON2_DEFAULTS;

  // 1. Derive classical key
  const classicalKey = deriveClassicalKey(password, hexToBytes(enc.kdfSalt), params);

  // 2. Derive Kyber keypair & decapsulate
  const { secretKey: kyberSK } = deriveKyberKeypair(password, hexToBytes(enc.kemSalt), params);
  const quantumKey = ml_kem768.decapsulate(hexToBytes(enc.kyberCiphertext), kyberSK);

  // 3. Combined key
  const encryptionKey = combineKeys(classicalKey, quantumKey);

  // 4. AES-256-GCM decrypt (throws on auth failure = wrong password)
  let plaintext;
  try {
    plaintext = gcm(encryptionKey, hexToBytes(enc.iv)).decrypt(hexToBytes(enc.ciphertext));
  } catch {
    throw new Error('Decryption failed: incorrect password or corrupted data');
  }

  // 5. Parse secrets and merge with public data
  const secrets = JSON.parse(new TextDecoder().decode(plaintext));

  const walletJSON = {};
  for (const k of ['version', 'type', 'network', 'spendPublicKey', 'viewPublicKey',
                    'address', 'carrotAddress', 'syncHeight', 'accounts', 'nextSubaddressIndex']) {
    if (envelope[k] !== undefined) walletJSON[k] = envelope[k];
  }
  Object.assign(walletJSON, secrets);

  // Merge CARROT public + secret keys
  if (envelope.carrotKeys || secrets.carrotSecrets) {
    walletJSON.carrotKeys = {
      ...(envelope.carrotKeys || {}),
      ...(secrets.carrotSecrets || {}),
    };
    delete walletJSON.carrotSecrets;
  }

  return walletJSON;
}

/**
 * Check if a wallet JSON object is encrypted.
 * @param {Object} json
 * @returns {boolean}
 */
export function isEncryptedWallet(json) {
  return json?.encrypted === true && json?.encryption != null;
}
