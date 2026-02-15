/**
 * Crypto Module — Public API
 *
 * Exports the provider (for backend switching) and both backends
 * for direct access when needed.
 *
 * @module crypto
 */

// Provider (default usage — delegates to active backend)
export {
  setCryptoBackend,
  getCryptoBackend,
  getCurrentBackendType,
  initCrypto,
  // Hashing
  keccak256, keccak256Hex, cnFastHash,
  blake2b,
  // Scalar ops
  scAdd, scSub, scMul, scMulAdd, scMulSub,
  scReduce32, scReduce64, scInvert, scCheck, scIsZero,
  scalarAdd,
  // Point ops
  scalarMultBase, scalarMultPoint, pointAddCompressed,
  pointSubCompressed, pointNegate, doubleScalarMultBase,
  isIdentity, isValidPoint,
  // Constants
  getGeneratorG, getGeneratorT,
  // Random
  randomScalar,
  // Hash-to-point & key derivation
  hashToPoint, generateKeyImage, generateKeyDerivation,
  derivePublicKey, deriveSecretKey,
  derivationToScalar, deriveViewTag, deriveSubaddressPublicKey,
  computeSharedSecret,
  // Amount encryption/decryption
  ecdhDecode, ecdhDecodeFull, ecdhEncode,
  // Pedersen commitments
  commit, zeroCommit, genCommitmentMask,
  // Oracle signature verification
  sha256, verifySignature,
  // Key derivation
  argon2id,
  // X25519
  x25519ScalarMult, edwardsToMontgomeryU,
  // CARROT key derivation
  computeCarrotSpendPubkey, computeCarrotAccountViewPubkey,
  computeCarrotMainAddressViewPubkey,
  // Batch operations
  cnSubaddressMapBatch, carrotSubaddressMapBatch,
  deriveCarrotKeysBatch, deriveCarrotViewOnlyKeysBatch,
  // CARROT helpers
  computeCarrotViewTag as computeCarrotViewTagRust,
  decryptCarrotAmount as decryptCarrotAmountRust,
  deriveCarrotCommitmentMask as deriveCarrotCommitmentMaskRust,
  recoverCarrotAddressSpendPubkey as recoverCarrotAddressSpendPubkeyRust,
  makeInputContextRct as makeInputContextRctRust,
  makeInputContextCoinbase as makeInputContextCoinbaseRust,
  // Transaction extra parsing & serialization
  parseExtra as parseExtraRust,
  serializeTxExtra as serializeTxExtraRust,
  computeTxPrefixHash as computeTxPrefixHashRust,
} from './provider.js';

// Backends (for direct access / testing)
// Note: WasmCryptoBackend is NOT re-exported here because it uses import.meta
// which is incompatible with React Native/Hermes. Import it directly:
//   import { WasmCryptoBackend } from 'salvium-js/src/crypto/backend-wasm.js';
export { JsCryptoBackend } from './backend-js.js';
export { JsiCryptoBackend } from './backend-jsi.js';
