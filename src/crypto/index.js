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
  isIdentity,
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
  // CARROT key derivation
  computeCarrotSpendPubkey, computeCarrotAccountViewPubkey,
  computeCarrotMainAddressViewPubkey,
} from './provider.js';

// Backends (for direct access / testing)
export { JsCryptoBackend } from './backend-js.js';
export { WasmCryptoBackend } from './backend-wasm.js';
