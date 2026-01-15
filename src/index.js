/**
 * salvium-js - JavaScript library for Salvium cryptocurrency
 *
 * Features:
 * - Address validation and parsing for all 18 address types
 * - Support for Legacy (CryptoNote) and CARROT address formats
 * - Mainnet, Testnet, and Stagenet support
 * - Base58 encoding/decoding (CryptoNote variant)
 * - Keccak-256 hashing
 * - Message signature verification (V1 and V2)
 * - Mnemonic seed encoding/decoding (12 languages)
 * - RPC clients for Daemon and Wallet interaction
 *
 * @module salvium-js
 */

// Re-export everything from submodules
export * from './constants.js';
export * from './keccak.js';
export * from './base58.js';
export * from './address.js';
export * from './signature.js';
export * from './blake2b.js';
export * from './carrot.js';
export * from './subaddress.js';
export * from './mnemonic.js';
export * from './scanning.js';
export * from './keyimage.js';
export * from './transaction.js';
export * from './bulletproofs_plus.js';

// Wordlists available as separate imports for tree-shaking
// Usage: import { spanish } from 'salvium-js/wordlists';
export * as wordlists from './wordlists/index.js';

// RPC clients available as namespace
// Usage: import { rpc } from 'salvium-js'; or import { DaemonRPC, WalletRPC } from 'salvium-js/rpc';
export * as rpc from './rpc/index.js';
export {
  RPCClient,
  DaemonRPC,
  WalletRPC,
  createDaemonRPC,
  createWalletRPC,
  RPC_ERROR_CODES,
  RPC_STATUS,
  PRIORITY,
  TRANSFER_TYPE
} from './rpc/index.js';
export {
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,
  getGeneratorG,
  getGeneratorT,
  computeCarrotSpendPubkey,
  computeCarrotAccountViewPubkey,
  computeCarrotMainAddressViewPubkey,
  testDouble,
  getBasePoint,
  test2G,
  testIdentity,
  get2GAffine,
  isOnCurve,
  checkG,
  check2G,
  compare2GMethods,
  decodeExpected2G,
  testFieldOps,
  debugCurveEquation,
  verifyDConstant,
  computeXFromY
} from './ed25519.js';

// Import named exports for combined API object
import {
  NETWORK,
  ADDRESS_TYPE,
  ADDRESS_FORMAT,
  PREFIXES
} from './constants.js';

import {
  keccak256,
  keccak256Hex,
  cnFastHash
} from './keccak.js';

import {
  encode,
  decode,
  encodeAddress,
  decodeAddress
} from './base58.js';

import {
  parseAddress,
  isValidAddress,
  isMainnet,
  isTestnet,
  isStagenet,
  isCarrot,
  isLegacy,
  isStandard,
  isIntegrated,
  isSubaddress,
  getSpendPublicKey,
  getViewPublicKey,
  getPaymentId,
  createAddress,
  toIntegratedAddress,
  toStandardAddress,
  describeAddress,
  bytesToHex,
  hexToBytes,
  generateCNSubaddress,
  generateCarrotSubaddress,
  generateRandomPaymentId,
  createIntegratedAddressWithRandomId
} from './address.js';

import {
  cnSubaddressSecretKey,
  cnSubaddressSpendPublicKey,
  cnSubaddress,
  carrotIndexExtensionGenerator,
  carrotSubaddressScalar,
  carrotSubaddress,
  generatePaymentId,
  isValidPaymentId
} from './subaddress.js';

import {
  verifySignature,
  parseSignature,
  testEd25519
} from './signature.js';

import {
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,
  getGeneratorG,
  getGeneratorT,
  computeCarrotSpendPubkey,
  computeCarrotAccountViewPubkey,
  computeCarrotMainAddressViewPubkey
} from './ed25519.js';

import {
  WORD_LIST,
  mnemonicToSeed,
  seedToMnemonic,
  validateMnemonic,
  languages,
  detectLanguage,
  getLanguage,
  getAvailableLanguages
} from './mnemonic.js';

import {
  generateSeed,
  deriveKeys,
  deriveCarrotKeys,
  makeViewBalanceSecret,
  makeViewIncomingKey,
  makeProveSpendKey,
  makeGenerateImageKey,
  makeGenerateAddressSecret
} from './carrot.js';

import {
  generateKeyDerivation,
  derivationToScalar,
  derivePublicKey,
  deriveSecretKey,
  deriveSubaddressPublicKey,
  deriveViewTag,
  computeSharedSecret,
  ecdhDecode,
  ecdhDecodeFull,
  ecdhEncode,
  checkOutputOwnership,
  checkSubaddressOwnership,
  scanOutput,
  scanTransaction
} from './scanning.js';

import {
  hashToPoint,
  generateKeyImage,
  deriveKeyImageGenerator,
  isValidKeyImage,
  keyImageToY,
  keyImageFromY,
  exportKeyImages,
  importKeyImages
} from './keyimage.js';

import {
  // Scalar operations
  L,
  H,
  bytesToBigInt,
  bigIntToBytes,
  scReduce32,
  scReduce64,
  scAdd,
  scSub,
  scMul,
  scMulAdd,
  scMulSub,
  scCheck,
  scIsZero,
  scRandom,
  scInvert,
  // Pedersen commitments
  commit,
  zeroCommit,
  genCommitmentMask,
  // Output creation
  generateOutputKeys,
  createOutput,
  // CLSAG signatures
  clsagSign,
  clsagVerify,
  // Utilities
  generateTxSecretKey,
  getTxPublicKey,
  getPreMlsagHash,
  // Serialization
  encodeVarint,
  decodeVarint,
  TX_VERSION,
  RCT_TYPE,
  TXOUT_TYPE,
  TXIN_TYPE,
  serializeTxOutput,
  serializeTxInput,
  serializeGenInput,
  serializeTxExtra,
  serializeTxPrefix,
  getTxPrefixHash,
  serializeCLSAG,
  serializeRctBase,
  serializeEcdhInfo,
  serializeOutPk,
  getTransactionHash,
  // Decoy selection
  GAMMA_SHAPE,
  GAMMA_SCALE,
  DEFAULT_UNLOCK_TIME,
  DIFFICULTY_TARGET,
  RECENT_SPEND_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
  DEFAULT_RING_SIZE,
  sampleGamma,
  GammaPicker,
  selectDecoys,
  indicesToOffsets,
  offsetsToIndices,
  // Fee calculation
  FEE_PER_KB,
  FEE_PER_BYTE,
  DYNAMIC_FEE_PER_KB_BASE_FEE,
  DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD,
  DYNAMIC_FEE_REFERENCE_TX_WEIGHT,
  FEE_QUANTIZATION_DECIMALS,
  FEE_MULTIPLIERS,
  FEE_PRIORITY,
  getFeeMultiplier,
  calculateFeeFromWeight,
  calculateFeeFromSize,
  estimateTxSize,
  estimateTxWeight,
  estimateFee,
  // RingCT assembly
  buildRingCtSignature,
  computePseudoOutputs,
  // CARROT output generation
  CARROT_DOMAIN,
  CARROT_ENOTE_TYPE,
  generateJanusAnchor,
  buildRingCtInputContext,
  buildCoinbaseInputContext,
  deriveCarrotEphemeralPrivkey,
  computeCarrotEphemeralPubkey,
  computeCarrotSharedSecret,
  deriveCarrotSenderReceiverSecret,
  deriveCarrotOnetimeExtensions,
  computeCarrotOnetimeAddress,
  deriveCarrotAmountBlindingFactor,
  deriveCarrotViewTag,
  encryptCarrotAnchor,
  encryptCarrotAmount,
  encryptCarrotPaymentId,
  createCarrotOutput,
  computeCarrotSpecialAnchor
} from './transaction.js';

import {
  RPCClient,
  DaemonRPC,
  WalletRPC,
  createDaemonRPC,
  createWalletRPC,
  RPC_ERROR_CODES,
  RPC_STATUS,
  PRIORITY,
  TRANSFER_TYPE
} from './rpc/index.js';

import {
  bytesToScalar,
  scalarToBytes,
  bytesToPoint,
  hashToPoint as bpHashToPoint,
  hashToScalar as bpHashToScalar,
  initGenerators,
  initTranscript,
  parseProof,
  multiScalarMul,
  verifyBulletproofPlus,
  verifyBulletproofPlusBatch,
  verifyRangeProof,
  Point
} from './bulletproofs_plus.js';

// Main API object
const salvium = {
  // Constants
  NETWORK,
  ADDRESS_TYPE,
  ADDRESS_FORMAT,
  PREFIXES,

  // Keccak
  keccak256,
  keccak256Hex,
  cnFastHash,

  // Base58
  base58Encode: encode,
  base58Decode: decode,
  encodeAddress,
  decodeAddress,

  // Address
  parseAddress,
  isValidAddress,
  isMainnet,
  isTestnet,
  isStagenet,
  isCarrot,
  isLegacy,
  isStandard,
  isIntegrated,
  isSubaddress,
  getSpendPublicKey,
  getViewPublicKey,
  getPaymentId,
  createAddress,
  toIntegratedAddress,
  toStandardAddress,
  describeAddress,
  bytesToHex,
  hexToBytes,

  // Signatures
  verifySignature,
  parseSignature,

  // Ed25519
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,
  getGeneratorG,
  getGeneratorT,

  // CARROT
  computeCarrotSpendPubkey,
  computeCarrotAccountViewPubkey,
  computeCarrotMainAddressViewPubkey,

  // Subaddress generation (CryptoNote)
  cnSubaddressSecretKey,
  cnSubaddressSpendPublicKey,
  cnSubaddress,
  generateCNSubaddress,

  // Subaddress generation (CARROT)
  carrotIndexExtensionGenerator,
  carrotSubaddressScalar,
  carrotSubaddress,
  generateCarrotSubaddress,

  // Integrated addresses / Payment IDs
  generatePaymentId,
  generateRandomPaymentId,
  isValidPaymentId,
  createIntegratedAddressWithRandomId,

  // Mnemonic
  WORD_LIST,
  mnemonicToSeed,
  seedToMnemonic,
  validateMnemonic,
  languages,
  detectLanguage,
  getLanguage,
  getAvailableLanguages,

  // Seed generation
  generateSeed,

  // Key derivation (CryptoNote)
  deriveKeys,

  // Key derivation (CARROT)
  deriveCarrotKeys,
  makeViewBalanceSecret,
  makeViewIncomingKey,
  makeProveSpendKey,
  makeGenerateImageKey,
  makeGenerateAddressSecret,

  // RPC
  RPCClient,
  DaemonRPC,
  WalletRPC,
  createDaemonRPC,
  createWalletRPC,
  RPC_ERROR_CODES,
  RPC_STATUS,
  PRIORITY,
  TRANSFER_TYPE,

  // Transaction Scanning
  generateKeyDerivation,
  derivationToScalar,
  derivePublicKey,
  deriveSecretKey,
  deriveSubaddressPublicKey,
  deriveViewTag,
  computeSharedSecret,
  ecdhDecode,
  ecdhDecodeFull,
  ecdhEncode,
  checkOutputOwnership,
  checkSubaddressOwnership,
  scanOutput,
  scanTransaction,

  // Key Images
  hashToPoint,
  generateKeyImage,
  deriveKeyImageGenerator,
  isValidKeyImage,
  keyImageToY,
  keyImageFromY,
  exportKeyImages,
  importKeyImages,

  // Transaction Construction
  L,
  H,
  bytesToBigInt,
  bigIntToBytes,
  scReduce32,
  scReduce64,
  scAdd,
  scSub,
  scMul,
  scMulAdd,
  scMulSub,
  scCheck,
  scIsZero,
  scRandom,
  scInvert,
  commit,
  zeroCommit,
  genCommitmentMask,
  generateOutputKeys,
  createOutput,
  clsagSign,
  clsagVerify,
  generateTxSecretKey,
  getTxPublicKey,
  getPreMlsagHash,

  // Serialization
  encodeVarint,
  decodeVarint,
  TX_VERSION,
  RCT_TYPE,
  TXOUT_TYPE,
  TXIN_TYPE,
  serializeTxOutput,
  serializeTxInput,
  serializeGenInput,
  serializeTxExtra,
  serializeTxPrefix,
  getTxPrefixHash,
  serializeCLSAG,
  serializeRctBase,
  serializeEcdhInfo,
  serializeOutPk,
  getTransactionHash,

  // Decoy Selection
  GAMMA_SHAPE,
  GAMMA_SCALE,
  DEFAULT_UNLOCK_TIME,
  DIFFICULTY_TARGET,
  RECENT_SPEND_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
  DEFAULT_RING_SIZE,
  sampleGamma,
  GammaPicker,
  selectDecoys,
  indicesToOffsets,
  offsetsToIndices,

  // Fee Calculation
  FEE_PER_KB,
  FEE_PER_BYTE,
  DYNAMIC_FEE_PER_KB_BASE_FEE,
  DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD,
  DYNAMIC_FEE_REFERENCE_TX_WEIGHT,
  FEE_QUANTIZATION_DECIMALS,
  FEE_MULTIPLIERS,
  FEE_PRIORITY,
  getFeeMultiplier,
  calculateFeeFromWeight,
  calculateFeeFromSize,
  estimateTxSize,
  estimateTxWeight,
  estimateFee,

  // RingCT Assembly
  buildRingCtSignature,
  computePseudoOutputs,

  // CARROT Output Generation
  CARROT_DOMAIN,
  CARROT_ENOTE_TYPE,
  generateJanusAnchor,
  buildRingCtInputContext,
  buildCoinbaseInputContext,
  deriveCarrotEphemeralPrivkey,
  computeCarrotEphemeralPubkey,
  computeCarrotSharedSecret,
  deriveCarrotSenderReceiverSecret,
  deriveCarrotOnetimeExtensions,
  computeCarrotOnetimeAddress,
  deriveCarrotAmountBlindingFactor,
  deriveCarrotViewTag,
  encryptCarrotAnchor,
  encryptCarrotAmount,
  encryptCarrotPaymentId,
  createCarrotOutput,
  computeCarrotSpecialAnchor,

  // Bulletproofs+
  bytesToScalar,
  scalarToBytes,
  bytesToPoint,
  bpHashToPoint,
  bpHashToScalar,
  initGenerators,
  initTranscript,
  parseProof,
  multiScalarMul,
  verifyBulletproofPlus,
  verifyBulletproofPlusBatch,
  verifyRangeProof,
  Point
};

export default salvium;
