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
export * from './mining.js';
export * from './wallet.js';
export * from './query.js';
export * from './connection-manager.js';
export * from './offline.js';
export * from './multisig.js';
export * from './wallet-store.js';
export * from './wallet-sync.js';
export { transfer, sweep, stake } from './wallet/transfer.js';
export * from './persistent-wallet.js';
export * from './consensus.js';

// Post-quantum wallet encryption
export { encryptWalletJSON, decryptWalletJSON, reEncryptWalletJSON, isEncryptedWallet } from './wallet-encryption.js';

// Validation exports
export * from './validation.js';

// Validation namespace
export * as validation from './validation.js';

// Oracle exports (selective to avoid COIN conflict with consensus.js)
export {
  PRICING_RECORD_VALID_BLOCKS,
  PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK,
  CONVERSION_RATE_ROUNDING,
  ASSET_TYPES,
  HF_VERSION_SLIPPAGE_YIELD,
  ORACLE_URLS,
  ORACLE_PUBLIC_KEY_MAINNET,
  ORACLE_PUBLIC_KEY_TESTNET,
  createEmptyPricingRecord,
  isPricingRecordEmpty,
  getAssetPrice,
  getAssetMaPrice,
  buildSignatureMessage,
  verifyPricingRecordSignature,
  getOraclePublicKey,
  validatePricingRecord,
  getConversionRate,
  getConvertedAmount,
  calculateSlippage,
  calculateConversion,
  parsePricingRecordFromJson,
  pricingRecordToJson,
  fetchPricingRecord
} from './oracle.js';

// RandomX proof-of-work (WASM-JIT implementation)
export * as randomx from './randomx/index.js';
export {
  // Light mode
  RandomXContext,
  RandomXNative,
  RandomXWorkerPool,
  getAvailableCores,
  // Full mode
  RandomXFullMode,
  createFullModeContext,
  RANDOMX_DATASET_ITEM_COUNT,
  RANDOMX_DATASET_ITEM_SIZE,
  RANDOMX_DATASET_SIZE,
  // Functions
  rxSlowHash,
  randomxHash,
  calculateCommitment,
  verifyHash,
  checkDifficulty,
  mine,
  randomx_init_cache,
  randomx_create_vm,
  randomx_machine_id,
  // Pure JS internals (for testing)
  RandomXCache,
  initDatasetItem,
  Blake2Generator,
  generateSuperscalar,
  executeSuperscalar,
  reciprocal,
  argon2d
} from './randomx/index.js';

// Wordlists available as separate imports for tree-shaking
// Usage: import { spanish } from 'salvium-js/wordlists';
export * as wordlists from './wordlists/index.js';

// RPC clients available as namespace
// Usage: import { rpc } from 'salvium-js'; or import { DaemonRPC, WalletRPC } from 'salvium-js/rpc';
export * as rpc from './rpc/index.js';

// Oracle/pricing available as namespace
// Usage: import { oracle } from 'salvium-js';
export * as oracle from './oracle.js';

// Stratum mining client
export * as stratum from './stratum/index.js';
export { StratumClient, StratumMiner, createMiner } from './stratum/index.js';
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
  pointSubCompressed,
  pointNegate,
  randomScalar as ed25519RandomScalar,
  randomPoint,
  isValidPoint,
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
  parseSignature
} from './signature.js';

import {
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,
  pointSubCompressed,
  pointNegate,
  randomScalar as ed25519RandomScalar,
  randomPoint,
  isValidPoint,
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
  computeCarrotSpecialAnchor,
  // Block serialization
  HF_VERSION_ENABLE_ORACLE,
  serializeSupplyData,
  serializeAssetData,
  serializePricingRecord,
  serializeBlockHeader,
  serializeBlock,
  getBlockHash,
  computeMerkleRoot,
  // UTXO Selection
  UTXO_STRATEGY,
  selectUTXOs,
  // Transaction Building
  buildTransaction,
  signTransaction,
  prepareInputs,
  estimateTransactionFee,
  validateTransaction,
  serializeTransaction,
  // Transaction Parsing
  parseTransaction,
  parseExtra,
  decodeAmount,
  extractTxPubKey,
  extractPaymentId,
  summarizeTransaction,
  getTransactionHashFromParsed
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
  // Proof generation
  proveRange,
  proveRangeMultiple,
  randomScalar,
  serializeProof,
  bulletproofPlusProve,
  Point
} from './bulletproofs_plus.js';

import {
  MINING_CONSTANTS,
  parseBlockTemplate,
  parseDifficulty,
  treeHash,
  constructBlockHashingBlob,
  setNonce,
  getNonce,
  setExtraNonce,
  checkHash,
  difficultyToTarget,
  hashToDifficulty,
  formatDifficulty,
  formatBlockForSubmission,
  findNonceOffset,
  calculateHashrate,
  formatHashrate,
  estimateBlockTime,
  formatDuration,
  createMiningContext
} from './mining.js';

import {
  // Light mode
  RandomXContext,
  RandomXNative,
  RandomXWorkerPool,
  getAvailableCores,
  // Full mode
  RandomXFullMode,
  createFullModeContext,
  RANDOMX_DATASET_ITEM_COUNT,
  RANDOMX_DATASET_ITEM_SIZE,
  RANDOMX_DATASET_SIZE,
  // Functions
  rxSlowHash,
  randomxHash,
  calculateCommitment,
  verifyHash,
  checkDifficulty as randomxCheckDifficulty,
  mine as randomxMine,
  randomx_init_cache,
  randomx_create_vm,
  randomx_machine_id
} from './randomx/index.js';

import {
  Wallet,
  WalletListener,
  Account,
  WALLET_TYPE,
  TX_TYPE,
  MAX_SUBADDRESS_MAJOR_INDEX,
  MAX_SUBADDRESS_MINOR_INDEX,
  createWallet,
  restoreWallet,
  createViewOnlyWallet
} from './wallet.js';

import {
  OutputQuery,
  TxQuery,
  TransferQuery,
  createOutputQuery,
  createTxQuery,
  createTransferQuery,
  unspentOutputs,
  spentOutputs,
  lockedOutputs,
  unlockedOutputs,
  stakingOutputs,
  yieldOutputs,
  incomingTxs,
  outgoingTxs,
  pendingTxs,
  confirmedTxs,
  stakingTxs,
  yieldTxs
} from './query.js';

import {
  ConnectionManager,
  ConnectionInfo,
  CONNECTION_STATE,
  createDaemonConnectionManager,
  createWalletConnectionManager
} from './connection-manager.js';

import {
  UNSIGNED_TX_VERSION,
  SIGNED_TX_VERSION,
  createUnsignedTx,
  parseUnsignedTx,
  createSignedTx,
  parseSignedTx,
  exportUnsignedTx,
  importUnsignedTx,
  signOffline,
  exportSignedTx,
  importSignedTx,
  getTxBlobHex,
  exportKeyImages as exportKeyImagesOffline,
  importKeyImages as importKeyImagesOffline,
  exportOutputs,
  importOutputs,
  verifyUnsignedTx,
  summarizeUnsignedTx
} from './offline.js';

import {
  MULTISIG_MAX_SIGNERS,
  MULTISIG_MIN_THRESHOLD,
  MULTISIG_NONCE_COMPONENTS,
  MULTISIG_MSG_TYPE,
  KexMessage,
  MultisigSigner,
  MultisigAccount,
  MultisigTxSet,
  MultisigPartialSig,
  MultisigTxBuilder,
  MultisigWallet,
  getMultisigBlindedSecretKey,
  computeDHSecret,
  kexRoundsRequired,
  generateMultisigNonces,
  combineMultisigNonces,
  createMultisigWallet,
  prepareMultisig,
  isMultisig
} from './multisig.js';

import {
  WalletStorage,
  WalletOutput,
  WalletTransaction,
  MemoryStorage,
  IndexedDBStorage,
  createStorage
} from './wallet-store.js';

import {
  WalletSync,
  createWalletSync,
  SYNC_STATUS,
  DEFAULT_BATCH_SIZE,
  SYNC_UNLOCK_BLOCKS
} from './wallet-sync.js';

import {
  PersistentWallet,
  createPersistentWallet,
  restorePersistentWallet,
  openPersistentWallet
} from './persistent-wallet.js';

import {
  // Constants
  MONEY_SUPPLY,
  EMISSION_SPEED_FACTOR_PER_MINUTE,
  FINAL_SUBSIDY_PER_MINUTE,
  COIN,
  CRYPTONOTE_DISPLAY_DECIMAL_POINT,
  PREMINE_AMOUNT,
  PREMINE_AMOUNT_UPFRONT,
  PREMINE_AMOUNT_MONTHLY,
  TREASURY_SAL1_MINT_AMOUNT,
  TREASURY_SAL1_MINT_COUNT,
  DIFFICULTY_TARGET_V1,
  DIFFICULTY_TARGET_V2 as CONSENSUS_DIFFICULTY_TARGET,
  CRYPTONOTE_BLOCK_FUTURE_TIME_LIMIT,
  BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW,
  DIFFICULTY_WINDOW,
  DIFFICULTY_WINDOW_V2,
  DIFFICULTY_LAG,
  DIFFICULTY_CUT,
  DIFFICULTY_BLOCKS_COUNT,
  DIFFICULTY_BLOCKS_COUNT_V2,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V1,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V2,
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE_V5,
  CRYPTONOTE_LONG_TERM_BLOCK_WEIGHT_WINDOW_SIZE,
  CRYPTONOTE_SHORT_TERM_BLOCK_WEIGHT_SURGE_FACTOR,
  CRYPTONOTE_MAX_TX_SIZE,
  CRYPTONOTE_MAX_TX_PER_BLOCK,
  MAX_TX_EXTRA_SIZE,
  BULLETPROOF_MAX_OUTPUTS,
  BULLETPROOF_PLUS_MAX_OUTPUTS,
  CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
  CRYPTONOTE_LOCKED_TX_ALLOWED_DELTA_BLOCKS,
  CURRENT_TRANSACTION_VERSION,
  TRANSACTION_VERSION_2_OUTS,
  TRANSACTION_VERSION_N_OUTS,
  TRANSACTION_VERSION_CARROT,
  DYNAMIC_FEE_REFERENCE_TRANSACTION_WEIGHT,
  DEFAULT_DUST_THRESHOLD,
  BASE_REWARD_CLAMP_THRESHOLD,
  CRYPTONOTE_MEMPOOL_TX_LIVETIME,
  CRYPTONOTE_MEMPOOL_TX_FROM_ALT_BLOCK_LIVETIME,
  DEFAULT_TXPOOL_MAX_WEIGHT,
  DEFAULT_RING_SIZE as CONSENSUS_DEFAULT_RING_SIZE,
  PRICING_RECORD_VALID_BLOCKS,
  PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK,
  BURN_LOCK_PERIOD,
  CONVERT_LOCK_PERIOD,
  HF_VERSION,
  NETWORK_ID,
  MAINNET_CONFIG,
  TESTNET_CONFIG,
  STAGENET_CONFIG,
  // Functions
  getNetworkConfig,
  getMinBlockWeight,
  getBlockReward,
  getApproximateEmission,
  nextDifficulty,
  nextDifficultyV2,
  checkHash as consensusCheckHash,
  getMedianTimestamp,
  validateBlockTimestamp,
  isOutputUnlocked,
  isCoinbaseMature,
  meetsMinimumAge,
  getMinimumFee,
  getDynamicFee,
  quantizeFee,
  validateBlockLinkage,
  validateBlockWeight,
  validateTxSize,
  validateTxExtraSize,
  validateOutputCount,
  validateRingSize
} from './consensus.js';

import {
  // Constants
  COIN as ORACLE_COIN,
  PRICING_RECORD_VALID_BLOCKS as ORACLE_PR_VALID_BLOCKS,
  PRICING_RECORD_VALID_TIME_DIFF_FROM_BLOCK as ORACLE_PR_TIME_DIFF,
  CONVERSION_RATE_ROUNDING,
  ASSET_TYPES,
  HF_VERSION_ENABLE_ORACLE as ORACLE_HF_ENABLE,
  HF_VERSION_SLIPPAGE_YIELD,
  ORACLE_URLS,
  ORACLE_PUBLIC_KEY_MAINNET,
  ORACLE_PUBLIC_KEY_TESTNET,
  // Data structures
  createEmptyPricingRecord,
  isPricingRecordEmpty,
  getAssetPrice,
  getAssetMaPrice,
  // Signature verification
  buildSignatureMessage,
  verifyPricingRecordSignature,
  getOraclePublicKey,
  // Validation
  validatePricingRecord,
  // Conversion
  getConversionRate,
  getConvertedAmount,
  calculateSlippage,
  calculateConversion,
  // Serialization
  parsePricingRecordFromJson,
  pricingRecordToJson,
  // HTTP client
  fetchPricingRecord
} from './oracle.js';

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
  pointSubCompressed,
  pointNegate,
  ed25519RandomScalar,
  randomPoint,
  isValidPoint,
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

  // Block Serialization
  HF_VERSION_ENABLE_ORACLE,
  serializeSupplyData,
  serializeAssetData,
  serializePricingRecord,
  serializeBlockHeader,
  serializeBlock,
  getBlockHash,
  computeMerkleRoot,

  // UTXO Selection
  UTXO_STRATEGY,
  selectUTXOs,

  // Transaction Building
  buildTransaction,
  signTransaction,
  prepareInputs,
  estimateTransactionFee,
  validateTransaction,
  serializeTransaction,

  // Transaction Parsing
  parseTransaction,
  parseExtra,
  decodeAmount,
  extractTxPubKey,
  extractPaymentId,
  summarizeTransaction,
  getTransactionHashFromParsed,

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
  // Proof generation
  proveRange,
  proveRangeMultiple,
  randomScalar,
  serializeProof,
  bulletproofPlusProve,
  Point,

  // Mining
  MINING_CONSTANTS,
  parseBlockTemplate,
  parseDifficulty,
  treeHash,
  constructBlockHashingBlob,
  setNonce,
  getNonce,
  setExtraNonce,
  checkHash,
  difficultyToTarget,
  hashToDifficulty,
  formatDifficulty,
  formatBlockForSubmission,
  findNonceOffset,
  calculateHashrate,
  formatHashrate,
  estimateBlockTime,
  formatDuration,
  createMiningContext,

  // RandomX (WASM-JIT)
  // Light mode (256MB cache per thread)
  RandomXContext,
  RandomXNative,
  RandomXWorkerPool,
  getAvailableCores,
  // Full mode (2GB shared dataset)
  RandomXFullMode,
  createFullModeContext,
  RANDOMX_DATASET_ITEM_COUNT,
  RANDOMX_DATASET_ITEM_SIZE,
  RANDOMX_DATASET_SIZE,
  // Functions
  rxSlowHash,
  randomxHash,
  calculateCommitment,
  verifyHash,
  randomxCheckDifficulty,
  randomxMine,
  randomx_init_cache,
  randomx_create_vm,
  randomx_machine_id,

  // Wallet
  Wallet,
  WalletListener,
  Account,
  WALLET_TYPE,
  TX_TYPE,
  MAX_SUBADDRESS_MAJOR_INDEX,
  MAX_SUBADDRESS_MINOR_INDEX,
  createWallet,
  restoreWallet,
  createViewOnlyWallet,

  // Query/Filter Objects
  OutputQuery,
  TxQuery,
  TransferQuery,
  createOutputQuery,
  createTxQuery,
  createTransferQuery,
  // Query presets
  unspentOutputs,
  spentOutputs,
  lockedOutputs,
  unlockedOutputs,
  stakingOutputs,
  yieldOutputs,
  incomingTxs,
  outgoingTxs,
  pendingTxs,
  confirmedTxs,
  stakingTxs,
  yieldTxs,

  // Connection Manager
  ConnectionManager,
  ConnectionInfo,
  CONNECTION_STATE,
  createDaemonConnectionManager,
  createWalletConnectionManager,

  // Offline Signing
  UNSIGNED_TX_VERSION,
  SIGNED_TX_VERSION,
  createUnsignedTx,
  parseUnsignedTx,
  createSignedTx,
  parseSignedTx,
  exportUnsignedTx,
  importUnsignedTx,
  signOffline,
  exportSignedTx,
  importSignedTx,
  getTxBlobHex,
  exportKeyImagesOffline,
  importKeyImagesOffline,
  exportOutputs,
  importOutputs,
  verifyUnsignedTx,
  summarizeUnsignedTx,

  // Multisig
  MULTISIG_MAX_SIGNERS,
  MULTISIG_MIN_THRESHOLD,
  MULTISIG_NONCE_COMPONENTS,
  MULTISIG_MSG_TYPE,
  KexMessage,
  MultisigSigner,
  MultisigAccount,
  MultisigTxSet,
  MultisigPartialSig,
  MultisigTxBuilder,
  MultisigWallet,
  getMultisigBlindedSecretKey,
  computeDHSecret,
  kexRoundsRequired,
  generateMultisigNonces,
  combineMultisigNonces,
  createMultisigWallet,
  prepareMultisig,
  isMultisig,

  // Wallet Storage
  WalletStorage,
  WalletOutput,
  WalletTransaction,
  MemoryStorage,
  IndexedDBStorage,
  createStorage,

  // Wallet Sync
  WalletSync,
  createWalletSync,
  SYNC_STATUS,
  DEFAULT_BATCH_SIZE,
  SYNC_UNLOCK_BLOCKS,

  // Persistent Wallet
  PersistentWallet,
  createPersistentWallet,
  restorePersistentWallet,
  openPersistentWallet,

  // Oracle/Pricing
  ORACLE_COIN,
  ORACLE_PR_VALID_BLOCKS,
  ORACLE_PR_TIME_DIFF,
  CONVERSION_RATE_ROUNDING,
  ASSET_TYPES,
  ORACLE_HF_ENABLE,
  HF_VERSION_SLIPPAGE_YIELD,
  ORACLE_URLS,
  ORACLE_PUBLIC_KEY_MAINNET,
  ORACLE_PUBLIC_KEY_TESTNET,
  createEmptyPricingRecord,
  isPricingRecordEmpty,
  getAssetPrice,
  getAssetMaPrice,
  buildSignatureMessage,
  verifyPricingRecordSignature,
  getOraclePublicKey,
  validatePricingRecord,
  getConversionRate,
  getConvertedAmount,
  calculateSlippage,
  calculateConversion,
  parsePricingRecordFromJson,
  pricingRecordToJson,
  fetchPricingRecord
};

export default salvium;
