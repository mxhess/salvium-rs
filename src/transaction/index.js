/**
 * Transaction Module Index
 *
 * Re-exports all transaction-related functionality from submodules.
 * This allows for both granular imports and backward-compatible bulk imports.
 *
 * @module transaction
 */

// Constants
export {
  ParseError,
  L,
  P,
  H,
  TX_VERSION,
  TX_TYPE,
  RCT_TYPE,
  TXOUT_TYPE,
  TXIN_TYPE,
  DIFFICULTY_TARGET,
  RECENT_SPEND_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
  DEFAULT_RING_SIZE,
  HF_VERSION_ENABLE_ORACLE,
  FEE_PER_KB,
  FEE_PER_BYTE,
  DYNAMIC_FEE_PER_KB_BASE_FEE,
  DYNAMIC_FEE_PER_KB_BASE_BLOCK_REWARD,
  DYNAMIC_FEE_REFERENCE_TX_WEIGHT,
  FEE_QUANTIZATION_DECIMALS,
  FEE_MULTIPLIERS,
  FEE_PRIORITY,
  getFeeMultiplier,
  UTXO_STRATEGY,
  CARROT_DOMAIN,
  CARROT_ENOTE_TYPE
} from './constants.js';

// UTXO Selection
export { selectUTXOs } from './utxo.js';

// Serialization
export {
  // Scalar operations
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
  // Commitments
  commit,
  zeroCommit,
  genCommitmentMask,
  // Varint
  encodeVarint,
  decodeVarint,
  // Utilities
  concatBytes,
  // Output/Input serialization
  serializeTxOutput,
  serializeTxInput,
  serializeGenInput,
  // Extra serialization
  serializeTxExtra,
  // Prefix serialization
  serializeTxPrefix,
  getTxPrefixHash,
  // RingCT serialization
  serializeCLSAG,
  serializeRctBase,
  serializeEcdhInfo,
  serializeOutPk,
  // Transaction serialization
  serializeTransaction
} from './serialization.js';

// Parsing
export {
  parseTransaction,
  parseExtra,
  parsePricingRecord,
  parseBlock
} from './parsing.js';

// Analysis
export {
  getTransactionHashFromParsed,
  decodeAmount,
  extractTxPubKey,
  extractPaymentId,
  extractAdditionalPubKeys,
  summarizeTransaction,
  getTransactionTypeName,
  getRctTypeName,
  analyzeTransaction
} from './analysis.js';

// CARROT Output Creation
export {
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
} from './carrot-output.js';
