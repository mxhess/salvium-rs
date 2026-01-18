/**
 * salvium-js TypeScript Definitions
 *
 * JavaScript library for Salvium cryptocurrency
 */

// ============================================================================
// Constants
// ============================================================================

export declare const NETWORK: {
  readonly MAINNET: 'mainnet';
  readonly TESTNET: 'testnet';
  readonly STAGENET: 'stagenet';
};

export declare const ADDRESS_TYPE: {
  readonly STANDARD: 'standard';
  readonly INTEGRATED: 'integrated';
  readonly SUBADDRESS: 'subaddress';
};

export declare const ADDRESS_FORMAT: {
  readonly LEGACY: 'legacy';
  readonly CARROT: 'carrot';
};

export declare const PREFIXES: {
  readonly [key: string]: {
    readonly network: string;
    readonly format: string;
    readonly type: string;
    readonly prefix: number;
  };
};

export type Network = 'mainnet' | 'testnet' | 'stagenet';
export type AddressType = 'standard' | 'integrated' | 'subaddress';
export type AddressFormat = 'legacy' | 'carrot';

// ============================================================================
// Hashing Functions
// ============================================================================

export declare function keccak256(data: Uint8Array | string): Uint8Array;
export declare function keccak256Hex(data: Uint8Array | string): string;
export declare function cnFastHash(data: Uint8Array | string): Uint8Array;

export declare function blake2b(data: Uint8Array, outlen?: number, key?: Uint8Array): Uint8Array;
export declare function blake2bHex(data: Uint8Array, outlen?: number, key?: Uint8Array): string;

// ============================================================================
// Base58 Encoding
// ============================================================================

export declare function encode(data: Uint8Array): string;
export declare function decode(str: string): Uint8Array;
export declare function encodeAddress(prefix: number, data: Uint8Array): string;
export declare function decodeAddress(address: string): { prefix: number; data: Uint8Array };

// ============================================================================
// Utilities
// ============================================================================

export declare function bytesToHex(bytes: Uint8Array): string;
export declare function hexToBytes(hex: string): Uint8Array;

// ============================================================================
// Address Functions
// ============================================================================

export interface ParsedAddress {
  valid: boolean;
  network: Network | null;
  format: AddressFormat | null;
  type: AddressType | null;
  prefix: string | null;
  spendPublicKey: Uint8Array | null;
  viewPublicKey: Uint8Array | null;
  paymentId: Uint8Array | null;
  error: string | null;
}

export interface CreateAddressOptions {
  network: Network;
  format: AddressFormat;
  type: AddressType;
  spendPublicKey: Uint8Array;
  viewPublicKey: Uint8Array;
  paymentId?: Uint8Array | string;
}

export declare function parseAddress(address: string): ParsedAddress;
export declare function isValidAddress(address: string): boolean;
export declare function isMainnet(address: string): boolean;
export declare function isTestnet(address: string): boolean;
export declare function isStagenet(address: string): boolean;
export declare function isCarrot(address: string): boolean;
export declare function isLegacy(address: string): boolean;
export declare function isStandard(address: string): boolean;
export declare function isIntegrated(address: string): boolean;
export declare function isSubaddress(address: string): boolean;
export declare function getSpendPublicKey(address: string): Uint8Array | null;
export declare function getViewPublicKey(address: string): Uint8Array | null;
export declare function getPaymentId(address: string): Uint8Array | null;
export declare function createAddress(options: CreateAddressOptions): string;
export declare function toIntegratedAddress(address: string, paymentId: string | Uint8Array): string;
export declare function toStandardAddress(integratedAddress: string): string;
export declare function describeAddress(address: string): string;

// ============================================================================
// Key Derivation
// ============================================================================

export interface DerivedKeys {
  spendSecretKey: Uint8Array;
  spendPublicKey: Uint8Array;
  viewSecretKey: Uint8Array;
  viewPublicKey: Uint8Array;
}

export interface CarrotKeys {
  masterSecret: string;
  proveSpendKey: string;
  viewBalanceSecret: string;
  generateImageKey: string;
  viewIncomingKey: string;
  generateAddressSecret: string;
}

export declare function generateSeed(): Uint8Array;
export declare function deriveKeys(seed: Uint8Array): DerivedKeys;
export declare function deriveCarrotKeys(seed: Uint8Array): CarrotKeys;
export declare function makeViewBalanceSecret(seed: Uint8Array): Uint8Array;
export declare function makeViewIncomingKey(seed: Uint8Array): Uint8Array;
export declare function makeProveSpendKey(seed: Uint8Array): Uint8Array;
export declare function makeGenerateImageKey(seed: Uint8Array): Uint8Array;
export declare function makeGenerateAddressSecret(seed: Uint8Array): Uint8Array;

// ============================================================================
// Mnemonic Functions
// ============================================================================

export interface MnemonicOptions {
  language?: string;
}

export interface MnemonicResult {
  valid: boolean;
  seed?: Uint8Array;
  error?: string;
}

export interface LanguageDetection {
  language: { name: string; code: string };
  confidence: number;
}

export declare function seedToMnemonic(seed: Uint8Array, options?: MnemonicOptions): string;
export declare function mnemonicToSeed(mnemonic: string, options?: MnemonicOptions): MnemonicResult;
export declare function validateMnemonic(mnemonic: string, options?: MnemonicOptions): MnemonicResult;
export declare function detectLanguage(mnemonic: string): LanguageDetection;
export declare function getLanguage(code: string): { name: string; words: string[] } | null;
export declare function getAvailableLanguages(): string[];

// ============================================================================
// Subaddress Generation
// ============================================================================

export interface CNSubaddressOptions {
  network: Network;
  spendPublicKey: Uint8Array;
  viewSecretKey: Uint8Array;
  major: number;
  minor: number;
}

export interface CarrotSubaddressOptions {
  network: Network;
  accountSpendPubkey: Uint8Array;
  accountViewPubkey: Uint8Array;
  generateAddressSecret: Uint8Array;
  major: number;
  minor: number;
}

export interface SubaddressResult {
  address: string;
  spendPublicKey: Uint8Array;
  viewPublicKey?: Uint8Array;
}

export declare function generateCNSubaddress(options: CNSubaddressOptions): SubaddressResult;
export declare function generateCarrotSubaddress(options: CarrotSubaddressOptions): SubaddressResult;
export declare function generateRandomPaymentId(): Uint8Array;
export declare function createIntegratedAddressWithRandomId(address: string): { address: string; paymentIdHex: string };

// ============================================================================
// Signature Verification
// ============================================================================

export interface SignatureResult {
  valid: boolean;
  version: number;
  keyType: 'spend' | 'view';
  error: string | null;
}

export declare function verifySignature(message: string, address: string, signature: string): SignatureResult;
export declare function parseSignature(signature: string): { version: number; data: Uint8Array } | null;

// ============================================================================
// Transaction Scanning
// ============================================================================

export declare function generateKeyDerivation(publicKey: Uint8Array, secretKey: Uint8Array): Uint8Array;
export declare function derivationToScalar(derivation: Uint8Array, outputIndex: number): Uint8Array;
export declare function derivePublicKey(derivation: Uint8Array, outputIndex: number, spendPublicKey: Uint8Array): Uint8Array;
export declare function deriveSecretKey(derivation: Uint8Array, outputIndex: number, spendSecretKey: Uint8Array): Uint8Array;
export declare function deriveViewTag(derivation: Uint8Array, outputIndex: number): number;
export declare function checkOutputOwnership(derivation: Uint8Array, outputIndex: number, spendPublicKey: Uint8Array, outputPublicKey: Uint8Array): boolean;

export interface ScanOutputParams {
  derivation: Uint8Array;
  outputIndex: number;
  outputPublicKey: Uint8Array;
  spendPublicKey: Uint8Array;
  viewTag?: number;
  encryptedAmount?: Uint8Array;
}

export interface ScanOutputResult {
  owned: boolean;
  amount?: bigint;
  outputSecretKey?: Uint8Array;
}

export declare function scanOutput(params: ScanOutputParams): ScanOutputResult;
export declare function ecdhDecode(encryptedAmount: Uint8Array, derivation: Uint8Array, outputIndex: number): bigint;
export declare function ecdhEncode(amount: bigint, derivation: Uint8Array, outputIndex: number): Uint8Array;

// ============================================================================
// Key Images
// ============================================================================

export declare function hashToPoint(data: Uint8Array): Uint8Array;
export declare function generateKeyImage(outputPublicKey: Uint8Array, outputSecretKey: Uint8Array): Uint8Array;
export declare function isValidKeyImage(keyImage: Uint8Array): boolean;

export interface KeyImageExport {
  keyImage: Uint8Array;
  txHash: string;
  outputIndex: number;
}

export declare function exportKeyImages(outputs: KeyImageExport[]): string;
export declare function importKeyImages(data: string): Map<string, KeyImageExport>;

// ============================================================================
// Transaction Construction
// ============================================================================

// Scalar operations
export declare const L: bigint;
export declare const H: Uint8Array;
export declare function scAdd(a: Uint8Array, b: Uint8Array): Uint8Array;
export declare function scSub(a: Uint8Array, b: Uint8Array): Uint8Array;
export declare function scMul(a: Uint8Array, b: Uint8Array): Uint8Array;
export declare function scRandom(): Uint8Array;
export declare function scInvert(a: Uint8Array): Uint8Array;

// Pedersen commitments
export declare function commit(amount: bigint, mask: Uint8Array): Uint8Array;
export declare function zeroCommit(amount: bigint): Uint8Array;
export declare function genCommitmentMask(derivation: Uint8Array, outputIndex: number): Uint8Array;

// Output creation
export interface OutputResult {
  outputPublicKey: Uint8Array;
  txPublicKey: Uint8Array;
  commitment: Uint8Array;
  encryptedAmount: Uint8Array;
  mask: Uint8Array;
  viewTag: number;
}

export declare function createOutput(
  txSecretKey: Uint8Array,
  recipientViewPublicKey: Uint8Array,
  recipientSpendPublicKey: Uint8Array,
  amount: bigint,
  outputIndex: number,
  isSubaddress?: boolean
): OutputResult;

// CLSAG signatures
export interface CLSAGSignature {
  s: Uint8Array[];
  c1: Uint8Array;
  D: Uint8Array;
}

export declare function clsagSign(
  message: Uint8Array,
  ring: Uint8Array[],
  secretKey: Uint8Array,
  commitments: Uint8Array[],
  maskDiff: Uint8Array,
  pseudoCommitment: Uint8Array,
  secretIndex: number
): CLSAGSignature;

export declare function clsagVerify(
  message: Uint8Array,
  signature: CLSAGSignature,
  ring: Uint8Array[],
  commitments: Uint8Array[],
  pseudoCommitment: Uint8Array
): boolean;

// Serialization
export declare function encodeVarint(value: bigint | number): Uint8Array;
export declare function decodeVarint(bytes: Uint8Array, offset?: number): { value: bigint; bytesRead: number };
export declare function serializeTxPrefix(tx: object): Uint8Array;
export declare function getTxPrefixHash(tx: object): Uint8Array;
export declare function getTransactionHash(tx: object): Uint8Array;

// Fee calculation
export declare const FEE_PER_BYTE: bigint;
export declare const FEE_PRIORITY: { DEFAULT: number; LOW: number; NORMAL: number; HIGH: number; HIGHEST: number };
export declare function estimateFee(numInputs: number, numOutputs: number, priority?: number): bigint;
export declare function estimateTxSize(numInputs: number, numOutputs: number): number;

// Decoy selection
export declare const DEFAULT_RING_SIZE: number;
export declare function selectDecoys(
  outputIndex: bigint,
  ringSize: number,
  availableOutputs: bigint[],
  recentOutputs?: bigint[]
): bigint[];

// ============================================================================
// UTXO Selection
// ============================================================================

export declare const UTXO_STRATEGY: {
  readonly MINIMIZE_INPUTS: 'minimize_inputs';
  readonly MINIMIZE_CHANGE: 'minimize_change';
  readonly OLDEST_FIRST: 'oldest_first';
  readonly NEWEST_FIRST: 'newest_first';
  readonly RANDOM: 'random';
};

export type UTXOStrategy = 'minimize_inputs' | 'minimize_change' | 'oldest_first' | 'newest_first' | 'random';

export interface UTXO {
  txHash: string;
  outputIndex: number;
  amount: bigint;
  publicKey: Uint8Array;
  commitment?: Uint8Array;
  globalIndex?: bigint;
  blockHeight?: number;
  unlockTime?: bigint;
}

export interface UTXOSelectionResult {
  selectedUTXOs: UTXO[];
  totalAmount: bigint;
  changeAmount: bigint;
  estimatedFee: bigint;
}

export declare function selectUTXOs(
  utxos: UTXO[],
  targetAmount: bigint,
  feePerByte?: bigint,
  strategy?: UTXOStrategy
): UTXOSelectionResult;

// ============================================================================
// Transaction Building
// ============================================================================

export interface Destination {
  address: string;
  amount: bigint;
}

export interface BuildTransactionOptions {
  utxos: UTXO[];
  destinations: Destination[];
  changeAddress: string;
  viewSecretKey: Uint8Array;
  spendSecretKey: Uint8Array;
  feePerByte?: bigint;
  ringSize?: number;
  unlockTime?: bigint;
}

export interface BuiltTransaction {
  tx: object;
  txHash: string;
  fee: bigint;
  changeAmount: bigint;
}

export declare function buildTransaction(options: BuildTransactionOptions): Promise<BuiltTransaction>;
export declare function signTransaction(unsignedTx: object, spendSecretKey: Uint8Array): object;
export declare function validateTransaction(tx: object): { valid: boolean; errors: string[] };
export declare function serializeTransaction(tx: object): Uint8Array;
export declare function estimateTransactionFee(numInputs: number, numOutputs: number, feePerByte?: bigint): bigint;

// ============================================================================
// Transaction Parsing
// ============================================================================

export interface ParsedExtra {
  txPubKey?: Uint8Array;
  paymentId?: Uint8Array;
  additionalPubKeys?: Uint8Array[];
  nonces?: Uint8Array[];
}

export interface TransactionSummary {
  hash: string;
  version: number;
  unlockTime: bigint;
  numInputs: number;
  numOutputs: number;
  fee?: bigint;
  isCoinbase: boolean;
  keyImages: Uint8Array[];
  outputKeys: Uint8Array[];
  commitments?: Uint8Array[];
  extra: ParsedExtra;
}

export declare function parseTransaction(txData: Uint8Array | string): object;
export declare function parseExtra(extra: Uint8Array): ParsedExtra;
export declare function extractTxPubKey(extra: ParsedExtra): Uint8Array | null;
export declare function extractPaymentId(extra: ParsedExtra): Uint8Array | null;
export declare function decodeAmount(encryptedAmount: Uint8Array, derivation: Uint8Array, outputIndex: number): bigint;
export declare function summarizeTransaction(tx: object): TransactionSummary;

// ============================================================================
// Bulletproofs+ Range Proofs
// ============================================================================

export interface BulletproofPlusProof {
  V: Uint8Array[];
  A: Uint8Array;
  A1: Uint8Array;
  B: Uint8Array;
  r1: Uint8Array;
  s1: Uint8Array;
  d1: Uint8Array;
  L: Uint8Array[];
  R: Uint8Array[];
}

export declare function proveRange(amount: bigint, mask: Uint8Array): BulletproofPlusProof;
export declare function proveRangeMultiple(amounts: bigint[], masks: Uint8Array[]): BulletproofPlusProof;
export declare function verifyBulletproofPlus(V: Uint8Array[], proof: BulletproofPlusProof): boolean;
export declare function verifyBulletproofPlusBatch(proofs: { V: Uint8Array[]; proof: BulletproofPlusProof }[]): boolean;
export declare function verifyRangeProof(commitments: Uint8Array[], proofBytes: Uint8Array): boolean;
export declare function parseProof(proofBytes: Uint8Array): BulletproofPlusProof;
export declare function serializeProof(proof: BulletproofPlusProof): Uint8Array;
export declare function randomScalar(): Uint8Array;
export declare function initGenerators(n: number): void;

// ============================================================================
// Mining
// ============================================================================

export declare const MINING_CONSTANTS: {
  CRYPTONOTE_BLOCK_GRANTED_FULL_REWARD_ZONE: number;
  CRYPTONOTE_COINBASE_BLOB_RESERVED_SIZE: number;
  DIFFICULTY_TARGET: number;
};

export interface BlockTemplate {
  blockTemplateBlob: Uint8Array;
  difficulty: bigint;
  height: number;
  reservedOffset: number;
  prevHash: Uint8Array;
  seedHash: Uint8Array;
}

export declare function parseBlockTemplate(templateHex: string, difficultyHex: string): BlockTemplate;
export declare function constructBlockHashingBlob(blockBlob: Uint8Array): Uint8Array;
export declare function setNonce(blockBlob: Uint8Array, nonce: number): void;
export declare function getNonce(blockBlob: Uint8Array): number;
export declare function checkHash(hash: Uint8Array, target: Uint8Array): boolean;
export declare function difficultyToTarget(difficulty: bigint): Uint8Array;
export declare function hashToDifficulty(hash: Uint8Array): bigint;
export declare function formatHashrate(hashrate: number): string;
export declare function calculateHashrate(hashes: number, seconds: number): number;

// ============================================================================
// RandomX Proof-of-Work
// ============================================================================

export declare class RandomXContext {
  constructor();
  init(key: Uint8Array | string, onProgress?: (percent: number) => void): Promise<void>;
  hash(input: Uint8Array | string): Uint8Array;
  hashHex(input: Uint8Array | string): string;
  verify(input: Uint8Array | string, expectedHash: Uint8Array | string): boolean;
  static getMachineId(): string;
}

export declare class RandomXNative {
  constructor();
  init(key: Uint8Array | string, onProgress?: (percent: number) => void): Promise<void>;
  hash(input: Uint8Array | string): Uint8Array;
  hashHex(input: Uint8Array | string): string;
  static getMachineId(): string;
}

export declare class RandomXWorkerPool {
  constructor(numWorkers?: number);
  init(key: Uint8Array | string): Promise<void>;
  hash(input: Uint8Array | string): Promise<Uint8Array>;
  terminate(): void;
}

export declare class RandomXFullMode {
  constructor();
  init(key: Uint8Array | string, onProgress?: (percent: number) => void): Promise<void>;
  hash(input: Uint8Array | string): Uint8Array;
  hashHex(input: Uint8Array | string): string;
}

export declare function rxSlowHash(key: Uint8Array | string, input: Uint8Array | string): Promise<Uint8Array>;
export declare function randomxHash(key: Uint8Array | string, input: Uint8Array | string): Promise<Uint8Array>;
export declare function verifyHash(key: Uint8Array | string, input: Uint8Array | string, expectedHash: Uint8Array | string): Promise<boolean>;
export declare function checkDifficulty(hash: Uint8Array | string, difficulty: bigint | number): boolean;
export declare function calculateCommitment(blockHash: Uint8Array, previousHash: Uint8Array): Uint8Array;

export declare function mine(
  key: Uint8Array | string,
  blockTemplate: Uint8Array,
  nonceOffset: number,
  difficulty: bigint,
  maxIterations?: number
): Promise<{ nonce: number; hash: Uint8Array } | null>;

export declare function getAvailableCores(): number;
export declare function createFullModeContext(): RandomXFullMode;

export declare const RANDOMX_DATASET_ITEM_COUNT: number;
export declare const RANDOMX_DATASET_ITEM_SIZE: number;
export declare const RANDOMX_DATASET_SIZE: number;

// RandomX internals (for testing)
export declare class RandomXCache {
  constructor();
  init(key: Uint8Array): void;
}

export declare class Blake2Generator {
  constructor(seed: Uint8Array);
  getByte(): number;
  getUInt32(): number;
  getBytes(count: number): Uint8Array;
}

export declare function initDatasetItem(cache: RandomXCache, itemNumber: number): Uint8Array;
export declare function generateSuperscalar(gen: Blake2Generator): object;
export declare function executeSuperscalar(registers: bigint[], program: object): void;
export declare function reciprocal(divisor: number): bigint;
export declare function argon2d(
  password: Uint8Array,
  salt: Uint8Array,
  timeCost: number,
  memoryCost: number,
  parallelism: number,
  outputLength: number
): Uint8Array;

// ============================================================================
// Wallet Class
// ============================================================================

export declare const WALLET_TYPE: {
  readonly FULL: 'full';
  readonly VIEW_ONLY: 'view_only';
};

export type WalletType = 'full' | 'view_only';

export interface WalletBalance {
  total: bigint;
  unlocked: bigint;
  locked: bigint;
}

export interface WalletJSON {
  version: number;
  type: WalletType;
  network: Network;
  createdAt: number;
  syncHeight: number;
  viewSecretKey: string;
  viewPublicKey: string;
  spendPublicKey: string;
  spendSecretKey?: string;
}

export declare class Wallet {
  constructor(options: {
    network?: Network;
    viewSecretKey: Uint8Array;
    viewPublicKey: Uint8Array;
    spendPublicKey: Uint8Array;
    spendSecretKey?: Uint8Array;
  });

  getType(): WalletType;
  getNetwork(): Network;
  isViewOnly(): boolean;
  canSign(): boolean;
  canScan(): boolean;

  getAddress(): string;
  getSubaddress(major: number, minor: number): string;

  getViewSecretKey(): Uint8Array;
  getViewPublicKey(): Uint8Array;
  getSpendPublicKey(): Uint8Array;
  getSpendSecretKey(): Uint8Array | null;
  getMnemonic(): string | null;

  getBalance(): WalletBalance;
  getUTXOs(): UTXO[];

  getSyncHeight(): number;
  setSyncHeight(height: number): void;

  toJSON(includeSecrets?: boolean): WalletJSON;
  static fromJSON(json: WalletJSON): Wallet;
}

export declare function createWallet(options?: { network?: Network }): {
  wallet: Wallet;
  mnemonic: string;
  seed: Uint8Array;
};

export declare function restoreWallet(mnemonic: string, options?: { network?: Network }): Wallet;

export declare function createViewOnlyWallet(options: {
  network?: Network;
  viewSecretKey: Uint8Array | string;
  spendPublicKey: Uint8Array | string;
}): Wallet;

// ============================================================================
// RPC Clients
// ============================================================================

export interface RPCClientOptions {
  url: string;
  timeout?: number;
  retries?: number;
  retryDelay?: number;
  username?: string;
  password?: string;
}

export interface RPCResponse<T = any> {
  success: boolean;
  result?: T;
  error?: { code: number; message: string };
}

export declare class RPCClient {
  constructor(options: RPCClientOptions);
  call<T = any>(method: string, params?: object): Promise<RPCResponse<T>>;
}

export declare class DaemonRPC extends RPCClient {
  getInfo(): Promise<RPCResponse>;
  getHeight(): Promise<RPCResponse<{ height: number }>>;
  getBlockTemplate(params: { wallet_address: string; reserve_size?: number }): Promise<RPCResponse>;
  submitBlock(blockBlob: string): Promise<RPCResponse>;
  getBlockHeaderByHeight(height: number): Promise<RPCResponse>;
  getBlockHeaderByHash(hash: string): Promise<RPCResponse>;
  getBlock(params: { height?: number; hash?: string }): Promise<RPCResponse>;
  getTransactions(txHashes: string[], decodeAsJson?: boolean): Promise<RPCResponse>;
  getTransactionPool(): Promise<RPCResponse>;
  sendRawTransaction(txAsHex: string): Promise<RPCResponse>;
  getFeeEstimate(): Promise<RPCResponse>;
  getOuts(outputs: { amount: number; index: number }[]): Promise<RPCResponse>;
  isKeyImageSpent(keyImages: string[]): Promise<RPCResponse>;
}

export declare class WalletRPC extends RPCClient {
  createWallet(params: { filename: string; password: string; language?: string }): Promise<RPCResponse>;
  openWallet(params: { filename: string; password: string }): Promise<RPCResponse>;
  closeWallet(): Promise<RPCResponse>;
  getBalance(params?: { account_index?: number }): Promise<RPCResponse>;
  getAddress(params?: { account_index?: number; address_index?: number[] }): Promise<RPCResponse>;
  createAddress(params?: { account_index?: number; label?: string }): Promise<RPCResponse>;
  transfer(params: {
    destinations: { address: string; amount: number }[];
    priority?: number;
    mixin?: number;
    unlock_time?: number;
  }): Promise<RPCResponse>;
  getTransfers(params: { in?: boolean; out?: boolean; pending?: boolean; pool?: boolean }): Promise<RPCResponse>;
  getTransferByTxid(params: { txid: string }): Promise<RPCResponse>;
  exportKeyImages(): Promise<RPCResponse>;
  importKeyImages(params: { signed_key_images: { key_image: string; signature: string }[] }): Promise<RPCResponse>;
  queryKey(params: { key_type: 'mnemonic' | 'view_key' | 'spend_key' }): Promise<RPCResponse>;
}

export declare function createDaemonRPC(options: RPCClientOptions): DaemonRPC;
export declare function createWalletRPC(options: RPCClientOptions): WalletRPC;

export declare const RPC_ERROR_CODES: { [key: string]: number };
export declare const RPC_STATUS: { OK: string; BUSY: string; ERROR: string };
export declare const PRIORITY: { DEFAULT: number; LOW: number; NORMAL: number; HIGH: number; HIGHEST: number };
export declare const TRANSFER_TYPE: { ALL: string; AVAILABLE: string; UNAVAILABLE: string };

// ============================================================================
// Stratum Mining
// ============================================================================

export declare class StratumClient {
  constructor(options: { host: string; port: number; ssl?: boolean });
  connect(): Promise<void>;
  disconnect(): void;
  login(params: { login: string; pass?: string; agent?: string }): Promise<object>;
  submit(params: { id: string; job_id: string; nonce: string; result: string }): Promise<boolean>;
  on(event: 'job' | 'error' | 'close', callback: (...args: any[]) => void): void;
}

export declare class StratumMiner {
  constructor(options: {
    host: string;
    port: number;
    wallet: string;
    password?: string;
    threads?: number;
    throttle?: number;
  });
  start(): Promise<void>;
  stop(): void;
  getHashrate(): number;
  getAcceptedShares(): number;
  getRejectedShares(): number;
  on(event: 'hashrate' | 'share' | 'error', callback: (...args: any[]) => void): void;
}

export declare function createMiner(options: {
  host: string;
  port: number;
  wallet: string;
  password?: string;
  threads?: number;
}): StratumMiner;

// ============================================================================
// Ed25519 Operations
// ============================================================================

export declare function scalarMultBase(scalar: Uint8Array): Uint8Array;
export declare function scalarMultPoint(scalar: Uint8Array, point: Uint8Array): Uint8Array;
export declare function pointAddCompressed(a: Uint8Array, b: Uint8Array): Uint8Array;
export declare function pointSubCompressed(a: Uint8Array, b: Uint8Array): Uint8Array;
export declare function pointNegate(point: Uint8Array): Uint8Array;
export declare function isValidPoint(point: Uint8Array): boolean;
export declare function randomPoint(): Uint8Array;

// ============================================================================
// Namespaces
// ============================================================================

export declare namespace randomx {
  export {
    RandomXContext,
    RandomXNative,
    RandomXWorkerPool,
    RandomXFullMode,
    RandomXCache,
    Blake2Generator,
    rxSlowHash,
    randomxHash,
    verifyHash,
    checkDifficulty,
    calculateCommitment,
    mine,
    initDatasetItem,
    generateSuperscalar,
    executeSuperscalar,
    reciprocal,
    argon2d,
    getAvailableCores,
    createFullModeContext,
    RANDOMX_DATASET_ITEM_COUNT,
    RANDOMX_DATASET_ITEM_SIZE,
    RANDOMX_DATASET_SIZE
  };
}

export declare namespace rpc {
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
  };
}

export declare namespace stratum {
  export {
    StratumClient,
    StratumMiner,
    createMiner
  };
}

export declare namespace wordlists {
  export const english: string[];
  export const spanish: string[];
  export const french: string[];
  export const german: string[];
  export const italian: string[];
  export const portuguese: string[];
  export const dutch: string[];
  export const russian: string[];
  export const japanese: string[];
  export const chinese_simplified: string[];
  export const esperanto: string[];
  export const lojban: string[];
}

// ============================================================================
// Default Export
// ============================================================================

declare const salvium: {
  // All named exports available on default object
  NETWORK: typeof NETWORK;
  ADDRESS_TYPE: typeof ADDRESS_TYPE;
  ADDRESS_FORMAT: typeof ADDRESS_FORMAT;

  keccak256: typeof keccak256;
  keccak256Hex: typeof keccak256Hex;
  blake2b: typeof blake2b;

  parseAddress: typeof parseAddress;
  isValidAddress: typeof isValidAddress;
  createAddress: typeof createAddress;

  generateSeed: typeof generateSeed;
  deriveKeys: typeof deriveKeys;
  deriveCarrotKeys: typeof deriveCarrotKeys;

  seedToMnemonic: typeof seedToMnemonic;
  mnemonicToSeed: typeof mnemonicToSeed;

  Wallet: typeof Wallet;
  createWallet: typeof createWallet;
  restoreWallet: typeof restoreWallet;
  createViewOnlyWallet: typeof createViewOnlyWallet;

  RandomXContext: typeof RandomXContext;
  rxSlowHash: typeof rxSlowHash;

  createDaemonRPC: typeof createDaemonRPC;
  createWalletRPC: typeof createWalletRPC;

  // ... and all other exports
  [key: string]: any;
};

export default salvium;
