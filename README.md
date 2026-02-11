# salvium-js

JavaScript/TypeScript library for Salvium cryptocurrency — wallet management, transaction construction, blockchain validation, and cryptographic operations with a high-performance Rust/WASM backend.

## Features

- **Wallet Generation** - Generate seeds, derive keys, create addresses
- **Mnemonic Support** - 25-word seed phrases in 12 languages
- **Key Derivation** - CryptoNote and CARROT key derivation from seeds
- **Address Creation** - Create all 18 Salvium address types
- **Subaddress Generation** - CryptoNote and CARROT subaddresses
- **Integrated Addresses** - Create and parse integrated addresses with payment IDs
- **Address Validation** - Parse and validate any Salvium address
- **Transaction Scanning** - CryptoNote + CARROT output detection, amount decryption, view tags
- **Key Images** - Generate and validate key images for spend detection
- **Transaction Construction** - Pedersen commitments, CLSAG/TCLSAG signatures, serialization
- **Bulletproofs+ Range Proofs** - Proof generation and verification
- **Blockchain Validation** - Full consensus rules, difficulty, fees, block/TX validation
- **RandomX Proof-of-Work** - WASM-JIT implementation with official test vectors
- **Stratum Mining Client** - Connect to mining pools with multi-threaded hashing
- **Wallet Class** - Unified wallet management with view-only mode, sync, and encrypted storage
- **UTXO Selection** - Multiple strategies (minimize inputs, minimize change, etc.)
- **Transaction Builder** - High-level buildTransaction() and signTransaction() API
- **Transaction Parser** - Decode and analyze transaction data
- **RPC Clients** - Full daemon and wallet RPC implementations
- **Signature Verification** - Verify message signatures (V1 and V2 formats)
- **Cryptographic Primitives** - Blake2b, Keccak-256, Ed25519, X25519, Base58
- **Multi-Network Support** - Mainnet, Testnet, Stagenet
- **TypeScript Support** - Full type definitions included
- **Oracle & Pricing** - Verify oracle signatures, fetch pricing records, calculate conversions
- **Wallet Encryption** - ML-KEM-768 + Argon2id encrypted wallet storage
- **Minimal Dependencies** - Only @noble/curves and @noble/hashes

## Crypto Backends

salvium-js includes three interchangeable crypto backends behind a unified provider API:

| Backend | Environment | Performance | Size |
|---------|-------------|-------------|------|
| **WASM** (default) | Browser, Node, Bun | 8-26x faster than JS | 336KB |
| **JSI** | React Native (iOS/Android) | Native speed via FFI | Static lib |
| **JS** | QuickJS, any JS runtime | Baseline (Noble curves) | Zero deps |

The WASM backend is loaded automatically via `initCrypto()`. All 28+ low-level primitives plus the expensive high-level protocols (CLSAG, TCLSAG, Bulletproofs+) run in Rust-compiled WASM. The JS backend is a transparent fallback for environments without WASM support.

```javascript
import { initCrypto, getCryptoBackend } from 'salvium-js';

// Initialize at app startup — loads WASM, falls back to JS
await initCrypto();

console.log(getCryptoBackend().name);  // 'wasm' or 'js'
```

### Performance (WASM vs JS)

| Operation | JS (Noble) | WASM (curve25519-dalek) | Speedup |
|-----------|-----------|-------------------------|---------|
| CLSAG sign (16-ring) | ~200ms | ~15ms | ~13x |
| TCLSAG sign (16-ring) | ~250ms | ~18ms | ~14x |
| BP+ prove (2 outputs) | ~1100ms | ~45ms | ~24x |
| BP+ verify (2 outputs) | ~300ms | ~20ms | ~15x |
| Key derivation | ~2ms | ~0.2ms | ~10x |

## Address Types Supported

| Network | Format | Standard | Integrated | Subaddress |
|---------|--------|----------|------------|------------|
| Mainnet | Legacy | SaLv... | SaLvi... | SaLvs... |
| Mainnet | CARROT | SC1... | SC1i... | SC1s... |
| Testnet | Legacy | SaLvT... | SaLvTi... | SaLvTs... |
| Testnet | CARROT | SC1T... | SC1Ti... | SC1Ts... |
| Stagenet | Legacy | SaLvS... | SaLvSi... | SaLvSs... |
| Stagenet | CARROT | SC1S... | SC1Si... | SC1Ss... |

## Installation

```bash
npm install salvium-js
```

Or include directly in browser:

```html
<script type="module">
  import salvium from './salvium-js/src/index.js';
</script>
```

## Quick Start: Generate a Wallet

```javascript
import {
  generateSeed,
  seedToMnemonic,
  deriveKeys,
  createAddress,
  generateCNSubaddress,
  bytesToHex
} from 'salvium-js';

// 1. Generate a cryptographically secure random seed
const seed = generateSeed();  // 32 random bytes

// 2. Convert to 25-word mnemonic for backup
const mnemonic = seedToMnemonic(seed, { language: 'english' });
console.log('Backup these words:', mnemonic);

// 3. Derive wallet keys from seed
const keys = deriveKeys(seed);
// {
//   spendSecretKey: Uint8Array(32),
//   spendPublicKey: Uint8Array(32),
//   viewSecretKey: Uint8Array(32),
//   viewPublicKey: Uint8Array(32)
// }

// 4. Create main wallet address
const address = createAddress({
  network: 'mainnet',
  format: 'legacy',
  type: 'standard',
  spendPublicKey: keys.spendPublicKey,
  viewPublicKey: keys.viewPublicKey
});
console.log('Main address:', address);  // SaLv...

// 5. Generate subaddresses
const subaddress = generateCNSubaddress({
  network: 'mainnet',
  spendPublicKey: keys.spendPublicKey,
  viewSecretKey: keys.viewSecretKey,
  major: 0,  // account index
  minor: 1   // address index
});
console.log('Subaddress:', subaddress.address);  // SaLvs...

// 6. Display secret keys (keep these safe!)
console.log('Spend secret key:', bytesToHex(keys.spendSecretKey));
console.log('View secret key:', bytesToHex(keys.viewSecretKey));
```

## Restore Wallet from Mnemonic

```javascript
import { mnemonicToSeed, deriveKeys, createAddress } from 'salvium-js';

const mnemonic = 'abbey ability able about above absent ...';  // 25 words

const result = mnemonicToSeed(mnemonic, { language: 'english' });
if (result.valid) {
  const keys = deriveKeys(result.seed);
  const address = createAddress({
    network: 'mainnet',
    format: 'legacy',
    type: 'standard',
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });
  console.log('Restored address:', address);
} else {
  console.error('Invalid mnemonic:', result.error);
}
```

## CARROT Address Format

```javascript
import {
  generateSeed,
  deriveKeys,
  deriveCarrotKeys,
  createAddress,
  generateCarrotSubaddress,
  hexToBytes,
  scalarMultPoint
} from 'salvium-js';

const seed = generateSeed();

// Derive CryptoNote keys (for public keys)
const keys = deriveKeys(seed);

// Derive CARROT-specific keys
const carrotKeys = deriveCarrotKeys(seed);
// {
//   masterSecret: '...',           // hex string
//   proveSpendKey: '...',          // k_ps
//   viewBalanceSecret: '...',      // s_vb
//   generateImageKey: '...',       // k_gi
//   viewIncomingKey: '...',        // k_vi
//   generateAddressSecret: '...'   // s_ga
// }

// Create CARROT main address
const carrotAddress = createAddress({
  network: 'mainnet',
  format: 'carrot',
  type: 'standard',
  spendPublicKey: keys.spendPublicKey,
  viewPublicKey: keys.viewPublicKey
});
console.log('CARROT address:', carrotAddress);  // SC1...

// Generate CARROT subaddress
const carrotSub = generateCarrotSubaddress({
  network: 'mainnet',
  accountSpendPubkey: keys.spendPublicKey,
  accountViewPubkey: keys.viewPublicKey,
  generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret),
  major: 0,
  minor: 1
});
console.log('CARROT subaddress:', carrotSub.address);  // SC1s...
```

## Integrated Addresses (with Payment ID)

```javascript
import {
  toIntegratedAddress,
  toStandardAddress,
  getPaymentId,
  generateRandomPaymentId,
  createIntegratedAddressWithRandomId,
  bytesToHex
} from 'salvium-js';

// Create integrated address with specific payment ID
const integrated = toIntegratedAddress('SaLv...', 'deadbeef12345678');
console.log('Integrated:', integrated);  // SaLvi...

// Create with random payment ID
const result = createIntegratedAddressWithRandomId('SaLv...');
console.log('Integrated:', result.address);
console.log('Payment ID:', result.paymentIdHex);

// Extract payment ID from integrated address
const paymentId = getPaymentId(integrated);
console.log('Payment ID:', bytesToHex(paymentId));

// Get standard address from integrated
const standard = toStandardAddress(integrated);
```

## Validate and Parse Addresses

```javascript
import { isValidAddress, parseAddress, describeAddress } from 'salvium-js';

// Simple validation
if (isValidAddress('SC1...')) {
  console.log('Valid!');
}

// Detailed parsing
const info = parseAddress('SC1...');
// {
//   valid: true,
//   network: 'mainnet',
//   format: 'carrot',
//   type: 'standard',
//   prefix: 'SC1',
//   spendPublicKey: Uint8Array(32),
//   viewPublicKey: Uint8Array(32),
//   paymentId: null,
//   error: null
// }

// Human-readable description
console.log(describeAddress('SaLvi...'));
// "Mainnet Legacy integrated (Payment ID: abcd1234...)"
```

## Check Address Properties

```javascript
import {
  isMainnet, isTestnet, isStagenet,
  isCarrot, isLegacy,
  isStandard, isIntegrated, isSubaddress
} from 'salvium-js';

const addr = 'SC1...';

isMainnet(addr);    // true
isCarrot(addr);     // true
isStandard(addr);   // true
isSubaddress(addr); // false
```

## Mnemonic Seeds

```javascript
import {
  seedToMnemonic,
  mnemonicToSeed,
  validateMnemonic,
  detectLanguage,
  getAvailableLanguages
} from 'salvium-js';

// Generate mnemonic from seed
const mnemonic = seedToMnemonic(seed, { language: 'english' });
// 25 words

// Convert mnemonic back to seed
const result = mnemonicToSeed(mnemonic, { language: 'english' });
if (result.valid) {
  console.log('Seed:', result.seed);
}

// Auto-detect language
const detected = detectLanguage(mnemonic);
console.log('Language:', detected.language.name);

// Validate without converting
const validation = validateMnemonic(mnemonic, { language: 'auto' });
console.log('Valid:', validation.valid);

// Available languages
console.log(getAvailableLanguages());
// ['english', 'spanish', 'french', 'italian', 'german', 'portuguese',
//  'russian', 'japanese', 'chinese_simplified', 'dutch', 'esperanto', 'lojban']
```

## RPC Clients

Full-featured RPC clients for Salvium daemon and wallet services.

### Default Ports (from cryptonote_config.h)

| Service | Mainnet | Testnet | Stagenet |
|---------|---------|---------|----------|
| Daemon RPC | 19081 | 29081 | 39081 |
| ZMQ RPC | 19083 | 29083 | 39083 |
| Wallet RPC* | 19083 | 29083 | 39083 |

*Wallet RPC has no default in source - port is user-specified, conventionally daemon+1

### Daemon RPC

```javascript
import { createDaemonRPC } from 'salvium-js/rpc';

const daemon = createDaemonRPC({ url: 'http://localhost:19081' });

// Get node info
const info = await daemon.getInfo();
if (info.success) {
  console.log('Height:', info.result.height);
  console.log('Network hashrate:', info.result.difficulty / 120);
  console.log('Synchronized:', info.result.synchronized);
}

// Get block by height
const block = await daemon.getBlockHeaderByHeight(100000);

// Get transactions
const txs = await daemon.getTransactions(['txhash1', 'txhash2']);

// Get fee estimate
const fee = await daemon.getFeeEstimate();
console.log('Fee per byte:', fee.result.fee);

// Mining
const template = await daemon.getBlockTemplate({
  wallet_address: 'SaLv...',
  reserve_size: 8
});
```

### Wallet RPC

```javascript
import { createWalletRPC, PRIORITY } from 'salvium-js/rpc';

const wallet = createWalletRPC({
  url: 'http://localhost:19083',
  username: 'user',
  password: 'pass'
});

// Open wallet
await wallet.openWallet({ filename: 'mywallet', password: 'secret' });

// Get balance (amounts in atomic units, divide by 1e8 for SAL)
const balance = await wallet.getBalance();
if (balance.success) {
  console.log('Balance:', balance.result.balance / 1e8, 'SAL');
  console.log('Unlocked:', balance.result.unlocked_balance / 1e8, 'SAL');
}

// Get address
const addr = await wallet.getAddress();
console.log('Address:', addr.result.address);

// Send transaction (1 SAL = 100000000 atomic units)
const tx = await wallet.transfer({
  destinations: [{ address: 'SaLv...', amount: 100000000 }],
  priority: PRIORITY.NORMAL
});

// Get transaction history
const transfers = await wallet.getTransfers({ in: true, out: true });

// Create subaddress
const newAddr = await wallet.createAddress({ account_index: 0 });

// Close wallet
await wallet.closeWallet();
```

### RPC Client Options

```javascript
const daemon = createDaemonRPC({
  url: 'http://localhost:19081',
  timeout: 30000,        // Request timeout in ms (default: 30000)
  retries: 2,            // Retry attempts (default: 2)
  retryDelay: 1000,      // Delay between retries in ms (default: 1000)
  username: 'user',      // HTTP basic auth username
  password: 'pass'       // HTTP basic auth password
});
```

### Available Daemon RPC Methods

- **Network**: `getInfo`, `getHeight`, `syncInfo`, `hardForkInfo`, `getNetStats`, `getConnections`, `getPeerList`
- **Blocks**: `getBlockHash`, `getBlock`, `getBlockHeaderByHash`, `getBlockHeaderByHeight`, `getBlockHeadersRange`, `getLastBlockHeader`
- **Transactions**: `getTransactions`, `getTransactionPool`, `sendRawTransaction`, `relayTx`
- **Outputs**: `getOuts`, `getOutputHistogram`, `getOutputDistribution`, `isKeyImageSpent`
- **Mining**: `getBlockTemplate`, `submitBlock`, `getMinerData`, `calcPow`
- **Fees**: `getFeeEstimate`, `getBaseFeeEstimate`, `getCoinbaseTxSum`

### Available Wallet RPC Methods

- **Wallet**: `createWallet`, `openWallet`, `closeWallet`, `restoreDeterministicWallet`, `generateFromKeys`
- **Accounts**: `getAccounts`, `createAccount`, `labelAccount`, `getAddress`, `createAddress`
- **Balance**: `getBalance`, `getTransfers`, `getTransferByTxid`, `incomingTransfers`
- **Transfers**: `transfer`, `transferSplit`, `sweepAll`, `sweepSingle`, `sweepDust`
- **Proofs**: `getTxKey`, `checkTxKey`, `getTxProof`, `checkTxProof`, `getReserveProof`
- **Keys**: `queryKey`, `getMnemonic`, `exportOutputs`, `importOutputs`, `exportKeyImages`
- **Signing**: `sign`, `verify`, `signMultisig`, `submitMultisig`

## Transaction Scanning

Detect owned outputs in transactions and decrypt amounts.

```javascript
import {
  generateKeyDerivation,
  derivePublicKey,
  deriveSecretKey,
  checkOutputOwnership,
  scanOutput,
  ecdhDecode,
  deriveViewTag
} from 'salvium-js';

// Given a transaction with tx public key R and your view secret key a:
const derivation = generateKeyDerivation(txPubKey, viewSecretKey);

// Check if output at index n belongs to you
const outputKey = tx.outputs[n].target;
const owned = checkOutputOwnership(derivation, n, spendPublicKey, outputKey);

if (owned) {
  // Decrypt the amount
  const amount = ecdhDecode(encryptedAmount, derivation, n);
  console.log('Received:', amount, 'atomic units');

  // Derive the secret key to spend this output
  const outputSecretKey = deriveSecretKey(derivation, n, spendSecretKey);
}

// Full output scan with view tag optimization
const result = scanOutput({
  derivation,
  outputIndex: 0,
  outputPublicKey: tx.outputs[0].target,
  spendPublicKey,
  viewTag: tx.outputs[0].viewTag,  // optional
  encryptedAmount: tx.outputs[0].encryptedAmount
});

if (result.owned) {
  console.log('Amount:', result.amount);
  console.log('Output secret:', result.outputSecretKey);
}
```

## Key Images

Generate key images for spend detection (required for full wallet functionality).

```javascript
import {
  hashToPoint,
  generateKeyImage,
  isValidKeyImage,
  exportKeyImages,
  importKeyImages
} from 'salvium-js';

// Generate key image for an output you own
// KI = x * H_p(P) where x is your output secret key, P is output public key
const keyImage = generateKeyImage(outputPublicKey, outputSecretKey);

// Validate a key image
if (isValidKeyImage(keyImage)) {
  console.log('Valid key image');
}

// Export key images for view-only wallet sync
const exported = exportKeyImages([
  { keyImage: ki1, txHash: 'abc...', outputIndex: 0 },
  { keyImage: ki2, txHash: 'def...', outputIndex: 1 }
]);

// Import key images into a view-only wallet
const keyImageMap = importKeyImages(exported);
// Can now detect which outputs have been spent
```

## Transaction Construction

Build transactions with Pedersen commitments and CLSAG/TCLSAG ring signatures.

```javascript
import {
  // Scalar operations
  scAdd, scSub, scMul, scRandom, scInvert,
  // Commitments
  commit, zeroCommit, genCommitmentMask,
  // Output creation
  generateOutputKeys, createOutput,
  // Signing (CLSAG for standard, TCLSAG for SalviumOne)
  clsagSign, clsagVerify,
  tclsagSign, tclsagVerify,
  // Serialization
  serializeTxPrefix, getTxPrefixHash, encodeVarint
} from 'salvium-js';

// Create a transaction output
const txSecretKey = scRandom();  // r - transaction secret key
const output = createOutput(
  txSecretKey,
  recipientViewPublicKey,
  recipientSpendPublicKey,
  1000000000n,  // 10 SAL in atomic units
  0,            // output index
  false         // isSubaddress
);
// Returns: { outputPublicKey, txPublicKey, commitment, encryptedAmount, mask }

// Pedersen commitment: C = mask*G + amount*H
const mask = scRandom();
const commitment = commit(1000000000n, mask);

// Zero commitment for fees (public amount)
const feeCommitment = zeroCommit(10000000n);  // 0.1 SAL fee

// CLSAG ring signature (standard RingCT)
const signature = clsagSign(
  message,           // Pre-MLSAG hash
  ring,              // Array of public keys (decoys + real)
  secretKey,         // Your secret key
  commitments,       // Ring member commitments
  maskDiff,          // Your mask - pseudo output mask
  pseudoCommitment,  // Pseudo output commitment
  secretIndex        // Your position in ring
);

// Verify CLSAG signature
const valid = clsagVerify(message, signature, ring, commitments, pseudoCommitment);

// TCLSAG ring signature (SalviumOne - uses dual generators G and T)
const tclsagSig = tclsagSign(
  message,           // Pre-MLSAG hash
  ring,              // Array of public keys
  secretKeyX,        // Spend secret key component
  secretKeyY,        // Auxiliary secret key component
  commitments,       // Ring member commitments
  maskDiff,          // Commitment mask difference
  pseudoCommitment,  // Pseudo output commitment
  secretIndex        // Your position in ring
);
// Returns { sx: [], sy: [], c1, I, D } - dual scalar arrays

// Verify TCLSAG signature
const tclsagValid = tclsagVerify(message, tclsagSig, ring, commitments, pseudoCommitment);
```

## Bulletproofs+ Range Proofs

Generate and verify range proofs that prove transaction amounts are in valid range (0 to 2^64-1) without revealing the actual amounts.

```javascript
import {
  // Proof generation
  proveRange,
  proveRangeMultiple,
  randomScalar,
  serializeProof,
  // Verification
  verifyBulletproofPlus,
  verifyRangeProof,
  parseProof,
  initGenerators,
  bytesToPoint
} from 'salvium-js';

// === PROOF GENERATION ===

// Generate a range proof for a single amount
const amount = 1000000000n;  // 10 SAL in atomic units
const mask = randomScalar();  // Blinding factor (commitment mask)

const proof = proveRange(amount, mask);
// proof = { V, A, A1, B, r1, s1, d1, L, R }
// V[0] is the Pedersen commitment: mask*G + amount*H

// Generate proof for multiple amounts (batched, more efficient)
const amounts = [1000000000n, 500000000n];
const masks = [randomScalar(), randomScalar()];
const batchProof = proveRangeMultiple(amounts, masks);

// Serialize for transmission
const proofBytes = serializeProof(proof);

// === VERIFICATION ===

// Verify a generated proof
const valid = verifyBulletproofPlus(proof.V, proof);

// Verify from serialized bytes (e.g., from a transaction)
const isValid = verifyRangeProof(
  tx.rctSig.outPk,      // Array of commitment bytes
  tx.rctSig.proofBytes  // Serialized Bulletproof+ proof
);

// Parse and verify separately for more control
const parsedProof = parseProof(proofBytes);
const verified = verifyBulletproofPlus(commitments, parsedProof);
```

```javascript
// Serialize transaction
const tx = {
  version: 2,
  unlockTime: 0n,
  inputs: [{ amount: 0n, keyOffsets: [100n, 50n], keyImage }],
  outputs: [{ amount: 0n, target: output.outputPublicKey, viewTag: 0x42 }],
  extra: { txPubKey: output.txPublicKey }
};
const serialized = serializeTxPrefix(tx);
const prefixHash = getTxPrefixHash(tx);
```

## RandomX Proof-of-Work

WASM-JIT accelerated RandomX implementation for mining and verification. Validated against [official test vectors](https://github.com/tevador/RandomX/blob/master/src/tests/tests.cpp).

```javascript
import {
  RandomXContext,
  rxSlowHash,
  verifyHash,
  checkDifficulty,
  mine
} from 'salvium-js';

// === BASIC HASHING ===

// One-shot hash (creates temporary context)
const hash = await rxSlowHash('block header hash', 'block blob');

// === REUSABLE CONTEXT (Recommended) ===

// For multiple hashes with same key, reuse context
const ctx = new RandomXContext();
await ctx.init('test key 000');  // Initialize 256MB cache

const hash1 = ctx.hash('This is a test');
const hash2 = ctx.hash('Another input');  // Much faster, reuses cache

// Verify against official test vectors
console.log(ctx.hashHex('This is a test'));
// '639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f'

// === VERIFICATION ===

// Verify a hash
const isValid = await verifyHash(key, input, expectedHash);

// Check if hash meets difficulty target
const meetsDifficulty = checkDifficulty(hash, difficulty);

// === MINING ===

// Find nonce that meets difficulty
const result = await mine(
  key,            // Cache key (prev block hash)
  blockBlob,      // Block blob with nonce placeholder
  nonceOffset,    // Byte offset of nonce in blob
  difficulty,     // Target difficulty (BigInt)
  maxNonce        // Max nonce to try (default: 2^32)
);

if (result) {
  console.log('Found nonce:', result.nonce);
  console.log('Hash:', result.hash);
}
```

**Modes:**
- **Light mode** (default) - 256MB cache per thread, suitable for verification and mining
- **Full mode** - 2GB shared dataset, faster hashing for dedicated miners

**Multi-threaded Mining:**
```javascript
import { RandomXWorkerPool, getAvailableCores } from 'salvium-js';

const pool = new RandomXWorkerPool(getAvailableCores());
await pool.init(key);
const hash = await pool.hash(input);
pool.terminate();
```

## Verify Message Signatures

```javascript
import { verifySignature, parseSignature } from 'salvium-js';

// Verify a signature created with `sign` command in salvium-wallet-cli
const result = verifySignature(
  'Hello, World!',    // The original message
  'SC1...',           // The signer's address
  'SigV2...'          // The signature string
);

console.log(result);
// {
//   valid: true,
//   version: 2,
//   keyType: 'spend',  // or 'view'
//   error: null
// }
```

## Cryptographic Primitives

```javascript
import { keccak256, keccak256Hex, blake2b, blake2bHex } from 'salvium-js';

// Keccak-256 (CryptoNote fast hash)
const hash = keccak256('hello');        // Uint8Array(32)
const hex = keccak256Hex('hello');      // "1c8aff950685..."

// Blake2b (CARROT key derivation)
const b2hash = blake2b(data, 32);       // 32-byte output
const b2keyed = blake2b(data, 32, key); // Keyed hash (MAC)
```

## API Reference

### Wallet Generation

| Function | Description |
|----------|-------------|
| `generateSeed()` | Generate 32-byte cryptographically secure random seed |
| `deriveKeys(seed)` | Derive CryptoNote keys from seed |
| `deriveCarrotKeys(seed)` | Derive CARROT keys from seed |
| `createAddress(options)` | Create address from public keys |

### Mnemonic Functions

| Function | Description |
|----------|-------------|
| `seedToMnemonic(seed, options)` | Convert 32-byte seed to 25-word mnemonic |
| `mnemonicToSeed(mnemonic, options)` | Convert mnemonic to seed |
| `validateMnemonic(mnemonic, options)` | Validate mnemonic without converting |
| `detectLanguage(mnemonic)` | Auto-detect mnemonic language |
| `getAvailableLanguages()` | List supported languages |

### Subaddress Functions

| Function | Description |
|----------|-------------|
| `generateCNSubaddress(options)` | Generate CryptoNote subaddress |
| `generateCarrotSubaddress(options)` | Generate CARROT subaddress |
| `generateRandomPaymentId()` | Generate 8-byte random payment ID |

### Address Functions

| Function | Description |
|----------|-------------|
| `parseAddress(addr)` | Parse address, returns detailed info object |
| `isValidAddress(addr)` | Returns true if valid |
| `isMainnet(addr)` | Check if mainnet address |
| `isTestnet(addr)` | Check if testnet address |
| `isStagenet(addr)` | Check if stagenet address |
| `isCarrot(addr)` | Check if CARROT format |
| `isLegacy(addr)` | Check if legacy CryptoNote format |
| `isStandard(addr)` | Check if standard address |
| `isIntegrated(addr)` | Check if integrated address |
| `isSubaddress(addr)` | Check if subaddress |
| `getSpendPublicKey(addr)` | Extract 32-byte spend public key |
| `getViewPublicKey(addr)` | Extract 32-byte view public key |
| `getPaymentId(addr)` | Extract 8-byte payment ID (integrated only) |
| `toIntegratedAddress(addr, paymentId)` | Create integrated from standard |
| `toStandardAddress(addr)` | Extract standard from integrated |
| `describeAddress(addr)` | Human-readable description |

### Crypto Backend Functions

| Function | Description |
|----------|-------------|
| `initCrypto()` | Initialize crypto (loads WASM, falls back to JS) |
| `setCryptoBackend(type)` | Set backend: `'wasm'`, `'jsi'`, or `'js'` |
| `getCryptoBackend()` | Get active backend instance |
| `getCurrentBackendType()` | Get active backend name string |

### Transaction Scanning Functions

| Function | Description |
|----------|-------------|
| `generateKeyDerivation(pubKey, secretKey)` | Compute ECDH shared secret D = 8*s*P |
| `derivationToScalar(derivation, outputIndex)` | Derive scalar from derivation |
| `derivePublicKey(derivation, index, spendPub)` | Derive one-time public key |
| `deriveSecretKey(derivation, index, spendSec)` | Derive one-time secret key |
| `deriveViewTag(derivation, index)` | Compute view tag for fast filtering |
| `checkOutputOwnership(derivation, index, spendPub, outputPub)` | Check if output belongs to wallet |
| `scanOutput(params)` | Full output scan with amount decryption |
| `ecdhDecode(encrypted, derivation, index)` | Decrypt amount |
| `ecdhEncode(amount, derivation, index)` | Encrypt amount |

### Key Image Functions

| Function | Description |
|----------|-------------|
| `hashToPoint(data)` | Hash to curve point (Elligator 2) |
| `generateKeyImage(outputPub, outputSec)` | Generate key image KI = x*H_p(P) |
| `isValidKeyImage(keyImage)` | Validate key image is on curve |
| `exportKeyImages(outputs)` | Format key images for export |
| `importKeyImages(data)` | Create lookup map from exported data |

### Transaction Construction Functions

| Function | Description |
|----------|-------------|
| `scAdd(a, b)` | Add scalars mod L |
| `scSub(a, b)` | Subtract scalars mod L |
| `scMul(a, b)` | Multiply scalars mod L |
| `scRandom()` | Generate random scalar |
| `scInvert(a)` | Compute modular inverse |
| `commit(amount, mask)` | Create Pedersen commitment |
| `zeroCommit(amount)` | Create commitment with zero mask |
| `generateOutputKeys(txSec, viewPub, spendPub, index)` | Generate one-time output keys |
| `createOutput(txSec, viewPub, spendPub, amount, index)` | Create full transaction output |
| `clsagSign(message, ring, secret, commitments, mask, pseudo, index)` | Generate CLSAG signature |
| `clsagVerify(message, sig, ring, commitments, pseudo)` | Verify CLSAG signature |
| `tclsagSign(message, ring, secretX, secretY, commitments, mask, pseudo, index)` | Generate TCLSAG signature (SalviumOne) |
| `tclsagVerify(message, sig, ring, commitments, pseudo)` | Verify TCLSAG signature |
| `serializeTxPrefix(tx)` | Serialize transaction prefix |
| `getTxPrefixHash(tx)` | Compute transaction prefix hash |
| `encodeVarint(value)` | Encode integer as varint |
| `decodeVarint(bytes, offset)` | Decode varint from bytes |

### Bulletproofs+ Functions

| Function | Description |
|----------|-------------|
| `proveRange(amount, mask)` | Generate range proof for single amount |
| `proveRangeMultiple(amounts, masks)` | Generate batched range proof for multiple amounts |
| `randomScalar()` | Generate cryptographically secure random scalar |
| `serializeProof(proof)` | Serialize proof to bytes for transmission |
| `verifyBulletproofPlus(V, proof)` | Verify single range proof |
| `verifyBulletproofPlusBatch(proofs)` | Batch verify multiple proofs |
| `verifyRangeProof(commitments, proofBytes)` | Verify from raw bytes |
| `initGenerators(n)` | Initialize Gi/Hi generators (cached) |
| `parseProof(proofBytes)` | Parse proof from serialized bytes |
| `multiScalarMul(scalars, points)` | Multiscalar multiplication |
| `bytesToPoint(bytes)` | Decode compressed point |
| `bytesToScalar(bytes)` | Decode scalar from bytes |

### RandomX Functions

| Function | Description |
|----------|-------------|
| `RandomXContext` | Reusable context class for repeated hashing with same key |
| `rxSlowHash(key, input)` | One-shot RandomX hash computation |
| `randomxHash(key, input)` | Alias for rxSlowHash |
| `verifyHash(key, input, expected)` | Verify RandomX hash matches expected |
| `checkDifficulty(hash, difficulty)` | Check if hash meets difficulty target |
| `mine(key, blob, nonceOffset, difficulty, maxNonce, onProgress)` | Find nonce meeting difficulty |
| `calculateCommitment(input, hashIn)` | Calculate hash commitment |
| `RandomXCache` | Cache class for Argon2d-initialized memory |
| `initDatasetItem(cache, itemNumber)` | Generate single dataset item from cache |
| `RandomXNative` | WASM-JIT RandomX context (vendored randomx.js) |
| `Blake2Generator` | Pseudo-random byte generator using Blake2b |
| `generateSuperscalar(gen)` | Generate superscalar program |
| `executeSuperscalar(registers, program)` | Execute superscalar program on registers |
| `reciprocal(divisor)` | Compute reciprocal for IMUL_RCP instruction |
| `argon2d(password, salt, tCost, mCost, parallelism, outLen)` | Argon2d hash function |
| `argon2InitCache(key)` | Initialize RandomX cache with Argon2d |

### Wallet Functions

| Function | Description |
|----------|-------------|
| `Wallet` | Wallet class with full and view-only modes |
| `createWallet(options?)` | Create new wallet with mnemonic |
| `restoreWallet(mnemonic, options?)` | Restore wallet from mnemonic |
| `createViewOnlyWallet(options)` | Create view-only wallet from keys |
| `wallet.getAddress(format?)` | Get main address (auto-detects CARROT vs Legacy) |
| `wallet.getSubaddress(major, minor)` | Generate subaddress |
| `wallet.getBalance()` | Get balance (total, unlocked, locked) |
| `wallet.getStorageBalance()` | Get balance from stored outputs |
| `wallet.getUTXOs(options?)` | Get unspent outputs (filters: unlockedOnly, accountIndex) |
| `wallet.getAssetTypes()` | Get all asset types with balances |
| `wallet.syncWithDaemon(daemon?)` | Sync wallet with daemon (CARROT-aware) |
| `wallet.startSyncing(daemon, interval?)` | Start background sync loop |
| `wallet.stopSyncing()` | Stop background sync |
| `wallet.transfer(destinations, options?)` | Build, sign, and broadcast transfer |
| `wallet.stake(amount, options?)` | Stake coins for yield |
| `wallet.burn(amount, options?)` | Burn coins |
| `wallet.convert(amount, src, dest, addr, options?)` | Convert between assets |
| `wallet.sweepAll(address, options?)` | Sweep all funds to address |
| `wallet.canSign()` | Check if wallet can sign transactions |
| `wallet.canScan()` | Check if wallet can scan for outputs |
| `wallet.toJSON(includeSecrets?)` | Serialize wallet to JSON |
| `wallet.toEncryptedJSON(password)` | Encrypt wallet (ML-KEM-768 + Argon2id) |
| `Wallet.fromJSON(json)` | Restore wallet from JSON |
| `Wallet.fromEncryptedJSON(data, password)` | Restore from encrypted JSON |
| `Wallet.fromMnemonic(mnemonic, options?)` | Restore from 25-word phrase |
| `Wallet.fromSeed(seed, options?)` | Restore from 32-byte seed |
| `Wallet.fromViewKey(viewSec, spendPub)` | Create view-only wallet |

### Wallet Sync Functions

| Function | Description |
|----------|-------------|
| `WalletSync` | Blockchain sync engine class |
| `createWalletSync(options)` | Create sync engine with keys + daemon |
| `sync.start(startHeight?)` | Start synchronization |
| `sync.stop()` | Stop synchronization |
| `sync.getProgress()` | Get sync status, height, percent |
| `sync.rescan(fromHeight)` | Rescan from specific height |
| `sync.scanMempool()` | Scan mempool for pending TXs |
| `sync.on(event, handler)` | Listen for sync events |
| `SYNC_STATUS` | Enum: IDLE, SYNCING, COMPLETE, ERROR |

### Oracle & Pricing Functions

| Function | Description |
|----------|-------------|
| `fetchPricingRecord(options)` | Fetch pricing from oracle server |
| `verifyPricingRecordSignature(pr, pubkey)` | Verify oracle signature |
| `getOraclePublicKey(network)` | Get oracle public key for network |
| `getConversionRate(pr, fromAsset, toAsset)` | Get conversion rate between assets |
| `calculateConversion(pr, src, dest, amount)` | Full conversion with slippage |
| `getConvertedAmount(rate, amount)` | Calculate converted amount |
| `calculateSlippage(amount)` | Calculate 3.125% slippage |
| `validatePricingRecord(pr, options)` | Full pricing record validation |

### UTXO Selection Functions

| Function | Description |
|----------|-------------|
| `selectUTXOs(utxos, amount, options?)` | Select UTXOs for transaction |
| `UTXO_STRATEGY.MINIMIZE_INPUTS` | Strategy to minimize number of inputs |
| `UTXO_STRATEGY.MINIMIZE_CHANGE` | Strategy to minimize change amount |
| `UTXO_STRATEGY.OLDEST_FIRST` | Strategy to spend oldest UTXOs first |
| `UTXO_STRATEGY.NEWEST_FIRST` | Strategy to spend newest UTXOs first |
| `UTXO_STRATEGY.RANDOM` | Random UTXO selection |

### Transaction Builder Functions

| Function | Description |
|----------|-------------|
| `buildTransaction(options)` | Build complete transaction with signatures |
| `signTransaction(unsignedTx, spendSecretKey)` | Sign an unsigned transaction |
| `prepareInputs(utxos, viewSecretKey)` | Prepare inputs with ring members |
| `estimateTransactionFee(numInputs, numOutputs, feePerByte?)` | Estimate transaction fee |
| `validateTransaction(tx)` | Validate transaction structure |
| `serializeTransaction(tx)` | Serialize transaction for broadcast |

### Transaction Parser Functions

| Function | Description |
|----------|-------------|
| `parseTransaction(txData)` | Parse raw transaction bytes/hex |
| `parseExtra(extra)` | Parse transaction extra field |
| `extractTxPubKey(extra)` | Extract transaction public key |
| `extractPaymentId(extra)` | Extract payment ID from extra |
| `decodeAmount(encrypted, derivation, index)` | Decrypt encrypted amount |
| `summarizeTransaction(tx)` | Get transaction summary |
| `getTransactionHashFromParsed(tx)` | Compute hash from parsed transaction |

### Utility Functions

| Function | Description |
|----------|-------------|
| `bytesToHex(bytes)` | Convert Uint8Array to hex string |
| `hexToBytes(hex)` | Convert hex string to Uint8Array |
| `keccak256(data)` | Keccak-256 hash, returns Uint8Array |
| `keccak256Hex(data)` | Keccak-256 hash, returns hex string |
| `blake2b(data, outlen, key?)` | Blake2b hash with optional key |
| `sha256(data)` | SHA-256 hash |
| `argon2id(password, salt, tCost, mCost, parallelism, outLen)` | Argon2id key derivation |
| `x25519ScalarMult(scalar, uCoord)` | X25519 scalar multiplication (Salvium clamping) |

## Wallet Class

Unified wallet management with full and view-only modes.

```javascript
import {
  Wallet,
  createWallet,
  restoreWallet,
  createViewOnlyWallet
} from 'salvium-js';

// Create a new wallet
const { wallet, mnemonic, seed } = createWallet({ network: 'mainnet' });
console.log('Backup:', mnemonic);  // 25 words
console.log('Address:', wallet.getAddress());

// Restore from mnemonic
const restored = restoreWallet('abbey ability able about...');

// Create view-only wallet (can scan, cannot spend)
const viewOnly = createViewOnlyWallet({
  network: 'mainnet',
  viewSecretKey: '...',
  spendPublicKey: '...'
});

console.log('Can scan:', viewOnly.canScan());   // true
console.log('Can sign:', viewOnly.canSign());   // false

// Generate subaddresses
const sub = wallet.getSubaddress(0, 1);  // account 0, index 1

// Serialize/deserialize
const json = wallet.toJSON();
const loaded = Wallet.fromJSON(json);
```

## Wallet Sync Engine

The `WalletSync` engine scans the blockchain for owned outputs using both CryptoNote and CARROT protocols. It handles binary block parsing, key image tracking, spent detection, coinbase unlock windows, chain reorganizations, and staking return output prediction.

```javascript
import { createDaemonRPC } from 'salvium-js/rpc';
import { Wallet, initCrypto } from 'salvium-js';

// Initialize WASM crypto backend
await initCrypto();

// Restore wallet and sync
const wallet = Wallet.fromMnemonic('abbey ability able about ...');
const daemon = createDaemonRPC({ url: 'http://localhost:19081' });

// One-shot sync (scans from last saved height to chain tip)
await wallet.syncWithDaemon(daemon);

// Check balance
const { balance, unlockedBalance, lockedBalance } = await wallet.getStorageBalance();
console.log(`Balance: ${Number(unlockedBalance) / 1e8} SAL`);
console.log(`Locked:  ${Number(lockedBalance) / 1e8} SAL`);

// Background sync (polls every 10 seconds)
await wallet.startSyncing(daemon, 10000);
wallet.stopSyncing();
```

### Direct WalletSync Usage

For lower-level control, use `WalletSync` directly:

```javascript
import { WalletSync, createWalletSync, SYNC_STATUS } from 'salvium-js';
import { WalletStorage } from 'salvium-js';

const sync = createWalletSync({
  storage,           // WalletStorage instance
  daemon,            // DaemonRPC instance
  keys: {
    viewSecretKey,
    spendSecretKey,  // null for view-only
    spendPublicKey,
    viewPublicKey
  },
  carrotKeys,        // From deriveCarrotKeys() — enables CARROT scanning
  batchSize: 100     // Blocks per RPC request
});

// Listen for events
sync.on('outputReceived', ({ amount, txHash }) => {
  console.log(`Received ${Number(amount) / 1e8} SAL in ${txHash}`);
});
sync.on('outputSpent', ({ keyImage }) => {
  console.log(`Output spent: ${keyImage}`);
});
sync.on('syncProgress', ({ currentHeight, targetHeight, percentComplete }) => {
  console.log(`${percentComplete.toFixed(1)}% (${currentHeight}/${targetHeight})`);
});

await sync.start();
```

### Sync Events

| Event | Payload | Description |
|-------|---------|-------------|
| `syncStart` | `{ startHeight, targetHeight }` | Sync started |
| `syncProgress` | `{ currentHeight, targetHeight, percentComplete }` | Progress update |
| `syncComplete` | `{ height }` | Reached chain tip |
| `outputReceived` | `{ amount, txHash, outputIndex }` | Owned output found |
| `outputSpent` | `{ keyImage, txHash }` | Output marked spent |
| `reorg` | `{ fromHeight, toHeight }` | Chain reorganization |
| `syncError` | `{ error }` | Error during sync |

## Staking, Burns, and Conversions

Salvium supports staking for yield, burning tokens, and cross-asset conversions.

```javascript
// Stake 1000 SAL for yield
const stakeTx = await wallet.stake(100000000000n, { daemon });
console.log('Stake TX:', stakeTx.txHash);

// Burn 10 SAL
const burnTx = await wallet.burn(1000000000n, { daemon });

// Convert between assets (requires oracle pricing)
const convertTx = await wallet.convert(
  1000000000n,    // amount
  'SAL',          // source asset
  'SAL1',         // destination asset
  destAddress,    // destination address
  { daemon }
);

// Check staking status
const locked = wallet.getLockedCoins();
const yield_ = wallet.getTotalYield();
```

## Oracle & Pricing

Verify oracle signatures and calculate cross-asset conversion rates.

```javascript
import {
  fetchPricingRecord,
  verifyPricingRecordSignature,
  getOraclePublicKey,
  getConversionRate,
  calculateConversion
} from 'salvium-js';

// Fetch current pricing from oracle
const pr = await fetchPricingRecord({ network: 'mainnet' });

// Verify oracle signature
const pubkey = getOraclePublicKey('mainnet');
const valid = await verifyPricingRecordSignature(pr, pubkey);

// Get conversion rate
const rate = getConversionRate(pr, 'SAL', 'SAL1');

// Calculate full conversion with slippage
const result = calculateConversion(pr, 'SAL', 'SAL1', 1000000000n);
console.log('You receive:', result.destAmount);
console.log('Slippage:', result.slippage);
```

## Wallet Encryption

Encrypt wallet data with ML-KEM-768 (post-quantum) + Argon2id key derivation.

```javascript
// Encrypt wallet for storage
const encrypted = wallet.toEncryptedJSON('my-password');

// Restore from encrypted JSON
const restored = Wallet.fromEncryptedJSON(encrypted, 'my-password');

// Change password
const reEncrypted = Wallet.changePassword(encrypted, 'old-pass', 'new-pass');

// Check if JSON is encrypted
Wallet.isEncrypted(data);  // true or false
```

## UTXO Selection

Multiple strategies for selecting transaction inputs.

```javascript
import { selectUTXOs, UTXO_STRATEGY } from 'salvium-js';

const utxos = [
  { txHash: 'abc...', outputIndex: 0, amount: 1000000000n, publicKey: ... },
  { txHash: 'def...', outputIndex: 1, amount: 500000000n, publicKey: ... },
  // ...
];

const result = selectUTXOs(utxos, 800000000n, {
  strategy: UTXO_STRATEGY.MINIMIZE_INPUTS,  // or MINIMIZE_CHANGE, OLDEST_FIRST, etc.
  feePerByte: 1000n
});

console.log('Selected:', result.selectedUTXOs.length);
console.log('Total:', result.totalAmount);
console.log('Change:', result.changeAmount);
console.log('Fee:', result.estimatedFee);
```

## Transaction Builder

High-level API for building and signing transactions.

```javascript
import { buildTransaction, signTransaction, validateTransaction } from 'salvium-js';

// Build a transaction
const tx = await buildTransaction({
  utxos: myUTXOs,
  destinations: [
    { address: 'SaLv...', amount: 1000000000n }
  ],
  changeAddress: myChangeAddress,
  viewSecretKey: keys.viewSecretKey,
  spendSecretKey: keys.spendSecretKey,
  ringSize: 16
});

console.log('TX Hash:', tx.txHash);
console.log('Fee:', tx.fee);

// Validate before broadcast
const validation = validateTransaction(tx.tx);
if (!validation.valid) {
  console.error('Errors:', validation.errors);
}
```

## Transaction Parser

Decode and analyze transaction data.

```javascript
import {
  parseTransaction,
  parseExtra,
  extractTxPubKey,
  extractPaymentId,
  summarizeTransaction
} from 'salvium-js';

// Parse raw transaction
const tx = parseTransaction(txHex);

// Get transaction summary
const summary = summarizeTransaction(tx);
console.log('Hash:', summary.hash);
console.log('Inputs:', summary.numInputs);
console.log('Outputs:', summary.numOutputs);
console.log('Coinbase:', summary.isCoinbase);
console.log('Key images:', summary.keyImages);

// Extract extra fields
const extra = parseExtra(tx.extra);
const txPubKey = extractTxPubKey(extra);
const paymentId = extractPaymentId(extra);
```

## Stratum Mining

Connect to mining pools with the stratum protocol.

```javascript
import { createMiner } from 'salvium-js';

const miner = createMiner({
  host: 'pool.example.com',
  port: 3333,
  wallet: 'SaLv...',
  password: 'x',
  threads: 4
});

miner.on('hashrate', (rate) => console.log(`${rate} H/s`));
miner.on('share', (accepted) => console.log(accepted ? 'Share accepted' : 'Share rejected'));

await miner.start();
// ... mining ...
miner.stop();
```

## Testing

```bash
# Run all tests
bun test/all.js

# Run with integration tests (requires running daemon)
bun test/all.js --integration

# Run against specific daemon
bun test/all.js --integration http://localhost:19081
```

25 test suites covering addresses, keys, mnemonics, CryptoNote + CARROT scanning, CLSAG/TCLSAG signatures, Bulletproofs+ range proofs, consensus rules, wallet sync, encrypted storage, blockchain reorgs, oracle verification, and cross-backend WASM/JS interop.

## Project Structure

```
salvium-js/
  src/
    address.js          # Address creation, parsing, validation
    blake2b.js          # Blake2b hashing
    blockchain.js       # Chain state, reorg detection
    bulletproofs_plus.js # BP+ range proofs
    carrot.js           # CARROT key derivation
    carrot-scanning.js  # CARROT output scanning (X25519 ECDH, internal/return)
    consensus.js        # Difficulty, rewards, fees, median
    keccak.js           # Keccak-256 hashing
    keyimage.js         # Key image generation
    mining.js           # RandomX mining
    mnemonic.js         # 25-word seed phrases
    oracle.js           # Oracle pricing, signature verification, conversions
    scanning.js         # CryptoNote output scanning
    signature.js        # Message signature verification
    subaddress.js       # Subaddress generation
    transaction.js      # TX construction, CLSAG/TCLSAG, decoy selection
    validation.js       # TX/block validation rules
    wallet.js           # Wallet class (sync, transfer, stake, burn, convert)
    wallet-sync.js      # Daemon sync engine (CARROT-aware, binary blocks)
    crypto/
      provider.js       # Backend-agnostic crypto API
      backend-js.js     # Pure JS backend (Noble curves)
      backend-wasm.js   # Rust/WASM backend (curve25519-dalek)
      backend-jsi.js    # React Native JSI backend (FFI)
      wasm/             # Compiled WASM binary (336KB)
    rpc/
      daemon.js         # Daemon RPC client
      wallet.js         # Wallet RPC client
    transaction/        # TX parsing, serialization, constants
    wallet/             # Account, storage, encryption (ML-KEM-768 + Argon2id)
  crates/
    salvium-crypto/     # Rust crate (CLSAG, TCLSAG, BP+, X25519, 30+ primitives)
  test/                 # 25 test suites
```

## Contributing

Contributions welcome! Please read the Salvium source code for reference:
https://github.com/salvium/salvium
