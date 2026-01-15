# salvium-js

JavaScript library for Salvium cryptocurrency - wallet generation, address handling, RPC clients, key derivation, and cryptographic utilities.

## Features

- **Wallet Generation** - Generate seeds, derive keys, create addresses
- **Mnemonic Support** - 25-word seed phrases in 12 languages
- **Key Derivation** - CryptoNote and CARROT key derivation from seeds
- **Address Creation** - Create all 18 Salvium address types
- **Subaddress Generation** - Generate CryptoNote and CARROT subaddresses
- **Integrated Addresses** - Create and parse integrated addresses with payment IDs
- **Address Validation** - Parse and validate any Salvium address
- **Transaction Scanning** - Detect owned outputs, decrypt amounts, view tags
- **Key Images** - Generate and validate key images for spend detection
- **Transaction Construction** - Pedersen commitments, CLSAG signatures, serialization
- **Bulletproofs+ Range Proofs** - Pure JS proof generation AND verification (mobile-friendly)
- **RandomX Proof-of-Work** - Pure JS implementation (no WASM/native) for mobile/browser
- **RPC Clients** - Full daemon and wallet RPC implementations
- **Signature Verification** - Verify message signatures (V1 and V2 formats)
- **Cryptographic Primitives** - Blake2b, Keccak-256, Ed25519, Base58
- **Multi-Network Support** - Mainnet, Testnet, Stagenet
- **Zero Dependencies** - Pure JavaScript, works in browsers and Node.js

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

Build transactions with Pedersen commitments and CLSAG ring signatures.

```javascript
import {
  // Scalar operations
  scAdd, scSub, scMul, scRandom, scInvert,
  // Commitments
  commit, zeroCommit, genCommitmentMask,
  // Output creation
  generateOutputKeys, createOutput,
  // Signing
  clsagSign, clsagVerify,
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

// CLSAG ring signature (simplified)
const signature = clsagSign(
  message,           // Pre-MLSAG hash
  ring,              // Array of public keys (decoys + real)
  secretKey,         // Your secret key
  commitments,       // Ring member commitments
  maskDiff,          // Your mask - pseudo output mask
  pseudoCommitment,  // Pseudo output commitment
  secretIndex        // Your position in ring
);

// Verify signature
const valid = clsagVerify(message, signature, ring, commitments, pseudoCommitment);
```

## Bulletproofs+ Range Proofs

Generate and verify range proofs that prove transaction amounts are in valid range (0 to 2^64-1) without revealing the actual amounts. **100% pure JavaScript** - no WASM required.

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

**Performance** (pure JavaScript, no WASM):
| Operation | Time |
|-----------|------|
| Generator init (1024 pts) | ~800ms (one-time, cached) |
| Single proof generation | ~1100ms |
| Proof verification | ~300ms |
| Round-trip (generate + verify) | ~1400ms |

This is fast enough for mobile wallets (React Native on iOS/Android).

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

Pure JavaScript implementation of RandomX for transaction verification and light mining. **No WASM, no native modules** - works in browsers, Node.js, and React Native.

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
const key = new TextEncoder().encode('block header hash');
const input = new TextEncoder().encode('block blob');
const hash = rxSlowHash(key, input);  // 32-byte hash

// === REUSABLE CONTEXT (Recommended) ===

// For multiple hashes with same key, reuse context
const ctx = new RandomXContext();
ctx.init(key);  // Initialize cache (takes time, ~256MB)

const hash1 = ctx.hash(input1);
const hash2 = ctx.hash(input2);  // Much faster, reuses cache

// === VERIFICATION ===

// Verify a hash
const isValid = verifyHash(key, input, expectedHash);

// Check if hash meets difficulty target
const meetsDifficulty = checkDifficulty(hash, difficulty);
// Uses: hash * difficulty <= 2^256 - 1

// === MINING ===

// Find nonce that meets difficulty
const result = mine(
  key,            // Cache key (prev block hash)
  blockBlob,      // Block blob with nonce placeholder
  nonceOffset,    // Byte offset of nonce in blob
  difficulty,     // Target difficulty (BigInt)
  maxNonce,       // Max nonce to try (default: 2^32)
  (nonce, rate) => console.log(`Nonce: ${nonce}, ${rate} H/s`)  // Progress
);

if (result) {
  console.log('Found nonce:', result.nonce);
  console.log('Hash:', result.hash);
}
```

**Components** (all pure JavaScript):
- **Argon2d** - Cache initialization (256MB, 3 iterations)
- **SuperscalarHash** - Dataset item generation with x86 pipeline simulation
- **Soft AES** - Scratchpad filling without hardware acceleration
- **RandomX VM** - Full instruction set (integer, float, memory ops)

**Performance Note**: Pure JS is significantly slower than native RandomX.
- Suitable for: transaction verification, light wallets, educational use, mobile mining (reduced hashrate)
- For high-performance mining, use native implementations

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
| `RandomXVM` | Virtual machine for RandomX program execution |
| `Blake2Generator` | Pseudo-random byte generator using Blake2b |
| `generateSuperscalar(gen)` | Generate superscalar program |
| `executeSuperscalar(registers, program)` | Execute superscalar program on registers |
| `reciprocal(divisor)` | Compute reciprocal for IMUL_RCP instruction |
| `argon2d(password, salt, tCost, mCost, parallelism, outLen)` | Argon2d hash function |
| `argon2InitCache(key)` | Initialize RandomX cache with Argon2d |

### Utility Functions

| Function | Description |
|----------|-------------|
| `bytesToHex(bytes)` | Convert Uint8Array to hex string |
| `hexToBytes(hex)` | Convert hex string to Uint8Array |
| `keccak256(data)` | Keccak-256 hash, returns Uint8Array |
| `keccak256Hex(data)` | Keccak-256 hash, returns hex string |
| `blake2b(data, outlen, key?)` | Blake2b hash with optional key |

## Testing

```bash
# Run all tests
bun test/all.js

# Run with integration tests (requires running daemon)
bun test/all.js --integration

# Run against specific daemon
bun test/all.js --integration http://localhost:19081
```

Test coverage: 259 tests across 13 test suites including RandomX.

## License

MIT

## Contributing

Contributions welcome! Please read the Salvium source code for reference:
https://github.com/salvium/salvium
