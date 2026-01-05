# salvium-js

JavaScript library for Salvium cryptocurrency - address validation, parsing, and cryptographic utilities.

## Features

- **Address Validation** - Validate all 18 Salvium address types
- **Address Parsing** - Extract public keys, payment IDs, detect network/format/type
- **Multi-Network Support** - Mainnet, Testnet, Stagenet
- **Dual Format Support** - Legacy (CryptoNote) and CARROT addresses
- **Base58 Encoding** - Monero-variant Base58 with checksums
- **Keccak-256** - Pre-SHA3 Keccak hashing (cn_fast_hash)
- **Signature Verification** - Verify message signatures (V1 and V2 formats)
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

## Usage

### Validate an Address

```javascript
import { isValidAddress, parseAddress } from 'salvium-js';

// Simple validation
if (isValidAddress('SC1...')) {
  console.log('Valid address!');
}

// Detailed parsing
const info = parseAddress('SC1...');
console.log(info);
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
```

### Check Address Properties

```javascript
import {
  isMainnet,
  isTestnet,
  isCarrot,
  isLegacy,
  isStandard,
  isIntegrated,
  isSubaddress
} from 'salvium-js';

const addr = 'SC1...';

isMainnet(addr);    // true
isCarrot(addr);     // true
isStandard(addr);   // true
isIntegrated(addr); // false
```

### Extract Keys

```javascript
import { getSpendPublicKey, getViewPublicKey, bytesToHex } from 'salvium-js';

const spendKey = getSpendPublicKey('SC1...');
const viewKey = getViewPublicKey('SC1...');

console.log('Spend Key:', bytesToHex(spendKey));
console.log('View Key:', bytesToHex(viewKey));
```

### Work with Integrated Addresses

```javascript
import { toIntegratedAddress, toStandardAddress, getPaymentId, bytesToHex } from 'salvium-js';

// Create integrated address with payment ID
const integrated = toIntegratedAddress('SC1...', 'deadbeef12345678');

// Extract payment ID
const paymentId = getPaymentId(integrated);
console.log('Payment ID:', bytesToHex(paymentId));

// Get standard address from integrated
const standard = toStandardAddress(integrated);
```

### Describe an Address

```javascript
import { describeAddress } from 'salvium-js';

console.log(describeAddress('SC1...'));
// "Mainnet CARROT standard"

console.log(describeAddress('SaLvi...'));
// "Mainnet Legacy integrated (Payment ID: abcd1234...)"
```

### Low-Level: Keccak-256

```javascript
import { keccak256, keccak256Hex } from 'salvium-js';

const hash = keccak256('hello');        // Uint8Array(32)
const hex = keccak256Hex('hello');      // "1c8aff950685..."
```

### Low-Level: Base58

```javascript
import { encode, decode, encodeAddress, decodeAddress } from 'salvium-js/base58';

const encoded = encode(new Uint8Array([1, 2, 3]));
const decoded = decode(encoded);
```

### Verify Message Signatures

```javascript
import { verifySignature, parseSignature } from 'salvium-js';

// Verify a signature created with `sign` command in salvium-wallet-cli
const result = verifySignature(
  'Hello, World!',                    // The original message
  'SC1...',                           // The signer's address
  'SigV2...'                          // The signature string
);

console.log(result);
// {
//   valid: true,
//   version: 2,
//   keyType: 'spend',  // or 'view'
//   error: null
// }

// Parse signature components
const sig = parseSignature('SigV2...');
console.log(sig);
// {
//   valid: true,
//   version: 2,
//   c: Uint8Array(32),
//   r: Uint8Array(32),
//   signMask: 0
// }
```

## API Reference

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

### Utility Functions

| Function | Description |
|----------|-------------|
| `bytesToHex(bytes)` | Convert Uint8Array to hex string |
| `hexToBytes(hex)` | Convert hex string to Uint8Array |
| `keccak256(data)` | Keccak-256 hash, returns Uint8Array |
| `keccak256Hex(data)` | Keccak-256 hash, returns hex string |

### Signature Functions

| Function | Description |
|----------|-------------|
| `verifySignature(message, address, signature)` | Verify a message signature, returns result object |
| `parseSignature(signature)` | Parse signature string into components |

## Contributing

Contributions welcome! Please read the Salvium source code for reference:
https://github.com/salvium/salvium

