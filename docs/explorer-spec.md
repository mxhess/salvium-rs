# Explorer WASM Integration Spec

How to use the `salvium-explorer` WASM module in a Cloudflare Worker or browser to parse blocks, analyze transactions, and scan outputs.

## 1. Build

```bash
# Build the wasm-bindgen package (JS glue + .wasm binary)
# Option A: build salvium-explorer (includes explorer-specific APIs + all re-exports)
wasm-pack build crates/salvium-explorer --release --target bundler --out-dir pkg

# Output:
#   crates/salvium-explorer/pkg/salvium_explorer.js       (JS glue)
#   crates/salvium-explorer/pkg/salvium_explorer_bg.wasm  (WASM binary)
#   crates/salvium-explorer/pkg/salvium_explorer.d.ts     (TypeScript types)
#   crates/salvium-explorer/pkg/package.json
```

Or use the build script which builds salvium-crypto directly (without the explorer-specific APIs) and also produces the C ABI static library:

```bash
scripts/build-wasm.sh
# Output in prebuilt/wasm/:
#   salvium_crypto.js, salvium_crypto_bg.wasm, salvium_crypto.d.ts, package.json
#   libsalvium_crypto.a (C ABI static lib)
```

**Note:** The build script builds `salvium-crypto`, not `salvium-explorer`. To get the 3 explorer-specific APIs (`parse_and_analyze_tx`, `parse_and_analyze_block`, `decode_outputs_for_view_key`), use `wasm-pack build crates/salvium-explorer` directly.

## 2. Initialize the Module

### Cloudflare Worker (bundler target)

```typescript
import init, { initSync } from 'salvium-explorer';
import wasmModule from 'salvium-explorer/salvium_explorer_bg.wasm';

// Synchronous init (preferred for Workers)
initSync({ module: wasmModule });

// Or async init
await init({ module_or_path: wasmModule });
```

### Browser

```typescript
import init from 'salvium-explorer';

await init();  // Fetches .wasm from same directory
```

After initialization, all exported functions are available as direct imports.

## 3. Explorer-Specific APIs

These are the 3 high-level functions unique to the explorer crate. They combine multiple salvium-crypto primitives into single calls.

### 3a. `parse_and_analyze_tx`

Parse a raw transaction binary and return enriched JSON.

```typescript
import { parse_and_analyze_tx } from 'salvium-explorer';

const result: string = parse_and_analyze_tx(txBytes: Uint8Array);
const tx = JSON.parse(result);
```

**Returns** all fields from `parse_transaction_bytes()` plus these analysis fields:

| Field | Type | Description |
|-------|------|-------------|
| `tx_type_name` | string | Human-readable TX type (e.g. `"Transfer"`, `"Miner"`, `"Protocol"`) |
| `rct_type_name` | string | Human-readable RCT type (e.g. `"RctBulletproofPlus"`) |
| `input_count` | number | Number of inputs |
| `output_count` | number | Number of outputs |
| `is_coinbase` | boolean | Whether this is a miner/coinbase TX |
| `is_carrot` | boolean | Whether any output uses CARROT format (type `0x04`) |
| `key_images` | string[] | Key image hex strings from inputs |
| `output_keys` | string[] | Output public key hex strings |
| `fee` | string | Transaction fee in atomic units (decimal string) |

**Error:** Returns `{"error": "..."}` on parse failure.

**Example response (trimmed):**
```json
{
  "prefix": {
    "version": 3,
    "txType": 3,
    "unlockTime": "0",
    "vin": [...],
    "vout": [...],
    "extra": { "pubkey": "ab12...", ... }
  },
  "rct": {
    "type": 6,
    "txnFee": "24960000",
    ...
  },
  "tx_type_name": "Transfer",
  "rct_type_name": "RctBulletproofPlus",
  "input_count": 2,
  "output_count": 2,
  "is_coinbase": false,
  "is_carrot": true,
  "key_images": ["aabb...", "ccdd..."],
  "output_keys": ["eeff...", "1122..."],
  "fee": "24960000"
}
```

### 3b. `parse_and_analyze_block`

Parse a raw block binary and return enriched JSON.

```typescript
import { parse_and_analyze_block } from 'salvium-explorer';

const result: string = parse_and_analyze_block(blockBytes: Uint8Array);
const block = JSON.parse(result);
```

**Returns** all fields from `parse_block_bytes()` plus:

| Field | Type | Description |
|-------|------|-------------|
| `tx_count` | number | Number of transaction hashes (excluding miner tx) |

**Base block fields:**

| Field | Type | Description |
|-------|------|-------------|
| `majorVersion` | number | Block major version |
| `minorVersion` | number | Block minor version |
| `timestamp` | number | Block timestamp (Unix) |
| `prevId` | string | Previous block hash (hex) |
| `nonce` | number | Mining nonce |
| `minerTx` | object | Miner transaction (full parsed TX) |
| `txHashes` | string[] | Transaction hashes in this block (hex) |

### 3c. `decode_outputs_for_view_key`

Scan a transaction for owned outputs using a view key pair.

```typescript
import { decode_outputs_for_view_key } from 'salvium-explorer';

const result: string = decode_outputs_for_view_key(
  txBytes: Uint8Array,      // raw transaction binary
  viewSecret: Uint8Array,   // 32-byte view secret key
  spendPub: Uint8Array,     // 32-byte spend public key
);
const outputs = JSON.parse(result);
```

**Parameters:**
- `txBytes`: Raw transaction blob (binary, NOT hex)
- `viewSecret`: 32-byte view secret key (the private view key)
- `spendPub`: 32-byte spend public key (the public spend key)

**Returns** a JSON array of owned outputs:

```json
[
  {
    "output_index": 0,
    "amount": "1000000000",
    "output_key": "aabbccdd...",
    "subaddress_major": 0,
    "subaddress_minor": 0
  }
]
```

| Field | Type | Description |
|-------|------|-------------|
| `output_index` | number | Index within the transaction's outputs |
| `amount` | string | Amount in atomic units (1 SAL = 100,000,000) |
| `output_key` | string | Output public key (hex) |
| `subaddress_major` | number | Subaddress major index (0 = main) |
| `subaddress_minor` | number | Subaddress minor index (0 = main) |

Returns `[]` if no outputs match. Returns `{"error": "..."}` on failure.

**How it works internally:**
1. Parses the transaction binary to extract `vout` and `extra.pubkey`
2. Computes key derivation: `D = 8 * view_secret * tx_pub_key`
3. For each output at index `i`: derives expected key `P' = H(D, i)*G + spend_pub`
4. Compares `P'` against the actual output key — match means the output is owned

**Note:** This is a CryptoNote (legacy) scan only. CARROT output scanning requires the full CARROT key set — use the low-level CARROT helpers for that (see Section 5).

## 4. Core Parsing Functions

These do raw binary parsing without the analysis enrichment.

### `parse_transaction_bytes`

```typescript
import { parse_transaction_bytes } from 'salvium-explorer';
const json: string = parse_transaction_bytes(data: Uint8Array);
```

Returns the full parsed transaction as JSON. All binary fields are hex-encoded, amounts are decimal strings.

### `parse_block_bytes`

```typescript
import { parse_block_bytes } from 'salvium-explorer';
const json: string = parse_block_bytes(data: Uint8Array);
```

### `parse_extra`

```typescript
import { parse_extra } from 'salvium-explorer';
const json: string = parse_extra(extraBytes: Uint8Array);
```

Parses just the TX extra field. Returns JSON with:
- `pubkey`: TX public key (hex)
- `nonces`: payment IDs, extra nonces
- `additionalPubkeys`: additional TX public keys (for subaddresses)

### `compute_tx_prefix_hash`

```typescript
import { compute_tx_prefix_hash } from 'salvium-explorer';
const hash: Uint8Array = compute_tx_prefix_hash(data: Uint8Array);
// Returns 32-byte keccak256 of the TX prefix
```

## 5. Crypto Primitives Available

The explorer re-exports the full salvium-crypto function set. These are the ones most relevant for explorer use:

### Hashing

```typescript
keccak256(data: Uint8Array): Uint8Array              // 32-byte CryptoNote hash
blake2b_hash(data: Uint8Array, outLen: number): Uint8Array
sha256(data: Uint8Array): Uint8Array
```

### Key Operations

```typescript
// CryptoNote key derivation (used by decode_outputs_for_view_key internally)
generate_key_derivation(pubKey: Uint8Array, secKey: Uint8Array): Uint8Array
derive_public_key(derivation: Uint8Array, outputIndex: number, basePub: Uint8Array): Uint8Array

// Key image
generate_key_image(pubKey: Uint8Array, secKey: Uint8Array): Uint8Array
is_valid_key_image(keyImage: Uint8Array): boolean

// Point operations
scalar_mult_base(s: Uint8Array): Uint8Array           // s*G
hash_to_point(data: Uint8Array): Uint8Array            // H_p(data)
```

### Address Utilities

```typescript
wasm_parse_address(address: string): string            // Address → JSON
wasm_is_valid_address(address: string): boolean        // Validate
wasm_describe_address(address: string): string         // Human-readable description
wasm_create_address(                                   // Create from components
  network: number,   // 0=mainnet, 1=testnet, 2=stagenet
  format: number,    // 0=legacy, 1=carrot
  addrType: number,  // 0=standard, 1=subaddress, 2=integrated
  spendKey: Uint8Array,
  viewKey: Uint8Array
): string
wasm_to_integrated_address(address: string, paymentId: Uint8Array): string
```

**`wasm_parse_address` returns:**
```json
{
  "network": "mainnet",
  "format": "legacy",
  "address_type": "standard",
  "spend_public_key": "hex64",
  "view_public_key": "hex64"
}
```

### TX Type / RCT Type Names

```typescript
wasm_tx_type_name(txType: number): string              // e.g. "Transfer", "Miner", "Protocol"
wasm_rct_type_name(rctType: number): string            // e.g. "RctBulletproofPlus"
```

### CARROT Output Scanning (Low-Level)

For full CARROT scanning (beyond what `decode_outputs_for_view_key` provides):

```typescript
// Build input context for a TX
make_input_context_rct(firstKeyImage: Uint8Array): Uint8Array       // Regular TX
make_input_context_coinbase(blockHeight: number): Uint8Array        // Coinbase TX (u64)

// View tag check (fast rejection)
compute_carrot_view_tag(sSrUnctx: Uint8Array, inputContext: Uint8Array, ko: Uint8Array): Uint8Array

// After view tag matches — full decryption
decrypt_carrot_amount(encAmount: Uint8Array, sSrCtx: Uint8Array, ko: Uint8Array): number  // u64
recover_carrot_address_spend_pubkey(ko: Uint8Array, sSrCtx: Uint8Array, commitment: Uint8Array): Uint8Array
derive_carrot_commitment_mask(sSrCtx: Uint8Array, amount: number, addressSpendPubkey: Uint8Array, enoteType: number): Uint8Array  // amount is u64

// CARROT key derivation (9 keys from master secret)
derive_carrot_keys_batch(masterSecret: Uint8Array): Uint8Array      // Returns 288 bytes (9 × 32)
derive_carrot_view_only_keys_batch(viewBalanceSecret: Uint8Array, accountSpendPubkey: Uint8Array): Uint8Array

// Subaddress map generation
carrot_subaddress_map_batch(
  accountSpendPubkey: Uint8Array,
  accountViewPubkey: Uint8Array,
  generateAddressSecret: Uint8Array,
  majorCount: number,
  minorCount: number
): Uint8Array  // Returns majorCount * minorCount * 40 bytes (32-byte key + 4-byte major + 4-byte minor each)
```

### Verification

```typescript
// Full RCT signature verification (all ring sigs + bulletproofs in one call)
verify_rct_signatures_wasm(
  rctType: number,
  inputCount: number,
  ringSize: number,
  txPrefixHash: Uint8Array,
  rctBaseBytes: Uint8Array,
  bpComponents: Uint8Array,
  keyImagesFlat: Uint8Array,
  pseudoOutsFlat: Uint8Array,
  sigsFlat: Uint8Array,
  ringPubkeysFlat: Uint8Array,
  ringCommitmentsFlat: Uint8Array
): Uint8Array  // Returns binary: [0x01] = valid, [0x00, idx_le_4bytes] = invalid at index, [0xFF] = error
```

## 6. Typical Explorer Workflow

### Block Page

```typescript
import { parse_and_analyze_block, parse_and_analyze_tx } from 'salvium-explorer';

// 1. Fetch block from daemon RPC (get_block endpoint returns binary blob)
const blockBlob: Uint8Array = await fetchBlockBlob(height);

// 2. Parse + analyze the block
const block = JSON.parse(parse_and_analyze_block(blockBlob));
// block.majorVersion, block.timestamp, block.prevId, block.tx_count, ...

// 3. The miner TX is embedded in the block
const minerTx = block.minerTx;
// minerTx.prefix.vout → miner reward outputs

// 4. Fetch and parse each transaction
for (const txHash of block.txHashes) {
    const txBlob: Uint8Array = await fetchTxBlob(txHash);
    const tx = JSON.parse(parse_and_analyze_tx(txBlob));
    // tx.tx_type_name, tx.input_count, tx.output_count, tx.fee, ...
}
```

### Transaction Page

```typescript
import { parse_and_analyze_tx, wasm_tx_type_name } from 'salvium-explorer';

const tx = JSON.parse(parse_and_analyze_tx(txBlob));

// Display summary
console.log(`Type: ${tx.tx_type_name}`);         // "Transfer"
console.log(`Fee: ${tx.fee} atomic`);             // "24960000"
console.log(`Inputs: ${tx.input_count}`);
console.log(`Outputs: ${tx.output_count}`);
console.log(`CARROT: ${tx.is_carrot}`);
console.log(`Coinbase: ${tx.is_coinbase}`);

// Key images (for double-spend checking)
for (const ki of tx.key_images) {
    console.log(`Key image: ${ki}`);
}

// Output keys (for output lookup)
for (const ok of tx.output_keys) {
    console.log(`Output key: ${ok}`);
}
```

### Output Decoding (View Key Search)

```typescript
import { decode_outputs_for_view_key } from 'salvium-explorer';

// User provides their view key + spend public key
const viewSecret = hexToBytes(viewSecretHex);  // 32 bytes
const spendPub = hexToBytes(spendPubHex);      // 32 bytes

const owned = JSON.parse(decode_outputs_for_view_key(txBlob, viewSecret, spendPub));

for (const out of owned) {
    console.log(`Output #${out.output_index}: ${out.amount} atomic SAL`);
    console.log(`  Key: ${out.output_key}`);
}
```

### Address Validation

```typescript
import { wasm_is_valid_address, wasm_parse_address } from 'salvium-explorer';

if (wasm_is_valid_address(userAddress)) {
    const info = JSON.parse(wasm_parse_address(userAddress));
    console.log(`Network: ${info.network}, Type: ${info.address_type}`);
}
```

## 7. Data Types — All Inputs are Raw Bytes

Every function that takes transaction or block data expects **raw binary** (`Uint8Array`), not hex strings. If your daemon returns hex, decode first:

```typescript
function hexToBytes(hex: string): Uint8Array {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
    }
    return bytes;
}

// Daemon RPC returns hex → convert before passing to WASM
const txHex: string = await daemon.getTransaction(txHash);
const txBytes: Uint8Array = hexToBytes(txHex);
const result = parse_and_analyze_tx(txBytes);
```

## 8. Error Handling

All string-returning functions follow the same pattern:

```typescript
const result = JSON.parse(parse_and_analyze_tx(txBytes));

if (result.error) {
    // Parse failed
    console.error(result.error);
} else {
    // Success — use result fields
}
```

For functions returning `Uint8Array`: an empty array (`length === 0`) indicates an error (invalid input, failed point decompression, etc).

For functions returning `boolean`: they return `false` on invalid input.

## 9. Memory / Performance Notes

- The WASM module is ~4MB (uncompressed). Cloudflare Workers supports this.
- All functions are synchronous — no async/await needed after `initSync()`.
- The module manages its own WASM linear memory. `Uint8Array` inputs are copied into WASM memory and results are copied out — no manual memory management needed from JS.
- `parse_and_analyze_tx` and `parse_and_analyze_block` do JSON serialization internally (serde_json). For hot paths parsing thousands of transactions, prefer `parse_transaction_bytes` and extract only the fields you need.

## Source Files

| File | What |
|------|------|
| `crates/salvium-explorer/src/lib.rs` | Explorer WASM APIs (3 custom + 67 re-exports) |
| `crates/salvium-explorer/Cargo.toml` | Crate config |
| `crates/salvium-explorer/pkg/` | Built wasm-pack output (JS glue, .wasm, .d.ts) |
| `crates/salvium-crypto/src/lib.rs` | Underlying crypto implementations |
| `crates/salvium-crypto/src/wasm_ffi.rs` | C ABI static lib (alternative to wasm-bindgen) |
| `crates/salvium-crypto/src/tx_parse.rs` | Transaction/block binary parser |
| `scripts/build-wasm.sh` | Build script (wasm-pack + staticlib) |
