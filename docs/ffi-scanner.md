# FFI CARROT Scanner Integration Reference

## 1. Overview

The Rust CARROT scanner performs the entire 7-step output scan in a single FFI call, eliminating the per-operation JS-to-Rust round-trips that made the pure-JS path slow.

**Two entry points:**

| Function | Purpose | Step 1 |
|----------|---------|--------|
| `salvium_carrot_scan_output` | Standard scan (incoming payments) | X25519 ECDH: `s_sr_unctx = k_vi * D_e` |
| `salvium_carrot_scan_internal` | Self-send scan (change/burns) | Uses `view_balance_secret` directly as `s_sr_unctx` |

**Return codes:** `1` = owned, `0` = not owned, `-1` = error.

Both functions write their result as a Rust-allocated JSON buffer via the `out_ptr`/`out_len` output parameters. The caller **must** free this buffer with `salvium_storage_free_buf`.

## 2. FFI Function Signatures

### `salvium_carrot_scan_output`

```c
int32_t salvium_carrot_scan_output(
    const uint8_t *ko,                   // 1
    const uint8_t *view_tag,             // 2
    const uint8_t *d_e,                  // 3
    const uint8_t *enc_amount,           // 4
    const uint8_t *commitment,           // 5  (nullable)
    const uint8_t *k_vi,                 // 6
    const uint8_t *account_spend_pubkey, // 7
    const uint8_t *input_context,        // 8
    uintptr_t      input_context_len,    // 9
    uint64_t       clear_text_amount,    // 10
    const uint8_t *subaddr_data,         // 11
    uint32_t       n_sub,                // 12
    uint8_t      **out_ptr,              // 13
    uintptr_t     *out_len               // 14
);
```

| # | Name | Type | Size | Notes |
|---|------|------|------|-------|
| 1 | `ko` | `*const u8` | 32 | Onetime output pubkey (compressed Ed25519) |
| 2 | `view_tag` | `*const u8` | 3 | View tag bytes |
| 3 | `d_e` | `*const u8` | 32 | Ephemeral pubkey |
| 4 | `enc_amount` | `*const u8` | 8 | Encrypted amount (little-endian) |
| 5 | `commitment` | `*const u8` | 32 | Pedersen commitment. **Nullable** -- pass null for coinbase outputs |
| 6 | `k_vi` | `*const u8` | 32 | View incoming key (secret scalar) |
| 7 | `account_spend_pubkey` | `*const u8` | 32 | Main account spend pubkey K_s |
| 8 | `input_context` | `*const u8` | var | TX input context (key image hashes) |
| 9 | `input_context_len` | `usize` | -- | Byte length of `input_context` |
| 10 | `clear_text_amount` | `u64` | 8 | Known amount (coinbase), or `u64::MAX` sentinel for "not provided" |
| 11 | `subaddr_data` | `*const u8` | n*40 | Binary subaddress map (see section 3) |
| 12 | `n_sub` | `u32` | 4 | Number of entries in `subaddr_data` |
| 13 | `out_ptr` | `*mut *mut u8` | 8 | Output: pointer to Rust-allocated JSON buffer |
| 14 | `out_len` | `*mut usize` | 8 | Output: byte length of JSON buffer |

### `salvium_carrot_scan_internal`

Identical signature. Parameter 6 is `view_balance_secret` instead of `k_vi`:

| # | Name | Type | Size | Notes |
|---|------|------|------|-------|
| 6 | `view_balance_secret` | `*const u8` | 32 | View balance secret (used directly as `s_sr_unctx`, no ECDH) |

### `salvium_storage_free_buf`

```c
void salvium_storage_free_buf(uint8_t *buf_ptr, uintptr_t len);
```

Frees the Rust-allocated JSON result buffer. Must be called exactly once per successful scan (`rc == 1`).

## 3. Binary Formats

### Subaddress map

Each entry is 40 bytes, tightly packed:

```
[32 bytes: spend pubkey] [4 bytes: major index LE] [4 bytes: minor index LE]
```

The buffer passed as `subaddr_data` must be exactly `n_sub * 40` bytes. Pass `n_sub = 0` with an empty/null buffer if there are no subaddresses.

### Clear text amount sentinel

Pass `0xFFFFFFFFFFFFFFFF` (u64::MAX) to indicate the amount is not known in clear text. The scanner will decrypt it from `enc_amount` using the derived mask. Pass the actual amount for coinbase outputs.

## 4. JSON Result Format

On success (`rc == 1`), the buffer at `*out_ptr` contains UTF-8 JSON:

```json
{
  "amount": 1000000000,
  "mask": "hex64",
  "enote_type": 0,
  "shared_secret": "hex64",
  "address_spend_pubkey": "hex64",
  "subaddress_major": 0,
  "subaddress_minor": 0,
  "is_main_address": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `amount` | u64 | Decrypted amount in atomic units |
| `mask` | hex string (64 chars) | Commitment mask (32 bytes) |
| `enote_type` | 0 or 1 | 0 = PAYMENT, 1 = CHANGE |
| `shared_secret` | hex string (64 chars) | Contextualized sender-receiver secret `s_sr_ctx` |
| `address_spend_pubkey` | hex string (64 chars) | Recovered address spend pubkey |
| `subaddress_major` | u32 | Major subaddress index (0 for main) |
| `subaddress_minor` | u32 | Minor subaddress index (0 for main) |
| `is_main_address` | bool | `true` if matched main account K_s |

## 5. Memory Management

1. Allocate `out_ptr` (8 bytes) and `out_len` (8 bytes) on the caller side.
2. Call the scan function.
3. If `rc == 1`: read `*out_ptr` and `*out_len`, copy/parse the JSON.
4. Call `salvium_storage_free_buf(*out_ptr, *out_len)` to release the buffer.
5. If `rc == 0` or `rc == -1`: no buffer was allocated, do not call free.

**Dart/Flutter example (dart:ffi):**

```dart
final outPtr = calloc<Pointer<Uint8>>();
final outLen = calloc<IntPtr>();

final rc = scanOutput(ko, viewTag, dE, encAmount, commitment,
    kVi, accountSpendPubkey, inputContext, inputContextLen,
    clearTextAmount, subaddrData, nSub, outPtr, outLen);

if (rc == 1) {
  final json = outPtr.value.cast<Utf8>().toDartString(length: outLen.value);
  freeBuf(outPtr.value, outLen.value);
  final result = jsonDecode(json);
  // use result...
}

calloc.free(outPtr);
calloc.free(outLen);
```

## 6. Scanning Algorithm Reference

All hash operations use keyed Blake2b. Transcript format: `[domain_len_byte][domain][data...]`.

| Step | Operation | Domain separator | Inputs | Output |
|------|-----------|-----------------|--------|--------|
| 1 | ECDH (standard only) | -- | `k_vi`, `D_e` | `s_sr_unctx` (32 bytes) |
| 2 | View tag test | `"Carrot view tag"` | `s_sr_unctx`, `input_context`, `Ko` | 3-byte tag; reject if mismatch |
| 3 | Contextualize secret | `"Carrot sender-receiver secret"` | `s_sr_unctx`, `D_e`, `input_context` | `s_sr_ctx` (32 bytes) |
| 4 | Recover spend pubkey | `"Carrot key extension G"`, `"Carrot key extension T"` | `s_sr_ctx`, commitment | `K^j_s = Ko - (k^o_g * G + k^o_t * T)` |
| 5 | Address matching | -- | recovered pubkey, subaddress map | Match against K_s or subaddress entries; reject if no match |
| 6 | Decrypt amount | `"Carrot encryption mask a"` | `s_sr_ctx`, `Ko` | XOR 8-byte mask with `enc_amount` |
| 7 | Verify commitment | `"Carrot commitment mask"` | `s_sr_ctx`, amount, address, enote_type | Derive mask, compute Pedersen `C = mask*G + amount*H`; try PAYMENT(0) then CHANGE(1) |

For the internal (self-send) path, step 1 is skipped -- `view_balance_secret` is used directly as `s_sr_unctx`.

## 7. Integration Checklist

- [ ] **Build the Rust crate** for each target:
  - Android: `cargo ndk -t arm64-v8a -t armeabi-v7a -o jniLibs build --release`
  - iOS: `cargo lipo --release` (or `cargo build --target aarch64-apple-ios`)
- [ ] **Load the shared library** via `dart:ffi` (`DynamicLibrary.open` on Android, `DynamicLibrary.process()` on iOS with static linking)
- [ ] **Define FFI bindings** matching the C signatures in section 2
- [ ] **Marshal inputs**: hex-decode keys to `Uint8List`, pack subaddress map as 40-byte entries, set `u64::MAX` for unknown clear text amounts
- [ ] **Two-pass scan** for each output:
  1. Call `salvium_carrot_scan_output` (standard path) with `k_vi`
  2. If `rc == 0`, call `salvium_carrot_scan_internal` with `view_balance_secret` to detect self-sends
- [ ] **Parse JSON result** and map fields to your wallet model
- [ ] **Free the buffer** with `salvium_storage_free_buf` after reading JSON
- [ ] **Handle errors** (`rc == -1`): log and continue scanning remaining outputs

## Source Files

| File | What |
|------|------|
| `crates/salvium-crypto/src/ffi.rs:873-1016` | FFI entry points |
| `crates/salvium-crypto/src/carrot_scan.rs` | Scanner algorithm and `CarrotScanResult` |
| `src/crypto/backend-ffi.js:628-722` | JS reference implementation of marshalling |
