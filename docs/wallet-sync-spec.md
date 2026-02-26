# Wallet Sync Integration Spec

How to use the salvium-rs FFI library to create a wallet, sync it, and read data.

## 1. Initialization

```c
// Optional — runtime is created lazily on first FFI call.
salvium_ffi_init();
```

## 2. Connect to Daemon

```c
void* daemon = salvium_daemon_connect("http://seed01.salvium.io:19081");
if (!daemon) {
    const char* err = salvium_last_error();  // DO NOT free this pointer
    // handle error...
}
```

**Seed nodes:**

| Network  | URL                                    |
|----------|----------------------------------------|
| Mainnet  | `http://seed01.salvium.io:19081`       |
| Testnet  | `http://seed01.salvium.io:29081`       |
| Stagenet | `http://seed01.salvium.io:39081`       |

Verify daemon is ready before syncing:

```c
int synced = salvium_daemon_is_synchronized(daemon);
// 1 = synced, 0 = still syncing, -1 = error
```

## 3. Create / Open Wallet

Three options — all return an opaque `void*` handle (null on error).

### 3a. From 25-word mnemonic

```c
void* wallet = salvium_wallet_from_mnemonic(
    "word1 word2 ... word25",  // null-terminated C string
    0,                          // network: 0=Mainnet, 1=Testnet, 2=Stagenet
    "/path/to/wallet.db",       // database file path
    db_key,                     // uint8_t* encryption key
    db_key_len                  // size_t key length
);
```

### 3b. From 32-byte seed

```c
void* wallet = salvium_wallet_create(
    seed_bytes,    // const uint8_t[32]
    0,             // network
    "/path/to/wallet.db",
    db_key,
    db_key_len
);
```

### 3c. From JSON keys (view-only supported)

```c
// Full wallet:   {"seed": "hex64", "network": "mainnet"}
// View-only:     {"view_secret_key": "hex64", "spend_public_key": "hex64", "network": "mainnet"}
void* wallet = salvium_wallet_open(keys_json, "/path/to/wallet.db", db_key, db_key_len);
```

### 3d. From PIN-encrypted blob

```c
void* wallet = salvium_wallet_import_blob(blob_json, pin, "/path/to/wallet.db");
```

## 4. Sync

### The call

```c
int rc = salvium_wallet_sync(wallet, daemon, my_callback);
// rc: 0 = success, -1 = error
```

**This function blocks until sync is complete.** It handles everything internally:
- Fetches blocks from the daemon in adaptive batches (2-1000 blocks per HTTP request)
- Parses each block and scans all transaction outputs for owned funds
- Detects chain reorganizations and rolls back automatically
- Stores matched outputs and transactions in the wallet database
- Updates sync height per-block for crash safety

### Callback (optional, may be NULL)

```c
typedef void (*SyncCallbackFn)(
    int event_type,          // event code (see below)
    uint64_t current_height, // current scan position
    uint64_t target_height,  // chain tip
    uint32_t outputs_found,  // cumulative owned outputs found
    const char* error_msg    // null unless event_type=4 or 5
);

void my_callback(int type, uint64_t cur, uint64_t target, uint32_t outs, const char* msg) {
    switch (type) {
        case 0: printf("Started: target=%llu\n", target); break;
        case 1: printf("Progress: %llu/%llu (%u outputs)\n", cur, target, outs); break;
        case 2: printf("Complete: height=%llu\n", cur); break;
        case 3: printf("Reorg: %llu -> %llu\n", cur, target); break;
        case 4: printf("Error: %s\n", msg); break;
        case 5: printf("Parse error at %llu: %s\n", cur, msg); break;
    }
}
```

| Event | Code | Frequency | Fields |
|-------|------|-----------|--------|
| Started | 0 | Once at start | `target_height` |
| Progress | 1 | Per batch (~every 2000 blocks) | `current_height`, `target_height`, `outputs_found` |
| Complete | 2 | Once at end | `current_height` = final height |
| Reorg | 3 | When chain fork detected | `current_height` = old tip, `target_height` = fork point |
| Error | 4 | On RPC/network error | `error_msg` = description |
| ParseError | 5 | On block parse failure | `current_height` = block height, `error_msg` = details |

### Incremental sync

`salvium_wallet_sync` is always incremental. It starts from the last persisted height and only fetches new blocks. Calling it again after completion returns immediately if no new blocks exist.

### Rescan

```c
salvium_wallet_reset_sync_height(wallet, 0);  // reset to genesis
salvium_wallet_sync(wallet, daemon, callback); // full rescan
```

## 5. Query Balance

```c
// Single asset
char* json = salvium_wallet_get_balance(wallet, "SAL", 0);
// Returns: {"balance":"123456789","unlocked_balance":"100000000","locked_balance":"23456789"}
// Amounts are atomic units (1 SAL = 100,000,000 atomic)
// CALLER MUST FREE:
salvium_string_free(json);

// All assets
char* all = salvium_wallet_get_all_balances(wallet, 0);
// Returns: {"SAL":{"balance":"...","unlocked_balance":"...","locked_balance":"..."}, ...}
salvium_string_free(all);
```

**You MUST sync before querying balances.** Without sync, the balance will be 0.

## 6. Query Transactions

```c
// All confirmed transfers
char* txs = salvium_wallet_get_transfers(wallet, "{\"is_confirmed\":true}");

// Only incoming
char* txs = salvium_wallet_get_transfers(wallet, "{\"is_incoming\":true}");

// Height range
char* txs = salvium_wallet_get_transfers(wallet, "{\"min_height\":100000,\"max_height\":200000}");

// Specific tx hash
char* txs = salvium_wallet_get_transfers(wallet, "{\"tx_hash\":\"abc123...\"}");

// Returns JSON array. ALWAYS free:
salvium_string_free(txs);
```

**TxQuery fields (all optional):**

| Field | Type | Description |
|-------|------|-------------|
| `is_incoming` | bool | Filter incoming transfers |
| `is_outgoing` | bool | Filter outgoing transfers |
| `is_confirmed` | bool | Filter confirmed (in-block) |
| `in_pool` | bool | Filter mempool transactions |
| `tx_type` | i64 | 1=miner, 2=protocol, 3=transfer |
| `min_height` | i64 | Minimum block height |
| `max_height` | i64 | Maximum block height |
| `tx_hash` | string | Exact transaction hash |

**TransactionRow fields in response:**

| Field | Type | Description |
|-------|------|-------------|
| `tx_hash` | string | Transaction hash (hex) |
| `block_height` | i64/null | Block height (null if in pool) |
| `block_timestamp` | i64 | Unix timestamp |
| `is_incoming` | bool | Received funds |
| `is_outgoing` | bool | Sent funds |
| `is_confirmed` | bool | In a block |
| `incoming_amount` | string | Atomic units received |
| `outgoing_amount` | string | Atomic units sent |
| `fee` | string | Transaction fee (atomic) |
| `asset_type` | string | e.g. "SAL" |
| `tx_type` | i64 | Transaction type code |

## 7. Query Outputs (UTXOs)

```c
// All unspent outputs
char* outs = salvium_wallet_get_outputs(wallet, "{\"is_spent\":false}");

// Unspent SAL only
char* outs = salvium_wallet_get_outputs(wallet, "{\"is_spent\":false,\"asset_type\":\"SAL\"}");

salvium_string_free(outs);
```

## 8. Other Wallet Queries

```c
// Addresses
char* cn_addr   = salvium_wallet_get_address(wallet, 0);  // CryptoNote
char* carr_addr  = salvium_wallet_get_address(wallet, 1);  // CARROT
salvium_string_free(cn_addr);
salvium_string_free(carr_addr);

// Mnemonic (null if view-only)
char* words = salvium_wallet_get_mnemonic(wallet);
if (words) salvium_string_free(words);

// Key material as JSON
char* keys = salvium_wallet_get_keys_json(wallet);
salvium_string_free(keys);

// Can this wallet spend?
int can = salvium_wallet_can_spend(wallet);  // 1=yes, 0=no

// Current sync height
uint64_t h = salvium_wallet_sync_height(wallet);

// Network
int net = salvium_wallet_network(wallet);  // 0=main, 1=test, 2=stage
```

## 9. Staking

```c
char* stakes = salvium_wallet_get_stakes(wallet, "locked");   // or "returned" or NULL for all
salvium_string_free(stakes);
```

## 10. Cleanup

**Close in reverse order.** Always close handles when done.

```c
salvium_wallet_close(wallet);   // wallet first
salvium_daemon_close(daemon);   // daemon second
```

## Error Handling

Every FFI function follows one of these patterns:

| Return type | Success | Error |
|-------------|---------|-------|
| `i32` | `0` | `-1` |
| `*mut c_char` | non-null string | `NULL` |
| `*mut c_void` | non-null handle | `NULL` |
| `u64` | value | `u64::MAX` |

On error, call `salvium_last_error()` to get the error message:

```c
const char* err = salvium_last_error();
// This pointer is valid until the NEXT FFI call on the same thread.
// DO NOT free it. Copy it if you need to keep it.
```

## Memory Rules

1. **Strings** returned by FFI functions (`*mut c_char`) MUST be freed with `salvium_string_free()`.
2. **Handles** (`*mut c_void`) MUST be closed with the matching `_close()` function.
3. **Error strings** from `salvium_last_error()` must NOT be freed — they are owned by the library.
4. **Input strings** (parameters you pass in) must be valid null-terminated UTF-8.

## Complete Example (Pseudocode)

```c
salvium_ffi_init();

// Connect
void* daemon = salvium_daemon_connect("http://seed01.salvium.io:19081");
assert(daemon != NULL);

// Wait for daemon to sync
while (salvium_daemon_is_synchronized(daemon) != 1) {
    sleep(5);
}

// Create wallet
uint8_t db_key[32];
generate_random_bytes(db_key, 32);
void* wallet = salvium_wallet_from_mnemonic(mnemonic, 0, "wallet.db", db_key, 32);
assert(wallet != NULL);

// Sync blockchain (blocks until complete)
int rc = salvium_wallet_sync(wallet, daemon, progress_callback);
assert(rc == 0);

// Read balance
char* bal = salvium_wallet_get_balance(wallet, "SAL", 0);
printf("Balance: %s\n", bal);
salvium_string_free(bal);

// Read transactions
char* txs = salvium_wallet_get_transfers(wallet, "{\"is_confirmed\":true}");
printf("Transfers: %s\n", txs);
salvium_string_free(txs);

// Cleanup
salvium_wallet_close(wallet);
salvium_daemon_close(daemon);
```

## Source Files

| File | What |
|------|------|
| `crates/salvium-ffi/src/lib.rs` | FFI entry point, runtime singleton |
| `crates/salvium-ffi/src/wallet.rs` | Wallet lifecycle, sync, queries |
| `crates/salvium-ffi/src/daemon.rs` | Daemon RPC handle |
| `crates/salvium-ffi/src/error.rs` | Error storage, `ffi_try` helpers |
| `crates/salvium-ffi/src/strings.rs` | String marshalling, `salvium_string_free` |
| `crates/salvium-wallet/src/wallet.rs` | Rust wallet implementation |
| `crates/salvium-wallet/src/sync.rs` | Sync engine internals |
| `crates/salvium-rpc/src/daemon.rs` | RPC client |
| `crates/salvium-sync-bench/src/main.rs` | Working Rust sync example |
