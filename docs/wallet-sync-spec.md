# Wallet Sync Integration Spec

How to use the salvium-rs FFI library to create a wallet, sync it, and read data.

**All JSON fields are camelCase.** Both query inputs and response outputs use camelCase
(e.g. `isConfirmed`, `incomingAmount`, `blockHeight`). This is enforced by
`#[serde(rename_all = "camelCase")]` on every struct.

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

### Cancellation

From another thread, call:

```c
int rc = salvium_wallet_stop_sync(wallet);
// rc: 0 = success, -1 = error
```

The sync loop stops before the next batch and returns error code -1.
The callback fires event type 6 (Cancelled) with the height reached.
After cancelling, you can `salvium_wallet_reset_sync_height` and restart.

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
        case 6: printf("Cancelled at %llu\n", cur); break;
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
| Cancelled | 6 | When `stop_sync` called | `current_height` = height reached |

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
// Returns: {"balance":"123456789","unlockedBalance":"100000000","lockedBalance":"23456789"}
// Amounts are atomic units (1 SAL = 100,000,000 atomic)
// CALLER MUST FREE:
salvium_string_free(json);

// All assets
char* all = salvium_wallet_get_all_balances(wallet, 0);
// Returns: {"SAL":{"balance":"...","unlockedBalance":"...","lockedBalance":"..."}, ...}
salvium_string_free(all);
```

**BalanceResult fields:**

| Field | Type | Description |
|-------|------|-------------|
| `balance` | string | Total balance (atomic units) |
| `unlockedBalance` | string | Spendable balance (atomic units) |
| `lockedBalance` | string | Locked/immature balance (atomic units) |

**You MUST sync before querying balances.** Without sync, the balance will be 0.

## 6. Query Transactions

```c
// All confirmed transfers
char* txs = salvium_wallet_get_transfers(wallet, "{\"isConfirmed\":true}");

// Only incoming
char* txs = salvium_wallet_get_transfers(wallet, "{\"isIncoming\":true}");

// Height range
char* txs = salvium_wallet_get_transfers(wallet, "{\"minHeight\":100000,\"maxHeight\":200000}");

// Specific tx hash
char* txs = salvium_wallet_get_transfers(wallet, "{\"txHash\":\"abc123...\"}");

// Returns JSON array. ALWAYS free:
salvium_string_free(txs);
```

**TxQuery fields (all optional, camelCase):**

| Field | Type | Description |
|-------|------|-------------|
| `isIncoming` | bool | Filter incoming transfers |
| `isOutgoing` | bool | Filter outgoing transfers |
| `isConfirmed` | bool | Filter confirmed (in-block) |
| `inPool` | bool | Filter mempool transactions |
| `txType` | i64 | Transaction type code (see below) |
| `minHeight` | i64 | Minimum block height |
| `maxHeight` | i64 | Maximum block height |
| `txHash` | string | Exact transaction hash |

**TransactionRow fields in response (camelCase):**

| Field | Type | Description |
|-------|------|-------------|
| `txHash` | string | Transaction hash (hex) |
| `txPubKey` | string/null | Transaction public key (hex) |
| `blockHeight` | i64/null | Block height (null if in pool) |
| `blockTimestamp` | i64/null | Unix timestamp |
| `isIncoming` | bool | Received funds |
| `isOutgoing` | bool | Sent funds |
| `isConfirmed` | bool | In a block |
| `incomingAmount` | string | Atomic units received |
| `outgoingAmount` | string | Atomic units sent |
| `fee` | string | Transaction fee (atomic) |
| `changeAmount` | string | Change returned to self (atomic) |
| `unlockTime` | string | Unlock time (0 = immediate) |
| `assetType` | string | e.g. "SAL" |
| `txType` | i64 | Transaction type code (see below) |
| `isMinerTx` | bool | Coinbase transaction |
| `isProtocolTx` | bool | Protocol yield/return transaction |
| `note` | string | User note (empty if unset) |

**Transaction types (`txType`):**

| Value | Meaning |
|-------|---------|
| 1 | Miner (coinbase) |
| 2 | Protocol (yield distribution, stake returns) |
| 3 | Transfer |
| 4 | Convert (SAL <-> VSD) |
| 5 | Burn |
| 6 | Stake |
| 7 | Return (stake unlock) |

**Display logic:**

- `isIncoming && !isOutgoing` — received funds, show `incomingAmount`
- `!isIncoming && isOutgoing` — sent funds, show `outgoingAmount - changeAmount`
- `isIncoming && isOutgoing` — self-transfer, net = `incomingAmount - outgoingAmount`

## 7. Query Outputs (UTXOs)

```c
// All unspent outputs
char* outs = salvium_wallet_get_outputs(wallet, "{\"isSpent\":false}");

// Unspent SAL only
char* outs = salvium_wallet_get_outputs(wallet, "{\"isSpent\":false,\"assetType\":\"SAL\"}");

salvium_string_free(outs);
```

**OutputQuery fields (all optional, camelCase):**

| Field | Type | Description |
|-------|------|-------------|
| `isSpent` | bool | Filter spent/unspent |
| `isFrozen` | bool | Filter frozen outputs |
| `assetType` | string | e.g. "SAL" |
| `txType` | i64 | Transaction type code |
| `accountIndex` | i64 | Account major index |
| `subaddressIndex` | i64 | Subaddress minor index |
| `minAmount` | string | Minimum amount (atomic) |
| `maxAmount` | string | Maximum amount (atomic) |

## 8. Subaddresses

```c
// Create a new subaddress (returns JSON: {"major":0,"minor":1,"address":"..."})
char* sub = salvium_wallet_create_subaddress(wallet, 0, "my label");
salvium_string_free(sub);

// List all subaddresses for account 0
char* subs = salvium_wallet_get_subaddresses(wallet, 0);
salvium_string_free(subs);

// Label an existing subaddress
salvium_wallet_label_subaddress(wallet, 0, 1, "new label");
```

Subaddresses are automatically CARROT or CryptoNote based on the current chain hardfork.

## 9. Other Wallet Queries

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

## 10. Staking

```c
char* stakes = salvium_wallet_get_stakes(wallet, "locked");   // or "returned" or NULL for all
salvium_string_free(stakes);
```

**StakeRow fields (camelCase):**

| Field | Type | Description |
|-------|------|-------------|
| `stakeTxHash` | string | Stake transaction hash |
| `stakeHeight` | i64/null | Block height of stake |
| `stakeTimestamp` | i64/null | Unix timestamp of stake |
| `amountStaked` | string | Amount staked (atomic) |
| `fee` | string | Transaction fee (atomic) |
| `assetType` | string | e.g. "SAL" |
| `status` | string | "locked" or "returned" |
| `returnTxHash` | string/null | Return transaction hash |
| `returnHeight` | i64/null | Block height of return |
| `returnAmount` | string | Amount returned (atomic) |

## 11. Sending Transactions

All transaction functions take a JSON params string. **`assetType` is required** — there is
no default. Omitting it returns an error.

All return a JSON string on success (caller must free with `salvium_string_free()`), or
NULL on error.

### Transfer

```c
char* result = salvium_wallet_transfer(wallet, daemon, "{\"destinations\":[{\"address\":\"Svk1...\",\"amount\":\"100000000\"}],\"assetType\":\"SAL1\"}");
salvium_string_free(result);
```

**Params (camelCase):**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `destinations` | array | yes | `[{"address": "...", "amount": "..."}]` (atomic units) |
| `assetType` | string | yes | Asset to spend (e.g. `"SAL1"`) |
| `priority` | string | no | `"low"`, `"normal"` (default), `"elevated"`, `"priority"` |
| `ringSize` | number | no | Default 16 |
| `dryRun` | bool | no | If true, build + sign but don't broadcast |

**Result:** `{"txHash": "...", "fee": "...", "amount": "..."}`
When `dryRun` is true, also includes `txHex` and `weight`.

### Transfer Dry Run

Convenience wrapper — forces `dryRun: true` regardless of params.

```c
char* result = salvium_wallet_transfer_dry_run(wallet, daemon, params_json);
```

### Stake

```c
char* result = salvium_wallet_stake(wallet, daemon, "{\"amount\":\"100000000\",\"assetType\":\"SAL1\"}");
salvium_string_free(result);
```

**Params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `amount` | string | yes | Amount to stake (atomic units) |
| `assetType` | string | yes | Asset to stake |
| `priority` | string | no | Fee priority (default `"normal"`) |
| `ringSize` | number | no | Default 16 |

**Result:** `{"txHash": "...", "fee": "...", "amount": "...", "weight": ...}`

### Stake Dry Run

```c
char* result = salvium_wallet_stake_dry_run(wallet, daemon, params_json);
```

### Sweep

Sends all unlocked outputs of the specified asset to a single address.

```c
char* result = salvium_wallet_sweep(wallet, daemon, "{\"address\":\"Svk1...\",\"assetType\":\"SAL1\"}");
salvium_string_free(result);
```

**Params:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `address` | string | yes | Destination address |
| `assetType` | string | yes | Asset to sweep |
| `priority` | string | no | Fee priority (default `"normal"`) |
| `ringSize` | number | no | Default 16 |
| `dryRun` | bool | no | If true, build + sign but don't broadcast |

**Result:** `{"txHash": "...", "fee": "...", "amount": "..."}`

## 12. Cleanup

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
char* txs = salvium_wallet_get_transfers(wallet, "{\"isConfirmed\":true}");
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
