/**
 * salvium_wallet.h — C FFI for salvium wallet, daemon, and transaction operations.
 *
 * Handle-based API for mobile/desktop integrations (Flutter, React Native,
 * Swift, Kotlin). Complex types are serialized as JSON strings.
 *
 * Conventions:
 *   - Functions returning int32_t: 0 = success, -1 = error
 *   - Functions returning char*: NULL = error (caller must free with salvium_string_free)
 *   - Functions returning void*: NULL = error (opaque handle, caller must _close)
 *   - Check salvium_last_error() after any error return
 *   - All string parameters are null-terminated UTF-8
 */

#ifndef SALVIUM_WALLET_H
#define SALVIUM_WALLET_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ─── Opaque Handle Types ──────────────────────────────────────────────────── */

typedef void *salvium_wallet_t;
typedef void *salvium_daemon_t;

/* ─── Runtime ──────────────────────────────────────────────────────────────── */

/** Initialize the FFI runtime. Optional — lazily created on first use.
 *  Returns 0 on success, -1 on error. */
int32_t salvium_ffi_init(void);

/* ─── Error Handling ───────────────────────────────────────────────────────── */

/** Get the last error message for the current thread.
 *  Returns NULL if no error. Do NOT free this pointer. */
const char *salvium_last_error(void);

/** Free a string returned by any salvium_wallet_* function. */
void salvium_string_free(char *ptr);

/* ─── Wallet Lifecycle ─────────────────────────────────────────────────────── */

/** Create a new wallet from a 32-byte seed.
 *  @param seed      Pointer to 32 bytes of seed material.
 *  @param network   0 = Mainnet, 1 = Testnet, 2 = Stagenet.
 *  @param db_path   Null-terminated path for the wallet database.
 *  @param db_key    Database encryption key.
 *  @param db_key_len Length of db_key in bytes.
 *  @return Wallet handle, or NULL on error. */
salvium_wallet_t salvium_wallet_create(
    const uint8_t *seed /* 32 bytes */,
    int32_t network,
    const char *db_path,
    const uint8_t *db_key, size_t db_key_len);

/** Restore a wallet from a 25-word mnemonic.
 *  @param words     Null-terminated space-separated mnemonic words.
 *  @return Wallet handle, or NULL on error. */
salvium_wallet_t salvium_wallet_from_mnemonic(
    const char *words,
    int32_t network,
    const char *db_path,
    const uint8_t *db_key, size_t db_key_len);

/** Open a wallet from JSON-encoded keys.
 *  Keys JSON must contain: seed (hex, optional), view_secret_key (hex),
 *  spend_public_key (hex), network ("Mainnet"/"Testnet"/"Stagenet").
 *  @return Wallet handle, or NULL on error. */
salvium_wallet_t salvium_wallet_open(
    const char *keys_json,
    const char *db_path,
    const uint8_t *db_key, size_t db_key_len);

/** Close a wallet handle, releasing all resources. */
void salvium_wallet_close(salvium_wallet_t wallet);

/* ─── Key / Address Queries ────────────────────────────────────────────────── */

/** Get a wallet address.
 *  @param addr_type 0 = CryptoNote, 1 = CARROT.
 *  @return Address string (caller must free), or NULL on error. */
char *salvium_wallet_get_address(salvium_wallet_t wallet, int32_t addr_type);

/** Get the 25-word mnemonic. NULL if view-only.
 *  @return Mnemonic string (caller must free), or NULL on error. */
char *salvium_wallet_get_mnemonic(salvium_wallet_t wallet);

/** Get public key material as JSON.
 *  @return JSON string (caller must free), or NULL on error. */
char *salvium_wallet_get_keys_json(salvium_wallet_t wallet);

/** Whether the wallet can sign transactions.
 *  @return 1 = yes, 0 = no, -1 = error. */
int32_t salvium_wallet_can_spend(salvium_wallet_t wallet);

/** Get the network type.
 *  @return 0 = Mainnet, 1 = Testnet, 2 = Stagenet, -1 = error. */
int32_t salvium_wallet_network(salvium_wallet_t wallet);

/** Get the current sync height.
 *  @return Height, or UINT64_MAX on error. */
uint64_t salvium_wallet_sync_height(salvium_wallet_t wallet);

/* ─── Balance ──────────────────────────────────────────────────────────────── */

/** Get balance for an asset type (e.g. "SAL").
 *  @return JSON: {"balance":"...","unlocked_balance":"...","locked_balance":"..."}
 *          Caller must free. NULL on error. */
char *salvium_wallet_get_balance(
    salvium_wallet_t wallet,
    const char *asset_type,
    int32_t account_index);

/** Get balances for all asset types.
 *  @return JSON object keyed by asset type. Caller must free. NULL on error. */
char *salvium_wallet_get_all_balances(
    salvium_wallet_t wallet,
    int32_t account_index);

/* ─── Wallet Attributes ───────────────────────────────────────────────────── */

/** Set a wallet attribute (key-value pair).
 *  @return 0 on success, -1 on error. */
int32_t salvium_wallet_set_attribute(
    salvium_wallet_t wallet,
    const char *key,
    const char *value);

/** Get a wallet attribute.
 *  @return Value string (caller must free), or NULL if not found. */
char *salvium_wallet_get_attribute(
    salvium_wallet_t wallet,
    const char *key);

/** Reset the sync height (for rescanning).
 *  @return 0 on success, -1 on error. */
int32_t salvium_wallet_reset_sync_height(
    salvium_wallet_t wallet,
    uint64_t height);

/* ─── Sync ─────────────────────────────────────────────────────────────────── */

/** Sync progress callback.
 *  @param event_type     0=started, 1=progress, 2=complete, 3=reorg, 4=error.
 *  @param current_height Current scan height.
 *  @param target_height  Target chain height.
 *  @param outputs_found  Number of outputs found so far.
 *  @param error_msg      NULL unless event_type == 4. */
typedef void (*salvium_sync_callback_t)(
    int32_t event_type,
    uint64_t current_height,
    uint64_t target_height,
    uint32_t outputs_found,
    const char *error_msg);

/** Sync the wallet with the blockchain. Blocks until complete.
 *  @param wallet   Wallet handle.
 *  @param daemon   Daemon handle.
 *  @param callback Optional progress callback (may be NULL).
 *  @return 0 on success, -1 on error. */
int32_t salvium_wallet_sync(
    salvium_wallet_t wallet,
    salvium_daemon_t daemon,
    salvium_sync_callback_t callback);

/* ─── Query Functions ──────────────────────────────────────────────────────── */

/** Get transfers matching a JSON query.
 *  Query fields (all optional): is_incoming, is_outgoing, is_confirmed,
 *  in_pool, tx_type, min_height, max_height, tx_hash.
 *  @return JSON array (caller must free), or NULL on error. */
char *salvium_wallet_get_transfers(
    salvium_wallet_t wallet,
    const char *filters_json);

/** Get outputs matching a JSON query.
 *  Query fields (all optional): is_spent, is_frozen, asset_type, tx_type,
 *  account_index, subaddress_index, min_amount, max_amount.
 *  @return JSON array (caller must free), or NULL on error. */
char *salvium_wallet_get_outputs(
    salvium_wallet_t wallet,
    const char *query_json);

/** Get staking entries, optionally filtered by status.
 *  @param status NULL for all, or "active"/"returned"/etc.
 *  @return JSON array (caller must free), or NULL on error. */
char *salvium_wallet_get_stakes(
    salvium_wallet_t wallet,
    const char *status);

/* ─── Address Book ─────────────────────────────────────────────────────────── */

/** List all address book entries.
 *  @return JSON array (caller must free), or NULL on error. */
char *salvium_wallet_address_book_list(salvium_wallet_t wallet);

/** Add an address book entry.
 *  @return Row ID on success, -1 on error. */
int64_t salvium_wallet_address_book_add(
    salvium_wallet_t wallet,
    const char *address,
    const char *label,
    const char *description);

/** Delete an address book entry by row_id.
 *  @return 0 on success, -1 on error. */
int32_t salvium_wallet_address_book_delete(
    salvium_wallet_t wallet,
    int64_t row_id);

/* ─── Transaction Notes ────────────────────────────────────────────────────── */

/** Set a note on a transaction.
 *  @return 0 on success, -1 on error. */
int32_t salvium_wallet_set_tx_note(
    salvium_wallet_t wallet,
    const char *tx_hash,
    const char *note);

/** Get notes for a list of transaction hashes.
 *  @param tx_hashes_json JSON array of hex hash strings.
 *  @return JSON object {hash: note} (caller must free), or NULL on error. */
char *salvium_wallet_get_tx_notes(
    salvium_wallet_t wallet,
    const char *tx_hashes_json);

/* ─── Output Freeze / Thaw ─────────────────────────────────────────────────── */

/** Freeze an output (exclude from coin selection).
 *  @return 0 on success, -1 on error. */
int32_t salvium_wallet_freeze_output(
    salvium_wallet_t wallet,
    const char *key_image);

/** Thaw a frozen output.
 *  @return 0 on success, -1 on error. */
int32_t salvium_wallet_thaw_output(
    salvium_wallet_t wallet,
    const char *key_image);

/* ─── Daemon ───────────────────────────────────────────────────────────────── */

/** Connect to a daemon RPC endpoint.
 *  @param url Daemon URL (e.g. "http://127.0.0.1:19081").
 *  @return Daemon handle, or NULL on error. */
salvium_daemon_t salvium_daemon_connect(const char *url);

/** Close a daemon handle. */
void salvium_daemon_close(salvium_daemon_t daemon);

/** Get daemon info as JSON.
 *  @return JSON string (caller must free), or NULL on error. */
char *salvium_daemon_get_info(salvium_daemon_t daemon);

/** Get the current daemon height.
 *  @return Height, or UINT64_MAX on error. */
uint64_t salvium_daemon_get_height(salvium_daemon_t daemon);

/** Check if the daemon is synchronized.
 *  @return 1 = yes, 0 = no, -1 = error. */
int32_t salvium_daemon_is_synchronized(salvium_daemon_t daemon);

/** Get fee estimate as JSON.
 *  @return JSON: {"fee": ..., "quantization_mask": ..., "status": "..."}
 *          Caller must free. NULL on error. */
char *salvium_daemon_get_fee_estimate(salvium_daemon_t daemon);

/** Get supply info as JSON.
 *  @return JSON string (caller must free), or NULL on error. */
char *salvium_daemon_get_supply_info(salvium_daemon_t daemon);

/** Get yield info as JSON.
 *  @return JSON string (caller must free), or NULL on error. */
char *salvium_daemon_get_yield_info(salvium_daemon_t daemon);

/* ─── Transfer / Stake ─────────────────────────────────────────────────────── */

/** Transfer funds to one or more destinations.
 *  @param params_json JSON: {"destinations":[{"address":"...","amount":"..."}],
 *                           "asset_type":"SAL","priority":"normal","ring_size":16}
 *  @return JSON: {"tx_hash":"...","fee":"...","amount":"..."}
 *          Caller must free. NULL on error. */
char *salvium_wallet_transfer(
    salvium_wallet_t wallet,
    salvium_daemon_t daemon,
    const char *params_json);

/** Stake funds.
 *  @param params_json JSON: {"amount":"...","asset_type":"SAL",
 *                           "priority":"normal","ring_size":16}
 *  @return JSON: {"tx_hash":"...","fee":"...","amount":"..."}
 *          Caller must free. NULL on error. */
char *salvium_wallet_stake(
    salvium_wallet_t wallet,
    salvium_daemon_t daemon,
    const char *params_json);

#ifdef __cplusplus
}
#endif

#endif /* SALVIUM_WALLET_H */
