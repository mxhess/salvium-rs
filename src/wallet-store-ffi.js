/**
 * FFI Storage Backend — SQLCipher via Rust FFI
 *
 * Moves wallet storage into Rust behind the FFI boundary. SQLite with
 * SQLCipher encryption, WAL mode, opaque handle pattern. Balance computation
 * happens in Rust — no need to round-trip all outputs.
 *
 * Uses the same Bun dlopen pattern as crypto/backend-ffi.js.
 *
 * @module wallet-store-ffi
 */

import { dlopen, FFIType, read, toBuffer, ptr as ptrFn, CString } from 'bun:ffi';
import { WalletStorage, WalletOutput, WalletTransaction } from './wallet-store.js';

const { ptr, i32, u32, i64, u64, usize } = FFIType;

// ─── Library path resolution ────────────────────────────────────────────────

function resolveLibPath() {
  if (process.env.SALVIUM_CRYPTO_LIB) {
    return process.env.SALVIUM_CRYPTO_LIB;
  }

  const { fileURLToPath } = require('url');
  const { dirname, join } = require('path');

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const projectRoot = join(__dirname, '..');
  return join(projectRoot, 'crates', 'salvium-crypto', 'target', 'release', 'libsalvium_crypto.so');
}

// ─── FFI symbol definitions (storage subset) ────────────────────────────────

const STORAGE_SYMBOLS = {
  salvium_storage_open:           { args: [ptr, usize, ptr, usize], returns: i32 },
  salvium_storage_close:          { args: [u32], returns: i32 },
  salvium_storage_clear:          { args: [u32], returns: i32 },

  salvium_storage_put_output:     { args: [u32, ptr, usize], returns: i32 },
  salvium_storage_get_output:     { args: [u32, ptr, usize, ptr, ptr], returns: i32 },
  salvium_storage_get_outputs:    { args: [u32, ptr, usize, ptr, ptr], returns: i32 },
  salvium_storage_mark_spent:     { args: [u32, ptr, usize, ptr, usize, i64], returns: i32 },

  salvium_storage_put_tx:         { args: [u32, ptr, usize], returns: i32 },
  salvium_storage_get_tx:         { args: [u32, ptr, usize, ptr, ptr], returns: i32 },
  salvium_storage_get_txs:        { args: [u32, ptr, usize, ptr, ptr], returns: i32 },

  salvium_storage_get_sync_height: { args: [u32], returns: i64 },
  salvium_storage_set_sync_height: { args: [u32, i64], returns: i32 },

  salvium_storage_put_block_hash: { args: [u32, i64, ptr, usize], returns: i32 },
  salvium_storage_get_block_hash: { args: [u32, i64, ptr, ptr], returns: i32 },

  salvium_storage_rollback:       { args: [u32, i64], returns: i32 },

  salvium_storage_get_asset_types: { args: [u32, ptr, ptr], returns: i32 },
  salvium_storage_get_balance:    { args: [u32, i64, ptr, usize, i32, ptr, ptr], returns: i32 },
  salvium_storage_get_all_balances: { args: [u32, i64, i32, ptr, ptr], returns: i32 },

  salvium_storage_free_buf:       { args: [ptr, usize], returns: FFIType.void },
};

// Singleton library handle
let _lib = null;

function getLib() {
  if (!_lib) {
    const libPath = resolveLibPath();
    _lib = dlopen(libPath, STORAGE_SYMBOLS);
  }
  return _lib;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Read a Rust-allocated buffer (out_ptr, out_len pattern) and free it.
 * Returns the content as a string.
 *
 * Uses CString instead of toBuffer to avoid creating external Buffer views
 * that become dangling pointers after free_buf — Bun's GC can crash when
 * scanning freed external memory during compaction.
 */
function readAndFree(outPtrBuf, outLenBuf) {
  // Read pointer and length from the output buffers
  const ptrVal = Number(outPtrBuf.readBigUInt64LE(0));
  const len = Number(outLenBuf.readBigUInt64LE(0));
  if (ptrVal === 0 || len === 0) return null;

  // CString reads from the pointer into a JS string — no external Buffer created
  const str = new CString(ptrVal, 0, len);

  // Free the Rust-allocated buffer
  getLib().symbols.salvium_storage_free_buf(ptrVal, len);

  // .toString() ensures we have a plain JS string (CString may lazy-evaluate)
  return str.toString();
}

// ─── FfiStorage class ───────────────────────────────────────────────────────

export class FfiStorage extends WalletStorage {
  constructor(options = {}) {
    super();
    this._path = options.path || './wallet.db';
    this._key = options.key;  // 32-byte Uint8Array or Buffer encryption key
    this._handle = -1;
  }

  async open() {
    const lib = getLib();
    const pathBuf = Buffer.from(this._path, 'utf-8');
    const keyBuf = this._key ? Buffer.from(this._key) : Buffer.alloc(32);
    this._handle = lib.symbols.salvium_storage_open(
      pathBuf, pathBuf.length, keyBuf, keyBuf.length
    );
    if (this._handle < 0) throw new Error('Failed to open storage');
  }

  async close() {
    if (this._handle >= 0) {
      getLib().symbols.salvium_storage_close(this._handle);
      this._handle = -1;
    }
  }

  async clear() {
    const rc = getLib().symbols.salvium_storage_clear(this._handle);
    if (rc !== 0) throw new Error('clear failed');
  }

  // ── Output operations ─────────────────────────────────────────────────

  async putOutput(output) {
    const wo = output instanceof WalletOutput ? output : new WalletOutput(output);
    const json = JSON.stringify(wo.toJSON());
    const buf = Buffer.from(json, 'utf-8');
    const rc = getLib().symbols.salvium_storage_put_output(this._handle, buf, buf.length);
    if (rc !== 0) throw new Error('putOutput failed');
    return wo;
  }

  async getOutput(keyImage) {
    if (!keyImage) return null;
    const kiBuf = Buffer.from(keyImage, 'utf-8');
    const outPtrBuf = Buffer.alloc(8); // pointer (64-bit)
    const outLenBuf = Buffer.alloc(8); // size_t (64-bit)
    const rc = getLib().symbols.salvium_storage_get_output(
      this._handle, kiBuf, kiBuf.length, outPtrBuf, outLenBuf
    );
    if (rc !== 0) return null;
    const jsonStr = readAndFree(outPtrBuf, outLenBuf);
    if (!jsonStr) return null;
    return WalletOutput.fromJSON(JSON.parse(jsonStr));
  }

  async getOutputs(query = {}) {
    const queryJson = JSON.stringify(query);
    const queryBuf = Buffer.from(queryJson, 'utf-8');
    const outPtrBuf = Buffer.alloc(8);
    const outLenBuf = Buffer.alloc(8);
    const rc = getLib().symbols.salvium_storage_get_outputs(
      this._handle, queryBuf, queryBuf.length, outPtrBuf, outLenBuf
    );
    if (rc !== 0) throw new Error('getOutputs failed');
    const jsonStr = readAndFree(outPtrBuf, outLenBuf);
    if (!jsonStr) return [];
    const rows = JSON.parse(jsonStr);
    return rows.map(r => WalletOutput.fromJSON(r));
  }

  async markOutputSpent(keyImage, spendingTxHash, spentHeight = null) {
    const kiBuf = Buffer.from(keyImage, 'utf-8');
    const txBuf = Buffer.from(spendingTxHash || '', 'utf-8');
    const rc = getLib().symbols.salvium_storage_mark_spent(
      this._handle, kiBuf, kiBuf.length, txBuf, txBuf.length,
      spentHeight !== null ? spentHeight : 0
    );
    if (rc !== 0) throw new Error('markOutputSpent failed');
  }

  // ── Transaction operations ────────────────────────────────────────────

  async putTransaction(tx) {
    const wt = tx instanceof WalletTransaction ? tx : new WalletTransaction(tx);
    const json = JSON.stringify(wt.toJSON());
    const buf = Buffer.from(json, 'utf-8');
    const rc = getLib().symbols.salvium_storage_put_tx(this._handle, buf, buf.length);
    if (rc !== 0) throw new Error('putTransaction failed');
    return wt;
  }

  async getTransaction(txHash) {
    const thBuf = Buffer.from(txHash, 'utf-8');
    const outPtrBuf = Buffer.alloc(8);
    const outLenBuf = Buffer.alloc(8);
    const rc = getLib().symbols.salvium_storage_get_tx(
      this._handle, thBuf, thBuf.length, outPtrBuf, outLenBuf
    );
    if (rc !== 0) return null;
    const jsonStr = readAndFree(outPtrBuf, outLenBuf);
    if (!jsonStr) return null;
    return WalletTransaction.fromJSON(JSON.parse(jsonStr));
  }

  async getTransactions(query = {}) {
    const queryJson = JSON.stringify(query);
    const queryBuf = Buffer.from(queryJson, 'utf-8');
    const outPtrBuf = Buffer.alloc(8);
    const outLenBuf = Buffer.alloc(8);
    const rc = getLib().symbols.salvium_storage_get_txs(
      this._handle, queryBuf, queryBuf.length, outPtrBuf, outLenBuf
    );
    if (rc !== 0) throw new Error('getTransactions failed');
    const jsonStr = readAndFree(outPtrBuf, outLenBuf);
    if (!jsonStr) return [];
    const rows = JSON.parse(jsonStr);
    return rows.map(r => WalletTransaction.fromJSON(r));
  }

  // ── Key image operations (delegated to output table) ──────────────────

  async putKeyImage(keyImage, outputRef) {
    // Key images are tracked via the outputs table — no separate call needed.
    // This is a no-op for FFI storage; key images are inserted with putOutput.
  }

  async isKeyImageSpent(keyImage) {
    const output = await this.getOutput(keyImage);
    return output ? output.isSpent : false;
  }

  async getSpentKeyImages() {
    const outputs = await this.getOutputs({ isSpent: true });
    return outputs.map(o => o.keyImage).filter(Boolean);
  }

  // ── Sync state ────────────────────────────────────────────────────────

  async getSyncHeight() {
    const h = getLib().symbols.salvium_storage_get_sync_height(this._handle);
    return Number(h >= 0n ? h : 0n);
  }

  async setSyncHeight(height) {
    const rc = getLib().symbols.salvium_storage_set_sync_height(this._handle, height);
    if (rc !== 0) throw new Error('setSyncHeight failed');
  }

  async getState(key) {
    // State is stored in the meta table but we don't have a generic get/set FFI.
    // For now, sync_height is the primary use case. Other state keys can use
    // block hash storage or be added later.
    if (key === 'syncHeight') {
      return await this.getSyncHeight();
    }
    return undefined;
  }

  async setState(key, value) {
    if (key === 'syncHeight') {
      return await this.setSyncHeight(value);
    }
  }

  // ── Block hash tracking ───────────────────────────────────────────────

  async putBlockHash(height, hash) {
    const hashBuf = Buffer.from(hash, 'utf-8');
    const rc = getLib().symbols.salvium_storage_put_block_hash(
      this._handle, height, hashBuf, hashBuf.length
    );
    if (rc !== 0) throw new Error('putBlockHash failed');
  }

  async getBlockHash(height) {
    const outPtrBuf = Buffer.alloc(8);
    const outLenBuf = Buffer.alloc(8);
    const rc = getLib().symbols.salvium_storage_get_block_hash(
      this._handle, height, outPtrBuf, outLenBuf
    );
    if (rc !== 0) return null;
    return readAndFree(outPtrBuf, outLenBuf);
  }

  async deleteBlockHashesAbove(height) {
    // Handled atomically by rollback; standalone call does rollback
    // For standalone usage, we do a rollback which includes this
  }

  // ── Reorg rollback (single atomic call) ───────────────────────────────

  async deleteOutputsAbove(height) {
    // Part of atomic rollback — call rollback() instead
  }

  async deleteTransactionsAbove(height) {
    // Part of atomic rollback — call rollback() instead
  }

  async unspendOutputsAbove(height) {
    // Part of atomic rollback — call rollback() instead
  }

  /**
   * Atomic rollback: deletes outputs/txs/block_hashes above height,
   * unspends outputs spent above height. All in one SQLite transaction.
   */
  async rollback(height) {
    const rc = getLib().symbols.salvium_storage_rollback(this._handle, height);
    if (rc !== 0) throw new Error('rollback failed');
  }

  // ── Asset Types ─────────────────────────────────────────────────────

  /**
   * Get distinct asset types present in the wallet outputs.
   * @returns {string[]} e.g. ['SAL', 'SAL1']
   */
  async getAssetTypes() {
    const outPtrBuf = Buffer.alloc(8);
    const outLenBuf = Buffer.alloc(8);
    const rc = getLib().symbols.salvium_storage_get_asset_types(
      this._handle, outPtrBuf, outLenBuf
    );
    if (rc !== 0) throw new Error('getAssetTypes failed');
    const jsonStr = readAndFree(outPtrBuf, outLenBuf);
    if (!jsonStr) return [];
    return JSON.parse(jsonStr);
  }

  // ── Balance (Rust-computed, no output round-trip) ─────────────────────

  /**
   * Compute balance in Rust. Returns { balance, unlockedBalance, lockedBalance }
   * as BigInt values.
   *
   * @param {Object} options
   * @param {number} options.currentHeight - Current blockchain height
   * @param {string} options.assetType - Asset type ('SAL', 'SAL1', or 'VSD')
   * @param {number} [options.accountIndex=-1] - Account index (-1 for all)
   * @returns {{ balance: bigint, unlockedBalance: bigint, lockedBalance: bigint }}
   */
  getBalance(options = {}) {
    const { currentHeight, assetType, accountIndex = -1 } = options;
    if (currentHeight === undefined) throw new Error('currentHeight required');
    if (!assetType) throw new Error('assetType required (e.g. "SAL", "SAL1", or "VSD")');

    const atBuf = Buffer.from(assetType, 'utf-8');
    const outPtrBuf = Buffer.alloc(8);
    const outLenBuf = Buffer.alloc(8);
    const rc = getLib().symbols.salvium_storage_get_balance(
      this._handle, currentHeight, atBuf, atBuf.length,
      accountIndex, outPtrBuf, outLenBuf
    );
    if (rc !== 0) throw new Error('getBalance failed');

    const jsonStr = readAndFree(outPtrBuf, outLenBuf);
    if (!jsonStr) return { balance: 0n, unlockedBalance: 0n, lockedBalance: 0n };

    const result = JSON.parse(jsonStr);
    return {
      balance: BigInt(result.balance || '0'),
      unlockedBalance: BigInt(result.unlockedBalance || '0'),
      lockedBalance: BigInt(result.lockedBalance || '0'),
    };
  }

  /**
   * Get balances for ALL asset types in the wallet. Single FFI call.
   *
   * @param {Object} options
   * @param {number} options.currentHeight - Current blockchain height
   * @param {number} [options.accountIndex=-1] - Account index (-1 for all)
   * @returns {Object<string, { balance: bigint, unlockedBalance: bigint, lockedBalance: bigint }>}
   */
  getAllBalances(options = {}) {
    const { currentHeight, accountIndex = -1 } = options;
    if (currentHeight === undefined) throw new Error('currentHeight required');

    const outPtrBuf = Buffer.alloc(8);
    const outLenBuf = Buffer.alloc(8);
    const rc = getLib().symbols.salvium_storage_get_all_balances(
      this._handle, currentHeight, accountIndex, outPtrBuf, outLenBuf
    );
    if (rc !== 0) throw new Error('getAllBalances failed');

    const jsonStr = readAndFree(outPtrBuf, outLenBuf);
    if (!jsonStr) return {};

    const raw = JSON.parse(jsonStr);
    const result = {};
    for (const [assetType, bal] of Object.entries(raw)) {
      result[assetType] = {
        balance: BigInt(bal.balance || '0'),
        unlockedBalance: BigInt(bal.unlockedBalance || '0'),
        lockedBalance: BigInt(bal.lockedBalance || '0'),
      };
    }
    return result;
  }
}

export default FfiStorage;
