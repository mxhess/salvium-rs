/**
 * Wallet Listener Module
 *
 * Event listener system for wallet updates:
 * - Sync progress notifications
 * - Balance change events
 * - Output received/spent events
 * - Stake payout events
 *
 * @module wallet/listener
 */

// =============================================================================
// WALLET LISTENER BASE CLASS
// =============================================================================

/**
 * Base class for wallet event listeners
 * Extend this class and override methods to receive wallet events
 */
export class WalletListener {
  /**
   * Called when sync progress updates
   * @param {number} height - Current sync height
   * @param {number} startHeight - Sync start height
   * @param {number} endHeight - Target end height
   * @param {number} percentDone - Percentage complete (0-100)
   * @param {string} message - Optional status message
   */
  onSyncProgress(height, startHeight, endHeight, percentDone, message) {}

  /**
   * Called when a new block is processed
   * @param {number} height - Block height
   * @param {string} hash - Block hash
   */
  onNewBlock(height, hash) {}

  /**
   * Called when wallet balance changes
   * @param {bigint} newBalance - New total balance
   * @param {bigint} newUnlockedBalance - New unlocked balance
   * @param {string} assetType - Asset type (default: 'SAL')
   */
  onBalanceChanged(newBalance, newUnlockedBalance, assetType = 'SAL') {}

  /**
   * Called when an output is received (called up to 3 times per output)
   * @param {Object} output - Output details
   * @param {string} status - 'unconfirmed', 'confirmed', or 'unlocked'
   */
  onOutputReceived(output, status) {}

  /**
   * Called when an output is spent (called up to 2 times per output)
   * @param {Object} output - Output details
   * @param {string} status - 'confirmed' or 'unlocked'
   */
  onOutputSpent(output, status) {}

  /**
   * Called when a stake payout is received
   * @param {Object} payout - Payout details (amount, stakeOrigin, etc.)
   */
  onStakePayout(payout) {}

  /**
   * Called when sync completes
   * @param {number} height - Final sync height
   */
  onSyncComplete(height) {}

  /**
   * Called on sync error
   * @param {Error} error - Error that occurred
   */
  onSyncError(error) {}
}

/**
 * Console logging listener for debugging
 */
export class ConsoleListener extends WalletListener {
  constructor(prefix = '[Wallet]') {
    super();
    this._prefix = prefix;
  }

  onSyncProgress(height, startHeight, endHeight, percentDone, message) {
    console.log(`${this._prefix} Sync: ${percentDone.toFixed(1)}% (${height}/${endHeight})${message ? ' - ' + message : ''}`);
  }

  onNewBlock(height, hash) {
    console.log(`${this._prefix} New block: ${height}`);
  }

  onBalanceChanged(newBalance, newUnlockedBalance, assetType) {
    console.log(`${this._prefix} Balance changed [${assetType}]: ${newBalance} (${newUnlockedBalance} unlocked)`);
  }

  onOutputReceived(output, status) {
    console.log(`${this._prefix} Output received [${status}]: ${output.amount}`);
  }

  onOutputSpent(output, status) {
    console.log(`${this._prefix} Output spent [${status}]: ${output.amount}`);
  }

  onStakePayout(payout) {
    console.log(`${this._prefix} Stake payout: ${payout.amount}`);
  }

  onSyncComplete(height) {
    console.log(`${this._prefix} Sync complete at height ${height}`);
  }

  onSyncError(error) {
    console.error(`${this._prefix} Sync error:`, error);
  }
}

/**
 * Callback-based listener for functional patterns
 */
export class CallbackListener extends WalletListener {
  constructor(callbacks = {}) {
    super();
    this._callbacks = callbacks;
  }

  onSyncProgress(height, startHeight, endHeight, percentDone, message) {
    this._callbacks.onSyncProgress?.(height, startHeight, endHeight, percentDone, message);
  }

  onNewBlock(height, hash) {
    this._callbacks.onNewBlock?.(height, hash);
  }

  onBalanceChanged(newBalance, newUnlockedBalance, assetType) {
    this._callbacks.onBalanceChanged?.(newBalance, newUnlockedBalance, assetType);
  }

  onOutputReceived(output, status) {
    this._callbacks.onOutputReceived?.(output, status);
  }

  onOutputSpent(output, status) {
    this._callbacks.onOutputSpent?.(output, status);
  }

  onStakePayout(payout) {
    this._callbacks.onStakePayout?.(payout);
  }

  onSyncComplete(height) {
    this._callbacks.onSyncComplete?.(height);
  }

  onSyncError(error) {
    this._callbacks.onSyncError?.(error);
  }
}
