/**
 * RPC Connection Manager
 *
 * Manages multiple RPC connections with:
 * - Automatic failover on connection failure
 * - Health checking and reconnection
 * - Load balancing (optional)
 * - Connection pooling
 *
 * @module connection-manager
 */

import { DaemonRPC, WalletRPC, createDaemonRPC, createWalletRPC } from './rpc/index.js';

// ============================================================================
// CONNECTION STATES
// ============================================================================

export const CONNECTION_STATE = {
  DISCONNECTED: 'disconnected',
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  FAILED: 'failed'
};

// ============================================================================
// CONNECTION INFO
// ============================================================================

/**
 * Represents a single RPC connection configuration
 */
export class ConnectionInfo {
  constructor(config = {}) {
    this.uri = config.uri || config.url;
    this.username = config.username || null;
    this.password = config.password || null;
    this.priority = config.priority ?? 1;  // Lower = higher priority
    this.timeout = config.timeout ?? 30000;
    this.retries = config.retries ?? 3;
    this.retryDelay = config.retryDelay ?? 1000;

    // State tracking
    this.state = CONNECTION_STATE.DISCONNECTED;
    this.lastCheckTime = null;
    this.lastError = null;
    this.failCount = 0;
    this.responseTime = null;  // Average response time in ms
  }

  /**
   * Get RPC client options
   * @returns {Object}
   */
  toRpcOptions() {
    return {
      url: this.uri,
      username: this.username,
      password: this.password,
      timeout: this.timeout,
      retries: this.retries,
      retryDelay: this.retryDelay
    };
  }

  /**
   * Mark connection as failed
   * @param {Error} error
   */
  markFailed(error) {
    this.state = CONNECTION_STATE.FAILED;
    this.lastError = error;
    this.failCount++;
  }

  /**
   * Mark connection as successful
   * @param {number} responseTime
   */
  markSuccess(responseTime) {
    this.state = CONNECTION_STATE.CONNECTED;
    this.lastError = null;
    this.failCount = 0;
    this.lastCheckTime = Date.now();
    // Exponential moving average for response time
    if (this.responseTime === null) {
      this.responseTime = responseTime;
    } else {
      this.responseTime = 0.7 * this.responseTime + 0.3 * responseTime;
    }
  }

  /**
   * Reset failure state (for retry)
   */
  reset() {
    this.state = CONNECTION_STATE.DISCONNECTED;
    this.failCount = 0;
  }
}

// ============================================================================
// CONNECTION MANAGER
// ============================================================================

/**
 * Manages multiple RPC connections with automatic failover
 */
export class ConnectionManager {
  /**
   * Create a connection manager
   * @param {Object} config - Configuration
   * @param {Array<Object>} config.connections - Array of connection configs
   * @param {number} config.checkPeriod - Health check interval in ms (default: 30000)
   * @param {boolean} config.autoSwitch - Auto-switch on failure (default: true)
   * @param {string} config.proxyType - 'daemon' or 'wallet' (default: 'daemon')
   */
  constructor(config = {}) {
    this.connections = (config.connections || []).map(c =>
      c instanceof ConnectionInfo ? c : new ConnectionInfo(c)
    );
    this.checkPeriod = config.checkPeriod ?? 30000;
    this.autoSwitch = config.autoSwitch ?? true;
    this.proxyType = config.proxyType ?? 'daemon';

    // Current active connection
    this._currentIndex = 0;
    this._client = null;

    // Health check interval
    this._checkInterval = null;

    // Event listeners
    this._listeners = [];

    // Sort by priority initially
    this._sortByPriority();
  }

  // ===========================================================================
  // EVENT SYSTEM
  // ===========================================================================

  /**
   * Add event listener
   * @param {string} event - Event name
   * @param {Function} callback - Callback function
   */
  on(event, callback) {
    this._listeners.push({ event, callback });
  }

  /**
   * Remove event listener
   * @param {string} event - Event name
   * @param {Function} callback - Callback function
   */
  off(event, callback) {
    this._listeners = this._listeners.filter(
      l => l.event !== event || l.callback !== callback
    );
  }

  /**
   * Emit an event
   * @private
   */
  _emit(event, ...args) {
    for (const listener of this._listeners) {
      if (listener.event === event) {
        try {
          listener.callback(...args);
        } catch (e) {
          console.error(`Connection manager listener error:`, e);
        }
      }
    }
  }

  // ===========================================================================
  // CONNECTION MANAGEMENT
  // ===========================================================================

  /**
   * Add a connection
   * @param {Object} config - Connection config
   * @returns {ConnectionInfo}
   */
  addConnection(config) {
    const conn = config instanceof ConnectionInfo ? config : new ConnectionInfo(config);
    this.connections.push(conn);
    this._sortByPriority();
    return conn;
  }

  /**
   * Remove a connection by URI
   * @param {string} uri - URI to remove
   */
  removeConnection(uri) {
    const index = this.connections.findIndex(c => c.uri === uri);
    if (index !== -1) {
      this.connections.splice(index, 1);
      if (this._currentIndex >= index && this._currentIndex > 0) {
        this._currentIndex--;
      }
    }
  }

  /**
   * Get all connections
   * @returns {Array<ConnectionInfo>}
   */
  getConnections() {
    return [...this.connections];
  }

  /**
   * Get current connection
   * @returns {ConnectionInfo|null}
   */
  getCurrentConnection() {
    return this.connections[this._currentIndex] || null;
  }

  /**
   * Sort connections by priority (and response time as tiebreaker)
   * @private
   */
  _sortByPriority() {
    this.connections.sort((a, b) => {
      if (a.priority !== b.priority) {
        return a.priority - b.priority;
      }
      // Use response time as tiebreaker (faster = better)
      const aTime = a.responseTime ?? Infinity;
      const bTime = b.responseTime ?? Infinity;
      return aTime - bTime;
    });
  }

  // ===========================================================================
  // CLIENT ACCESS
  // ===========================================================================

  /**
   * Get the active RPC client
   * @returns {DaemonRPC|WalletRPC|null}
   */
  getClient() {
    if (!this._client) {
      this._createClient();
    }
    return this._client;
  }

  /**
   * Get daemon RPC client (alias for getClient when proxyType='daemon')
   * @returns {DaemonRPC}
   */
  getDaemon() {
    if (this.proxyType !== 'daemon') {
      throw new Error('Connection manager is not configured for daemon connections');
    }
    return this.getClient();
  }

  /**
   * Get wallet RPC client (alias for getClient when proxyType='wallet')
   * @returns {WalletRPC}
   */
  getWallet() {
    if (this.proxyType !== 'wallet') {
      throw new Error('Connection manager is not configured for wallet connections');
    }
    return this.getClient();
  }

  /**
   * Create RPC client for current connection
   * @private
   */
  _createClient() {
    const conn = this.getCurrentConnection();
    if (!conn) {
      this._client = null;
      return;
    }

    const options = conn.toRpcOptions();
    if (this.proxyType === 'daemon') {
      this._client = createDaemonRPC(options);
    } else {
      this._client = createWalletRPC(options);
    }

    // Wrap methods to handle failover
    this._wrapClientMethods();
  }

  /**
   * Wrap client methods to handle automatic failover
   * @private
   */
  _wrapClientMethods() {
    if (!this._client || !this.autoSwitch) return;

    const originalCall = this._client.call.bind(this._client);
    this._client.call = async (method, params) => {
      const startTime = Date.now();
      try {
        const result = await originalCall(method, params);
        const elapsed = Date.now() - startTime;

        // Mark current connection as successful
        const conn = this.getCurrentConnection();
        if (conn) conn.markSuccess(elapsed);

        return result;
      } catch (error) {
        // Mark current connection as failed
        const conn = this.getCurrentConnection();
        if (conn) conn.markFailed(error);

        // Try to switch to another connection
        const switched = await this._trySwitch();
        if (switched) {
          // Retry with new connection
          return this._client.call(method, params);
        }

        throw error;
      }
    };
  }

  /**
   * Try to switch to another healthy connection
   * @private
   * @returns {boolean} True if switched successfully
   */
  async _trySwitch() {
    const originalIndex = this._currentIndex;

    // Try each connection in priority order
    for (let i = 0; i < this.connections.length; i++) {
      if (i === originalIndex) continue;  // Skip current

      const conn = this.connections[i];
      if (conn.state === CONNECTION_STATE.FAILED && conn.failCount > 3) {
        continue;  // Skip connections that have failed too many times
      }

      // Test connection
      const healthy = await this._checkConnection(conn);
      if (healthy) {
        this._currentIndex = i;
        this._createClient();
        this._emit('connectionChanged', conn, this.connections[originalIndex]);
        return true;
      }
    }

    return false;
  }

  // ===========================================================================
  // HEALTH CHECKING
  // ===========================================================================

  /**
   * Start periodic health checks
   */
  startChecking() {
    if (this._checkInterval) return;

    // Initial check
    this.checkAll();

    // Periodic checks
    this._checkInterval = setInterval(() => {
      this.checkAll();
    }, this.checkPeriod);
  }

  /**
   * Stop periodic health checks
   */
  stopChecking() {
    if (this._checkInterval) {
      clearInterval(this._checkInterval);
      this._checkInterval = null;
    }
  }

  /**
   * Check all connections
   * @returns {Promise<void>}
   */
  async checkAll() {
    const checks = this.connections.map(conn => this._checkConnection(conn));
    await Promise.all(checks);
    this._sortByPriority();
  }

  /**
   * Check a single connection
   * @private
   * @param {ConnectionInfo} conn
   * @returns {Promise<boolean>} True if healthy
   */
  async _checkConnection(conn) {
    const startTime = Date.now();
    conn.state = CONNECTION_STATE.CONNECTING;

    try {
      // Create temporary client for health check
      const options = conn.toRpcOptions();
      const client = this.proxyType === 'daemon'
        ? createDaemonRPC(options)
        : createWalletRPC(options);

      // Simple health check - get info
      let result;
      if (this.proxyType === 'daemon') {
        result = await client.getInfo();
      } else {
        result = await client.getHeight();
      }

      const elapsed = Date.now() - startTime;

      if (result.success) {
        conn.markSuccess(elapsed);
        return true;
      } else {
        conn.markFailed(new Error(result.error?.message || 'Unknown error'));
        return false;
      }
    } catch (error) {
      conn.markFailed(error);
      return false;
    }
  }

  /**
   * Get best available connection
   * @returns {ConnectionInfo|null}
   */
  getBestConnection() {
    // Find first connected or disconnected connection (not failed)
    return this.connections.find(c =>
      c.state === CONNECTION_STATE.CONNECTED ||
      c.state === CONNECTION_STATE.DISCONNECTED
    ) || null;
  }

  /**
   * Force switch to a specific connection
   * @param {string} uri - URI to switch to
   * @returns {boolean} True if switched
   */
  switchTo(uri) {
    const index = this.connections.findIndex(c => c.uri === uri);
    if (index === -1) return false;

    this._currentIndex = index;
    this._createClient();
    this._emit('connectionChanged', this.connections[index], null);
    return true;
  }

  /**
   * Reset all failed connections (allow retry)
   */
  resetFailed() {
    for (const conn of this.connections) {
      if (conn.state === CONNECTION_STATE.FAILED) {
        conn.reset();
      }
    }
  }

  // ===========================================================================
  // CLEANUP
  // ===========================================================================

  /**
   * Disconnect and clean up
   */
  disconnect() {
    this.stopChecking();
    this._client = null;
    for (const conn of this.connections) {
      conn.state = CONNECTION_STATE.DISCONNECTED;
    }
    this._emit('disconnected');
  }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/**
 * Create a connection manager for daemon connections
 * @param {Array<Object>} connections - Connection configs
 * @param {Object} options - Manager options
 * @returns {ConnectionManager}
 */
export function createDaemonConnectionManager(connections, options = {}) {
  return new ConnectionManager({
    ...options,
    connections,
    proxyType: 'daemon'
  });
}

/**
 * Create a connection manager for wallet connections
 * @param {Array<Object>} connections - Connection configs
 * @param {Object} options - Manager options
 * @returns {ConnectionManager}
 */
export function createWalletConnectionManager(connections, options = {}) {
  return new ConnectionManager({
    ...options,
    connections,
    proxyType: 'wallet'
  });
}

export default {
  ConnectionManager,
  ConnectionInfo,
  CONNECTION_STATE,
  createDaemonConnectionManager,
  createWalletConnectionManager
};
