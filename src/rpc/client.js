/**
 * Base RPC Client
 *
 * Provides HTTP client infrastructure for Salvium daemon and wallet RPC.
 * Supports JSON-RPC 2.0 protocol with authentication, retries, and error handling.
 * Works in both browser and Node.js environments.
 *
 * Supports multiple server URLs with latency-based selection via ConnectionManager.
 * Single URL = direct connection (no overhead).
 * Multiple URLs = race on connect, pick fastest, failover on error.
 */

import { ConnectionManager, SEED_NODES } from './connection-manager.js';

/** Base64 encode a string (works in QuickJS, browsers, Node.js) */
function _toBase64(str) {
  if (typeof btoa === 'function') return btoa(str);
  const bytes = new TextEncoder().encode(str);
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let result = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i], b = bytes[i + 1] || 0, c = bytes[i + 2] || 0;
    result += chars[a >> 2] + chars[((a & 3) << 4) | (b >> 4)]
      + (i + 1 < bytes.length ? chars[((b & 15) << 2) | (c >> 6)] : '=')
      + (i + 2 < bytes.length ? chars[c & 63] : '=');
  }
  return result;
}

/**
 * @typedef {Object} RPCClientOptions
 * @property {string} url - RPC server URL (e.g., 'http://localhost:19081')
 * @property {string} [username] - Optional username for digest authentication
 * @property {string} [password] - Optional password for digest authentication
 * @property {number} [timeout=30000] - Request timeout in milliseconds
 * @property {number} [retries=0] - Number of retry attempts on failure
 * @property {number} [retryDelay=1000] - Delay between retries in milliseconds
 * @property {Object} [headers] - Additional HTTP headers
 */

/**
 * @typedef {Object} RPCResponse
 * @property {boolean} success - Whether the request was successful
 * @property {*} [result] - Response data on success
 * @property {RPCError} [error] - Error details on failure
 */

/**
 * @typedef {Object} RPCError
 * @property {number} code - Error code
 * @property {string} message - Error message
 * @property {*} [data] - Additional error data
 */

/**
 * Standard JSON-RPC 2.0 error codes
 */
export const RPC_ERROR_CODES = {
  PARSE_ERROR: -32700,
  INVALID_REQUEST: -32600,
  METHOD_NOT_FOUND: -32601,
  INVALID_PARAMS: -32602,
  INTERNAL_ERROR: -32603,
  // Salvium-specific error codes
  WALLET_NOT_FOUND: -1,
  WALLET_RPC_ERROR: -2,
  NETWORK_ERROR: -3,
  TIMEOUT_ERROR: -4,
  AUTHENTICATION_ERROR: -5
};

/**
 * RPC status values
 */
export const RPC_STATUS = {
  OK: 'OK',
  BUSY: 'BUSY',
  NOT_MINING: 'NOT MINING',
  PAYMENT_REQUIRED: 'PAYMENT REQUIRED'
};

/**
 * Base RPC Client class
 */
export class RPCClient {
  /**
   * Create an RPC client
   * @param {RPCClientOptions} options - Client configuration
   */
  constructor(options = {}) {
    // Resolve URLs: explicit urls array, network seed nodes, or single url
    let urls = options.urls || null;
    if (!urls && options.network && SEED_NODES[options.network]) {
      urls = SEED_NODES[options.network];
    }

    if (urls && urls.length > 0) {
      this.url = urls[0].replace(/\/+$/, '');
      this._connectionManager = new ConnectionManager({
        urls: urls.map(u => u.replace(/\/+$/, '')),
        raceTimeout: options.raceTimeout || 5000,
        degradationFactor: options.degradationFactor || 2,
        raceInterval: options.raceInterval || 0,
        onSwitch: options.onSwitch || null,
      });
    } else if (options.url) {
      this.url = options.url.replace(/\/+$/, '');
      this._connectionManager = null;
    } else {
      throw new Error('RPC client requires a url, urls array, or network name');
    }

    this.username = options.username || null;
    this.password = options.password || null;
    this.timeout = options.timeout || 30000;
    this.retries = options.retries || 0;
    this.retryDelay = options.retryDelay || 1000;
    this.headers = options.headers || {};
    this._requestId = 0;
  }

  /**
   * Get the currently active URL (may change with ConnectionManager)
   * @returns {string}
   */
  getActiveUrl() {
    if (this._connectionManager) {
      return this._connectionManager.activeUrl;
    }
    return this.url;
  }

  /**
   * Race all configured servers and pick the fastest.
   * No-op if only one server is configured.
   * @returns {Promise<string>} The active URL after racing
   */
  async race() {
    if (this._connectionManager) {
      const url = await this._connectionManager.race();
      this.url = url;
      return url;
    }
    return this.url;
  }

  /**
   * Generate a unique request ID
   * @returns {number} Request ID
   * @private
   */
  _nextId() {
    return ++this._requestId;
  }

  /**
   * Build request headers
   * @returns {Object} Headers object
   * @private
   */
  _buildHeaders() {
    const headers = {
      'Content-Type': 'application/json',
      ...this.headers
    };

    // Add basic auth if credentials provided
    if (this.username && this.password) {
      const credentials = _toBase64(`${this.username}:${this.password}`);
      headers['Authorization'] = `Basic ${credentials}`;
    }

    return headers;
  }

  /**
   * Sleep for a specified duration
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<void>}
   * @private
   */
  _sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Make an HTTP request with timeout
   * @param {string} url - Request URL
   * @param {Object} options - Fetch options
   * @returns {Promise<Response>}
   * @private
   */
  async _fetchWithTimeout(url, options) {
    return Promise.race([
      fetch(url, options),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Request timed out')), this.timeout)
      ),
    ]);
  }

  /**
   * Make a JSON-RPC 2.0 request
   * @param {string} method - RPC method name
   * @param {Object} [params={}] - Method parameters
   * @returns {Promise<RPCResponse>}
   */
  /**
   * Get the current URL, ensuring connection manager has raced if needed.
   * @returns {Promise<string>}
   * @private
   */
  async _resolveUrl() {
    if (this._connectionManager) {
      await this._connectionManager.ensureConnected();
      this.url = this._connectionManager.activeUrl;
    }
    return this.url;
  }

  /**
   * Record latency and handle failover via connection manager.
   * @param {number} latencyMs - Response latency
   * @private
   */
  _recordLatency(latencyMs) {
    if (this._connectionManager) {
      this._connectionManager.recordLatency(latencyMs);
      this.url = this._connectionManager.activeUrl;
    }
  }

  /**
   * Handle network failure — failover to next server if available.
   * @returns {Promise<boolean>} true if a new server is available to retry
   * @private
   */
  async _handleNetworkFailure() {
    if (this._connectionManager && this._connectionManager.isMultiServer) {
      const newUrl = await this._connectionManager.handleFailure();
      if (newUrl) {
        this.url = newUrl;
        return true;
      }
    }
    return false;
  }

  async call(method, params = {}) {
    const payload = {
      jsonrpc: '2.0',
      id: this._nextId(),
      method,
      params
    };

    await this._resolveUrl();

    let lastError = null;
    const attempts = this.retries + 1;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      const start = Date.now();
      try {
        const response = await this._fetchWithTimeout(`${this.url}/json_rpc`, {
          method: 'POST',
          headers: this._buildHeaders(),
          body: JSON.stringify(payload)
        });

        this._recordLatency(Date.now() - start);

        if (!response.ok) {
          if (response.status === 401) {
            return {
              success: false,
              error: {
                code: RPC_ERROR_CODES.AUTHENTICATION_ERROR,
                message: 'Authentication failed'
              }
            };
          }
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        // Handle JSON-RPC error response
        if (data.error) {
          return {
            success: false,
            error: {
              code: data.error.code || RPC_ERROR_CODES.INTERNAL_ERROR,
              message: data.error.message || 'Unknown RPC error',
              data: data.error.data
            }
          };
        }

        // Check for Salvium status field in result
        if (data.result && data.result.status && data.result.status !== RPC_STATUS.OK) {
          if (data.result.status === RPC_STATUS.BUSY) {
            // Daemon is syncing, might want to retry
            if (attempt < attempts) {
              lastError = { code: -1, message: 'Daemon is busy syncing' };
              await this._sleep(this.retryDelay);
              continue;
            }
          }
          // Return the result anyway, let caller handle status
        }

        return {
          success: true,
          result: data.result
        };

      } catch (error) {
        if (error.name === 'AbortError') {
          lastError = {
            code: RPC_ERROR_CODES.TIMEOUT_ERROR,
            message: `Request timed out after ${this.timeout}ms`
          };
        } else {
          lastError = {
            code: RPC_ERROR_CODES.NETWORK_ERROR,
            message: error.message || 'Network error'
          };
        }

        // Try failover to another server before exhausting retries
        if (await this._handleNetworkFailure()) {
          continue; // Retry on the new server
        }

        if (attempt < attempts) {
          await this._sleep(this.retryDelay);
        }
      }
    }

    return {
      success: false,
      error: lastError
    };
  }

  /**
   * Make a raw HTTP POST request (for non-JSON-RPC endpoints)
   * @param {string} endpoint - API endpoint path
   * @param {Object} [data={}] - Request body
   * @returns {Promise<RPCResponse>}
   */
  async post(endpoint, data = {}) {
    await this._resolveUrl();

    let lastError = null;
    const attempts = this.retries + 1;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      const start = Date.now();
      try {
        const url = endpoint.startsWith('/')
          ? `${this.url}${endpoint}`
          : `${this.url}/${endpoint}`;

        const response = await this._fetchWithTimeout(url, {
          method: 'POST',
          headers: this._buildHeaders(),
          body: JSON.stringify(data)
        });

        this._recordLatency(Date.now() - start);

        if (!response.ok) {
          if (response.status === 401) {
            return {
              success: false,
              error: {
                code: RPC_ERROR_CODES.AUTHENTICATION_ERROR,
                message: 'Authentication failed'
              }
            };
          }
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        // Check for status field
        if (result.status && result.status !== RPC_STATUS.OK) {
          if (result.status === RPC_STATUS.BUSY && attempt < attempts) {
            lastError = { code: -1, message: 'Daemon is busy syncing' };
            await this._sleep(this.retryDelay);
            continue;
          }
        }

        return {
          success: true,
          result
        };

      } catch (error) {
        if (error.name === 'AbortError') {
          lastError = {
            code: RPC_ERROR_CODES.TIMEOUT_ERROR,
            message: `Request timed out after ${this.timeout}ms`
          };
        } else {
          lastError = {
            code: RPC_ERROR_CODES.NETWORK_ERROR,
            message: error.message || 'Network error'
          };
        }

        if (await this._handleNetworkFailure()) {
          continue;
        }

        if (attempt < attempts) {
          await this._sleep(this.retryDelay);
        }
      }
    }

    return {
      success: false,
      error: lastError
    };
  }

  /**
   * POST binary data (portable storage format) and parse binary response
   * @param {string} endpoint - API endpoint path
   * @param {Uint8Array} body - Binary request body
   * @returns {Promise<RPCResponse>}
   */
  async postBinary(endpoint, body) {
    await this._resolveUrl();

    let lastError = null;
    const attempts = this.retries + 1;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      const start = Date.now();
      try {
        const url = endpoint.startsWith('/')
          ? `${this.url}${endpoint}`
          : `${this.url}/${endpoint}`;

        const response = await this._fetchWithTimeout(url, {
          method: 'POST',
          headers: {
            ...this._buildHeaders(),
            'Content-Type': 'application/octet-stream'
          },
          body
        });

        this._recordLatency(Date.now() - start);

        if (!response.ok) {
          if (response.status === 401) {
            return {
              success: false,
              error: {
                code: RPC_ERROR_CODES.AUTHENTICATION_ERROR,
                message: 'Authentication failed'
              }
            };
          }
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const arrayBuffer = await response.arrayBuffer();
        return {
          success: true,
          result: new Uint8Array(arrayBuffer)
        };

      } catch (error) {
        if (error.name === 'AbortError') {
          lastError = {
            code: RPC_ERROR_CODES.TIMEOUT_ERROR,
            message: `Request timed out after ${this.timeout}ms`
          };
        } else {
          lastError = {
            code: RPC_ERROR_CODES.NETWORK_ERROR,
            message: error.message || 'Network error'
          };
        }

        if (await this._handleNetworkFailure()) {
          continue;
        }

        if (attempt < attempts) {
          await this._sleep(this.retryDelay);
        }
      }
    }

    return {
      success: false,
      error: lastError
    };
  }

  /**
   * Make a raw HTTP GET request
   * @param {string} endpoint - API endpoint path
   * @param {Object} [params={}] - Query parameters
   * @returns {Promise<RPCResponse>}
   */
  async get(endpoint, params = {}) {
    await this._resolveUrl();

    let lastError = null;
    const attempts = this.retries + 1;

    for (let attempt = 1; attempt <= attempts; attempt++) {
      const start = Date.now();
      try {
        let url = endpoint.startsWith('/')
          ? `${this.url}${endpoint}`
          : `${this.url}/${endpoint}`;

        // Add query parameters
        const queryString = Object.entries(params)
          .filter(([, v]) => v !== undefined && v !== null)
          .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
          .join('&');
        if (queryString) {
          url += `?${queryString}`;
        }

        const response = await this._fetchWithTimeout(url, {
          method: 'GET',
          headers: this._buildHeaders()
        });

        this._recordLatency(Date.now() - start);

        if (!response.ok) {
          if (response.status === 401) {
            return {
              success: false,
              error: {
                code: RPC_ERROR_CODES.AUTHENTICATION_ERROR,
                message: 'Authentication failed'
              }
            };
          }
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        const result = await response.json();

        return {
          success: true,
          result
        };

      } catch (error) {
        if (error.name === 'AbortError') {
          lastError = {
            code: RPC_ERROR_CODES.TIMEOUT_ERROR,
            message: `Request timed out after ${this.timeout}ms`
          };
        } else {
          lastError = {
            code: RPC_ERROR_CODES.NETWORK_ERROR,
            message: error.message || 'Network error'
          };
        }

        if (await this._handleNetworkFailure()) {
          continue;
        }

        if (attempt < attempts) {
          await this._sleep(this.retryDelay);
        }
      }
    }

    return {
      success: false,
      error: lastError
    };
  }

  /**
   * Check if the RPC server is reachable
   * @returns {Promise<boolean>}
   */
  async isConnected() {
    try {
      const response = await this._fetchWithTimeout(this.url, {
        method: 'GET',
        headers: this._buildHeaders()
      });
      return response.ok || response.status === 404; // 404 is OK, server is reachable
    } catch (_e) {
      return false;
    }
  }

  /**
   * Update client configuration
   * @param {Partial<RPCClientOptions>} options - Options to update
   */
  configure(options) {
    if (options.url) this.url = options.url.replace(/\/+$/, '');
    if (options.username !== undefined) this.username = options.username;
    if (options.password !== undefined) this.password = options.password;
    if (options.timeout !== undefined) this.timeout = options.timeout;
    if (options.retries !== undefined) this.retries = options.retries;
    if (options.retryDelay !== undefined) this.retryDelay = options.retryDelay;
    if (options.headers) this.headers = { ...this.headers, ...options.headers };
  }
}

/**
 * Create a new RPC client instance
 * @param {RPCClientOptions} options - Client configuration
 * @returns {RPCClient}
 */
export function createClient(options) {
  return new RPCClient(options);
}

export default {
  RPCClient,
  createClient,
  RPC_ERROR_CODES,
  RPC_STATUS
};
