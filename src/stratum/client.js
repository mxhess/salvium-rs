/**
 * Stratum Protocol Client
 *
 * Implements the stratum mining protocol for pool communication.
 * Based on the stratum protocol used by most cryptocurrency mining pools.
 *
 * Protocol flow:
 * 1. Connect to pool
 * 2. Login with wallet address and worker name
 * 3. Receive mining jobs
 * 4. Submit shares (valid hashes)
 */

import { createConnection } from 'net';
import { connect as tlsConnect } from 'tls';
import { EventEmitter } from 'events';

// Stratum message types
const METHOD = {
  LOGIN: 'login',
  SUBMIT: 'submit',
  KEEPALIVE: 'keepalived',
  JOB: 'job',
  GET_VERSION: 'getjob' // Some pools use this
};

/**
 * Stratum client for pool communication
 *
 * @fires StratumClient#connected - Connected to pool
 * @fires StratumClient#disconnected - Disconnected from pool
 * @fires StratumClient#job - New mining job received
 * @fires StratumClient#accepted - Share accepted
 * @fires StratumClient#rejected - Share rejected
 * @fires StratumClient#error - Error occurred
 * @fires StratumClient#log - Log message
 */
export class StratumClient extends EventEmitter {
  /**
   * Create a stratum client
   *
   * @param {Object} options - Configuration options
   * @param {string} options.pool - Pool URL (stratum+tcp://host:port or stratum+ssl://host:port)
   * @param {string} options.wallet - Wallet address
   * @param {string} options.worker - Worker name (default: 'salvium-js')
   * @param {string} options.password - Pool password (default: 'x')
   * @param {number} options.keepaliveInterval - Keepalive interval in ms (default: 30000)
   * @param {number} options.reconnectDelay - Reconnect delay in ms (default: 5000)
   * @param {boolean} options.autoReconnect - Auto reconnect on disconnect (default: true)
   */
  constructor(options = {}) {
    super();

    // Parse pool URL
    const poolUrl = this._parsePoolUrl(options.pool);
    this.host = poolUrl.host;
    this.port = poolUrl.port;
    this.ssl = poolUrl.ssl;

    // Configuration
    this.wallet = options.wallet;
    this.worker = options.worker || 'salvium-js';
    this.password = options.password || 'x';
    this.keepaliveInterval = options.keepaliveInterval || 30000;
    this.reconnectDelay = options.reconnectDelay || 5000;
    this.autoReconnect = options.autoReconnect !== false;
    this.rigId = options.rigId || null;

    // State
    this.socket = null;
    this.connected = false;
    this.loggedIn = false;
    this.messageId = 1;
    this.pendingRequests = new Map();
    this.currentJob = null;
    this.jobId = null;
    this.keepaliveTimer = null;
    this.reconnectTimer = null;
    this.buffer = '';
    this.muted = false;  // Suppress logging when true

    // Statistics
    this.stats = {
      sharesAccepted: 0,
      sharesRejected: 0,
      jobsReceived: 0,
      lastShareTime: null,
      connectedAt: null,
      reconnects: 0
    };
  }

  /**
   * Parse pool URL
   *
   * Supports formats:
   * - stratum+tcp://host:port
   * - stratum+ssl://host:port
   * - host:port (defaults to tcp)
   */
  _parsePoolUrl(url) {
    if (!url) {
      throw new Error('Pool URL is required');
    }

    let ssl = false;
    let host, port;

    if (url.startsWith('stratum+ssl://')) {
      ssl = true;
      url = url.replace('stratum+ssl://', '');
    } else if (url.startsWith('stratum+tcp://')) {
      url = url.replace('stratum+tcp://', '');
    } else if (url.startsWith('stratum://')) {
      url = url.replace('stratum://', '');
    }

    const parts = url.split(':');
    host = parts[0];
    port = parseInt(parts[1]) || (ssl ? 443 : 3333);

    return { host, port, ssl };
  }

  /**
   * Connect to the pool
   *
   * @returns {Promise<void>}
   */
  connect() {
    return new Promise((resolve, reject) => {
      if (this.connected) {
        resolve();
        return;
      }

      this._log(`Connecting to ${this.ssl ? 'ssl' : 'tcp'}://${this.host}:${this.port}...`);

      // Create socket
      if (this.ssl) {
        this.socket = tlsConnect({
          host: this.host,
          port: this.port,
          rejectUnauthorized: false // Many pools use self-signed certs
        });
      } else {
        this.socket = createConnection({
          host: this.host,
          port: this.port
        });
      }

      // Socket event handlers
      this.socket.once('connect', () => {
        this.connected = true;
        this.stats.connectedAt = Date.now();
        this._log('Connected to pool');
        this.emit('connected');

        // Start keepalive
        this._startKeepalive();

        // Login
        this._login()
          .then(resolve)
          .catch(reject);
      });

      this.socket.on('data', (data) => {
        this._onData(data);
      });

      this.socket.on('error', (err) => {
        this._log(`Socket error: ${err.message}`, 'error');
        this.emit('error', err);
        if (!this.connected) {
          reject(err);
        }
      });

      this.socket.on('close', () => {
        this._onDisconnect();
      });

      this.socket.on('end', () => {
        this._onDisconnect();
      });

      // Connection timeout
      this.socket.setTimeout(10000, () => {
        if (!this.connected) {
          this.socket.destroy();
          reject(new Error('Connection timeout'));
        }
      });
    });
  }

  /**
   * Disconnect from pool
   */
  disconnect() {
    this.autoReconnect = false;
    this._stopKeepalive();

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }

    this.connected = false;
    this.loggedIn = false;
    this._log('Disconnected from pool');
    this.emit('disconnected');
  }

  /**
   * Submit a share
   *
   * @param {string} nonce - Nonce that produces valid hash (hex string)
   * @param {string} result - Hash result (hex string)
   * @returns {Promise<boolean>} - True if accepted
   */
  async submitShare(nonce, result) {
    if (!this.loggedIn) {
      throw new Error('Not logged in to pool');
    }

    const params = {
      id: this.jobId,
      job_id: this.currentJob?.job_id,
      nonce: nonce,
      result: result
    };

    if (this.rigId) {
      params.rig_id = this.rigId;
    }

    try {
      const response = await this._sendRequest(METHOD.SUBMIT, params);

      if (response.status === 'OK' || response.result?.status === 'OK') {
        this.stats.sharesAccepted++;
        this.stats.lastShareTime = Date.now();
        this._log(`Share accepted! (${this.stats.sharesAccepted} total)`);
        this.emit('accepted', { nonce, result });
        return true;
      } else {
        this.stats.sharesRejected++;
        const reason = response.error || response.result?.error || 'Unknown reason';
        this._log(`Share rejected: ${reason}`, 'warn');
        this.emit('rejected', { nonce, result, reason });
        return false;
      }
    } catch (err) {
      this.stats.sharesRejected++;
      this._log(`Share submission error: ${err.message}`, 'error');
      this.emit('rejected', { nonce, result, reason: err.message });
      return false;
    }
  }

  /**
   * Get current job
   *
   * @returns {Object|null}
   */
  getJob() {
    return this.currentJob;
  }

  /**
   * Get statistics
   *
   * @returns {Object}
   */
  getStats() {
    return {
      ...this.stats,
      connected: this.connected,
      loggedIn: this.loggedIn,
      uptime: this.stats.connectedAt
        ? Date.now() - this.stats.connectedAt
        : 0
    };
  }

  // === Private methods ===

  _log(message, level = 'info') {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [Stratum] ${message}`;
    this.emit('log', { level, message: logMessage });

    // Skip console output when silent or muted (unless error)
    if ((this.silent || this.muted) && level !== 'error') {
      return;
    }

    if (level === 'error') {
      console.error(logMessage);
    } else if (level === 'warn') {
      console.warn(logMessage);
    } else {
      console.log(logMessage);
    }
  }

  /**
   * Mute logging (suppress non-error messages)
   */
  mute() {
    this.muted = true;
  }

  /**
   * Unmute logging
   */
  unmute() {
    this.muted = false;
  }

  async _login() {
    const params = {
      login: this.wallet,
      pass: this.password,
      agent: `salvium-js/1.0.1`
    };

    if (this.rigId) {
      params.rigid = this.rigId;
    }

    try {
      const response = await this._sendRequest(METHOD.LOGIN, params);

      if (response.error) {
        throw new Error(response.error.message || 'Login failed');
      }

      this.loggedIn = true;
      this.jobId = response.result?.id || response.id;

      // First job often comes with login response
      if (response.result?.job) {
        this._handleJob(response.result.job);
      }

      this._log(`Logged in as ${this.worker}`);
      return true;
    } catch (err) {
      this._log(`Login failed: ${err.message}`, 'error');
      throw err;
    }
  }

  _sendRequest(method, params) {
    return new Promise((resolve, reject) => {
      const id = this.messageId++;

      const request = {
        id,
        jsonrpc: '2.0',
        method,
        params
      };

      this.pendingRequests.set(id, { resolve, reject });

      const message = JSON.stringify(request) + '\n';
      this.socket.write(message);

      // Timeout for response
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error('Request timeout'));
        }
      }, 30000);
    });
  }

  _onData(data) {
    this.buffer += data.toString();

    // Process complete messages (newline-delimited JSON)
    let newlineIndex;
    while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.substring(0, newlineIndex);
      this.buffer = this.buffer.substring(newlineIndex + 1);

      if (line.trim()) {
        try {
          const message = JSON.parse(line);
          this._handleMessage(message);
        } catch (err) {
          this._log(`Failed to parse message: ${line}`, 'error');
        }
      }
    }
  }

  _handleMessage(message) {
    // Response to a request
    if (message.id && this.pendingRequests.has(message.id)) {
      const { resolve } = this.pendingRequests.get(message.id);
      this.pendingRequests.delete(message.id);
      resolve(message);
      return;
    }

    // Server notification (new job, etc.)
    if (message.method === METHOD.JOB || message.method === 'job') {
      this._handleJob(message.params);
    } else if (message.params?.job) {
      // Some pools send job in params
      this._handleJob(message.params.job);
    }
  }

  _handleJob(job) {
    if (!job || !job.blob) {
      this._log('Received invalid job', 'warn');
      return;
    }

    this.currentJob = {
      job_id: job.job_id || job.id,
      blob: job.blob,
      target: job.target,
      height: job.height,
      seed_hash: job.seed_hash,
      algo: job.algo || 'rx/0'
    };

    this.stats.jobsReceived++;
    this._log(`New job: height=${job.height}, target=${job.target}`);
    this.emit('job', this.currentJob);
  }

  _startKeepalive() {
    this._stopKeepalive();

    this.keepaliveTimer = setInterval(() => {
      if (this.connected && this.loggedIn) {
        this._sendRequest(METHOD.KEEPALIVE, { id: this.jobId })
          .catch(() => {}); // Ignore keepalive errors
      }
    }, this.keepaliveInterval);
  }

  _stopKeepalive() {
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer);
      this.keepaliveTimer = null;
    }
  }

  _onDisconnect() {
    const wasConnected = this.connected;
    this.connected = false;
    this.loggedIn = false;
    this._stopKeepalive();

    if (wasConnected) {
      this._log('Disconnected from pool');
      this.emit('disconnected');

      if (this.autoReconnect) {
        this._scheduleReconnect();
      }
    }
  }

  _scheduleReconnect() {
    if (this.reconnectTimer) return;

    this._log(`Reconnecting in ${this.reconnectDelay}ms...`);

    this.reconnectTimer = setTimeout(async () => {
      this.reconnectTimer = null;
      this.stats.reconnects++;

      try {
        await this.connect();
      } catch (err) {
        this._log(`Reconnection failed: ${err.message}`, 'error');
        if (this.autoReconnect) {
          this._scheduleReconnect();
        }
      }
    }, this.reconnectDelay);
  }
}

export default StratumClient;
