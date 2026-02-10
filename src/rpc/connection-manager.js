/**
 * Connection Manager — Latency-Based Server Selection
 *
 * Manages multiple RPC server URLs. Races them on connect, picks the fastest,
 * monitors latency, and re-races when performance degrades or a server fails.
 *
 * Single URL = no overhead, just uses it directly.
 * Multiple URLs = race, pick fastest, failover on error, re-race on degradation.
 */

/**
 * Default seed nodes for each Salvium network.
 * Same hostnames, different ports per network.
 */
export const SEED_NODES = {
  mainnet: [
    'http://seed01.salvium.io:19081',
    'http://seed02.salvium.io:19081',
    'http://seed03.salvium.io:19081',
  ],
  testnet: [
    'http://seed01.salvium.io:29081',
    'http://seed02.salvium.io:29081',
    'http://seed03.salvium.io:29081',
  ],
  stagenet: [
    'http://seed01.salvium.io:39081',
    'http://seed02.salvium.io:39081',
    'http://seed03.salvium.io:39081',
  ],
};

/**
 * @typedef {Object} ConnectionManagerOptions
 * @property {string[]} urls - Server URLs to race
 * @property {number} [raceTimeout=5000] - Timeout per server during race (ms)
 * @property {number} [degradationFactor=2] - Re-race when latency > baseline * factor
 * @property {number} [raceInterval=0] - Periodic re-race interval (ms), 0 = disabled
 * @property {function} [onSwitch] - Callback when active server changes (oldUrl, newUrl)
 */

export class ConnectionManager {
  /**
   * @param {ConnectionManagerOptions} options
   */
  constructor(options = {}) {
    this.urls = options.urls || [];
    this.raceTimeout = options.raceTimeout || 5000;
    this.degradationFactor = options.degradationFactor || 2;
    this.raceInterval = options.raceInterval || 0;
    this.onSwitch = options.onSwitch || null;

    this.activeUrl = this.urls[0] || null;
    this.baselineLatency = null;
    this._latencies = new Map(); // url -> last latency ms
    this._ranked = [...this.urls]; // sorted by latency after each race
    this._racing = false;
    this._raceTimer = null;
    this._initialized = false;
  }

  /**
   * Whether this manager has multiple servers to race.
   */
  get isMultiServer() {
    return this.urls.length > 1;
  }

  /**
   * Race all servers, pick the fastest responding one.
   * Sets activeUrl and baselineLatency.
   * @returns {Promise<string>} The winning URL
   */
  async race() {
    if (this._racing) return this.activeUrl;
    if (this.urls.length === 0) return this.activeUrl;
    if (this.urls.length === 1) {
      this.activeUrl = this.urls[0];
      this._initialized = true;
      return this.activeUrl;
    }

    this._racing = true;

    try {
      const results = await Promise.all(
        this.urls.map(async (url) => {
          const start = Date.now();

          try {
            const resp = await Promise.race([
              fetch(`${url.replace(/\/+$/, '')}/get_info`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: '{}',
              }),
              new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Race timeout')), this.raceTimeout)
              ),
            ]);

            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            await resp.json(); // consume body

            const latency = Date.now() - start;
            this._latencies.set(url, latency);
            return { status: 'fulfilled', value: { url, latency } };
          } catch (e) {
            this._latencies.set(url, Infinity);
            return { status: 'rejected', reason: e };
          }
        })
      );

      // Pick the fastest successful result
      let best = null;
      for (const result of results) {
        if (result.status === 'fulfilled') {
          if (!best || result.value.latency < best.latency) {
            best = result.value;
          }
        }
      }

      // Sort URLs by latency (fastest first) for failover ordering
      this._ranked = [...this.urls].sort((a, b) => {
        const la = this._latencies.get(a) ?? Infinity;
        const lb = this._latencies.get(b) ?? Infinity;
        return la - lb;
      });

      if (best) {
        const oldUrl = this.activeUrl;
        this.activeUrl = best.url;
        this.baselineLatency = best.latency;
        this._initialized = true;

        if (oldUrl && oldUrl !== best.url && this.onSwitch) {
          this.onSwitch(oldUrl, best.url);
        }
      }

      // Set up periodic re-race
      if (this.raceInterval > 0 && !this._raceTimer) {
        this._raceTimer = setInterval(() => this.race(), this.raceInterval);
        // Don't keep process alive just for re-racing
        if (this._raceTimer.unref) this._raceTimer.unref();
      }
    } finally {
      this._racing = false;
    }

    return this.activeUrl;
  }

  /**
   * Ensure connection manager is initialized (first race completed).
   * @returns {Promise<string>} Active URL
   */
  async ensureConnected() {
    if (!this._initialized) {
      return this.race();
    }
    return this.activeUrl;
  }

  /**
   * Record a successful response latency. Triggers re-race if degraded.
   * @param {number} latencyMs - Response time in milliseconds
   */
  recordLatency(latencyMs) {
    if (!this.isMultiServer || !this.baselineLatency) return;

    this._latencies.set(this.activeUrl, latencyMs);

    // Check for degradation
    if (latencyMs > this.baselineLatency * this.degradationFactor) {
      // Fire re-race in background (don't await)
      this.race();
    }
  }

  /**
   * Report a failure on the active server. Switch to next best, or re-race.
   * @returns {Promise<string|null>} New active URL, or null if all failed
   */
  async handleFailure() {
    if (!this.isMultiServer) return this.activeUrl;

    // Mark current as failed
    this._latencies.set(this.activeUrl, Infinity);

    // Walk the ranked list (sorted by latency at last race) for next best
    const ranked = this._ranked || this.urls;
    for (const url of ranked) {
      if (url === this.activeUrl) continue;
      const lat = this._latencies.get(url) ?? 0;
      if (lat < Infinity) {
        const oldUrl = this.activeUrl;
        this.activeUrl = url;
        if (this.onSwitch) this.onSwitch(oldUrl, url);
        return url;
      }
    }

    // All servers have failed — re-race
    return this.race();
  }

  /**
   * Stop periodic re-racing and clean up.
   */
  destroy() {
    if (this._raceTimer) {
      clearInterval(this._raceTimer);
      this._raceTimer = null;
    }
  }
}
