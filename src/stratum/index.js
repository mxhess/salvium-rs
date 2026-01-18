/**
 * Stratum Mining Client
 *
 * Full-featured stratum mining client for Salvium/RandomX pools.
 * Supports stratum+tcp and stratum+ssl protocols.
 *
 * Features:
 * - Multi-threaded mining with worker threads
 * - Automatic reconnection
 * - Job management and share submission
 * - Statistics tracking (hashrate, shares, etc.)
 * - Light mode (256MB per thread) support
 */

export { StratumClient } from './client.js';
export { StratumMiner, createMiner, getAvailableCores } from './miner.js';
