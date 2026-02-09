#!/usr/bin/env bun
/**
 * Solo Miner — mines blocks against a daemon using WASM or Rust RandomX.
 *
 * Supports:
 *   - WASM JIT: multi-threaded via worker pool (light mode)
 *   - Rust native: spawns salvium-miner binary (light or full mode)
 *
 * Usage:
 *   bun test/solo-miner.js --backend <wasm|rust> --blocks <N> --address <ADDR> [options]
 *
 * Options:
 *   --backend, -b   wasm|rust (default: wasm)
 *   --mode, -m      light|full (default: light)
 *   --blocks, -n    Number of blocks to mine (default: 5)
 *   --address, -a   Wallet address for mining rewards (required)
 *   --daemon, -d    Daemon URL (default: http://web.whiskymine.io:29081)
 *   --threads, -t   Number of mining threads (default: 4, max: 4)
 */

import { Worker } from 'worker_threads';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { DaemonRPC } from '../src/rpc/daemon.js';
import {
  findNonceOffset, formatBlockForSubmission, formatHashrate, formatDuration
} from '../src/mining.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const RUST_MINER_PATH = join(__dirname, '../crates/salvium-miner/target/release/salvium-miner');

// ─── Parse CLI args ──────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = {
    backend: 'wasm',
    mode: 'light',
    blocks: 5,
    address: '',
    daemon: 'http://web.whiskymine.io:29081',
    threads: 4,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--backend': case '-b': opts.backend = args[++i]; break;
      case '--mode': case '-m': opts.mode = args[++i]; break;
      case '--blocks': case '-n': opts.blocks = parseInt(args[++i], 10); break;
      case '--address': case '-a': opts.address = args[++i]; break;
      case '--daemon': case '-d': opts.daemon = args[++i]; break;
      case '--threads': case '-t': opts.threads = Math.min(4, parseInt(args[++i], 10)); break;
      case '--help': case '-h':
        console.log('Usage: bun test/solo-miner.js --backend <js|wasm|rust> --blocks <N> --address <ADDR> [--mode light|full] [--threads T] [--daemon URL]');
        process.exit(0);
    }
  }

  if (!opts.address) {
    console.error('Error: --address is required');
    process.exit(1);
  }
  if (!['wasm', 'rust'].includes(opts.backend)) {
    console.error('Error: --backend must be "wasm" or "rust"');
    process.exit(1);
  }
  if (!['light', 'full'].includes(opts.mode)) {
    console.error('Error: --mode must be "light" or "full"');
    process.exit(1);
  }

  // WASM full mode not implemented
  if (opts.backend === 'wasm' && opts.mode === 'full') {
    console.log('Note: WASM full mode (2GB dataset) not yet implemented, using light mode.');
    opts.mode = 'light';
  }

  return opts;
}

// ─── Hex helpers ─────────────────────────────────────────────────────────────

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// ─── Worker Pool Mining (WASM-JIT backend) ───────────────────────────────────

class WorkerMinerPool {
  /**
   * @param {number} numThreads
   */
  constructor(numThreads) {
    this.numThreads = numThreads;
    this.workers = [];
    this.ready = false;
    this.workerPath = new URL('../src/randomx/randomx-worker.js', import.meta.url).pathname;
    this._handlers = [];  // Track active handlers for cleanup
    this._jobCounter = 0;
  }

  async init(seedHash) {
    const seedBytes = hexToBytes(seedHash);

    // Terminate old workers if re-initializing
    this.terminate();

    const initPromises = [];
    for (let i = 0; i < this.numThreads; i++) {
      const worker = new Worker(this.workerPath);
      this.workers.push(worker);

      const p = new Promise((resolve, reject) => {
        const handler = (msg) => {
          if (msg.type === 'ready') {
            worker.off('message', handler);
            resolve();
          } else if (msg.type === 'error') {
            reject(new Error(msg.error));
          }
        };
        worker.on('message', handler);
        worker.on('error', reject);
      });

      worker.postMessage({ type: 'init', id: i, key: seedBytes });
      initPromises.push(p);
    }

    await Promise.all(initPromises);
    this.ready = true;

    console.log(`  ${this.numThreads} WASM-JIT workers initialized (${this.numThreads * 256}MB total)`);
  }

  /**
   * Mine a block: each worker searches a different nonce range.
   * Workers use async chunked mining, so sending a new mine message
   * cancels the previous one without needing to kill/respawn workers.
   *
   * Uses jobId to prevent stale messages from previous blocks being
   * accepted by the current block's handler.
   *
   * Returns { nonce, hash, hashCount } on success.
   */
  async mineBlock(hashingBlob, nonceOffset, difficulty) {
    const RANGE_PER_WORKER = 0x10000000; // ~268M nonces per worker
    const baseNonce = Math.floor(Math.random() * 0x40000000);
    const jobId = ++this._jobCounter;

    // Clean up any leftover handlers from previous blocks
    for (const { worker, handler } of this._handlers) {
      worker.off('message', handler);
    }
    this._handlers = [];

    // Cancel any in-flight mining from previous blocks
    for (const w of this.workers) {
      w.postMessage({ type: 'cancel' });
    }

    return new Promise((resolve, reject) => {
      let found = false;
      let completed = 0;
      let totalHashCount = 0;
      const workerHashes = new Array(this.workers.length).fill(0);
      const mineStart = Date.now();

      for (let i = 0; i < this.workers.length; i++) {
        const worker = this.workers[i];
        const startNonce = (baseNonce + i * RANGE_PER_WORKER) >>> 0;
        const endNonce = (startNonce + RANGE_PER_WORKER) >>> 0;

        const handler = (msg) => {
          // Ignore messages from previous jobs
          if (msg.jobId !== undefined && msg.jobId !== jobId) return;
          if (found) return;

          if (msg.type === 'found') {
            found = true;

            // Cancel all workers and remove all handlers
            for (const w of this.workers) {
              w.postMessage({ type: 'cancel' });
            }
            for (const h of this._handlers) {
              h.worker.off('message', h.handler);
            }
            this._handlers = [];

            totalHashCount += msg.hashCount || 0;
            resolve({ nonce: msg.nonce, hash: msg.hash, hashCount: totalHashCount });
          } else if (msg.type === 'progress') {
            workerHashes[i] = msg.hashCount || 0;
            const runningTotal = workerHashes.reduce((a, b) => a + b, 0);
            const elapsed = (Date.now() - mineStart) / 1000;
            if (elapsed > 0.5) {
              const hr = runningTotal / elapsed;
              process.stderr.write(`\r  ${runningTotal} hashes, ${formatHashrate(hr)}...`);
            }
          } else if (msg.type === 'notfound') {
            completed++;
            totalHashCount += msg.hashCount || 0;
            if (completed === this.workers.length && !found) {
              for (const h of this._handlers) {
                h.worker.off('message', h.handler);
              }
              this._handlers = [];
              reject(new Error('No nonce found in range'));
            }
          } else if (msg.type === 'error') {
            if (!found) {
              for (const h of this._handlers) {
                h.worker.off('message', h.handler);
              }
              this._handlers = [];
              reject(new Error(msg.error));
            }
          }
        };

        worker.on('message', handler);
        this._handlers.push({ worker, handler });

        worker.postMessage({
          type: 'mine',
          id: i,
          jobId,
          input: {
            template: Array.from(hashingBlob),
            nonceOffset,
            difficulty: Number(difficulty),
            startNonce,
            endNonce,
          }
        });
      }
    });
  }

  terminate() {
    for (const w of this.workers) w.terminate();
    this.workers = [];
    this.ready = false;
  }
}

// ─── Rust Native Mining (child process) ─────────────────────────────────────

class RustMiner {
  constructor(opts) {
    this.daemon = opts.daemon;
    this.address = opts.address;
    this.threads = opts.threads;
    this.light = opts.mode === 'light';
    this.proc = null;
  }

  async init(_seedHash) {
    const { access } = await import('fs/promises');
    try {
      await access(RUST_MINER_PATH);
    } catch {
      throw new Error(`Rust miner binary not found at ${RUST_MINER_PATH}. Run: cargo build --release -p salvium-miner`);
    }
    const modeStr = this.light ? 'light (256MB/thread)' : 'full (2GB shared dataset)';
    console.log(`  Rust miner ready: ${this.threads} threads, ${modeStr}`);
  }

  async mineNBlocks(targetBlocks) {
    const args = [
      '--daemon', this.daemon,
      '--wallet', this.address,
      '--threads', String(this.threads),
    ];
    if (this.light) args.push('--light');

    return new Promise((resolve, reject) => {
      const results = [];
      let totalHashes = 0;
      const startTime = Date.now();
      let stderrBuffer = '';

      this.proc = spawn(RUST_MINER_PATH, args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      this.proc.on('error', (err) => {
        reject(new Error(`Failed to spawn Rust miner: ${err.message}`));
      });

      this.proc.stderr.on('data', (chunk) => {
        const text = chunk.toString();
        stderrBuffer += text;

        const lines = stderrBuffer.split('\n');
        stderrBuffer = lines.pop();

        for (const line of lines) {
          const trimmed = line.trim();

          const foundMatch = trimmed.match(/BLOCK FOUND at height (\d+).*nonce=(\d+)/);
          if (foundMatch) {
            results.push({
              height: parseInt(foundMatch[1], 10),
              nonce: parseInt(foundMatch[2], 10),
              elapsed: 0,
              status: 'pending',
            });
          }

          if (trimmed.includes('Block accepted!')) {
            const last = results[results.length - 1];
            if (last && last.status === 'pending') {
              last.status = 'accepted';
              last.elapsed = (Date.now() - startTime) / 1000;
              console.log(`  Block ${last.height} ACCEPTED (nonce=${last.nonce})`);
            }
            if (results.filter(r => r.status === 'accepted').length >= targetBlocks) {
              this.proc.kill('SIGTERM');
            }
          }

          if (trimmed.includes('Block rejected:')) {
            const last = results[results.length - 1];
            if (last && last.status === 'pending') {
              last.status = 'rejected';
              last.elapsed = (Date.now() - startTime) / 1000;
              console.log(`  Block ${last.height} REJECTED: ${trimmed}`);
            }
          }

          const statsMatch = trimmed.match(/Hashes:\s*(\d+)/);
          if (statsMatch) totalHashes = parseInt(statsMatch[1], 10);

          const hrMatch = trimmed.match(/\[H=\d+\]\s+([\d.]+ [KMG]?H\/s)/);
          if (hrMatch) {
            process.stderr.write(`\r  Rust: ${hrMatch[1]}, ${results.filter(r => r.status === 'accepted').length}/${targetBlocks} blocks...`);
          }
        }
      });

      this.proc.stdout.on('data', () => {});

      this.proc.on('close', () => {
        process.stderr.write('\r' + ' '.repeat(80) + '\r');
        const totalElapsed = (Date.now() - startTime) / 1000;
        for (const r of results) {
          if (r.status === 'pending') r.status = 'error';
        }
        resolve({ results, totalHashes, totalElapsed });
      });
    });
  }

  terminate() {
    if (this.proc && !this.proc.killed) {
      this.proc.kill('SIGTERM');
    }
  }
}

// ─── Main mining loop (WASM backend) ──────────────────────────────────────────

async function mineBlocksWorkerPool(opts) {
  const daemon = new DaemonRPC({ url: opts.daemon });

  const info = await daemon.getInfo();
  const height = info.result?.height || info.height;
  const label = `WASM-JIT light (${opts.threads} threads)`;

  console.log(`\nSolo Miner — ${label}`);
  console.log(`Daemon: ${opts.daemon} (height ${height})`);
  console.log(`Target: ${opts.blocks} blocks → ${opts.address.slice(0, 20)}...`);
  console.log();

  const tmpl0 = await daemon.getBlockTemplate(opts.address, 8);
  let currentSeedHash = tmpl0.result.seed_hash;

  const miner = new WorkerMinerPool(opts.threads);

  console.log(`Initializing RandomX (seed: ${currentSeedHash.slice(0, 16)}...)...`);
  await miner.init(currentSeedHash);
  console.log();

  const results = [];
  let totalHashes = 0;
  const overallStart = Date.now();

  for (let blockNum = 0; blockNum < opts.blocks; blockNum++) {
    const tmplResp = await daemon.getBlockTemplate(opts.address, 8);
    const tmpl = tmplResp.result;

    if (tmpl.seed_hash !== currentSeedHash) {
      console.log(`  Seed hash changed, re-initializing...`);
      await miner.init(tmpl.seed_hash);
      currentSeedHash = tmpl.seed_hash;
    }

    const difficulty = BigInt(tmpl.difficulty);
    const tmplHeight = tmpl.height;
    const hashingBlob = hexToBytes(tmpl.blockhashing_blob);
    const templateBlob = hexToBytes(tmpl.blocktemplate_blob);
    const nonceOffset = findNonceOffset(hashingBlob);

    console.log(`[${blockNum + 1}/${opts.blocks}] Mining height ${tmplHeight} (diff ${difficulty})...`);
    const blockStart = Date.now();

    try {
      const result = await miner.mineBlock(hashingBlob, nonceOffset, difficulty);
      const blockElapsed = (Date.now() - blockStart) / 1000;
      const hashCount = result.hashCount || Math.round(Number(difficulty) * 0.5);
      const hr = hashCount / blockElapsed;

      process.stderr.write('\r' + ' '.repeat(80) + '\r');
      console.log(`  FOUND! nonce=${result.nonce}, ${hashCount} hashes, time=${blockElapsed.toFixed(1)}s, ~${formatHashrate(hr)}`);

      // Submit block
      const templateNonceOffset = findNonceOffset(templateBlob);
      const blockHex = formatBlockForSubmission(templateBlob, result.nonce, templateNonceOffset);

      if (nonceOffset !== templateNonceOffset) {
        console.log(`  WARNING: nonce offset mismatch! hashing=${nonceOffset} template=${templateNonceOffset}`);
      }

      const submitResp = await daemon.submitBlock([blockHex]);
      if (submitResp.result?.status === 'OK' || submitResp.error === undefined) {
        console.log(`  Block ${tmplHeight} ACCEPTED`);
        results.push({ height: tmplHeight, nonce: result.nonce, elapsed: blockElapsed, status: 'accepted' });
      } else {
        console.log(`  Block ${tmplHeight} REJECTED: ${JSON.stringify(submitResp)}`);
        results.push({ height: tmplHeight, nonce: result.nonce, elapsed: blockElapsed, status: 'rejected' });
      }

      totalHashes += hashCount;
    } catch (err) {
      console.log(`  Mining error: ${err.message}`);
      results.push({ height: tmplHeight, nonce: 0, elapsed: 0, status: 'error' });
    }
  }

  miner.terminate();

  const totalElapsed = (Date.now() - overallStart) / 1000;
  return { results, totalHashes, totalElapsed };
}

// ─── Main mining loop (Rust backend) ─────────────────────────────────────────

async function mineBlocksRust(opts) {
  const daemon = new DaemonRPC({ url: opts.daemon });
  const info = await daemon.getInfo();
  const height = info.result?.height || info.height;
  const modeLabel = opts.mode === 'full' ? 'full (2GB dataset)' : 'light (256MB/thread)';
  const backendLabel = `Rust native ${modeLabel} (${opts.threads} threads)`;

  console.log(`\nSolo Miner — ${backendLabel}`);
  console.log(`Daemon: ${opts.daemon} (height ${height})`);
  console.log(`Target: ${opts.blocks} blocks → ${opts.address.slice(0, 20)}...`);
  console.log();

  const miner = new RustMiner(opts);
  await miner.init();
  console.log();

  console.log(`Mining ${opts.blocks} blocks with Rust native miner...`);
  const { results, totalHashes, totalElapsed } = await miner.mineNBlocks(opts.blocks);
  miner.terminate();

  return { results, totalHashes, totalElapsed };
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs();

  let summary;
  if (opts.backend === 'rust') {
    summary = await mineBlocksRust(opts);
  } else {
    summary = await mineBlocksWorkerPool(opts);
  }

  const { results, totalHashes, totalElapsed } = summary;
  const accepted = results.filter(r => r.status === 'accepted').length;
  const avgBlockTime = totalElapsed / Math.max(1, results.length);

  const backendLabel = opts.backend === 'rust'
    ? `Rust ${opts.mode} (${opts.threads} threads)`
    : `WASM-JIT light (${opts.threads} threads)`;

  console.log(`\n${'='.repeat(60)}`);
  console.log(`Solo Miner Summary — ${backendLabel}`);
  console.log(`${'='.repeat(60)}`);
  console.log(`Blocks: ${accepted}/${opts.blocks} accepted`);
  console.log(`Total time: ${formatDuration(totalElapsed)}`);
  console.log(`Avg time/block: ${formatDuration(avgBlockTime)}`);
  if (totalHashes > 0) {
    console.log(`Total hashes: ${totalHashes}`);
    console.log(`Avg hashrate: ${formatHashrate(totalHashes / totalElapsed)}`);
  }
  console.log();

  for (const r of results) {
    console.log(`  Height ${r.height}: ${r.status} (${r.elapsed.toFixed(1)}s)`);
  }

  // JSON output for programmatic use
  const jsonSummary = {
    backend: opts.backend,
    mode: opts.mode,
    threads: opts.threads,
    blocks: opts.blocks,
    accepted,
    rejected: results.filter(r => r.status === 'rejected').length,
    errors: results.filter(r => r.status === 'error').length,
    totalHashes,
    totalElapsed,
    avgBlockTime,
    results,
  };

  if (process.env.SOLO_MINER_LOG) {
    const { writeFile } = await import('fs/promises');
    await writeFile(process.env.SOLO_MINER_LOG, JSON.stringify(jsonSummary, null, 2));
    console.log(`\nLog written to ${process.env.SOLO_MINER_LOG}`);
  }

  if (accepted < opts.blocks) {
    console.error(`\nWARNING: ${opts.blocks - accepted} blocks were not accepted!`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
