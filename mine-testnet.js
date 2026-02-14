#!/usr/bin/env bun
/**
 * Local RandomX miner against remote Salvium daemon
 *
 * Uses our WASM RandomX (full mode, 2GB dataset) + daemon RPC.
 * Single-threaded but with full dataset for maximum per-thread hashrate.
 *
 * Usage:
 *   bun mine-testnet.js [mode]
 *   mode: "full" (default, 2GB dataset, ~30-50 H/s) or "light" (256MB, ~10 H/s)
 */

import { DaemonRPC } from './src/rpc/daemon.js';
import { RandomXContext } from './src/randomx/index.js';
import { RandomXFullMode } from './src/randomx/full-mode.js';
import {
  parseBlockTemplate,
  findNonceOffset,
  setNonce,
  checkHash,
  formatBlockForSubmission,
  formatHashrate,
} from './src/mining.js';
import { hexToBytes, bytesToHex } from './src/address.js';

// ============================================================================
// Configuration
// ============================================================================

const DAEMON_URL = process.env.DAEMON_URL || 'http://node12.whiskymine.io:29081';
const WALLET_FILE = process.env.WALLET_FILE || `${process.env.HOME}/testnet-wallet/wallet.json`;
const MODE = process.argv[2] || 'full';
const TEMPLATE_REFRESH_MS = 5000;

// ============================================================================
// Main
// ============================================================================

const wallet = JSON.parse(await Bun.file(WALLET_FILE).text());
const daemon = new DaemonRPC({ url: DAEMON_URL });

console.log('Salvium Local RandomX Miner');
console.log('===========================');
console.log(`Daemon:  ${DAEMON_URL}`);
console.log(`Wallet:  ${wallet.address.slice(0, 20)}...`);
console.log(`Mode:    ${MODE} (${MODE === 'full' ? '2GB dataset' : '256MB cache'})`);
console.log('');

// Verify daemon
const info = await daemon.getInfo();
if (!info.success) {
  console.error('Cannot connect to daemon');
  process.exit(1);
}
console.log(`Daemon height: ${info.result.height}, difficulty: ${info.result.difficulty}`);
console.log('');

// Get block template
let template = await daemon.getBlockTemplate(wallet.address, 8);
if (!template.success) {
  console.error('Failed to get block template:', template.error);
  process.exit(1);
}

let parsed = parseBlockTemplate(template.result);
console.log(`Template: height=${parsed.height}, difficulty=${parsed.difficulty}`);

// Initialize RandomX
const seedBytes = parsed.seedHash ? hexToBytes(parsed.seedHash) : new Uint8Array(32);
let rx;

if (MODE === 'full') {
  console.log('Initializing RandomX full mode (256MB cache + 2GB dataset)...');
  console.log('This will take 30-60 seconds...');
  rx = new RandomXFullMode();
  await rx.init(seedBytes, {
    onProgress: (pct, phase) => {
      process.stdout.write(`\r  ${phase}: ${pct}%   `);
    }
  });
  console.log('');
} else {
  console.log('Initializing RandomX light mode (256MB cache)...');
  rx = new RandomXContext();
  await rx.init(seedBytes);
}

console.log('RandomX ready.\n');

// ============================================================================
// Mining loop
// ============================================================================

let totalHashes = 0;
let blocksFound = 0;
const startTime = Date.now();
let lastTemplateFetch = Date.now();
let lastStatsPrint = Date.now();
let currentSeedHash = parsed.seedHash;
let running = true;

process.on('SIGINT', () => {
  running = false;
  console.log('\nShutting down...');
  const elapsed = (Date.now() - startTime) / 1000;
  console.log(`Total hashes: ${totalHashes.toLocaleString()}`);
  console.log(`Blocks found: ${blocksFound}`);
  console.log(`Avg hashrate: ${formatHashrate(totalHashes / elapsed)}`);
  process.exit(0);
});

console.log('Mining started. Press Ctrl+C to stop.\n');

while (running) {
  const hashingBlob = parsed.blockhashingBytes;
  const nonceOffset = findNonceOffset(hashingBlob);
  const difficulty = parsed.difficulty;
  const templateBlob = parsed.blocktemplateBytes;

  // Random starting nonce
  const startNonce = Math.floor(Math.random() * 0xFFFFFFFF);

  for (let i = 0; i < 256 && running; i++) {
    const nonce = (startNonce + i) & 0xFFFFFFFF;
    const blob = setNonce(hashingBlob, nonce, nonceOffset);
    const hash = rx.hash(blob);
    totalHashes++;

    if (checkHash(hash, difficulty)) {
      const blockHex = formatBlockForSubmission(templateBlob, nonce,
        findNonceOffset(templateBlob));

      console.log(`\n*** BLOCK FOUND at height ${parsed.height}! nonce=${nonce} ***`);

      const submitResult = await daemon.submitBlock([blockHex]);
      if (submitResult.success) {
        blocksFound++;
        console.log(`Block accepted! Total: ${blocksFound}`);
      } else {
        console.log(`Rejected: ${JSON.stringify(submitResult.error || submitResult.result)}`);
      }

      // New template immediately
      lastTemplateFetch = 0;
      break;
    }
  }

  // Refresh template
  const now = Date.now();
  if (now - lastTemplateFetch > TEMPLATE_REFRESH_MS) {
    try {
      const newTemplate = await daemon.getBlockTemplate(wallet.address, 8);
      if (newTemplate.success) {
        const newParsed = parseBlockTemplate(newTemplate.result);
        if (newParsed.seedHash !== currentSeedHash) {
          console.log(`\nSeed changed, re-initializing RandomX...`);
          if (MODE === 'full') {
            await rx.init(hexToBytes(newParsed.seedHash), {});
          } else {
            await rx.init(hexToBytes(newParsed.seedHash));
          }
          currentSeedHash = newParsed.seedHash;
        }
        parsed = newParsed;
      }
      lastTemplateFetch = now;
    } catch (e) {
      // Keep mining
    }
  }

  // Stats every 10s
  if (now - lastStatsPrint > 10000) {
    const elapsed = (now - startTime) / 1000;
    const hr = totalHashes / elapsed;
    const estBlockTime = Number(parsed.difficulty) / hr;
    process.stdout.write(
      `\r[H=${parsed.height}] ${formatHashrate(hr)} | ` +
      `Hashes: ${totalHashes.toLocaleString()} | ` +
      `Blocks: ${blocksFound} | ` +
      `Diff: ${parsed.difficulty} | ` +
      `Est: ${isFinite(estBlockTime) ? estBlockTime.toFixed(0) + 's' : '...'}   `
    );
    lastStatsPrint = now;
  }
}
