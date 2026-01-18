#!/usr/bin/env node
/**
 * Salvium JS Miner - CLI Tool
 *
 * Usage:
 *   bun run bin/miner.js --pool stratum+tcp://pool.example.com:3333 --wallet SAL... --worker myrig
 *
 * Options:
 *   --pool, -p      Pool URL (stratum+tcp:// or stratum+ssl://)
 *   --wallet, -w    Wallet address
 *   --worker, -n    Worker/rig name (default: salvium-js)
 *   --password      Pool password (default: x)
 *   --threads, -t   Number of threads (default: CPU cores - 1)
 *   --mode, -m      Mining mode: light (256MB) or full (2GB WASM VM)
 *   --help, -h      Show help
 */

import { StratumMiner, getAvailableCores } from '../src/index.js';
import { RandomXFullMode, RANDOMX_DATASET_SIZE } from '../src/randomx/full-mode.js';

// ANSI colors
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  red: '\x1b[31m'
};

function printBanner() {
  console.log(`
${colors.cyan}╔═════════════════════════════════════════════════════════════╗
║                                                             ║
║   ${colors.bright}███████╗ █████╗ ██╗    ██╗   ██╗██╗██╗   ██╗███╗   ███╗${colors.reset}${colors.cyan}   ║
║   ${colors.bright}██╔════╝██╔══██╗██║    ██║   ██║██║██║   ██║████╗ ████║${colors.reset}${colors.cyan}   ║
║   ${colors.bright}███████╗███████║██║    ██║   ██║██║██║   ██║██╔████╔██║${colors.reset}${colors.cyan}   ║
║   ${colors.bright}╚════██║██╔══██║██║    ╚██╗ ██╔╝██║██║   ██║██║╚██╔╝██║${colors.reset}${colors.cyan}   ║
║   ${colors.bright}███████║██║  ██║███████╗╚████╔╝ ██║╚██████╔╝██║ ╚═╝ ██║${colors.reset}${colors.cyan}   ║
║   ${colors.bright}╚══════╝╚═╝  ╚═╝╚══════╝ ╚═══╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝${colors.reset}${colors.cyan}   ║
║                                                             ║
║              ${colors.yellow}JavaScript RandomX Miner${colors.cyan}                       ║
║                     v1.0.1                                  ║
╚═════════════════════════════════════════════════════════════╝${colors.reset}
`);
}

function printHelp() {
  console.log(`
${colors.bright}Usage:${colors.reset}
  bun run bin/miner.js [options]

${colors.bright}Required:${colors.reset}
  --pool, -p      Pool URL (stratum+tcp://host:port or stratum+ssl://host:port)
  --wallet, -w    Your Salvium wallet address

${colors.bright}Optional:${colors.reset}
  --worker, -n    Worker/rig name (default: salvium-js)
  --password      Pool password (default: x)
  --threads, -t   Number of mining threads (default: ${getAvailableCores() - 1})
  --mode, -m      Mining mode: light or full (default: light)
  --help, -h      Show this help message

${colors.bright}Mining Modes:${colors.reset}
  light           Each thread uses 256MB RAM for RandomX cache
                  Typical hashrate: ~10-15 H/s per thread

  full            Pre-computes 2GB dataset (shared across all threads)
                  Uses AssemblyScript WASM VM for ~40-50 H/s per thread
                  Requires 2.3GB RAM, dataset generation takes ~30-60 seconds

${colors.bright}Examples:${colors.reset}
  bun run bin/miner.js -p stratum+tcp://pool.salvium.io:3333 -w SAL1abc...xyz
  bun run bin/miner.js -p stratum+ssl://pool.salvium.io:443 -w SAL1abc...xyz -t 4
  bun run bin/miner.js -p stratum+tcp://pool.salvium.io:3333 -w SAL1abc...xyz -m full
`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  const options = {
    pool: null,
    wallet: null,
    worker: 'salvium-js',
    password: 'x',
    threads: Math.max(1, getAvailableCores() - 1),
    mode: 'light'  // 'light' or 'full'
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const next = args[i + 1];

    switch (arg) {
      case '--pool':
      case '-p':
        options.pool = next;
        i++;
        break;
      case '--wallet':
      case '-w':
        options.wallet = next;
        i++;
        break;
      case '--worker':
      case '-n':
        options.worker = next;
        i++;
        break;
      case '--password':
        options.password = next;
        i++;
        break;
      case '--threads':
      case '-t':
        options.threads = parseInt(next) || options.threads;
        i++;
        break;
      case '--mode':
      case '-m':
        if (next === 'light' || next === 'full') {
          options.mode = next;
        } else {
          console.error(`${colors.red}Error: Invalid mode "${next}". Use "light" or "full"${colors.reset}`);
          process.exit(1);
        }
        i++;
        break;
      case '--help':
      case '-h':
        printHelp();
        process.exit(0);
        break;
    }
  }

  return options;
}

function formatUptime(ms) {
  const seconds = Math.floor(ms / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);

  if (hours > 0) {
    return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  } else if (minutes > 0) {
    return `${minutes}m ${seconds % 60}s`;
  } else {
    return `${seconds}s`;
  }
}

function formatHashrate(h) {
  if (h >= 1000000) return `${(h / 1000000).toFixed(2)} MH/s`;
  if (h >= 1000) return `${(h / 1000).toFixed(2)} KH/s`;
  return `${h.toFixed(2)} H/s`;
}

async function main() {
  printBanner();

  const options = parseArgs();

  // Validate required options
  if (!options.pool) {
    console.error(`${colors.red}Error: Pool URL is required${colors.reset}`);
    console.log('Use --help for usage information');
    process.exit(1);
  }

  if (!options.wallet) {
    console.error(`${colors.red}Error: Wallet address is required${colors.reset}`);
    console.log('Use --help for usage information');
    process.exit(1);
  }

  // Format wallet: first 8 chars...last 8 chars
  const walletDisplay = options.wallet.length > 20
    ? `${options.wallet.substring(0, 8)}...${options.wallet.slice(-8)}`
    : options.wallet;

  // Calculate memory usage
  let memoryDisplay;
  if (options.mode === 'full') {
    const datasetGB = RANDOMX_DATASET_SIZE / (1024 * 1024 * 1024);
    memoryDisplay = `${datasetGB.toFixed(2)}GB dataset + 256MB cache (shared)`;
  } else {
    memoryDisplay = `${options.threads * 256}MB (${options.threads} × 256MB cache)`;
  }

  console.log(`${colors.bright}Configuration:${colors.reset}`);
  console.log(`  Pool:    ${colors.cyan}${options.pool}${colors.reset}`);
  console.log(`  Wallet:  ${colors.cyan}${walletDisplay}${colors.reset}`);
  console.log(`  Worker:  ${colors.cyan}${options.worker}${colors.reset}`);
  console.log(`  Threads: ${colors.cyan}${options.threads}${colors.reset}`);
  console.log(`  Mode:    ${colors.cyan}${options.mode}${colors.reset}`);
  console.log(`  Memory:  ${colors.cyan}${memoryDisplay}${colors.reset}`);
  console.log();

  // Create miner
  const miner = new StratumMiner({
    pool: options.pool,
    wallet: options.wallet,
    worker: options.worker,
    password: options.password,
    threads: options.threads,
    mode: options.mode
  });

  // Event handlers
  miner.on('datasetProgress', (info) => {
    process.stdout.write(`\r${colors.yellow}Dataset generation: ${info.percent}%${colors.reset}   `);
  });

  miner.on('datasetReady', (info) => {
    console.log(`\n${colors.green}✓ Dataset ready${colors.reset} (${info.timeSeconds.toFixed(1)}s)`);
  });

  miner.on('started', (info) => {
    console.log(`${colors.green}✓ Mining started${colors.reset} (${info.mode} mode)`);
  });

  miner.on('job', (job) => {
    console.log(`${colors.blue}► New job${colors.reset} height=${job.height}`);
  });

  miner.on('share', (share) => {
    console.log(`${colors.yellow}★ Share found${colors.reset} nonce=${share.nonce}`);
  });

  miner.on('accepted', (share) => {
    console.log(`${colors.green}✓ Share accepted${colors.reset}`);
  });

  miner.on('rejected', (share) => {
    console.log(`${colors.red}✗ Share rejected${colors.reset} - ${share.reason}`);
  });

  miner.on('hashrate', (info) => {
    const stats = miner.getStats();
    process.stdout.write(
      `\r${colors.cyan}⚡ ${formatHashrate(info.hashrate)}${colors.reset} | ` +
      `Shares: ${colors.green}${stats.sharesAccepted}${colors.reset}/${colors.red}${stats.sharesRejected}${colors.reset} | ` +
      `Uptime: ${formatUptime(stats.uptime)}   `
    );
  });

  miner.on('error', (err) => {
    console.error(`${colors.red}Error: ${err.message}${colors.reset}`);
  });

  // Handle shutdown
  process.on('SIGINT', () => {
    console.log(`\n${colors.yellow}Shutting down...${colors.reset}`);
    miner.stop();

    const stats = miner.getStats();
    console.log(`\n${colors.bright}Final Statistics:${colors.reset}`);
    console.log(`  Total hashes:    ${stats.totalHashes.toLocaleString()}`);
    console.log(`  Shares accepted: ${stats.sharesAccepted}`);
    console.log(`  Shares rejected: ${stats.sharesRejected}`);
    console.log(`  Uptime:          ${formatUptime(stats.uptime)}`);

    process.exit(0);
  });

  // Start mining
  try {
    await miner.start();
  } catch (err) {
    console.error(`${colors.red}Failed to start miner: ${err.message}${colors.reset}`);
    process.exit(1);
  }
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
