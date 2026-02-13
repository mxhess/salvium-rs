#!/usr/bin/env bun
/**
 * Full Testnet Validation — mines through all 10 hard forks, tests all TX
 * types in CN / SAL1 / CARROT eras, and validates the salvium-js stack.
 *
 * Usage:
 *   bun test/full-testnet.js [--daemon URL] [--skip-mining] [--resume-from HF]
 *
 * Mines through each of the 10 hard forks with:
 *   - WASM probe (3 blocks) at every fork boundary
 *   - Full TX tests at era boundaries (HF2, HF6, HF10)
 *   - Lightweight transfer test at intermediate forks
 *   - Final reconciliation and gap sync
 */

import { Wallet } from '../src/wallet.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { initCrypto } from '../src/crypto/index.js';
import {
  TESTNET_CONFIG, COIN, CRYPTONOTE_MINED_MONEY_UNLOCK_WINDOW,
  CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE,
  getHfVersionForHeight, NETWORK_ID,
} from '../src/consensus.js';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const WALLET_DIR = join(homedir(), 'testnet-wallet');
const LOG_PATH = join(WALLET_DIR, 'full-testnet-log.json');
const DEFAULT_DAEMON = 'http://web.whiskymine.io:29081';

// ─── Fork table ──────────────────────────────────────────────────────────────

const FORKS = [
  { hf: 1,  height: 1,    asset: 'SAL',  addrFormat: 'legacy' },
  { hf: 2,  height: 250,  asset: 'SAL',  addrFormat: 'legacy', fullTests: true },
  { hf: 3,  height: 500,  asset: 'SAL',  addrFormat: 'legacy' },
  { hf: 4,  height: 600,  asset: 'SAL',  addrFormat: 'legacy' },
  { hf: 5,  height: 800,  asset: 'SAL',  addrFormat: 'legacy', paused: true },  // SHUTDOWN_USER_TXS — daemon rejects all user TXs
  { hf: 6,  height: 815,  asset: 'SAL1', addrFormat: 'legacy', fullTests: true },
  { hf: 7,  height: 900,  asset: 'SAL1', addrFormat: 'legacy' },
  { hf: 8,  height: 950,  asset: 'SAL1', addrFormat: 'legacy' },
  { hf: 9,  height: 1000, asset: 'SAL1', addrFormat: 'legacy' },
  { hf: 10, height: 1100, asset: 'SAL1', addrFormat: 'carrot', fullTests: true },
];
const WASM_PROBE_BLOCKS = 3;
const MATURITY_OFFSET = 80;  // 60 coinbase lock + 16 ring + 4 buffer
const MATURITY_BLOCKS = 10;  // blocks to mine after TX for spendable age

// ─── CLI ────────────────────────────────────────────────────────────────────

function parseArgs() {
  const args = process.argv.slice(2);
  const opts = { daemon: DEFAULT_DAEMON, skipMining: false, resumeFrom: 0 };
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--daemon': case '-d': opts.daemon = args[++i]; break;
      case '--skip-mining': opts.skipMining = true; break;
      case '--resume-from': case '-r': opts.resumeFrom = parseInt(args[++i], 10); break;
      case '--help': case '-h':
        console.log('Usage: bun test/full-testnet.js [--daemon URL] [--skip-mining] [--resume-from HF]');
        process.exit(0);
    }
  }
  return opts;
}

// ─── Helpers ────────────────────────────────────────────────────────────────

function sal(n) { return BigInt(Math.round(n * 1e8)); }
function fmtSAL(atomic) { return (Number(atomic) / 1e8).toFixed(8); }
function fmtDuration(s) {
  if (s < 60) return `${s.toFixed(1)}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${Math.floor(s % 60)}s`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

const log = {
  _data: { phases: [], txResults: [], miningStats: [], finalBalances: null, startedAt: new Date().toISOString() },
  phase(name, data) { this._data.phases.push({ name, ...data, ts: new Date().toISOString() }); },
  tx(result) { this._data.txResults.push({ ...result, ts: new Date().toISOString() }); },
  mining(stats) { this._data.miningStats.push(stats); },
  save() {
    this._data.completedAt = new Date().toISOString();
    writeFileSync(LOG_PATH, JSON.stringify(this._data, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2));
    console.log(`\nLog saved → ${LOG_PATH}`);
  },
};

async function getDaemonHeight(daemon) {
  const info = await daemon.getInfo();
  return info.result?.height ?? info.height;
}

async function waitForHeight(daemon, target) {
  while (true) {
    const h = await getDaemonHeight(daemon);
    if (h >= target) return h;
    await new Promise(r => setTimeout(r, 3000));
  }
}

// ─── Mining wrappers ────────────────────────────────────────────────────────

/**
 * Spawn solo-miner.js as a child process and wait for it to finish.
 * Returns the exit code.
 */
function runMiner(opts) {
  const { backend, blocks, address, daemon, threads = 4 } = opts;
  const args = [
    'test/solo-miner.js',
    '--backend', backend,
    '--blocks', String(blocks),
    '--address', address,
    '--daemon', daemon,
    '--threads', String(threads),
  ];
  if (backend === 'rust') args.push('--mode', 'light');

  return new Promise((resolve, reject) => {
    const proc = spawn('bun', args, {
      cwd: join(__dirname, '..'),
      stdio: ['ignore', 'inherit', 'inherit'],
    });
    proc.on('error', reject);
    proc.on('close', (code) => resolve(code));
  });
}

/**
 * Mine blocks to reach a target height using the given backend.
 */
async function mineTo(daemon, targetHeight, address, daemonUrl, backend = 'rust') {
  const currentHeight = await getDaemonHeight(daemon);
  if (currentHeight >= targetHeight) {
    console.log(`  Already at height ${currentHeight} (target ${targetHeight}), skipping`);
    return { blocksNeeded: 0, backend };
  }
  const blocksNeeded = targetHeight - currentHeight;
  console.log(`  Mining ${blocksNeeded} blocks (${currentHeight} → ${targetHeight}) with ${backend}...`);
  const t0 = performance.now();
  const code = await runMiner({ backend, blocks: blocksNeeded, address, daemon: daemonUrl });
  const elapsed = (performance.now() - t0) / 1000;
  if (code !== 0) throw new Error(`Miner exited with code ${code}`);
  const finalHeight = await getDaemonHeight(daemon);
  console.log(`  Reached height ${finalHeight} in ${fmtDuration(elapsed)}`);
  log.mining({ backend, blocksNeeded, elapsed, fromHeight: currentHeight, toHeight: finalHeight });
  return { blocksNeeded, elapsed, backend };
}

// ─── Wallet loading ─────────────────────────────────────────────────────────

function loadWallet(name, pin) {
  const walletPath = join(WALLET_DIR, `wallet-${name}.json`);
  const json = JSON.parse(readFileSync(walletPath, 'utf8'));
  const wallet = Wallet.fromEncryptedJSON(json, pin);
  // Always start from height 0 — stale sync caches from previous sessions will
  // have wrong heights and corrupt address format selection.
  wallet.setSyncHeight(0);
  console.log(`  Loaded wallet ${name.toUpperCase()} (fresh sync from genesis)`);
  return wallet;
}

function saveSyncCache(wallet, name) {
  const cachePath = join(WALLET_DIR, `wallet-${name}-sync.json`);
  try {
    const cache = wallet.dumpSyncCache();
    writeFileSync(cachePath, JSON.stringify(cache, (_, v) => typeof v === 'bigint' ? v.toString() : v));
  } catch (e) {
    console.log(`  Cache save skipped for ${name}: ${e.message}`);
  }
}

async function syncWallet(wallet, daemon, label) {
  console.log(`  Syncing wallet ${label}...`);
  const t0 = performance.now();
  const { syncHeight } = await wallet.syncWithDaemon(daemon);
  const elapsed = (performance.now() - t0) / 1000;
  console.log(`  Wallet ${label} synced to height ${syncHeight} (${fmtDuration(elapsed)})`);
  return syncHeight;
}

async function printBalance(wallet, label, assetType) {
  if (!assetType) throw new Error('printBalance: assetType is required');
  const bal = await wallet.getStorageBalance({ assetType });
  console.log(`  ${label} [${assetType}]: balance=${fmtSAL(bal.balance)} unlocked=${fmtSAL(bal.unlockedBalance)} locked=${fmtSAL(bal.lockedBalance)}`);
  return bal;
}

// ─── TX helpers ─────────────────────────────────────────────────────────────

async function doTransfer(fromWallet, toWallet, amount, label, { legacy = false, assetType } = {}) {
  if (!assetType) throw new Error('doTransfer: assetType is required');
  const dest = legacy ? toWallet.getLegacyAddress() : toWallet.getAddress();
  console.log(`  TX: ${label} → ${fmtSAL(amount)} ${assetType} to ${dest.slice(0, 20)}...`);
  try {
    const result = await fromWallet.transfer([{ address: dest, amount }], { assetType });
    console.log(`    hash=${result.txHash} fee=${fmtSAL(result.fee)}`);
    log.tx({ type: 'transfer', label, txHash: result.txHash, fee: result.fee.toString(), amount: amount.toString() });
    return result;
  } catch (e) {
    console.error(`    FAILED: ${e.message}`);
    log.tx({ type: 'transfer', label, error: e.message, amount: amount.toString() });
    throw e;
  }
}

async function doStake(wallet, amount, label, assetType) {
  if (!assetType) throw new Error('doStake: assetType is required');
  console.log(`  TX: ${label} stake ${fmtSAL(amount)} ${assetType}`);
  try {
    const result = await wallet.stake(amount, { assetType });
    console.log(`    hash=${result.txHash} fee=${fmtSAL(result.fee)}`);
    log.tx({ type: 'stake', label, txHash: result.txHash, fee: result.fee.toString(), amount: amount.toString() });
    return result;
  } catch (e) {
    console.error(`    FAILED: ${e.message}`);
    log.tx({ type: 'stake', label, error: e.message, amount: amount.toString() });
    throw e;
  }
}

async function doBurn(wallet, amount, label, assetType) {
  if (!assetType) throw new Error('doBurn: assetType is required');
  console.log(`  TX: ${label} burn ${fmtSAL(amount)} ${assetType}`);
  try {
    const result = await wallet.burn(amount, { assetType });
    console.log(`    hash=${result.txHash} fee=${fmtSAL(result.fee)}`);
    log.tx({ type: 'burn', label, txHash: result.txHash, fee: result.fee.toString(), amount: amount.toString() });
    return result;
  } catch (e) {
    console.error(`    FAILED: ${e.message}`);
    log.tx({ type: 'burn', label, error: e.message, amount: amount.toString() });
    throw e;
  }
}

async function doSweep(wallet, address, label, assetType) {
  if (!assetType) throw new Error('doSweep: assetType is required');
  console.log(`  TX: ${label} sweep → ${address.slice(0, 20)}...`);
  try {
    const result = await wallet.sweep(address, { assetType });
    console.log(`    hash=${result.txHash} fee=${fmtSAL(result.fee)} amount=${fmtSAL(result.amount)}`);
    log.tx({ type: 'sweep', label, txHash: result.txHash, fee: result.fee.toString(), amount: result.amount.toString() });
    return result;
  } catch (e) {
    console.error(`    FAILED: ${e.message}`);
    log.tx({ type: 'sweep', label, error: e.message });
    throw e;
  }
}

// ─── Setup ──────────────────────────────────────────────────────────────────

async function phase0_setup(daemon, daemonUrl) {
  console.log('\n═══ Phase 0: Setup ═══');
  const t0 = performance.now();

  // Verify daemon
  const height = await getDaemonHeight(daemon);
  const info = await daemon.getInfo();
  const hfVer = getHfVersionForHeight(height, NETWORK_ID.TESTNET);
  console.log(`  Daemon: ${daemonUrl}`);
  console.log(`  Height: ${height}, HF version: ${hfVer}`);
  console.log(`  Network: ${info.result?.nettype ?? 'testnet'}`);

  // Load wallets
  const walletA = loadWallet('a', '471001');
  const walletB = loadWallet('b', '401605');
  walletA.setDaemon(daemon);
  walletB.setDaemon(daemon);

  console.log(`  Wallet A (CN):     ${walletA.getLegacyAddress().slice(0, 30)}...`);
  console.log(`  Wallet A (CARROT): ${walletA.getCarrotAddress()?.slice(0, 30) ?? 'n/a'}...`);
  console.log(`  Wallet B (CN):     ${walletB.getLegacyAddress().slice(0, 30)}...`);
  console.log(`  Wallet B (CARROT): ${walletB.getCarrotAddress()?.slice(0, 30) ?? 'n/a'}...`);

  const elapsed = (performance.now() - t0) / 1000;
  log.phase('setup', { height, hfVer, elapsed });
  return { walletA, walletB, startHeight: height };
}

// ─── Fork-driven mining and testing ─────────────────────────────────────────

/**
 * Mine to a fork boundary and run WASM probe blocks.
 */
async function mineToFork(fork, daemon, walletA, daemonUrl) {
  const currentHeight = await getDaemonHeight(daemon);
  const miningAddr = fork.addrFormat === 'carrot'
    ? walletA.getCarrotAddress()
    : walletA.getLegacyAddress();

  // For HF10: need legacy address up to fork boundary, CARROT after
  if (fork.hf === 10 && currentHeight < fork.height) {
    const legacyAddr = walletA.getLegacyAddress();
    await mineTo(daemon, fork.height, legacyAddr, daemonUrl, 'rust');
  } else if (currentHeight < fork.height) {
    await mineTo(daemon, fork.height, miningAddr, daemonUrl, 'rust');
  }

  // WASM probe: 3 blocks in the new era
  console.log(`\n  ── WASM Probe HF${fork.hf} ──`);
  const wasmAddr = fork.addrFormat === 'carrot'
    ? walletA.getCarrotAddress()
    : walletA.getLegacyAddress();
  await mineTo(daemon, (await getDaemonHeight(daemon)) + WASM_PROBE_BLOCKS,
               wasmAddr, daemonUrl, 'wasm');
}

/**
 * Mine enough blocks after a fork for coinbase outputs to mature.
 */
async function mineMaturity(daemon, walletA, daemonUrl, fork) {
  const addr = fork.addrFormat === 'carrot'
    ? walletA.getCarrotAddress()
    : walletA.getLegacyAddress();
  const target = fork.height + MATURITY_OFFSET;
  const current = await getDaemonHeight(daemon);
  if (current < target) {
    await mineTo(daemon, target, addr, daemonUrl, 'rust');
  }
}

/**
 * Run TX tests appropriate for the fork era.
 * Full tests at era boundaries (HF2, HF6, HF10), lightweight at others.
 */
async function runForkTests(fork, daemon, daemonUrl, walletA, walletB) {
  const AT = fork.asset;
  const legacy = fork.addrFormat === 'legacy';

  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  await printBalance(walletA, 'A', AT);
  await printBalance(walletB, 'B', AT);

  const miningAddr = legacy ? walletA.getLegacyAddress() : walletA.getCarrotAddress();

  if (fork.fullTests) {
    // Full test suite for era boundaries (HF2, HF6, HF10)
    // Transfers A→B
    await doTransfer(walletA, walletB, sal(1), `HF${fork.hf} A→B 1 ${AT}`, { legacy, assetType: AT });
    await doTransfer(walletA, walletB, sal(2), `HF${fork.hf} A→B 2 ${AT}`, { legacy, assetType: AT });
    await doTransfer(walletA, walletB, sal(5), `HF${fork.hf} A→B 5 ${AT}`, { legacy, assetType: AT });

    // Mine maturity so B can spend
    await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, miningAddr, daemonUrl, 'rust');
    await syncWallet(walletA, daemon, 'A');
    await syncWallet(walletB, daemon, 'B');

    // Transfer B→A
    await doTransfer(walletB, walletA, sal(0.5), `HF${fork.hf} B→A 0.5 ${AT}`, { legacy, assetType: AT });

    // Era-specific tests
    if (fork.hf >= 6) {
      // Stake available from SAL1 era onwards
      await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, miningAddr, daemonUrl, 'rust');
      await syncWallet(walletA, daemon, 'A');
      await doStake(walletA, sal(10), `HF${fork.hf} stake 10 ${AT}`, AT);
    }
    if (fork.hf >= 10) {
      // Burn + sweep in CARROT era
      await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, miningAddr, daemonUrl, 'rust');
      await syncWallet(walletA, daemon, 'A');
      await doBurn(walletA, sal(0.1), `HF${fork.hf} burn 0.1 ${AT}`, AT);

      await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, miningAddr, daemonUrl, 'rust');
      await syncWallet(walletB, daemon, 'B');
      await doSweep(walletB, walletB.getAddress(), `HF${fork.hf} sweep B→B`, AT);
    }
  } else if (fork.paused) {
    // Paused forks (HF5, HF7, HF9): daemon rejects user transactions
    console.log(`  (HF${fork.hf} paused — user transactions disabled by daemon, WASM probe only)`);
  } else if (fork.hf > 1) {
    // Lightweight transfer test at intermediate forks (skip HF1 — no mature outputs yet)
    await doTransfer(walletA, walletB, sal(0.5), `HF${fork.hf} A→B 0.5 ${AT}`, { legacy, assetType: AT });
  } else {
    console.log('  (HF1 genesis — WASM probe only, no TX tests until coinbase matures)');
  }

  // Mine maturity for the last TX
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, miningAddr, daemonUrl, 'rust');
  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');

  const balA = await printBalance(walletA, 'A', AT);
  const balB = await printBalance(walletB, 'B', AT);
  saveSyncCache(walletA, 'a');
  saveSyncCache(walletB, 'b');

  return { balA, balB };
}

// ─── Reconciliation & Gap Sync ──────────────────────────────────────────────

async function phase7_reconciliation(daemon, walletA, walletB) {
  console.log('\n═══ Phase 7: Final Reconciliation ═══');
  const t0 = performance.now();

  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');

  const height = await getDaemonHeight(daemon);
  const hfVer = getHfVersionForHeight(height, NETWORK_ID.TESTNET);

  console.log(`\n  Chain height: ${height} (HF ${hfVer})`);

  // Balances for all asset types
  const results = {};
  for (const [label, wallet, name] of [['A', walletA, 'a'], ['B', walletB, 'b']]) {
    const salBal = await printBalance(wallet, label, 'SAL');
    results[`wallet${label}_SAL`] = { balance: salBal.balance.toString(), unlocked: salBal.unlockedBalance.toString() };

    // Try SAL1 balance
    try {
      const sal1Bal = await printBalance(wallet, label, 'SAL1');
      results[`wallet${label}_SAL1`] = { balance: sal1Bal.balance.toString(), unlocked: sal1Bal.unlockedBalance.toString() };
    } catch { /* SAL1 may not exist */ }
  }

  // TX summary
  const txs = log._data.txResults;
  const successful = txs.filter(t => t.txHash);
  const failed = txs.filter(t => t.error);
  console.log(`\n  Transactions: ${successful.length} succeeded, ${failed.length} failed`);
  console.log(`  Total fees: ${fmtSAL(successful.reduce((s, t) => s + BigInt(t.fee || 0), 0n))} SAL`);

  if (failed.length > 0) {
    console.log('\n  Failed TXs:');
    for (const f of failed) console.log(`    ${f.label}: ${f.error}`);
  }

  // Mining stats
  const miningStats = log._data.miningStats;
  const totalMined = miningStats.reduce((s, m) => s + (m.blocksNeeded || 0), 0);
  const totalMiningTime = miningStats.reduce((s, m) => s + (m.elapsed || 0), 0);
  console.log(`\n  Total blocks mined: ${totalMined}`);
  console.log(`  Total mining time: ${fmtDuration(totalMiningTime)}`);

  log._data.finalBalances = results;
  const elapsed = (performance.now() - t0) / 1000;
  log.phase('reconciliation', { height, hfVer, elapsed, txSucceeded: successful.length, txFailed: failed.length });

  return { succeeded: successful.length, failed: failed.length };
}

async function phase8_gapSync(daemon) {
  console.log('\n═══ Phase 8: Gap Sync — Fresh Wallet C ═══');
  const t0 = performance.now();

  // Create a fresh wallet and sync from genesis
  const walletC = Wallet.create({ network: 'testnet' });
  walletC.setDaemon(daemon);
  console.log(`  Wallet C: ${walletC.getLegacyAddress().slice(0, 30)}...`);
  console.log(`  Syncing from genesis...`);

  const { syncHeight } = await walletC.syncWithDaemon(daemon);
  const elapsed = (performance.now() - t0) / 1000;
  console.log(`  Wallet C synced to height ${syncHeight} in ${fmtDuration(elapsed)}`);

  // Determine asset type at current height
  const h = await getDaemonHeight(daemon);
  const hfVer = getHfVersionForHeight(h, NETWORK_ID.TESTNET);
  const AT = hfVer >= 6 ? 'SAL1' : 'SAL';
  const bal = await walletC.getStorageBalance({ assetType: AT });
  console.log(`  Wallet C balance: ${fmtSAL(bal.balance)} ${AT} (expected 0)`);

  log.phase('gap-sync', { syncHeight, elapsed, balance: bal.balance.toString() });
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  await initCrypto();

  const opts = parseArgs();
  const daemon = new DaemonRPC({ url: opts.daemon });

  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║           Full Testnet Validation — salvium-js              ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');

  const overallStart = performance.now();

  // Phase 0: Setup (always runs)
  const { walletA, walletB, startHeight } = await phase0_setup(daemon, opts.daemon);

  // Mine through each fork with WASM probes + TX tests
  for (const fork of FORKS) {
    if (fork.hf < opts.resumeFrom) {
      console.log(`\n  Skipping HF${fork.hf} — resume-from=${opts.resumeFrom}`);
      continue;
    }

    console.log(`\n${'═'.repeat(60)}`);
    console.log(`  HF${fork.hf} @ height ${fork.height} — ${fork.asset} / ${fork.addrFormat}`);
    console.log(`${'═'.repeat(60)}`);

    if (!opts.skipMining) {
      try {
        await mineToFork(fork, daemon, walletA, opts.daemon);
      } catch (e) {
        console.error(`\n  MINING FAILED at HF${fork.hf}: ${e.message}`);
        console.error(e.stack);
        log.phase(`hf${fork.hf}-mining-error`, { error: e.message });
        log.save();
        process.exit(1);
      }
    }

    // Mine maturity for fullTests forks so coinbase outputs are spendable
    if (fork.fullTests && !opts.skipMining) {
      await mineMaturity(daemon, walletA, opts.daemon, fork);
    }

    try {
      await runForkTests(fork, daemon, opts.daemon, walletA, walletB);
    } catch (e) {
      console.error(`\n  TX TESTS FAILED at HF${fork.hf}: ${e.message}`);
      console.error(e.stack);
      log.phase(`hf${fork.hf}-tx-error`, { error: e.message });
      log.save();
      process.exit(1);
    }

    log.phase(`hf${fork.hf}`, { height: await getDaemonHeight(daemon) });
  }

  // Phase 7: Reconciliation
  let lastResult;
  try {
    lastResult = await phase7_reconciliation(daemon, walletA, walletB);
  } catch (e) {
    console.error(`\n  RECONCILIATION FAILED: ${e.message}`);
    console.error(e.stack);
    log.phase('reconciliation-error', { error: e.message });
    log.save();
    process.exit(1);
  }

  // Phase 8: Gap sync
  try {
    await phase8_gapSync(daemon);
  } catch (e) {
    console.error(`\n  GAP SYNC FAILED: ${e.message}`);
    console.error(e.stack);
    log.phase('gap-sync-error', { error: e.message });
    log.save();
    process.exit(1);
  }

  const totalElapsed = (performance.now() - overallStart) / 1000;

  console.log('\n╔══════════════════════════════════════════════════════════════╗');
  console.log('║                     TEST COMPLETE                           ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');
  console.log(`  Total time: ${fmtDuration(totalElapsed)}`);
  console.log(`  Start height: ${startHeight}`);
  console.log(`  Final height: ${await getDaemonHeight(daemon)}`);

  if (lastResult && typeof lastResult === 'object' && 'failed' in lastResult) {
    console.log(`  TX results: ${lastResult.succeeded} passed, ${lastResult.failed} failed`);
    if (lastResult.failed > 0) {
      console.log('\n  ⚠ Some transactions failed — check log for details');
    }
  }

  log.save();
  process.exit(lastResult?.failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error(`\nFatal: ${err.message}`);
  console.error(err.stack);
  log.save();
  process.exit(1);
});
