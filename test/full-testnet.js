#!/usr/bin/env bun
/**
 * Full Testnet Validation — mines through all 10 hard forks, tests all TX
 * types in CN / SAL1 / CARROT eras, and validates the salvium-js stack.
 *
 * Usage:
 *   bun test/full-testnet.js [--daemon URL] [--skip-mining] [--resume-from PHASE]
 *
 * Phases:
 *   0  Setup — load wallets, verify daemon
 *   1  Mine to HF2 (height 270) — WASM probe + Rust fill
 *   2  CN TX tests — transfers A→B, B→A
 *   3  Mine to HF6 (height 835) — Rust
 *   4  SAL1 TX tests — transfers, stake
 *   5  Mine to CARROT (height 1120) — Rust + WASM probe
 *   6  CARROT TX tests — transfers, stake, burn, sweep
 *   7  Final reconciliation — balances, output counts
 *   8  Gap sync — fresh wallet C syncs from genesis
 */

import { Wallet } from '../src/wallet.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
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

// Target heights (HF activation + coinbase maturity + ring buffer)
// Coinbase outputs lock for 60 blocks. After a fork, new-era outputs need
// to unlock before they can be spent. Need: 60 (lock) + 16 (ring size) + 4 buffer = 80.
const TARGET = {
  HF2_MATURE: 270,    // HF2 at 250 + 20 (SAL outputs already plentiful)
  HF6_MATURE: 895,    // HF6 at 815 + 80 (SAL1 coinbase needs 60-block unlock)
  CARROT_MATURE: 1180, // HF10 at 1100 + 80 (same coinbase maturity requirement)
  FINAL: 1260,
};

const MATURITY_BLOCKS = 10; // blocks to mine after TX for spendable age
const WASM_PROBE_BLOCKS = 3;

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
        console.log('Usage: bun test/full-testnet.js [--daemon URL] [--skip-mining] [--resume-from PHASE]');
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

// ─── Phases ─────────────────────────────────────────────────────────────────

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

async function phase1_mineToHF2(daemon, daemonUrl, walletA) {
  console.log('\n═══ Phase 1: Mine to HF2 (target height 270) ═══');
  const t0 = performance.now();
  const address = walletA.getLegacyAddress();
  const startHeight = await getDaemonHeight(daemon);

  // WASM probe: mine 3 blocks to validate WASM mining works
  if (startHeight < 35) {
    console.log('\n  ── WASM Probe 1 ──');
    await mineTo(daemon, startHeight + WASM_PROBE_BLOCKS, address, daemonUrl, 'wasm');
  } else {
    console.log('  WASM probe skipped (already past bootstrap)');
  }

  // Rust fill to target
  await mineTo(daemon, TARGET.HF2_MATURE, address, daemonUrl, 'rust');

  const finalHeight = await getDaemonHeight(daemon);
  const hfVer = getHfVersionForHeight(finalHeight, NETWORK_ID.TESTNET);
  const elapsed = (performance.now() - t0) / 1000;
  console.log(`  HF version at ${finalHeight}: ${hfVer}`);
  log.phase('mine-to-hf2', { startHeight, finalHeight, hfVer, elapsed });
}

async function phase2_cnTxTests(daemon, daemonUrl, walletA, walletB) {
  console.log('\n═══ Phase 2: CN Era TX Tests ═══');
  const t0 = performance.now();

  // Sync both wallets to pick up mined coinbases
  const AT = 'SAL'; // CN era asset type
  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  await printBalance(walletA, 'A', AT);
  await printBalance(walletB, 'B', AT);

  // Transfers A→B (legacy CN addresses — pre-CARROT era)
  const LG = { legacy: true, assetType: AT };
  await doTransfer(walletA, walletB, sal(1), 'CN A→B 1 SAL', LG);
  await doTransfer(walletA, walletB, sal(2), 'CN A→B 2 SAL', LG);
  await doTransfer(walletA, walletB, sal(5), 'CN A→B 5 SAL', LG);

  // Mine maturity blocks so B can spend
  const address = walletA.getLegacyAddress();
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');

  // Sync, then B→A
  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  await printBalance(walletB, 'B', AT);

  await doTransfer(walletB, walletA, sal(0.5), 'CN B→A 0.5 SAL', LG);

  // Mine maturity for the B→A tx
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');

  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  const balA = await printBalance(walletA, 'A', AT);
  const balB = await printBalance(walletB, 'B', AT);

  saveSyncCache(walletA, 'a');
  saveSyncCache(walletB, 'b');

  const elapsed = (performance.now() - t0) / 1000;
  log.phase('cn-tx-tests', { elapsed, balA: balA.balance.toString(), balB: balB.balance.toString() });
}

async function phase3_mineToHF6(daemon, daemonUrl, walletA) {
  console.log(`\n═══ Phase 3: Mine to HF6 / SAL1 (target height ${TARGET.HF6_MATURE}) ═══`);
  const t0 = performance.now();
  const address = walletA.getLegacyAddress();
  await mineTo(daemon, TARGET.HF6_MATURE, address, daemonUrl, 'rust');
  const finalHeight = await getDaemonHeight(daemon);
  const hfVer = getHfVersionForHeight(finalHeight, NETWORK_ID.TESTNET);
  const elapsed = (performance.now() - t0) / 1000;
  console.log(`  HF version at ${finalHeight}: ${hfVer}`);
  log.phase('mine-to-hf6', { finalHeight, hfVer, elapsed });
}

async function phase4_sal1TxTests(daemon, daemonUrl, walletA, walletB) {
  console.log('\n═══ Phase 4: SAL1 Era TX Tests ═══');
  const t0 = performance.now();
  const AT = 'SAL1'; // SAL1 era asset type

  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  await printBalance(walletA, 'A', AT);

  // Transfers A→B in SAL1 era (still pre-CARROT, use legacy addresses)
  const LG = { legacy: true, assetType: AT };
  await doTransfer(walletA, walletB, sal(1), 'SAL1 A→B 1 SAL1', LG);
  await doTransfer(walletA, walletB, sal(2), 'SAL1 A→B 2 SAL1', LG);

  // Mine maturity
  const address = walletA.getLegacyAddress();
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');
  await syncWallet(walletA, daemon, 'A');

  // Stake
  await doStake(walletA, sal(10), 'SAL1 stake 10 SAL1', AT);

  // Mine maturity
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');
  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  const balA = await printBalance(walletA, 'A', AT);
  const balB = await printBalance(walletB, 'B', AT);

  saveSyncCache(walletA, 'a');
  saveSyncCache(walletB, 'b');

  const elapsed = (performance.now() - t0) / 1000;
  log.phase('sal1-tx-tests', { elapsed, balA: balA.balance.toString(), balB: balB.balance.toString() });
}

async function phase5_mineToCarrot(daemon, daemonUrl, walletA) {
  console.log(`\n═══ Phase 5: Mine to CARROT (target height ${TARGET.CARROT_MATURE}) ═══`);
  const t0 = performance.now();
  const legacyAddr = walletA.getLegacyAddress();
  const carrotAddr = walletA.getCarrotAddress();

  // Mine up to HF10 boundary (1100) with legacy address
  const HF10_HEIGHT = 1100;
  const currentHeight = await getDaemonHeight(daemon);
  if (currentHeight < HF10_HEIGHT) {
    console.log(`  Mining to HF10 boundary (${HF10_HEIGHT}) with legacy address...`);
    await mineTo(daemon, HF10_HEIGHT, legacyAddr, daemonUrl, 'rust');
  }

  // After HF10: daemon requires CARROT address for coinbase outputs
  console.log(`  Switching to CARROT address for post-HF10 mining`);
  await mineTo(daemon, TARGET.CARROT_MATURE, carrotAddr, daemonUrl, 'rust');

  // WASM probe 2: mine 3 blocks in the CARROT era to validate WASM still works
  const postHeight = await getDaemonHeight(daemon);
  console.log('\n  ── WASM Probe 2 (CARROT era) ──');
  await mineTo(daemon, postHeight + WASM_PROBE_BLOCKS, carrotAddr, daemonUrl, 'wasm');

  // Mine a few more for maturity
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS + 2, carrotAddr, daemonUrl, 'rust');

  const finalHeight = await getDaemonHeight(daemon);
  const hfVer = getHfVersionForHeight(finalHeight, NETWORK_ID.TESTNET);
  const elapsed = (performance.now() - t0) / 1000;
  console.log(`  HF version at ${finalHeight}: ${hfVer}`);
  log.phase('mine-to-carrot', { finalHeight, hfVer, elapsed });
}

async function phase6_carrotTxTests(daemon, daemonUrl, walletA, walletB) {
  console.log('\n═══ Phase 6: CARROT Era TX Tests ═══');
  const t0 = performance.now();
  const AT = 'SAL1'; // CARROT era still uses SAL1 asset type

  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  await printBalance(walletA, 'A', AT);
  await printBalance(walletB, 'B', AT);

  // CARROT transfers A→B
  await doTransfer(walletA, walletB, sal(1), 'CARROT A→B 1 SAL1', { assetType: AT });
  await doTransfer(walletA, walletB, sal(2), 'CARROT A→B 2 SAL1', { assetType: AT });
  await doTransfer(walletA, walletB, sal(5), 'CARROT A→B 5 SAL1', { assetType: AT });

  // Mine maturity so B can spend (CARROT address required post-HF10)
  const address = walletA.getCarrotAddress();
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');
  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  await printBalance(walletB, 'B', AT);

  // CARROT transfer B→A
  await doTransfer(walletB, walletA, sal(0.5), 'CARROT B→A 0.5 SAL1', { assetType: AT });

  // Mine maturity
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');
  await syncWallet(walletA, daemon, 'A');

  // CARROT stake
  await doStake(walletA, sal(10), 'CARROT stake 10 SAL1', AT);

  // CARROT burn
  await doBurn(walletA, sal(0.1), 'CARROT burn 0.1 SAL1', AT);

  // Mine maturity
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');
  await syncWallet(walletB, daemon, 'B');

  // CARROT sweep B→B
  const bAddr = walletB.getAddress();
  await doSweep(walletB, bAddr, 'CARROT sweep B→B', AT);

  // Mine maturity for sweep
  await mineTo(daemon, (await getDaemonHeight(daemon)) + MATURITY_BLOCKS, address, daemonUrl, 'rust');
  await syncWallet(walletA, daemon, 'A');
  await syncWallet(walletB, daemon, 'B');
  const balA = await printBalance(walletA, 'A', AT);
  const balB = await printBalance(walletB, 'B', AT);

  saveSyncCache(walletA, 'a');
  saveSyncCache(walletB, 'b');

  const elapsed = (performance.now() - t0) / 1000;
  log.phase('carrot-tx-tests', { elapsed, balA: balA.balance.toString(), balB: balB.balance.toString() });
}

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

// ─── Extra mining to pad the chain ──────────────────────────────────────────

async function phaseExtra_mine(daemon, daemonUrl, walletA) {
  const currentHeight = await getDaemonHeight(daemon);
  if (currentHeight >= TARGET.FINAL) {
    console.log(`\n  Already at height ${currentHeight}, skipping extra mining`);
    return;
  }
  console.log(`\n═══ Extra: Mine to ${TARGET.FINAL} ═══`);
  // Post-HF10: use CARROT address for coinbase outputs
  const address = currentHeight >= 1100 ? walletA.getCarrotAddress() : walletA.getLegacyAddress();
  await mineTo(daemon, TARGET.FINAL, address, daemonUrl, 'rust');
}

// ─── Main ───────────────────────────────────────────────────────────────────

async function main() {
  const opts = parseArgs();
  const daemon = new DaemonRPC({ url: opts.daemon });

  console.log('╔══════════════════════════════════════════════════════════════╗');
  console.log('║           Full Testnet Validation — salvium-js              ║');
  console.log('╚══════════════════════════════════════════════════════════════╝');

  const overallStart = performance.now();

  // Phase 0: Setup (always runs)
  const { walletA, walletB, startHeight } = await phase0_setup(daemon, opts.daemon);

  const phases = [
    { id: 1, name: 'Mine to HF2',        fn: () => phase1_mineToHF2(daemon, opts.daemon, walletA) },
    { id: 2, name: 'CN TX tests',         fn: () => phase2_cnTxTests(daemon, opts.daemon, walletA, walletB) },
    { id: 3, name: 'Mine to HF6',         fn: () => phase3_mineToHF6(daemon, opts.daemon, walletA) },
    { id: 4, name: 'SAL1 TX tests',       fn: () => phase4_sal1TxTests(daemon, opts.daemon, walletA, walletB) },
    { id: 5, name: 'Mine to CARROT',      fn: () => phase5_mineToCarrot(daemon, opts.daemon, walletA) },
    { id: 6, name: 'CARROT TX tests',     fn: () => phase6_carrotTxTests(daemon, opts.daemon, walletA, walletB) },
    { id: 7, name: 'Reconciliation',      fn: () => phase7_reconciliation(daemon, walletA, walletB) },
    { id: 8, name: 'Gap sync',            fn: () => phase8_gapSync(daemon) },
  ];

  let lastResult;
  for (const phase of phases) {
    if (phase.id < opts.resumeFrom) {
      console.log(`\n  Skipping phase ${phase.id} (${phase.name}) — resume-from=${opts.resumeFrom}`);
      continue;
    }
    if (opts.skipMining && [1, 3, 5].includes(phase.id)) {
      console.log(`\n  Skipping phase ${phase.id} (${phase.name}) — --skip-mining`);
      continue;
    }
    try {
      lastResult = await phase.fn();
    } catch (e) {
      console.error(`\n  PHASE ${phase.id} FAILED: ${e.message}`);
      console.error(e.stack);
      log.phase(`phase-${phase.id}-error`, { error: e.message });
      log.save();
      process.exit(1);
    }
  }

  // Extra mining after all tests pass
  if (!opts.skipMining) {
    try {
      await phaseExtra_mine(daemon, opts.daemon, walletA);
    } catch (e) {
      console.log(`  Extra mining skipped: ${e.message}`);
    }
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
