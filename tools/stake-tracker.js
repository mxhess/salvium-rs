#!/usr/bin/env bun
/**
 * Salvium Stake Tracker
 *
 * Demonstrates stake + return tracking by scanning the chain for STAKE (type 6)
 * and PROTOCOL (type 2) transactions, showing how amount_burnt flows through
 * the staking lifecycle.
 *
 * Usage:
 *   bun tools/stake-tracker.js [--daemon URL] [--height N] [--range N] [--tx HASH]
 *
 * Examples:
 *   # Track the 130,130 SAL1 stake at block 417082
 *   bun tools/stake-tracker.js --height 417082
 *
 *   # Scan 500 blocks from a starting height
 *   bun tools/stake-tracker.js --height 417000 --range 500
 *
 *   # Look up a specific transaction by hash
 *   bun tools/stake-tracker.js --tx 1563a8c7...
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { parseTransaction, parseBlock } from '../src/transaction/parsing.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { TX_TYPE, RCT_TYPE } from '../src/transaction/constants.js';

// ─── CLI ─────────────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(name, fallback) {
  const idx = args.indexOf(name);
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : fallback;
}

const DAEMON_URL = getArg('--daemon', 'http://seed01.salvium.io:19081');
const START_HEIGHT = parseInt(getArg('--height', '417080'), 10);
const RANGE = parseInt(getArg('--range', '200'), 10);
const TX_HASH_LOOKUP = getArg('--tx', null);

// ─── Formatting ──────────────────────────────────────────────────────────────

const DIM = '\x1b[2m';
const BOLD = '\x1b[1m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';

function fmtSAL(atomic) {
  const n = typeof atomic === 'bigint' ? atomic : BigInt(atomic || 0);
  const whole = n / 100000000000n;
  const frac = n % 100000000000n;
  const fracStr = frac.toString().padStart(11, '0').replace(/0+$/, '') || '0';
  return `${whole}.${fracStr}`;
}

function truncHash(h, len = 16) {
  if (!h || h.length <= len * 2) return h;
  return `${h.slice(0, len)}...${h.slice(-8)}`;
}

const TX_TYPE_NAMES = {
  0: 'UNSET', 1: 'MINER', 2: 'PROTOCOL', 3: 'TRANSFER',
  4: 'CONVERT', 5: 'BURN', 6: 'STAKE', 7: 'RETURN', 8: 'AUDIT'
};

// ─── TX Lookup Mode ─────────────────────────────────────────────────────────

async function lookupTx(daemon, txHash) {
  console.log(`${BOLD}Salvium Stake Tracker${RESET} — TX Lookup`);
  console.log(`Daemon: ${DAEMON_URL}\n`);

  const resp = await daemon.getTransactions([txHash], { decode_as_json: true });
  if (!resp.success || !resp.result.txs?.length) {
    console.error(`Transaction not found: ${txHash}`);
    process.exit(1);
  }

  const txData = resp.result.txs[0];
  const txBytes = hexToBytes(txData.as_hex);
  const tx = parseTransaction(txBytes);
  const txType = tx.prefix?.txType || 0;
  const amountBurnt = tx.prefix?.amount_burnt || 0n;
  const fee = tx.rct?.txnFee || 0n;
  const inputs = tx.prefix?.vin || [];
  const outputs = tx.prefix?.vout || [];

  console.log(`${'═'.repeat(78)}`);
  console.log(`  ${BOLD}TRANSACTION DETAILS${RESET}`);
  console.log(`${'═'.repeat(78)}\n`);
  console.log(`  Hash:          ${CYAN}${txData.tx_hash}${RESET}`);
  console.log(`  Type:          ${BOLD}${TX_TYPE_NAMES[txType] || txType}${RESET} (${txType})`);
  console.log(`  Block:         ${txData.block_height ?? 'mempool'}`);
  console.log(`  Confirmations: ${txData.block_height != null ? '(in block)' : 'unconfirmed'}`);
  console.log(`  Amount Burnt:  ${BOLD}${fmtSAL(amountBurnt)} SAL1${RESET}`);
  console.log(`  Fee:           ${fmtSAL(fee)} SAL1`);
  console.log(`  Inputs:        ${inputs.length}`);
  console.log(`  Outputs:       ${outputs.length}`);

  if (inputs.length > 0) {
    console.log(`\n  ${DIM}Key Images:${RESET}`);
    for (const inp of inputs) {
      if (inp.keyImage) {
        console.log(`    ${DIM}${bytesToHex(inp.keyImage)}${RESET}`);
      }
    }
  }

  if (outputs.length > 0) {
    console.log(`\n  ${DIM}Output Keys:${RESET}`);
    for (let i = 0; i < outputs.length; i++) {
      const out = outputs[i];
      const key = out.key ? bytesToHex(out.key) : '(unknown)';
      const amount = out.amount || 0n;
      const amountStr = amount > 0n ? ` amount=${fmtSAL(amount)}` : '';
      console.log(`    [${i}] ${DIM}${truncHash(key, 24)}${amountStr}${RESET}`);
    }
  }

  console.log();
}

// ─── Scan Mode ──────────────────────────────────────────────────────────────

async function scanBlocks(daemon) {
  const infoResp = await daemon.getInfo();
  if (!infoResp.success) {
    console.error('Failed to connect to daemon:', DAEMON_URL);
    process.exit(1);
  }
  const chainHeight = infoResp.result.height;

  console.log(`${BOLD}Salvium Stake Tracker${RESET}`);
  console.log(`Daemon: ${DAEMON_URL}  Chain height: ${chainHeight}`);
  console.log(`Scanning blocks ${START_HEIGHT} to ${START_HEIGHT + RANGE - 1}...\n`);

  const stakes = [];
  const protocols = [];
  const burns = [];
  const converts = [];

  const endHeight = Math.min(START_HEIGHT + RANGE, chainHeight);
  const batchSize = 20;

  for (let h = START_HEIGHT; h < endHeight; h += batchSize) {
    const batchEnd = Math.min(h + batchSize, endHeight);
    const heights = [];
    for (let i = h; i < batchEnd; i++) heights.push(i);

    process.stdout.write(`\r  Scanning ${h} - ${batchEnd - 1}...`);

    const resp = await daemon.getBlocksByHeight(heights);
    if (!resp.success) {
      console.error(`\n  Failed at height ${h}:`, resp.error?.message);
      continue;
    }

    for (let bi = 0; bi < resp.result.blocks.length; bi++) {
      const block = resp.result.blocks[bi];
      const blockHeight = h + bi;

      // Parse block blob to get tx hashes
      let parsedBlock = null;
      try {
        const blockBlob = block.block instanceof Uint8Array
          ? block.block : new Uint8Array(block.block);
        parsedBlock = parseBlock(blockBlob);
      } catch (_e) {
        // Fall through — txHashes unavailable
      }

      // Parse user transactions
      const txBlobs = block.txs || [];
      for (let ti = 0; ti < txBlobs.length; ti++) {
        try {
          const txBytes = txBlobs[ti] instanceof Uint8Array ? txBlobs[ti] : hexToBytes(txBlobs[ti]);
          const tx = parseTransaction(txBytes);
          const txType = tx.prefix?.txType || 0;

          // Get tx hash from parsed block's txHashes array
          let txHash = '?';
          if (parsedBlock?.txHashes?.[ti]) {
            txHash = bytesToHex(parsedBlock.txHashes[ti]);
          }

          const amountBurnt = tx.prefix?.amount_burnt || 0n;
          const fee = tx.rct?.txnFee || 0n;
          const inputs = tx.prefix?.vin || [];
          const outputs = tx.prefix?.vout || [];
          const keyImages = inputs
            .filter(inp => inp.keyImage)
            .map(inp => bytesToHex(inp.keyImage));

          if (txType === TX_TYPE.STAKE) {
            stakes.push({
              txHash, height: blockHeight, amountBurnt, fee,
              inputCount: inputs.length, outputCount: outputs.length,
              keyImages
            });
          } else if (txType === TX_TYPE.PROTOCOL) {
            const amounts = outputs.map(o => o.amount || 0n);
            protocols.push({
              txHash, height: blockHeight,
              outputCount: outputs.length, amounts, amountBurnt
            });
          } else if (txType === TX_TYPE.BURN) {
            burns.push({ txHash, height: blockHeight, amountBurnt, fee });
          } else if (txType === TX_TYPE.CONVERT) {
            converts.push({ txHash, height: blockHeight, amountBurnt, fee });
          }
        } catch (e) {
          // Skip unparseable txs
        }
      }
    }
  }

  process.stdout.write('\r' + ' '.repeat(60) + '\r');

  // ─── Display Results ─────────────────────────────────────────────────────

  console.log(`${'═'.repeat(78)}`);
  console.log(`  ${BOLD}SCAN RESULTS${RESET}  blocks ${START_HEIGHT}–${endHeight - 1} (${endHeight - START_HEIGHT} blocks)`);
  console.log(`${'═'.repeat(78)}\n`);

  // Stakes
  if (stakes.length > 0) {
    console.log(`${GREEN}${BOLD}  STAKE TRANSACTIONS (${stakes.length})${RESET}`);
    console.log(`  ${'─'.repeat(74)}`);
    for (const s of stakes) {
      console.log(`  ${YELLOW}Block ${s.height}${RESET}  tx: ${CYAN}${truncHash(s.txHash, 20)}${RESET}`);
      console.log(`    Amount Staked:  ${BOLD}${fmtSAL(s.amountBurnt)} SAL1${RESET}  (locked in amount_burnt)`);
      console.log(`    Fee:           ${fmtSAL(s.fee)} SAL1`);
      console.log(`    Inputs:        ${s.inputCount} (spent to fund stake + change)`);
      console.log(`    Outputs:       ${s.outputCount} (change only — staked amount has no output)`);
      console.log(`    Key Images:    ${DIM}${s.keyImages.slice(0, 3).map(k => truncHash(k, 12)).join(', ')}${s.keyImages.length > 3 ? ` ... +${s.keyImages.length - 3} more` : ''}${RESET}`);
      console.log();
    }
  } else {
    console.log(`  ${DIM}No STAKE transactions found in range${RESET}\n`);
  }

  // Protocol (returns/yields)
  if (protocols.length > 0) {
    console.log(`${CYAN}${BOLD}  PROTOCOL TRANSACTIONS (${protocols.length})${RESET}  ${DIM}(yield payouts / stake returns)${RESET}`);
    console.log(`  ${'─'.repeat(74)}`);
    for (const p of protocols) {
      console.log(`  ${YELLOW}Block ${p.height}${RESET}  tx: ${CYAN}${truncHash(p.txHash, 20)}${RESET}`);
      console.log(`    Outputs:       ${p.outputCount}`);
      if (p.amountBurnt > 0n) {
        console.log(`    Amount Burnt:  ${fmtSAL(p.amountBurnt)} SAL1`);
      }
      console.log();
    }
  } else {
    console.log(`  ${DIM}No PROTOCOL transactions found in range${RESET}\n`);
  }

  // Burns
  if (burns.length > 0) {
    console.log(`${RED}${BOLD}  BURN TRANSACTIONS (${burns.length})${RESET}`);
    console.log(`  ${'─'.repeat(74)}`);
    for (const b of burns) {
      console.log(`  ${YELLOW}Block ${b.height}${RESET}  tx: ${CYAN}${truncHash(b.txHash, 20)}${RESET}`);
      console.log(`    Amount Burned: ${BOLD}${fmtSAL(b.amountBurnt)} SAL1${RESET}`);
      console.log(`    Fee:           ${fmtSAL(b.fee)} SAL1`);
      console.log();
    }
  }

  // Converts
  if (converts.length > 0) {
    console.log(`${BOLD}  CONVERT TRANSACTIONS (${converts.length})${RESET}`);
    console.log(`  ${'─'.repeat(74)}`);
    for (const c of converts) {
      console.log(`  ${YELLOW}Block ${c.height}${RESET}  tx: ${CYAN}${truncHash(c.txHash, 20)}${RESET}`);
      console.log(`    Amount Converted: ${BOLD}${fmtSAL(c.amountBurnt)} SAL1${RESET}`);
      console.log(`    Fee:              ${fmtSAL(c.fee)} SAL1`);
      console.log();
    }
  }

  // ─── Staking Lifecycle Summary ───────────────────────────────────────────

  if (stakes.length > 0 || protocols.length > 0) {
    console.log(`${'═'.repeat(78)}`);
    console.log(`  ${BOLD}STAKING LIFECYCLE${RESET}`);
    console.log(`${'═'.repeat(78)}\n`);

    console.log(`  ${DIM}How Salvium staking works on-chain:${RESET}`);
    console.log(`    1. ${GREEN}STAKE TX${RESET}  — User sends inputs; staked amount goes to ${BOLD}amount_burnt${RESET}`);
    console.log(`                    (not to any output). Only change is returned.`);
    console.log(`    2. ${DIM}Lock period${RESET} — Staked coins earn yield proportional to`);
    console.log(`                    (your_stake / total_locked) * block_slippage`);
    console.log(`    3. ${CYAN}PROTOCOL TX${RESET} — Daemon generates a payout TX returning`);
    console.log(`                    the original stake + accrued yield\n`);

    const totalStaked = stakes.reduce((sum, s) => sum + s.amountBurnt, 0n);
    const totalFees = stakes.reduce((sum, s) => sum + s.fee, 0n);
    console.log(`  ${BOLD}Summary for this range:${RESET}`);
    console.log(`    Total staked:     ${GREEN}${fmtSAL(totalStaked)} SAL1${RESET} across ${stakes.length} tx(s)`);
    console.log(`    Staking fees:     ${fmtSAL(totalFees)} SAL1`);
    console.log(`    Protocol returns: ${CYAN}${protocols.length}${RESET} tx(s) in range`);

    if (protocols.length === 0 && stakes.length > 0) {
      console.log(`\n  ${DIM}Tip: Stake returns may be beyond this range. Try --range 1000 or higher.${RESET}`);
    }
  }

  console.log();
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  const daemon = new DaemonRPC({ url: DAEMON_URL });

  if (TX_HASH_LOOKUP) {
    await lookupTx(daemon, TX_HASH_LOOKUP);
  } else {
    await scanBlocks(daemon);
  }
}

main().catch(e => {
  console.error('Fatal:', e.message);
  process.exit(1);
});
