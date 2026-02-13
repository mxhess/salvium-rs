#!/usr/bin/env bun
/**
 * Salvium Block Privacy Extractor
 *
 * Extracts real cryptographic data from Salvium blocks to demonstrate
 * the privacy features of the blockchain. Shows what the public sees
 * (encrypted data, ring signatures, stealth addresses) vs what Bitcoin
 * would reveal (clear addresses, amounts).
 *
 * Usage:
 *   bun tools/block-privacy-extract.js [--daemon URL] [--height N] [--count N] [--format json|visual]
 */

import { DaemonRPC } from '../src/rpc/daemon.js';
import { parseTransaction } from '../src/transaction/parsing.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { TX_TYPE, RCT_TYPE, TXOUT_TYPE, TXIN_TYPE } from '../src/transaction/constants.js';

// ─── CLI Args ──────────────────────────────────────────────────────────────

const args = process.argv.slice(2);
function getArg(name, fallback) {
  const idx = args.indexOf(name);
  return idx >= 0 && args[idx + 1] ? args[idx + 1] : fallback;
}

const DAEMON_URL = getArg('--daemon', 'http://seed01.salvium.io:19081');
const START_HEIGHT = parseInt(getArg('--height', '0'), 10); // 0 = latest
const BLOCK_COUNT = parseInt(getArg('--count', '3'), 10);
const FORMAT = getArg('--format', 'visual'); // 'visual' or 'json'

// ─── Helpers ───────────────────────────────────────────────────────────────

const TX_TYPE_NAMES = Object.fromEntries(Object.entries(TX_TYPE).map(([k, v]) => [v, k]));
const RCT_TYPE_NAMES = Object.fromEntries(Object.entries(RCT_TYPE).map(([k, v]) => [v, k]));

function outTypeName(type) {
  if (type === 0x04) return 'CARROT_V1';
  if (type === 0x03) return 'TAGGED_KEY';
  if (type === 0x02) return 'KEY';
  return `0x${type.toString(16)}`;
}

function truncHex(hex, len = 16) {
  return hex; // Show full strings for commercial/demo use
}

function toHex(u8) {
  if (!u8) return '(null)';
  if (typeof u8 === 'string') return u8;
  return bytesToHex(u8);
}

function fmtBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024).toFixed(1)} KB`;
}

// ─── Data Extraction ───────────────────────────────────────────────────────

function extractTxPrivacyData(tx, txHash) {
  const p = tx.prefix || tx;
  const rct = tx.rct || {};

  // Inputs: key images + ring members
  const inputs = (p.vin || []).map((inp, i) => {
    if (inp.type === TXIN_TYPE.GEN) {
      return {
        index: i,
        type: 'coinbase',
        height: Number(inp.height || inp.amount || 0)
      };
    }
    return {
      index: i,
      type: 'key',
      keyImage: toHex(inp.keyImage),
      ringSize: inp.keyOffsets ? inp.keyOffsets.length : 0,
      ringOffsets: inp.keyOffsets || [],
      amount: '0 (hidden by RingCT)',
      assetType: inp.assetType || 'SAL'
    };
  });

  // Outputs: stealth addresses, view tags, encrypted amounts
  const outputs = (p.vout || []).map((out, i) => {
    const ecdhAmount = rct.ecdhInfo && rct.ecdhInfo[i]
      ? toHex(rct.ecdhInfo[i].amount)
      : null;
    const commitment = rct.outPk && rct.outPk[i]
      ? toHex(rct.outPk[i])
      : null;

    const o = {
      index: i,
      outputType: outTypeName(out.type),
      stealthAddress: toHex(out.key),
      amount: '(encrypted)',
      assetType: out.assetType || 'SAL'
    };

    if (out.viewTag !== undefined && out.viewTag !== null) {
      o.viewTag = typeof out.viewTag === 'number'
        ? `0x${out.viewTag.toString(16).padStart(2, '0')}`
        : toHex(out.viewTag);
    }
    if (out.encryptedJanusAnchor) {
      o.encryptedJanusAnchor = toHex(out.encryptedJanusAnchor);
    }
    if (ecdhAmount) o.encryptedAmount = ecdhAmount;
    if (commitment) o.pedersenCommitment = commitment;

    return o;
  });

  // Extra field: ephemeral keys
  const extra = {};
  if (p.extra) {
    for (const field of p.extra) {
      if (field.tag === 'tx_pubkey') {
        extra.ephemeralPubkey = toHex(field.key);
      } else if (field.tag === 'additional_pubkeys') {
        extra.additionalPubkeys = (field.keys || []).map(k => toHex(k));
      } else if (field.tag === 'nonce' && field.paymentId) {
        extra.encryptedPaymentId = toHex(field.paymentId);
      }
    }
  }

  // Ring signatures
  const ringSignatures = {};
  if (rct.CLSAGs && rct.CLSAGs.length > 0) {
    ringSignatures.type = 'CLSAG';
    ringSignatures.count = rct.CLSAGs.length;
    ringSignatures.sample = {
      s_responses: (rct.CLSAGs[0].s || []).map(s => toHex(s)),
      challenge_c1: toHex(rct.CLSAGs[0].c1),
      D: toHex(rct.CLSAGs[0].D)
    };
  } else if (rct.TCLSAGs && rct.TCLSAGs.length > 0) {
    ringSignatures.type = 'TCLSAG (Twin)';
    ringSignatures.count = rct.TCLSAGs.length;
    ringSignatures.sample = {
      sx_responses: (rct.TCLSAGs[0].sx || []).map(s => toHex(s)),
      sy_responses: (rct.TCLSAGs[0].sy || []).map(s => toHex(s)),
      challenge_c1: toHex(rct.TCLSAGs[0].c1),
      D: toHex(rct.TCLSAGs[0].D)
    };
  }

  // Range proofs
  const rangeProofs = {};
  if (rct.bulletproofPlus && rct.bulletproofPlus.length > 0) {
    const bp = rct.bulletproofPlus[0];
    rangeProofs.type = 'Bulletproof+';
    rangeProofs.count = rct.bulletproofPlus.length;
    rangeProofs.sample = {
      A: toHex(bp.A),
      A1: toHex(bp.A1),
      B: toHex(bp.B),
      r1: toHex(bp.r1),
      s1: toHex(bp.s1),
      d1: toHex(bp.d1),
      L_count: (bp.L || []).length,
      R_count: (bp.R || []).length
    };
    if (bp.L && bp.L.length > 0) {
      rangeProofs.sample.L = bp.L.map(v => toHex(v));
      rangeProofs.sample.R = bp.R.map(v => toHex(v));
    }
  }

  // Pseudo-outputs (input commitments)
  const pseudoOuts = (rct.pseudoOuts || []).map(p => toHex(p));

  return {
    txHash,
    txType: TX_TYPE_NAMES[p.txType] || `UNKNOWN(${p.txType})`,
    rctType: RCT_TYPE_NAMES[rct.type] || `UNKNOWN(${rct.type})`,
    fee: rct.txnFee ? `${Number(rct.txnFee)} atomic` : '0 (coinbase)',
    version: p.version,
    inputCount: inputs.length,
    outputCount: outputs.length,
    inputs,
    outputs,
    extra,
    ringSignatures,
    rangeProofs,
    pseudoOuts,
    // Salvium-specific
    ...(p.amount_burnt ? { amountBurnt: `${p.amount_burnt} (hidden)` } : {}),
    ...(p.source_asset_type ? { sourceAsset: p.source_asset_type } : {}),
    ...(p.destination_asset_type ? { destAsset: p.destination_asset_type } : {})
  };
}

// ─── Visual Formatting ────────────────────────────────────────────────────

const DIM = '\x1b[2m';
const CYAN = '\x1b[36m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const MAGENTA = '\x1b[35m';
const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';

function printVisual(blockData, txDataList) {
  const hdr = blockData.header;

  console.log(`\n${BOLD}${CYAN}${'═'.repeat(80)}${RESET}`);
  console.log(`${BOLD}${CYAN}  BLOCK ${hdr.height}${RESET}  ${DIM}hash: ${hdr.hash}${RESET}`);
  console.log(`${DIM}  timestamp: ${new Date(hdr.timestamp * 1000).toISOString()}  |  txns: ${hdr.num_txes}  |  reward: ${(hdr.reward / 1e8).toFixed(8)} SAL${RESET}`);
  console.log(`${CYAN}${'─'.repeat(80)}${RESET}`);

  for (const txd of txDataList) {
    console.log(`\n  ${BOLD}TX ${truncHex(txd.txHash, 20)}${RESET}`);
    // Infer era from RCT type
    const era = txd.rctType === 'SalviumOne' ? 'CARROT'
      : txd.rctType === 'SalviumZero' ? 'SAL1'
      : txd.rctType === 'FullProofs' ? 'HF3-5'
      : txd.rctType === 'BulletproofPlus' ? 'HF1-2'
      : '';
    const eraTag = era ? `  era: ${CYAN}${era}${RESET}${DIM}` : '';
    console.log(`  ${DIM}type: ${YELLOW}${txd.txType}${RESET}${DIM}  rct: ${txd.rctType}${eraTag}  fee: ${txd.fee}${RESET}`);

    // --- Inputs ---
    if (txd.inputs.length > 0) {
      console.log(`\n  ${GREEN}INPUTS (${txd.inputs.length})${RESET}  ${DIM}— what was spent (hidden by ring signatures)${RESET}`);
      for (const inp of txd.inputs) {
        if (inp.type === 'coinbase') {
          console.log(`    ${DIM}[${inp.index}]${RESET} coinbase (block reward, height ${inp.height})`);
        } else {
          console.log(`    ${DIM}[${inp.index}]${RESET} ${RED}Key Image:${RESET} ${DIM}${truncHex(inp.keyImage, 24)}${RESET}`);
          console.log(`         ${DIM}Ring size: ${YELLOW}${inp.ringSize} decoys${RESET}${DIM} — observer cannot determine real input${RESET}`);
          if (inp.ringOffsets.length > 0) {
            const offsets = inp.ringOffsets.slice(0, 6).join(', ');
            const more = inp.ringOffsets.length > 6 ? `, ... +${inp.ringOffsets.length - 6} more` : '';
            console.log(`         ${DIM}Ring offsets: [${offsets}${more}]${RESET}`);
          }
        }
      }
    }

    // --- Outputs ---
    if (txd.outputs.length > 0) {
      console.log(`\n  ${MAGENTA}OUTPUTS (${txd.outputs.length})${RESET}  ${DIM}— recipient addresses (stealth, one-time use)${RESET}`);
      for (const out of txd.outputs) {
        console.log(`    ${DIM}[${out.index}]${RESET} ${BOLD}${out.outputType}${RESET} ${DIM}(${out.assetType})${RESET}`);
        console.log(`         Stealth Address: ${CYAN}${truncHex(out.stealthAddress, 24)}${RESET}`);
        if (out.viewTag) {
          const vtSize = out.outputType === 'CARROT_V1' ? '3-byte' : '1-byte';
          console.log(`         View Tag:        ${YELLOW}${out.viewTag}${RESET}  ${DIM}(${vtSize} scan filter — reveals nothing about recipient)${RESET}`);
        }
        if (out.encryptedJanusAnchor) {
          console.log(`         Janus Anchor:    ${RED}${truncHex(out.encryptedJanusAnchor, 16)}${RESET}  ${DIM}(encrypted verification data)${RESET}`);
        }
        if (out.encryptedAmount) {
          console.log(`         Encrypted Amt:   ${RED}${out.encryptedAmount}${RESET}  ${DIM}(8 bytes, only recipient can decrypt)${RESET}`);
        }
        if (out.pedersenCommitment) {
          console.log(`         Commitment:      ${DIM}${truncHex(out.pedersenCommitment, 24)}${RESET}  ${DIM}(Pedersen: hides amount, proves validity)${RESET}`);
        }
      }
    }

    // --- Ephemeral Keys ---
    if (txd.extra.ephemeralPubkey) {
      console.log(`\n  ${YELLOW}EPHEMERAL KEY${RESET}  ${DIM}— Diffie-Hellman exchange (one-time, unlinkable)${RESET}`);
      console.log(`    tx_pubkey: ${DIM}${txd.extra.ephemeralPubkey}${RESET}`);
      if (txd.extra.additionalPubkeys && txd.extra.additionalPubkeys.length > 0) {
        console.log(`    + ${txd.extra.additionalPubkeys.length} additional pubkeys (for subaddresses)`);
      }
    }

    // --- Ring Signatures ---
    if (txd.ringSignatures.type) {
      console.log(`\n  ${RED}RING SIGNATURES (${txd.ringSignatures.type})${RESET}  ${DIM}— proves authorization without revealing signer${RESET}`);
      console.log(`    ${txd.ringSignatures.count} signature(s)`);
      const sig = txd.ringSignatures.sample;
      if (sig.s_responses) {
        console.log(`    Challenge c₁:  ${DIM}${truncHex(sig.challenge_c1, 24)}${RESET}`);
        console.log(`    Responses (${sig.s_responses.length}):`);
        for (let i = 0; i < sig.s_responses.length; i++) {
          console.log(`      s[${i.toString().padStart(2)}]: ${DIM}${truncHex(sig.s_responses[i], 24)}${RESET}`);
        }
        console.log(`    D (linking tag): ${DIM}${truncHex(sig.D, 24)}${RESET}`);
      }
      if (sig.sx_responses) {
        console.log(`    Challenge c₁:  ${DIM}${truncHex(sig.challenge_c1, 24)}${RESET}`);
        console.log(`    Twin responses X (${sig.sx_responses.length}):`);
        for (let i = 0; i < sig.sx_responses.length; i++) {
          console.log(`      sx[${i.toString().padStart(2)}]: ${DIM}${truncHex(sig.sx_responses[i], 24)}${RESET}`);
        }
        console.log(`    Twin responses Y (${sig.sy_responses.length}):`);
        for (let i = 0; i < sig.sy_responses.length; i++) {
          console.log(`      sy[${i.toString().padStart(2)}]: ${DIM}${truncHex(sig.sy_responses[i], 24)}${RESET}`);
        }
      }
    }

    // --- Range Proofs ---
    if (txd.rangeProofs.type) {
      console.log(`\n  ${GREEN}RANGE PROOFS (${txd.rangeProofs.type})${RESET}  ${DIM}— proves amounts are valid (0..2⁶⁴) without revealing them${RESET}`);
      const rp = txd.rangeProofs.sample;
      console.log(`    ${txd.rangeProofs.count} proof(s), ${rp.L_count} inner product rounds each`);
      console.log(`    A:  ${DIM}${truncHex(rp.A, 24)}${RESET}`);
      console.log(`    A1: ${DIM}${truncHex(rp.A1, 24)}${RESET}`);
      console.log(`    B:  ${DIM}${truncHex(rp.B, 24)}${RESET}`);
      if (rp.L && rp.L.length > 0) {
        for (let i = 0; i < rp.L.length; i++) {
          console.log(`    L[${i}]: ${DIM}${truncHex(rp.L[i], 24)}${RESET}`);
          console.log(`    R[${i}]: ${DIM}${truncHex(rp.R[i], 24)}${RESET}`);
        }
      }
      console.log(`    r1: ${DIM}${truncHex(rp.r1, 24)}${RESET}`);
      console.log(`    s1: ${DIM}${truncHex(rp.s1, 24)}${RESET}`);
    }

    // --- Pseudo-outputs ---
    if (txd.pseudoOuts.length > 0) {
      console.log(`\n  ${DIM}PSEUDO-OUTPUTS (${txd.pseudoOuts.length}) — input commitments (balance proof)${RESET}`);
      for (const po of txd.pseudoOuts) {
        console.log(`    ${DIM}${truncHex(po, 24)}${RESET}`);
      }
    }
  }

  console.log(`\n${CYAN}${'═'.repeat(80)}${RESET}\n`);
}

function printComparison() {
  console.log(`\n${BOLD}${YELLOW}  SALVIUM vs BITCOIN — What the public sees${RESET}\n`);
  console.log(`  ${'─'.repeat(72)}`);
  console.log(`  ${BOLD}Field${RESET}                  ${BOLD}Bitcoin${RESET}                    ${BOLD}Salvium${RESET}`);
  console.log(`  ${'─'.repeat(72)}`);
  console.log(`  Sender address       ${RED}VISIBLE${RESET} (input scripts)       ${GREEN}HIDDEN${RESET} (ring sigs, 16 decoys)`);
  console.log(`  Recipient address    ${RED}VISIBLE${RESET} (output scripts)      ${GREEN}HIDDEN${RESET} (stealth addresses)`);
  console.log(`  Amount transferred   ${RED}VISIBLE${RESET} (plaintext satoshi)   ${GREEN}ENCRYPTED${RESET} (RingCT + Pedersen)`);
  console.log(`  Transaction linkage  ${RED}TRACEABLE${RESET} (UTXO graph)        ${GREEN}UNLINKABLE${RESET} (key images)`);
  console.log(`  Address reuse        ${RED}COMMON${RESET} (same addr visible)    ${GREEN}IMPOSSIBLE${RESET} (one-time keys)`);
  console.log(`  Balance              ${RED}COMPUTABLE${RESET} (sum UTXOs)         ${GREEN}HIDDEN${RESET} (only owner knows)`);
  console.log(`  Tx graph analysis    ${RED}POSSIBLE${RESET} (chain analysis)     ${GREEN}DEFEATED${RESET} (ring + stealth + CT)`);
  console.log(`  ${'─'.repeat(72)}\n`);
}

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  const daemon = new DaemonRPC({ url: DAEMON_URL });

  // Get chain height
  const info = await daemon.getInfo();
  if (!info.success) {
    console.error('Failed to connect to daemon:', info.error?.message || 'unknown error');
    console.error('URL:', DAEMON_URL);
    process.exit(1);
  }

  const chainHeight = info.result.height;
  const startAt = START_HEIGHT > 0 ? START_HEIGHT : Math.max(1, chainHeight - BLOCK_COUNT);

  const log = FORMAT === 'json' ? console.error : console.log;
  log(`${BOLD}Salvium Block Privacy Extractor${RESET}`);
  log(`${DIM}Daemon: ${DAEMON_URL}  Chain height: ${chainHeight}${RESET}`);
  log(`${DIM}Extracting blocks ${startAt} to ${startAt + BLOCK_COUNT - 1}...${RESET}`);

  if (FORMAT === 'visual') {
    printComparison();
  }

  const allBlocks = [];
  const allVisualBlocks = []; // for summary stats

  for (let h = startAt; h < startAt + BLOCK_COUNT && h < chainHeight; h++) {
    // Fetch block header + blob
    const blockResp = await daemon.getBlock({ height: h });
    if (!blockResp.success) {
      console.error(`Failed to fetch block ${h}:`, blockResp.error?.message);
      continue;
    }

    const block = blockResp.result;
    const hdr = block.block_header;
    const txDataList = [];

    // Parse the miner transaction from the block blob
    try {
      const blockBlob = hexToBytes(block.blob);
      const parsed = (await import('../src/transaction/parsing.js')).parseBlock(blockBlob);

      if (parsed.minerTx) {
        txDataList.push(extractTxPrivacyData(parsed.minerTx, hdr.miner_tx_hash));
      }
      if (parsed.protocolTx && parsed.protocolTx.prefix && parsed.protocolTx.prefix.vout && parsed.protocolTx.prefix.vout.length > 0) {
        txDataList.push(extractTxPrivacyData(parsed.protocolTx, hdr.protocol_tx_hash || 'protocol_tx'));
      }
    } catch (e) {
      console.error(`  ${DIM}(block blob parse failed: ${e.message})${RESET}`);
    }

    // Fetch user transactions from the block
    const userTxHashes = block.tx_hashes || [];
    if (userTxHashes.length > 0) {
      const txResp = await daemon.getTransactions(userTxHashes);
      if (txResp.success && txResp.result.txs) {
        for (const txEntry of txResp.result.txs) {
          try {
            const txData = hexToBytes(txEntry.as_hex);
            const parsed = parseTransaction(txData);
            txDataList.push(extractTxPrivacyData(parsed, txEntry.tx_hash));
          } catch (e) {
            console.error(`  ${DIM}(tx parse failed: ${e.message})${RESET}`);
          }
        }
      }
    }

    if (FORMAT === 'json') {
      allBlocks.push({
        height: hdr.height,
        hash: hdr.hash,
        timestamp: hdr.timestamp,
        reward: hdr.reward,
        numTxes: hdr.num_txes,
        transactions: txDataList
      });
    } else {
      allVisualBlocks.push(txDataList);
      printVisual({ header: hdr }, txDataList);
    }
  }

  if (FORMAT === 'json') {
    console.log(JSON.stringify(allBlocks, null, 2));
  }

  // Summary — data-driven from what was actually extracted
  if (FORMAT === 'visual') {
    const stats = { blocks: 0, carrot: 0, tagged: 0, legacy: 0, clsag: 0, tclsag: 0, rctTypes: new Set() };
    for (const blk of allVisualBlocks) {
      stats.blocks++;
      for (const tx of blk) {
        if (tx.rctType !== 'Null') stats.rctTypes.add(tx.rctType);
        if (tx.ringSignatures.type === 'CLSAG') stats.clsag += tx.ringSignatures.count || 0;
        if (tx.ringSignatures.type === 'TCLSAG (Twin)') stats.tclsag += tx.ringSignatures.count || 0;
        for (const out of tx.outputs) {
          if (out.outputType === 'CARROT_V1') stats.carrot++;
          else if (out.outputType === 'TAGGED_KEY') stats.tagged++;
          else stats.legacy++;
        }
      }
    }

    const ringSigType = stats.tclsag > 0 && stats.clsag > 0 ? 'CLSAG + TCLSAG'
      : stats.tclsag > 0 ? 'TCLSAG (Twin)' : 'CLSAG';

    console.log(`${BOLD}${CYAN}  SUMMARY${RESET}`);
    console.log(`  ${DIM}Blocks extracted: ${stats.blocks}  |  Daemon: ${DAEMON_URL}${RESET}`);
    console.log(`  ${DIM}Every output uses a unique stealth address — no address reuse possible${RESET}`);
    console.log(`  ${DIM}Every amount is encrypted with Pedersen commitments + Bulletproof+ proofs${RESET}`);
    console.log(`  ${DIM}Every input is hidden among 16 decoys via ${ringSigType} ring signatures${RESET}`);
    if (stats.carrot > 0) {
      console.log(`  ${DIM}CARROT outputs (${stats.carrot}): 3-byte view tags + encrypted Janus anchors${RESET}`);
    }
    if (stats.tagged > 0) {
      console.log(`  ${DIM}Tagged-key outputs (${stats.tagged}): 1-byte view tags + stealth keys${RESET}`);
    }
    if (stats.legacy > 0) {
      console.log(`  ${DIM}Legacy key outputs (${stats.legacy}): stealth keys only${RESET}`);
    }
    if (stats.rctTypes.size > 0) {
      console.log(`  ${DIM}RCT types seen: ${[...stats.rctTypes].join(', ')}${RESET}`);
    }
    console.log();
  }
}

main().catch(err => {
  console.error('Fatal:', err.message);
  process.exit(1);
});
