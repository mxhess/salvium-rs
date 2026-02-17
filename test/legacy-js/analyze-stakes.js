#!/usr/bin/env bun
/**
 * Analyze stakes, returns, and yields from wallet sync
 *
 * Based on Salvium C++ wallet yield_info implementation:
 * - STAKE transactions (type 6) lock coins for STAKE_LOCK_PERIOD (21600 blocks)
 * - PROTOCOL transactions (type 2) return staked coins + yield
 * - Yield = return_amount - staked_amount
 */

import { createDaemonRPC } from '../src/rpc/index.js';
import { MemoryStorage } from '../src/wallet-store.js';
import { WalletSync } from '../src/wallet-sync.js';
import { deriveKeys, deriveCarrotKeys } from '../src/carrot.js';
import { hexToBytes, bytesToHex } from '../src/address.js';
import { generateCNSubaddressMap, generateCarrotSubaddressMap } from '../src/subaddress.js';
import { TX_TYPE } from '../src/wallet.js';

const MASTER_KEY = process.env.MASTER_KEY;
const START_HEIGHT = parseInt(process.env.START_HEIGHT || '0', 10);
const DAEMON_URL = process.env.DAEMON_URL || 'http://seed01.salvium.io:19081';
const STAKE_LOCK_PERIOD = 21600; // 30*24*30 blocks on mainnet

async function analyzeStakes() {
  console.log('=== Stake/Return/Yield Analysis ===\n');

  if (!MASTER_KEY) {
    console.error('ERROR: MASTER_KEY environment variable required.\n');
    console.log('Usage:');
    console.log('  MASTER_KEY="64-char-hex" bun test/analyze-stakes.js');
    console.log('  MASTER_KEY="hex" START_HEIGHT=190000 bun test/analyze-stakes.js');
    process.exit(1);
  }

  console.log(`Stake lock period: ${STAKE_LOCK_PERIOD} blocks\n`);

  // Derive keys
  const keys = deriveKeys(hexToBytes(MASTER_KEY));
  const carrotKeys = deriveCarrotKeys(keys.spendSecretKey);

  // Connect to daemon
  const daemon = createDaemonRPC({ url: DAEMON_URL, timeout: 30000 });
  const info = await daemon.getInfo();
  if (!info.success) {
    console.error('Failed to connect to daemon');
    process.exit(1);
  }
  const currentHeight = info.result.height;
  console.log(`Daemon height: ${currentHeight}\n`);

  // Generate subaddress maps
  console.log('Generating subaddress maps...');
  const cnSubaddresses = generateCNSubaddressMap(keys.spendPublicKey, keys.viewSecretKey, 50, 200);
  const carrotSubaddresses = generateCarrotSubaddressMap(
    hexToBytes(carrotKeys.accountSpendPubkey),
    hexToBytes(carrotKeys.accountViewPubkey),
    hexToBytes(carrotKeys.generateAddressSecret),
    50, 200
  );
  console.log(`  CN: ${cnSubaddresses.size}, CARROT: ${carrotSubaddresses.size}\n`);

  // Setup storage and sync
  const storage = new MemoryStorage();
  await storage.open();

  const sync = new WalletSync({
    storage,
    daemon,
    keys: {
      viewSecretKey: keys.viewSecretKey,
      spendPublicKey: keys.spendPublicKey,
      spendSecretKey: keys.spendSecretKey
    },
    carrotKeys: {
      viewIncomingKey: hexToBytes(carrotKeys.viewIncomingKey),
      accountSpendPubkey: hexToBytes(carrotKeys.accountSpendPubkey),
      generateImageKey: hexToBytes(carrotKeys.generateImageKey),
      generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret)
    },
    subaddresses: cnSubaddresses,
    carrotSubaddresses: carrotSubaddresses,
    batchSize: 200
  });

  // Progress reporting
  let lastHeight = START_HEIGHT;
  sync.on('syncProgress', (data) => {
    if (data.currentHeight - lastHeight >= 10000) {
      console.log(`  Syncing... height ${data.currentHeight}`);
      lastHeight = data.currentHeight;
    }
  });

  console.log(`Starting sync from height ${START_HEIGHT}...`);
  const startTime = Date.now();
  await sync.start(START_HEIGHT);
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`Sync completed in ${elapsed}s\n`);

  // Get all outputs and transactions
  const outputs = await storage.getOutputs();
  const transactions = await storage.getTransactions();

  console.log(`Total outputs: ${outputs.length}`);
  console.log(`Total transactions: ${transactions.length}\n`);

  // Categorize transactions by type
  const txByType = {
    miner: [],
    protocol: [],
    transfer: [],
    stake: [],
    return: [],
    convert: [],
    burn: [],
    audit: [],
    other: []
  };

  for (const tx of transactions) {
    const type = tx.txType;
    if (type === TX_TYPE.MINER || type === 'miner' || tx.isMinerTx) {
      txByType.miner.push(tx);
    } else if (type === TX_TYPE.PROTOCOL || type === 'protocol' || tx.isProtocolTx) {
      txByType.protocol.push(tx);
    } else if (type === TX_TYPE.STAKE || type === 6) {
      txByType.stake.push(tx);
    } else if (type === TX_TYPE.RETURN || type === 7) {
      txByType.return.push(tx);
    } else if (type === TX_TYPE.CONVERT || type === 4) {
      txByType.convert.push(tx);
    } else if (type === TX_TYPE.BURN || type === 5) {
      txByType.burn.push(tx);
    } else if (type === TX_TYPE.AUDIT || type === 8) {
      txByType.audit.push(tx);
    } else if (type === TX_TYPE.TRANSFER || type === 3) {
      txByType.transfer.push(tx);
    } else {
      txByType.other.push(tx);
    }
  }

  console.log('=== TRANSACTION BREAKDOWN ===\n');
  console.log(`  Miner (coinbase):  ${txByType.miner.length}`);
  console.log(`  Protocol (yields): ${txByType.protocol.length}`);
  console.log(`  Transfer:          ${txByType.transfer.length}`);
  console.log(`  Stake:             ${txByType.stake.length}`);
  console.log(`  Return:            ${txByType.return.length}`);
  console.log(`  Convert:           ${txByType.convert.length}`);
  console.log(`  Burn:              ${txByType.burn.length}`);
  console.log(`  Audit:             ${txByType.audit.length}`);
  console.log(`  Other/Unknown:     ${txByType.other.length}`);
  console.log('');

  // Group outputs by transaction
  const outputsByTx = new Map();
  for (const output of outputs) {
    if (!outputsByTx.has(output.txHash)) {
      outputsByTx.set(output.txHash, []);
    }
    outputsByTx.get(output.txHash).push(output);
  }

  // Find stake outputs - outputs with unlock_time = height + STAKE_LOCK_PERIOD
  const stakeOutputs = [];
  for (const output of outputs) {
    const unlockTime = Number(output.unlockTime || 0);
    if (unlockTime > 0) {
      const lockDuration = unlockTime - output.blockHeight;
      // Allow some tolerance (within 100 blocks of expected lock period)
      if (Math.abs(lockDuration - STAKE_LOCK_PERIOD) <= 100) {
        stakeOutputs.push({
          ...output,
          expectedUnlock: output.blockHeight + STAKE_LOCK_PERIOD,
          actualUnlock: unlockTime
        });
      }
    }
  }

  // Group outputs by height for return matching
  const outputsByHeight = new Map();
  for (const output of outputs) {
    if (!outputsByHeight.has(output.blockHeight)) {
      outputsByHeight.set(output.blockHeight, []);
    }
    outputsByHeight.get(output.blockHeight).push(output);
  }

  // Match stakes with returns
  console.log('=== STAKE ANALYSIS ===\n');
  console.log(`Found ${stakeOutputs.length} stake output(s)\n`);

  const stakeRecords = [];

  for (let i = 0; i < stakeOutputs.length; i++) {
    const stake = stakeOutputs[i];
    const stakeAmt = Number(stake.amount) / 1e8;
    const unlockHeight = stake.actualUnlock;

    // Look for return in protocol outputs at or near unlock height
    let returnOutput = null;
    let yieldAmount = 0n;

    // Check unlock height and a few blocks after
    for (let h = unlockHeight; h <= unlockHeight + 5; h++) {
      const candidates = outputsByHeight.get(h) || [];
      for (const candidate of candidates) {
        // Check if it's from a protocol tx
        const tx = transactions.find(t => t.txHash === candidate.txHash);
        if (tx && (tx.isProtocolTx || tx.txType === TX_TYPE.PROTOCOL || tx.txType === 'protocol')) {
          // Return should be >= stake amount (stake + yield)
          if (candidate.amount >= stake.amount) {
            returnOutput = candidate;
            yieldAmount = candidate.amount - stake.amount;
            break;
          }
        }
      }
      if (returnOutput) break;
    }

    const record = {
      index: i + 1,
      stakeHeight: stake.blockHeight,
      stakeAmount: stake.amount,
      unlockHeight: unlockHeight,
      stakeSpent: stake.isSpent,
      returnFound: !!returnOutput,
      returnHeight: returnOutput?.blockHeight || null,
      returnAmount: returnOutput?.amount || 0n,
      yieldAmount: yieldAmount,
      matured: currentHeight >= unlockHeight
    };
    stakeRecords.push(record);

    // Print stake info
    console.log(`Stake #${record.index}:`);
    console.log(`  Staked at block:     ${record.stakeHeight}`);
    console.log(`  Stake amount:        ${stakeAmt.toFixed(8)} SAL`);
    console.log(`  Unlocks at block:    ${record.unlockHeight}`);
    console.log(`  Maturity status:     ${record.matured ? 'MATURED' : `Matures in ${record.unlockHeight - currentHeight} blocks`}`);
    console.log(`  Stake output spent:  ${record.stakeSpent ? 'YES' : 'NO'}`);

    if (record.returnFound) {
      const returnAmt = Number(record.returnAmount) / 1e8;
      const yieldAmt = Number(record.yieldAmount) / 1e8;
      console.log(`  Return found:        YES (block ${record.returnHeight})`);
      console.log(`  Return amount:       ${returnAmt.toFixed(8)} SAL`);
      console.log(`  Yield earned:        ${yieldAmt.toFixed(8)} SAL`);
    } else {
      console.log(`  Return found:        NO`);
    }
    console.log('');
  }

  // Protocol transaction analysis (yields from staking network)
  console.log('=== PROTOCOL TRANSACTION OUTPUTS ===\n');

  const protocolOutputs = [];
  for (const output of outputs) {
    const tx = transactions.find(t => t.txHash === output.txHash);
    if (tx && (tx.isProtocolTx || tx.txType === TX_TYPE.PROTOCOL || tx.txType === 'protocol')) {
      protocolOutputs.push({ output, tx });
    }
  }

  console.log(`Total protocol tx outputs: ${protocolOutputs.length}\n`);

  let totalProtocolAmount = 0n;
  for (const { output } of protocolOutputs) {
    const amt = Number(output.amount) / 1e8;
    console.log(`  Height ${output.blockHeight}: ${amt.toFixed(8)} SAL (${output.isSpent ? 'SPENT' : 'UNSPENT'})`);
    totalProtocolAmount += output.amount;
  }

  // Summary
  console.log('\n=== SUMMARY ===\n');

  let totalStaked = 0n;
  let totalReturned = 0n;
  let totalYield = 0n;
  let activeStakes = 0;

  for (const record of stakeRecords) {
    totalStaked += record.stakeAmount;
    if (record.returnFound) {
      totalReturned += record.returnAmount;
      totalYield += record.yieldAmount;
    }
    if (!record.matured) {
      activeStakes++;
    }
  }

  console.log(`Stakes found:              ${stakeRecords.length}`);
  console.log(`Active (not matured):      ${activeStakes}`);
  console.log(`Total staked:              ${(Number(totalStaked) / 1e8).toFixed(8)} SAL`);
  console.log(`Total returned:            ${(Number(totalReturned) / 1e8).toFixed(8)} SAL`);
  console.log(`Total yield earned:        ${(Number(totalYield) / 1e8).toFixed(8)} SAL`);
  console.log(`Protocol tx total:         ${(Number(totalProtocolAmount) / 1e8).toFixed(8)} SAL`);

  // Current balance
  let unspentBalance = 0n;
  let unspentCount = 0;
  for (const o of outputs) {
    if (!o.isSpent) {
      unspentBalance += o.amount;
      unspentCount++;
    }
  }
  console.log(`\nCurrent balance:           ${(Number(unspentBalance) / 1e8).toFixed(8)} SAL (${unspentCount} unspent outputs)`);

  await storage.close();
}

analyzeStakes().catch(console.error);
