#!/usr/bin/env bun
/**
 * StakeRecord Lifecycle Tests
 *
 * Tests for stake lifecycle tracking:
 * - StakeRecord model (constructor, BigInt handling, toJSON/fromJSON)
 * - WalletOutput isReturn/returnOriginKey fields
 * - MemoryStorage stake operations (CRUD, queries, reorg rollback)
 * - Storage dump/load roundtrip (v1 backward compat, v2 with stakes)
 * - _extractReturnPubkey (pre-CARROT, CARROT, missing)
 * - _recordStakeLifecycle (STAKE recording, PROTOCOL return matching)
 */

import {
  WalletOutput,
  WalletTransaction,
  StakeRecord,
  MemoryStorage
} from '../src/wallet-store.js';
import { WalletSync } from '../src/wallet-sync.js';
import { TX_TYPE } from '../src/transaction/constants.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

async function testAsync(name, fn) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message || 'Assertion failed');
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected ${expected}, got ${actual}`);
  }
}

console.log('=== StakeRecord Lifecycle Tests ===\n');

// ============================================================================
// StakeRecord Model Tests
// ============================================================================

console.log('--- StakeRecord Model ---');

test('creates StakeRecord with default values', () => {
  const sr = new StakeRecord();
  assertEqual(sr.stakeTxHash, null);
  assertEqual(sr.stakeHeight, null);
  assertEqual(sr.stakeTimestamp, null);
  assertEqual(sr.amountStaked, 0n);
  assertEqual(sr.fee, 0n);
  assertEqual(sr.assetType, 'SAL');
  assertEqual(sr.changeOutputKey, null);
  assertEqual(sr.status, 'locked');
  assertEqual(sr.returnTxHash, null);
  assertEqual(sr.returnHeight, null);
  assertEqual(sr.returnTimestamp, null);
  assertEqual(sr.returnAmount, 0n);
});

test('creates StakeRecord with provided values', () => {
  const sr = new StakeRecord({
    stakeTxHash: 'abc123',
    stakeHeight: 417082,
    stakeTimestamp: 1700000000,
    amountStaked: 130130000000000n,
    fee: 50000000n,
    assetType: 'SAL',
    changeOutputKey: 'pubkey_hex_abc',
    status: 'returned',
    returnTxHash: 'def456',
    returnHeight: 417200,
    returnTimestamp: 1700014000,
    returnAmount: 130200000000000n
  });
  assertEqual(sr.stakeTxHash, 'abc123');
  assertEqual(sr.stakeHeight, 417082);
  assertEqual(sr.amountStaked, 130130000000000n);
  assertEqual(sr.fee, 50000000n);
  assertEqual(sr.changeOutputKey, 'pubkey_hex_abc');
  assertEqual(sr.status, 'returned');
  assertEqual(sr.returnTxHash, 'def456');
  assertEqual(sr.returnHeight, 417200);
  assertEqual(sr.returnAmount, 130200000000000n);
});

test('amountStaked accepts number and converts to BigInt', () => {
  const sr = new StakeRecord({ amountStaked: 1000 });
  assertEqual(sr.amountStaked, 1000n);
});

test('amountStaked accepts string and converts to BigInt', () => {
  const sr = new StakeRecord({ amountStaked: '130130000000000' });
  assertEqual(sr.amountStaked, 130130000000000n);
});

test('fee accepts number and converts to BigInt', () => {
  const sr = new StakeRecord({ fee: 50000000 });
  assertEqual(sr.fee, 50000000n);
});

test('returnAmount accepts string and converts to BigInt', () => {
  const sr = new StakeRecord({ returnAmount: '130200000000000' });
  assertEqual(sr.returnAmount, 130200000000000n);
});

test('toJSON serializes BigInts as strings', () => {
  const sr = new StakeRecord({
    stakeTxHash: 'abc',
    amountStaked: 130130000000000n,
    fee: 50000000n,
    returnAmount: 130200000000000n
  });
  const json = sr.toJSON();
  assertEqual(json.stakeTxHash, 'abc');
  assertEqual(json.amountStaked, '130130000000000');
  assertEqual(json.fee, '50000000');
  assertEqual(json.returnAmount, '130200000000000');
  assertEqual(typeof json.amountStaked, 'string');
});

test('fromJSON deserializes correctly', () => {
  const json = {
    stakeTxHash: 'xyz',
    stakeHeight: 1000,
    amountStaked: '999999999999999',
    fee: '100000',
    returnAmount: '1000000000000000',
    status: 'returned',
    changeOutputKey: 'some_key'
  };
  const sr = StakeRecord.fromJSON(json);
  assertEqual(sr.stakeTxHash, 'xyz');
  assertEqual(sr.stakeHeight, 1000);
  assertEqual(sr.amountStaked, 999999999999999n);
  assertEqual(sr.fee, 100000n);
  assertEqual(sr.returnAmount, 1000000000000000n);
  assertEqual(sr.status, 'returned');
  assertEqual(sr.changeOutputKey, 'some_key');
});

test('round-trip JSON serialization preserves all fields', () => {
  const original = new StakeRecord({
    stakeTxHash: 'roundtrip_hash',
    stakeHeight: 500000,
    stakeTimestamp: 1700000000,
    amountStaked: 123456789012345678901234n,
    fee: 999999999999n,
    assetType: 'SAL',
    changeOutputKey: 'change_key_hex',
    status: 'returned',
    returnTxHash: 'return_hash',
    returnHeight: 500100,
    returnTimestamp: 1700012000,
    returnAmount: 123500000000000000000000n
  });
  const json = original.toJSON();
  const restored = StakeRecord.fromJSON(json);
  assertEqual(restored.stakeTxHash, original.stakeTxHash);
  assertEqual(restored.stakeHeight, original.stakeHeight);
  assertEqual(restored.stakeTimestamp, original.stakeTimestamp);
  assertEqual(restored.amountStaked, original.amountStaked);
  assertEqual(restored.fee, original.fee);
  assertEqual(restored.assetType, original.assetType);
  assertEqual(restored.changeOutputKey, original.changeOutputKey);
  assertEqual(restored.status, original.status);
  assertEqual(restored.returnTxHash, original.returnTxHash);
  assertEqual(restored.returnHeight, original.returnHeight);
  assertEqual(restored.returnTimestamp, original.returnTimestamp);
  assertEqual(restored.returnAmount, original.returnAmount);
});

// ============================================================================
// WalletOutput isReturn / returnOriginKey Tests
// ============================================================================

console.log('\n--- WalletOutput isReturn / returnOriginKey ---');

test('WalletOutput defaults isReturn to false and returnOriginKey to null', () => {
  const output = new WalletOutput();
  assertEqual(output.isReturn, false);
  assertEqual(output.returnOriginKey, null);
});

test('WalletOutput accepts isReturn and returnOriginKey', () => {
  const output = new WalletOutput({
    keyImage: 'ki_1',
    isReturn: true,
    returnOriginKey: 'origin_key_abc'
  });
  assertEqual(output.isReturn, true);
  assertEqual(output.returnOriginKey, 'origin_key_abc');
});

test('WalletOutput toJSON includes isReturn and returnOriginKey', () => {
  const output = new WalletOutput({
    keyImage: 'ki_2',
    isReturn: true,
    returnOriginKey: 'origin_key_def'
  });
  const json = output.toJSON();
  assertEqual(json.isReturn, true);
  assertEqual(json.returnOriginKey, 'origin_key_def');
});

test('WalletOutput fromJSON preserves isReturn and returnOriginKey', () => {
  const json = {
    keyImage: 'ki_3',
    amount: '1000',
    unlockTime: '0',
    isReturn: true,
    returnOriginKey: 'origin_key_ghi'
  };
  const output = WalletOutput.fromJSON(json);
  assertEqual(output.isReturn, true);
  assertEqual(output.returnOriginKey, 'origin_key_ghi');
});

test('WalletOutput round-trip preserves return fields', () => {
  const original = new WalletOutput({
    keyImage: 'ki_4',
    isReturn: true,
    returnOriginKey: 'roundtrip_origin_key'
  });
  const restored = WalletOutput.fromJSON(original.toJSON());
  assertEqual(restored.isReturn, original.isReturn);
  assertEqual(restored.returnOriginKey, original.returnOriginKey);
});

// ============================================================================
// MemoryStorage Stake Operations
// ============================================================================

console.log('\n--- MemoryStorage Stake Operations ---');

await testAsync('putStake and getStake work', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const sr = new StakeRecord({
    stakeTxHash: 'stake_tx_1',
    stakeHeight: 1000,
    amountStaked: 100000000000n,
    changeOutputKey: 'change_key_1'
  });

  await storage.putStake(sr);
  const retrieved = await storage.getStake('stake_tx_1');

  assertEqual(retrieved.stakeTxHash, 'stake_tx_1');
  assertEqual(retrieved.stakeHeight, 1000);
  assertEqual(retrieved.amountStaked, 100000000000n);
  assertEqual(retrieved.changeOutputKey, 'change_key_1');
  assertEqual(retrieved.status, 'locked');

  await storage.close();
});

await testAsync('getStake returns null for nonexistent hash', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  const result = await storage.getStake('nonexistent');
  assertEqual(result, null);

  await storage.close();
});

await testAsync('getStakeByOutputKey returns matching stake', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({
    stakeTxHash: 'stake_tx_2',
    changeOutputKey: 'output_key_abc'
  }));

  const result = await storage.getStakeByOutputKey('output_key_abc');
  assertEqual(result.stakeTxHash, 'stake_tx_2');

  const noResult = await storage.getStakeByOutputKey('nonexistent_key');
  assertEqual(noResult, null);

  await storage.close();
});

await testAsync('getStakes returns all stakes', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({ stakeTxHash: 'st1', status: 'locked' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st2', status: 'returned' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st3', status: 'locked' }));

  const all = await storage.getStakes();
  assertEqual(all.length, 3);

  await storage.close();
});

await testAsync('getStakes filters by status', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({ stakeTxHash: 'st1', status: 'locked' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st2', status: 'returned' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st3', status: 'locked' }));

  const locked = await storage.getStakes({ status: 'locked' });
  assertEqual(locked.length, 2);

  const returned = await storage.getStakes({ status: 'returned' });
  assertEqual(returned.length, 1);
  assertEqual(returned[0].stakeTxHash, 'st2');

  await storage.close();
});

await testAsync('getStakes filters by assetType', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({ stakeTxHash: 'st1', assetType: 'SAL' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st2', assetType: 'USD' }));

  const sal = await storage.getStakes({ assetType: 'SAL' });
  assertEqual(sal.length, 1);
  assertEqual(sal[0].stakeTxHash, 'st1');

  await storage.close();
});

await testAsync('markStakeReturned updates stake fields', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({
    stakeTxHash: 'stake_mark',
    amountStaked: 100000000000n,
    status: 'locked'
  }));

  await storage.markStakeReturned('stake_mark', {
    returnTxHash: 'return_tx',
    returnHeight: 2000,
    returnTimestamp: 1700020000,
    returnAmount: 101000000000n
  });

  const updated = await storage.getStake('stake_mark');
  assertEqual(updated.status, 'returned');
  assertEqual(updated.returnTxHash, 'return_tx');
  assertEqual(updated.returnHeight, 2000);
  assertEqual(updated.returnTimestamp, 1700020000);
  assertEqual(updated.returnAmount, 101000000000n);

  await storage.close();
});

await testAsync('markStakeReturned is no-op for nonexistent stake', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  // Should not throw
  await storage.markStakeReturned('nonexistent', {
    returnTxHash: 'ret',
    returnHeight: 100,
    returnTimestamp: 1700000000,
    returnAmount: 0n
  });

  await storage.close();
});

await testAsync('deleteStakesAbove removes stakes above height', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({ stakeTxHash: 'st_low', stakeHeight: 100, changeOutputKey: 'k1' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st_mid', stakeHeight: 200, changeOutputKey: 'k2' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st_high', stakeHeight: 300, changeOutputKey: 'k3' }));

  await storage.deleteStakesAbove(150);

  const remaining = await storage.getStakes();
  assertEqual(remaining.length, 1);
  assertEqual(remaining[0].stakeTxHash, 'st_low');

  // Output key index should also be cleaned up
  const lookupDeleted = await storage.getStakeByOutputKey('k2');
  assertEqual(lookupDeleted, null);
  const lookupRemaining = await storage.getStakeByOutputKey('k1');
  assertEqual(lookupRemaining.stakeTxHash, 'st_low');

  await storage.close();
});

await testAsync('deleteStakesAbove reverts returned stakes to locked if returnHeight > cutoff', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({
    stakeTxHash: 'st_returned',
    stakeHeight: 100,
    status: 'locked'
  }));
  await storage.markStakeReturned('st_returned', {
    returnTxHash: 'ret_tx',
    returnHeight: 250,
    returnTimestamp: 1700025000,
    returnAmount: 105000000000n
  });

  // Verify it's returned
  let stake = await storage.getStake('st_returned');
  assertEqual(stake.status, 'returned');
  assertEqual(stake.returnAmount, 105000000000n);

  // Reorg: rollback to height 200 — the return at 250 should be undone
  await storage.deleteStakesAbove(200);

  stake = await storage.getStake('st_returned');
  assertEqual(stake.status, 'locked');
  assertEqual(stake.returnTxHash, null);
  assertEqual(stake.returnHeight, null);
  assertEqual(stake.returnAmount, 0n);

  await storage.close();
});

await testAsync('clear removes all stakes', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({ stakeTxHash: 'st1', changeOutputKey: 'k1' }));
  await storage.putStake(new StakeRecord({ stakeTxHash: 'st2', changeOutputKey: 'k2' }));

  await storage.clear();

  const stakes = await storage.getStakes();
  assertEqual(stakes.length, 0);

  const lookup = await storage.getStakeByOutputKey('k1');
  assertEqual(lookup, null);

  await storage.close();
});

// ============================================================================
// Storage dump/load Roundtrip
// ============================================================================

console.log('\n--- Storage dump/load Roundtrip ---');

await testAsync('dump includes stakes array', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({
    stakeTxHash: 'dump_stake',
    amountStaked: 50000000000n,
    changeOutputKey: 'dump_key'
  }));

  const data = storage.dump();
  assertEqual(data.version, 2);
  assertEqual(data.stakes.length, 1);
  assertEqual(data.stakes[0].stakeTxHash, 'dump_stake');
  assertEqual(data.stakes[0].amountStaked, '50000000000');

  await storage.close();
});

await testAsync('load restores stakes from dump', async () => {
  const storage1 = new MemoryStorage();
  await storage1.open();

  await storage1.putStake(new StakeRecord({
    stakeTxHash: 'load_stake',
    stakeHeight: 500,
    amountStaked: 75000000000n,
    changeOutputKey: 'load_key',
    status: 'returned',
    returnTxHash: 'load_return',
    returnHeight: 600,
    returnAmount: 76000000000n
  }));

  const data = storage1.dump();

  const storage2 = new MemoryStorage();
  await storage2.open();
  storage2.load(data);

  const stake = await storage2.getStake('load_stake');
  assertEqual(stake.stakeTxHash, 'load_stake');
  assertEqual(stake.stakeHeight, 500);
  assertEqual(stake.amountStaked, 75000000000n);
  assertEqual(stake.status, 'returned');
  assertEqual(stake.returnTxHash, 'load_return');
  assertEqual(stake.returnAmount, 76000000000n);

  // Output key index should also be restored
  const byKey = await storage2.getStakeByOutputKey('load_key');
  assertEqual(byKey.stakeTxHash, 'load_stake');

  await storage1.close();
  await storage2.close();
});

await testAsync('dumpJSON includes stakes', async () => {
  const storage = new MemoryStorage();
  await storage.open();

  await storage.putStake(new StakeRecord({
    stakeTxHash: 'json_stake',
    amountStaked: 25000000000n
  }));

  const jsonStr = storage.dumpJSON();
  const parsed = JSON.parse(jsonStr);
  assertEqual(parsed.version, 2);
  assertEqual(parsed.stakes.length, 1);
  assertEqual(parsed.stakes[0].stakeTxHash, 'json_stake');
  assertEqual(parsed.stakes[0].amountStaked, '25000000000');

  await storage.close();
});

await testAsync('dumpJSON roundtrip through load', async () => {
  const storage1 = new MemoryStorage();
  await storage1.open();

  await storage1.putStake(new StakeRecord({
    stakeTxHash: 'json_rt',
    amountStaked: 99000000000n,
    changeOutputKey: 'json_rt_key'
  }));

  const jsonStr = storage1.dumpJSON();
  const parsed = JSON.parse(jsonStr);

  const storage2 = new MemoryStorage();
  await storage2.open();
  storage2.load(parsed);

  const stake = await storage2.getStake('json_rt');
  assertEqual(stake.amountStaked, 99000000000n);
  assertEqual(stake.changeOutputKey, 'json_rt_key');

  await storage1.close();
  await storage2.close();
});

await testAsync('load v1 data (no stakes) works fine', async () => {
  const v1Data = {
    version: 1,
    syncHeight: 500,
    outputs: [],
    transactions: [],
    spentKeyImages: [],
    blockHashes: {},
    state: {}
    // No stakes field
  };

  const storage = new MemoryStorage();
  await storage.open();
  storage.load(v1Data);

  const height = await storage.getSyncHeight();
  assertEqual(height, 500);

  const stakes = await storage.getStakes();
  assertEqual(stakes.length, 0);

  await storage.close();
});

// ============================================================================
// _extractReturnPubkey Tests
// ============================================================================

console.log('\n--- _extractReturnPubkey ---');

test('extracts from prefix.protocol_tx_data.return_pubkey (CARROT, string)', () => {
  const sync = new WalletSync({});
  const tx = {
    prefix: {
      protocol_tx_data: {
        return_pubkey: 'aabbccdd'
      }
    }
  };
  assertEqual(sync._extractReturnPubkey(tx), 'aabbccdd');
});

test('extracts from prefix.protocol_tx_data.return_pubkey (CARROT, Uint8Array)', () => {
  const sync = new WalletSync({});
  const tx = {
    prefix: {
      protocol_tx_data: {
        return_pubkey: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd])
      }
    }
  };
  assertEqual(sync._extractReturnPubkey(tx), 'aabbccdd');
});

test('extracts from prefix.return_pubkey (pre-CARROT, string)', () => {
  const sync = new WalletSync({});
  const tx = {
    prefix: {
      return_pubkey: '11223344'
    }
  };
  assertEqual(sync._extractReturnPubkey(tx), '11223344');
});

test('extracts from prefix.return_pubkey (pre-CARROT, Uint8Array)', () => {
  const sync = new WalletSync({});
  const tx = {
    prefix: {
      return_pubkey: new Uint8Array([0x11, 0x22, 0x33, 0x44])
    }
  };
  assertEqual(sync._extractReturnPubkey(tx), '11223344');
});

test('prefers protocol_tx_data over top-level return_pubkey', () => {
  const sync = new WalletSync({});
  const tx = {
    prefix: {
      return_pubkey: 'fallback',
      protocol_tx_data: {
        return_pubkey: 'preferred'
      }
    }
  };
  assertEqual(sync._extractReturnPubkey(tx), 'preferred');
});

test('returns null when no return_pubkey exists', () => {
  const sync = new WalletSync({});
  const tx = { prefix: {} };
  assertEqual(sync._extractReturnPubkey(tx), null);
});

test('handles tx without prefix wrapper', () => {
  const sync = new WalletSync({});
  const tx = { return_pubkey: 'direct_key' };
  assertEqual(sync._extractReturnPubkey(tx), 'direct_key');
});

// ============================================================================
// _recordStakeLifecycle Tests
// ============================================================================

console.log('\n--- _recordStakeLifecycle ---');

await testAsync('records STAKE tx as locked StakeRecord', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  const walletTx = new WalletTransaction({
    txHash: 'stake_hash_1',
    amountBurnt: 130130000000000n,
    fee: 50000000n
  });
  const changeOutput = new WalletOutput({
    keyImage: 'ki_change',
    publicKey: 'change_pubkey',
    assetType: 'SAL'
  });
  const spentOutput = new WalletOutput({ keyImage: 'ki_spent' });
  const tx = {
    prefix: {
      return_pubkey: 'return_pubkey_hex'
    }
  };

  await sync._recordStakeLifecycle(
    TX_TYPE.STAKE,       // txType
    false,               // isProtocolTx
    'stake_hash_1',      // txHash
    { height: 417082, timestamp: 1700000000 }, // header
    [changeOutput],      // ownedOutputs
    [spentOutput],       // spentOutputs (non-empty → we sent it)
    walletTx,            // walletTx
    tx                   // parsed tx
  );

  const stake = await storage.getStake('stake_hash_1');
  assertEqual(stake.stakeTxHash, 'stake_hash_1');
  assertEqual(stake.stakeHeight, 417082);
  assertEqual(stake.stakeTimestamp, 1700000000);
  assertEqual(stake.amountStaked, 130130000000000n);
  assertEqual(stake.fee, 50000000n);
  assertEqual(stake.assetType, 'SAL');
  assertEqual(stake.changeOutputKey, 'return_pubkey_hex');
  assertEqual(stake.status, 'locked');

  await storage.close();
});

await testAsync('STAKE tx uses return_pubkey over change output key', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  const walletTx = new WalletTransaction({ txHash: 'st2', amountBurnt: 1000n, fee: 10n });
  const changeOutput = new WalletOutput({ keyImage: 'ki', publicKey: 'change_pk' });
  const tx = { prefix: { return_pubkey: 'explicit_return_pk' } };

  await sync._recordStakeLifecycle(
    TX_TYPE.STAKE, false, 'st2',
    { height: 100, timestamp: 1700000000 },
    [changeOutput], [changeOutput], walletTx, tx
  );

  const stake = await storage.getStake('st2');
  assertEqual(stake.changeOutputKey, 'explicit_return_pk');

  await storage.close();
});

await testAsync('STAKE tx falls back to change output publicKey when no return_pubkey', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  const walletTx = new WalletTransaction({ txHash: 'st3', amountBurnt: 1000n, fee: 10n });
  const changeOutput = new WalletOutput({ keyImage: 'ki', publicKey: 'fallback_pk' });
  const tx = { prefix: {} }; // No return_pubkey

  await sync._recordStakeLifecycle(
    TX_TYPE.STAKE, false, 'st3',
    { height: 100, timestamp: 1700000000 },
    [changeOutput], [changeOutput], walletTx, tx
  );

  const stake = await storage.getStake('st3');
  assertEqual(stake.changeOutputKey, 'fallback_pk');

  await storage.close();
});

await testAsync('does not record STAKE when no spentOutputs (not our stake)', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  const walletTx = new WalletTransaction({ txHash: 'st_other', amountBurnt: 1000n });
  const tx = { prefix: {} };

  await sync._recordStakeLifecycle(
    TX_TYPE.STAKE, false, 'st_other',
    { height: 100, timestamp: 1700000000 },
    [], [], walletTx, tx
  );

  const stake = await storage.getStake('st_other');
  assertEqual(stake, null);

  await storage.close();
});

await testAsync('PROTOCOL return matches via returnOriginKey (CARROT path)', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  // Pre-existing stake
  await storage.putStake(new StakeRecord({
    stakeTxHash: 'orig_stake',
    stakeHeight: 100,
    amountStaked: 50000000000n,
    changeOutputKey: 'carrot_origin_key',
    status: 'locked'
  }));

  // Incoming PROTOCOL output with returnOriginKey from CARROT scanning
  const returnOutput = new WalletOutput({
    keyImage: 'ki_ret',
    publicKey: 'some_different_key',
    amount: 51000000000n,
    returnOriginKey: 'carrot_origin_key', // Matches the stake's changeOutputKey
    isReturn: true
  });
  const walletTx = new WalletTransaction({ txHash: 'prot_tx_1' });
  const tx = { prefix: {} };

  await sync._recordStakeLifecycle(
    TX_TYPE.PROTOCOL,   // txType
    true,               // isProtocolTx
    'prot_tx_1',        // txHash
    { height: 200, timestamp: 1700012000 },
    [returnOutput],     // ownedOutputs
    [],                 // spentOutputs (protocol txs have no user-spent inputs)
    walletTx, tx
  );

  const stake = await storage.getStake('orig_stake');
  assertEqual(stake.status, 'returned');
  assertEqual(stake.returnTxHash, 'prot_tx_1');
  assertEqual(stake.returnHeight, 200);
  assertEqual(stake.returnTimestamp, 1700012000);
  assertEqual(stake.returnAmount, 51000000000n);

  await storage.close();
});

await testAsync('PROTOCOL return matches via publicKey (pre-CARROT path)', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  // Pre-existing stake with return_pubkey as changeOutputKey
  await storage.putStake(new StakeRecord({
    stakeTxHash: 'precarrot_stake',
    stakeHeight: 50,
    amountStaked: 30000000000n,
    changeOutputKey: 'matching_pubkey',
    status: 'locked'
  }));

  // Incoming PROTOCOL output — no returnOriginKey (not CARROT), but publicKey matches
  const returnOutput = new WalletOutput({
    keyImage: 'ki_pc_ret',
    publicKey: 'matching_pubkey',
    amount: 31000000000n
    // No returnOriginKey — pre-CARROT path
  });
  const walletTx = new WalletTransaction({ txHash: 'prot_tx_2' });
  const tx = { prefix: {} };

  await sync._recordStakeLifecycle(
    TX_TYPE.PROTOCOL, true, 'prot_tx_2',
    { height: 150, timestamp: 1700015000 },
    [returnOutput], [], walletTx, tx
  );

  const stake = await storage.getStake('precarrot_stake');
  assertEqual(stake.status, 'returned');
  assertEqual(stake.returnTxHash, 'prot_tx_2');
  assertEqual(stake.returnHeight, 150);
  assertEqual(stake.returnAmount, 31000000000n);

  await storage.close();
});

await testAsync('PROTOCOL tx with non-matching output does not update any stake', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  await storage.putStake(new StakeRecord({
    stakeTxHash: 'untouched_stake',
    stakeHeight: 100,
    amountStaked: 10000n,
    changeOutputKey: 'specific_key',
    status: 'locked'
  }));

  // PROTOCOL output that doesn't match
  const output = new WalletOutput({
    keyImage: 'ki_nm',
    publicKey: 'different_key',
    amount: 5000n
  });
  const walletTx = new WalletTransaction({ txHash: 'prot_nm' });
  const tx = { prefix: {} };

  await sync._recordStakeLifecycle(
    TX_TYPE.PROTOCOL, true, 'prot_nm',
    { height: 200, timestamp: 1700020000 },
    [output], [], walletTx, tx
  );

  const stake = await storage.getStake('untouched_stake');
  assertEqual(stake.status, 'locked');
  assertEqual(stake.returnTxHash, null);

  await storage.close();
});

await testAsync('PROTOCOL tx with no owned outputs is a no-op', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  await storage.putStake(new StakeRecord({
    stakeTxHash: 'no_out_stake',
    stakeHeight: 100,
    amountStaked: 10000n,
    changeOutputKey: 'no_out_key',
    status: 'locked'
  }));

  const walletTx = new WalletTransaction({ txHash: 'prot_no_out' });
  const tx = { prefix: {} };

  await sync._recordStakeLifecycle(
    TX_TYPE.PROTOCOL, true, 'prot_no_out',
    { height: 200, timestamp: 1700020000 },
    [], [], walletTx, tx
  );

  const stake = await storage.getStake('no_out_stake');
  assertEqual(stake.status, 'locked');

  await storage.close();
});

await testAsync('non-STAKE, non-PROTOCOL tx is ignored', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  const walletTx = new WalletTransaction({ txHash: 'transfer_tx', amountBurnt: 0n });
  const output = new WalletOutput({ keyImage: 'ki_t', publicKey: 'pk_t' });
  const tx = { prefix: {} };

  await sync._recordStakeLifecycle(
    TX_TYPE.TRANSFER, false, 'transfer_tx',
    { height: 100, timestamp: 1700000000 },
    [output], [output], walletTx, tx
  );

  const stakes = await storage.getStakes();
  assertEqual(stakes.length, 0);

  await storage.close();
});

await testAsync('full STAKE → RETURN lifecycle', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  // Step 1: User creates a STAKE
  const stakeWalletTx = new WalletTransaction({
    txHash: 'lifecycle_stake',
    amountBurnt: 100000000000000n,
    fee: 50000000n,
    txType: TX_TYPE.STAKE
  });
  const changeOutput = new WalletOutput({
    keyImage: 'ki_lifecycle_change',
    publicKey: 'lifecycle_change_key',
    assetType: 'SAL'
  });
  const stakeTx = {
    prefix: {
      protocol_tx_data: {
        return_pubkey: new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
      }
    }
  };

  await sync._recordStakeLifecycle(
    TX_TYPE.STAKE, false, 'lifecycle_stake',
    { height: 1000, timestamp: 1700000000 },
    [changeOutput],
    [new WalletOutput({ keyImage: 'ki_spent' })],
    stakeWalletTx, stakeTx
  );

  // Verify stake is locked
  let stake = await storage.getStake('lifecycle_stake');
  assertEqual(stake.status, 'locked');
  assertEqual(stake.amountStaked, 100000000000000n);
  assertEqual(stake.changeOutputKey, 'aabbccddeeff'); // from protocol_tx_data.return_pubkey

  // Step 2: PROTOCOL tx returns the stake
  const returnOutput = new WalletOutput({
    keyImage: 'ki_lifecycle_return',
    publicKey: 'aabbccddeeff', // matches the return_pubkey → pre-CARROT path
    amount: 101000000000000n   // stake + yield
  });
  const protocolWalletTx = new WalletTransaction({
    txHash: 'lifecycle_return',
    txType: TX_TYPE.PROTOCOL
  });

  await sync._recordStakeLifecycle(
    TX_TYPE.PROTOCOL, true, 'lifecycle_return',
    { height: 1100, timestamp: 1700012000 },
    [returnOutput], [],
    protocolWalletTx, { prefix: {} }
  );

  // Verify stake is now returned
  stake = await storage.getStake('lifecycle_stake');
  assertEqual(stake.status, 'returned');
  assertEqual(stake.returnTxHash, 'lifecycle_return');
  assertEqual(stake.returnHeight, 1100);
  assertEqual(stake.returnAmount, 101000000000000n);

  // Step 3: Reorg undoes the return
  await storage.deleteStakesAbove(1050);

  stake = await storage.getStake('lifecycle_stake');
  assertEqual(stake.status, 'locked');
  assertEqual(stake.returnTxHash, null);
  assertEqual(stake.returnHeight, null);
  assertEqual(stake.returnAmount, 0n);

  // Stake itself (at height 1000) should survive
  assertEqual(stake.stakeHeight, 1000);
  assertEqual(stake.amountStaked, 100000000000000n);

  await storage.close();
});

await testAsync('reorg above stake height removes the stake entirely', async () => {
  const storage = new MemoryStorage();
  await storage.open();
  const sync = new WalletSync({ storage });

  const walletTx = new WalletTransaction({ txHash: 'reorg_stake', amountBurnt: 1000n, fee: 10n });
  const tx = { prefix: { return_pubkey: 'reorg_key' } };

  await sync._recordStakeLifecycle(
    TX_TYPE.STAKE, false, 'reorg_stake',
    { height: 500, timestamp: 1700000000 },
    [new WalletOutput({ keyImage: 'ki_r', publicKey: 'pk_r' })],
    [new WalletOutput({ keyImage: 'ki_s' })],
    walletTx, tx
  );

  let stake = await storage.getStake('reorg_stake');
  assert(stake !== null, 'Stake should exist before reorg');

  // Reorg to height 400 — stake at 500 should be removed
  await storage.deleteStakesAbove(400);

  stake = await storage.getStake('reorg_stake');
  assertEqual(stake, null);

  // Output key index should also be cleaned
  const byKey = await storage.getStakeByOutputKey('reorg_key');
  assertEqual(byKey, null);

  await storage.close();
});

// ============================================================================
// Summary
// ============================================================================

console.log('\n--- Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);

if (failed > 0) {
  console.log('\n✗ Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All stake lifecycle tests passed!');
  process.exit(0);
}
