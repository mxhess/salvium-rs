#!/usr/bin/env bun
/**
 * TX Verification Diagnostic — verify each component of a built TX
 */

import { setCryptoBackend } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { Wallet } from '../src/wallet.js';
import { bytesToHex, hexToBytes } from '../src/address.js';
import { loadWalletFromFile, getHeight } from './test-helpers.js';
import { existsSync } from 'node:fs';
import {
  clsagVerify, getPreMlsagHash, serializeRctBase, getTxPrefixHash,
  commit, zeroCommit, scAdd, scSub, bytesToBigInt, bigIntToBytes
} from '../src/transaction.js';
import { verifyBulletproofPlus } from '../src/bulletproofs_plus.js';
import { pointAddCompressed, scalarMultBase, scalarMultPoint } from '../src/ed25519.js';

await setCryptoBackend('wasm');

const DAEMON_URL = 'http://web.whiskymine.io:29081';
const WALLET_A_FILE = `${process.env.HOME}/testnet-wallet/wallet-a.json`;
const SYNC_CACHE_A = WALLET_A_FILE.replace(/\.json$/, '-sync.json');
const daemon = new DaemonRPC({ url: DAEMON_URL });

async function main() {
  const h = await getHeight(daemon);
  console.log(`Chain height: ${h}\n`);

  // Load and sync wallet
  const walletA = await loadWalletFromFile(WALLET_A_FILE, 'testnet');
  walletA.setDaemon(daemon);
  if (existsSync(SYNC_CACHE_A)) {
    walletA.loadSyncCache(JSON.parse(await Bun.file(SYNC_CACHE_A).text()));
  }
  await walletA.syncWithDaemon();

  const { unlockedBalance } = await walletA.getStorageBalance();
  console.log(`Unlocked balance: ${unlockedBalance}\n`);

  // Build dry-run transfer
  const addr = walletA.getLegacyAddress();
  const result = await walletA.transfer(
    [{ address: addr, amount: 10_000_000n }],
    { priority: 'default', dryRun: true }
  );

  const tx = result.tx;
  const prefix = tx.prefix;
  const rct = tx.rct;

  console.log(`TX version: ${prefix.version}, rctType: ${rct.type}`);
  console.log(`Inputs: ${prefix.vin.length}, Outputs: ${prefix.vout.length}`);
  console.log(`Fee: ${rct.fee}\n`);

  // === 1. VERIFY BALANCE EQUATION ===
  console.log('=== 1. BALANCE EQUATION ===');
  // sum(pseudoOuts) should equal sum(outPk) + fee*H + p_r

  const H_HEX = '8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94';
  const H_POINT = hexToBytes(H_HEX);

  // Fee commitment: fee * H
  const feeBytes = bigIntToBytes(rct.fee);
  const feeH = scalarMultPoint(feeBytes, H_POINT);
  console.log(`  feeH: ${bytesToHex(feeH).slice(0,16)}...`);

  // Sum of outPk
  let sumOutPk = null;
  for (const pk of rct.outPk) {
    const pkBytes = typeof pk === 'string' ? hexToBytes(pk) : pk;
    sumOutPk = sumOutPk ? pointAddCompressed(sumOutPk, pkBytes) : pkBytes;
  }
  console.log(`  sum(outPk): ${bytesToHex(sumOutPk).slice(0,16)}...`);

  // p_r
  const p_r = typeof rct.p_r === 'string' ? hexToBytes(rct.p_r) : rct.p_r;
  console.log(`  p_r: ${bytesToHex(p_r).slice(0,16)}...`);

  // LHS = sum(outPk) + feeH + p_r
  let lhs = pointAddCompressed(sumOutPk, feeH);
  lhs = pointAddCompressed(lhs, p_r);
  console.log(`  LHS (sum(outPk)+feeH+p_r): ${bytesToHex(lhs).slice(0,16)}...`);

  // Sum of pseudoOuts
  let sumPseudo = null;
  for (const po of rct.pseudoOuts) {
    const poBytes = typeof po === 'string' ? hexToBytes(po) : po;
    sumPseudo = sumPseudo ? pointAddCompressed(sumPseudo, poBytes) : poBytes;
  }
  console.log(`  RHS (sum(pseudoOuts)): ${bytesToHex(sumPseudo).slice(0,16)}...`);

  if (bytesToHex(lhs) === bytesToHex(sumPseudo)) {
    console.log('  BALANCE: OK ✓\n');
  } else {
    console.log('  BALANCE: FAIL ✗\n');
    console.log('  LHS:', bytesToHex(lhs));
    console.log('  RHS:', bytesToHex(sumPseudo));
  }

  // === 2. VERIFY CLSAG ===
  console.log('=== 2. CLSAG SIGNATURE ===');
  const prefixForSerialization = {
    ...tx.prefix,
    inputs: tx.prefix.vin,
    outputs: tx.prefix.vout
  };
  const txPrefixHash = getTxPrefixHash(prefixForSerialization);
  const rctBaseSerialized = serializeRctBase(tx.rct);

  // Get the BP+ proof for hashing
  const bpProof = tx.rct.bulletproofPlus;
  const preMLsagHash = getPreMlsagHash(txPrefixHash, rctBaseSerialized, bpProof);
  console.log(`  preMLsagHash: ${bytesToHex(preMLsagHash).slice(0,16)}...`);

  const meta = tx._meta;
  if (rct.CLSAGs && rct.CLSAGs.length > 0) {
    for (let i = 0; i < rct.CLSAGs.length; i++) {
      const sig = rct.CLSAGs[i];
      const ring = meta.ringData[i].ring.map(k => typeof k === 'string' ? hexToBytes(k) : k);
      const ringComms = meta.ringData[i].ringCommitments.map(c => typeof c === 'string' ? hexToBytes(c) : c);
      const pseudoOut = typeof rct.pseudoOuts[i] === 'string' ? hexToBytes(rct.pseudoOuts[i]) : rct.pseudoOuts[i];
      const keyImage = typeof meta.keyImages[i] === 'string' ? hexToBytes(meta.keyImages[i]) : meta.keyImages[i];

      console.log(`  CLSAG[${i}]: ring_size=${ring.length}, realIdx=${meta.ringData[i].realIndex}`);
      console.log(`    keyImage: ${bytesToHex(keyImage).slice(0,16)}...`);
      console.log(`    pseudoOut: ${bytesToHex(pseudoOut).slice(0,16)}...`);

      try {
        const valid = clsagVerify(preMLsagHash, sig, ring, ringComms, pseudoOut);
        console.log(`    Verify: ${valid ? 'OK ✓' : 'FAIL ✗'}`);
      } catch (e) {
        console.log(`    Verify ERROR: ${e.message}`);
      }
    }
  }

  // === 3. VERIFY BP+ ===
  console.log('\n=== 3. BULLETPROOFS+ ===');
  if (bpProof) {
    // bpProof should contain V (Noble Points) and proof fields { A, A1, B, r1, s1, d1, L, R }
    console.log(`  bpProof keys: ${Object.keys(bpProof).join(', ')}`);
    console.log(`  Has V: ${!!bpProof.V}, V.length: ${bpProof.V?.length}`);
    console.log(`  Has A: ${!!bpProof.A}, Has L: ${!!bpProof.L}`);
    try {
      // V from WASM is raw bytes — convert to Noble points for verify
      const { bytesToPoint: bpBytesToPoint } = await import('../src/bulletproofs_plus.js');
      const vPoints = bpProof.V.map(v =>
        v?.toBytes ? v : bpBytesToPoint(typeof v === 'string' ? hexToBytes(v) : v)
      );
      const bpValid = verifyBulletproofPlus(vPoints, bpProof);
      console.log(`  Verify: ${bpValid ? 'OK ✓' : 'FAIL ✗'}`);
    } catch (e) {
      console.log(`  Verify ERROR: ${e.message}`);
      console.log(`  Stack: ${e.stack?.split('\n').slice(0,3).join('\n')}`);
    }
  }

  // === 4. CHECK RING MEMBER COMMITMENTS ===
  console.log('\n=== 4. RING MEMBER DETAILS ===');
  if (meta.ringData[0]) {
    const rd = meta.ringData[0];
    console.log(`  Ring size: ${rd.ring.length}`);
    console.log(`  Real index: ${rd.realIndex}`);
    console.log(`  Real key: ${typeof rd.ring[rd.realIndex] === 'string' ? rd.ring[rd.realIndex].slice(0,16) : bytesToHex(rd.ring[rd.realIndex]).slice(0,16)}...`);
    console.log(`  Real commitment: ${typeof rd.ringCommitments[rd.realIndex] === 'string' ? rd.ringCommitments[rd.realIndex].slice(0,16) : bytesToHex(rd.ringCommitments[rd.realIndex]).slice(0,16)}...`);
  }

  // Check that our owned output's commitment matches what getOuts returns
  const allOuts = walletA._storage ? await walletA._storage.getOutputs({ isSpent: false }) : [];
  const spendable = allOuts.filter(o => typeof o.isSpendable === 'function' ? o.isSpendable(h) : true);
  if (spendable.length > 0) {
    const ownedOut = spendable[0];
    console.log(`\n  Owned output: ki=${ownedOut.keyImage?.slice(0,16)}...`);
    console.log(`    stored commitment: ${ownedOut.commitment?.slice(0,16) || 'NONE'}...`);
    console.log(`    stored mask: ${ownedOut.mask?.slice(0,16) || 'NONE'}...`);
    console.log(`    stored pubKey: ${ownedOut.publicKey?.slice(0,16) || 'NONE'}...`);
    console.log(`    stored amount: ${ownedOut.amount}`);
    console.log(`    isCoinbase: ${!ownedOut.mask}`);

    // If coinbase, verify recomputed commitment matches what daemon has
    if (!ownedOut.mask && ownedOut.globalIndex != null) {
      const IDENTITY_MASK = '0100000000000000000000000000000000000000000000000000000000000000';
      const recomputed = bytesToHex(commit(ownedOut.amount, hexToBytes(IDENTITY_MASK)));
      console.log(`    recomputed commitment: ${recomputed.slice(0,16)}...`);

      // Also check via zeroCommit
      const zcCommit = bytesToHex(zeroCommit(ownedOut.amount));
      console.log(`    zeroCommit(amount): ${zcCommit.slice(0,16)}...`);

      // Fetch from daemon
      try {
        const outsResp = await daemon.getOuts(
          [{ amount: 0, index: ownedOut.globalIndex }],
          { asset_type: ownedOut.assetType || 'SAL' }
        );
        const daemonOuts = outsResp.result?.outs || outsResp.outs || [];
        if (daemonOuts[0]) {
          console.log(`    daemon commitment (mask): ${daemonOuts[0].mask.slice(0,16)}...`);
          console.log(`    daemon key: ${daemonOuts[0].key.slice(0,16)}...`);

          if (daemonOuts[0].mask === recomputed) {
            console.log(`    Commitment MATCH ✓`);
          } else {
            console.log(`    Commitment MISMATCH ✗`);
            console.log(`      ours:   ${recomputed}`);
            console.log(`      daemon: ${daemonOuts[0].mask}`);
          }
        }
      } catch (e) {
        console.log(`    Failed to fetch from daemon: ${e.message}`);
      }
    }
  }
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
