#!/usr/bin/env bun
/**
 * Raw TX hex analysis - manually find outPk position and verify parsing.
 * Also try using the daemon's view of the commitment directly.
 */
import { setCryptoBackend, commit } from '../src/crypto/index.js';
import { DaemonRPC } from '../src/rpc/daemon.js';

await setCryptoBackend('wasm');

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const txHash = 'd2ad187cc0dde491ae6134c8ad2df9188646859ecf2974271375f5257a51ada2';

const txResp = await daemon.getTransactions([txHash], { decode_as_json: true, prune: false });
const txData = txResp.result?.txs?.[0] || txResp.txs?.[0];
const rawHex = txData.as_hex;

// Find the outPk in the raw hex
const outPk0 = 'fdd6e627997742579544cc64529aeb73a7b3770555bbc73056786adccfea15e4';
const outPk1 = '2e9c3b33757e6ad2461b139e220d9968c8d5780f58bd51c719f2f6124b88f584';
const ecdhAmount0 = '1b48655a3f838e68';

const posOutPk0 = rawHex.indexOf(outPk0);
const posOutPk1 = rawHex.indexOf(outPk1);
const posEcdh0 = rawHex.indexOf(ecdhAmount0);

console.log(`Raw TX hex length: ${rawHex.length} chars (${rawHex.length/2} bytes)`);
console.log(`outPk[0] position in hex: ${posOutPk0} (byte ${posOutPk0/2})`);
console.log(`outPk[1] position in hex: ${posOutPk1} (byte ${posOutPk1/2})`);
console.log(`ecdhInfo[0].amount position: ${posEcdh0} (byte ${posEcdh0/2})`);
console.log(`Distance outPk0-outPk1: ${posOutPk1 - posOutPk0} chars (${(posOutPk1 - posOutPk0)/2} bytes)`);

// Show context around outPk
if (posOutPk0 >= 0) {
  const before = rawHex.slice(Math.max(0, posOutPk0 - 20), posOutPk0);
  const after = rawHex.slice(posOutPk0 + 64, posOutPk0 + 84);
  console.log(`\nBefore outPk0: ...${before}`);
  console.log(`outPk0: ${outPk0}`);
  console.log(`After outPk0: ${after}...`);
}

// Now let's try something completely different: use the daemon's get_outs RPC
// to get the commitment for this output, which is what ring members use.
// But we'd need the global output index...

// Let's check if our amount + commitment works with a different approach.
// What if we need to REVERSE the comparison: find what mask produces outPk?
// C_a = mask*G + amount*H
// C_a - amount*H = mask*G
// So mask*G = outPk - amount*H
// And amount*H = commit(amount, 0)

const zeroMask = new Uint8Array(32);
const amountH = commit(2366447376n, zeroMask);  // amount*H
console.log(`\namount*H = ${bytesToHex(amountH)}`);

// Now outPk - amount*H should = mask*G
// Use point subtraction: outPk + (-(amount*H))
import { pointAddCompressed, scalarMultBase } from '../src/crypto/index.js';
const negAmountH = new Uint8Array(amountH);
negAmountH[31] ^= 0x80;  // Negate point
const maskG = pointAddCompressed(hexToBytes(outPk0), negAmountH);
console.log(`maskG = outPk - amount*H: ${bytesToHex(maskG)}`);

// If our derived mask is correct, then scalarMultBase(mask) should equal maskG
const mask = hexToBytes('803b135e5613cdf4905268b48e408213b336ac491d81b67ce1adaf8d6673d004');
const expectedMaskG = scalarMultBase(mask);
console.log(`scalarMultBase(our mask): ${bytesToHex(expectedMaskG)}`);
console.log(`maskG == scalarMultBase(mask): ${bytesToHex(maskG) === bytesToHex(expectedMaskG)}`);

// What is the actual mask that would produce outPk?
// We can't easily derive the scalar, but we can check if maskG is a known point
console.log(`\n=== Are we using the right H point? ===`);
const H = commit(1n, zeroMask);  // 0*G + 1*H = H
console.log(`H point: ${bytesToHex(H)}`);

// Check if maybe outPk uses zeroCommit formula instead of commit
import { getCryptoBackend } from '../src/crypto/provider.js';
const backend = getCryptoBackend();
const zc = backend.zeroCommit(2366447376n);
console.log(`\nzeroCommit(amount): ${bytesToHex(zc)}`);
console.log(`zeroCommit == outPk: ${bytesToHex(zc) === outPk0}`);

// What if the amount needs to be in piconero (atomic units)?
// 2366447376 might already be atomic units, or might need conversion
console.log(`\nAmount: ${2366447376}`);
console.log(`Amount / 1e12 = ${2366447376 / 1e12} SAL`);
console.log(`Amount / 1e8 = ${2366447376 / 1e8} SAL`);
