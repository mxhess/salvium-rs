import { setCryptoBackend, getCryptoBackend, generateKeyDerivation, deriveSubaddressPublicKey } from '../src/crypto/index.js';
import { loadWalletFromFile } from './test-helpers.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

await setCryptoBackend('wasm');
const w = await loadWalletFromFile(process.env.HOME + '/testnet-wallet/wallet-a.json', 'testnet');
w.setDaemon(new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' }));
const ws = w._ensureSync();

// Count calls to different stages
let totalCalls = 0, viewTagReject = 0, derivFail = 0, noSubaddr = 0, found = 0;
let nativeAttempt = 0, nativeNull = 0;

const origScan = ws._scanCNOutput.bind(ws);
ws._scanCNOutput = async function(output, outputIndex, tx, txHash, txPubKey, header, precomputedDerivation) {
  totalCalls++;
  
  // Replicate the logic to find where it fails
  const outputPubKey = ws._extractOutputPubKey(output);
  if (!outputPubKey) { return null; }
  
  const derivation = precomputedDerivation || generateKeyDerivation(txPubKey, ws.keys.viewSecretKey);
  if (!derivation) { derivFail++; return null; }

  // Check if native scan path is taken
  const backend = getCryptoBackend();
  if (typeof backend.scanCnOutput === 'function') {
    nativeAttempt++;
    const r = backend.scanCnOutput(outputPubKey, derivation, outputIndex, output.viewTag,
      tx.rct?.type ?? 0, undefined, undefined, ws.keys.spendSecretKey, ws.keys.viewSecretKey, ws.subaddresses);
    if (r === null) nativeNull++;
  }

  // Call original
  return origScan(output, outputIndex, tx, txHash, txPubKey, header, precomputedDerivation);
};

await w.syncWithDaemon();
const storage = w._ensureStorage();

console.log('Backend:', getCryptoBackend().name);
console.log('Total CN scans:', totalCalls);
console.log('Native attempts:', nativeAttempt, 'null:', nativeNull);
console.log('Storage outputs:', storage._outputs.size);
