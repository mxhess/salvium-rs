import { setCryptoBackend, getCryptoBackend, generateKeyDerivation, deriveSubaddressPublicKey } from '../src/crypto/index.js';
import { loadWalletFromFile } from './test-helpers.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

await setCryptoBackend('ffi');
const w = await loadWalletFromFile(process.env.HOME + '/testnet-wallet/wallet-a.json', 'testnet');
w.setDaemon(new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' }));
const ws = w._ensureSync();

// Intercept _scanCNOutput to capture args from first scan that returns a result
let captured = null;
const origScan = ws._scanCNOutput.bind(ws);
let count = 0;
ws._scanCNOutput = async function(output, outputIndex, tx, txHash, txPubKey, header, precomputedDerivation) {
  const r = await origScan(output, outputIndex, tx, txHash, txPubKey, header, precomputedDerivation);
  count++;
  if (r && !captured) {
    captured = { output, outputIndex, tx, txPubKey, precomputedDerivation, result: r };
  }
  return r;
};

await w.syncWithDaemon();
console.log('Total CN scans:', count, 'Found:', ws._ensureSync ? 'n/a' : 0);

if (captured) {
  console.log('\nFirst matched output:');
  const { output, outputIndex, tx, txPubKey, precomputedDerivation, result } = captured;
  const outputPubKey = ws._extractOutputPubKey(output);
  const derivation = precomputedDerivation || generateKeyDerivation(txPubKey, ws.keys.viewSecretKey);

  console.log('  outputPubKey:', bytesToHex(outputPubKey));
  console.log('  derivation:', bytesToHex(derivation));
  console.log('  outputIndex:', outputIndex);
  console.log('  result:', JSON.stringify(result, (k,v) => typeof v === 'bigint' ? v.toString() : v));

  // Now try the JS path manually
  const derivedSpendPubKey = deriveSubaddressPublicKey(outputPubKey, derivation, outputIndex);
  console.log('  JS derivedSpendPubKey:', bytesToHex(derivedSpendPubKey));
  console.log('  mainSpendPubKey:', bytesToHex(ws._mainSpendPubKeyBytes));
  console.log('  JS match:', bytesToHex(derivedSpendPubKey) === bytesToHex(ws._mainSpendPubKeyBytes));

  // Direct FFI call with same args
  const backend = getCryptoBackend();
  const directResult = backend.scanCnOutput(
    outputPubKey, derivation, outputIndex, output.viewTag,
    tx.rct?.type ?? 0,
    (tx.rct?.type ?? 0) === 0 ? BigInt(output.amount || 0) : undefined,
    (tx.rct?.type ?? 0) !== 0 ? tx.rct?.ecdhInfo?.[outputIndex]?.amount : undefined,
    ws.keys.spendSecretKey, ws.keys.viewSecretKey,
    ws.subaddresses
  );
  console.log('  Direct FFI result:', JSON.stringify(directResult, (k,v) => typeof v === 'bigint' ? v.toString() : v));
} else {
  console.log('No matched output captured');
}
