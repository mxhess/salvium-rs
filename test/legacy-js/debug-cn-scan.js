import { setCryptoBackend, getCryptoBackend, generateKeyDerivation, deriveSubaddressPublicKey, deriveViewTag } from '../src/crypto/index.js';
import { loadWalletFromFile } from './test-helpers.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

const daemon = new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' });
const path = process.env.HOME + '/testnet-wallet/wallet-a.json';

for (const backend of ['wasm', 'ffi']) {
  await setCryptoBackend(backend);
  const w = await loadWalletFromFile(path, 'testnet');
  w.setDaemon(daemon);
  const ws = w._ensureSync();

  let logged = false;
  const origScan = ws._scanCNOutput.bind(ws);
  ws._scanCNOutput = async function(output, outputIndex, tx, txHash, txPubKey, header, precomputedDerivation) {
    if (!logged) {
      logged = true;
      const outputPubKey = ws._extractOutputPubKey(output);
      const derivation = precomputedDerivation || generateKeyDerivation(txPubKey, ws.keys.viewSecretKey);
      console.log(backend + ' first CN scan:');
      console.log('  outputPubKey:', outputPubKey ? bytesToHex(outputPubKey).slice(0,32) : 'null');
      console.log('  txPubKey:', txPubKey ? bytesToHex(txPubKey).slice(0,32) : 'null');
      console.log('  derivation:', derivation ? bytesToHex(derivation).slice(0,32) : 'null');
      console.log('  viewTag:', output.viewTag);
      console.log('  output.type:', output.type);
      console.log('  rctType:', tx.rct?.type);
      
      if (derivation) {
        const vt = deriveViewTag(derivation, outputIndex);
        console.log('  computed viewTag:', vt);
        const derived = deriveSubaddressPublicKey(outputPubKey, derivation, outputIndex);
        console.log('  derivedSpendPubKey:', derived ? bytesToHex(derived).slice(0,32) : 'null');
        console.log('  mainSpendPubKey:', ws._mainSpendPubKeyBytes ? bytesToHex(ws._mainSpendPubKeyBytes).slice(0,32) : 'null');
        if (derived && ws._mainSpendPubKeyBytes) {
          const derivedHex = bytesToHex(derived);
          const mainHex = bytesToHex(ws._mainSpendPubKeyBytes);
          console.log('  match:', derivedHex === mainHex);
          console.log('  subaddresses has:', ws.subaddresses.has(derivedHex));
        }
      }
    }
    return origScan(output, outputIndex, tx, txHash, txPubKey, header, precomputedDerivation);
  };

  await w.syncWithDaemon();
  console.log(backend + ' outputs:', w._ensureStorage()._outputs.size);
  console.log('');
}
