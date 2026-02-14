import { setCryptoBackend, getCryptoBackend } from '../src/crypto/index.js';
import { loadWalletFromFile } from './test-helpers.js';
import { DaemonRPC } from '../src/rpc/daemon.js';
import { bytesToHex, hexToBytes } from '../src/address.js';

await setCryptoBackend('ffi');
const w = await loadWalletFromFile(process.env.HOME + '/testnet-wallet/wallet-a.json', 'testnet');
w.setDaemon(new DaemonRPC({ url: 'http://node12.whiskymine.io:29081' }));
const ws = w._ensureSync();

console.log('subaddresses size:', ws.subaddresses.size);
for (const [hexKey, {major, minor}] of ws.subaddresses) {
  console.log('  key:', hexKey.slice(0, 32) + '... major:', major, 'minor:', minor);
  console.log('  key length:', hexKey.length, '(expected 64 hex chars = 32 bytes)');
}

// Now test scanCnOutput directly with a known non-matching output
const backend = getCryptoBackend();
const fakeOutput = new Uint8Array(32);
fakeOutput[0] = 0x58; // G point
const fakeDeriv = new Uint8Array(32);
fakeDeriv.fill(0x42);

const result = backend.scanCnOutput(
  fakeOutput, fakeDeriv, 0, undefined,
  0, 100n, undefined,
  null, ws.keys.viewSecretKey,
  ws.subaddresses
);
console.log('\nFake output scan result:', result);

// Test with empty subaddress map
const emptyMap = new Map();
const result2 = backend.scanCnOutput(
  fakeOutput, fakeDeriv, 0, undefined,
  0, 100n, undefined,
  null, ws.keys.viewSecretKey,
  emptyMap
);
console.log('Empty map scan result:', result2);
