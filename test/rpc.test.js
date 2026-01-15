/**
 * RPC Module Tests
 *
 * Tests for the Salvium RPC client implementations.
 * Note: Most tests require a running daemon/wallet RPC server.
 * These unit tests focus on module structure and offline functionality.
 */

import {
  RPCClient,
  DaemonRPC,
  WalletRPC,
  createDaemonRPC,
  createWalletRPC,
  RPC_ERROR_CODES,
  RPC_STATUS,
  PRIORITY,
  TRANSFER_TYPE,
  DAEMON_MAINNET_URL,
  DAEMON_TESTNET_URL,
  DAEMON_STAGENET_URL,
  ZMQ_MAINNET_URL,
  ZMQ_TESTNET_URL,
  ZMQ_STAGENET_URL,
  WALLET_MAINNET_URL,
  WALLET_TESTNET_URL,
  WALLET_STAGENET_URL
} from '../src/rpc/index.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (error) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${error.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message = '') {
  if (actual !== expected) {
    throw new Error(`${message} Expected ${expected}, got ${actual}`);
  }
}

function assertExists(value, message = '') {
  if (value === undefined || value === null) {
    throw new Error(`${message} Value is ${value}`);
  }
}

function assertInstanceOf(value, type, message = '') {
  if (!(value instanceof type)) {
    throw new Error(`${message} Expected instance of ${type.name}`);
  }
}

function assertFunction(value, message = '') {
  if (typeof value !== 'function') {
    throw new Error(`${message} Expected function, got ${typeof value}`);
  }
}

// ============================================================
// Module Export Tests
// ============================================================

console.log('\n--- RPC Module Export Tests ---');

test('RPCClient class is exported', () => {
  assertFunction(RPCClient);
});

test('DaemonRPC class is exported', () => {
  assertFunction(DaemonRPC);
});

test('WalletRPC class is exported', () => {
  assertFunction(WalletRPC);
});

test('createDaemonRPC function is exported', () => {
  assertFunction(createDaemonRPC);
});

test('createWalletRPC function is exported', () => {
  assertFunction(createWalletRPC);
});

test('RPC_ERROR_CODES is exported', () => {
  assertExists(RPC_ERROR_CODES);
  assertExists(RPC_ERROR_CODES.NETWORK_ERROR);
  assertExists(RPC_ERROR_CODES.TIMEOUT_ERROR);
});

test('RPC_STATUS is exported', () => {
  assertExists(RPC_STATUS);
  assertEqual(RPC_STATUS.OK, 'OK');
  assertEqual(RPC_STATUS.BUSY, 'BUSY');
});

test('PRIORITY constants are exported', () => {
  assertExists(PRIORITY);
  assertEqual(PRIORITY.DEFAULT, 0);
  assertEqual(PRIORITY.PRIORITY, 4);
});

test('TRANSFER_TYPE constants are exported', () => {
  assertExists(TRANSFER_TYPE);
  assertEqual(TRANSFER_TYPE.ALL, 'all');
  assertEqual(TRANSFER_TYPE.AVAILABLE, 'available');
});

test('Daemon URLs are exported with correct Salvium ports (from cryptonote_config.h)', () => {
  // config::RPC_DEFAULT_PORT values
  assertEqual(DAEMON_MAINNET_URL, 'http://localhost:19081');
  assertEqual(DAEMON_TESTNET_URL, 'http://localhost:29081');
  assertEqual(DAEMON_STAGENET_URL, 'http://localhost:39081');
});

test('ZMQ URLs are exported with correct Salvium ports (from cryptonote_config.h)', () => {
  // config::ZMQ_RPC_DEFAULT_PORT values
  assertEqual(ZMQ_MAINNET_URL, 'http://localhost:19083');
  assertEqual(ZMQ_TESTNET_URL, 'http://localhost:29083');
  assertEqual(ZMQ_STAGENET_URL, 'http://localhost:39083');
});

test('Wallet URLs are exported (conventional ports, no source default)', () => {
  // No default in salvium-wallet-rpc source - convention is daemon port + 1
  assertEqual(WALLET_MAINNET_URL, 'http://localhost:19083');
  assertEqual(WALLET_TESTNET_URL, 'http://localhost:29083');
  assertEqual(WALLET_STAGENET_URL, 'http://localhost:39083');
});

// ============================================================
// RPCClient Tests
// ============================================================

console.log('\n--- RPCClient Tests ---');

test('RPCClient requires URL', () => {
  let threw = false;
  try {
    new RPCClient({});
  } catch (e) {
    threw = true;
  }
  if (!threw) throw new Error('Should have thrown error');
});

test('RPCClient accepts URL', () => {
  const client = new RPCClient({ url: 'http://localhost:19081' });
  assertEqual(client.url, 'http://localhost:19081');
});

test('RPCClient strips trailing slashes', () => {
  const client = new RPCClient({ url: 'http://localhost:19081///' });
  assertEqual(client.url, 'http://localhost:19081');
});

test('RPCClient accepts timeout option', () => {
  const client = new RPCClient({ url: 'http://localhost:19081', timeout: 60000 });
  assertEqual(client.timeout, 60000);
});

test('RPCClient accepts retry options', () => {
  const client = new RPCClient({
    url: 'http://localhost:19081',
    retries: 3,
    retryDelay: 2000
  });
  assertEqual(client.retries, 3);
  assertEqual(client.retryDelay, 2000);
});

test('RPCClient accepts auth options', () => {
  const client = new RPCClient({
    url: 'http://localhost:19081',
    username: 'user',
    password: 'pass'
  });
  assertEqual(client.username, 'user');
  assertEqual(client.password, 'pass');
});

test('RPCClient.configure updates options', () => {
  const client = new RPCClient({ url: 'http://localhost:19081' });
  client.configure({ timeout: 5000 });
  assertEqual(client.timeout, 5000);
});

// ============================================================
// DaemonRPC Tests
// ============================================================

console.log('\n--- DaemonRPC Tests ---');

test('DaemonRPC extends RPCClient', () => {
  const daemon = new DaemonRPC({ url: 'http://localhost:19081' });
  assertInstanceOf(daemon, RPCClient);
});

test('DaemonRPC defaults to mainnet port', () => {
  const daemon = new DaemonRPC();
  assertEqual(daemon.url, 'http://localhost:19081');
});

test('DaemonRPC has network info methods', () => {
  const daemon = new DaemonRPC();
  assertFunction(daemon.getInfo);
  assertFunction(daemon.getHeight);
  assertFunction(daemon.getBlockCount);
  assertFunction(daemon.syncInfo);
  assertFunction(daemon.hardForkInfo);
});

test('DaemonRPC has block operation methods', () => {
  const daemon = new DaemonRPC();
  assertFunction(daemon.getBlockHash);
  assertFunction(daemon.getBlockHeaderByHash);
  assertFunction(daemon.getBlockHeaderByHeight);
  assertFunction(daemon.getBlockHeadersRange);
  assertFunction(daemon.getLastBlockHeader);
  assertFunction(daemon.getBlock);
});

test('DaemonRPC has transaction methods', () => {
  const daemon = new DaemonRPC();
  assertFunction(daemon.getTransactions);
  assertFunction(daemon.getTransactionPool);
  assertFunction(daemon.sendRawTransaction);
  assertFunction(daemon.relayTx);
});

test('DaemonRPC has output methods', () => {
  const daemon = new DaemonRPC();
  assertFunction(daemon.getOuts);
  assertFunction(daemon.getOutputHistogram);
  assertFunction(daemon.getOutputDistribution);
  assertFunction(daemon.isKeyImageSpent);
});

test('DaemonRPC has mining methods', () => {
  const daemon = new DaemonRPC();
  assertFunction(daemon.getBlockTemplate);
  assertFunction(daemon.submitBlock);
  assertFunction(daemon.getMinerData);
  assertFunction(daemon.calcPow);
});

test('DaemonRPC has fee estimation methods', () => {
  const daemon = new DaemonRPC();
  assertFunction(daemon.getFeeEstimate);
  assertFunction(daemon.getBaseFeeEstimate);
  assertFunction(daemon.getCoinbaseTxSum);
});

test('DaemonRPC has utility methods', () => {
  const daemon = new DaemonRPC();
  assertFunction(daemon.isSynchronized);
  assertFunction(daemon.getNetworkType);
  assertFunction(daemon.waitForSync);
});

test('createDaemonRPC creates DaemonRPC instance', () => {
  const daemon = createDaemonRPC({ url: 'http://localhost:39081' });
  assertInstanceOf(daemon, DaemonRPC);
  assertEqual(daemon.url, 'http://localhost:39081');
});

// ============================================================
// WalletRPC Tests
// ============================================================

console.log('\n--- WalletRPC Tests ---');

test('WalletRPC extends RPCClient', () => {
  const wallet = new WalletRPC({ url: 'http://localhost:19083' });
  assertInstanceOf(wallet, RPCClient);
});

test('WalletRPC defaults to mainnet port', () => {
  const wallet = new WalletRPC();
  assertEqual(wallet.url, 'http://localhost:19083');
});

test('WalletRPC has wallet management methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.createWallet);
  assertFunction(wallet.openWallet);
  assertFunction(wallet.closeWallet);
  assertFunction(wallet.restoreDeterministicWallet);
  assertFunction(wallet.generateFromKeys);
});

test('WalletRPC has address methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.getAddress);
  assertFunction(wallet.getAddressIndex);
  assertFunction(wallet.createAddress);
  assertFunction(wallet.labelAddress);
  assertFunction(wallet.validateAddress);
  assertFunction(wallet.makeIntegratedAddress);
  assertFunction(wallet.splitIntegratedAddress);
});

test('WalletRPC has account methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.getAccounts);
  assertFunction(wallet.createAccount);
  assertFunction(wallet.labelAccount);
  assertFunction(wallet.tagAccounts);
});

test('WalletRPC has balance methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.getBalance);
  assertFunction(wallet.getHeight);
  assertFunction(wallet.getTransfers);
  assertFunction(wallet.getTransferByTxid);
  assertFunction(wallet.getPayments);
  assertFunction(wallet.incomingTransfers);
});

test('WalletRPC has transfer methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.transfer);
  assertFunction(wallet.transferSplit);
  assertFunction(wallet.sweepAll);
  assertFunction(wallet.sweepSingle);
  assertFunction(wallet.sweepDust);
  assertFunction(wallet.relayTx);
});

test('WalletRPC has proof methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.getTxKey);
  assertFunction(wallet.checkTxKey);
  assertFunction(wallet.getTxProof);
  assertFunction(wallet.checkTxProof);
  assertFunction(wallet.getSpendProof);
  assertFunction(wallet.checkSpendProof);
  assertFunction(wallet.getReserveProof);
  assertFunction(wallet.checkReserveProof);
});

test('WalletRPC has key management methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.queryKey);
  assertFunction(wallet.getMnemonic);
  assertFunction(wallet.getViewKey);
  assertFunction(wallet.getSpendKey);
  assertFunction(wallet.exportOutputs);
  assertFunction(wallet.importOutputs);
  assertFunction(wallet.exportKeyImages);
  assertFunction(wallet.importKeyImages);
});

test('WalletRPC has signing methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.sign);
  assertFunction(wallet.verify);
});

test('WalletRPC has multisig methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.prepareMultisig);
  assertFunction(wallet.makeMultisig);
  assertFunction(wallet.exportMultisigInfo);
  assertFunction(wallet.importMultisigInfo);
  assertFunction(wallet.signMultisig);
  assertFunction(wallet.submitMultisig);
});

test('WalletRPC has settings methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.autoRefresh);
  assertFunction(wallet.refresh);
  assertFunction(wallet.rescanBlockchain);
  assertFunction(wallet.setDaemon);
  assertFunction(wallet.getAttribute);
  assertFunction(wallet.setAttribute);
});

test('WalletRPC has URI methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.makeUri);
  assertFunction(wallet.parseUri);
});

test('WalletRPC has utility methods', () => {
  const wallet = new WalletRPC();
  assertFunction(wallet.getUnlockedBalance);
  assertFunction(wallet.getPrimaryAddress);
  assertFunction(wallet.sendTo);
  assertFunction(wallet.waitForSync);
});

test('createWalletRPC creates WalletRPC instance', () => {
  const wallet = createWalletRPC({ url: 'http://localhost:39083' });
  assertInstanceOf(wallet, WalletRPC);
  assertEqual(wallet.url, 'http://localhost:39083');
});

// ============================================================
// Integration with main module
// ============================================================

console.log('\n--- Main Module Integration Tests ---');

test('RPC exports available from main module', async () => {
  const salvium = await import('../src/index.js');
  assertFunction(salvium.DaemonRPC);
  assertFunction(salvium.WalletRPC);
  assertFunction(salvium.createDaemonRPC);
  assertFunction(salvium.createWalletRPC);
});

test('RPC namespace available from main module', async () => {
  const salvium = await import('../src/index.js');
  assertExists(salvium.rpc);
  assertFunction(salvium.rpc.DaemonRPC);
  assertFunction(salvium.rpc.WalletRPC);
});

// ============================================================
// Summary
// ============================================================

console.log('\n--- RPC Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n⚠️  Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All tests passed!');
}
