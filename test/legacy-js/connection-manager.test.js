#!/usr/bin/env bun
/**
 * Connection Manager Tests
 *
 * Tests for connection-manager.js:
 * - ConnectionInfo class
 * - ConnectionManager class
 * - Connection state tracking
 */

import {
  ConnectionManager,
  ConnectionInfo,
  CONNECTION_STATE,
  createDaemonConnectionManager,
  createWalletConnectionManager
} from '../src/connection-manager.js';

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

console.log('=== Connection Manager Tests ===\n');

// ============================================================================
// Constants Tests
// ============================================================================

console.log('--- Constants ---');

test('CONNECTION_STATE has correct values', () => {
  assertEqual(CONNECTION_STATE.DISCONNECTED, 'disconnected');
  assertEqual(CONNECTION_STATE.CONNECTING, 'connecting');
  assertEqual(CONNECTION_STATE.CONNECTED, 'connected');
  assertEqual(CONNECTION_STATE.FAILED, 'failed');
});

// ============================================================================
// ConnectionInfo Tests
// ============================================================================

console.log('\n--- ConnectionInfo ---');

test('creates with uri', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });
  assertEqual(info.uri, 'http://localhost:19081');
  assertEqual(info.state, CONNECTION_STATE.DISCONNECTED);
});

test('creates with url (alias for uri)', () => {
  const info = new ConnectionInfo({ url: 'http://localhost:19081' });
  assertEqual(info.uri, 'http://localhost:19081');
});

test('creates with all options', () => {
  const info = new ConnectionInfo({
    uri: 'http://seed01.salvium.io:19081',
    username: 'user',
    password: 'pass',
    priority: 5,
    timeout: 60000,
    retries: 5,
    retryDelay: 2000
  });

  assertEqual(info.uri, 'http://seed01.salvium.io:19081');
  assertEqual(info.username, 'user');
  assertEqual(info.password, 'pass');
  assertEqual(info.priority, 5);
  assertEqual(info.timeout, 60000);
  assertEqual(info.retries, 5);
  assertEqual(info.retryDelay, 2000);
});

test('defaults priority to 1', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });
  assertEqual(info.priority, 1);
});

test('defaults timeout to 30000', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });
  assertEqual(info.timeout, 30000);
});

test('defaults retries to 3', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });
  assertEqual(info.retries, 3);
});

test('markFailed updates state and failCount', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });
  assertEqual(info.failCount, 0);
  assertEqual(info.state, CONNECTION_STATE.DISCONNECTED);

  info.markFailed(new Error('Connection refused'));

  assertEqual(info.state, CONNECTION_STATE.FAILED);
  assertEqual(info.failCount, 1);
  assert(info.lastError !== null);
});

test('markFailed increments failCount', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });

  info.markFailed(new Error('Error 1'));
  info.markFailed(new Error('Error 2'));
  info.markFailed(new Error('Error 3'));

  assertEqual(info.failCount, 3);
});

test('markSuccess updates state and resets failCount', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });
  info.markFailed(new Error('test'));
  assertEqual(info.failCount, 1);

  info.markSuccess(100);

  assertEqual(info.state, CONNECTION_STATE.CONNECTED);
  assertEqual(info.failCount, 0);
  assertEqual(info.lastError, null);
});

test('markSuccess tracks response time', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });

  info.markSuccess(100);
  assertEqual(info.responseTime, 100);

  // Should use exponential moving average
  info.markSuccess(200);
  assert(info.responseTime > 100 && info.responseTime < 200);
});

test('reset clears failure state', () => {
  const info = new ConnectionInfo({ uri: 'http://localhost:19081' });
  info.markFailed(new Error('test'));
  info.markFailed(new Error('test2'));

  info.reset();

  assertEqual(info.state, CONNECTION_STATE.DISCONNECTED);
  assertEqual(info.failCount, 0);
});

test('toRpcOptions returns correct object', () => {
  const info = new ConnectionInfo({
    uri: 'http://localhost:19081',
    username: 'user',
    password: 'pass',
    timeout: 5000
  });

  const opts = info.toRpcOptions();

  assertEqual(opts.url, 'http://localhost:19081');
  assertEqual(opts.username, 'user');
  assertEqual(opts.password, 'pass');
  assertEqual(opts.timeout, 5000);
});

// ============================================================================
// ConnectionManager Tests
// ============================================================================

console.log('\n--- ConnectionManager ---');

test('creates with array of connection configs', () => {
  const manager = new ConnectionManager({
    connections: [
      { uri: 'http://seed01.salvium.io:19081' },
      { uri: 'http://seed02.salvium.io:19081' },
      { uri: 'http://seed03.salvium.io:19081' }
    ]
  });

  assertEqual(manager.connections.length, 3);
});

test('creates with ConnectionInfo objects', () => {
  const manager = new ConnectionManager({
    connections: [
      new ConnectionInfo({ uri: 'http://seed01.salvium.io:19081', priority: 1 }),
      new ConnectionInfo({ uri: 'http://seed02.salvium.io:19081', priority: 2 })
    ]
  });

  assertEqual(manager.connections.length, 2);
});

test('sorts connections by priority (lower first)', () => {
  const manager = new ConnectionManager({
    connections: [
      { uri: 'http://low:19081', priority: 10 },
      { uri: 'http://high:19081', priority: 1 },
      { uri: 'http://med:19081', priority: 5 }
    ]
  });

  // Lower priority = higher priority (sorted first)
  assertEqual(manager.connections[0].uri, 'http://high:19081');
  assertEqual(manager.connections[1].uri, 'http://med:19081');
  assertEqual(manager.connections[2].uri, 'http://low:19081');
});

test('addConnection adds new connection', () => {
  const manager = new ConnectionManager({
    connections: [{ uri: 'http://seed01.salvium.io:19081' }]
  });

  manager.addConnection({ uri: 'http://seed02.salvium.io:19081' });

  assertEqual(manager.connections.length, 2);
});

test('removeConnection removes by URI', () => {
  const manager = new ConnectionManager({
    connections: [
      { uri: 'http://seed01.salvium.io:19081' },
      { uri: 'http://seed02.salvium.io:19081' },
      { uri: 'http://seed03.salvium.io:19081' }
    ]
  });

  manager.removeConnection('http://seed02.salvium.io:19081');

  assertEqual(manager.connections.length, 2);
  assert(!manager.connections.some(c => c.uri === 'http://seed02.salvium.io:19081'));
});

test('getConnections returns all connections', () => {
  const manager = new ConnectionManager({
    connections: [
      { uri: 'http://seed01.salvium.io:19081' },
      { uri: 'http://seed02.salvium.io:19081' }
    ]
  });

  const connections = manager.getConnections();
  assertEqual(connections.length, 2);
});

test('getCurrentConnection returns first connection initially', () => {
  const manager = new ConnectionManager({
    connections: [
      { uri: 'http://seed01.salvium.io:19081', priority: 1 },
      { uri: 'http://seed02.salvium.io:19081', priority: 2 }
    ]
  });

  const current = manager.getCurrentConnection();
  assertEqual(current.uri, 'http://seed01.salvium.io:19081');
});

test('switchTo changes active connection', () => {
  const manager = new ConnectionManager({
    connections: [
      { uri: 'http://seed01.salvium.io:19081' },
      { uri: 'http://seed02.salvium.io:19081' }
    ]
  });

  manager.switchTo('http://seed02.salvium.io:19081');
  const current = manager.getCurrentConnection();

  assertEqual(current.uri, 'http://seed02.salvium.io:19081');
});

test('getBestConnection returns connected connection', () => {
  const manager = new ConnectionManager({
    connections: [
      { uri: 'http://seed01.salvium.io:19081' },
      { uri: 'http://seed02.salvium.io:19081' }
    ]
  });

  // Mark first as failed, second as connected
  manager.connections[0].markFailed(new Error('test'));
  manager.connections[1].markSuccess(100);

  const best = manager.getBestConnection();
  assertEqual(best.uri, 'http://seed02.salvium.io:19081');
});

// ============================================================================
// Event System Tests
// ============================================================================

console.log('\n--- Events ---');

test('on adds listener', () => {
  const manager = new ConnectionManager({
    connections: [{ uri: 'http://localhost:19081' }]
  });
  let called = false;

  manager.on('test', () => { called = true; });
  manager._emit('test');

  assert(called);
});

test('off removes listener', () => {
  const manager = new ConnectionManager({
    connections: [{ uri: 'http://localhost:19081' }]
  });
  let count = 0;
  const handler = () => { count++; };

  manager.on('test', handler);
  manager._emit('test');
  assertEqual(count, 1);

  manager.off('test', handler);
  manager._emit('test');
  assertEqual(count, 1);
});

// ============================================================================
// Factory Function Tests
// ============================================================================

console.log('\n--- Factory Functions ---');

test('createDaemonConnectionManager creates manager for daemon', () => {
  // First arg is connections array, second is options
  const manager = createDaemonConnectionManager([
    { uri: 'http://localhost:19081' }
  ]);

  assert(manager instanceof ConnectionManager);
  assertEqual(manager.proxyType, 'daemon');
});

test('createWalletConnectionManager creates manager for wallet', () => {
  // First arg is connections array, second is options
  const manager = createWalletConnectionManager([
    { uri: 'http://localhost:19083' }
  ]);

  assert(manager instanceof ConnectionManager);
  assertEqual(manager.proxyType, 'wallet');
});

// ============================================================================
// Configuration Tests
// ============================================================================

console.log('\n--- Configuration ---');

test('autoSwitch defaults to true', () => {
  const manager = new ConnectionManager({
    connections: [{ uri: 'http://localhost:19081' }]
  });
  assertEqual(manager.autoSwitch, true);
});

test('checkPeriod defaults to 30000', () => {
  const manager = new ConnectionManager({
    connections: [{ uri: 'http://localhost:19081' }]
  });
  assertEqual(manager.checkPeriod, 30000);
});

test('proxyType defaults to daemon', () => {
  const manager = new ConnectionManager({
    connections: [{ uri: 'http://localhost:19081' }]
  });
  assertEqual(manager.proxyType, 'daemon');
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
  console.log('\n✓ All connection manager tests passed!');
  process.exit(0);
}
