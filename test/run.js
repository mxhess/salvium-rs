/**
 * salvium-js Test Suite
 *
 * Run with: node test/run.js
 */

import salvium, {
  keccak256,
  keccak256Hex,
  encode,
  decode,
  parseAddress,
  isValidAddress,
  isMainnet,
  isCarrot,
  isLegacy,
  describeAddress,
  bytesToHex,
  hexToBytes,
  NETWORK,
  ADDRESS_FORMAT,
  ADDRESS_TYPE
} from '../src/index.js';

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

function assertEqual(actual, expected, msg = '') {
  if (actual !== expected) {
    throw new Error(`${msg} Expected ${expected}, got ${actual}`);
  }
}

function assertArrayEqual(actual, expected, msg = '') {
  if (actual.length !== expected.length) {
    throw new Error(`${msg} Length mismatch: ${actual.length} vs ${expected.length}`);
  }
  for (let i = 0; i < actual.length; i++) {
    if (actual[i] !== expected[i]) {
      throw new Error(`${msg} Mismatch at index ${i}: ${actual[i]} vs ${expected[i]}`);
    }
  }
}

console.log('\n=== salvium-js Test Suite ===\n');

// Keccak-256 Tests
console.log('Keccak-256 Tests:');

test('Empty string hash', () => {
  // Known Keccak-256 hash of empty string
  const hash = keccak256Hex('');
  assertEqual(hash, 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470');
});

test('Simple string hash', () => {
  // Known Keccak-256 hash of "test"
  const hash = keccak256Hex('test');
  assertEqual(hash, '9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658');
});

test('Bytes input', () => {
  const input = new Uint8Array([0x74, 0x65, 0x73, 0x74]); // "test"
  const hash = keccak256Hex(input);
  assertEqual(hash, '9c22ff5f21f0b81b113e63f7db6da94fedef11b2119b4088b89664fb9a3cb658');
});

// Base58 Tests
console.log('\nBase58 Tests:');

test('Encode empty', () => {
  const result = encode(new Uint8Array(0));
  assertEqual(result, '');
});

test('Encode/decode roundtrip', () => {
  const original = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  const encoded = encode(original);
  const decoded = decode(encoded);
  assertArrayEqual(decoded, original);
});

test('Encode/decode 64 bytes (key size)', () => {
  // Simulate public keys (64 bytes)
  const original = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    original[i] = i;
  }
  const encoded = encode(original);
  const decoded = decode(encoded);
  assertArrayEqual(decoded, original);
});

// Utility Tests
console.log('\nUtility Tests:');

test('bytesToHex', () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x0f, 0xff]);
  assertEqual(bytesToHex(bytes), '00010fff');
});

test('hexToBytes', () => {
  const hex = '00010fff';
  const bytes = hexToBytes(hex);
  assertArrayEqual(bytes, new Uint8Array([0x00, 0x01, 0x0f, 0xff]));
});

test('Hex roundtrip', () => {
  const original = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const hex = bytesToHex(original);
  const recovered = hexToBytes(hex);
  assertArrayEqual(recovered, original);
});

// Address Validation Tests (with invalid addresses)
console.log('\nAddress Validation Tests:');

test('Reject empty string', () => {
  assertEqual(isValidAddress(''), false);
});

test('Reject too short', () => {
  assertEqual(isValidAddress('SaLv123'), false);
});

test('Reject invalid characters', () => {
  // 0, O, I, l are not in Base58 alphabet
  assertEqual(isValidAddress('SaLv0OIl' + 'x'.repeat(90)), false);
});

test('Reject invalid checksum', () => {
  // A valid-looking address with wrong checksum should fail
  const fakeAddr = '1'.repeat(95);
  assertEqual(isValidAddress(fakeAddr), false);
});

// Constants Tests
console.log('\nConstants Tests:');

test('Network constants exist', () => {
  assertEqual(NETWORK.MAINNET, 'mainnet');
  assertEqual(NETWORK.TESTNET, 'testnet');
  assertEqual(NETWORK.STAGENET, 'stagenet');
});

test('Address type constants exist', () => {
  assertEqual(ADDRESS_TYPE.STANDARD, 'standard');
  assertEqual(ADDRESS_TYPE.INTEGRATED, 'integrated');
  assertEqual(ADDRESS_TYPE.SUBADDRESS, 'subaddress');
});

test('Address format constants exist', () => {
  assertEqual(ADDRESS_FORMAT.LEGACY, 'legacy');
  assertEqual(ADDRESS_FORMAT.CARROT, 'carrot');
});

// Summary
console.log('\n=== Summary ===');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log('');

if (failed > 0) {
  process.exit(1);
}

// Interactive test with real addresses
console.log('=== Real Address Tests ===');
console.log('To test with real Salvium addresses, run:');
console.log('  node -e "import(\'./src/index.js\').then(s => console.log(s.parseAddress(\'YOUR_ADDRESS\')))"');
console.log('');
console.log('To run all tests including transaction/wallet tests:');
console.log('  bun test/all.js');
console.log('');
