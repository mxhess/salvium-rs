/**
 * Address Generation Tests
 *
 * Tests for address creation, integrated addresses, and high-level subaddress generation.
 */

import {
  generateSeed,
  deriveKeys,
  deriveCarrotKeys,
  createAddress,
  parseAddress,
  toIntegratedAddress,
  toStandardAddress,
  generateRandomPaymentId,
  createIntegratedAddressWithRandomId,
  generateCNSubaddress,
  generateCarrotSubaddress,
  isValidAddress,
  isMainnet,
  isTestnet,
  isStagenet,
  isCarrot,
  isLegacy,
  isStandard,
  isIntegrated,
  isSubaddress,
  bytesToHex,
  hexToBytes,
  seedToMnemonic,
  mnemonicToSeed,
  NETWORK,
  ADDRESS_TYPE,
  ADDRESS_FORMAT
} from '../src/index.js';

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
    throw new Error(`${message} Expected "${expected}", got "${actual}"`);
  }
}

function assertNotEqual(actual, expected, message = '') {
  if (actual === expected) {
    throw new Error(`${message} Values should not be equal: ${actual}`);
  }
}

function assertTrue(value, message = '') {
  if (!value) {
    throw new Error(`${message} Expected true, got ${value}`);
  }
}

function assertFalse(value, message = '') {
  if (value) {
    throw new Error(`${message} Expected false, got ${value}`);
  }
}

function assertLength(value, length, message = '') {
  if (value.length !== length) {
    throw new Error(`${message} Expected length ${length}, got ${value.length}`);
  }
}

// ============================================================
// Seed Generation Tests
// ============================================================

console.log('\n--- Seed Generation Tests ---');

test('generateSeed returns 32 bytes', () => {
  const seed = generateSeed();
  assertLength(seed, 32);
});

test('generateSeed returns Uint8Array', () => {
  const seed = generateSeed();
  assertTrue(seed instanceof Uint8Array);
});

test('generateSeed produces different seeds each time', () => {
  const seed1 = generateSeed();
  const seed2 = generateSeed();
  assertNotEqual(bytesToHex(seed1), bytesToHex(seed2));
});

test('generateSeed produces non-zero seeds', () => {
  const seed = generateSeed();
  let hasNonZero = false;
  for (let i = 0; i < seed.length; i++) {
    if (seed[i] !== 0) {
      hasNonZero = true;
      break;
    }
  }
  assertTrue(hasNonZero, 'Seed should have non-zero bytes');
});

// ============================================================
// Address Creation Tests
// ============================================================

console.log('\n--- Address Creation Tests ---');

const testSeed = generateSeed();
const testKeys = deriveKeys(testSeed);

test('createAddress creates valid mainnet legacy standard address', () => {
  const addr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  assertTrue(addr !== null, 'Address should not be null');
  assertTrue(isValidAddress(addr), 'Address should be valid');
  assertTrue(isMainnet(addr), 'Should be mainnet');
  assertTrue(isLegacy(addr), 'Should be legacy');
  assertTrue(isStandard(addr), 'Should be standard');
});

test('createAddress creates valid mainnet CARROT standard address', () => {
  const addr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.CARROT,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  assertTrue(addr !== null);
  assertTrue(isValidAddress(addr));
  assertTrue(isMainnet(addr));
  assertTrue(isCarrot(addr));
  assertTrue(isStandard(addr));
});

test('createAddress creates valid testnet address', () => {
  const addr = createAddress({
    network: NETWORK.TESTNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  assertTrue(addr !== null);
  assertTrue(isValidAddress(addr));
  assertTrue(isTestnet(addr));
});

test('createAddress creates valid stagenet address', () => {
  const addr = createAddress({
    network: NETWORK.STAGENET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  assertTrue(addr !== null);
  assertTrue(isValidAddress(addr));
  assertTrue(isStagenet(addr));
});

test('createAddress returns null for invalid keys', () => {
  const addr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: new Uint8Array(31), // Wrong length
    viewPublicKey: testKeys.viewPublicKey
  });
  assertEqual(addr, null);
});

test('createAddress round-trips correctly', () => {
  const addr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const parsed = parseAddress(addr);
  assertTrue(parsed.valid);
  assertEqual(bytesToHex(parsed.spendPublicKey), bytesToHex(testKeys.spendPublicKey));
  assertEqual(bytesToHex(parsed.viewPublicKey), bytesToHex(testKeys.viewPublicKey));
});

// ============================================================
// Integrated Address Tests
// ============================================================

console.log('\n--- Integrated Address Tests ---');

test('toIntegratedAddress creates valid integrated address', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const paymentId = generateRandomPaymentId();
  const integrated = toIntegratedAddress(standardAddr, paymentId);

  assertTrue(integrated !== null);
  assertTrue(isValidAddress(integrated));
  assertTrue(isIntegrated(integrated));
  assertTrue(isMainnet(integrated));
});

test('toIntegratedAddress accepts hex string payment ID', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const integrated = toIntegratedAddress(standardAddr, 'deadbeef12345678');

  assertTrue(integrated !== null);
  assertTrue(isIntegrated(integrated));
});

test('toIntegratedAddress preserves payment ID', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const paymentIdHex = 'deadbeef12345678';
  const integrated = toIntegratedAddress(standardAddr, paymentIdHex);
  const parsed = parseAddress(integrated);

  assertEqual(bytesToHex(parsed.paymentId), paymentIdHex);
});

test('toIntegratedAddress returns null for integrated address input', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const integrated = toIntegratedAddress(standardAddr, 'deadbeef12345678');
  const doubleIntegrated = toIntegratedAddress(integrated, 'abcdef0123456789');

  assertEqual(doubleIntegrated, null);
});

test('toStandardAddress extracts standard from integrated', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const integrated = toIntegratedAddress(standardAddr, 'deadbeef12345678');
  const extracted = toStandardAddress(integrated);

  assertEqual(extracted, standardAddr);
});

test('toStandardAddress returns null for non-integrated', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const result = toStandardAddress(standardAddr);

  assertEqual(result, null);
});

test('createIntegratedAddressWithRandomId works', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const result = createIntegratedAddressWithRandomId(standardAddr);

  assertTrue(result !== null);
  assertTrue(result.address !== null);
  assertTrue(isIntegrated(result.address));
  assertLength(result.paymentId, 8);
  assertLength(result.paymentIdHex, 16);
});

test('createIntegratedAddressWithRandomId generates unique payment IDs', () => {
  const standardAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const result1 = createIntegratedAddressWithRandomId(standardAddr);
  const result2 = createIntegratedAddressWithRandomId(standardAddr);

  assertNotEqual(result1.paymentIdHex, result2.paymentIdHex);
});

// ============================================================
// High-Level Subaddress Generation Tests
// ============================================================

console.log('\n--- High-Level Subaddress Generation Tests ---');

test('generateCNSubaddress creates valid subaddress', () => {
  const result = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey,
    major: 0,
    minor: 1
  });

  assertTrue(result !== null);
  assertTrue(result.address !== null);
  assertTrue(isValidAddress(result.address));
  assertTrue(isSubaddress(result.address));
  assertTrue(isLegacy(result.address));
  assertLength(result.spendPublicKey, 32);
  assertLength(result.viewPublicKey, 32);
  assertEqual(result.major, 0);
  assertEqual(result.minor, 1);
});

test('generateCNSubaddress (0,0) creates standard address', () => {
  const result = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey,
    major: 0,
    minor: 0
  });

  // (0,0) should return original keys, but as subaddress type
  assertEqual(bytesToHex(result.spendPublicKey), bytesToHex(testKeys.spendPublicKey));
});

test('generateCNSubaddress creates different addresses for different indices', () => {
  const result1 = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey,
    major: 0,
    minor: 1
  });
  const result2 = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey,
    major: 0,
    minor: 2
  });

  assertNotEqual(result1.address, result2.address);
});

test('generateCarrotSubaddress creates valid CARROT subaddress', () => {
  const carrotKeys = deriveCarrotKeys(testSeed);
  const result = generateCarrotSubaddress({
    network: NETWORK.MAINNET,
    accountSpendPubkey: testKeys.spendPublicKey,
    accountViewPubkey: testKeys.viewPublicKey,
    generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret),
    major: 0,
    minor: 1
  });

  assertTrue(result !== null);
  assertTrue(result.address !== null);
  assertTrue(isValidAddress(result.address));
  assertTrue(isCarrot(result.address));
  assertFalse(result.isMainAddress);
});

test('generateCarrotSubaddress (0,0) returns main address', () => {
  const carrotKeys = deriveCarrotKeys(testSeed);
  const result = generateCarrotSubaddress({
    network: NETWORK.MAINNET,
    accountSpendPubkey: testKeys.spendPublicKey,
    accountViewPubkey: testKeys.viewPublicKey,
    generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret),
    major: 0,
    minor: 0
  });

  assertTrue(result.isMainAddress);
  assertTrue(isStandard(result.address));
});

// ============================================================
// Full Wallet Generation Flow Test
// ============================================================

console.log('\n--- Full Wallet Generation Flow ---');

test('Complete wallet generation flow works', () => {
  // 1. Generate seed
  const seed = generateSeed();
  assertLength(seed, 32);

  // 2. Derive keys
  const keys = deriveKeys(seed);
  assertLength(keys.spendSecretKey, 32);
  assertLength(keys.spendPublicKey, 32);
  assertLength(keys.viewSecretKey, 32);
  assertLength(keys.viewPublicKey, 32);

  // 3. Create main address
  const mainAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });
  assertTrue(isValidAddress(mainAddress));
  assertTrue(isStandard(mainAddress));

  // 4. Generate subaddress
  const subaddress = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: keys.spendPublicKey,
    viewSecretKey: keys.viewSecretKey,
    major: 0,
    minor: 1
  });
  assertTrue(isValidAddress(subaddress.address));
  assertTrue(isSubaddress(subaddress.address));

  // 5. Create integrated address
  const integrated = createIntegratedAddressWithRandomId(mainAddress);
  assertTrue(isValidAddress(integrated.address));
  assertTrue(isIntegrated(integrated.address));

  // 6. Verify addresses are on same network
  assertTrue(isMainnet(mainAddress));
  assertTrue(isMainnet(subaddress.address));
  assertTrue(isMainnet(integrated.address));
});

test('Complete CARROT wallet generation flow works', () => {
  // 1. Generate seed
  const seed = generateSeed();

  // 2. Derive keys
  const keys = deriveKeys(seed);
  const carrotKeys = deriveCarrotKeys(seed);

  // 3. Create CARROT main address
  const mainAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.CARROT,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });
  assertTrue(isValidAddress(mainAddress));
  assertTrue(isCarrot(mainAddress));

  // 4. Generate CARROT subaddress
  const subaddress = generateCarrotSubaddress({
    network: NETWORK.MAINNET,
    accountSpendPubkey: keys.spendPublicKey,
    accountViewPubkey: keys.viewPublicKey,
    generateAddressSecret: hexToBytes(carrotKeys.generateAddressSecret),
    major: 0,
    minor: 1
  });
  assertTrue(isValidAddress(subaddress.address));
  assertTrue(isCarrot(subaddress.address));
});

// ============================================================
// Recovery & Round-Trip Tests
// ============================================================

console.log('\n--- Recovery & Round-Trip Tests ---');

test('Seed -> Mnemonic -> Seed round-trip produces identical seed', () => {
  const originalSeed = generateSeed();
  const mnemonic = seedToMnemonic(originalSeed, { language: 'english' });
  const result = mnemonicToSeed(mnemonic, { language: 'english' });

  assertTrue(result.valid, 'Mnemonic should be valid');
  assertEqual(bytesToHex(result.seed), bytesToHex(originalSeed), 'Recovered seed should match original');
});

test('Seed -> Mnemonic -> Seed -> Keys produces identical keys', () => {
  const originalSeed = generateSeed();
  const originalKeys = deriveKeys(originalSeed);

  // Convert to mnemonic and back
  const mnemonic = seedToMnemonic(originalSeed, { language: 'english' });
  const result = mnemonicToSeed(mnemonic, { language: 'english' });
  const recoveredKeys = deriveKeys(result.seed);

  assertEqual(bytesToHex(recoveredKeys.spendSecretKey), bytesToHex(originalKeys.spendSecretKey));
  assertEqual(bytesToHex(recoveredKeys.spendPublicKey), bytesToHex(originalKeys.spendPublicKey));
  assertEqual(bytesToHex(recoveredKeys.viewSecretKey), bytesToHex(originalKeys.viewSecretKey));
  assertEqual(bytesToHex(recoveredKeys.viewPublicKey), bytesToHex(originalKeys.viewPublicKey));
});

test('Seed -> Mnemonic -> Seed -> Address produces identical address', () => {
  const originalSeed = generateSeed();
  const originalKeys = deriveKeys(originalSeed);
  const originalAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: originalKeys.spendPublicKey,
    viewPublicKey: originalKeys.viewPublicKey
  });

  // Recover from mnemonic
  const mnemonic = seedToMnemonic(originalSeed, { language: 'english' });
  const result = mnemonicToSeed(mnemonic, { language: 'english' });
  const recoveredKeys = deriveKeys(result.seed);
  const recoveredAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: recoveredKeys.spendPublicKey,
    viewPublicKey: recoveredKeys.viewPublicKey
  });

  assertEqual(recoveredAddress, originalAddress, 'Recovered address should match original');
});

test('Full wallet recovery flow with subaddresses', () => {
  // Original wallet
  const originalSeed = generateSeed();
  const originalKeys = deriveKeys(originalSeed);
  const originalMain = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: originalKeys.spendPublicKey,
    viewPublicKey: originalKeys.viewPublicKey
  });
  const originalSub = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: originalKeys.spendPublicKey,
    viewSecretKey: originalKeys.viewSecretKey,
    major: 0,
    minor: 5
  });

  // Backup and recover
  const mnemonic = seedToMnemonic(originalSeed, { language: 'english' });

  // Simulate recovery on different device
  const recoveryResult = mnemonicToSeed(mnemonic, { language: 'english' });
  assertTrue(recoveryResult.valid);

  const recoveredKeys = deriveKeys(recoveryResult.seed);
  const recoveredMain = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: recoveredKeys.spendPublicKey,
    viewPublicKey: recoveredKeys.viewPublicKey
  });
  const recoveredSub = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: recoveredKeys.spendPublicKey,
    viewSecretKey: recoveredKeys.viewSecretKey,
    major: 0,
    minor: 5
  });

  assertEqual(recoveredMain, originalMain, 'Main address should match');
  assertEqual(recoveredSub.address, originalSub.address, 'Subaddress should match');
});

test('CARROT wallet recovery flow', () => {
  // Original CARROT wallet
  const originalSeed = generateSeed();
  const originalKeys = deriveKeys(originalSeed);
  const originalCarrotKeys = deriveCarrotKeys(originalSeed);
  const originalAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.CARROT,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: originalKeys.spendPublicKey,
    viewPublicKey: originalKeys.viewPublicKey
  });

  // Backup and recover
  const mnemonic = seedToMnemonic(originalSeed, { language: 'english' });
  const recoveryResult = mnemonicToSeed(mnemonic, { language: 'english' });

  const recoveredKeys = deriveKeys(recoveryResult.seed);
  const recoveredCarrotKeys = deriveCarrotKeys(recoveryResult.seed);
  const recoveredAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.CARROT,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: recoveredKeys.spendPublicKey,
    viewPublicKey: recoveredKeys.viewPublicKey
  });

  assertEqual(recoveredAddress, originalAddress, 'CARROT address should match');
  assertEqual(recoveredCarrotKeys.proveSpendKey, originalCarrotKeys.proveSpendKey);
  assertEqual(recoveredCarrotKeys.viewBalanceSecret, originalCarrotKeys.viewBalanceSecret);
  assertEqual(recoveredCarrotKeys.generateAddressSecret, originalCarrotKeys.generateAddressSecret);
});

test('Mnemonic recovery works across all supported languages', () => {
  const originalSeed = generateSeed();
  const originalKeys = deriveKeys(originalSeed);
  const originalAddress = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: originalKeys.spendPublicKey,
    viewPublicKey: originalKeys.viewPublicKey
  });

  // Test a selection of languages
  const testLanguages = ['english', 'spanish', 'french', 'italian', 'portuguese'];

  for (const lang of testLanguages) {
    const mnemonic = seedToMnemonic(originalSeed, { language: lang });
    const result = mnemonicToSeed(mnemonic, { language: lang });

    assertTrue(result.valid, `${lang} mnemonic should be valid`);

    const recoveredKeys = deriveKeys(result.seed);
    const recoveredAddress = createAddress({
      network: NETWORK.MAINNET,
      format: ADDRESS_FORMAT.LEGACY,
      type: ADDRESS_TYPE.STANDARD,
      spendPublicKey: recoveredKeys.spendPublicKey,
      viewPublicKey: recoveredKeys.viewPublicKey
    });

    assertEqual(recoveredAddress, originalAddress, `${lang} recovery should produce same address`);
  }
});

test('Address parsing and recreation produces identical address', () => {
  const seed = generateSeed();
  const keys = deriveKeys(seed);
  const original = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });

  // Parse it
  const parsed = parseAddress(original);
  assertTrue(parsed.valid);

  // Recreate it from parsed components
  const recreated = createAddress({
    network: parsed.network,
    format: parsed.format,
    type: parsed.type,
    spendPublicKey: parsed.spendPublicKey,
    viewPublicKey: parsed.viewPublicKey
  });

  assertEqual(recreated, original);
});

test('Integrated address round-trip preserves all data', () => {
  const seed = generateSeed();
  const keys = deriveKeys(seed);
  const standard = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: keys.spendPublicKey,
    viewPublicKey: keys.viewPublicKey
  });

  const paymentId = 'abcdef0123456789';
  const integrated = toIntegratedAddress(standard, paymentId);

  // Parse integrated
  const parsed = parseAddress(integrated);
  assertTrue(parsed.valid);
  assertEqual(parsed.type, ADDRESS_TYPE.INTEGRATED);
  assertEqual(bytesToHex(parsed.paymentId), paymentId);

  // Extract standard and verify
  const extractedStandard = toStandardAddress(integrated);
  assertEqual(extractedStandard, standard);
});

// ============================================================
// Summary
// ============================================================

console.log('\n--- Address Test Summary ---');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n⚠️  Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All address tests passed!');
}
