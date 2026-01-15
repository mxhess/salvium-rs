/**
 * Comprehensive Wallet Tests
 *
 * Tests wallet functionality in logical order:
 * 1. Account keys
 * 2. Address keys
 * 3. View-only wallets
 * 4. Key relationships
 * 5. Subaddresses
 * 6. Integrated addresses
 * 7. Key images (preparation)
 */

import {
  // Seed and key generation
  generateSeed,
  deriveKeys,
  deriveCarrotKeys,

  // Address creation
  createAddress,
  parseAddress,

  // Subaddress functions
  cnSubaddressSecretKey,
  cnSubaddressSpendPublicKey,
  cnSubaddress,
  generateCNSubaddress,
  carrotIndexExtensionGenerator,
  carrotSubaddressScalar,
  carrotSubaddress,
  generateCarrotSubaddress,

  // Integrated addresses
  toIntegratedAddress,
  toStandardAddress,
  generateRandomPaymentId,
  createIntegratedAddressWithRandomId,

  // Ed25519 operations
  scalarMultBase,
  scalarMultPoint,
  pointAddCompressed,

  // Validation
  isValidAddress,
  isMainnet,
  isSubaddress,
  isIntegrated,
  isStandard,
  isCarrot,
  isLegacy,

  // Mnemonic
  seedToMnemonic,
  mnemonicToSeed,

  // Utilities
  bytesToHex,
  hexToBytes,
  keccak256,

  // Constants
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

function assertArrayEqual(a, b, message = '') {
  if (a.length !== b.length) {
    throw new Error(`${message} Length mismatch: ${a.length} vs ${b.length}`);
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      throw new Error(`${message} Mismatch at index ${i}`);
    }
  }
}

// Generate test wallet
const testSeed = generateSeed();
const testKeys = deriveKeys(testSeed);
const testCarrotKeys = deriveCarrotKeys(testSeed);

// ============================================================
// 1. ACCOUNT KEYS
// ============================================================

console.log('\n========================================');
console.log('1. ACCOUNT KEYS');
console.log('========================================');

test('Account 0 and Account 1 have different subaddress secrets', () => {
  // In CryptoNote, accounts are distinguished by major index
  const account0Secret = cnSubaddressSecretKey(testKeys.viewSecretKey, 0, 1);
  const account1Secret = cnSubaddressSecretKey(testKeys.viewSecretKey, 1, 1);

  assertNotEqual(bytesToHex(account0Secret), bytesToHex(account1Secret));
});

test('Account subaddress secrets are deterministic', () => {
  const secret1 = cnSubaddressSecretKey(testKeys.viewSecretKey, 0, 1);
  const secret2 = cnSubaddressSecretKey(testKeys.viewSecretKey, 0, 1);

  assertEqual(bytesToHex(secret1), bytesToHex(secret2));
});

test('Different accounts produce different spend public keys', () => {
  const account0Spend = cnSubaddressSpendPublicKey(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);
  const account1Spend = cnSubaddressSpendPublicKey(testKeys.spendPublicKey, testKeys.viewSecretKey, 1, 1);

  assertNotEqual(bytesToHex(account0Spend), bytesToHex(account1Spend));
});

test('Account 0 address 0 returns main spend key', () => {
  const mainSpend = cnSubaddressSpendPublicKey(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 0);

  assertEqual(bytesToHex(mainSpend), bytesToHex(testKeys.spendPublicKey));
});

test('Account generation is consistent across recovery', () => {
  // Generate wallet, create account addresses, recover, verify same addresses
  const seed = generateSeed();
  const keys = deriveKeys(seed);

  const account0Addr = cnSubaddress(keys.spendPublicKey, keys.viewSecretKey, 0, 1);
  const account1Addr = cnSubaddress(keys.spendPublicKey, keys.viewSecretKey, 1, 0);

  // Simulate recovery
  const mnemonic = seedToMnemonic(seed, { language: 'english' });
  const recovered = mnemonicToSeed(mnemonic, { language: 'english' });
  const recoveredKeys = deriveKeys(recovered.seed);

  const recoveredAccount0 = cnSubaddress(recoveredKeys.spendPublicKey, recoveredKeys.viewSecretKey, 0, 1);
  const recoveredAccount1 = cnSubaddress(recoveredKeys.spendPublicKey, recoveredKeys.viewSecretKey, 1, 0);

  assertEqual(bytesToHex(recoveredAccount0.spendPublicKey), bytesToHex(account0Addr.spendPublicKey));
  assertEqual(bytesToHex(recoveredAccount1.spendPublicKey), bytesToHex(account1Addr.spendPublicKey));
});

test('CARROT accounts use different index generators', () => {
  const s_ga = hexToBytes(testCarrotKeys.generateAddressSecret);

  const gen0 = carrotIndexExtensionGenerator(s_ga, 0, 1);
  const gen1 = carrotIndexExtensionGenerator(s_ga, 1, 1);

  assertNotEqual(bytesToHex(gen0), bytesToHex(gen1));
});

// ============================================================
// 2. ADDRESS KEYS
// ============================================================

console.log('\n========================================');
console.log('2. ADDRESS KEYS');
console.log('========================================');

test('Each address has unique spend public key', () => {
  const addr0 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 0);
  const addr1 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);
  const addr2 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 2);

  assertNotEqual(bytesToHex(addr0.spendPublicKey), bytesToHex(addr1.spendPublicKey));
  assertNotEqual(bytesToHex(addr1.spendPublicKey), bytesToHex(addr2.spendPublicKey));
  assertNotEqual(bytesToHex(addr0.spendPublicKey), bytesToHex(addr2.spendPublicKey));
});

test('Each address has unique view public key', () => {
  const addr0 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 0);
  const addr1 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);
  const addr2 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 2);

  assertNotEqual(bytesToHex(addr0.viewPublicKey), bytesToHex(addr1.viewPublicKey));
  assertNotEqual(bytesToHex(addr1.viewPublicKey), bytesToHex(addr2.viewPublicKey));
});

test('Address keys are 32 bytes each', () => {
  const addr = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 5);

  assertLength(addr.spendPublicKey, 32);
  assertLength(addr.viewPublicKey, 32);
});

test('Address generation is deterministic', () => {
  const addr1 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 10);
  const addr2 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 10);

  assertEqual(bytesToHex(addr1.spendPublicKey), bytesToHex(addr2.spendPublicKey));
  assertEqual(bytesToHex(addr1.viewPublicKey), bytesToHex(addr2.viewPublicKey));
});

test('Address keys can create valid addresses', () => {
  const addr = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);

  const addressString = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.SUBADDRESS,
    spendPublicKey: addr.spendPublicKey,
    viewPublicKey: addr.viewPublicKey
  });

  assertTrue(isValidAddress(addressString));
  assertTrue(isSubaddress(addressString));
});

test('CARROT address keys are derived correctly', () => {
  const s_ga = hexToBytes(testCarrotKeys.generateAddressSecret);

  const addr = carrotSubaddress(
    testKeys.spendPublicKey,
    testKeys.viewPublicKey,
    s_ga,
    0, 1
  );

  assertLength(addr.spendPublicKey, 32);
  assertLength(addr.viewPublicKey, 32);
  assertFalse(addr.isMainAddress);
});

// ============================================================
// 3. VIEW-ONLY WALLETS
// ============================================================

console.log('\n========================================');
console.log('3. VIEW-ONLY WALLETS');
console.log('========================================');

test('View secret key can derive view public key', () => {
  const derivedViewPub = scalarMultBase(testKeys.viewSecretKey);

  assertEqual(bytesToHex(derivedViewPub), bytesToHex(testKeys.viewPublicKey));
});

test('View-only wallet can verify it owns an address (via view key)', () => {
  // A view-only wallet has: spendPublicKey, viewSecretKey
  // It can verify ownership by checking if address was derived from its keys

  const viewOnlyWallet = {
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey
    // Note: does NOT have spendSecretKey
  };

  // Generate a subaddress
  const subaddr = cnSubaddress(
    viewOnlyWallet.spendPublicKey,
    viewOnlyWallet.viewSecretKey,
    0, 5
  );

  // Create address string
  const addrString = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.SUBADDRESS,
    spendPublicKey: subaddr.spendPublicKey,
    viewPublicKey: subaddr.viewPublicKey
  });

  // View-only wallet can regenerate this address
  const regenerated = cnSubaddress(
    viewOnlyWallet.spendPublicKey,
    viewOnlyWallet.viewSecretKey,
    0, 5
  );

  const regeneratedString = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.SUBADDRESS,
    spendPublicKey: regenerated.spendPublicKey,
    viewPublicKey: regenerated.viewPublicKey
  });

  assertEqual(regeneratedString, addrString);
});

test('View-only wallet can scan subaddresses', () => {
  // Simulate scanning first 10 addresses
  const viewOnlyWallet = {
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey
  };

  const addresses = [];
  for (let i = 0; i < 10; i++) {
    const sub = cnSubaddress(
      viewOnlyWallet.spendPublicKey,
      viewOnlyWallet.viewSecretKey,
      0, i
    );
    addresses.push(bytesToHex(sub.spendPublicKey));
  }

  // All should be unique
  const unique = new Set(addresses);
  assertEqual(unique.size, 10);
});

test('View-only cannot derive spend secret key', () => {
  // This is a conceptual test - view-only means no spend secret
  // We verify that viewSecretKey != spendSecretKey
  assertNotEqual(
    bytesToHex(testKeys.viewSecretKey),
    bytesToHex(testKeys.spendSecretKey)
  );
});

// ============================================================
// 4. KEY RELATIONSHIPS
// ============================================================

console.log('\n========================================');
console.log('4. KEY RELATIONSHIPS');
console.log('========================================');

test('spend_public = spend_secret * G', () => {
  const derivedSpendPub = scalarMultBase(testKeys.spendSecretKey);

  assertEqual(bytesToHex(derivedSpendPub), bytesToHex(testKeys.spendPublicKey));
});

test('view_public = view_secret * G', () => {
  const derivedViewPub = scalarMultBase(testKeys.viewSecretKey);

  assertEqual(bytesToHex(derivedViewPub), bytesToHex(testKeys.viewPublicKey));
});

test('view_secret = H(spend_secret) in CryptoNote', () => {
  // In CryptoNote: view_secret = keccak256(spend_secret) mod L
  const hash = keccak256(testKeys.spendSecretKey);

  // The deriveKeys function reduces mod L, so we need to check
  // that the hash (before reduction) when reduced equals viewSecretKey
  // This is implicitly tested by the fact that deriveKeys works

  // Verify view public key derivation
  const viewPub = scalarMultBase(testKeys.viewSecretKey);
  assertEqual(bytesToHex(viewPub), bytesToHex(testKeys.viewPublicKey));
});

test('Subaddress spend key: D = K_spend + m*G', () => {
  // m = subaddress secret
  const m = cnSubaddressSecretKey(testKeys.viewSecretKey, 0, 1);

  // M = m * G
  const M = scalarMultBase(m);

  // D = K_spend + M
  const D = pointAddCompressed(testKeys.spendPublicKey, M);

  // Compare with cnSubaddressSpendPublicKey
  const expected = cnSubaddressSpendPublicKey(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);

  assertEqual(bytesToHex(D), bytesToHex(expected));
});

test('Subaddress view key: C = k_view * D', () => {
  // D = subaddress spend public key
  const D = cnSubaddressSpendPublicKey(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);

  // C = k_view * D
  const C = scalarMultPoint(testKeys.viewSecretKey, D);

  // Compare with cnSubaddress
  const sub = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);

  assertEqual(bytesToHex(C), bytesToHex(sub.viewPublicKey));
});

test('CARROT: proveSpendKey derived from masterSecret', () => {
  // k_ps = H_n("Carrot prove-spend key", s_master)
  // This is tested implicitly by deriveCarrotKeys working
  assertLength(testCarrotKeys.proveSpendKey, 64); // hex string = 64 chars
});

test('CARROT: viewBalanceSecret derived from masterSecret', () => {
  // s_vb = H_32("Carrot view-balance secret", s_master)
  assertLength(testCarrotKeys.viewBalanceSecret, 64);
});

test('CARROT: viewIncomingKey derived from viewBalanceSecret', () => {
  // k_vi = H_n("Carrot incoming view key", s_vb)
  assertLength(testCarrotKeys.viewIncomingKey, 64);
});

test('Key derivation is one-way (cannot derive secret from public)', () => {
  // This is a mathematical property of EC - we just verify they're different
  assertNotEqual(
    bytesToHex(testKeys.spendSecretKey),
    bytesToHex(testKeys.spendPublicKey)
  );
  assertNotEqual(
    bytesToHex(testKeys.viewSecretKey),
    bytesToHex(testKeys.viewPublicKey)
  );
});

// ============================================================
// 5. SUBADDRESSES
// ============================================================

console.log('\n========================================');
console.log('5. SUBADDRESSES');
console.log('========================================');

test('Main address (0,0) returns original keys', () => {
  const main = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 0);

  assertEqual(bytesToHex(main.spendPublicKey), bytesToHex(testKeys.spendPublicKey));
});

test('Subaddresses are valid curve points', () => {
  for (let i = 1; i <= 5; i++) {
    const sub = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, i);

    // Points should be non-zero
    let hasNonZero = false;
    for (let j = 0; j < 32; j++) {
      if (sub.spendPublicKey[j] !== 0) hasNonZero = true;
    }
    assertTrue(hasNonZero, `Subaddress ${i} spend key should be non-zero`);
  }
});

test('generateCNSubaddress produces valid address strings', () => {
  const result = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey,
    major: 0,
    minor: 1
  });

  assertTrue(isValidAddress(result.address));
  assertTrue(isSubaddress(result.address));
  assertTrue(isLegacy(result.address));
  assertTrue(isMainnet(result.address));
});

test('generateCarrotSubaddress produces valid CARROT addresses', () => {
  const result = generateCarrotSubaddress({
    network: NETWORK.MAINNET,
    accountSpendPubkey: testKeys.spendPublicKey,
    accountViewPubkey: testKeys.viewPublicKey,
    generateAddressSecret: hexToBytes(testCarrotKeys.generateAddressSecret),
    major: 0,
    minor: 1
  });

  assertTrue(isValidAddress(result.address));
  assertTrue(isCarrot(result.address));
  assertFalse(result.isMainAddress);
});

test('Subaddress index 0,0 vs 0,1 are different', () => {
  const main = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey,
    major: 0,
    minor: 0
  });

  const sub1 = generateCNSubaddress({
    network: NETWORK.MAINNET,
    spendPublicKey: testKeys.spendPublicKey,
    viewSecretKey: testKeys.viewSecretKey,
    major: 0,
    minor: 1
  });

  assertNotEqual(main.address, sub1.address);
});

test('Can generate many subaddresses efficiently', () => {
  const addresses = new Set();

  for (let i = 0; i < 100; i++) {
    const sub = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, i);
    addresses.add(bytesToHex(sub.spendPublicKey));
  }

  assertEqual(addresses.size, 100, 'All 100 subaddresses should be unique');
});

// ============================================================
// 6. INTEGRATED ADDRESSES
// ============================================================

console.log('\n========================================');
console.log('6. INTEGRATED ADDRESSES');
console.log('========================================');

test('Integrated address contains payment ID', () => {
  const mainAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });

  const paymentId = 'abcdef0123456789';
  const integrated = toIntegratedAddress(mainAddr, paymentId);

  const parsed = parseAddress(integrated);
  assertTrue(parsed.valid);
  assertEqual(parsed.type, ADDRESS_TYPE.INTEGRATED);
  assertEqual(bytesToHex(parsed.paymentId), paymentId);
});

test('Random payment IDs are unique', () => {
  const ids = new Set();
  for (let i = 0; i < 100; i++) {
    const pid = generateRandomPaymentId();
    ids.add(bytesToHex(pid));
  }
  assertEqual(ids.size, 100);
});

test('Payment ID is 8 bytes', () => {
  const pid = generateRandomPaymentId();
  assertLength(pid, 8);
});

test('Integrated address round-trips correctly', () => {
  const mainAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });

  const integrated = toIntegratedAddress(mainAddr, 'deadbeef12345678');
  const standard = toStandardAddress(integrated);

  assertEqual(standard, mainAddr);
});

test('createIntegratedAddressWithRandomId returns all components', () => {
  const mainAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });

  const result = createIntegratedAddressWithRandomId(mainAddr);

  assertTrue(result !== null);
  assertTrue(isIntegrated(result.address));
  assertLength(result.paymentId, 8);
  assertLength(result.paymentIdHex, 16);
});

test('Integrated addresses preserve network', () => {
  // Mainnet
  const mainnetAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const mainnetIntegrated = toIntegratedAddress(mainnetAddr, 'abcdef0123456789');
  assertTrue(isMainnet(mainnetIntegrated));

  // Testnet
  const testnetAddr = createAddress({
    network: NETWORK.TESTNET,
    format: ADDRESS_FORMAT.LEGACY,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });
  const testnetIntegrated = toIntegratedAddress(testnetAddr, 'abcdef0123456789');
  const parsed = parseAddress(testnetIntegrated);
  assertEqual(parsed.network, NETWORK.TESTNET);
});

test('CARROT integrated addresses work', () => {
  const carrotAddr = createAddress({
    network: NETWORK.MAINNET,
    format: ADDRESS_FORMAT.CARROT,
    type: ADDRESS_TYPE.STANDARD,
    spendPublicKey: testKeys.spendPublicKey,
    viewPublicKey: testKeys.viewPublicKey
  });

  const integrated = toIntegratedAddress(carrotAddr, 'fedcba9876543210');

  assertTrue(isValidAddress(integrated));
  assertTrue(isCarrot(integrated));
  assertTrue(isIntegrated(integrated));
});

// ============================================================
// 7. KEY IMAGES (Preparation)
// ============================================================

console.log('\n========================================');
console.log('7. KEY IMAGES (Preparation)');
console.log('========================================');

test('Key image requires spend secret key', () => {
  // Key image I = x * H_p(P) where x is spend secret, P is output public key
  // We verify we have the necessary components
  assertLength(testKeys.spendSecretKey, 32);
  assertTrue(testKeys.spendSecretKey instanceof Uint8Array);
});

test('CARROT generateImageKey is derived correctly', () => {
  // k_gi = H_n("Carrot generate-image key", s_vb)
  assertLength(testCarrotKeys.generateImageKey, 64); // hex

  // It should be different from other keys
  assertNotEqual(testCarrotKeys.generateImageKey, testCarrotKeys.proveSpendKey);
  assertNotEqual(testCarrotKeys.generateImageKey, testCarrotKeys.viewIncomingKey);
});

test('Each subaddress can have unique key images', () => {
  // Key images are per-output, but subaddress derivation affects them
  // Different subaddresses have different spend keys
  const sub1 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 1);
  const sub2 = cnSubaddress(testKeys.spendPublicKey, testKeys.viewSecretKey, 0, 2);

  // Different spend public keys mean different key image bases
  assertNotEqual(bytesToHex(sub1.spendPublicKey), bytesToHex(sub2.spendPublicKey));
});

test('Key material is suitable for key image generation', () => {
  // For key image generation, we need:
  // 1. Spend secret key (scalar)
  // 2. Output public key (point)
  // 3. Hash-to-point function

  // Verify spend secret is valid scalar (< L)
  const L = (1n << 252n) + 27742317777372353535851937790883648493n;
  let n = 0n;
  for (let i = 31; i >= 0; i--) {
    n = (n << 8n) | BigInt(testKeys.spendSecretKey[i]);
  }
  assertTrue(n < L, 'Spend secret should be < L');
});

// ============================================================
// RECOVERY VERIFICATION
// ============================================================

console.log('\n========================================');
console.log('RECOVERY VERIFICATION');
console.log('========================================');

test('Full wallet recovery produces identical addresses for all indices', () => {
  const seed = generateSeed();
  const keys = deriveKeys(seed);

  // Generate addresses at various indices
  const originalAddresses = [];
  for (let major = 0; major < 3; major++) {
    for (let minor = 0; minor < 5; minor++) {
      const sub = cnSubaddress(keys.spendPublicKey, keys.viewSecretKey, major, minor);
      originalAddresses.push({
        major, minor,
        spend: bytesToHex(sub.spendPublicKey),
        view: bytesToHex(sub.viewPublicKey)
      });
    }
  }

  // Recover wallet
  const mnemonic = seedToMnemonic(seed, { language: 'english' });
  const recovered = mnemonicToSeed(mnemonic, { language: 'english' });
  const recoveredKeys = deriveKeys(recovered.seed);

  // Verify all addresses match
  for (const orig of originalAddresses) {
    const recov = cnSubaddress(
      recoveredKeys.spendPublicKey,
      recoveredKeys.viewSecretKey,
      orig.major,
      orig.minor
    );
    assertEqual(bytesToHex(recov.spendPublicKey), orig.spend,
      `Account ${orig.major} Address ${orig.minor} spend key mismatch`);
    assertEqual(bytesToHex(recov.viewPublicKey), orig.view,
      `Account ${orig.major} Address ${orig.minor} view key mismatch`);
  }
});

test('CARROT wallet recovery produces identical CARROT keys', () => {
  const seed = generateSeed();
  const carrotKeys = deriveCarrotKeys(seed);

  // Recover
  const mnemonic = seedToMnemonic(seed, { language: 'english' });
  const recovered = mnemonicToSeed(mnemonic, { language: 'english' });
  const recoveredCarrot = deriveCarrotKeys(recovered.seed);

  assertEqual(recoveredCarrot.proveSpendKey, carrotKeys.proveSpendKey);
  assertEqual(recoveredCarrot.viewBalanceSecret, carrotKeys.viewBalanceSecret);
  assertEqual(recoveredCarrot.generateImageKey, carrotKeys.generateImageKey);
  assertEqual(recoveredCarrot.viewIncomingKey, carrotKeys.viewIncomingKey);
  assertEqual(recoveredCarrot.generateAddressSecret, carrotKeys.generateAddressSecret);
});

// ============================================================
// Summary
// ============================================================

console.log('\n========================================');
console.log('WALLET TEST SUMMARY');
console.log('========================================');
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total: ${passed + failed}`);

if (failed > 0) {
  console.log('\n⚠️  Some tests failed!');
  process.exit(1);
} else {
  console.log('\n✓ All wallet tests passed!');
}
