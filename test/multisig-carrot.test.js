/**
 * Multisig CARROT Tests
 *
 * Tests CARROT key derivation from multisig accounts,
 * payment/transaction proposals, and serialization.
 */

import { describe, test, expect } from 'bun:test';
import {
  CarrotPaymentProposal,
  CarrotTransactionProposal,
  MultisigCarrotAccount,
  CARROT_ENOTE_TYPE,
  buildMultisigCarrotTx,
  generateMultisigCarrotKeyImage
} from '../src/multisig-carrot.js';
import { bytesToHex } from '../src/address.js';
import { randomScalar } from '../src/crypto/index.js';

// Helper: create a MultisigCarrotAccount with simulated KEX completion
function createCompletedAccount() {
  const account = new MultisigCarrotAccount({
    threshold: 2,
    signerCount: 2,
    spendSecretKey: randomScalar(),
    viewSecretKey: randomScalar()
  });

  // Simulate KEX completion by setting internal state
  account.kexComplete = true;
  account.multisigSpendSecretKey = randomScalar();
  account.multisigCommonSecretKey = randomScalar();

  return account;
}

describe('CarrotPaymentProposal', () => {
  test('constructor with defaults', () => {
    const p = new CarrotPaymentProposal();
    expect(p.destination).toBe('');
    expect(p.amount).toBe(0n);
    expect(p.assetType).toBe('SAL');
    expect(p.isSubaddress).toBe(false);
  });

  test('constructor with config', () => {
    const p = new CarrotPaymentProposal({
      destination: 'SC1test...',
      amount: 1000000000n,
      assetType: 'VSD',
      isSubaddress: true
    });
    expect(p.destination).toBe('SC1test...');
    expect(p.amount).toBe(1000000000n);
    expect(p.assetType).toBe('VSD');
    expect(p.isSubaddress).toBe(true);
  });

  test('toJSON/fromJSON round-trip', () => {
    const original = new CarrotPaymentProposal({
      destination: 'SC1abc123',
      amount: 5000000000n,
      assetType: 'SAL',
      isSubaddress: false
    });
    const json = original.toJSON();
    const restored = CarrotPaymentProposal.fromJSON(json);

    expect(restored.destination).toBe(original.destination);
    expect(restored.amount).toBe(original.amount);
    expect(restored.assetType).toBe(original.assetType);
    expect(restored.isSubaddress).toBe(original.isSubaddress);
  });

  test('toJSON serializes amount as string', () => {
    const p = new CarrotPaymentProposal({ amount: 999999999999n });
    const json = p.toJSON();
    expect(typeof json.amount).toBe('string');
    expect(json.amount).toBe('999999999999');
  });
});

describe('CarrotTransactionProposal', () => {
  test('constructor defaults', () => {
    const tp = new CarrotTransactionProposal();
    expect(tp.paymentProposals).toEqual([]);
    expect(tp.selfSendProposals).toEqual([]);
    expect(tp.fee).toBe(0n);
    expect(tp.txType).toBe(3);
  });

  test('addPayment adds proposal', () => {
    const tp = new CarrotTransactionProposal();
    tp.addPayment('SC1dest', 1000000000n);
    expect(tp.paymentProposals.length).toBe(1);
    expect(tp.paymentProposals[0].destination).toBe('SC1dest');
    expect(tp.paymentProposals[0].amount).toBe(1000000000n);
  });

  test('addPayment with asset type', () => {
    const tp = new CarrotTransactionProposal();
    tp.addPayment('SC1dest', 500000000n, 'VSD', true);
    expect(tp.paymentProposals[0].assetType).toBe('VSD');
    expect(tp.paymentProposals[0].isSubaddress).toBe(true);
  });

  test('addSelfSend adds change output', () => {
    const tp = new CarrotTransactionProposal();
    tp.addSelfSend('SC1self', 200000000n, CARROT_ENOTE_TYPE.CHANGE);
    expect(tp.selfSendProposals.length).toBe(1);
    expect(tp.selfSendProposals[0].amount).toBe(200000000n);
  });

  test('getTotalAmount sums all outputs', () => {
    const tp = new CarrotTransactionProposal();
    tp.addPayment('SC1a', 1000000000n);
    tp.addPayment('SC1b', 500000000n);
    tp.addSelfSend('SC1self', 200000000n);
    expect(tp.getTotalAmount()).toBe(1700000000n);
  });

  test('toJSON/fromJSON round-trip', () => {
    const original = new CarrotTransactionProposal();
    original.addPayment('SC1dest1', 1000000000n, 'SAL');
    original.addPayment('SC1dest2', 500000000n, 'VSD', true);
    original.addSelfSend('SC1change', 300000000n);
    original.fee = 10000000n;
    original.txType = 4;

    const json = original.toJSON();
    const restored = CarrotTransactionProposal.fromJSON(json);

    expect(restored.paymentProposals.length).toBe(2);
    expect(restored.selfSendProposals.length).toBe(1);
    expect(restored.fee).toBe(10000000n);
    expect(restored.txType).toBe(4);
    expect(restored.paymentProposals[0].destination).toBe('SC1dest1');
    expect(restored.paymentProposals[1].assetType).toBe('VSD');
    expect(restored.selfSendProposals[0].amount).toBe(300000000n);
  });

  test('toJSON can be JSON.stringify\'d', () => {
    const tp = new CarrotTransactionProposal();
    tp.addPayment('SC1test', 1000n);
    tp.fee = 100n;
    const str = JSON.stringify(tp.toJSON());
    expect(typeof str).toBe('string');
    const parsed = JSON.parse(str);
    const restored = CarrotTransactionProposal.fromJSON(parsed);
    expect(restored.paymentProposals[0].amount).toBe(1000n);
  });

  test('getSignableHash returns 32 bytes', () => {
    const tp = new CarrotTransactionProposal();
    tp.addPayment('SC1dest', 1000000000n);
    tp.fee = 10000000n;
    const hash = tp.getSignableHash();
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(32);
  });

  test('getSignableHash is deterministic', () => {
    const tp1 = new CarrotTransactionProposal();
    tp1.addPayment('SC1dest', 1000000000n);
    tp1.fee = 10000000n;

    const tp2 = new CarrotTransactionProposal();
    tp2.addPayment('SC1dest', 1000000000n);
    tp2.fee = 10000000n;

    expect(bytesToHex(tp1.getSignableHash())).toBe(bytesToHex(tp2.getSignableHash()));
  });

  test('getSignableHash differs for different proposals', () => {
    const tp1 = new CarrotTransactionProposal();
    tp1.addPayment('SC1dest', 1000000000n);
    tp1.fee = 10000000n;

    const tp2 = new CarrotTransactionProposal();
    tp2.addPayment('SC1dest', 2000000000n);
    tp2.fee = 10000000n;

    expect(bytesToHex(tp1.getSignableHash())).not.toBe(bytesToHex(tp2.getSignableHash()));
  });
});

describe('MultisigCarrotAccount', () => {
  test('extends MultisigAccount', () => {
    const account = new MultisigCarrotAccount({
      threshold: 2,
      signerCount: 3
    });
    expect(account.threshold).toBe(2);
    expect(account.signerCount).toBe(3);
    expect(account.carrotKeys).toBeNull();
  });

  test('deriveCarrotKeys fails before KEX', () => {
    const account = new MultisigCarrotAccount({
      threshold: 2,
      signerCount: 2,
      spendSecretKey: randomScalar(),
      viewSecretKey: randomScalar()
    });
    expect(() => account.deriveCarrotKeys()).toThrow('Key exchange must be complete');
  });

  test('deriveCarrotKeys succeeds after KEX', () => {
    const account = createCompletedAccount();
    const keys = account.deriveCarrotKeys();

    expect(keys.proveSpendKey).toBeDefined();
    expect(keys.viewIncomingKey).toBeDefined();
    expect(keys.generateImageKey).toBeDefined();
    expect(keys.generateAddressSecret).toBeDefined();
    expect(keys.accountSpendPubkey).toBeDefined();

    // All should be 64-char hex strings (32 bytes)
    expect(keys.proveSpendKey.length).toBe(64);
    expect(keys.viewIncomingKey.length).toBe(64);
    expect(keys.generateImageKey.length).toBe(64);
    expect(keys.generateAddressSecret.length).toBe(64);
    expect(keys.accountSpendPubkey.length).toBe(64);
  });

  test('deriveCarrotKeys is deterministic', () => {
    const spendKey = randomScalar();
    const viewKey = randomScalar();
    const msSpend = randomScalar();

    const account1 = new MultisigCarrotAccount({
      threshold: 2, signerCount: 2,
      spendSecretKey: spendKey, viewSecretKey: viewKey
    });
    account1.kexComplete = true;
    account1.multisigSpendSecretKey = new Uint8Array(msSpend);

    const account2 = new MultisigCarrotAccount({
      threshold: 2, signerCount: 2,
      spendSecretKey: spendKey, viewSecretKey: viewKey
    });
    account2.kexComplete = true;
    account2.multisigSpendSecretKey = new Uint8Array(msSpend);

    const keys1 = account1.deriveCarrotKeys();
    const keys2 = account2.deriveCarrotKeys();

    expect(keys1.accountSpendPubkey).toBe(keys2.accountSpendPubkey);
    expect(keys1.viewIncomingKey).toBe(keys2.viewIncomingKey);
  });

  test('getCarrotAddress fails without deriveCarrotKeys', () => {
    const account = createCompletedAccount();
    expect(() => account.getCarrotAddress()).toThrow('CARROT keys not derived');
  });

  test('getCarrotAddress returns valid address string', () => {
    const account = createCompletedAccount();
    account.deriveCarrotKeys();
    const address = account.getCarrotAddress('mainnet');
    expect(typeof address).toBe('string');
    expect(address.startsWith('SC1')).toBe(true);
  });

  test('getCarrotAddress for testnet', () => {
    const account = createCompletedAccount();
    account.deriveCarrotKeys();
    const address = account.getCarrotAddress('testnet');
    expect(address.startsWith('SC1T')).toBe(true);
  });

  test('getCarrotSubaddress returns valid address', () => {
    const account = createCompletedAccount();
    account.deriveCarrotKeys();
    const sub = account.getCarrotSubaddress('mainnet', 0, 1);
    expect(sub.address).toBeDefined();
    expect(typeof sub.address).toBe('string');
  });

  test('getCarrotSubaddress fails without deriveCarrotKeys', () => {
    const account = createCompletedAccount();
    expect(() => account.getCarrotSubaddress()).toThrow('CARROT keys not derived');
  });
});

describe('Aspirational functions', () => {
  test('buildMultisigCarrotTx throws with clear message', () => {
    const account = createCompletedAccount();
    account.deriveCarrotKeys();
    const proposal = new CarrotTransactionProposal();
    proposal.addPayment('SC1dest', 1000000000n);

    expect(() => buildMultisigCarrotTx(proposal, account))
      .toThrow('protocol support');
  });

  test('buildMultisigCarrotTx validates input types', () => {
    expect(() => buildMultisigCarrotTx({}, {}))
      .toThrow('Expected CarrotTransactionProposal');

    const proposal = new CarrotTransactionProposal();
    expect(() => buildMultisigCarrotTx(proposal, {}))
      .toThrow('Expected MultisigCarrotAccount');
  });

  test('generateMultisigCarrotKeyImage throws with clear message', () => {
    const account = createCompletedAccount();
    expect(() => generateMultisigCarrotKeyImage(account, new Uint8Array(32)))
      .toThrow('protocol support');
  });
});

describe('CARROT_ENOTE_TYPE constants', () => {
  test('enote types are defined', () => {
    expect(CARROT_ENOTE_TYPE.PAYMENT).toBe(0);
    expect(CARROT_ENOTE_TYPE.CHANGE).toBe(1);
    expect(CARROT_ENOTE_TYPE.SELF_SPEND).toBe(2);
  });
});
