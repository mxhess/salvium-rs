/**
 * Wallet Account Module
 *
 * Account class for managing subaddresses within a wallet.
 * Each account represents a major index in the subaddress system.
 *
 * @module wallet/account
 */

// =============================================================================
// ACCOUNT CLASS
// =============================================================================

/**
 * Represents a wallet account (major index in subaddress system)
 */
export class Account {
  constructor(wallet, index, label = '') {
    this._wallet = wallet;
    this._index = index;
    this._label = label;
    this._subaddressLabels = new Map(); // minor index -> label
  }

  /** Get account index */
  get index() { return this._index; }

  /** Get/set account label */
  get label() { return this._label; }
  set label(value) { this._label = value; }

  /**
   * Get the primary address for this account
   * @returns {string}
   */
  getPrimaryAddress() {
    return this._wallet.getSubaddress(this._index, 0);
  }

  /**
   * Get a subaddress in this account
   * @param {number} minor - Subaddress index
   * @returns {string}
   */
  getSubaddress(minor) {
    return this._wallet.getSubaddress(this._index, minor);
  }

  /**
   * Create a new subaddress in this account
   * @param {string} label - Optional label
   * @returns {Object} { index, address }
   */
  createSubaddress(label = '') {
    const minor = this._wallet._getNextSubaddressIndex(this._index);
    const address = this._wallet.getSubaddress(this._index, minor);
    if (label) {
      this._subaddressLabels.set(minor, label);
    }
    return { index: minor, address };
  }

  /**
   * Get all subaddresses in this account
   * @returns {Array<Object>} Array of { index, address, label }
   */
  getSubaddresses() {
    const result = [];
    for (let minor = 0; minor < this._wallet._getNextSubaddressIndex(this._index); minor++) {
      result.push({
        index: minor,
        address: this._wallet.getSubaddress(this._index, minor),
        label: this._subaddressLabels.get(minor) || ''
      });
    }
    return result;
  }

  /**
   * Get subaddress label
   * @param {number} minor - Subaddress index
   * @returns {string}
   */
  getSubaddressLabel(minor) {
    return this._subaddressLabels.get(minor) || '';
  }

  /**
   * Set subaddress label
   * @param {number} minor - Subaddress index
   * @param {string} label - Label to set
   */
  setSubaddressLabel(minor, label) {
    this._subaddressLabels.set(minor, label);
  }

  /**
   * Get account balance
   * @param {string} assetType - Asset type (default: 'SAL')
   * @returns {Object} { balance, unlockedBalance }
   */
  getBalance(assetType = 'SAL') {
    return this._wallet.getAccountBalance(this._index, assetType);
  }

  /**
   * Get all outputs for this account
   * @param {Object} options - Filter options
   * @returns {Array<Object>}
   */
  getOutputs(options = {}) {
    return this._wallet.getOutputs({
      ...options,
      accountIndex: this._index
    });
  }

  /**
   * Get transaction history for this account
   * @param {Object} options - Filter options
   * @returns {Array<Object>}
   */
  getTransactions(options = {}) {
    return this._wallet.getTransactions({
      ...options,
      accountIndex: this._index
    });
  }

  /**
   * Serialize account for storage
   * @returns {Object}
   */
  toJSON() {
    return {
      index: this._index,
      label: this._label,
      subaddressLabels: Object.fromEntries(this._subaddressLabels)
    };
  }

  /**
   * Restore account from JSON
   * @param {Object} wallet - Parent wallet
   * @param {Object} json - Serialized account data
   * @returns {Account}
   */
  static fromJSON(wallet, json) {
    const account = new Account(wallet, json.index, json.label || '');
    if (json.subaddressLabels) {
      for (const [key, value] of Object.entries(json.subaddressLabels)) {
        account._subaddressLabels.set(parseInt(key), value);
      }
    }
    return account;
  }
}
