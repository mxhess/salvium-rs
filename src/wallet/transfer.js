/**
 * High-Level Transfer, Sweep & Stake Functions
 *
 * Orchestrates the full transaction lifecycle:
 *   UTXO selection → input preparation → TX build → serialize → broadcast
 *
 * Reference: Salvium src/wallet/wallet2.cpp create_transactions_2()
 */

import { parseAddress, hexToBytes, bytesToHex } from '../address.js';
import {
  buildTransaction, buildStakeTransaction, prepareInputs, estimateTransactionFee,
  selectUTXOs, serializeTransaction, TX_TYPE, DEFAULT_RING_SIZE
} from '../transaction.js';
import { getNetworkConfig, NETWORK_ID, getActiveAssetType } from '../consensus.js';
import {
  generateKeyDerivation, deriveSecretKey, scalarAdd
} from '../crypto/index.js';
import { cnSubaddressSecretKey } from '../subaddress.js';

/**
 * Derive the output secret key needed for spending.
 *
 * @param {Object} output - WalletOutput with txPubKey, outputIndex
 * @param {Object} keys - Wallet keys { viewSecretKey, spendSecretKey }
 * @param {Object} [subaddressIndex] - { major, minor }
 * @returns {Uint8Array} Output secret key
 */
function deriveOutputSecretKey(output, keys) {
  const txPubKey = typeof output.txPubKey === 'string'
    ? hexToBytes(output.txPubKey) : output.txPubKey;
  const viewSecretKey = typeof keys.viewSecretKey === 'string'
    ? hexToBytes(keys.viewSecretKey) : keys.viewSecretKey;
  let spendSecretKey = typeof keys.spendSecretKey === 'string'
    ? hexToBytes(keys.spendSecretKey) : keys.spendSecretKey;

  // For subaddresses, compute subaddress secret key
  const sub = output.subaddressIndex;
  if (sub && (sub.major !== 0 || sub.minor !== 0)) {
    const subaddrScalar = cnSubaddressSecretKey(viewSecretKey, sub.major, sub.minor);
    spendSecretKey = scalarAdd(spendSecretKey, subaddrScalar);
  }

  const derivation = generateKeyDerivation(txPubKey, viewSecretKey);
  return deriveSecretKey(derivation, output.outputIndex, spendSecretKey);
}

/**
 * Resolve global output indices for a set of outputs.
 *
 * @param {Array<Object>} outputs - WalletOutput objects
 * @param {Object} daemon - DaemonRPC instance
 * @returns {Promise<Map<string, number>>} Map of keyImage → globalIndex
 */
async function resolveGlobalIndices(outputs, daemon) {
  const indices = new Map();

  // Group outputs by txHash to minimize RPC calls
  const byTx = new Map();
  for (const output of outputs) {
    if (output.globalIndex != null) {
      indices.set(output.keyImage, output.globalIndex);
      continue;
    }
    if (!byTx.has(output.txHash)) byTx.set(output.txHash, []);
    byTx.get(output.txHash).push(output);
  }

  for (const [txHash, outs] of byTx) {
    const resp = await daemon.getOutputIndexes(txHash);
    if (!resp.success || !resp.data?.o_indexes) {
      throw new Error(`Failed to get output indexes for tx ${txHash}`);
    }
    const oIndexes = resp.data.o_indexes;
    const assetTypeIndexes = resp.data.asset_type_output_indices || [];
    for (const out of outs) {
      if (out.outputIndex < oIndexes.length) {
        const gi = Number(oIndexes[out.outputIndex]);
        indices.set(out.keyImage, gi);
        out.globalIndex = gi;
        if (out.outputIndex < assetTypeIndexes.length) {
          out.assetTypeIndex = Number(assetTypeIndexes[out.outputIndex]);
        }
      }
    }
  }

  return indices;
}

/**
 * Transfer SAL to one or more destinations.
 *
 * @param {Object} params
 * @param {Object} params.wallet - WalletSync instance (has storage + keys)
 * @param {Object} params.daemon - DaemonRPC instance
 * @param {Array<{address: string, amount: bigint}>} params.destinations - Where to send
 * @param {Object} [params.options]
 * @param {string} [params.options.priority='default'] - Fee priority
 * @param {boolean} [params.options.subtractFeeFromAmount=false] - Deduct fee from first destination
 * @param {string} [params.options.assetType='SAL'] - Asset type to send
 * @param {boolean} [params.options.dryRun=false] - Build TX but don't broadcast
 * @returns {Promise<{txHash: string, fee: bigint, tx: Object}>}
 */
export async function transfer({ wallet, daemon, destinations, options = {} }) {
  const {
    priority = 'default',
    subtractFeeFromAmount = false,
    assetType: assetTypeOpt,
    dryRun = false
  } = options;

  if (!destinations || destinations.length === 0) {
    throw new Error('At least one destination is required');
  }

  // 1. Parse destination addresses
  const parsedDests = destinations.map(d => {
    const parsed = parseAddress(d.address);
    if (!parsed.valid) {
      throw new Error(`Invalid address: ${d.address} — ${parsed.error}`);
    }
    return {
      viewPublicKey: parsed.viewPublicKey,
      spendPublicKey: parsed.spendPublicKey,
      isSubaddress: parsed.type === 'subaddress',
      amount: typeof d.amount === 'bigint' ? d.amount : BigInt(d.amount)
    };
  });

  // 2. Calculate total send amount
  let totalSend = 0n;
  for (const d of parsedDests) totalSend += d.amount;

  // 3. Get current height for spendability check
  const infoResp = await daemon.getInfo();
  if (!infoResp.success) throw new Error('Failed to get daemon info');
  const currentHeight = infoResp.result?.height || infoResp.data?.height;

  // 4. Get spendable outputs — use HF-based asset type if not specified
  const assetType = assetTypeOpt || getActiveAssetType(currentHeight, options.network);
  const allOutputs = await wallet.storage.getOutputs({
    isSpent: false,
    isFrozen: false,
    assetType
  });
  const spendable = allOutputs.filter(o => o.isSpendable(currentHeight));

  if (spendable.length === 0) {
    throw new Error('No spendable outputs available');
  }

  // 5. Initial fee estimate (2 outputs: dest + change)
  let estimatedFee = estimateTransactionFee(
    2, // guess 2 inputs initially
    parsedDests.length + 1, // destinations + change
    { priority }
  );

  // 6. Select UTXOs
  const target = subtractFeeFromAmount ? totalSend : totalSend + estimatedFee;
  const selection = selectUTXOs(
    spendable.map(o => ({
      amount: o.amount,
      globalIndex: o.globalIndex,
      keyImage: o.keyImage,
      _output: o
    })),
    target,
    estimatedFee / 2n, // rough per-input fee
    { currentHeight }
  );

  if (!selection.selected || selection.selected.length === 0) {
    throw new Error(`Insufficient balance. Need ${target}, have ${spendable.reduce((s, o) => s + o.amount, 0n)}`);
  }

  // 7. Recalculate fee with actual input count
  estimatedFee = estimateTransactionFee(
    selection.selected.length,
    parsedDests.length + (selection.changeAmount > 0n ? 1 : 0),
    { priority }
  );

  // Adjust amounts if subtracting fee
  if (subtractFeeFromAmount) {
    parsedDests[0].amount -= estimatedFee;
    if (parsedDests[0].amount <= 0n) {
      throw new Error('Amount too small to cover fee');
    }
  }

  // 8. Resolve global indices for selected outputs
  const selectedOutputs = selection.selected.map(s => s._output);
  await resolveGlobalIndices(selectedOutputs, daemon);

  // 9. Derive output secret keys for each input
  // For coinbase outputs (no RCT), mask = identity scalar (1), commitment = zeroCommit(amount)
  const IDENTITY_MASK = '0100000000000000000000000000000000000000000000000000000000000000';
  const { commit: pedersenCommit } = await import('../transaction/serialization.js');

  const ownedForPrep = selectedOutputs.map((o, idx) => {
    let mask = o.mask;
    let commitment = o.commitment;

    // Coinbase outputs have no RCT mask — use identity
    if (!mask) {
      mask = IDENTITY_MASK;
      commitment = bytesToHex(pedersenCommit(o.amount, hexToBytes(IDENTITY_MASK)));
    }

    // Debug: check if publicKey looks valid
    const pkType = typeof o.publicKey;
    const pkLen = o.publicKey?.length;
    console.log(`[PREP DEBUG] Output ${idx}: publicKey type=${pkType}, len=${pkLen}, value=${String(o.publicKey).slice(0, 32)}...`);

    return {
      secretKey: deriveOutputSecretKey(o, wallet.keys),
      publicKey: o.publicKey,
      amount: o.amount,
      mask,
      globalIndex: o.globalIndex,
      assetTypeIndex: o.assetTypeIndex,
      commitment
    };
  });

  // 10. Prepare inputs (fetch decoys from daemon)
  const preparedInputs = await prepareInputs(ownedForPrep, daemon, {
    ringSize: DEFAULT_RING_SIZE,
    assetType
  });

  // 11. Build change address from wallet's primary address
  const changeAddress = {
    viewPublicKey: wallet.keys.viewPublicKey,
    spendPublicKey: wallet.keys.spendPublicKey,
    isSubaddress: false
  };

  // 12. Build the transaction
  const spendPub = typeof wallet.keys.spendPublicKey === 'string'
    ? hexToBytes(wallet.keys.spendPublicKey) : wallet.keys.spendPublicKey;
  const viewPub = typeof wallet.keys.viewPublicKey === 'string'
    ? hexToBytes(wallet.keys.viewPublicKey) : wallet.keys.viewPublicKey;
  const tx = buildTransaction(
    {
      inputs: preparedInputs,
      destinations: parsedDests,
      changeAddress,
      fee: estimatedFee
    },
    {
      txType: TX_TYPE.TRANSFER,
      sourceAssetType: assetType,
      destinationAssetType: assetType,
      returnAddress: spendPub,
      returnPubkey: viewPub,
      height: currentHeight,
      network: options.network
    }
  );

  // DEBUG: log TX structure
  console.log(`  [DEBUG] TX version: ${tx.prefix.version}, RCT type: ${tx.rct.type}`);
  console.log(`  [DEBUG] p_r: ${bytesToHex(typeof tx.rct.p_r === 'string' ? hexToBytes(tx.rct.p_r) : tx.rct.p_r).slice(0, 16)}...`);
  console.log(`  [DEBUG] ecdhInfo[0]: ${tx.rct.ecdhInfo[0]?.slice(0, 16)}...`);
  console.log(`  [DEBUG] outPk count: ${tx.rct.outPk.length}, pseudoOuts count: ${tx.rct.pseudoOuts.length}`);
  console.log(`  [DEBUG] CLSAGs: ${tx.rct.CLSAGs?.length || 0}, BP+ proof: ${tx.rct.bulletproofPlus ? 'yes' : 'no'}`);
  if (tx.rct.salvium_data) console.log(`  [DEBUG] salvium_data: type=${tx.rct.salvium_data.salvium_data_type}`);

  // 13. Serialize
  const serialized = serializeTransaction(tx);
  const txHex = bytesToHex(serialized);

  // DEBUG: dump TX hex for analysis and round-trip test
  try {
    const fs = await import('fs');
    fs.writeFileSync('/tmp/last_tx.hex', txHex);
    console.log(`  [DEBUG] TX hex dumped to /tmp/last_tx.hex (${txHex.length / 2} bytes)`);
  } catch (_e) { /* ignore */ }

  // 14. Broadcast
  if (!dryRun) {
    const sendResp = await daemon.sendRawTransaction(txHex, { source_asset_type: assetType });
    if (!sendResp.success) {
      throw new Error(`Failed to broadcast: ${JSON.stringify(sendResp)}`);
    }
    const respData = sendResp.result || sendResp.data?.result || sendResp.data;
    console.log(`  [DEBUG] Daemon response:`, JSON.stringify(respData));
    if (respData?.status !== 'OK') {
      const reason = respData?.reason || respData?.status || 'unknown';
      throw new Error(`Transaction rejected: ${reason}`);
    }
  }

  // 15. Compute TX hash
  const { keccak256 } = await import('../crypto/index.js');
  const txHash = bytesToHex(keccak256(serialized));

  // Collect spent key images for caller to mark as spent
  const spentKeyImages = selection.selected.map(u => u.keyImage);

  return {
    txHash,
    fee: estimatedFee,
    tx,
    serializedHex: txHex,
    inputCount: preparedInputs.length,
    outputCount: tx.prefix.vout.length,
    spentKeyImages
  };
}

/**
 * Sweep all spendable outputs to a single destination.
 *
 * @param {Object} params
 * @param {Object} params.wallet - WalletSync instance
 * @param {Object} params.daemon - DaemonRPC instance
 * @param {string} params.address - Destination address
 * @param {Object} [params.options]
 * @param {string} [params.options.priority='default'] - Fee priority
 * @param {string} [params.options.assetType='SAL'] - Asset type
 * @param {boolean} [params.options.dryRun=false] - Build TX but don't broadcast
 * @returns {Promise<{txHash: string, fee: bigint, amount: bigint, tx: Object}>}
 */
export async function sweep({ wallet, daemon, address, options = {} }) {
  const {
    priority = 'default',
    assetType: assetTypeOpt,
    dryRun = false
  } = options;

  // Parse destination
  const parsed = parseAddress(address);
  if (!parsed.valid) {
    throw new Error(`Invalid address: ${address} — ${parsed.error}`);
  }

  // Get current height
  const infoResp = await daemon.getInfo();
  if (!infoResp.success) throw new Error('Failed to get daemon info');
  const currentHeight = infoResp.result?.height || infoResp.data?.height;

  // Use HF-based asset type detection (like C++ wallet2)
  const assetType = assetTypeOpt || getActiveAssetType(currentHeight, options.network);

  // Get all spendable outputs
  const allOutputs = await wallet.storage.getOutputs({
    isSpent: false,
    isFrozen: false,
    assetType
  });
  let spendable = allOutputs.filter(o => o.isSpendable(currentHeight));

  if (spendable.length === 0) {
    throw new Error('No spendable outputs available');
  }

  // Limit inputs to avoid exceeding max tx weight (149400 bytes)
  // Each TCLSAG input adds ~2KB, so max ~60 inputs safely
  const MAX_SWEEP_INPUTS = 60;
  if (spendable.length > MAX_SWEEP_INPUTS) {
    // Sort by amount descending to sweep largest first
    spendable.sort((a, b) => b.amount > a.amount ? 1 : b.amount < a.amount ? -1 : 0);
    spendable = spendable.slice(0, MAX_SWEEP_INPUTS);
  }

  let totalAmount = 0n;
  for (const o of spendable) totalAmount += o.amount;

  // Estimate fee with all inputs, 1 output (no change for sweep)
  const estimatedFee = estimateTransactionFee(
    spendable.length,
    1, // single output, no change
    { priority }
  );

  const sendAmount = totalAmount - estimatedFee;
  if (sendAmount <= 0n) {
    throw new Error(`Total balance ${totalAmount} is too small to cover fee ${estimatedFee}`);
  }

  // Resolve global indices
  await resolveGlobalIndices(spendable, daemon);

  // Derive secret keys
  const IDENTITY_MASK = '0100000000000000000000000000000000000000000000000000000000000000';
  const { commit: pedersenCommit } = await import('../transaction/serialization.js');

  const ownedForPrep = spendable.map(o => {
    let mask = o.mask;
    let commitment = o.commitment;

    // Coinbase outputs have no RCT mask — use identity
    if (!mask) {
      mask = IDENTITY_MASK;
      commitment = bytesToHex(pedersenCommit(o.amount, hexToBytes(IDENTITY_MASK)));
    }

    return {
      secretKey: deriveOutputSecretKey(o, wallet.keys),
      publicKey: o.publicKey,
      amount: o.amount,
      mask,
      globalIndex: o.globalIndex,
      assetTypeIndex: o.assetTypeIndex,
      commitment
    };
  });

  // Prepare inputs
  const preparedInputs = await prepareInputs(ownedForPrep, daemon, {
    ringSize: DEFAULT_RING_SIZE,
    assetType
  });

  // Build TX (no change output)
  const sweepSpendPub = typeof wallet.keys.spendPublicKey === 'string'
    ? hexToBytes(wallet.keys.spendPublicKey) : wallet.keys.spendPublicKey;
  const sweepViewPub = typeof wallet.keys.viewPublicKey === 'string'
    ? hexToBytes(wallet.keys.viewPublicKey) : wallet.keys.viewPublicKey;
  const tx = buildTransaction(
    {
      inputs: preparedInputs,
      destinations: [{
        viewPublicKey: parsed.viewPublicKey,
        spendPublicKey: parsed.spendPublicKey,
        isSubaddress: parsed.type === 'subaddress',
        amount: sendAmount
      }],
      changeAddress: null,
      fee: estimatedFee
    },
    {
      txType: TX_TYPE.TRANSFER,
      sourceAssetType: assetType,
      destinationAssetType: assetType,
      returnAddress: sweepSpendPub,
      returnPubkey: sweepViewPub,
      height: currentHeight,
      network: options.network
    }
  );

  // Serialize and broadcast
  const serialized = serializeTransaction(tx);
  const txHex = bytesToHex(serialized);

  if (!dryRun) {
    const sendResp = await daemon.sendRawTransaction(txHex, { source_asset_type: assetType });
    if (!sendResp.success) {
      throw new Error(`Failed to broadcast: ${JSON.stringify(sendResp.error || sendResp.data)}`);
    }
    const respData = sendResp.result || sendResp.data?.result || sendResp.data;
    console.log(`  [DEBUG] Sweep daemon response:`, JSON.stringify(respData));
    if (respData?.status !== 'OK') {
      const reason = respData?.reason || respData?.status || 'unknown';
      throw new Error(`Transaction rejected: ${reason}`);
    }
  }

  const { keccak256 } = await import('../crypto/index.js');
  const txHash = bytesToHex(keccak256(serialized));

  return {
    txHash,
    fee: estimatedFee,
    amount: sendAmount,
    tx,
    serializedHex: txHex,
    inputCount: preparedInputs.length
  };
}

/**
 * Stake SAL to earn yield from conversion slippage.
 *
 * Locks funds for STAKE_LOCK_PERIOD blocks. After maturity, a protocol_tx
 * returns the original stake + accumulated yield to the return address.
 *
 * @param {Object} params
 * @param {Object} params.wallet - WalletSync instance (has storage + keys)
 * @param {Object} params.daemon - DaemonRPC instance
 * @param {bigint} params.amount - Amount to stake (atomic units)
 * @param {Object} [params.options]
 * @param {string} [params.options.priority='default'] - Fee priority
 * @param {string} [params.options.assetType='SAL'] - Asset type to stake
 * @param {string} [params.options.network='mainnet'] - Network for lock period
 * @param {boolean} [params.options.dryRun=false] - Build TX but don't broadcast
 * @returns {Promise<{txHash: string, fee: bigint, stakeAmount: bigint, lockPeriod: number, tx: Object}>}
 */
export async function stake({ wallet, daemon, amount, options = {} }) {
  const {
    priority = 'default',
    assetType: assetTypeOpt,
    network = 'mainnet',
    dryRun = false
  } = options;

  const stakeAmount = typeof amount === 'bigint' ? amount : BigInt(amount);
  if (stakeAmount <= 0n) {
    throw new Error('Stake amount must be positive');
  }

  // Resolve string network names to numeric NETWORK_ID
  const NETWORK_NAME_MAP = { mainnet: NETWORK_ID.MAINNET, testnet: NETWORK_ID.TESTNET, stagenet: NETWORK_ID.STAGENET };
  const networkId = typeof network === 'string' ? (NETWORK_NAME_MAP[network] ?? network) : network;
  const networkConfig = getNetworkConfig(networkId);
  const stakeLockPeriod = networkConfig.STAKE_LOCK_PERIOD;

  // 1. Get current height
  const infoResp = await daemon.getInfo();
  if (!infoResp.success) throw new Error('Failed to get daemon info');
  const currentHeight = infoResp.result?.height || infoResp.data?.height;

  // 2. Use HF-based asset type detection (like C++ wallet2)
  const assetType = assetTypeOpt || getActiveAssetType(currentHeight, network);

  // 3. Get spendable outputs
  const allOutputs = await wallet.storage.getOutputs({
    isSpent: false,
    isFrozen: false,
    assetType
  });
  const spendable = allOutputs.filter(o => o.isSpendable(currentHeight));

  if (spendable.length === 0) {
    throw new Error('No spendable outputs available');
  }

  // 3. Estimate fee (inputs + 1 change output, no payment outputs)
  let estimatedFee = estimateTransactionFee(
    2, // guess 2 inputs
    1, // change only
    { priority }
  );

  // 4. Select UTXOs
  const target = stakeAmount + estimatedFee;
  const selection = selectUTXOs(
    spendable.map(o => ({
      amount: o.amount,
      globalIndex: o.globalIndex,
      keyImage: o.keyImage,
      _output: o
    })),
    target,
    estimatedFee / 2n,
    { currentHeight }
  );

  if (!selection.selected || selection.selected.length === 0) {
    throw new Error(`Insufficient balance. Need ${target}, have ${spendable.reduce((s, o) => s + o.amount, 0n)}`);
  }

  // 5. Recalculate fee with actual input count
  estimatedFee = estimateTransactionFee(
    selection.selected.length,
    selection.changeAmount > 0n ? 1 : 0,
    { priority }
  );

  // 6. Resolve global indices
  const selectedOutputs = selection.selected.map(s => s._output);
  await resolveGlobalIndices(selectedOutputs, daemon);

  // 7. Derive output secret keys
  const IDENTITY_MASK = '0100000000000000000000000000000000000000000000000000000000000000';
  const { commit: pedersenCommit } = await import('../transaction/serialization.js');

  const ownedForPrep = selectedOutputs.map(o => {
    let mask = o.mask;
    let commitment = o.commitment;

    if (!mask) {
      mask = IDENTITY_MASK;
      commitment = bytesToHex(pedersenCommit(o.amount, hexToBytes(IDENTITY_MASK)));
    }

    return {
      secretKey: deriveOutputSecretKey(o, wallet.keys),
      publicKey: o.publicKey,
      amount: o.amount,
      mask,
      globalIndex: o.globalIndex,
      assetTypeIndex: o.assetTypeIndex,
      commitment
    };
  });

  // 8. Prepare inputs (fetch decoys)
  const preparedInputs = await prepareInputs(ownedForPrep, daemon, {
    ringSize: DEFAULT_RING_SIZE,
    assetType
  });

  // 9. Return address = wallet's own address (stake returns here)
  const returnAddress = {
    viewPublicKey: wallet.keys.viewPublicKey,
    spendPublicKey: wallet.keys.spendPublicKey,
    isSubaddress: false
  };

  // 10. Build stake transaction
  const tx = buildStakeTransaction(
    {
      inputs: preparedInputs,
      stakeAmount,
      returnAddress,
      fee: estimatedFee
    },
    {
      stakeLockPeriod,
      assetType,
      height: currentHeight,
      network
    }
  );

  // 11. Serialize
  const serialized = serializeTransaction(tx);
  const txHex = bytesToHex(serialized);

  // 12. Broadcast
  if (!dryRun) {
    const sendResp = await daemon.sendRawTransaction(txHex, { source_asset_type: assetType });
    if (!sendResp.success) {
      throw new Error(`Failed to broadcast: ${JSON.stringify(sendResp.error || sendResp.data)}`);
    }
    const respData = sendResp.result || sendResp.data?.result || sendResp.data;
    console.log(`  [DEBUG] Stake daemon response:`, JSON.stringify(respData));
    if (respData?.status !== 'OK') {
      const reason = respData?.reason || respData?.status || 'unknown';
      throw new Error(`Transaction rejected: ${reason}`);
    }
  }

  // 13. Compute TX hash
  const { keccak256 } = await import('../crypto/index.js');
  const txHash = bytesToHex(keccak256(serialized));

  // Collect spent key images for caller to mark as spent
  const spentKeyImages = selection.selected.map(u => u.keyImage);

  return {
    txHash,
    fee: estimatedFee,
    stakeAmount,
    lockPeriod: stakeLockPeriod,
    tx,
    serializedHex: txHex,
    inputCount: preparedInputs.length,
    outputCount: tx.prefix.vout.length,
    spentKeyImages
  };
}
