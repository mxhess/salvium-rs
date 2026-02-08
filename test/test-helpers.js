/**
 * Shared test helpers for Salvium-JS integration tests.
 *
 * Extracts common utilities used across sweep, sync, stress, and burn-in tests.
 */
import { Wallet } from '../src/wallet.js';

/**
 * Get current blockchain height from daemon.
 * @param {Object} daemon - DaemonRPC instance
 * @returns {Promise<number>}
 */
export async function getHeight(daemon) {
  const info = await daemon.getInfo();
  return info.result?.height || info.data?.height || 0;
}

/**
 * Poll daemon until target height is reached.
 * @param {Object} daemon - DaemonRPC instance
 * @param {number} target - Target block height
 * @param {string} [label] - Label for progress display
 * @returns {Promise<number>} Final height
 */
export async function waitForHeight(daemon, target, label = '') {
  let h = await getHeight(daemon);
  if (h >= target) return h;
  const tag = label ? ` [${label}]` : '';
  process.stdout.write(`  Waiting for height ${target}${tag}... (at ${h})`);
  while (h < target) {
    await new Promise(r => setTimeout(r, 3000));
    h = await getHeight(daemon);
    process.stdout.write(`\r  Waiting for height ${target}${tag}... (at ${h})     `);
  }
  process.stdout.write('\n');
  return h;
}

/**
 * Format atomic units as "X.XXXXXXXX SAL".
 * @param {bigint|number} atomic
 * @returns {string}
 */
export function fmt(atomic) {
  return `${(Number(atomic) / 1e8).toFixed(8)} SAL`;
}

/**
 * Truncate an address for display.
 * @param {string} addr
 * @returns {string}
 */
export function short(addr) {
  return addr ? addr.slice(0, 20) + '...' : 'N/A';
}

/**
 * Load a wallet from a JSON file on disk.
 * @param {string} path - Absolute path to wallet JSON file
 * @param {string} [network='testnet'] - Network override
 * @returns {Promise<Wallet>}
 */
export async function loadWalletFromFile(path, network = 'testnet') {
  const data = JSON.parse(await Bun.file(path).text());
  return Wallet.fromJSON(data, { network });
}
