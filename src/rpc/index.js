/**
 * Salvium RPC Module
 *
 * Provides RPC client implementations for interacting with Salvium daemon and wallet services.
 *
 * Port configuration from cryptonote_config.h:
 * - Daemon RPC: 19081 (mainnet), 29081 (testnet), 39081 (stagenet)
 * - ZMQ RPC:    19083 (mainnet), 29083 (testnet), 39083 (stagenet)
 * - Wallet RPC: No default in source - conventionally daemon port + 1
 * - Restricted: No default in source - conventionally daemon port + 8
 *
 * @example
 * // Import the RPC clients
 * import { DaemonRPC, WalletRPC, createDaemonRPC, createWalletRPC } from 'salvium-js/rpc';
 *
 * // Create daemon client (port 19081 from config::RPC_DEFAULT_PORT)
 * const daemon = createDaemonRPC({ url: 'http://localhost:19081' });
 * const info = await daemon.getInfo();
 *
 * // Create wallet client (port 19083 is convention, not in source)
 * const wallet = createWalletRPC({ url: 'http://localhost:19083' });
 * const balance = await wallet.getBalance();
 *
 * @example
 * // Using class constructors
 * const daemon = new DaemonRPC({ url: 'http://node.example.com:19081' });
 * const wallet = new WalletRPC({
 *   url: 'http://localhost:19083',
 *   username: 'user',
 *   password: 'pass'
 * });
 */

// Base client
export {
  RPCClient,
  createClient,
  RPC_ERROR_CODES,
  RPC_STATUS
} from './client.js';

// Daemon RPC
export {
  DaemonRPC,
  createDaemonRPC,
  MAINNET_URL as DAEMON_MAINNET_URL,
  TESTNET_URL as DAEMON_TESTNET_URL,
  STAGENET_URL as DAEMON_STAGENET_URL,
  ZMQ_MAINNET_URL,
  ZMQ_TESTNET_URL,
  ZMQ_STAGENET_URL,
  RESTRICTED_MAINNET_URL as DAEMON_RESTRICTED_MAINNET_URL,
  RESTRICTED_TESTNET_URL as DAEMON_RESTRICTED_TESTNET_URL,
  RESTRICTED_STAGENET_URL as DAEMON_RESTRICTED_STAGENET_URL
} from './daemon.js';

// Wallet RPC
export {
  WalletRPC,
  createWalletRPC,
  PRIORITY,
  TRANSFER_TYPE,
  MAINNET_URL as WALLET_MAINNET_URL,
  TESTNET_URL as WALLET_TESTNET_URL,
  STAGENET_URL as WALLET_STAGENET_URL
} from './wallet.js';

// Default export with all components
import { RPCClient, createClient, RPC_ERROR_CODES, RPC_STATUS } from './client.js';
import {
  DaemonRPC, createDaemonRPC,
  MAINNET_URL as DAEMON_MAINNET, TESTNET_URL as DAEMON_TESTNET, STAGENET_URL as DAEMON_STAGENET,
  ZMQ_MAINNET_URL as ZMQ_MAINNET, ZMQ_TESTNET_URL as ZMQ_TESTNET, ZMQ_STAGENET_URL as ZMQ_STAGENET,
  RESTRICTED_MAINNET_URL as DAEMON_RESTRICTED_MAINNET, RESTRICTED_TESTNET_URL as DAEMON_RESTRICTED_TESTNET, RESTRICTED_STAGENET_URL as DAEMON_RESTRICTED_STAGENET
} from './daemon.js';
import { WalletRPC, createWalletRPC, PRIORITY, TRANSFER_TYPE, MAINNET_URL as WALLET_MAINNET, TESTNET_URL as WALLET_TESTNET, STAGENET_URL as WALLET_STAGENET } from './wallet.js';

export default {
  // Base client
  RPCClient,
  createClient,
  RPC_ERROR_CODES,
  RPC_STATUS,

  // Daemon RPC
  DaemonRPC,
  createDaemonRPC,

  // Wallet RPC
  WalletRPC,
  createWalletRPC,
  PRIORITY,
  TRANSFER_TYPE,

  // Default URLs (from cryptonote_config.h and conventions)
  urls: {
    daemon: {
      mainnet: DAEMON_MAINNET,       // config::RPC_DEFAULT_PORT = 19081
      testnet: DAEMON_TESTNET,       // config::testnet::RPC_DEFAULT_PORT = 29081
      stagenet: DAEMON_STAGENET,     // config::stagenet::RPC_DEFAULT_PORT = 39081
      restrictedMainnet: DAEMON_RESTRICTED_MAINNET, // convention (no source default)
      restrictedTestnet: DAEMON_RESTRICTED_TESTNET, // convention (no source default)
      restrictedStagenet: DAEMON_RESTRICTED_STAGENET // convention (no source default)
    },
    zmq: {
      mainnet: ZMQ_MAINNET,          // config::ZMQ_RPC_DEFAULT_PORT = 19083
      testnet: ZMQ_TESTNET,          // config::testnet::ZMQ_RPC_DEFAULT_PORT = 29083
      stagenet: ZMQ_STAGENET         // config::stagenet::ZMQ_RPC_DEFAULT_PORT = 39083
    },
    wallet: {
      mainnet: WALLET_MAINNET,       // convention - daemon port + 1 (no source default)
      testnet: WALLET_TESTNET,       // convention - daemon port + 1 (no source default)
      stagenet: WALLET_STAGENET      // convention - daemon port + 1 (no source default)
    }
  }
};
