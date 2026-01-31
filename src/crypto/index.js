/**
 * Crypto Module — Public API
 *
 * Exports the provider (for backend switching) and both backends
 * for direct access when needed.
 *
 * @module crypto
 */

// Provider (default usage — delegates to active backend)
export {
  setCryptoBackend,
  getCryptoBackend,
  getCurrentBackendType,
  keccak256,
  blake2b,
  scAdd, scSub, scMul, scMulAdd, scMulSub,
  scReduce32, scReduce64, scInvert, scCheck, scIsZero,
  scalarMultBase, scalarMultPoint, pointAddCompressed,
  pointSubCompressed, pointNegate, doubleScalarMultBase,
} from './provider.js';

// Backends (for direct access / testing)
export { JsCryptoBackend } from './backend-js.js';
