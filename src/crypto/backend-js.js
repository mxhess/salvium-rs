/**
 * JavaScript Crypto Backend
 *
 * Wraps existing pure-JS implementations behind the unified backend interface.
 * All existing code remains untouched — this is just a thin adapter.
 *
 * @module crypto/backend-js
 */

import { keccak256 as jsKeccak } from '../keccak.js';
import { blake2b as jsBlake2b } from '../blake2b.js';
import {
  scAdd, scSub, scMul, scMulAdd, scMulSub,
  scReduce32, scReduce64, scInvert, scCheck, scIsZero
} from '../transaction/serialization.js';
import {
  scalarMultBase, scalarMultPoint, pointAddCompressed,
  pointSubCompressed, pointNegate, doubleScalarMultBase
} from '../ed25519.js';

export class JsCryptoBackend {
  constructor() {
    this.name = 'js';
  }

  async init() {
    // No initialization needed for JS backend
  }

  keccak256(data) {
    return jsKeccak(data);
  }

  blake2b(data, outLen, key) {
    return jsBlake2b(data, outLen, key);
  }

  // Scalar ops
  scAdd(a, b) { return scAdd(a, b); }
  scSub(a, b) { return scSub(a, b); }
  scMul(a, b) { return scMul(a, b); }
  scMulAdd(a, b, c) { return scMulAdd(a, b, c); }
  scMulSub(a, b, c) { return scMulSub(a, b, c); }
  scReduce32(s) { return scReduce32(s); }
  scReduce64(s) { return scReduce64(s); }
  scInvert(a) { return scInvert(a); }
  scCheck(s) { return scCheck(s); }
  scIsZero(s) { return scIsZero(s); }

  // Point ops
  scalarMultBase(s) { return scalarMultBase(s); }
  scalarMultPoint(s, p) { return scalarMultPoint(s, p); }
  pointAddCompressed(p, q) { return pointAddCompressed(p, q); }
  pointSubCompressed(p, q) { return pointSubCompressed(p, q); }
  pointNegate(p) { return pointNegate(p); }
  doubleScalarMultBase(a, p, b) {
    // JS doubleScalarMultBase expects decompressed point object, not bytes.
    // Compose from primitives instead: a*P + b*G
    const aP = scalarMultPoint(a, p);
    const bG = scalarMultBase(b);
    return pointAddCompressed(aP, bG);
  }
}
