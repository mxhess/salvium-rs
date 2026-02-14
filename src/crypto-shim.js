// Shim for Node.js 'crypto' module — bridges to globalThis.crypto (polyfilled by Dart)
export default globalThis.crypto;
export const webcrypto = globalThis.crypto;
export function randomBytes(n) {
  const buf = new Uint8Array(n);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}
export function getRandomValues(arr) {
  return globalThis.crypto.getRandomValues(arr);
}
export function createHash() {
  throw new Error('createHash not available in QuickJS — use keccak/blake2b');
}
export function createVerify() {
  throw new Error('createVerify not available in QuickJS — oracle signature verification requires Node.js');
}
