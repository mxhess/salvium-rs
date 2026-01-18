/**
 * Debug: Verify AES key byte ordering matches C++
 *
 * C++ rx_set_int_vec_i128(a, b, c, d) uses _mm_set_epi32(d, c, b, a)
 * which puts 'a' at bytes 0-3, 'b' at bytes 4-7, etc.
 *
 * Example: AES_GEN_1R_KEY0 = 0xb4f44917, 0xdbb5552b, 0x62716609, 0x6daca553
 *
 * Expected byte order (little-endian per 32-bit value):
 * bytes 0-3:   0xb4f44917 -> 17 49 f4 b4
 * bytes 4-7:   0xdbb5552b -> 2b 55 b5 db
 * bytes 8-11:  0x62716609 -> 09 66 71 62
 * bytes 12-15: 0x6daca553 -> 53 a5 ac 6d
 *
 * Full key: 1749f4b42b55b5db09667162 53a5ac6d
 */

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Current implementation (with v3, v2, v1, v0 parameter order)
function i128ToBytesOld(v3, v2, v1, v0) {
  const arr = new Uint8Array(16);
  arr[0] = v0 & 0xff; arr[1] = (v0 >> 8) & 0xff; arr[2] = (v0 >> 16) & 0xff; arr[3] = (v0 >> 24) & 0xff;
  arr[4] = v1 & 0xff; arr[5] = (v1 >> 8) & 0xff; arr[6] = (v1 >> 16) & 0xff; arr[7] = (v1 >> 24) & 0xff;
  arr[8] = v2 & 0xff; arr[9] = (v2 >> 8) & 0xff; arr[10] = (v2 >> 16) & 0xff; arr[11] = (v2 >> 24) & 0xff;
  arr[12] = v3 & 0xff; arr[13] = (v3 >> 8) & 0xff; arr[14] = (v3 >> 16) & 0xff; arr[15] = (v3 >> 24) & 0xff;
  return arr;
}

// Alternative: v0 first parameter order
function i128ToBytesNew(v0, v1, v2, v3) {
  const arr = new Uint8Array(16);
  arr[0] = v0 & 0xff; arr[1] = (v0 >> 8) & 0xff; arr[2] = (v0 >> 16) & 0xff; arr[3] = (v0 >> 24) & 0xff;
  arr[4] = v1 & 0xff; arr[5] = (v1 >> 8) & 0xff; arr[6] = (v1 >> 16) & 0xff; arr[7] = (v1 >> 24) & 0xff;
  arr[8] = v2 & 0xff; arr[9] = (v2 >> 8) & 0xff; arr[10] = (v2 >> 16) & 0xff; arr[11] = (v2 >> 24) & 0xff;
  arr[12] = v3 & 0xff; arr[13] = (v3 >> 8) & 0xff; arr[14] = (v3 >> 16) & 0xff; arr[15] = (v3 >> 24) & 0xff;
  return arr;
}

console.log('=== AES Key Byte Order Debug ===\n');

// Test with AES_GEN_1R_KEY0 values: 0xb4f44917, 0xdbb5552b, 0x62716609, 0x6daca553
const a = 0xb4f44917;
const b = 0xdbb5552b;
const c = 0x62716609;
const d = 0x6daca553;

console.log('Input values (in C++ macro order):');
console.log(`  a = 0x${a.toString(16)}`);
console.log(`  b = 0x${b.toString(16)}`);
console.log(`  c = 0x${c.toString(16)}`);
console.log(`  d = 0x${d.toString(16)}`);
console.log();

// C++ rx_set_int_vec_i128(a, b, c, d) uses _mm_set_epi32(d, c, b, a)
// which results in: a at bytes 0-3, b at bytes 4-7, c at bytes 8-11, d at bytes 12-15
console.log('Expected (C++ rx_set_int_vec_i128 behavior):');
console.log('  a at bytes 0-3, b at bytes 4-7, c at bytes 8-11, d at bytes 12-15');
console.log(`  = 1749f4b42b55b5db0966716253a5ac6d`);
console.log();

console.log('Current i128ToBytes(a,b,c,d) with (v3,v2,v1,v0) signature:');
const old = i128ToBytesOld(a, b, c, d);
console.log(`  = ${bytesToHex(old)}`);
console.log(`  v0 (${d.toString(16)}) at bytes 0-3: ${bytesToHex(old.slice(0, 4))}`);
console.log(`  v3 (${a.toString(16)}) at bytes 12-15: ${bytesToHex(old.slice(12, 16))}`);
console.log();

console.log('Alternative i128ToBytes(a,b,c,d) with (v0,v1,v2,v3) signature:');
const newKey = i128ToBytesNew(a, b, c, d);
console.log(`  = ${bytesToHex(newKey)}`);
console.log(`  v0 (${a.toString(16)}) at bytes 0-3: ${bytesToHex(newKey.slice(0, 4))}`);
console.log(`  v3 (${d.toString(16)}) at bytes 12-15: ${bytesToHex(newKey.slice(12, 16))}`);
