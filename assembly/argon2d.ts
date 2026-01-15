/**
 * Argon2d implementation in AssemblyScript
 *
 * This is the critical path for RandomX cache initialization.
 * Native u64 operations give massive speedup over JS BigInt.
 */

import { blake2b, blake2b_init, blake2b_update, blake2b_final } from './blake2b';

// Constants
const ARGON2_BLOCK_SIZE: u32 = 1024;
const ARGON2_QWORDS_IN_BLOCK: u32 = 128;
const ARGON2_SYNC_POINTS: u32 = 4;
const ARGON2_VERSION: u32 = 0x13;

// RandomX parameters
const RANDOMX_ARGON_MEMORY: u32 = 262144;  // KiB
const RANDOMX_ARGON_ITERATIONS: u32 = 3;
const RANDOMX_ARGON_LANES: u32 = 1;

// Memory for Argon2d (256MB = 262144 * 1024 bytes = 33554432 u64s)
// We'll allocate this dynamically

// Working block storage (128 u64s)
let blockR: StaticArray<u64> = new StaticArray<u64>(128);
let blockTmp: StaticArray<u64> = new StaticArray<u64>(128);
let workV: StaticArray<u64> = new StaticArray<u64>(16);

// Memory pointer and dimensions
let memoryPtr: usize = 0;
let laneLength: u32 = 0;
let segmentLength: u32 = 0;

/**
 * 64-bit rotation right
 */
@inline
function rotr64(x: u64, n: u32): u64 {
  return (x >> n) | (x << (64 - n));
}

/**
 * BlaMka mixing function: f(x, y) = x + y + 2 * trunc(x) * trunc(y)
 */
@inline
function fBlaMka(x: u64, y: u64): u64 {
  const mask32: u64 = 0xFFFFFFFF;
  const xy = (x & mask32) * (y & mask32);
  return x + y + (xy << 1);
}

/**
 * G mixing function for Argon2
 */
@inline
function G(a: i32, b: i32, c: i32, d: i32): void {
  unchecked(workV[a] = fBlaMka(workV[a], workV[b]));
  unchecked(workV[d] = rotr64(workV[d] ^ workV[a], 32));
  unchecked(workV[c] = fBlaMka(workV[c], workV[d]));
  unchecked(workV[b] = rotr64(workV[b] ^ workV[c], 24));
  unchecked(workV[a] = fBlaMka(workV[a], workV[b]));
  unchecked(workV[d] = rotr64(workV[d] ^ workV[a], 16));
  unchecked(workV[c] = fBlaMka(workV[c], workV[d]));
  unchecked(workV[b] = rotr64(workV[b] ^ workV[c], 63));
}

/**
 * Blake2 round (without message) for Argon2
 */
@inline
function blake2RoundNoMsg(): void {
  // Column mixing
  G(0, 4, 8, 12);
  G(1, 5, 9, 13);
  G(2, 6, 10, 14);
  G(3, 7, 11, 15);
  // Diagonal mixing
  G(0, 5, 10, 15);
  G(1, 6, 11, 12);
  G(2, 7, 8, 13);
  G(3, 4, 9, 14);
}

/**
 * Read u64 from memory
 */
@inline
function readQword(blockIdx: u32, qwordIdx: u32): u64 {
  const offset = (blockIdx * ARGON2_QWORDS_IN_BLOCK + qwordIdx) * 8;
  return load<u64>(memoryPtr + offset);
}

/**
 * Write u64 to memory
 */
@inline
function writeQword(blockIdx: u32, qwordIdx: u32, value: u64): void {
  const offset = (blockIdx * ARGON2_QWORDS_IN_BLOCK + qwordIdx) * 8;
  store<u64>(memoryPtr + offset, value);
}

/**
 * Read a full block from memory into blockR
 */
function readBlock(blockIdx: u32, dst: StaticArray<u64>): void {
  const baseOffset = blockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
  for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    unchecked(dst[i] = load<u64>(memoryPtr + baseOffset + i * 8));
  }
}

/**
 * Write a full block from source to memory
 */
function writeBlockToMem(blockIdx: u32, src: StaticArray<u64>): void {
  const baseOffset = blockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
  for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    store<u64>(memoryPtr + baseOffset + i * 8, unchecked(src[i]));
  }
}

/**
 * Fill a block using compression function
 */
function fillBlock(prevBlockIdx: u32, refBlockIdx: u32, currBlockIdx: u32, withXor: bool): void {
  // blockR = ref_block XOR prev_block
  const prevBase = prevBlockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
  const refBase = refBlockIdx * ARGON2_QWORDS_IN_BLOCK * 8;

  for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    const prev = load<u64>(memoryPtr + prevBase + i * 8);
    const ref = load<u64>(memoryPtr + refBase + i * 8);
    unchecked(blockR[i] = prev ^ ref);
  }

  // blockTmp = blockR (or XOR with current block if withXor)
  if (withXor) {
    const currBase = currBlockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
    for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
      unchecked(blockTmp[i] = blockR[i] ^ load<u64>(memoryPtr + currBase + i * 8));
    }
  } else {
    for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
      unchecked(blockTmp[i] = blockR[i]);
    }
  }

  // Apply Blake2 rounds on columns
  for (let i: u32 = 0; i < 8; i++) {
    for (let j: u32 = 0; j < 16; j++) {
      unchecked(workV[j] = blockR[i * 16 + j]);
    }
    blake2RoundNoMsg();
    for (let j: u32 = 0; j < 16; j++) {
      unchecked(blockR[i * 16 + j] = workV[j]);
    }
  }

  // Apply Blake2 rounds on rows
  for (let i: u32 = 0; i < 8; i++) {
    unchecked(workV[0] = blockR[i * 2]);
    unchecked(workV[1] = blockR[i * 2 + 1]);
    unchecked(workV[2] = blockR[i * 2 + 16]);
    unchecked(workV[3] = blockR[i * 2 + 17]);
    unchecked(workV[4] = blockR[i * 2 + 32]);
    unchecked(workV[5] = blockR[i * 2 + 33]);
    unchecked(workV[6] = blockR[i * 2 + 48]);
    unchecked(workV[7] = blockR[i * 2 + 49]);
    unchecked(workV[8] = blockR[i * 2 + 64]);
    unchecked(workV[9] = blockR[i * 2 + 65]);
    unchecked(workV[10] = blockR[i * 2 + 80]);
    unchecked(workV[11] = blockR[i * 2 + 81]);
    unchecked(workV[12] = blockR[i * 2 + 96]);
    unchecked(workV[13] = blockR[i * 2 + 97]);
    unchecked(workV[14] = blockR[i * 2 + 112]);
    unchecked(workV[15] = blockR[i * 2 + 113]);

    blake2RoundNoMsg();

    unchecked(blockR[i * 2] = workV[0]);
    unchecked(blockR[i * 2 + 1] = workV[1]);
    unchecked(blockR[i * 2 + 16] = workV[2]);
    unchecked(blockR[i * 2 + 17] = workV[3]);
    unchecked(blockR[i * 2 + 32] = workV[4]);
    unchecked(blockR[i * 2 + 33] = workV[5]);
    unchecked(blockR[i * 2 + 48] = workV[6]);
    unchecked(blockR[i * 2 + 49] = workV[7]);
    unchecked(blockR[i * 2 + 64] = workV[8]);
    unchecked(blockR[i * 2 + 65] = workV[9]);
    unchecked(blockR[i * 2 + 80] = workV[10]);
    unchecked(blockR[i * 2 + 81] = workV[11]);
    unchecked(blockR[i * 2 + 96] = workV[12]);
    unchecked(blockR[i * 2 + 97] = workV[13]);
    unchecked(blockR[i * 2 + 112] = workV[14]);
    unchecked(blockR[i * 2 + 113] = workV[15]);
  }

  // next_block = blockTmp XOR blockR
  const currBase = currBlockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
  for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    store<u64>(memoryPtr + currBase + i * 8, unchecked(blockTmp[i] ^ blockR[i]));
  }
}

/**
 * Index alpha calculation for Argon2d
 */
function indexAlpha(pass: u32, slice: u32, index: u32, pseudoRand: u32, sameLane: bool): u32 {
  let referenceAreaSize: u32;

  if (pass == 0) {
    if (slice == 0) {
      referenceAreaSize = index - 1;
    } else {
      if (sameLane) {
        referenceAreaSize = slice * segmentLength + index - 1;
      } else {
        referenceAreaSize = slice * segmentLength + (index == 0 ? 0 : 0) - (index == 0 ? 1 : 0);
      }
    }
  } else {
    if (sameLane) {
      referenceAreaSize = laneLength - segmentLength + index - 1;
    } else {
      referenceAreaSize = laneLength - segmentLength + (index == 0 ? 0 : 0) - (index == 0 ? 1 : 0);
    }
  }

  // Map pseudo_rand to [0, reference_area_size)
  let relativePos: u64 = <u64>pseudoRand;
  relativePos = (relativePos * relativePos) >> 32;
  relativePos = <u64>referenceAreaSize - 1 - ((<u64>referenceAreaSize * relativePos) >> 32);

  // Starting position
  let startPosition: u32 = 0;
  if (pass != 0) {
    startPosition = (slice == ARGON2_SYNC_POINTS - 1) ? 0 : (slice + 1) * segmentLength;
  }

  return (startPosition + <u32>relativePos) % laneLength;
}

/**
 * Fill a segment
 */
function fillSegment(pass: u32, lane: u32, slice: u32): void {
  let startingIndex: u32 = (pass == 0 && slice == 0) ? 2 : 0;
  let currOffset: u32 = lane * laneLength + slice * segmentLength + startingIndex;
  let prevOffset: u32 = (currOffset % laneLength == 0) ? currOffset + laneLength - 1 : currOffset - 1;

  for (let i: u32 = startingIndex; i < segmentLength; i++) {
    if (currOffset % laneLength == 1) {
      prevOffset = currOffset - 1;
    }

    // Get pseudo-random from previous block
    const pseudoRand = readQword(prevOffset, 0);
    let refLane: u32 = <u32>((pseudoRand >> 32) % <u64>RANDOMX_ARGON_LANES);
    if (pass == 0 && slice == 0) {
      refLane = lane;
    }

    const refIndex = indexAlpha(pass, slice, i, <u32>(pseudoRand & 0xFFFFFFFF), refLane == lane);
    const refBlockIdx = laneLength * refLane + refIndex;

    const withXor = pass != 0 && ARGON2_VERSION != 0x10;
    fillBlock(prevOffset, refBlockIdx, currOffset, withXor);

    currOffset++;
    prevOffset++;
  }
}

/**
 * Initialize memory for Argon2d
 * Returns the memory pointer
 */
export function argon2d_init(memPtr: usize, totalBlocks: u32, laneLenParam: u32, segLenParam: u32): void {
  memoryPtr = memPtr;
  laneLength = laneLenParam;
  segmentLength = segLenParam;
}

/**
 * Fill a single segment (called from JS for progress reporting)
 */
export function argon2d_fill_segment(pass: u32, lane: u32, slice: u32): void {
  fillSegment(pass, lane, slice);
}

/**
 * Write initial block from bytes
 */
export function argon2d_write_block(blockIdx: u32, dataPtr: usize): void {
  const baseOffset = blockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
  for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    const val: u64 =
      <u64>load<u8>(dataPtr + i * 8) |
      (<u64>load<u8>(dataPtr + i * 8 + 1) << 8) |
      (<u64>load<u8>(dataPtr + i * 8 + 2) << 16) |
      (<u64>load<u8>(dataPtr + i * 8 + 3) << 24) |
      (<u64>load<u8>(dataPtr + i * 8 + 4) << 32) |
      (<u64>load<u8>(dataPtr + i * 8 + 5) << 40) |
      (<u64>load<u8>(dataPtr + i * 8 + 6) << 48) |
      (<u64>load<u8>(dataPtr + i * 8 + 7) << 56);
    store<u64>(memoryPtr + baseOffset + i * 8, val);
  }
}

/**
 * Read block to bytes (for final XOR)
 */
export function argon2d_read_block(blockIdx: u32, dataPtr: usize): void {
  const baseOffset = blockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
  for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    const val = load<u64>(memoryPtr + baseOffset + i * 8);
    store<u8>(dataPtr + i * 8, <u8>(val));
    store<u8>(dataPtr + i * 8 + 1, <u8>(val >> 8));
    store<u8>(dataPtr + i * 8 + 2, <u8>(val >> 16));
    store<u8>(dataPtr + i * 8 + 3, <u8>(val >> 24));
    store<u8>(dataPtr + i * 8 + 4, <u8>(val >> 32));
    store<u8>(dataPtr + i * 8 + 5, <u8>(val >> 40));
    store<u8>(dataPtr + i * 8 + 6, <u8>(val >> 48));
    store<u8>(dataPtr + i * 8 + 7, <u8>(val >> 56));
  }
}

/**
 * XOR block into accumulator
 */
export function argon2d_xor_block(blockIdx: u32, accumPtr: usize): void {
  const baseOffset = blockIdx * ARGON2_QWORDS_IN_BLOCK * 8;
  for (let i: u32 = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
    const existing = load<u64>(accumPtr + i * 8);
    const blockVal = load<u64>(memoryPtr + baseOffset + i * 8);
    store<u64>(accumPtr + i * 8, existing ^ blockVal);
  }
}
