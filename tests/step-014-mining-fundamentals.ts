/**
 * AETHER LEARNING SYSTEM - STEP 014: MINING FUNDAMENTALS
 * ═══════════════════════════════════════════════════════════════════════════
 * Proof of Work and mining difficulty calculations
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";

/**
 * Check if hash meets difficulty target
 * In Bitcoin, difficulty is expressed as a target (maximum valid hash value)
 */
export function checkProofOfWork(hash: Uint8Array, target: Uint8Array): boolean {
  // Hash is valid if it's less than or equal to target (as little-endian comparison)
  return hashLessThanTarget(hash, target);
}

/**
 * Compare hash to target (little-endian)
 */
function hashLessThanTarget(hash: Uint8Array, target: Uint8Array): boolean {
  // Compare from end to beginning (little-endian)
  for (let i = hash.length - 1; i >= 0; i--) {
    if (hash[i] < target[i]) return true;
    if (hash[i] > target[i]) return false;
  }
  return true;
}

/**
 * Calculate difficulty from target
 * difficulty = max_target / current_target
 */
export function calculateDifficulty(target: Uint8Array): BigInt {
  const maxTarget = hexToBytes("00000000ffff0000000000000000000000000000000000000000000000000000");
  return bytesToBigInt(maxTarget) / bytesToBigInt(target);
}

/**
 * Convert difficulty to target
 */
export function difficultyToTarget(difficulty: BigInt): Uint8Array {
  const maxTarget = bytesToBigInt(hexToBytes("00000000ffff0000000000000000000000000000000000000000000000000000"));
  const target = maxTarget / difficulty;
  return bigIntToBytes(target, 32);
}

/**
 * Mine a block (find valid nonce)
 * Iterates nonce values until finding a valid proof-of-work
 */
export function mineBlock(
  blockHeader: Uint8Array,
  target: Uint8Array,
  startNonce: number = 0,
  maxNonce: number = 0xffffffff
): number | null {
  const header = new Uint8Array(blockHeader);

  for (let nonce = startNonce; nonce <= maxNonce; nonce++) {
    // Write nonce to header (position 76-79, little-endian)
    writeUInt32LE(header, 76, nonce);

    // Calculate hash
    const hash1 = sha256(header);
    const hash = sha256(hash1);

    // Check if valid
    if (checkProofOfWork(hash, target)) {
      return nonce;
    }
  }

  return null; // No valid nonce found
}

/**
 * Verify block proof-of-work
 */
export function verifyBlockProofOfWork(blockHeader: Uint8Array, target: Uint8Array): boolean {
  const hash1 = sha256(blockHeader);
  const hash = sha256(hash1);
  return checkProofOfWork(hash, target);
}

/**
 * Calculate leading zeros in hash (common difficulty metric)
 */
export function countLeadingZeros(hash: Uint8Array): number {
  let zeros = 0;
  for (const byte of hash) {
    if (byte === 0) {
      zeros += 8;
    } else {
      // Count leading zeros in this byte
      let b = byte;
      while ((b & 0x80) === 0) {
        zeros++;
        b <<= 1;
      }
      break;
    }
  }
  return zeros;
}

/**
 * Estimate time to find valid block (in seconds)
 */
export function estimateMiningTime(hashRate: number, difficulty: BigInt): number {
  // Expected hashes needed = difficulty * 2^32 / max_target
  const expectedHashes = Number(difficulty) * (2 ** 32);
  return expectedHashes / hashRate;
}

/**
 * Helper: Write UInt32 in little-endian
 */
function writeUInt32LE(buffer: Uint8Array, offset: number, value: number): void {
  buffer[offset] = value & 0xff;
  buffer[offset + 1] = (value >> 8) & 0xff;
  buffer[offset + 2] = (value >> 16) & 0xff;
  buffer[offset + 3] = (value >> 24) & 0xff;
}

/**
 * Convert bytes to BigInt
 */
function bytesToBigInt(bytes: Uint8Array): BigInt {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert BigInt to bytes
 */
function bigIntToBytes(num: BigInt, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  const hex = num.toString(16).padStart(length * 2, "0");
  for (let i = 0; i < length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

export { sha256 };
