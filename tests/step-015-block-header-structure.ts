/**
 * AETHER LEARNING SYSTEM - STEP 015: BITCOIN BLOCK HEADER STRUCTURE
 * ═══════════════════════════════════════════════════════════════════════════
 * Build and parse Bitcoin block headers
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";

export interface BlockHeader {
  version: number;
  previousBlockHash: Uint8Array;
  merkleRoot: Uint8Array;
  timestamp: number;
  bits: number; // Difficulty encoding
  nonce: number; // Proof-of-work nonce
}

export interface Block {
  header: BlockHeader;
  txCount: number;
  transactions?: Uint8Array[];
}

/**
 * Create a new block header
 */
export function createBlockHeader(): BlockHeader {
  return {
    version: 0x20000000, // Version 2 with top bits for signaling
    previousBlockHash: new Uint8Array(32),
    merkleRoot: new Uint8Array(32),
    timestamp: Math.floor(Date.now() / 1000),
    bits: 0x207fffff, // Easy difficulty for testing
    nonce: 0,
  };
}

/**
 * Serialize block header to bytes
 * Bitcoin block headers are always 80 bytes
 */
export function serializeBlockHeader(header: BlockHeader): Uint8Array {
  const buffer = new Uint8Array(80);
  let pos = 0;

  // Version (4 bytes, little-endian)
  writeUInt32LE(buffer, pos, header.version);
  pos += 4;

  // Previous block hash (32 bytes, reversed)
  buffer.set(header.previousBlockHash, pos);
  pos += 32;

  // Merkle root (32 bytes, reversed)
  buffer.set(header.merkleRoot, pos);
  pos += 32;

  // Timestamp (4 bytes, little-endian)
  writeUInt32LE(buffer, pos, header.timestamp);
  pos += 4;

  // Bits (4 bytes, little-endian)
  writeUInt32LE(buffer, pos, header.bits);
  pos += 4;

  // Nonce (4 bytes, little-endian)
  writeUInt32LE(buffer, pos, header.nonce);
  pos += 4;

  return buffer;
}

/**
 * Parse block header from bytes
 */
export function parseBlockHeader(data: Uint8Array): BlockHeader {
  if (data.length < 80) {
    throw new Error("Block header must be at least 80 bytes");
  }

  return {
    version: readUInt32LE(data, 0),
    previousBlockHash: data.slice(4, 36),
    merkleRoot: data.slice(36, 68),
    timestamp: readUInt32LE(data, 68),
    bits: readUInt32LE(data, 72),
    nonce: readUInt32LE(data, 76),
  };
}

/**
 * Calculate block hash (TXID)
 */
export function calculateBlockHash(header: BlockHeader): Uint8Array {
  const serialized = serializeBlockHeader(header);
  const hash1 = sha256(serialized);
  return sha256(hash1);
}

/**
 * Get block hash as hex string
 */
export function getBlockHashHex(header: BlockHeader): string {
  const hash = calculateBlockHash(header);
  return bytesToHex(hash.reverse());
}

/**
 * Decode difficulty from bits field
 * Bits is a compact representation: 3-byte mantissa + 1-byte exponent
 */
export function bitsToTarget(bits: number): Uint8Array {
  const exponent = bits >> 24;
  const mantissa = bits & 0xffffff;

  const target = new Uint8Array(32);
  
  if (exponent <= 3) {
    // Shift right (rare)
    const shifted = mantissa >> (8 * (3 - exponent));
    return target;
  }

  // Place mantissa at correct position
  const shift = 8 * (exponent - 3);
  if (shift + 3 > 32) {
    return target; // Overflow, return zero
  }

  const mantissaBytes = [
    (mantissa >> 16) & 0xff,
    (mantissa >> 8) & 0xff,
    mantissa & 0xff,
  ];

  let targetPos = shift;
  for (const byte of mantissaBytes) {
    if (targetPos < 32) {
      target[targetPos] = byte;
    }
    targetPos++;
  }

  return target;
}

/**
 * Encode difficulty to bits field
 */
export function targetToBits(target: Uint8Array): number {
  // Find the first non-zero byte
  let size = target.length;
  let firstNonZero = 0;

  for (let i = 0; i < target.length; i++) {
    if (target[i] !== 0) {
      firstNonZero = i;
      break;
    }
  }

  size = target.length - firstNonZero;

  let mantissa = 0;
  if (size >= 1) mantissa |= target[firstNonZero] << 16;
  if (size >= 2) mantissa |= target[firstNonZero + 1] << 8;
  if (size >= 3) mantissa |= target[firstNonZero + 2];

  // Adjust if high bit is set
  if ((mantissa & 0x800000) !== 0) {
    mantissa = mantissa >> 8;
    size++;
  }

  return (size << 24) | mantissa;
}

/**
 * Helper: Read UInt32 in little-endian
 */
function readUInt32LE(buffer: Uint8Array, offset: number): number {
  return buffer[offset] | (buffer[offset + 1] << 8) | (buffer[offset + 2] << 16) | (buffer[offset + 3] << 24);
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
 * Convert bytes to hex string
 */
function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += ("0" + byte.toString(16)).slice(-2);
  }
  return hex;
}

export { sha256 };
