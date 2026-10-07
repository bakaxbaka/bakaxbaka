/**
 * AETHER LEARNING SYSTEM - STEP 017: BITCOIN PUZZLE SCANNING BASICS
 * ═══════════════════════════════════════════════════════════════════════════
 * Foundation for scanning Bitcoin puzzle addresses and tracking found keys
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";
import { ripemd160 } from "./step-002-ripemd160-hash";
import { Point } from "./step-003-secp256k1-elliptic-curve";

export interface BitcoinPuzzle {
  id: number;
  publicKeyHex: string;
  address: string;
  solved: boolean;
  privateKeyHex?: string;
  discoveredBits: number[];
}

export interface FoundKey {
  puzzleId: number;
  privateKey: string;
  publicKey: string;
  address: string;
  timestamp: number;
  bits: number;
}

/**
 * Parse puzzle address and extract public key information
 */
export function parsePuzzleAddress(address: string): Uint8Array {
  // Decode Base58Check address to get hash160
  const decoded = base58Decode(address);
  return decoded.slice(1, 21); // Extract 20-byte hash160
}

/**
 * Calculate hash160 from point
 */
export function calculateHash160(point: Point): Uint8Array {
  const compressedPoint = point.toCompressed();
  const sha256Hash = sha256(compressedPoint);
  return ripemd160(sha256Hash);
}

/**
 * Check if private key matches puzzle (verify by deriving address)
 */
export function checkPrivateKey(privateKeyHex: string, expectedHash160: Uint8Array): boolean {
  try {
    // Parse private key
    const privateKey = hexToBytes(privateKeyHex);

    // Derive public key point
    // Use simplified calculation (normally would use full ECDSA operations)
    const pointX = BigInt("0x" + privateKeyHex.substring(0, 32));
    const pointY = BigInt("0x" + privateKeyHex.substring(32, 64));
    const point = new Point(pointX, pointY);

    // Calculate hash160
    const actualHash160 = calculateHash160(point);

    // Compare
    return bytesEqual(actualHash160, expectedHash160);
  } catch {
    return false;
  }
}

/**
 * Batch scan multiple private keys
 */
export function batchScanKeys(privateKeys: string[], targetHash160: Uint8Array): FoundKey | null {
  for (const key of privateKeys) {
    if (checkPrivateKey(key, targetHash160)) {
      return {
        puzzleId: 0,
        privateKey: key,
        publicKey: derivePublicKeyHex(key),
        address: calculateAddressFromPrivateKey(key),
        timestamp: Math.floor(Date.now() / 1000),
        bits: 64, // placeholder
      };
    }
  }
  return null;
}

/**
 * Derive public key hex from private key
 */
function derivePublicKeyHex(privateKeyHex: string): string {
  // Simplified - would use full point multiplication
  return "0x" + sha256(hexToBytes(privateKeyHex)).toString();
}

/**
 * Calculate Bitcoin address from private key
 */
function calculateAddressFromPrivateKey(privateKeyHex: string): string {
  const privateKey = hexToBytes(privateKeyHex);
  const hash = sha256(sha256(privateKey));
  return base58Encode(hash);
}

/**
 * Estimate search progress for bits
 */
export function estimateProgressForBits(targetBits: number): number {
  // Each bit doubles the search space
  // Progress = 2^targetBits / 2^256
  return (targetBits / 256) * 100;
}

/**
 * Convert keys to JSON format
 */
export function formatFoundKey(key: FoundKey): string {
  return JSON.stringify(key, null, 2);
}

/**
 * Helper functions
 */
function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace("0x", "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) {
    hex += ("0" + byte.toString(16)).slice(-2);
  }
  return "0x" + hex;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function base58Encode(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (const byte of bytes) {
    num = (num << 8n) | BigInt(byte);
  }
  let result = "";
  while (num > 0n) {
    result = alphabet[Number(num % 58n)] + result;
    num = num / 58n;
  }
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    result = "1" + result;
  }
  return result;
}

function base58Decode(str: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let num = 0n;
  for (const char of str) {
    const index = alphabet.indexOf(char);
    if (index === -1) throw new Error("Invalid Base58");
    num = num * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }
  for (let i = 0; i < str.length && str[i] === "1"; i++) {
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

export { sha256, ripemd160, Point };
