/**
 * AETHER LEARNING SYSTEM - STEP 010: POINT COMPRESSION AND DECOMPRESSION
 * ═══════════════════════════════════════════════════════════════════════════
 * Compress and decompress elliptic curve points for Bitcoin
 */

import { Point, mod, modExp, SECP256K1_P } from "./step-003-secp256k1-elliptic-curve";

/**
 * Compress a point to 33 bytes
 * Format: 0x02 (y even) or 0x03 (y odd) + 32 bytes of x coordinate
 */
export function compressPoint(point: Point): Uint8Array {
  if (point.isInfinity) throw new Error("Cannot compress point at infinity");
  return point.toCompressed();
}

/**
 * Decompress a 33-byte compressed point
 * 
 * Algorithm:
 * 1. Extract prefix (0x02 or 0x03) to determine y parity
 * 2. Extract x coordinate from remaining 32 bytes
 * 3. Calculate y² = x³ + 7 (mod p)
 * 4. Calculate y = ±√(y²) using modular square root
 * 5. Select y with correct parity
 */
export function decompressPoint(compressed: Uint8Array): Point {
  if (compressed.length !== 33) {
    throw new Error("Compressed point must be 33 bytes");
  }

  const prefix = compressed[0];
  const isEvenY = prefix === 0x02;

  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new Error("Invalid compressed point prefix");
  }

  // Extract x coordinate
  let x = 0n;
  for (let i = 1; i < 33; i++) {
    x = (x << 8n) | BigInt(compressed[i]);
  }

  // Verify x is in valid range
  if (x >= SECP256K1_P) {
    throw new Error("x coordinate out of range");
  }

  // Calculate y² = x³ + 7 (mod p)
  const x3 = mod(x * x * x, SECP256K1_P);
  const ySquared = mod(x3 + 7n, SECP256K1_P);

  // Calculate y using Tonelli-Shanks or simple method
  // For secp256k1: p ≡ 3 (mod 4), so y = ±ySquared^((p+1)/4) mod p
  const exp = (SECP256K1_P + 1n) >> 2n;
  let y = modExp(ySquared, exp, SECP256K1_P);

  // Ensure correct parity
  const yIsEven = (y & 1n) === 0n;
  if (yIsEven !== isEvenY) {
    y = mod(-y, SECP256K1_P);
  }

  return new Point(x, y, false);
}

/**
 * Decompress from uncompressed format (65 bytes)
 * Format: 0x04 + 32 bytes x + 32 bytes y
 */
export function decompressUncompressed(uncompressed: Uint8Array): Point {
  if (uncompressed.length !== 65) {
    throw new Error("Uncompressed point must be 65 bytes");
  }

  if (uncompressed[0] !== 0x04) {
    throw new Error("Invalid uncompressed point prefix");
  }

  // Extract x
  let x = 0n;
  for (let i = 1; i < 33; i++) {
    x = (x << 8n) | BigInt(uncompressed[i]);
  }

  // Extract y
  let y = 0n;
  for (let i = 33; i < 65; i++) {
    y = (y << 8n) | BigInt(uncompressed[i]);
  }

  return new Point(x, y, false);
}

/**
 * Convert compressed to uncompressed
 * More efficient than decompressing and recompressing
 */
export function compressedToUncompressed(compressed: Uint8Array): Uint8Array {
  const point = decompressPoint(compressed);
  return point.toUncompressed();
}

/**
 * Convert uncompressed to compressed
 */
export function uncompressedToCompressed(uncompressed: Uint8Array): Uint8Array {
  const point = decompressUncompressed(uncompressed);
  return point.toCompressed();
}

/**
 * Determine if point is in compressed or uncompressed format
 */
export function getPointFormat(data: Uint8Array): "compressed" | "uncompressed" | "invalid" {
  if (data.length === 33 && (data[0] === 0x02 || data[0] === 0x03)) {
    return "compressed";
  }
  if (data.length === 65 && data[0] === 0x04) {
    return "uncompressed";
  }
  return "invalid";
}

/**
 * Validate compressed point format without full decompression
 */
export function isValidCompressedPoint(data: Uint8Array): boolean {
  if (data.length !== 33) return false;
  if (data[0] !== 0x02 && data[0] !== 0x03) return false;

  // Extract x coordinate
  let x = 0n;
  for (let i = 1; i < 33; i++) {
    x = (x << 8n) | BigInt(data[i]);
  }

  return x < SECP256K1_P;
}

/**
 * Validate uncompressed point format
 */
export function isValidUncompressedPoint(data: Uint8Array): boolean {
  if (data.length !== 65) return false;
  if (data[0] !== 0x04) return false;

  // Extract coordinates
  let x = 0n, y = 0n;
  for (let i = 1; i < 33; i++) {
    x = (x << 8n) | BigInt(data[i]);
  }
  for (let i = 33; i < 65; i++) {
    y = (y << 8n) | BigInt(data[i]);
  }

  return x < SECP256K1_P && y < SECP256K1_P;
}

/**
 * Modular exponentiation utility
 */
function modExp(base: BigInt, exp: BigInt, modulus: BigInt): BigInt {
  let result = 1n;
  base = mod(base, modulus);

  while (exp > 0n) {
    if ((exp & 1n) === 1n) {
      result = mod(result * base, modulus);
    }
    exp = exp >> 1n;
    base = mod(base * base, modulus);
  }

  return result;
}

export { Point, SECP256K1_P, mod };
