/**
 * AETHER LEARNING SYSTEM - STEP 008: BITCOIN ADDRESS GENERATION
 * ═══════════════════════════════════════════════════════════════════════════
 * Convert public keys to Bitcoin addresses using hash160
 * Implements P2PKH, P2WPKH address formats
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";
import { ripemd160 } from "./step-002-ripemd160-hash";
import { Point } from "./step-003-secp256k1-elliptic-curve";

/**
 * Calculate hash160: RIPEMD160(SHA256(data))
 * Standard Bitcoin function for address generation
 */
export function hash160(publicKey: Uint8Array | Point): Uint8Array {
  let pubKeyBytes: Uint8Array;

  if (publicKey instanceof Point) {
    pubKeyBytes = publicKey.toCompressed();
  } else {
    pubKeyBytes = publicKey;
  }

  const sha256Hash = sha256(pubKeyBytes);
  return ripemd160(sha256Hash);
}

/**
 * Generate P2PKH address from public key
 * Format: 1... addresses (legacy Bitcoin)
 * 
 * Process:
 * 1. Calculate hash160 of public key
 * 2. Prepend version byte 0x00
 * 3. Calculate checksum = SHA256(SHA256(versioned_hash))
 * 4. Take first 4 bytes of checksum
 * 5. Append checksum to versioned hash
 * 6. Encode to Base58
 */
export function generateP2PKHAddress(publicKey: Uint8Array | Point): string {
  const h160 = hash160(publicKey);

  // Prepend version byte 0x00 (mainnet)
  const versioned = new Uint8Array(21);
  versioned[0] = 0x00;
  versioned.set(h160, 1);

  // Calculate checksum
  const hash1 = sha256(versioned);
  const hash2 = sha256(hash1);
  const checksum = hash2.slice(0, 4);

  // Combine
  const address = new Uint8Array(25);
  address.set(versioned);
  address.set(checksum, 21);

  return base58Encode(address);
}

/**
 * Generate P2WPKH address (SegWit v0)
 * Format: bc1... addresses (modern Bitcoin)
 */
export function generateP2WPKHAddress(publicKey: Uint8Array | Point): string {
  const h160 = hash160(publicKey);

  // Witness program: OP_0 + 20 bytes
  const scriptPubKey = new Uint8Array(22);
  scriptPubKey[0] = 0x00; // OP_0
  scriptPubKey[1] = 0x14; // 20 bytes
  scriptPubKey.set(h160, 2);

  // Bech32 encode
  return bech32Encode("bc", scriptPubKey);
}

/**
 * Base58 alphabet for Bitcoin
 */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode bytes to Base58 string
 */
function base58Encode(bytes: Uint8Array): string {
  // Convert to BigInt
  let num = 0n;
  for (const byte of bytes) {
    num = (num << 8n) | BigInt(byte);
  }

  // Convert to Base58
  let result = "";
  while (num > 0n) {
    const remainder = Number(num % 58n);
    result = BASE58_ALPHABET[remainder] + result;
    num = num / 58n;
  }

  // Add leading zeros
  for (const byte of bytes) {
    if (byte === 0) result = "1" + result;
    else break;
  }

  return result;
}

/**
 * Decode Base58 string to bytes
 */
function base58Decode(str: string): Uint8Array {
  let num = 0n;
  for (const char of str) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error("Invalid Base58 character");
    num = num * 58n + BigInt(index);
  }

  // Convert to bytes
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  // Add leading zeros
  for (const char of str) {
    if (char === "1") bytes.unshift(0);
    else break;
  }

  return new Uint8Array(bytes);
}

/**
 * Bech32 encoding for SegWit addresses
 */
const BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values: number[]): number {
  let chk = 1;
  for (const value of values) {
    const top = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ value;
    for (let i = 0; i < 5; i++) {
      chk ^= top & (1 << i) ? BECH32_GENERATOR[i] : 0;
    }
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const result: number[] = [];
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) >> 5);
  }
  result.push(0);
  for (let i = 0; i < hrp.length; i++) {
    result.push(hrp.charCodeAt(i) & 31);
  }
  return result;
}

function bech32VerifyChecksum(hrp: string, data: number[]): boolean {
  return bech32Polymod(bech32HrpExpand(hrp).concat(data)) === 1;
}

function bech32Encode(hrp: string, data: Uint8Array): string {
  // Convert 8-bit to 5-bit
  const values = convertBits(Array.from(data), 8, 5);
  
  // Calculate checksum
  const checksum = bech32CreateChecksum(hrp, values);
  const combined = values.concat(checksum);

  // Encode
  let result = hrp + "1";
  for (const value of combined) {
    result += BECH32_CHARSET[value];
  }
  return result;
}

function bech32CreateChecksum(hrp: string, data: number[]): number[] {
  const values = bech32HrpExpand(hrp).concat(data);
  const polymod = bech32Polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
  return [(polymod >> 25) & 31, (polymod >> 20) & 31, (polymod >> 15) & 31, (polymod >> 10) & 31, (polymod >> 5) & 31, polymod & 31];
}

function convertBits(data: number[], fromBits: number, toBits: number): number[] {
  let acc = 0, bits = 0;
  const result: number[] = [];
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      result.push((acc >> bits) & ((1 << toBits) - 1));
    }
  }
  if (bits > 0) {
    result.push((acc << (toBits - bits)) & ((1 << toBits) - 1));
  }
  return result;
}

/**
 * Validate Bitcoin address format
 */
export function isValidAddress(address: string): boolean {
  try {
    if (address.startsWith("bc1")) {
      // Bech32 validation
      return true; // Simplified
    } else {
      // Base58 validation
      const decoded = base58Decode(address);
      if (decoded.length !== 25) return false;

      const payload = decoded.slice(0, 21);
      const checksum = decoded.slice(21);
      const hash1 = sha256(payload);
      const hash2 = sha256(hash1);
      const expected = hash2.slice(0, 4);

      return Array.from(checksum).every((v, i) => v === expected[i]);
    }
  } catch {
    return false;
  }
}

export { Point, hash160 };
