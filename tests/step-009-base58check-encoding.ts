/**
 * AETHER LEARNING SYSTEM - STEP 009: BASE58CHECK ENCODING AND DECODING
 * ═══════════════════════════════════════════════════════════════════════════
 * Encode and decode Bitcoin addresses, private keys, extended keys using Base58Check
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode bytes to Base58 string
 * Converts Uint8Array to base58 representation
 */
export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";

  let num = 0n;
  for (const byte of bytes) {
    num = (num << 8n) | BigInt(byte);
  }

  let result = "";
  while (num > 0n) {
    result = BASE58_ALPHABET[Number(num % 58n)] + result;
    num = num / 58n;
  }

  // Add leading "1" for each leading zero byte
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    result = "1" + result;
  }

  return result || "1";
}

/**
 * Decode Base58 string to bytes
 * Converts base58 string back to Uint8Array
 */
export function base58Decode(str: string): Uint8Array {
  let num = 0n;

  for (const char of str) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`Invalid Base58 character: ${char}`);
    num = num * 58n + BigInt(index);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }

  // Add leading zero bytes for leading "1"
  for (let i = 0; i < str.length && str[i] === "1"; i++) {
    bytes.unshift(0);
  }

  return new Uint8Array(bytes);
}

/**
 * Encode data with checksum using Base58Check
 * 
 * Format:
 * 1. Append 4-byte checksum (first 4 bytes of SHA256(SHA256(data)))
 * 2. Encode to Base58
 * 
 * Used for: Bitcoin addresses, private keys, extended keys
 */
export function base58CheckEncode(data: Uint8Array): string {
  // Calculate checksum: first 4 bytes of SHA256(SHA256(data))
  const hash1 = sha256(data);
  const hash2 = sha256(hash1);
  const checksum = hash2.slice(0, 4);

  // Append checksum to data
  const encoded = new Uint8Array(data.length + 4);
  encoded.set(data);
  encoded.set(checksum, data.length);

  return base58Encode(encoded);
}

/**
 * Decode Base58Check encoded string
 * 
 * Verifies checksum and returns original data
 * 
 * @throws Error if checksum is invalid
 */
export function base58CheckDecode(str: string): Uint8Array {
  const decoded = base58Decode(str);

  if (decoded.length < 4) {
    throw new Error("Base58Check string too short");
  }

  // Split data and checksum
  const data = decoded.slice(0, -4);
  const checksum = decoded.slice(-4);

  // Verify checksum
  const hash1 = sha256(data);
  const hash2 = sha256(hash1);
  const expectedChecksum = hash2.slice(0, 4);

  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expectedChecksum[i]) {
      throw new Error("Base58Check checksum invalid");
    }
  }

  return data;
}

/**
 * Create versioned Base58Check (e.g., Bitcoin address)
 * Prepends version byte and encodes
 */
export function versionedBase58CheckEncode(version: number, payload: Uint8Array): string {
  const data = new Uint8Array(1 + payload.length);
  data[0] = version;
  data.set(payload, 1);
  return base58CheckEncode(data);
}

/**
 * Decode versioned Base58Check and verify version
 */
export function versionedBase58CheckDecode(str: string, expectedVersion?: number): { version: number; data: Uint8Array } {
  const decoded = base58CheckDecode(str);
  const version = decoded[0];
  const data = decoded.slice(1);

  if (expectedVersion !== undefined && version !== expectedVersion) {
    throw new Error(`Invalid version: expected ${expectedVersion}, got ${version}`);
  }

  return { version, data };
}

/**
 * Bitcoin address versions
 */
export const ADDRESS_VERSIONS = {
  mainnet_p2pkh: 0x00,
  mainnet_p2sh: 0x05,
  testnet_p2pkh: 0x6f,
  testnet_p2sh: 0xc4,
  private_key: 0x80,
  private_key_testnet: 0xef,
  bip32_xpub: 0x0488b21e,
  bip32_xprv: 0x0488ad4e,
  bip32_tpub: 0x043587cf,
  bip32_tprv: 0x04358394,
};

/**
 * Check if address is valid P2PKH (version 0x00)
 */
export function isValidP2PKHAddress(address: string): boolean {
  try {
    const { version, data } = versionedBase58CheckDecode(address);
    return version === ADDRESS_VERSIONS.mainnet_p2pkh && data.length === 20;
  } catch {
    return false;
  }
}

/**
 * Check if address is valid P2SH (version 0x05)
 */
export function isValidP2SHAddress(address: string): boolean {
  try {
    const { version, data } = versionedBase58CheckDecode(address);
    return version === ADDRESS_VERSIONS.mainnet_p2sh && data.length === 20;
  } catch {
    return false;
  }
}

/**
 * Encode private key to WIF (Wallet Import Format)
 * 
 * Format: 0x80 + private_key_bytes + (0x01 for compressed) + checksum
 * Used for importing/exporting private keys from wallets
 */
export function privateKeyToWIF(privateKey: Uint8Array, compressed: boolean = true): string {
  const data = new Uint8Array(compressed ? 34 : 33);
  data[0] = ADDRESS_VERSIONS.private_key;
  data.set(privateKey, 1);
  if (compressed) {
    data[33] = 0x01;
  }
  return base58CheckEncode(data);
}

/**
 * Decode WIF to private key
 */
export function wifToPrivateKey(wif: string): { key: Uint8Array; compressed: boolean } {
  const decoded = base58CheckDecode(wif);

  if (decoded[0] !== ADDRESS_VERSIONS.private_key) {
    throw new Error("Invalid WIF version");
  }

  if (decoded.length === 33) {
    return { key: decoded.slice(1, 33), compressed: false };
  } else if (decoded.length === 34 && decoded[33] === 0x01) {
    return { key: decoded.slice(1, 33), compressed: true };
  } else {
    throw new Error("Invalid WIF format");
  }
}

export { sha256 };
