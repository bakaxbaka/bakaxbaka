/**
 * AETHER LEARNING SYSTEM - STEP 012: BIP32 HIERARCHICAL DETERMINISTIC WALLETS
 * ═══════════════════════════════════════════════════════════════════════════
 * Generate key hierarchies from a single seed (HD wallets)
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";
import { ripemd160 } from "./step-002-ripemd160-hash";

export interface ExtendedKey {
  privateKey?: Uint8Array;
  publicKeyPoint?: { x: BigInt; y: BigInt };
  chainCode: Uint8Array;
  depth: number;
  parentFingerprint: number;
  childIndex: number;
}

/**
 * HMAC-SHA512 for key derivation
 */
function hmacSha512(key: Uint8Array, data: Uint8Array): Uint8Array {
  const blockSize = 64;
  let k = key;

  if (k.length > blockSize) {
    k = sha256(k);
  }

  if (k.length < blockSize) {
    const padded = new Uint8Array(blockSize);
    padded.set(k);
    k = padded;
  }

  const opad = new Uint8Array(blockSize);
  const ipad = new Uint8Array(blockSize);

  for (let i = 0; i < blockSize; i++) {
    opad[i] = k[i] ^ 0x5c;
    ipad[i] = k[i] ^ 0x36;
  }

  const ipadData = new Uint8Array(blockSize + data.length);
  ipadData.set(ipad);
  ipadData.set(data, blockSize);

  const hash1 = sha256(ipadData);

  const opadHash = new Uint8Array(blockSize + hash1.length);
  opadHash.set(opad);
  opadHash.set(hash1, blockSize);

  return sha256(opadHash);
}

/**
 * Generate master key from seed
 */
export function generateMasterKey(seed: Uint8Array): ExtendedKey {
  const hmac = hmacSha512(Buffer.from("Bitcoin seed"), seed);

  const privateKey = hmac.slice(0, 32);
  const chainCode = hmac.slice(32, 64);

  return {
    privateKey,
    chainCode,
    depth: 0,
    parentFingerprint: 0,
    childIndex: 0,
  };
}

/**
 * Derive child key (hardened: >= 0x80000000, normal: < 0x80000000)
 */
export function deriveChildKey(parentKey: ExtendedKey, childIndex: number): ExtendedKey {
  if (!parentKey.privateKey) {
    throw new Error("Cannot derive hardened child without private key");
  }

  let data: Uint8Array;

  if (childIndex >= 0x80000000) {
    // Hardened: use private key
    data = new Uint8Array(37);
    data[0] = 0;
    data.set(parentKey.privateKey, 1);
  } else {
    // Normal: use public key
    throw new Error("Public key derivation not yet implemented");
  }

  // Append child index (big-endian)
  data[33] = (childIndex >> 24) & 0xff;
  data[34] = (childIndex >> 16) & 0xff;
  data[35] = (childIndex >> 8) & 0xff;
  data[36] = childIndex & 0xff;

  const hmac = hmacSha512(parentKey.chainCode, data);
  const newPrivateKey = hmac.slice(0, 32);
  const newChainCode = hmac.slice(32, 64);

  return {
    privateKey: newPrivateKey,
    chainCode: newChainCode,
    depth: parentKey.depth + 1,
    parentFingerprint: calculateFingerprint(parentKey),
    childIndex,
  };
}

/**
 * Calculate key fingerprint (first 4 bytes of hash160)
 */
function calculateFingerprint(key: ExtendedKey): number {
  if (!key.privateKey) throw new Error("Cannot calculate fingerprint without private key");

  // Get public key hash
  const hash = ripemd160(sha256(key.privateKey));
  let fingerprint = 0;

  for (let i = 0; i < 4; i++) {
    fingerprint = (fingerprint << 8) | hash[i];
  }

  return fingerprint;
}

/**
 * Derive path like "m/44'/0'/0'/0/0"
 */
export function derivePath(masterKey: ExtendedKey, path: string): ExtendedKey {
  const parts = path.split("/");
  if (parts[0] !== "m") {
    throw new Error("Path must start with 'm'");
  }

  let key = masterKey;

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    let childIndex = parseInt(part);

    if (part.endsWith("'") || part.endsWith("H")) {
      childIndex = (childIndex | 0x80000000) >>> 0;
    }

    key = deriveChildKey(key, childIndex);
  }

  return key;
}

/**
 * Serialize extended key to string
 */
export function serializeExtendedKey(key: ExtendedKey): string {
  // Simplified Base58Check encoding
  const data = new Uint8Array(78);

  // Version (xprv: 0x0488ade4, xpub: 0x0488b21e)
  if (key.privateKey) {
    data[0] = 0x04;
    data[1] = 0x88;
    data[2] = 0xad;
    data[3] = 0xe4;
  }

  // Depth
  data[4] = key.depth;

  // Parent fingerprint
  data[5] = (key.parentFingerprint >> 24) & 0xff;
  data[6] = (key.parentFingerprint >> 16) & 0xff;
  data[7] = (key.parentFingerprint >> 8) & 0xff;
  data[8] = key.parentFingerprint & 0xff;

  // Child index
  data[9] = (key.childIndex >> 24) & 0xff;
  data[10] = (key.childIndex >> 16) & 0xff;
  data[11] = (key.childIndex >> 8) & 0xff;
  data[12] = key.childIndex & 0xff;

  // Chain code
  data.set(key.chainCode, 13);

  // Key data
  if (key.privateKey) {
    data[45] = 0;
    data.set(key.privateKey, 46);
  }

  // Calculate checksum
  const hash1 = sha256(data);
  const hash2 = sha256(hash1);
  const checksum = hash2.slice(0, 4);

  const full = new Uint8Array(82);
  full.set(data);
  full.set(checksum, 78);

  return base58Encode(full);
}

/**
 * Base58 encode helper
 */
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

export { hmacSha512 };
