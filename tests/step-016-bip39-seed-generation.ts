/**
 * AETHER LEARNING SYSTEM - STEP 016: BIP39 SEED GENERATION FROM MNEMONICS
 * ═══════════════════════════════════════════════════════════════════════════
 * Convert mnemonic phrases to deterministic seeds
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";

// BIP39 English word list (first 256 for simplicity)
const WORDLIST = [
  "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
  "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic",
  "acquire", "across", "act", "action", "actor", "acts", "actual", "acumen",
  // ... truncated for brevity, full list would have 2048 words
];

/**
 * Generate random mnemonic phrase
 * @param strength Bits of entropy: 128, 160, 192, 224, or 256
 */
export function generateMnemonic(strength: number = 128): string {
  // Validate strength
  if (![128, 160, 192, 224, 256].includes(strength)) {
    throw new Error("Strength must be 128, 160, 192, 224, or 256");
  }

  // Generate random bytes
  const entropy = new Uint8Array(strength / 8);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(entropy);
  } else {
    for (let i = 0; i < entropy.length; i++) {
      entropy[i] = Math.floor(Math.random() * 256);
    }
  }

  return entropyToMnemonic(entropy);
}

/**
 * Convert entropy bytes to mnemonic phrase
 */
export function entropyToMnemonic(entropy: Uint8Array): string {
  // Verify entropy length
  const entropyBits = entropy.length * 8;
  if (![128, 160, 192, 224, 256].includes(entropyBits)) {
    throw new Error("Entropy must be 128, 160, 192, 224, or 256 bits");
  }

  // Calculate checksum
  const checksum = calculateChecksum(entropy);
  const checksumBits = entropyBits / 32;

  // Combine entropy and checksum into bits
  const bits = bytesToBits(entropy) + checksum.substring(0, checksumBits);

  // Split into 11-bit groups and map to words
  const words: string[] = [];
  for (let i = 0; i < bits.length; i += 11) {
    const wordIndex = parseInt(bits.substring(i, i + 11), 2);
    words.push(WORDLIST[wordIndex]);
  }

  return words.join(" ");
}

/**
 * Calculate BIP39 checksum
 */
function calculateChecksum(entropy: Uint8Array): string {
  const hash = sha256(entropy);
  return bytesToBits(hash.slice(0, 1));
}

/**
 * Convert bytes to binary string
 */
function bytesToBits(bytes: Uint8Array): string {
  let bits = "";
  for (const byte of bytes) {
    bits += byte.toString(2).padStart(8, "0");
  }
  return bits;
}

/**
 * Validate mnemonic phrase
 */
export function isValidMnemonic(mnemonic: string): boolean {
  const words = mnemonic.trim().split(/\s+/);

  // Valid word counts: 12, 15, 18, 21, 24
  if (![12, 15, 18, 21, 24].includes(words.length)) {
    return false;
  }

  // Check all words exist in wordlist
  const wordSet = new Set(WORDLIST);
  for (const word of words) {
    if (!wordSet.has(word)) {
      return false;
    }
  }

  // Verify checksum
  try {
    mnemonicToEntropy(mnemonic);
    return true;
  } catch {
    return false;
  }
}

/**
 * Convert mnemonic to entropy bytes
 */
export function mnemonicToEntropy(mnemonic: string): Uint8Array {
  const words = mnemonic.trim().split(/\s+/);

  // Convert words to indices
  const indices: number[] = [];
  for (const word of words) {
    const index = WORDLIST.indexOf(word);
    if (index === -1) {
      throw new Error(`Word not in BIP39 wordlist: ${word}`);
    }
    indices.push(index);
  }

  // Convert indices to bits
  let bits = "";
  for (const index of indices) {
    bits += index.toString(2).padStart(11, "0");
  }

  // Split entropy and checksum
  const entropyBits = (words.length * 11 * 8) / 33; // 32/33 is entropy ratio
  const entropy = bitsToBytes(bits.substring(0, entropyBits));

  // Verify checksum
  const expectedChecksum = calculateChecksum(entropy);
  const actualChecksum = bits.substring(entropyBits);

  if (expectedChecksum !== actualChecksum) {
    throw new Error("BIP39 checksum invalid");
  }

  return entropy;
}

/**
 * Convert binary string to bytes
 */
function bitsToBytes(bits: string): Uint8Array {
  const bytes = new Uint8Array(bits.length / 8);
  for (let i = 0; i < bits.length; i += 8) {
    bytes[i / 8] = parseInt(bits.substring(i, i + 8), 2);
  }
  return bytes;
}

/**
 * Generate seed from mnemonic (PBKDF2)
 */
export function mnemonicToSeed(mnemonic: string, passphrase: string = ""): Uint8Array {
  // Normalize mnemonic
  const normalizedMnemonic = mnemonic.trim().split(/\s+/).join(" ");

  // Use SHA256 for simplified PBKDF2 (real implementation uses HMAC-SHA512)
  const salt = new TextEncoder().encode("TREZOR" + passphrase);
  const mnemonicBytes = new TextEncoder().encode(normalizedMnemonic);

  // Simplified: hash mnemonic + salt multiple times
  let seed = sha256(new Uint8Array([...mnemonicBytes, ...salt]));
  for (let i = 0; i < 2047; i++) {
    seed = sha256(seed);
  }

  return seed;
}

export { sha256 };
