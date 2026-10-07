/**
 * AETHER LEARNING SYSTEM - STEP 006: ECDSA SIGNATURE GENERATION
 * ═══════════════════════════════════════════════════════════════════════════
 * ECDSA (Elliptic Curve Digital Signature Algorithm) Signature Generation
 * Core signing operation for Bitcoin transactions and cryptographic authentication
 */

import { Point, mod, modInverseFermat, SECP256K1_N } from "./step-003-secp256k1-elliptic-curve";
import { scalarMultiplyBinary } from "./step-004-scalar-multiplication";

export interface Signature {
  r: BigInt;
  s: BigInt;
  recovery: number; // Recovery ID for public key recovery
}

/**
 * Generate random k value for ECDSA signature
 * RFC 6979 specifies deterministic k generation
 * Must be non-zero and less than curve order
 */
function generateSigningNonce(): BigInt {
  let k: BigInt;
  do {
    const randomBytes = new Uint8Array(32);
    if (globalThis.crypto?.getRandomValues) {
      globalThis.crypto.getRandomValues(randomBytes);
    } else {
      for (let i = 0; i < 32; i++) randomBytes[i] = Math.floor(Math.random() * 256);
    }
    
    let num = 0n;
    for (const byte of randomBytes) {
      num = (num << 8n) | BigInt(byte);
    }
    k = mod(num, SECP256K1_N);
  } while (k === 0n);
  
  return k;
}

/**
 * Sign a message hash with private key using ECDSA
 * 
 * Algorithm:
 * 1. Generate random k value
 * 2. Compute point R = k*G
 * 3. Extract r = R.x mod n
 * 4. If r = 0, go to step 1 (retry)
 * 5. Compute s = k^(-1) * (hash + r*d) mod n
 * 6. If s = 0, go to step 1 (retry)
 * 7. Return (r, s)
 * 
 * @param messageHash - Message hash to sign (32 bytes or BigInt)
 * @param privateKey - Private key (BigInt or Uint8Array)
 * @returns Signature object with r, s, recovery ID
 */
export function signMessage(messageHash: Uint8Array | BigInt, privateKey: BigInt | Uint8Array): Signature {
  // Convert message hash to BigInt
  let hash: BigInt;
  if (messageHash instanceof Uint8Array) {
    hash = 0n;
    for (const byte of messageHash) {
      hash = (hash << 8n) | BigInt(byte);
    }
  } else {
    hash = messageHash;
  }
  hash = mod(hash, SECP256K1_N);

  // Convert private key to BigInt
  let d: BigInt;
  if (privateKey instanceof Uint8Array) {
    d = 0n;
    for (const byte of privateKey) {
      d = (d << 8n) | BigInt(byte);
    }
  } else {
    d = privateKey;
  }
  if (d <= 0n || d >= SECP256K1_N) throw new Error("Invalid private key");

  // ECDSA signing loop
  let r = 0n, s = 0n, recovery = 0;
  const G = new Point(
    BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
  );

  while (r === 0n || s === 0n) {
    // Generate random k
    const k = generateSigningNonce();

    // Compute R = k*G
    const R = scalarMultiplyBinary(k, G);

    // Extract r = R.x mod n
    r = mod(R.x, SECP256K1_N);

    if (r === 0n) continue;

    // Compute s = k^(-1) * (hash + r*d) mod n
    const kInv = modInverseFermat(k, SECP256K1_N);
    const term1 = mod(hash + r * d, SECP256K1_N);
    s = mod(kInv * term1, SECP256K1_N);

    // Determine recovery ID
    recovery = R.y % 2n === 0n ? 0 : 1;
  }

  // If s is in upper half, use low s (for signature malleability protection)
  if (s > SECP256K1_N >> 1n) {
    s = mod(-s, SECP256K1_N);
    recovery ^= 1;
  }

  return { r, s, recovery };
}

/**
 * Verify signature format
 * @returns true if r and s are in valid range
 */
export function isValidSignature(sig: Signature): boolean {
  return (
    sig.r > 0n &&
    sig.r < SECP256K1_N &&
    sig.s > 0n &&
    sig.s < SECP256K1_N &&
    sig.recovery >= 0 &&
    sig.recovery < 4
  );
}

/**
 * Serialize signature to DER format (used in Bitcoin)
 * 
 * DER format: 0x30 [total_length] 0x02 [r_length] [r] 0x02 [s_length] [s]
 */
export function signatureToDer(sig: Signature): Uint8Array {
  // Convert r and s to bytes (big-endian)
  let rBytes = sig.r.toString(16).padStart(64, "0");
  let sBytes = sig.s.toString(16).padStart(64, "0");

  // Remove leading zeros but keep one if high bit is set
  rBytes = rBytes.replace(/^00+(?=[89a-f])/i, "").replace(/^00+$/, "00");
  sBytes = sBytes.replace(/^00+(?=[89a-f])/i, "").replace(/^00+$/, "00");

  const rHex = rBytes.length % 2 === 0 ? rBytes : "0" + rBytes;
  const sHex = sBytes.length % 2 === 0 ? sBytes : "0" + sBytes;

  const r = new Uint8Array(rHex.length / 2);
  const s = new Uint8Array(sHex.length / 2);

  for (let i = 0; i < r.length; i++) r[i] = parseInt(rHex.substr(i * 2, 2), 16);
  for (let i = 0; i < s.length; i++) s[i] = parseInt(sHex.substr(i * 2, 2), 16);

  const result = new Uint8Array(6 + r.length + s.length);
  result[0] = 0x30; // Sequence tag
  result[1] = 4 + r.length + s.length;
  result[2] = 0x02; // Integer tag
  result[3] = r.length;
  result.set(r, 4);
  result[4 + r.length] = 0x02;
  result[5 + r.length] = s.length;
  result.set(s, 6 + r.length);

  return result;
}

/**
 * Parse DER encoded signature
 */
export function parseSignatureDer(der: Uint8Array): Signature {
  if (der[0] !== 0x30) throw new Error("Invalid DER signature: bad sequence tag");

  let pos = 2;
  if (der[pos] !== 0x02) throw new Error("Invalid DER signature: expected integer tag for r");

  const rLen = der[++pos];
  const r = 0n; // Parse from bytes...
  let rValue = 0n;
  for (let i = 0; i < rLen; i++) {
    rValue = (rValue << 8n) | BigInt(der[pos + 1 + i]);
  }

  pos += 1 + rLen;
  if (der[pos] !== 0x02) throw new Error("Invalid DER signature: expected integer tag for s");

  const sLen = der[++pos];
  let sValue = 0n;
  for (let i = 0; i < sLen; i++) {
    sValue = (sValue << 8n) | BigInt(der[pos + 1 + i]);
  }

  return { r: rValue, s: sValue, recovery: 0 };
}

/**
 * Normalize signature (low s form for malleability resistance)
 */
export function normalizeSignature(sig: Signature): Signature {
  let { r, s, recovery } = sig;
  const n_half = SECP256K1_N >> 1n;

  if (s > n_half) {
    s = mod(-s, SECP256K1_N);
    recovery ^= 1;
  }

  return { r, s, recovery };
}

export { Point, SECP256K1_N };
