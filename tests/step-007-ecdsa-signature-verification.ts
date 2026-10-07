/**
 * AETHER LEARNING SYSTEM - STEP 007: ECDSA SIGNATURE VERIFICATION
 * ═══════════════════════════════════════════════════════════════════════════
 * Verify ECDSA signatures using public key
 * Critical for Bitcoin transaction validation and authentication
 */

import { Point, mod, modInverseFermat, SECP256K1_N, SECP256K1_P } from "./step-003-secp256k1-elliptic-curve";
import { scalarMultiplyBinary } from "./step-004-scalar-multiplication";
import { shamirMultiply } from "./step-004-scalar-multiplication";

export interface Signature {
  r: BigInt;
  s: BigInt;
  recovery?: number;
}

/**
 * Verify ECDSA signature against message hash and public key
 * 
 * Algorithm:
 * 1. Check r, s are in valid range [1, n-1]
 * 2. Compute w = s^(-1) mod n
 * 3. Compute u1 = (hash * w) mod n
 * 4. Compute u2 = (r * w) mod n
 * 5. Compute point P = u1*G + u2*Q
 * 6. Signature valid if P.x ≡ r (mod n) and P not at infinity
 * 
 * Uses Shamir's trick for efficiency (combined scalar multiplication)
 * 
 * @param messageHash - Hash of message (32 bytes or BigInt)
 * @param signature - Signature (r, s)
 * @param publicKey - Public key point
 * @returns true if signature is valid for message and public key
 */
export function verifySignature(
  messageHash: Uint8Array | BigInt,
  signature: Signature,
  publicKey: Point
): boolean {
  // Convert hash to BigInt
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

  // Basic validation
  if (signature.r <= 0n || signature.r >= SECP256K1_N) return false;
  if (signature.s <= 0n || signature.s >= SECP256K1_N) return false;
  if (publicKey.isInfinity || !publicKey.isValid()) return false;

  // Compute w = s^(-1) mod n
  const w = modInverseFermat(signature.s, SECP256K1_N);

  // Compute u1 = (hash * w) mod n
  const u1 = mod(hash * w, SECP256K1_N);

  // Compute u2 = (r * w) mod n
  const u2 = mod(signature.r * w, SECP256K1_N);

  // Generator point
  const G = new Point(
    BigInt("0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
    BigInt("0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")
  );

  // Use Shamir's trick: P = u1*G + u2*Q
  const P = shamirMultiply(u1, G, u2, publicKey);

  // Invalid if P is point at infinity
  if (P.isInfinity) return false;

  // Check if P.x ≡ r (mod n)
  return mod(P.x, SECP256K1_N) === signature.r;
}

/**
 * Recover public key from signature and message
 * 
 * Given a signature (r, s) and message hash, recover which public key signed it
 * Uses recovery ID (0-3) to identify correct recovery point
 * 
 * @param messageHash - Hash of message
 * @param signature - Signature with recovery ID
 * @returns Array of possible public keys (usually 1-2 valid ones)
 */
export function recoverPublicKey(
  messageHash: Uint8Array | BigInt,
  signature: Signature & { recovery: number }
): Point[] {
  // Convert hash to BigInt
  let hash: BigInt;
  if (messageHash instanceof Uint8Array) {
    hash = 0n;
    for (const byte of messageHash) {
      hash = (hash << 8n) | BigInt(byte);
    }
  } else {
    hash = messageHash;
  }

  const recoveryId = signature.recovery;
  const isYEven = (recoveryId & 1) === 0;
  const xOverflow = (recoveryId & 2) !== 0;

  // Calculate x coordinate of R
  let x = signature.r;
  if (xOverflow) {
    x = mod(x + SECP256K1_N, SECP256K1_P);
  }

  // Calculate y² = x³ + 7 (mod p)
  const x3 = mod(x * x * x, SECP256K1_P);
  const ySquared = mod(x3 + 7n, SECP256K1_P);

  // Calculate y using modular square root
  // For secp256k1 p ≡ 3 (mod 4), sqrt(x) = x^((p+1)/4) mod p
  const expValue = mod((SECP256K1_P + 1n) >> 2n, SECP256K1_P);
  let y = modExp(ySquared, expValue, SECP256K1_P);

  // Ensure correct parity
  if ((y & 1n) !== (isYEven ? 0n : 1n)) {
    y = mod(-y, SECP256K1_P);
  }

  const R = new Point(x, y, false);

  // Compute e (message hash as BigInt in curve order)
  const e = mod(hash, SECP256K1_N);

  // Compute (-e) * R
  const negE = mod(-e, SECP256K1_N);
  const negER = scalarMultiplyBinary(negE, R);

  // Compute (1/r) * s * R
  const rInv = modInverseFermat(signature.r, SECP256K1_N);
  const sR = scalarMultiplyBinary(signature.s, R);
  const rInvSR = scalarMultiplyBinary(rInv, sR);

  // Q = (1/r) * (s*R - e*R)
  const Q = Point.add(rInvSR, negER);

  return [Q];
}

/**
 * Batch verify multiple signatures efficiently
 * 
 * Verifies a list of (message, signature, publicKey) tuples
 * 
 * @param messages - Array of message hashes
 * @param signatures - Array of signatures
 * @param publicKeys - Array of public keys
 * @returns Array of boolean verification results
 */
export function batchVerify(
  messages: (Uint8Array | BigInt)[],
  signatures: Signature[],
  publicKeys: Point[]
): boolean[] {
  if (messages.length !== signatures.length || messages.length !== publicKeys.length) {
    throw new Error("Messages, signatures, and public keys must have same length");
  }

  return messages.map((msg, i) => verifySignature(msg, signatures[i], publicKeys[i]));
}

/**
 * Modular exponentiation (needed for key recovery)
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

/**
 * Check signature format validity
 */
export function isValidSignatureFormat(sig: Signature): boolean {
  return sig.r > 0n && sig.r < SECP256K1_N && sig.s > 0n && sig.s < SECP256K1_N;
}

export { Point, SECP256K1_N };
