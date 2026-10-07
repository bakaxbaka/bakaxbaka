/**
 * AETHER LEARNING SYSTEM - STEP 018: KEY RECOVERY ALGORITHMS
 * ═══════════════════════════════════════════════════════════════════════════
 * Recover private keys from partial information or signatures
 */

import { Point, mod, modInverseFermat, SECP256K1_N, SECP256K1_P } from "./step-003-secp256k1-elliptic-curve";

/**
 * Recover public key from ECDSA signature and message
 * Given r, s from signature and message hash, recover possible public keys
 */
export function recoverPublicKeyFromSignature(
  r: BigInt,
  s: BigInt,
  messageHash: BigInt,
  recovery_id: number = 0
): Point {
  const isYOdd = (recovery_id & 1) === 1;
  const isSecondR = (recovery_id & 2) !== 0;

  // Calculate x coordinate from r
  let x = r;
  if (isSecondR) {
    x = mod(r + SECP256K1_N, SECP256K1_P);
  }

  // Calculate y² = x³ + 7
  const x3 = mod(x * x * x, SECP256K1_P);
  const ySquared = mod(x3 + 7n, SECP256K1_P);

  // Calculate y using modular square root
  const exp = (SECP256K1_P + 1n) >> 2n;
  let y = modExp(ySquared, exp, SECP256K1_P);

  // Ensure correct parity
  if ((y & 1n) !== (isYOdd ? 1n : 0n)) {
    y = mod(-y, SECP256K1_P);
  }

  const R = new Point(x, y, false);

  // Q = r^(-1) * (s*R - e*G)
  const e = mod(messageHash, SECP256K1_N);
  const rInv = modInverseFermat(r, SECP256K1_N);

  // Would need full point arithmetic here
  // Simplified version for now
  return R;
}

/**
 * Tonelli-Shanks algorithm for modular square root
 * Computes sqrt(n) mod p
 */
export function tonelliShanks(n: BigInt, p: BigInt): BigInt | null {
  // Check quadratic residue using Euler's criterion
  const legendre = modExp(n, (p - 1n) >> 1n, p);
  if (legendre !== 1n) return null; // Not a quadratic residue

  // Write p-1 as 2^s * q where q is odd
  let s = 0n;
  let q = p - 1n;
  while ((q & 1n) === 0n) {
    q = q >> 1n;
    s++;
  }

  // Find non-residue z
  let z = 2n;
  while (modExp(z, (p - 1n) >> 1n, p) !== p - 1n) {
    z = z + 1n;
  }

  let m = s;
  let c = modExp(z, q, p);
  let t = modExp(n, (q + 1n) >> 1n, p);
  let r = modExp(n, (q + 1n) >> 1n, p);

  while (true) {
    if (t === 0n) return 0n;
    if (t === 1n) return r;

    // Find least i such that t^(2^i) = 1
    let i = 1n;
    let temp = mod(t * t, p);
    while (temp !== 1n && i < m) {
      temp = mod(temp * temp, p);
      i++;
    }

    // Update values
    let b = c;
    for (let j = 0n; j < m - i - 1n; j++) {
      b = mod(b * b, p);
    }

    m = i;
    c = mod(b * b, p);
    t = mod(t * c, p);
    r = mod(r * b, p);
  }
}

/**
 * Pohlig-Hellman algorithm for discrete log with smooth order
 * Works efficiently when the group order has small prime factors
 */
export function pohligHellman(
  g: BigInt,
  h: BigInt,
  primeFactors: { prime: BigInt; power: BigInt }[],
  p: BigInt
): BigInt | null {
  let x = 0n;
  let multiplier = 1n;

  for (const factor of primeFactors) {
    const prime = factor.prime;
    const power = factor.power;

    // Compute prime^power
    let primePower = 1n;
    for (let i = 0n; i < power; i++) {
      primePower = primePower * prime;
    }

    // Solve subproblem modulo prime^power
    let gamma = 0n;
    for (let i = 0n; i < power; i++) {
      const p_inv = mod(p / primePower, p);
      const g_prime = modExp(g, p_inv, p);
      const h_prime = modExp(h, p_inv, p);

      // Shanks baby-step giant-step for small problem
      gamma = gamma + discreteLogShanks(g_prime, h_prime, prime) * multiplier;

      multiplier = multiplier * prime;
    }

    x = mod(x + gamma, p - 1n);
  }

  return x;
}

/**
 * Baby-step giant-step algorithm for discrete logarithm
 * Time: O(sqrt(n)), Space: O(sqrt(n))
 */
export function discreteLogShanks(g: BigInt, h: BigInt, p: BigInt): BigInt {
  const m = ceilSqrt(p);

  // Baby step: build table of g^j for j = 0, 1, ..., m-1
  const table = new Map<BigInt, BigInt>();
  let power = 1n;
  for (let j = 0n; j < m; j++) {
    if (!table.has(power)) {
      table.set(power, j);
    }
    power = mod(power * g, p);
  }

  // Giant step: compute g^(-im) and check table
  const gm = modExp(g, m, p);
  const gmInv = modInverseFermat(gm, p);

  let gamma = h;
  for (let i = 0n; i < m; i++) {
    if (table.has(gamma)) {
      const j = table.get(gamma)!;
      const x = i * m + j;
      if (modExp(g, x, p) === h) {
        return x;
      }
    }
    gamma = mod(gamma * gmInv, p);
  }

  throw new Error("Discrete log not found");
}

/**
 * Helper: Modular exponentiation
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
 * Ceiling of square root
 */
function ceilSqrt(n: BigInt): BigInt {
  let x = n;
  let y = (x + 1n) >> 1n;
  while (y < x) {
    x = y;
    y = (x + n / x) >> 1n;
  }
  return x;
}

export { Point, SECP256K1_N, SECP256K1_P, mod, modInverseFermat };
