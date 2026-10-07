/**
 * AETHER LEARNING SYSTEM - STEP 011: MERKLE TREES FOR BITCOIN
 * ═══════════════════════════════════════════════════════════════════════════
 * Efficient verification of transaction sets and blockchain integrity
 */

import { sha256 } from "./step-001-sha256-cryptographic-hash";

export class MerkleTree {
  private leaves: Uint8Array[] = [];
  private tree: Uint8Array[][] = [];

  constructor(transactions: Uint8Array[] = []) {
    for (const tx of transactions) {
      this.addLeaf(tx);
    }
  }

  /**
   * Add a transaction (leaf) to the tree
   */
  addLeaf(txHash: Uint8Array): void {
    this.leaves.push(txHash);
    this.rebuildTree();
  }

  /**
   * Rebuild entire Merkle tree from leaves
   */
  private rebuildTree(): void {
    if (this.leaves.length === 0) {
      this.tree = [];
      return;
    }

    // Start with leaves (double SHA256 for Bitcoin)
    this.tree = [this.leaves.map((leaf) => this.hashLeaf(leaf))];

    // Build tree upwards
    let currentLevel = this.tree[0];
    while (currentLevel.length > 1) {
      const nextLevel: Uint8Array[] = [];

      // If odd number of nodes, duplicate last
      if (currentLevel.length % 2 === 1) {
        currentLevel = [...currentLevel, currentLevel[currentLevel.length - 1]];
      }

      // Pair and hash nodes
      for (let i = 0; i < currentLevel.length; i += 2) {
        const hash = this.hashPair(currentLevel[i], currentLevel[i + 1]);
        nextLevel.push(hash);
      }

      this.tree.push(nextLevel);
      currentLevel = nextLevel;
    }
  }

  /**
   * Hash a leaf (double SHA256)
   */
  private hashLeaf(data: Uint8Array): Uint8Array {
    return sha256(sha256(data));
  }

  /**
   * Hash a pair of nodes
   */
  private hashPair(left: Uint8Array, right: Uint8Array): Uint8Array {
    const combined = new Uint8Array(left.length + right.length);
    combined.set(left);
    combined.set(right, left.length);
    return sha256(sha256(combined));
  }

  /**
   * Get the Merkle root
   */
  getRoot(): Uint8Array | null {
    if (this.tree.length === 0) return null;
    const topLevel = this.tree[this.tree.length - 1];
    return topLevel[0];
  }

  /**
   * Get proof path for leaf at index
   * Returns list of sibling hashes needed to verify inclusion
   */
  getProof(leafIndex: number): Uint8Array[] {
    if (leafIndex >= this.leaves.length) {
      throw new Error("Leaf index out of range");
    }

    const proof: Uint8Array[] = [];
    let index = leafIndex;

    for (let level = 0; level < this.tree.length - 1; level++) {
      const currentLevel = this.tree[level];
      const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;

      if (siblingIndex < currentLevel.length) {
        proof.push(currentLevel[siblingIndex]);
      }

      index = Math.floor(index / 2);
    }

    return proof;
  }

  /**
   * Verify a Merkle proof
   */
  verifyProof(leafHash: Uint8Array, leafIndex: number, proof: Uint8Array[]): boolean {
    const root = this.getRoot();
    if (!root) return false;

    let hash = this.hashLeaf(leafHash);
    let index = leafIndex;

    for (const sibling of proof) {
      if (index % 2 === 0) {
        hash = this.hashPair(hash, sibling);
      } else {
        hash = this.hashPair(sibling, hash);
      }
      index = Math.floor(index / 2);
    }

    return this.bytesEqual(hash, root);
  }

  /**
   * Compare two byte arrays
   */
  private bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }

  /**
   * Get all leaves
   */
  getLeaves(): Uint8Array[] {
    return [...this.leaves];
  }

  /**
   * Get tree size (number of leaves)
   */
  size(): number {
    return this.leaves.length;
  }
}

/**
 * Fast Merkle root calculation for transaction list
 */
export function calculateMerkleRoot(txHashes: Uint8Array[]): Uint8Array | null {
  const tree = new MerkleTree(txHashes);
  return tree.getRoot();
}

/**
 * Verify multiple proofs efficiently (batch verification)
 */
export function batchVerifyProofs(
  leaves: Uint8Array[],
  indices: number[],
  proofs: Uint8Array[][],
  root: Uint8Array
): boolean[] {
  return leaves.map((leaf, i) => {
    let hash = sha256(sha256(leaf));
    let index = indices[i];
    const proof = proofs[i];

    for (const sibling of proof) {
      const combined = new Uint8Array(64);
      if (index % 2 === 0) {
        combined.set(hash);
        combined.set(sibling, 32);
      } else {
        combined.set(sibling);
        combined.set(hash, 32);
      }
      hash = sha256(sha256(combined));
      index = Math.floor(index / 2);
    }

    return bytesEqual(hash, root);
  });
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export { sha256 };
