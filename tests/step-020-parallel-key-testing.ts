/**
 * AETHER LEARNING SYSTEM - STEP 020: PARALLEL KEY TESTING FRAMEWORK
 * ═══════════════════════════════════════════════════════════════════════════
 * Efficient parallel testing of candidate private keys against Bitcoin puzzles
 */

/**
 * Test result for a single key
 */
export interface KeyTestResult {
  key: string;
  valid: boolean;
  puzzleId?: number;
  hashMatch: boolean;
  timestamp: number;
  executionTime: number;
}

/**
 * Batch test multiple keys against a single puzzle
 */
export function batchTestKeysAgainstPuzzle(
  keys: string[],
  expectedHash160: Uint8Array,
  verifyFunction: (k: string, hash: Uint8Array) => boolean
): KeyTestResult[] {
  const results: KeyTestResult[] = [];
  const startTime = performance.now();

  for (const key of keys) {
    const keyStart = performance.now();
    const isValid = verifyFunction(key, expectedHash160);
    const keyTime = performance.now() - keyStart;

    results.push({
      key,
      valid: isValid,
      hashMatch: isValid,
      timestamp: Math.floor(Date.now() / 1000),
      executionTime: keyTime,
    });
  }

  return results;
}

/**
 * Test single key against multiple puzzles
 */
export function testKeyAgainstMultiplePuzzles(
  key: string,
  puzzles: Array<{ id: number; hash: Uint8Array }>,
  verifyFunction: (k: string, hash: Uint8Array) => boolean
): KeyTestResult[] {
  const results: KeyTestResult[] = [];

  for (const puzzle of puzzles) {
    const isValid = verifyFunction(key, puzzle.hash);

    if (isValid) {
      results.push({
        key,
        valid: true,
        puzzleId: puzzle.id,
        hashMatch: true,
        timestamp: Math.floor(Date.now() / 1000),
        executionTime: 0,
      });
    }
  }

  return results;
}

/**
 * Grid search: test multiple keys against multiple puzzles efficiently
 */
export function gridSearch(
  keys: string[],
  puzzles: Array<{ id: number; hash: Uint8Array }>,
  verifyFunction: (k: string, hash: Uint8Array) => boolean
): Map<number, string[]> {
  const foundKeys = new Map<number, string[]>();

  for (const puzzle of puzzles) {
    const matchingKeys: string[] = [];

    for (const key of keys) {
      if (verifyFunction(key, puzzle.hash)) {
        matchingKeys.push(key);
      }
    }

    if (matchingKeys.length > 0) {
      foundKeys.set(puzzle.id, matchingKeys);
    }
  }

  return foundKeys;
}

/**
 * Progressive testing: test keys in order of likelihood
 * Prioritize based on bit patterns or known partial solutions
 */
export function progressiveTest(
  keys: string[],
  expectedHash: Uint8Array,
  verifyFunction: (k: string, hash: Uint8Array) => boolean,
  priorityComparator?: (a: string, b: string) => number
): KeyTestResult | null {
  const sortedKeys = priorityComparator ? [...keys].sort(priorityComparator) : keys;

  for (const key of sortedKeys) {
    if (verifyFunction(key, expectedHash)) {
      return {
        key,
        valid: true,
        hashMatch: true,
        timestamp: Math.floor(Date.now() / 1000),
        executionTime: 0,
      };
    }
  }

  return null;
}

/**
 * Calculate testing statistics
 */
export function calculateStatistics(results: KeyTestResult[]): {
  totalTested: number;
  foundCount: number;
  averageTime: number;
  successRate: number;
} {
  const found = results.filter((r) => r.valid).length;
  const totalTime = results.reduce((sum, r) => sum + r.executionTime, 0);

  return {
    totalTested: results.length,
    foundCount: found,
    averageTime: results.length > 0 ? totalTime / results.length : 0,
    successRate: results.length > 0 ? found / results.length : 0,
  };
}

/**
 * Estimate remaining time for full key space search
 */
export function estimateSearchTime(
  averageTimePerKey: number,
  totalKeysInSpace: BigInt = BigInt("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
): number {
  const keysPerSecond = 1000 / averageTimePerKey; // approximate
  return Number(totalKeysInSpace) / keysPerSecond;
}

/**
 * Worker thread simulation for parallel testing
 */
export class KeyTestWorker {
  private queue: string[] = [];
  private results: KeyTestResult[] = [];

  addKey(key: string): void {
    this.queue.push(key);
  }

  addKeys(keys: string[]): void {
    this.queue.push(...keys);
  }

  testAllAgainstHash(hash: Uint8Array, verifier: (k: string, h: Uint8Array) => boolean): KeyTestResult[] {
    this.results = [];

    while (this.queue.length > 0) {
      const key = this.queue.shift()!;
      if (verifier(key, hash)) {
        this.results.push({
          key,
          valid: true,
          hashMatch: true,
          timestamp: Math.floor(Date.now() / 1000),
          executionTime: 0,
        });
      }
    }

    return this.results;
  }

  getResults(): KeyTestResult[] {
    return [...this.results];
  }

  reset(): void {
    this.queue = [];
    this.results = [];
  }
}

/**
 * Multi-worker coordinator
 */
export class MultiWorkerCoordinator {
  private workers: KeyTestWorker[] = [];
  private numWorkers: number;

  constructor(numWorkers: number = 4) {
    this.numWorkers = numWorkers;
    for (let i = 0; i < numWorkers; i++) {
      this.workers.push(new KeyTestWorker());
    }
  }

  /**
   * Distribute keys across workers
   */
  distributeKeys(keys: string[]): void {
    for (let i = 0; i < keys.length; i++) {
      this.workers[i % this.numWorkers].addKey(keys[i]);
    }
  }

  /**
   * Test all keys
   */
  testAll(hash: Uint8Array, verifier: (k: string, h: Uint8Array) => boolean): KeyTestResult[] {
    const allResults: KeyTestResult[] = [];

    for (const worker of this.workers) {
      allResults.push(...worker.testAllAgainstHash(hash, verifier));
    }

    return allResults;
  }

  reset(): void {
    for (const worker of this.workers) {
      worker.reset();
    }
  }
}

export {};
