/**
 * AETHER LEARNING SYSTEM - STEP 023: BITCOIN PUZZLE METADATA DATABASE
 * ═══════════════════════════════════════════════════════════════════════════
 * Manage Bitcoin puzzle data and metadata
 */

export interface PuzzleData {
  id: number;
  bits: number;
  publicKey: string;
  address: string;
  hash160: string;
  solved: boolean;
  solvedAt?: number;
  privateKey?: string;
  btcValue: number;
  status: "unsolved" | "found" | "claimed";
}

export interface SearchProgress {
  puzzleId: number;
  bitsFound: number[];
  estimatedProgress: number;
  lastUpdated: number;
  keysSearched: BigInt;
}

/**
 * In-memory puzzle database
 */
export class PuzzleDatabase {
  private puzzles: Map<number, PuzzleData> = new Map();
  private progress: Map<number, SearchProgress> = new Map();

  /**
   * Add puzzle to database
   */
  addPuzzle(puzzle: PuzzleData): void {
    this.puzzles.set(puzzle.id, puzzle);
    this.progress.set(puzzle.id, {
      puzzleId: puzzle.id,
      bitsFound: [],
      estimatedProgress: 0,
      lastUpdated: Math.floor(Date.now() / 1000),
      keysSearched: 0n,
    });
  }

  /**
   * Get puzzle by ID
   */
  getPuzzle(id: number): PuzzleData | undefined {
    return this.puzzles.get(id);
  }

  /**
   * Get all puzzles
   */
  getAllPuzzles(): PuzzleData[] {
    return Array.from(this.puzzles.values());
  }

  /**
   * Find puzzle by address
   */
  findByAddress(address: string): PuzzleData | undefined {
    for (const puzzle of this.puzzles.values()) {
      if (puzzle.address === address) return puzzle;
    }
    return undefined;
  }

  /**
   * Get unsolved puzzles
   */
  getUnsolvedPuzzles(): PuzzleData[] {
    return Array.from(this.puzzles.values()).filter((p) => !p.solved);
  }

  /**
   * Mark puzzle as solved
   */
  solvePuzzle(id: number, privateKey: string): boolean {
    const puzzle = this.puzzles.get(id);
    if (!puzzle) return false;

    puzzle.solved = true;
    puzzle.solvedAt = Math.floor(Date.now() / 1000);
    puzzle.privateKey = privateKey;
    puzzle.status = "found";

    return true;
  }

  /**
   * Update search progress
   */
  updateProgress(id: number, bitsFound: number[], keysSearched: BigInt): void {
    const progress = this.progress.get(id);
    if (!progress) return;

    progress.bitsFound = bitsFound;
    progress.keysSearched = keysSearched;
    progress.estimatedProgress = (bitsFound.length / 64) * 100;
    progress.lastUpdated = Math.floor(Date.now() / 1000);
  }

  /**
   * Get progress for puzzle
   */
  getProgress(id: number): SearchProgress | undefined {
    return this.progress.get(id);
  }

  /**
   * Get statistics
   */
  getStatistics(): {
    totalPuzzles: number;
    solvedCount: number;
    totalValue: number;
    averageProgress: number;
  } {
    const puzzles = Array.from(this.puzzles.values());
    const solved = puzzles.filter((p) => p.solved).length;
    const totalValue = puzzles.reduce((sum, p) => sum + p.btcValue, 0);
    const avgProgress =
      puzzles.reduce((sum, p) => sum + this.getProgressPercent(p.id), 0) / puzzles.length;

    return {
      totalPuzzles: puzzles.length,
      solvedCount: solved,
      totalValue,
      averageProgress: avgProgress || 0,
    };
  }

  /**
   * Get progress percentage for puzzle
   */
  private getProgressPercent(id: number): number {
    const progress = this.progress.get(id);
    return progress ? progress.estimatedProgress : 0;
  }

  /**
   * Export database to JSON
   */
  export(): string {
    const data = {
      puzzles: Array.from(this.puzzles.values()),
      progress: Array.from(this.progress.values()),
    };
    return JSON.stringify(data, (key, value) => {
      if (typeof value === "bigint") return value.toString();
      return value;
    });
  }

  /**
   * Import from JSON
   */
  import(jsonData: string): void {
    try {
      const data = JSON.parse(jsonData);
      for (const puzzle of data.puzzles) {
        this.puzzles.set(puzzle.id, puzzle);
      }
      for (const prog of data.progress) {
        prog.keysSearched = BigInt(prog.keysSearched);
        this.progress.set(prog.puzzleId, prog);
      }
    } catch (e) {
      console.error("Failed to import database:", e);
    }
  }
}

/**
 * Load standard Bitcoin puzzle data (from CSV or API)
 */
export async function loadBitcoinPuzzles(): Promise<PuzzleData[]> {
  // Would load from:
  // 1. GitHub API: https://raw.githubusercontent.com/...puzzles.csv
  // 2. Local CSV file
  // 3. Database API

  const puzzles: PuzzleData[] = [
    {
      id: 1,
      bits: 1,
      publicKey: "0x04..." ,
      address: "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
      hash160: "...",
      solved: true,
      solvedAt: 1704067200,
      privateKey: "0x0000000000000000000000000000000000000000000000000000000000000001",
      btcValue: 1,
      status: "claimed",
    },
    // ... more puzzles
  ];

  return puzzles;
}

/**
 * Fetch puzzle data from remote source
 */
export async function fetchPuzzleDataFromGitHub(
  owner: string = "ricmoo",
  repo: string = "BitcoinPuzzleProject",
  branch: string = "master"
): Promise<PuzzleData[]> {
  const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/puzzles.csv`;

  try {
    const response = await fetch(url);
    const csv = await response.text();
    return parsePuzzleCSV(csv);
  } catch (error) {
    console.error("Failed to fetch puzzle data:", error);
    return [];
  }
}

/**
 * Parse CSV puzzle data
 */
function parsePuzzleCSV(csv: string): PuzzleData[] {
  const lines = csv.trim().split("\n");
  const puzzles: PuzzleData[] = [];

  for (const line of lines.slice(1)) {
    // Skip header
    const parts = line.split(",");
    if (parts.length < 6) continue;

    puzzles.push({
      id: parseInt(parts[0]),
      bits: parseInt(parts[1]),
      publicKey: parts[2],
      address: parts[3],
      hash160: parts[4],
      solved: parts[5] === "true",
      btcValue: parseFloat(parts[6] || "0"),
      status: "unsolved",
    });
  }

  return puzzles;
}

export {};
