import { type Barretenberg, Fr } from "@aztec/bb.js";

const TREE_DEPTH = 20;

/**
 * Production append-only Merkle tree backed by Poseidon2.
 *
 * - Leaves are stored in a flat array.
 * - Internal nodes are stored in a map keyed by (level, index).
 * - Zero-hashes (empty subtree roots) are precomputed at init.
 */
export class AppendOnlyMerkleTree {
  private leaves: string[] = [];
  private nodes: Map<string, string> = new Map();
  private zeroHashes: string[] = [];
  private nextIndex = 0;

  private constructor(
    private api: Barretenberg,
    private depth: number,
  ) {}

  /** Factory — must be async because zero-hash precomputation uses bb. */
  static async create(
    api: Barretenberg,
    depth: number = TREE_DEPTH,
  ): Promise<AppendOnlyMerkleTree> {
    const tree = new AppendOnlyMerkleTree(api, depth);
    await tree.init();
    return tree;
  }

  // -------------------------------------------------------------------------
  // Initialisation
  // -------------------------------------------------------------------------

  private async init(): Promise<void> {
    // Precompute zero hashes bottom-up.
    // zeroHashes[0] = 0  (canonical empty leaf)
    // zeroHashes[i] = poseidon2([zeroHashes[i-1], zeroHashes[i-1]])
    this.zeroHashes = new Array(this.depth + 1);
    this.zeroHashes[0] = Fr.ZERO.toString();

    for (let i = 1; i <= this.depth; i++) {
      this.zeroHashes[i] = (
        await this.api.poseidon2Hash([
          Fr.fromString(this.zeroHashes[i - 1]),
          Fr.fromString(this.zeroHashes[i - 1]),
        ])
      ).toString();
    }

    // Initialise all leaves to zero.
    const maxLeaves = 1 << this.depth;
    this.leaves = new Array(maxLeaves).fill(Fr.ZERO.toString());
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /** Insert a leaf and recompute the path to the root. Returns the leaf index. */
  async insert(leafHash: string): Promise<number> {
    const idx = this.nextIndex++;
    this.leaves[idx] = leafHash;

    // Walk up, recomputing each level.
    let currentIdx = idx;
    let currentHash = leafHash;

    for (let level = 0; level < this.depth; level++) {
      const isRight = currentIdx & 1;
      const siblingIdx = isRight ? currentIdx - 1 : currentIdx + 1;
      const siblingHash = this.getNode(level, siblingIdx);

      const [left, right] = isRight
        ? [siblingHash, currentHash]
        : [currentHash, siblingHash];

      currentHash = (
        await this.api.poseidon2Hash([Fr.fromString(left), Fr.fromString(right)])
      ).toString();

      const parentIdx = currentIdx >> 1;
      this.setNode(level + 1, parentIdx, currentHash);
      currentIdx = parentIdx;
    }

    return idx;
  }

  /** Current root hash. */
  root(): string {
    return this.getNode(this.depth, 0);
  }

  /** Sibling hashes for the Merkle path at `index`. */
  async siblings(index: number): Promise<string[]> {
    const sibs: string[] = [];
    let currentIdx = index;

    for (let level = 0; level < this.depth; level++) {
      const siblingIdx = currentIdx ^ 1;
      sibs.push(this.getNode(level, siblingIdx));
      currentIdx >>= 1;
    }

    return sibs;
  }

  /** Non-membership witness for the next empty slot. */
  async nonMembershipWitness(
    nextIndex?: number,
  ): Promise<{ index: number; siblings: string[] }> {
    const idx = nextIndex ?? this.nextIndex;
    return {
      index: idx,
      siblings: await this.siblings(idx),
    };
  }

  /** Number of leaves inserted so far. */
  get size(): number {
    return this.nextIndex;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  private nodeKey(level: number, index: number): string {
    return `${level}:${index}`;
  }

  private getNode(level: number, index: number): string {
    return this.nodes.get(this.nodeKey(level, index)) ?? this.zeroHashes[level];
  }

  private setNode(level: number, index: number, hash: string): void {
    this.nodes.set(this.nodeKey(level, index), hash);
  }
}
