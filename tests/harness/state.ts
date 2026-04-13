/**
 * TestL3State -- single source of truth for L3 state in tests.
 *
 * Uses @aztec/foundation for poseidon2 hashing (no Barretenberg instance needed).
 */

import { Fr } from "@aztec/aztec.js/fields";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";

const TREE_DEPTH = 20;
// Per-tx layout constants are pipeline-independent.
const MAX_NOTES_PER_TX = 2;
const MAX_OUTPUTS_PER_TX = 2;

// Batch size is pipeline-specific, so it is passed in by the caller
// (see BatchSizing below). The IVC path uses 8, the Recursive path uses 16.
export interface BatchSizing {
  maxBatchSize: number;
  batchNullifiersCount: number; // maxBatchSize * MAX_NOTES_PER_TX
  batchNoteHashesCount: number; // maxBatchSize * MAX_OUTPUTS_PER_TX
}

// IVC pipeline bumped to batch=8 (experimental — verifies the Chonk ECCVM
// 32768-row ceiling still holds headroom at 8×batch_app verifications).
// Recursive pipeline also at sub-batch size 8; larger total batches are built
// by aggregating multiple sub-batches via the pair_wrapper circuit (not yet
// wired into this harness).
export const IVC_BATCH_SIZING: BatchSizing = {
  maxBatchSize: 8,
  batchNullifiersCount: 16,
  batchNoteHashesCount: 16,
};

export const RECURSIVE_BATCH_SIZING: BatchSizing = {
  maxBatchSize: 8,
  batchNullifiersCount: 16,
  batchNoteHashesCount: 16,
};

// -------------------------------------------------------------------------
// Async poseidon2 wrapper (foundation's poseidon2Hash returns a Promise)
// -------------------------------------------------------------------------

async function p2h(inputs: Fr[]): Promise<Fr> {
  return poseidon2Hash(inputs);
}

// -------------------------------------------------------------------------
// Append-only Merkle tree
// -------------------------------------------------------------------------

export class AppendOnlyTree {
  private nodes = new Map<string, Fr>();
  private zeroHashes: Fr[] = [];
  private nextIndex = 0;

  private constructor(private depth: number) {}

  static async create(depth = TREE_DEPTH) {
    const tree = new AppendOnlyTree(depth);
    tree.zeroHashes = new Array(depth + 1);
    tree.zeroHashes[0] = Fr.ZERO;
    for (let i = 1; i <= depth; i++) {
      tree.zeroHashes[i] = await p2h([tree.zeroHashes[i - 1], tree.zeroHashes[i - 1]]);
    }
    return tree;
  }

  get size() { return this.nextIndex; }

  root(): Fr { return this.getNode(this.depth, 0); }

  async insert(leafHash: Fr): Promise<number> {
    const idx = this.nextIndex++;
    this.setNode(0, idx, leafHash);
    let currentIdx = idx;
    let currentHash = leafHash;
    for (let level = 0; level < this.depth; level++) {
      const sib = this.getNode(level, currentIdx ^ 1);
      const [left, right] = currentIdx & 1 ? [sib, currentHash] : [currentHash, sib];
      currentHash = await p2h([left, right]);
      currentIdx >>= 1;
      this.setNode(level + 1, currentIdx, currentHash);
    }
    return idx;
  }

  siblings(index: number): Fr[] {
    const sibs: Fr[] = [];
    let currentIdx = index;
    for (let level = 0; level < this.depth; level++) {
      sibs.push(this.getNode(level, currentIdx ^ 1));
      currentIdx >>= 1;
    }
    return sibs;
  }

  private getNode(level: number, index: number): Fr {
    return this.nodes.get(`${level}:${index}`) ?? this.zeroHashes[level];
  }
  private setNode(level: number, index: number, hash: Fr) {
    this.nodes.set(`${level}:${index}`, hash);
  }
}

// -------------------------------------------------------------------------
// Indexed leaf
// -------------------------------------------------------------------------

export interface IndexedLeaf {
  value: Fr;
  nextIndex: Fr;
  nextValue: Fr;
}

async function indexedLeafHash(leaf: IndexedLeaf) {
  return p2h([leaf.value, leaf.nextIndex, leaf.nextValue]);
}

// -------------------------------------------------------------------------
// Indexed Merkle tree (nullifier tree)
// -------------------------------------------------------------------------

export class IndexedTree {
  private leaves: IndexedLeaf[] = [];
  private nodes = new Map<string, Fr>();
  private zeroHashes: Fr[] = [];
  private nextIndex = 0;

  private constructor(private depth: number) {}

  static async create(depth = TREE_DEPTH) {
    const tree = new IndexedTree(depth);
    tree.zeroHashes = new Array(depth + 1);
    tree.zeroHashes[0] = Fr.ZERO;
    for (let i = 1; i <= depth; i++) {
      tree.zeroHashes[i] = await p2h([tree.zeroHashes[i - 1], tree.zeroHashes[i - 1]]);
    }
    const zeroLeaf: IndexedLeaf = { value: Fr.ZERO, nextIndex: Fr.ZERO, nextValue: Fr.ZERO };
    tree.leaves.push(zeroLeaf);
    tree.setNode(0, 0, await indexedLeafHash(zeroLeaf));
    await tree.recomputePath(0);
    tree.nextIndex = 1;
    return tree;
  }

  get size() { return this.nextIndex; }
  root(): Fr { return this.getNode(this.depth, 0); }

  findLowLeaf(target: Fr): { leaf: IndexedLeaf; index: number } {
    const targetBig = target.toBigInt();
    let bestIdx = 0;
    let bestVal = 0n;
    for (let i = 0; i < this.leaves.length; i++) {
      const v = this.leaves[i].value.toBigInt();
      if (v < targetBig && v >= bestVal) { bestVal = v; bestIdx = i; }
    }
    return { leaf: this.leaves[bestIdx], index: bestIdx };
  }

  siblings(index: number): Fr[] {
    const sibs: Fr[] = [];
    let currentIdx = index;
    for (let level = 0; level < this.depth; level++) {
      sibs.push(this.getNode(level, currentIdx ^ 1));
      currentIdx >>= 1;
    }
    return sibs;
  }

  async insert(value: Fr): Promise<{
    lowLeaf: IndexedLeaf; lowLeafIndex: number;
    lowLeafSiblings: Fr[]; newLeafSiblings: Fr[];
  }> {
    const { leaf: lowLeaf, index: lowIdx } = this.findLowLeaf(value);
    const lowLeafSiblings = this.siblings(lowIdx);

    const updatedLow: IndexedLeaf = {
      value: lowLeaf.value, nextIndex: new Fr(BigInt(this.nextIndex)), nextValue: value,
    };
    this.leaves[lowIdx] = updatedLow;
    this.setNode(0, lowIdx, await indexedLeafHash(updatedLow));
    await this.recomputePath(lowIdx);

    const newLeaf: IndexedLeaf = {
      value, nextIndex: lowLeaf.nextIndex, nextValue: lowLeaf.nextValue,
    };
    const newIdx = this.nextIndex++;
    this.leaves.push(newLeaf);
    const newLeafSiblings = this.siblings(newIdx);

    this.setNode(0, newIdx, await indexedLeafHash(newLeaf));
    await this.recomputePath(newIdx);

    return { lowLeaf: { ...lowLeaf }, lowLeafIndex: lowIdx, lowLeafSiblings, newLeafSiblings };
  }

  private async recomputePath(leafIdx: number) {
    let currentIdx = leafIdx;
    for (let level = 0; level < this.depth; level++) {
      const left = this.getNode(level, currentIdx & ~1);
      const right = this.getNode(level, currentIdx | 1);
      currentIdx >>= 1;
      this.setNode(level + 1, currentIdx, await p2h([left, right]));
    }
  }

  private getNode(level: number, index: number): Fr {
    return this.nodes.get(`${level}:${index}`) ?? this.zeroHashes[level];
  }
  private setNode(level: number, index: number, hash: Fr) {
    this.nodes.set(`${level}:${index}`, hash);
  }
}

// -------------------------------------------------------------------------
// Note tracking
// -------------------------------------------------------------------------

export interface L3Note {
  ownerPubkeyHash: Fr;
  amount: Fr;
  tokenId: Fr;
  salt: Fr;
  hash: Fr;
  treeIndex: number;
  spent: boolean;
}

// -------------------------------------------------------------------------
// TestL3State
// -------------------------------------------------------------------------

export class TestL3State {
  public nullifierTree!: IndexedTree;
  public noteHashTree!: AppendOnlyTree;
  public notes: L3Note[] = [];
  public stateRoot: Fr = Fr.ZERO;
  public pendingDeposits = new Set<string>();
  public pendingWithdrawals = new Set<string>();

  static async create() {
    const state = new TestL3State();
    state.nullifierTree = await IndexedTree.create();
    state.noteHashTree = await AppendOnlyTree.create();
    state.stateRoot = await state.computeStateRoot();
    return state;
  }

  get nullifierTreeStartIndex() { return this.nullifierTree.size; }
  get noteHashTreeStartIndex() { return this.noteHashTree.size; }

  async computeStateRoot(): Promise<Fr> {
    return p2h([this.nullifierTree.root(), this.noteHashTree.root()]);
  }

  async noteHash(ownerPubkeyHash: Fr, amount: Fr, tokenId: Fr, salt: Fr): Promise<Fr> {
    return p2h([ownerPubkeyHash, amount, tokenId, salt]);
  }

  async depositHash(recipientPubkeyHash: Fr, amount: Fr, tokenId: Fr, salt: Fr): Promise<Fr> {
    return p2h([recipientPubkeyHash, amount, tokenId, salt]);
  }

  async computeNullifier(ownerSecret: Fr, noteSalt: Fr): Promise<Fr> {
    return p2h([ownerSecret, noteSalt]);
  }

  async hashPubkey(x: Fr, y: Fr): Promise<Fr> {
    return p2h([x, y]);
  }

  registerDeposit(depositHash: Fr) {
    this.pendingDeposits.add(depositHash.toString());
  }

  trackNote(
    ownerPubkeyHash: Fr, amount: Fr, tokenId: Fr, salt: Fr,
    hash: Fr, treeIndex: number,
  ): L3Note {
    const note: L3Note = { ownerPubkeyHash, amount, tokenId, salt, hash, treeIndex, spent: false };
    this.notes.push(note);
    return note;
  }

  async insertNullifier(value: Fr) {
    return this.nullifierTree.insert(value);
  }

  noteWitness(note: L3Note) {
    return { index: note.treeIndex, siblings: this.noteHashTree.siblings(note.treeIndex) };
  }

  nullifierNonMembershipWitness(nullifierValue: Fr) {
    const { leaf, index } = this.nullifierTree.findLowLeaf(nullifierValue);
    return { lowLeaf: leaf, lowLeafIndex: index, lowLeafSiblings: this.nullifierTree.siblings(index) };
  }

  unspentNotes(ownerPubkeyHash: Fr): L3Note[] {
    return this.notes.filter((n) => !n.spent && n.ownerPubkeyHash.equals(ownerPubkeyHash));
  }

  spendNote(note: L3Note) { note.spent = true; }

  async syncStateRoot() { this.stateRoot = await this.computeStateRoot(); }

  async buildSettleInputs(entries: BatchEntry[], sizing: BatchSizing): Promise<SettleBatchInputs> {
    const { maxBatchSize, batchNullifiersCount, batchNoteHashesCount } = sizing;
    const nullifiers = new Array<Fr>(batchNullifiersCount).fill(Fr.ZERO);
    const noteHashes = new Array<Fr>(batchNoteHashesCount).fill(Fr.ZERO);
    const depositNullifiers = new Array<Fr>(maxBatchSize).fill(Fr.ZERO);
    const withdrawalClaims = new Array<Fr>(maxBatchSize).fill(Fr.ZERO);

    for (let i = 0; i < entries.length && i < maxBatchSize; i++) {
      const e = entries[i];
      nullifiers[i * MAX_NOTES_PER_TX] = e.nullifiers[0];
      nullifiers[i * MAX_NOTES_PER_TX + 1] = e.nullifiers[1];
      noteHashes[i * MAX_OUTPUTS_PER_TX] = e.noteHashes[0];
      noteHashes[i * MAX_OUTPUTS_PER_TX + 1] = e.noteHashes[1];
      if (e.type === "deposit") depositNullifiers[i] = e.nullifiers[0];
      if (e.type === "withdraw") withdrawalClaims[i] = e.noteHashes[0];
    }

    return {
      nullifiers, noteHashes, depositNullifiers, withdrawalClaims,
      nullifiersBatchHash: await p2h(nullifiers),
      noteHashesBatchHash: await p2h(noteHashes),
      depositNullifiersHash: await p2h(depositNullifiers),
      withdrawalClaimsHash: await p2h(withdrawalClaims),
    };
  }
}

// -------------------------------------------------------------------------
// Batch entry types
// -------------------------------------------------------------------------

export interface BatchEntry {
  type: "deposit" | "payment" | "withdraw" | "padding";
  nullifiers: [Fr, Fr];
  noteHashes: [Fr, Fr];
}

export interface SettleBatchInputs {
  nullifiers: Fr[];
  noteHashes: Fr[];
  depositNullifiers: Fr[];
  withdrawalClaims: Fr[];
  nullifiersBatchHash: Fr;
  noteHashesBatchHash: Fr;
  depositNullifiersHash: Fr;
  withdrawalClaimsHash: Fr;
}
