/**
 * Prover (recursive) -- batch_app -> wrapper pipeline.
 *
 * Replaces the IVC/Chonk/tube pipeline with a single recursive
 * UltraHonk wrapper circuit. No kernels, no Chonk, no AztecClientBackend.
 *
 * The wrapper circuit verifies a batch_app UltraHonk proof and re-exposes
 * the same 8 BatchOutput public inputs. The wrapper proof is what
 * submit_batch verifies on L2.
 */

import { type Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Fr } from "@aztec/aztec.js/fields";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { Noir } from "@aztec/noir-noir_js";
import { readFileSync } from "fs";
import { resolve } from "path";
import { RECURSIVE_BATCH_SIZING, type TestL3State, type SettleBatchInputs, type L3Note } from "./state.js";
import {
  proveDeposit,
  provePayment,
  proveWithdraw,
  provePadding,
  type TxProofResult,
  type BatchArtifact,
} from "./prover.js";

const TARGET_DIR = resolve(import.meta.dirname ?? ".", "../../target");
// Recursive pipeline batch sizes. Must match circuits/batch_app_standalone/src/main.nr
// globals and contract_recursive/src/main.nr. No ECCVM bottleneck (standalone UltraHonk).
const MAX_BATCH_SIZE = RECURSIVE_BATCH_SIZING.maxBatchSize;         // 8
const MAX_NOTES_PER_TX = 2;
const MAX_OUTPUTS_PER_TX = 2;
const BATCH_NULLIFIERS_COUNT = RECURSIVE_BATCH_SIZING.batchNullifiersCount;   // 16
const BATCH_NOTE_HASHES_COUNT = RECURSIVE_BATCH_SIZING.batchNoteHashesCount;  // 16

// Proof / VK field lengths (shared across buildBatchProofRecursive and buildPairWrapperProof).
const VK_FIELDS = 115;
const PROOF_FIELDS = 500;

// -------------------------------------------------------------------------
// Circuit loading (cached)
// -------------------------------------------------------------------------

const circuitCache = new Map<string, any>();
function loadCircuit(name: string) {
  if (!circuitCache.has(name)) {
    circuitCache.set(name, JSON.parse(readFileSync(resolve(TARGET_DIR, `l3_${name}.json`), "utf-8")));
  }
  return circuitCache.get(name)!;
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

const f2s = (f: Fr) => f.toString();
const fs2s = (fs: Fr[]) => fs.map(f2s);

async function p2h(inputs: Fr[]): Promise<Fr> {
  return poseidon2Hash(inputs);
}

function bytesToFieldStrings(buf: Uint8Array, numFields: number): string[] {
  const fields: string[] = [];
  for (let i = 0; i < numFields; i++) {
    const slice = buf.slice(i * 32, (i + 1) * 32);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    fields.push(BigInt(hex).toString());
  }
  return fields;
}

function vkToFields(vk: Uint8Array): Fr[] {
  const numFields = vk.length / 32;
  const fields: Fr[] = [];
  for (let i = 0; i < numFields; i++) {
    const slice = vk.slice(i * 32, (i + 1) * 32);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    fields.push(new Fr(BigInt(hex)));
  }
  return fields;
}

function serLeaf(leaf: { value: Fr; nextIndex: Fr; nextValue: Fr }) {
  return { value: f2s(leaf.value), next_index: f2s(leaf.nextIndex), next_value: f2s(leaf.nextValue) };
}

function zeroSibs(): string[] { return new Array(20).fill("0"); }

// -------------------------------------------------------------------------
// buildBatchProofRecursive
//
// Shared logic with buildBatchProof up through batch_app witness execution,
// then diverges: UltraHonk prove batch_app -> execute wrapper -> prove wrapper.
// -------------------------------------------------------------------------

export interface BuildRecursiveOptions {
  /**
   * Verifier target for the wrapper proof.
   *
   * - "noir-recursive" (default): produces 500-field UltraHonkZK proofs that
   *   match the contract's UltraHonkZKProof ABI. Use for both direct L2
   *   submission (submit_batch) and pair_wrapper aggregation.
   * - "noir-rollup": produces 519-field RollupHonk proofs with IPA material.
   *   NOT recommended — the contract ABI declares [Field; 500] and the SDK
   *   silently truncates the extra 19 fields. See SILENT_FAILURE_REVIEW.md.
   */
  wrapperTarget?: "noir-rollup" | "noir-recursive";
}

export async function buildBatchProofRecursive(
  api: Barretenberg,
  state: TestL3State,
  realSlots: TxProofResult[],
  options: BuildRecursiveOptions = {},
): Promise<BatchArtifact> {
  const wrapperTarget = options.wrapperTarget ?? "noir-recursive";
  if (realSlots.length > MAX_BATCH_SIZE) throw new Error("too many slots");

  const oldStateRoot = state.stateRoot;
  const nullStartIdx = new Fr(BigInt(state.nullifierTreeStartIndex));
  const nhStartIdx = new Fr(BigInt(state.noteHashTreeStartIndex));
  const oldNullRoot = state.nullifierTree.root();
  const oldNhRoot = state.noteHashTree.root();

  // 1. Order and pad.
  const deposits = realSlots.filter((x) => x.type === "deposit");
  const payments = realSlots.filter((x) => x.type === "payment");
  const withdrawals = realSlots.filter((x) => x.type === "withdraw");
  const ordered = [...deposits, ...payments, ...withdrawals];
  const paddingCount = MAX_BATCH_SIZE - ordered.length;
  const paddingProof = await provePadding(api);
  const slots: TxProofResult[] = [...ordered, ...Array.from({ length: paddingCount }, () => paddingProof)];

  // 2. Apply state transitions, collect insertion witnesses.
  const zeroLeafSer = serLeaf({ value: Fr.ZERO, nextIndex: Fr.ZERO, nextValue: Fr.ZERO });
  const nullLowLeaves: any[] = new Array(BATCH_NULLIFIERS_COUNT).fill(null).map(() => ({ ...zeroLeafSer }));
  const nullLowLeafIndices: string[] = new Array(BATCH_NULLIFIERS_COUNT).fill("0");
  const nullLowLeafSibs: string[][] = new Array(BATCH_NULLIFIERS_COUNT).fill(null).map(() => zeroSibs());
  const nullNewLeafSibs: string[][] = new Array(BATCH_NULLIFIERS_COUNT).fill(null).map(() => zeroSibs());
  const nhInsertSibs: string[][] = new Array(BATCH_NOTE_HASHES_COUNT).fill(null).map(() => zeroSibs());
  const noteInsertionIndices: number[][] = slots.map(() => [-1, -1]);

  for (let i = 0; i < MAX_BATCH_SIZE; i++) {
    const slot = slots[i];
    if (slot.type === "padding") continue;

    for (let j = 0; j < MAX_NOTES_PER_TX; j++) {
      const idx = i * MAX_NOTES_PER_TX + j;
      const nullVal = slot.nullifiers[j];
      if (!nullVal.equals(Fr.ZERO)) {
        const w = await state.insertNullifier(nullVal);
        nullLowLeaves[idx] = serLeaf(w.lowLeaf);
        nullLowLeafIndices[idx] = w.lowLeafIndex.toString();
        nullLowLeafSibs[idx] = fs2s(w.lowLeafSiblings);
        nullNewLeafSibs[idx] = fs2s(w.newLeafSiblings);
      } else {
        nullLowLeaves[idx] = serLeaf({ value: Fr.ZERO, nextIndex: Fr.ZERO, nextValue: Fr.ZERO });
      }
    }

    for (let j = 0; j < MAX_OUTPUTS_PER_TX; j++) {
      const idx = i * MAX_OUTPUTS_PER_TX + j;
      const nhVal = slot.noteHashes[j];
      if (!nhVal.equals(Fr.ZERO)) {
        const nhIdx = state.noteHashTree.size;
        nhInsertSibs[idx] = fs2s(state.noteHashTree.siblings(nhIdx));
        await state.noteHashTree.insert(nhVal);
        noteInsertionIndices[i][j] = nhIdx;
      }
    }

    if (slot.type === "deposit") state.pendingDeposits.delete(slot.nullifiers[0].toString());
    if (slot.type === "withdraw") state.pendingWithdrawals.add(slot.noteHashes[0].toString());
  }

  await state.syncStateRoot();
  const newNullRoot = state.nullifierTree.root();
  const newNhRoot = state.noteHashTree.root();
  const newStateRoot = state.stateRoot;

  const settleEntries = slots.map((sl) => ({
    type: sl.type as any, nullifiers: sl.nullifiers, noteHashes: sl.noteHashes,
  }));
  const settleInputs = await state.buildSettleInputs(settleEntries, RECURSIVE_BATCH_SIZING);

  // 3. Execute batch_app_standalone (UltraHonk-compatible, no databus).
  console.log("    Executing batch_app_standalone...");
  const batchAppCircuit = loadCircuit("batch_app_standalone");
  const batchNoir = new Noir(batchAppCircuit);

  const depositVkBytes = deposits.length > 0 ? deposits[0].vk : paddingProof.vk;
  const paymentVkBytes = payments.length > 0 ? payments[0].vk : paddingProof.vk;
  const withdrawVkBytes = withdrawals.length > 0 ? withdrawals[0].vk : paddingProof.vk;
  const paddVkBytes = paddingProof.vk;

  const vkHashStr = async (vk: Uint8Array) => f2s(await p2h(vkToFields(vk)));

  const { witness: batchWitness } = await batchNoir.execute({
    deposit_vk: bytesToFieldStrings(depositVkBytes, VK_FIELDS),
    deposit_vk_hash: await vkHashStr(depositVkBytes),
    payment_vk: bytesToFieldStrings(paymentVkBytes, VK_FIELDS),
    payment_vk_hash: await vkHashStr(paymentVkBytes),
    withdraw_vk: bytesToFieldStrings(withdrawVkBytes, VK_FIELDS),
    withdraw_vk_hash: await vkHashStr(withdrawVkBytes),
    padding_vk: bytesToFieldStrings(paddVkBytes, VK_FIELDS),
    padding_vk_hash: await vkHashStr(paddVkBytes),
    deposit_count: deposits.length.toString(),
    payment_count: payments.length.toString(),
    withdraw_count: withdrawals.length.toString(),
    tx_proofs: slots.map((sl) => bytesToFieldStrings(sl.proof, PROOF_FIELDS)),
    tx_public_inputs: slots.map((sl) => sl.publicInputs),
    old_nullifier_tree_root: f2s(oldNullRoot),
    old_note_hash_tree_root: f2s(oldNhRoot),
    new_nullifier_tree_root: f2s(newNullRoot),
    new_note_hash_tree_root: f2s(newNhRoot),
    nullifier_low_leaves: nullLowLeaves,
    nullifier_low_leaf_indices: nullLowLeafIndices,
    nullifier_low_leaf_siblings: nullLowLeafSibs,
    nullifier_new_leaf_siblings: nullNewLeafSibs,
    note_hash_insertion_siblings: nhInsertSibs,
    old_state_root: f2s(oldStateRoot),
    new_state_root: f2s(newStateRoot),
    nullifiers_batch_hash: f2s(settleInputs.nullifiersBatchHash),
    note_hashes_batch_hash: f2s(settleInputs.noteHashesBatchHash),
    deposit_nullifiers_hash: f2s(settleInputs.depositNullifiersHash),
    withdrawal_claims_hash: f2s(settleInputs.withdrawalClaimsHash),
    nullifier_tree_start_index: f2s(nullStartIdx),
    note_hash_tree_start_index: f2s(nhStartIdx),
  });
  console.log("    batch_app_standalone executed");

  // --- RECURSIVE PATH: no IVC, no Chonk ---

  // 4. Prove batch_app_standalone as UltraHonk.
  console.log("    Proving batch_app_standalone (UltraHonk, noir-recursive)...");
  const batchAppBackend = new UltraHonkBackend(batchAppCircuit.bytecode, api);
  const batchAppProofData = await batchAppBackend.generateProof(batchWitness, { verifierTarget: "noir-recursive" });
  const batchAppVk = await batchAppBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  console.log(`    batch_app proof: ${batchAppProofData.proof.length} bytes, ${batchAppProofData.publicInputs.length} public inputs`);

  // 5. Execute wrapper circuit.
  console.log("    Executing wrapper...");
  const wrapperCircuit = loadCircuit("wrapper");
  const wrapperNoir = new Noir(wrapperCircuit);

  const batchAppVkFields = vkToFields(batchAppVk);
  const batchAppVkHash = await p2h(batchAppVkFields);

  const { witness: wrapperWitness } = await wrapperNoir.execute({
    batch_app_vk: bytesToFieldStrings(batchAppVk, VK_FIELDS),
    batch_app_proof: bytesToFieldStrings(batchAppProofData.proof, PROOF_FIELDS),
    batch_app_public_inputs: batchAppProofData.publicInputs,
    batch_app_vk_hash: f2s(batchAppVkHash),
    old_state_root: batchAppProofData.publicInputs[0],
    new_state_root: batchAppProofData.publicInputs[1],
    nullifiers_batch_hash: batchAppProofData.publicInputs[2],
    note_hashes_batch_hash: batchAppProofData.publicInputs[3],
    deposit_nullifiers_hash: batchAppProofData.publicInputs[4],
    withdrawal_claims_hash: batchAppProofData.publicInputs[5],
    nullifier_tree_start_index: batchAppProofData.publicInputs[6],
    note_hash_tree_start_index: batchAppProofData.publicInputs[7],
  });
  console.log("    wrapper executed");

  // 6. Prove wrapper as UltraHonk targeted according to caller preference.
  //    - noir-rollup: direct L2 verification via submit_batch.
  //    - noir-recursive: consumed by pair_wrapper for proof aggregation.
  console.log(`    Proving wrapper (UltraHonk, ${wrapperTarget})...`);
  const wrapperBackend = new UltraHonkBackend(wrapperCircuit.bytecode, api);
  const wrapperProofData = await wrapperBackend.generateProof(wrapperWitness, { verifierTarget: wrapperTarget });
  const wrapperVk = await wrapperBackend.getVerificationKey({ verifierTarget: wrapperTarget });
  console.log(`    wrapper proof: ${wrapperProofData.proof.length} bytes`);

  // 7. Verify locally.
  const wrapperValid = await wrapperBackend.verifyProof(wrapperProofData, { verifierTarget: wrapperTarget });
  console.log(`    wrapper verified: ${wrapperValid}`);

  // Return same BatchArtifact shape -- tubeProof/tubeVk are the wrapper equivalents.
  return {
    slots,
    depositCount: deposits.length,
    paymentCount: payments.length,
    withdrawCount: withdrawals.length,
    paddingCount,
    settleInputs,
    oldStateRoot,
    newStateRoot,
    nullifierTreeStartIndex: nullStartIdx,
    noteHashTreeStartIndex: nhStartIdx,
    noteInsertionIndices,
    tubeProof: wrapperProofData.proof,
    tubeVk: wrapperVk,
    tubePublicInputs: batchAppProofData.publicInputs.map((x: string) => new Fr(BigInt(x))),
  };
}

// -------------------------------------------------------------------------
// Compute wrapper VK hash without running the full pipeline.
// -------------------------------------------------------------------------

export async function computeWrapperVkHash(api: Barretenberg): Promise<{ vkHash: Fr; vk: Uint8Array }> {
  const wrapperCircuit = loadCircuit("wrapper");
  const wrapperBackend = new UltraHonkBackend(wrapperCircuit.bytecode, api);
  const vk = await wrapperBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const vkFields = vkToFields(vk);
  const vkHash = await p2h(vkFields);
  return { vkHash, vk };
}

// -------------------------------------------------------------------------
// Compute pair_wrapper VK hash.
//
// Two wrapper verification targets are relevant to pair_wrapper:
//   - The wrapper VK pair_wrapper verifies internally must be the "noir-recursive"
//     wrapper VK (the one used to recursively verify inside another circuit).
//   - The pair_wrapper's OWN proof is "noir-rollup"-targeted (L2-verifiable).
// -------------------------------------------------------------------------

export async function computePairWrapperVkHash(api: Barretenberg): Promise<{ vkHash: Fr; vk: Uint8Array }> {
  const circuit = loadCircuit("pair_wrapper");
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  const vk = await backend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const vkFields = vkToFields(vk);
  const vkHash = await p2h(vkFields);
  return { vkHash, vk };
}

// -------------------------------------------------------------------------
// buildPairWrapperProof
//
// Takes two BatchArtifacts produced by buildBatchProofRecursive (A then B,
// where B's oldStateRoot == A's newStateRoot), runs the pair_wrapper circuit
// to recursively verify both wrapper proofs and merge their settle data,
// returns a single noir-rollup-targeted UltraHonk proof plus its VK and the
// merged 8-field public inputs suitable for the L2 submit_merged_batch call.
// -------------------------------------------------------------------------

export interface PairWrapperArtifact {
  pairProof: Uint8Array;
  pairVk: Uint8Array;
  mergedPublicInputs: string[]; // 8 fields -- BatchOutput shape, merged
  // Concatenated settle arrays (ready to pass to submit_merged_batch):
  mergedNullifiers: Fr[];       // 32 fields
  mergedNoteHashes: Fr[];       // 32 fields
  mergedDeposits: Fr[];         // 16 fields
  mergedWithdrawals: Fr[];      // 16 fields
}

export async function buildPairWrapperProof(
  api: Barretenberg,
  artifactA: BatchArtifact,
  artifactB: BatchArtifact,
): Promise<PairWrapperArtifact> {
  // 1. Sanity: both batches must share the same wrapper VK.
  //    Caller must have produced both artifacts with wrapperTarget="noir-recursive"
  //    via buildBatchProofRecursive (otherwise pair_wrapper's inner verify_honk_proof
  //    won't accept them).
  if (artifactA.tubeVk.length !== artifactB.tubeVk.length) {
    throw new Error("buildPairWrapperProof: wrapper VK byte lengths differ");
  }
  for (let i = 0; i < artifactA.tubeVk.length; i++) {
    if (artifactA.tubeVk[i] !== artifactB.tubeVk[i]) {
      throw new Error("buildPairWrapperProof: wrapper VKs differ at byte " + i);
    }
  }

  // 2. Sanity: state-root chain.
  if (artifactA.newStateRoot.toBigInt() !== artifactB.oldStateRoot.toBigInt()) {
    throw new Error(
      `buildPairWrapperProof: state chain broken: A.new=${artifactA.newStateRoot} B.old=${artifactB.oldStateRoot}`,
    );
  }

  // 3. Merge settle arrays (A then B).
  const mergedNullifiers = [
    ...artifactA.settleInputs.nullifiers,
    ...artifactB.settleInputs.nullifiers,
  ];
  const mergedNoteHashes = [
    ...artifactA.settleInputs.noteHashes,
    ...artifactB.settleInputs.noteHashes,
  ];
  const mergedDeposits = [
    ...artifactA.settleInputs.depositNullifiers,
    ...artifactB.settleInputs.depositNullifiers,
  ];
  const mergedWithdrawals = [
    ...artifactA.settleInputs.withdrawalClaims,
    ...artifactB.settleInputs.withdrawalClaims,
  ];

  // 4. Hashes of merged arrays (match pair_wrapper's in-circuit poseidon2).
  const mergedNullifiersHash = await p2h(mergedNullifiers);
  const mergedNoteHashesHash = await p2h(mergedNoteHashes);
  const mergedDepositsHash = await p2h(mergedDeposits);
  const mergedWithdrawalsHash = await p2h(mergedWithdrawals);

  // 5. Wrapper VK hash (the VK that pair_wrapper's verify_honk_proof checks against).
  //    artifactA.tubeVk is the wrapper VK produced at noir-recursive target.
  const wrapperVkFields = vkToFields(artifactA.tubeVk);
  const wrapperVkHash = await p2h(wrapperVkFields);

  // 6. Execute pair_wrapper circuit.
  console.log("    Executing pair_wrapper...");
  const pairCircuit = loadCircuit("pair_wrapper");
  const pairNoir = new Noir(pairCircuit);

  const { witness: pairWitness } = await pairNoir.execute({
    wrapper_vk: bytesToFieldStrings(artifactA.tubeVk, VK_FIELDS),
    wrapper_vk_hash: f2s(wrapperVkHash),

    wrapper_proof_a: bytesToFieldStrings(artifactA.tubeProof, PROOF_FIELDS),
    wrapper_public_inputs_a: artifactA.tubePublicInputs.map(f2s),

    wrapper_proof_b: bytesToFieldStrings(artifactB.tubeProof, PROOF_FIELDS),
    wrapper_public_inputs_b: artifactB.tubePublicInputs.map(f2s),

    nullifiers_a: artifactA.settleInputs.nullifiers.map(f2s),
    note_hashes_a: artifactA.settleInputs.noteHashes.map(f2s),
    deposits_a: artifactA.settleInputs.depositNullifiers.map(f2s),
    withdrawals_a: artifactA.settleInputs.withdrawalClaims.map(f2s),

    nullifiers_b: artifactB.settleInputs.nullifiers.map(f2s),
    note_hashes_b: artifactB.settleInputs.noteHashes.map(f2s),
    deposits_b: artifactB.settleInputs.depositNullifiers.map(f2s),
    withdrawals_b: artifactB.settleInputs.withdrawalClaims.map(f2s),

    old_state_root: f2s(artifactA.oldStateRoot),
    new_state_root: f2s(artifactB.newStateRoot),
    merged_nullifiers_hash: f2s(mergedNullifiersHash),
    merged_note_hashes_hash: f2s(mergedNoteHashesHash),
    merged_deposit_nullifiers_hash: f2s(mergedDepositsHash),
    merged_withdrawal_claims_hash: f2s(mergedWithdrawalsHash),
    nullifier_tree_start_index: f2s(artifactA.nullifierTreeStartIndex),
    note_hash_tree_start_index: f2s(artifactA.noteHashTreeStartIndex),
  });
  console.log("    pair_wrapper executed");

  // 7. Prove pair_wrapper at noir-recursive target for L2 submission.
  //    This produces 500-field UltraHonkZK proofs matching the contract's ABI.
  //    (noir-rollup would produce 519-field RollupHonk proofs that the SDK
  //    silently truncates — see SILENT_FAILURE_REVIEW.md.)
  console.log("    Proving pair_wrapper (UltraHonk, noir-recursive)...");
  const pairBackend = new UltraHonkBackend(pairCircuit.bytecode, api);
  const pairProofData = await pairBackend.generateProof(pairWitness, { verifierTarget: "noir-recursive" });
  const pairVk = await pairBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  console.log(`    pair_wrapper proof: ${pairProofData.proof.length} bytes`);

  const pairValid = await pairBackend.verifyProof(pairProofData, { verifierTarget: "noir-recursive" });
  console.log(`    pair_wrapper verified: ${pairValid}`);

  return {
    pairProof: pairProofData.proof,
    pairVk,
    mergedPublicInputs: pairProofData.publicInputs,
    mergedNullifiers,
    mergedNoteHashes,
    mergedDeposits,
    mergedWithdrawals,
  };
}

// Re-export tx provers for the test to use directly.
export { proveDeposit, provePayment, proveWithdraw, provePadding };
export type { TxProofResult, BatchArtifact };
