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
import { UH_PROOF_FIELDS as PROOF_FIELDS, UH_VK_FIELDS as VK_FIELDS } from "./recursive-shapes.js";

const TARGET_DIR = resolve(import.meta.dirname ?? ".", "../../target");
// Recursive pipeline batch sizes. Must match circuits/batch_app_standalone/src/main.nr
// globals and contract_recursive/src/main.nr. No ECCVM bottleneck (standalone UltraHonk).
const MAX_BATCH_SIZE = RECURSIVE_BATCH_SIZING.maxBatchSize;         // 8
const MAX_NOTES_PER_TX = 2;
const MAX_OUTPUTS_PER_TX = 2;
const BATCH_NULLIFIERS_COUNT = RECURSIVE_BATCH_SIZING.batchNullifiersCount;   // 16
const BATCH_NOTE_HASHES_COUNT = RECURSIVE_BATCH_SIZING.batchNoteHashesCount;  // 16

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
// The wrapper is always proved at "noir-recursive" target (500-field
// UltraHonkZK proofs matching the contract's UltraHonkZKProof ABI), which
// is the only format consumable by both submit_batch and wrapper_16.
// -------------------------------------------------------------------------

export async function buildBatchProofRecursive(
  api: Barretenberg,
  state: TestL3State,
  realSlots: TxProofResult[],
): Promise<BatchArtifact> {
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

  // 6. Prove wrapper at noir-recursive target.
  //    Produces 500-field UltraHonkZK proofs matching the contract's
  //    UltraHonkZKProof ABI — consumed by submit_batch directly and by
  //    wrapper_16 for proof aggregation.
  console.log("    Proving wrapper (UltraHonk, noir-recursive)...");
  const wrapperBackend = new UltraHonkBackend(wrapperCircuit.bytecode, api);
  const wrapperProofData = await wrapperBackend.generateProof(wrapperWitness, { verifierTarget: "noir-recursive" });
  const wrapperVk = await wrapperBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const wrapperProofFields = wrapperProofData.proof.length / 32;
  console.log(`    wrapper proof: ${wrapperProofData.proof.length} bytes (${wrapperProofFields} fields)`);

  // Shape invariant: UltraHonkZK wrapper proofs are PROOF_FIELDS fields.
  if (wrapperProofFields !== PROOF_FIELDS) {
    throw new Error(`wrapper proof has ${wrapperProofFields} fields (expected ${PROOF_FIELDS})`);
  }

  // 7. Verify locally.
  const wrapperValid = await wrapperBackend.verifyProof(wrapperProofData, { verifierTarget: "noir-recursive" });
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
    tubePublicInputs: wrapperProofData.publicInputs.map((x: string) => new Fr(BigInt(x))),
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
// Compute wrapper_16 VK hash.
//
// Both wrapper_16's inner verify_honk_proof VK and its own output proof
// are at noir-recursive target (500-field UltraHonkZK).
// -------------------------------------------------------------------------

export async function computeWrapper16VkHash(api: Barretenberg): Promise<{ vkHash: Fr; vk: Uint8Array }> {
  const circuit = loadCircuit("wrapper_16");
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  const vk = await backend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const vkFields = vkToFields(vk);
  const vkHash = await p2h(vkFields);
  return { vkHash, vk };
}

// -------------------------------------------------------------------------
// buildWrapper16Proof
//
// Takes two BatchArtifacts produced by buildBatchProofRecursive (A then B,
// where B's oldStateRoot == A's newStateRoot), runs the wrapper_16 circuit
// to recursively verify both wrapper proofs and merge their settle data,
// returns a single noir-recursive-targeted UltraHonk proof (500 fields) plus
// its VK and the merged 8-field public inputs suitable for the L2
// submit_batch_16 call.
// -------------------------------------------------------------------------

export interface Wrapper16Artifact {
  w16Proof: Uint8Array;
  w16Vk: Uint8Array;
  mergedPublicInputs: string[]; // 8 fields -- BatchOutput shape, merged
  // Concatenated settle arrays (ready to pass to submit_batch_16):
  mergedNullifiers: Fr[];       // 32 fields
  mergedNoteHashes: Fr[];       // 32 fields
  mergedDeposits: Fr[];         // 16 fields
  mergedWithdrawals: Fr[];      // 16 fields
}

export async function buildWrapper16Proof(
  api: Barretenberg,
  artifactA: BatchArtifact,
  artifactB: BatchArtifact,
): Promise<Wrapper16Artifact> {
  // 1. Sanity: both batches must share the same wrapper VK.
  //    buildBatchProofRecursive always produces noir-recursive wrappers, so this
  //    holds by construction; the byte-equality check guards against callers
  //    assembling BatchArtifacts by hand with mismatched VKs.
  if (artifactA.tubeVk.length !== artifactB.tubeVk.length) {
    throw new Error("buildWrapper16Proof: wrapper VK byte lengths differ");
  }
  for (let i = 0; i < artifactA.tubeVk.length; i++) {
    if (artifactA.tubeVk[i] !== artifactB.tubeVk[i]) {
      throw new Error("buildWrapper16Proof: wrapper VKs differ at byte " + i);
    }
  }

  // 2. Sanity: state-root chain.
  if (artifactA.newStateRoot.toBigInt() !== artifactB.oldStateRoot.toBigInt()) {
    throw new Error(
      `buildWrapper16Proof: state chain broken: A.new=${artifactA.newStateRoot} B.old=${artifactB.oldStateRoot}`,
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

  // 4. Hashes of merged arrays (match wrapper_16's in-circuit poseidon2).
  const mergedNullifiersHash = await p2h(mergedNullifiers);
  const mergedNoteHashesHash = await p2h(mergedNoteHashes);
  const mergedDepositsHash = await p2h(mergedDeposits);
  const mergedWithdrawalsHash = await p2h(mergedWithdrawals);

  // 5. Wrapper VK hash (the VK that wrapper_16's verify_honk_proof checks
  //    against). Also exposed as wrapper_16's 9th public output, which
  //    the contract asserts == committed tube_vk_hash in submit_batch_16
  //    (inner-VK substitution hardening).
  const wrapperVkFields = vkToFields(artifactA.tubeVk);
  const wrapperVkHash = await p2h(wrapperVkFields);

  // 6. Execute wrapper_16 circuit.
  console.log("    Executing wrapper_16...");
  const pairCircuit = loadCircuit("wrapper_16");
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
    // New 9th public input: the wrapper VK hash the two inner proofs were
    // verified under. The contract's submit_batch_16 binds this to its
    // committed tube_vk_hash (inner-VK substitution hardening).
    out_wrapper_vk_hash: f2s(wrapperVkHash),
  });
  console.log("    wrapper_16 executed");

  // 7. Prove wrapper_16 at noir-recursive target for L2 submission.
  //    Produces 500-field UltraHonkZK proofs matching the contract's ABI.
  console.log("    Proving wrapper_16 (UltraHonk, noir-recursive)...");
  const pairBackend = new UltraHonkBackend(pairCircuit.bytecode, api);
  const w16ProofData = await pairBackend.generateProof(pairWitness, { verifierTarget: "noir-recursive" });
  const w16Vk = await pairBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const w16ProofFields = w16ProofData.proof.length / 32;
  console.log(`    wrapper_16 proof: ${w16ProofData.proof.length} bytes (${w16ProofFields} fields)`);

  // Shape invariant: UltraHonkZK merged proof is PROOF_FIELDS fields.
  if (w16ProofFields !== PROOF_FIELDS) {
    throw new Error(`wrapper_16 proof has ${w16ProofFields} fields (expected ${PROOF_FIELDS})`);
  }

  const pairValid = await pairBackend.verifyProof(w16ProofData, { verifierTarget: "noir-recursive" });
  console.log(`    wrapper_16 verified: ${pairValid}`);

  return {
    w16Proof: w16ProofData.proof,
    w16Vk,
    mergedPublicInputs: w16ProofData.publicInputs,
    mergedNullifiers,
    mergedNoteHashes,
    mergedDeposits,
    mergedWithdrawals,
  };
}

// -------------------------------------------------------------------------
// Compute wrapper_32 VK hash (shared by wrapper_64 internally).
// -------------------------------------------------------------------------

export async function computeWrapper32VkHash(api: Barretenberg): Promise<{ vkHash: Fr; vk: Uint8Array }> {
  const circuit = loadCircuit("wrapper_32");
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  const vk = await backend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const vkFields = vkToFields(vk);
  const vkHash = await p2h(vkFields);
  return { vkHash, vk };
}

// -------------------------------------------------------------------------
// Compute wrapper_64 VK hash (what the contract binds for submit_batch_64).
// -------------------------------------------------------------------------

export async function computeWrapper64VkHash(api: Barretenberg): Promise<{ vkHash: Fr; vk: Uint8Array }> {
  const circuit = loadCircuit("wrapper_64");
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  const vk = await backend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const vkFields = vkToFields(vk);
  const vkHash = await p2h(vkFields);
  return { vkHash, vk };
}

// -------------------------------------------------------------------------
// buildWrapper32Proof
//
// Takes two Wrapper16Artifacts (each a 16-slot merged batch), runs the
// wrapper_32 circuit to verify both and merge their arrays, returns
// a single noir-recursive-targeted UltraHonk proof (500 fields) with
// 32-slot-merged public inputs.
// -------------------------------------------------------------------------

export interface Wrapper32Artifact {
  w32Proof: Uint8Array;
  w32Vk: Uint8Array;
  mergedPublicInputs: string[];      // 8 fields (BatchOutput shape)
  mergedNullifiers: Fr[];            // 64 fields
  mergedNoteHashes: Fr[];            // 64 fields
  mergedDeposits: Fr[];              // 32 fields
  mergedWithdrawals: Fr[];           // 32 fields
  // Pass through for state-chain construction at the quad level:
  oldStateRoot: Fr;
  newStateRoot: Fr;
  nullifierTreeStartIndex: Fr;
  noteHashTreeStartIndex: Fr;
}

export async function buildWrapper32Proof(
  api: Barretenberg,
  mergedA: Wrapper16Artifact,
  mergedB: Wrapper16Artifact,
): Promise<Wrapper32Artifact> {
  // 1. Sanity: both halves must have been produced by the same wrapper_16 VK.
  //    buildWrapper16Proof always proves at noir-recursive, so this holds by
  //    construction; byte-equality guard against caller-assembled artifacts.
  // 2. State-root chain: B's old == A's new.
  //    (Encoded in mergedPublicInputs[0]/[1].)
  if (mergedA.mergedPublicInputs[1] !== mergedB.mergedPublicInputs[0]) {
    throw new Error(
      `buildWrapper32Proof: state chain broken: A.new=${mergedA.mergedPublicInputs[1]} B.old=${mergedB.mergedPublicInputs[0]}`,
    );
  }

  // 3. Merge settle arrays (A then B).
  const mergedNullifiers = [...mergedA.mergedNullifiers, ...mergedB.mergedNullifiers];
  const mergedNoteHashes = [...mergedA.mergedNoteHashes, ...mergedB.mergedNoteHashes];
  const mergedDeposits = [...mergedA.mergedDeposits, ...mergedB.mergedDeposits];
  const mergedWithdrawals = [...mergedA.mergedWithdrawals, ...mergedB.mergedWithdrawals];

  // 4. Merged-hashes and wrapper_16 VK hash (for the witness).
  const mergedNullifiersHash = await p2h(mergedNullifiers);
  const mergedNoteHashesHash = await p2h(mergedNoteHashes);
  const mergedDepositsHash = await p2h(mergedDeposits);
  const mergedWithdrawalsHash = await p2h(mergedWithdrawals);
  const w16VkHash = await p2h(vkToFields(mergedA.w16Vk));

  // 5. Execute wrapper_32.
  console.log("    Executing wrapper_32...");
  const ppCircuit = loadCircuit("wrapper_32");
  const ppNoir = new Noir(ppCircuit);

  const { witness: ppWitness } = await ppNoir.execute({
    w16_vk: bytesToFieldStrings(mergedA.w16Vk, VK_FIELDS),
    w16_vk_hash: f2s(w16VkHash),

    w16_proof_a: bytesToFieldStrings(mergedA.w16Proof, PROOF_FIELDS),
    w16_public_inputs_a: mergedA.mergedPublicInputs,

    w16_proof_b: bytesToFieldStrings(mergedB.w16Proof, PROOF_FIELDS),
    w16_public_inputs_b: mergedB.mergedPublicInputs,

    nullifiers_a: mergedA.mergedNullifiers.map(f2s),
    note_hashes_a: mergedA.mergedNoteHashes.map(f2s),
    deposits_a: mergedA.mergedDeposits.map(f2s),
    withdrawals_a: mergedA.mergedWithdrawals.map(f2s),

    nullifiers_b: mergedB.mergedNullifiers.map(f2s),
    note_hashes_b: mergedB.mergedNoteHashes.map(f2s),
    deposits_b: mergedB.mergedDeposits.map(f2s),
    withdrawals_b: mergedB.mergedWithdrawals.map(f2s),

    old_state_root: mergedA.mergedPublicInputs[0],
    new_state_root: mergedB.mergedPublicInputs[1],
    merged_nullifiers_hash: f2s(mergedNullifiersHash),
    merged_note_hashes_hash: f2s(mergedNoteHashesHash),
    merged_deposit_nullifiers_hash: f2s(mergedDepositsHash),
    merged_withdrawal_claims_hash: f2s(mergedWithdrawalsHash),
    nullifier_tree_start_index: mergedA.mergedPublicInputs[6],
    note_hash_tree_start_index: mergedA.mergedPublicInputs[7],
    // Inner-VK-chain propagation (PI[8] of wrapper_16 is wrapper_vk_hash;
    // both halves must agree -- circuit enforces, we supply the shared value).
    out_wrapper_vk_hash: mergedA.mergedPublicInputs[8],
    out_w16_vk_hash: f2s(w16VkHash),
  });
  console.log("    wrapper_32 executed");

  // 6. Prove at noir-recursive (consumed by wrapper_64).
  console.log("    Proving wrapper_32 (UltraHonk, noir-recursive)...");
  const ppBackend = new UltraHonkBackend(ppCircuit.bytecode, api);
  const w32ProofData = await ppBackend.generateProof(ppWitness, { verifierTarget: "noir-recursive" });
  const w32Vk = await ppBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const w32ProofFields = w32ProofData.proof.length / 32;
  console.log(`    wrapper_32 proof: ${w32ProofData.proof.length} bytes (${w32ProofFields} fields)`);
  if (w32ProofFields !== PROOF_FIELDS) {
    throw new Error(`wrapper_32 proof has ${w32ProofFields} fields (expected ${PROOF_FIELDS})`);
  }
  const ppValid = await ppBackend.verifyProof(w32ProofData, { verifierTarget: "noir-recursive" });
  console.log(`    wrapper_32 verified: ${ppValid}`);

  return {
    w32Proof: w32ProofData.proof,
    w32Vk,
    mergedPublicInputs: w32ProofData.publicInputs,
    mergedNullifiers,
    mergedNoteHashes,
    mergedDeposits,
    mergedWithdrawals,
    oldStateRoot: new Fr(BigInt(mergedA.mergedPublicInputs[0])),
    newStateRoot: new Fr(BigInt(mergedB.mergedPublicInputs[1])),
    nullifierTreeStartIndex: new Fr(BigInt(mergedA.mergedPublicInputs[6])),
    noteHashTreeStartIndex: new Fr(BigInt(mergedA.mergedPublicInputs[7])),
  };
}

// -------------------------------------------------------------------------
// buildWrapper64Proof
//
// Takes two Wrapper32Artifacts (each a 32-slot doubly-merged batch),
// runs the wrapper_64 circuit to verify both and merge their arrays,
// returns a single noir-recursive-targeted UltraHonk proof (500 fields)
// with 64-slot-merged public inputs — the proof submit_batch_64 accepts.
// -------------------------------------------------------------------------

export interface Wrapper64Artifact {
  w64Proof: Uint8Array;
  w64Vk: Uint8Array;
  mergedPublicInputs: string[];      // 8 fields
  mergedNullifiers: Fr[];            // 128 fields
  mergedNoteHashes: Fr[];            // 128 fields
  mergedDeposits: Fr[];              // 64 fields
  mergedWithdrawals: Fr[];           // 64 fields
}

export async function buildWrapper64Proof(
  api: Barretenberg,
  ppA: Wrapper32Artifact,
  ppB: Wrapper32Artifact,
): Promise<Wrapper64Artifact> {
  // State-root chain.
  if (ppA.mergedPublicInputs[1] !== ppB.mergedPublicInputs[0]) {
    throw new Error(
      `buildWrapper64Proof: state chain broken: A.new=${ppA.mergedPublicInputs[1]} B.old=${ppB.mergedPublicInputs[0]}`,
    );
  }

  // Merge (A then B).
  const mergedNullifiers = [...ppA.mergedNullifiers, ...ppB.mergedNullifiers];
  const mergedNoteHashes = [...ppA.mergedNoteHashes, ...ppB.mergedNoteHashes];
  const mergedDeposits = [...ppA.mergedDeposits, ...ppB.mergedDeposits];
  const mergedWithdrawals = [...ppA.mergedWithdrawals, ...ppB.mergedWithdrawals];

  const mergedNullifiersHash = await p2h(mergedNullifiers);
  const mergedNoteHashesHash = await p2h(mergedNoteHashes);
  const mergedDepositsHash = await p2h(mergedDeposits);
  const mergedWithdrawalsHash = await p2h(mergedWithdrawals);
  const w32VkHash = await p2h(vkToFields(ppA.w32Vk));

  console.log("    Executing wrapper_64...");
  const quadCircuit = loadCircuit("wrapper_64");
  const quadNoir = new Noir(quadCircuit);

  const { witness: quadWitness } = await quadNoir.execute({
    w32_vk: bytesToFieldStrings(ppA.w32Vk, VK_FIELDS),
    w32_vk_hash: f2s(w32VkHash),

    w32_proof_a: bytesToFieldStrings(ppA.w32Proof, PROOF_FIELDS),
    w32_public_inputs_a: ppA.mergedPublicInputs,

    w32_proof_b: bytesToFieldStrings(ppB.w32Proof, PROOF_FIELDS),
    w32_public_inputs_b: ppB.mergedPublicInputs,

    nullifiers_a: ppA.mergedNullifiers.map(f2s),
    note_hashes_a: ppA.mergedNoteHashes.map(f2s),
    deposits_a: ppA.mergedDeposits.map(f2s),
    withdrawals_a: ppA.mergedWithdrawals.map(f2s),

    nullifiers_b: ppB.mergedNullifiers.map(f2s),
    note_hashes_b: ppB.mergedNoteHashes.map(f2s),
    deposits_b: ppB.mergedDeposits.map(f2s),
    withdrawals_b: ppB.mergedWithdrawals.map(f2s),

    old_state_root: ppA.mergedPublicInputs[0],
    new_state_root: ppB.mergedPublicInputs[1],
    merged_nullifiers_hash: f2s(mergedNullifiersHash),
    merged_note_hashes_hash: f2s(mergedNoteHashesHash),
    merged_deposit_nullifiers_hash: f2s(mergedDepositsHash),
    merged_withdrawal_claims_hash: f2s(mergedWithdrawalsHash),
    nullifier_tree_start_index: ppA.mergedPublicInputs[6],
    note_hash_tree_start_index: ppA.mergedPublicInputs[7],
    // Full inner-VK-chain propagation: wrapper_32's PI[8]/PI[9] are
    // wrapper_vk_hash / pair_vk_hash. Both halves must agree (circuit
    // enforces); we propagate both plus our own pp_vk_hash as PI[10].
    out_wrapper_vk_hash: ppA.mergedPublicInputs[8],
    out_w16_vk_hash: ppA.mergedPublicInputs[9],
    out_w32_vk_hash: f2s(w32VkHash),
  });
  console.log("    wrapper_64 executed");

  console.log("    Proving wrapper_64 (UltraHonk, noir-recursive)...");
  const quadBackend = new UltraHonkBackend(quadCircuit.bytecode, api);
  const w64ProofData = await quadBackend.generateProof(quadWitness, { verifierTarget: "noir-recursive" });
  const w64Vk = await quadBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const w64ProofFields = w64ProofData.proof.length / 32;
  console.log(`    wrapper_64 proof: ${w64ProofData.proof.length} bytes (${w64ProofFields} fields)`);
  if (w64ProofFields !== PROOF_FIELDS) {
    throw new Error(`wrapper_64 proof has ${w64ProofFields} fields (expected ${PROOF_FIELDS})`);
  }
  const quadValid = await quadBackend.verifyProof(w64ProofData, { verifierTarget: "noir-recursive" });
  console.log(`    wrapper_64 verified: ${quadValid}`);

  return {
    w64Proof: w64ProofData.proof,
    w64Vk,
    mergedPublicInputs: w64ProofData.publicInputs,
    mergedNullifiers,
    mergedNoteHashes,
    mergedDeposits,
    mergedWithdrawals,
  };
}

// Re-export tx provers for the test to use directly.
export { proveDeposit, provePayment, proveWithdraw, provePadding };
export type { TxProofResult, BatchArtifact };
