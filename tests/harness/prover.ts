/**
 * Prover -- real tx proofs + real batch_app/IVC/tube pipeline.
 *
 * Every tx slot has a real UltraHonk proof. The batch is aggregated
 * through batch_app -> init_kernel -> tail_kernel -> hiding_kernel (IVC/Chonk)
 * -> tube (UltraHonk). The tube proof is what submit_batch verifies on L2.
 */

import { type Barretenberg, UltraHonkBackend, AztecClientBackend } from "@aztec/bb.js";
import { Fr } from "@aztec/aztec.js/fields";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { Noir } from "@aztec/noir-noir_js";
import { readFileSync } from "fs";
import { resolve } from "path";
import { IVC_BATCH_SIZING, type TestL3State, type SettleBatchInputs, type L3Note } from "./state.js";

const TARGET_DIR = resolve(import.meta.dirname ?? ".", "../../target");
const TREE_DEPTH = 20;
// IVC pipeline batch sizes. Must match circuits/batch_app/src/main.nr globals
// and contract_ivc/src/main.nr. Bounded by the Chonk ECCVM 32768-row limit.
const MAX_BATCH_SIZE = IVC_BATCH_SIZING.maxBatchSize;        // 8
const MAX_NOTES_PER_TX = 2;
const MAX_OUTPUTS_PER_TX = 2;
const BATCH_NULLIFIERS_COUNT = IVC_BATCH_SIZING.batchNullifiersCount;   // 16
const BATCH_NOTE_HASHES_COUNT = IVC_BATCH_SIZING.batchNoteHashesCount;  // 16
const MEGA_VK_LENGTH = 127;

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

// Chonk VKs are computed internally by AztecClientBackend when empty buffers are passed.

// Extract raw ACIR bytecode buffer from a compiled circuit (for AztecClientBackend).
// The bytecode in compiled JSON is base64-encoded gzip — must decompress.
import { ungzip } from "pako";
function acirBuffer(circuit: any): Uint8Array {
  return ungzip(Buffer.from(circuit.bytecode, "base64"));
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

const f2s = (f: Fr) => f.toString();
const fs2s = (fs: Fr[]) => fs.map(f2s);

async function derivePubkey(secret: Fr) {
  const pk = await Grumpkin.mul(Grumpkin.generator, secret);
  return { x: pk.x, y: pk.y };
}

async function p2h(inputs: Fr[]): Promise<Fr> {
  return poseidon2Hash(inputs);
}

function zeroSibs(): string[] { return new Array(TREE_DEPTH).fill("0"); }

// Convert a raw Uint8Array (n fields × 32 bytes each) into an array of field strings.
function bytesToFieldStrings(buf: Uint8Array, numFields: number): string[] {
  const fields: string[] = [];
  for (let i = 0; i < numFields; i++) {
    const slice = buf.slice(i * 32, (i + 1) * 32);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    fields.push(BigInt(hex).toString());
  }
  return fields;
}

// Convert VK bytes to field array for hashing.
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

// -------------------------------------------------------------------------
// Types
// -------------------------------------------------------------------------

export type TxType = "deposit" | "payment" | "withdraw" | "padding";

export interface TxProofResult {
  type: TxType;
  proof: Uint8Array;
  vk: Uint8Array;
  publicInputs: string[];
  nullifiers: [Fr, Fr];
  noteHashes: [Fr, Fr];
}

export interface BatchArtifact {
  slots: TxProofResult[];
  depositCount: number;
  paymentCount: number;
  withdrawCount: number;
  paddingCount: number;
  settleInputs: SettleBatchInputs;
  oldStateRoot: Fr;
  newStateRoot: Fr;
  nullifierTreeStartIndex: Fr;
  noteHashTreeStartIndex: Fr;
  noteInsertionIndices: number[][];
  tubeProof: Uint8Array;
  tubeVk: Uint8Array;
  tubePublicInputs: Fr[];
}

// NOTE: A tubeTarget option was explored for Path C (IVC + recursive
// aggregation) but is NOT feasible. The tube circuit's Chonk verification
// produces IPA material that prevents noir-recursive tube proving. And
// noir-rollup tube proofs use a different algebraic commitment scheme
// that can't be recursively verified in-circuit. See step10 header.

// -------------------------------------------------------------------------
// Per-tx proof helper: execute circuit + generate proof + get VK
// -------------------------------------------------------------------------

async function proveTx(
  api: Barretenberg,
  circuitName: string,
  inputs: Record<string, any>,
  verifierTarget: "noir-recursive" | "noir-rollup",
): Promise<{ witness: Uint8Array; proof: Uint8Array; vk: Uint8Array; publicInputs: string[]; returnValue: any }> {
  const circuit = loadCircuit(circuitName);
  const noir = new Noir(circuit);
  const backend = new UltraHonkBackend(circuit.bytecode, api);

  const { witness, returnValue } = await noir.execute(inputs);
  const proofData = await backend.generateProof(witness, { verifierTarget });
  const vk = await backend.getVerificationKey({ verifierTarget });

  return { witness, proof: proofData.proof, vk, publicInputs: proofData.publicInputs, returnValue };
}

// -------------------------------------------------------------------------
// proveDeposit
// -------------------------------------------------------------------------

export async function proveDeposit(
  api: Barretenberg, state: TestL3State, amount: Fr, tokenId: Fr,
  recipientPubkeyX: Fr, recipientPubkeyY: Fr, salt: Fr,
): Promise<TxProofResult> {
  const pkHash = await state.hashPubkey(recipientPubkeyX, recipientPubkeyY);
  const dHash = await state.depositHash(pkHash, amount, tokenId, salt);
  const nHash = await state.noteHash(pkHash, amount, tokenId, salt);
  const sr = state.stateRoot;

  const { proof, vk, publicInputs } = await proveTx(api, "deposit", {
    amount: f2s(amount), token_id: f2s(tokenId),
    l3_recipient_pubkey_x: f2s(recipientPubkeyX), l3_recipient_pubkey_y: f2s(recipientPubkeyY),
    salt: f2s(salt),
    nullifiers: [f2s(dHash), "0"], note_hashes: [f2s(nHash), "0"], state_root: f2s(sr),
  }, "noir-recursive");

  return {
    type: "deposit", proof, vk, publicInputs,
    nullifiers: [dHash, Fr.ZERO], noteHashes: [nHash, Fr.ZERO],
  };
}

// -------------------------------------------------------------------------
// provePayment
// -------------------------------------------------------------------------

export async function provePayment(
  api: Barretenberg, state: TestL3State, ownerSecret: Fr, inputNotes: L3Note[],
  recipientPubkeyX: Fr, recipientPubkeyY: Fr, recipientAmount: Fr,
  outputSalts: [Fr, Fr],
): Promise<TxProofResult> {

  const ownerPk = await derivePubkey(ownerSecret);
  const ownerPkHash = await state.hashPubkey(ownerPk.x, ownerPk.y);
  const nhRoot = state.noteHashTree.root();
  const nullRoot = state.nullifierTree.root();
  const sr = state.stateRoot;
  const tokenId = inputNotes[0].tokenId;

  const notes: any[] = [], noteIdx: string[] = [], noteSibs: string[][] = [];
  const lLeaves: any[] = [], lIdx: string[] = [], lSibs: string[][] = [];
  const active: string[] = [], nulls: Fr[] = [];
  let total = 0n;

  for (let i = 0; i < MAX_NOTES_PER_TX; i++) {
    if (i < inputNotes.length) {
      const n = inputNotes[i];
      const nul = await state.computeNullifier(ownerSecret, n.salt);
      const nw = state.noteWitness(n);
      const nulW = state.nullifierNonMembershipWitness(nul);
      notes.push({ owner_pubkey_hash: f2s(n.ownerPubkeyHash), amount: f2s(n.amount), token_id: f2s(n.tokenId), salt: f2s(n.salt) });
      noteIdx.push(nw.index.toString()); noteSibs.push(fs2s(nw.siblings));
      lLeaves.push(serLeaf(nulW.lowLeaf)); lIdx.push(nulW.lowLeafIndex.toString()); lSibs.push(fs2s(nulW.lowLeafSiblings));
      active.push("1"); nulls.push(nul); total += n.amount.toBigInt();
    } else {
      notes.push({ owner_pubkey_hash: "0", amount: "0", token_id: "0", salt: "0" });
      noteIdx.push("0"); noteSibs.push(zeroSibs());
      lLeaves.push(serLeaf({ value: Fr.ZERO, nextIndex: Fr.ZERO, nextValue: Fr.ZERO }));
      lIdx.push("0"); lSibs.push(zeroSibs());
      active.push("0"); nulls.push(Fr.ZERO);
    }
  }

  const rPkHash = await state.hashPubkey(recipientPubkeyX, recipientPubkeyY);
  const rNoteHash = await state.noteHash(rPkHash, recipientAmount, tokenId, outputSalts[0]);
  const change = new Fr(total - recipientAmount.toBigInt());
  const cNoteHash = !change.equals(Fr.ZERO)
    ? await state.noteHash(ownerPkHash, change, tokenId, outputSalts[1]) : Fr.ZERO;

  const { proof, vk, publicInputs } = await proveTx(api, "payment", {
    owner_secret: f2s(ownerSecret), input_notes: notes, input_note_indices: noteIdx,
    input_note_siblings: noteSibs, low_leaves: lLeaves, low_leaf_indices: lIdx,
    low_leaf_siblings: lSibs, active_inputs: active,
    recipient_pubkey_x: f2s(recipientPubkeyX), recipient_pubkey_y: f2s(recipientPubkeyY),
    output_salts: fs2s(outputSalts), recipient_amount: f2s(recipientAmount),
    note_hash_tree_root: f2s(nhRoot), nullifier_tree_root: f2s(nullRoot),
    nullifiers: fs2s(nulls), note_hashes: [f2s(rNoteHash), f2s(cNoteHash)], state_root: f2s(sr),
  }, "noir-recursive");

  return {
    type: "payment", proof, vk, publicInputs,
    nullifiers: [nulls[0], nulls[1]], noteHashes: [rNoteHash, cNoteHash],
  };
}

// -------------------------------------------------------------------------
// proveWithdraw
// -------------------------------------------------------------------------

export async function proveWithdraw(
  api: Barretenberg, state: TestL3State, ownerSecret: Fr, inputNotes: L3Note[],
  l2TokenAddr: Fr, l2Recipient: Fr, claimSalt: Fr, withdrawAmt: Fr, changeSalt: Fr,
): Promise<TxProofResult> {

  const ownerPk = await derivePubkey(ownerSecret);
  const ownerPkHash = await state.hashPubkey(ownerPk.x, ownerPk.y);
  const nhRoot = state.noteHashTree.root();
  const nullRoot = state.nullifierTree.root();
  const sr = state.stateRoot;
  const tokenId = inputNotes[0].tokenId;

  const l3n: any[] = [], l3idx: string[] = [], l3sibs: string[][] = [];
  const lLeaves: any[] = [], lIdx: string[] = [], lSibs: string[][] = [];
  const active: string[] = [], nulls: Fr[] = [];
  let total = 0n;

  for (let i = 0; i < MAX_NOTES_PER_TX; i++) {
    if (i < inputNotes.length) {
      const n = inputNotes[i];
      const nul = await state.computeNullifier(ownerSecret, n.salt);
      const nw = state.noteWitness(n);
      const nulW = state.nullifierNonMembershipWitness(nul);
      l3n.push({ owner_pubkey_hash: f2s(n.ownerPubkeyHash), amount: f2s(n.amount), token_id: f2s(n.tokenId), salt: f2s(n.salt) });
      l3idx.push(nw.index.toString()); l3sibs.push(fs2s(nw.siblings));
      lLeaves.push(serLeaf(nulW.lowLeaf)); lIdx.push(nulW.lowLeafIndex.toString()); lSibs.push(fs2s(nulW.lowLeafSiblings));
      active.push("1"); nulls.push(nul); total += n.amount.toBigInt();
    } else {
      l3n.push({ owner_pubkey_hash: "0", amount: "0", token_id: "0", salt: "0" });
      l3idx.push("0"); l3sibs.push(zeroSibs());
      lLeaves.push(serLeaf({ value: Fr.ZERO, nextIndex: Fr.ZERO, nextValue: Fr.ZERO }));
      lIdx.push("0"); lSibs.push(zeroSibs());
      active.push("0"); nulls.push(Fr.ZERO);
    }
  }

  const secret = await p2h([l2Recipient, claimSalt]);
  const claimHash = await p2h([l2TokenAddr, withdrawAmt, secret]);
  const change = new Fr(total - withdrawAmt.toBigInt());
  const cNoteHash = !change.equals(Fr.ZERO)
    ? await state.noteHash(ownerPkHash, change, tokenId, changeSalt) : Fr.ZERO;

  const { proof, vk, publicInputs } = await proveTx(api, "withdraw", {
    owner_secret: f2s(ownerSecret), l3_notes: l3n, l3_note_indices: l3idx,
    l3_note_siblings: l3sibs, low_leaves: lLeaves, low_leaf_indices: lIdx,
    low_leaf_siblings: lSibs, active_inputs: active,
    l2_token_address: f2s(l2TokenAddr), l2_recipient_address: f2s(l2Recipient),
    claim_salt: f2s(claimSalt), withdraw_amount: f2s(withdrawAmt), change_salt: f2s(changeSalt),
    note_hash_tree_root: f2s(nhRoot), nullifier_tree_root: f2s(nullRoot),
    nullifiers: fs2s(nulls), note_hashes: [f2s(claimHash), f2s(cNoteHash)], state_root: f2s(sr),
  }, "noir-recursive");

  return {
    type: "withdraw", proof, vk, publicInputs,
    nullifiers: [nulls[0], nulls[1]], noteHashes: [claimHash, cNoteHash],
  };
}

// -------------------------------------------------------------------------
// provePadding (cached -- deterministic)
// -------------------------------------------------------------------------

let cachedPadding: TxProofResult | null = null;
export async function provePadding(api: Barretenberg): Promise<TxProofResult> {
  if (cachedPadding) return cachedPadding;
  const { proof, vk } = await proveTx(api, "padding", {
    nullifiers: ["0", "0"], note_hashes: ["0", "0"], state_root: "0",
  }, "noir-recursive");
  cachedPadding = {
    type: "padding", proof, vk,
    publicInputs: ["0", "0", "0", "0", "0"],
    nullifiers: [Fr.ZERO, Fr.ZERO], noteHashes: [Fr.ZERO, Fr.ZERO],
  };
  return cachedPadding;
}

// -------------------------------------------------------------------------
// buildBatchProof -- real pipeline
// -------------------------------------------------------------------------

export async function buildBatchProof(
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
  const settleInputs = await state.buildSettleInputs(settleEntries, IVC_BATCH_SIZING);

  // 3. Execute batch_app.
  console.log("    Executing batch_app...");
  const batchAppCircuit = loadCircuit("batch_app");
  const batchNoir = new Noir(batchAppCircuit);

  const depositVkBytes = deposits.length > 0 ? deposits[0].vk : paddingProof.vk;
  const paymentVkBytes = payments.length > 0 ? payments[0].vk : paddingProof.vk;
  const withdrawVkBytes = withdrawals.length > 0 ? withdrawals[0].vk : paddingProof.vk;
  const paddVkBytes = paddingProof.vk;

  const VK_FIELDS = 115; // ULTRA_HONK_VK_LENGTH
  const PROOF_FIELDS = 500; // ULTRA_HONK_PROOF_LENGTH

  // VK hashes via poseidon2.
  const vkHashStr = async (vk: Uint8Array) => f2s(await p2h(vkToFields(vk)));

  const { witness: batchWitness, returnValue: batchReturn } = await batchNoir.execute({
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
  console.log("    batch_app executed");

  // 4. Compute Mega VKs for all circuits (needed for kernel witness inputs AND Chonk proving).
  const initCircuit = loadCircuit("init_kernel");
  const tailCircuit = loadCircuit("tail_kernel");
  const hidingCircuit = loadCircuit("hiding_kernel");

  const acirBufs = [batchAppCircuit, initCircuit, tailCircuit, hidingCircuit].map(acirBuffer);
  const circuitNames = ["batch_app", "init_kernel", "tail_kernel", "hiding_kernel"];

  console.log("    Computing Mega VKs...");
  const megaVks: Uint8Array[] = [];
  for (let i = 0; i < acirBufs.length; i++) {
    const vkResult = await api.chonkComputeVk({
      circuit: { name: circuitNames[i], bytecode: acirBufs[i] },
    });
    megaVks.push(vkResult.bytes);
  }
  console.log(`    VKs computed (${megaVks.map((v) => v.length).join(", ")} bytes)`);

  // Convert raw Mega VK bytes to Noir VerificationKey struct: { key: [Field; 127], hash: Field }
  async function megaVkToNoirStruct(rawVk: Uint8Array) {
    const fields = vkToFields(rawVk); // 127 Fr values
    const hash = await p2h(fields);
    return { key: fields.map(f2s), hash: f2s(hash) };
  }

  const batchAppVk = await megaVkToNoirStruct(megaVks[0]);
  const initKernelVk = await megaVkToNoirStruct(megaVks[1]);
  const tailKernelVk = await megaVkToNoirStruct(megaVks[2]);

  // 5. Execute IVC kernel chain with real VKs.
  console.log("    Executing IVC kernels (with real VKs)...");

  const { witness: initWitness, returnValue: initReturn } =
    await new Noir(initCircuit).execute({ app_inputs: batchReturn, app_vk: batchAppVk });
  const { witness: tailWitness, returnValue: tailReturn } =
    await new Noir(tailCircuit).execute({ prev_kernel_inputs: initReturn, kernel_vk: initKernelVk });
  const { witness: hidingWitness } =
    await new Noir(hidingCircuit).execute({ prev_kernel_inputs: tailReturn, kernel_vk: tailKernelVk });

  // 6. Prove IVC chain (Chonk).
  console.log("    Proving IVC (Chonk)...");
  const aztecBackend = new AztecClientBackend(acirBufs, api, circuitNames);
  // Witnesses from Noir.execute() are gzip-compressed; AztecClientBackend needs raw.
  const witnesses = [batchWitness, initWitness, tailWitness, hidingWitness].map(
    (w) => ungzip(w),
  );
  const [chonkProofFields, chonkProof, chonkVk] = await aztecBackend.prove(
    witnesses,
    megaVks,
  );
  console.log(`    Chonk proof: ${chonkProofFields.length} fields`);

  const chonkValid = await aztecBackend.verify(chonkProof, chonkVk);
  console.log(`    Chonk verified: ${chonkValid}`);

  // 6. Execute + prove tube.
  console.log("    Proving tube...");
  const tubeCircuit = loadCircuit("tube");

  // Convert Chonk VK bytes (127 fields x 32 bytes each) to Fr array.
  const MEGA_VK_FIELDS = 127;
  const chonkVkFieldsFr = vkToFields(chonkVk);
  // Truncate/pad to expected length.
  while (chonkVkFieldsFr.length < MEGA_VK_FIELDS) chonkVkFieldsFr.push(Fr.ZERO);
  const chonkKeyHash = await p2h(chonkVkFieldsFr.slice(0, MEGA_VK_FIELDS));

  // Convert proof fields (each is a 32-byte Uint8Array) to strings.
  const fieldBufToStr = (buf: Uint8Array) => {
    const hex = "0x" + Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
    return BigInt(hex).toString();
  };

  const BATCH_OUTPUT_FIELDS = 8;
  const batchOutputStrs = chonkProofFields.slice(0, BATCH_OUTPUT_FIELDS).map(fieldBufToStr);
  const proofBodyStrs = chonkProofFields.slice(BATCH_OUTPUT_FIELDS).map(fieldBufToStr);

  console.log(`    Chonk VK: ${chonkVk.length} bytes (${chonkVkFieldsFr.length} fields)`);
  console.log(`    Chonk proof: ${BATCH_OUTPUT_FIELDS} public + ${proofBodyStrs.length} proof fields`);

  const { witness: tubeWitness } = await new Noir(tubeCircuit).execute({
    verification_key: chonkVkFieldsFr.slice(0, MEGA_VK_FIELDS).map(f2s),
    proof: proofBodyStrs,
    chonk_public_inputs: batchOutputStrs,
    key_hash: f2s(chonkKeyHash),
    old_state_root: batchOutputStrs[0],
    new_state_root: batchOutputStrs[1],
    nullifiers_batch_hash: batchOutputStrs[2],
    note_hashes_batch_hash: batchOutputStrs[3],
    deposit_nullifiers_hash: batchOutputStrs[4],
    withdrawal_claims_hash: batchOutputStrs[5],
    nullifier_tree_start_index: batchOutputStrs[6],
    note_hash_tree_start_index: batchOutputStrs[7],
  });

  const tubeBackend = new UltraHonkBackend(tubeCircuit.bytecode, api);
  const tubeProofData = await tubeBackend.generateProof(tubeWitness, { verifierTarget: "noir-rollup" });
  const tubeVk = await tubeBackend.getVerificationKey({ verifierTarget: "noir-rollup" });
  console.log(`    Tube proof: ${tubeProofData.proof.length} bytes`);

  const tubeValid = await tubeBackend.verifyProof(tubeProofData, { verifierTarget: "noir-rollup" });
  console.log(`    Tube verified: ${tubeValid}`);

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
    tubeProof: tubeProofData.proof,
    tubeVk,
    tubePublicInputs: batchOutputStrs.map((x) => new Fr(BigInt(x))),
  };
}

// -------------------------------------------------------------------------
// Compute tube VK hash without running the full pipeline.
// -------------------------------------------------------------------------

export async function computeTubeVkHash(api: Barretenberg): Promise<{ vkHash: Fr; vk: Uint8Array }> {
  const tubeCircuit = loadCircuit("tube");
  const tubeBackend = new UltraHonkBackend(tubeCircuit.bytecode, api);
  const vk = await tubeBackend.getVerificationKey({ verifierTarget: "noir-rollup" });
  // VK is [Field; 115] — convert 32-byte chunks to field elements before hashing.
  const vkFields = vkToFields(vk);
  const vkHash = await p2h(vkFields);
  return { vkHash, vk };
}

// -------------------------------------------------------------------------
// Compute pair_tube VK hash.
// -------------------------------------------------------------------------

export async function computePairTubeVkHash(api: Barretenberg): Promise<{ vkHash: Fr; vk: Uint8Array }> {
  const circuit = loadCircuit("pair_tube");
  const backend = new UltraHonkBackend(circuit.bytecode, api);
  // pair_tube finalizes IPA in-circuit via ROOT_ROLLUP_HONK, so its own
  // proof is emitted at noir-recursive target (500-field UltraHonkZK).
  const vk = await backend.getVerificationKey({ verifierTarget: "noir-recursive" });
  const vkFields = vkToFields(vk);
  const vkHash = await p2h(vkFields);
  return { vkHash, vk };
}

// -------------------------------------------------------------------------
// buildPairTubeProof -- Path C: aggregate 2 IVC tube proofs via pair_tube.
//
// Consumes two 519-field noir-rollup tube proofs and verifies them inside
// pair_tube under ROOT_ROLLUP_HONK (proof type 5), which finalizes both
// accumulated IPA claims natively. pair_tube's output therefore carries no
// IPA material and is emitted at noir-recursive target as a 500-field
// UltraHonkZK proof that matches the contract ABI.
// -------------------------------------------------------------------------

export interface PairTubeArtifact {
  pairProof: Uint8Array;
  pairVk: Uint8Array;
  mergedPublicInputs: string[];  // 8 fields -- BatchOutput shape, merged
  mergedNullifiers: Fr[];        // 32 fields
  mergedNoteHashes: Fr[];        // 32 fields
  mergedDeposits: Fr[];          // 16 fields
  mergedWithdrawals: Fr[];       // 16 fields
}

// RollupHonk proof is 519 fields (449 base + 6 IPA claim + 64 IPA proof).
const ROLLUP_HONK_PROOF_FIELDS = 519;

export async function buildPairTubeProof(
  api: Barretenberg,
  artifactA: BatchArtifact,
  artifactB: BatchArtifact,
): Promise<PairTubeArtifact> {
  // 1. Sanity: both batches must share the same tube VK.
  if (artifactA.tubeVk.length !== artifactB.tubeVk.length) {
    throw new Error("buildPairTubeProof: tube VK byte lengths differ");
  }
  for (let i = 0; i < artifactA.tubeVk.length; i++) {
    if (artifactA.tubeVk[i] !== artifactB.tubeVk[i]) {
      throw new Error("buildPairTubeProof: tube VKs differ at byte " + i);
    }
  }

  // 2. Sanity: state-root chain.
  if (artifactA.newStateRoot.toBigInt() !== artifactB.oldStateRoot.toBigInt()) {
    throw new Error(
      `buildPairTubeProof: state chain broken: A.new=${artifactA.newStateRoot} B.old=${artifactB.oldStateRoot}`,
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

  // 4. Hashes of merged arrays.
  const mergedNullifiersHash = await p2h(mergedNullifiers);
  const mergedNoteHashesHash = await p2h(mergedNoteHashes);
  const mergedDepositsHash = await p2h(mergedDeposits);
  const mergedWithdrawalsHash = await p2h(mergedWithdrawals);

  // 5. Tube VK hash.
  const VK_FIELDS = 115;
  const tubeVkFields = vkToFields(artifactA.tubeVk);
  const tubeVkHash = await p2h(tubeVkFields);

  // 6. Execute pair_tube circuit.
  console.log("    Executing pair_tube...");
  const pairCircuit = loadCircuit("pair_tube");
  const pairNoir = new Noir(pairCircuit);

  const f2s = (f: Fr) => f.toString();

  const { witness: pairWitness } = await pairNoir.execute({
    tube_vk: bytesToFieldStrings(artifactA.tubeVk, VK_FIELDS),
    tube_vk_hash: f2s(tubeVkHash),

    tube_proof_a: bytesToFieldStrings(artifactA.tubeProof, ROLLUP_HONK_PROOF_FIELDS),
    tube_public_inputs_a: artifactA.tubePublicInputs.map(f2s),

    tube_proof_b: bytesToFieldStrings(artifactB.tubeProof, ROLLUP_HONK_PROOF_FIELDS),
    tube_public_inputs_b: artifactB.tubePublicInputs.map(f2s),

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
  console.log("    pair_tube executed");

  // 7. Prove pair_tube at noir-recursive target for L2 submission.
  //    IPA was finalized in-circuit by ROOT_ROLLUP_HONK, so the emitted
  //    proof is a clean 500-field UltraHonkZK compatible with the contract's
  //    verify_honk_proof / UltraHonkZKProof ABI.
  console.log("    Proving pair_tube (UltraHonk, noir-recursive)...");
  const pairBackend = new UltraHonkBackend(pairCircuit.bytecode, api);
  const pairProofData = await pairBackend.generateProof(pairWitness, { verifierTarget: "noir-recursive" });
  const pairVk = await pairBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
  console.log(`    pair_tube proof: ${pairProofData.proof.length} bytes`);

  const pairValid = await pairBackend.verifyProof(pairProofData, { verifierTarget: "noir-recursive" });
  console.log(`    pair_tube verified: ${pairValid}`);

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
