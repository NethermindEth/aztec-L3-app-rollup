/**
 * step8-ivc-meta-16slot.ts
 *
 * IVC meta-batch test with CONCURRENT proving of two sub-batches.
 *
 * Structure: 2 x batch=8 (each = 1 real deposit + 7 padding) → 16 slot capacity,
 * 2 real deposits total, settled in ONE L2 transaction via submit_two_batches.
 *
 * Concurrency: each sub-batch proves on its own Barretenberg instance in
 * parallel via Promise.all. Expected wall-clock ≈ single-batch time (~1.4 min),
 * vs. step7's sequential 2.9 min.
 */

import { Barretenberg } from "@aztec/bb.js";
import { Fr } from "@aztec/aztec.js/fields";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/stdlib/abi";
import type { NoirCompiledContract } from "@aztec/stdlib/noir";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { TokenContract } from "@aztec/noir-contracts.js/Token";
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

import { TestL3State } from "./harness/state.js";
import {
  proveDeposit,
  buildBatchProof,
  computeTubeVkHash,
  type BatchArtifact,
  type TxProofResult,
} from "./harness/prover.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_ivc_settlement-L3IvcSettlement.json",
);
const METRICS_OUT = resolve(import.meta.dirname ?? ".", "../target/step8-metrics.json");

function fmt(ms: number) {
  if (ms < 1000) return `${ms.toFixed(0)} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${(ms / 60_000).toFixed(2)} min`;
}

async function view(method: any, from: any): Promise<bigint> {
  const r = await method.simulate({ from });
  return BigInt((r.result ?? r).toString());
}

async function derivePubkey(secret: Fr) {
  return Grumpkin.mul(Grumpkin.generator, secret);
}

function bytesToBigInts(buf: Uint8Array): bigint[] {
  const n = Math.floor(buf.length / 32);
  const out: bigint[] = [];
  for (let i = 0; i < n; i++) {
    const slice = buf.slice(i * 32, (i + 1) * 32);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    out.push(BigInt(hex));
  }
  return out;
}

async function main() {
  console.log("=== step8: IVC meta-batch (concurrent proving, 16 slot capacity) ===\n");

  console.log(`Connecting to ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error("Cannot reach sandbox."); process.exit(1);
  }

  // Primary api for setup proofs (deposit circuit, tube VK hash).
  const api = await Barretenberg.new({ threads: 4 });

  console.log("Computing tube VK hash...");
  const vkStart = performance.now();
  const { vkHash: tubeVkHash } = await computeTubeVkHash(api);
  console.log(`  VK hash: ${tubeVkHash.toString().slice(0, 18)}... (${fmt(performance.now() - vkStart)})\n`);

  // Accounts
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin, aliceL2] = await Promise.all(
    testAccounts.slice(0, 2).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  // Deploy
  console.log("Deploying Token + L3IvcSettlement...");
  const { contract: token } = await TokenContract.deploy(wallet, admin, "TestToken", "TT", 18)
    .send({ from: admin });

  const l3State = await TestL3State.create();
  const initialStateRoot = l3State.stateRoot;

  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT_PATH, "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(
    wallet, l3Artifact,
    [initialStateRoot.toBigInt(), tubeVkHash.toBigInt(), 0n],
    "constructor",
  ).send({ from: admin });

  await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });
  await token.methods.mint_to_private(aliceL2, 10_000n).send({ from: admin });
  console.log(`  Token: ${token.address}`);
  console.log(`  L3:    ${l3.address}\n`);

  // Shared setup
  const aliceSecret = new Fr(0xdead_beefn);
  const alicePk = await derivePubkey(aliceSecret);
  const alicePkHash = await l3State.hashPubkey(alicePk.x, alicePk.y);
  const tokenId = new Fr(token.address.toBigInt());
  const amount = new Fr(100n);

  async function l2Deposit(salt: Fr) {
    const nonce = Fr.random();
    const action = token.methods.transfer_to_public(aliceL2, l3.address, amount.toBigInt(), nonce);
    const authwit = await wallet.createAuthWit(aliceL2, { caller: l3.address, action });
    await l3.methods
      .deposit(token.address, amount, alicePk.x, alicePk.y, salt, nonce)
      .send({ from: aliceL2, authWitnesses: [authwit] });
    const dHash = await l3State.depositHash(alicePkHash, amount, tokenId, salt);
    l3State.registerDeposit(dHash);
  }

  // ==================================================================
  // Register 2 deposits up front
  // ==================================================================
  const saltA = new Fr(0xaaaa_1111n);
  const saltB = new Fr(0xbbbb_1111n);
  await l2Deposit(saltA);
  await l2Deposit(saltB);
  console.log("2 L2 deposits registered (one per sub-batch)\n");

  // ==================================================================
  // Prove per-tx deposit proofs serially (cheap, each against same state root)
  // Both deposits commit to the PRE-batch state root.
  // ==================================================================
  console.log("Proving per-tx deposit proofs...");
  const perTxStart = performance.now();
  const depProofA = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltA);
  const depProofB = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltB);
  const perTxMs = performance.now() - perTxStart;
  console.log(`  Per-tx proofs ready: ${fmt(perTxMs)}\n`);

  // ==================================================================
  // Concurrent batch proving.
  //
  // buildBatchProof internally advances l3State (applies nullifier/note-hash
  // insertions). Because it MUTATES shared state, we cannot run two
  // buildBatchProof calls against the same l3State in parallel safely.
  //
  // Solution: fork a secondary l3State snapshot for batch B that starts from
  // the state batch A will leave behind. Do this by pre-computing the set of
  // state updates that batch A will apply, then building batch B from a state
  // that already has those updates applied.
  //
  // For our specific test (2 deposits, 1 real each + padding), we achieve this
  // cleanly by applying deposit A's insertion to l3State FIRST (so batch B can
  // see the post-A state as its "old" state), but batch A's proof was already
  // generated against the pre-A state. Both batches' buildBatchProof calls then
  // use DIFFERENT l3State objects (one snapshot per).
  //
  // To avoid the shared-mutation hazard: we clone l3State for batch B BEFORE
  // running buildBatchProof on batch A. Each buildBatchProof advances its own
  // l3State copy.
  // ==================================================================

  console.log("Building two IVC batch proofs CONCURRENTLY on separate bb instances...");

  // We need a state object for batch A and one for batch B with the post-A
  // state. Simplest path: construct batch B's l3State explicitly by replaying
  // deposit A's expected updates on a cloned state.

  // For this test we use a simpler shortcut that works because both deposits
  // produce independent note hashes and nullifiers:
  //   - Batch A runs on the real l3State.
  //   - Batch B runs on a fresh TestL3State that has ALL prior state +
  //     deposit A's insertions applied.
  // To build batch B's state, we need to manually apply deposit A's insertions
  // to a cloned state. We achieve that via a deep state clone function.

  const apiA = api;                                          // first bb instance
  const apiB = await Barretenberg.new({ threads: 4 });       // second bb instance for concurrency

  // Build batch B's state by applying deposit A's insertions on a cloned state.
  const l3StateB = await cloneL3StateWithDeposit(
    l3State, depProofA,
  );

  // depProofB was proved against the CURRENT l3State (pre-batch A state root).
  // That state root = batch B's OLD state root must be batch A's NEW state root.
  // So we need to re-prove depProofB against the post-A state root.
  console.log("  Re-proving deposit B against post-batch-A state root...");
  const depProofB_v2 = await proveDeposit(
    api, l3StateB, amount, tokenId, alicePk.x, alicePk.y, saltB,
  );

  // NOW buildBatchProof for batch A (uses l3State) and batch B (uses l3StateB)
  // can run in parallel — no shared mutable state.
  const proveConcurrentStart = performance.now();
  const [artifactA, artifactB] = await Promise.all([
    buildBatchProof(apiA, l3State, [depProofA]),
    buildBatchProof(apiB, l3StateB, [depProofB_v2]),
  ]);
  const proveConcurrentMs = performance.now() - proveConcurrentStart;
  console.log(`  Concurrent batch proving wall-clock: ${fmt(proveConcurrentMs)}`);
  console.log(`    A tube: ${artifactA.tubeProof.length} bytes, B tube: ${artifactB.tubeProof.length} bytes\n`);

  // Sanity: B's old_state_root should match A's new_state_root.
  if (artifactA.newStateRoot.toBigInt() !== artifactB.oldStateRoot.toBigInt()) {
    throw new Error(
      `State chain broken: A.new=${artifactA.newStateRoot} B.old=${artifactB.oldStateRoot}`,
    );
  }
  console.log("  State chain A.new == B.old: OK\n");

  // ==================================================================
  // Submit via submit_two_batches
  // ==================================================================
  const tubeVkFieldsA = bytesToBigInts(artifactA.tubeVk);
  const tubeProofFieldsA = bytesToBigInts(artifactA.tubeProof);
  const tubeProofFieldsB = bytesToBigInts(artifactB.tubeProof);

  // DA accounting
  const daFields =
    tubeVkFieldsA.length                                  // shared VK
    + 1                                                   // vk hash
    + tubeProofFieldsA.length + tubeProofFieldsB.length   // 2 proofs
    + artifactA.tubePublicInputs.length + artifactB.tubePublicInputs.length // 2 x 8 pub
    + artifactA.settleInputs.nullifiers.length + artifactB.settleInputs.nullifiers.length  // 2 x 16
    + artifactA.settleInputs.noteHashes.length + artifactB.settleInputs.noteHashes.length  // 2 x 16
    + artifactA.settleInputs.depositNullifiers.length + artifactB.settleInputs.depositNullifiers.length  // 2 x 8
    + artifactA.settleInputs.withdrawalClaims.length + artifactB.settleInputs.withdrawalClaims.length;   // 2 x 8
  const daBytes = daFields * 32;
  console.log(`DA: ${daFields} fields (${daBytes} bytes)\n`);

  console.log("Submitting via submit_two_batches (1 L2 tx, 2 settle calls)...");
  const submitStart = performance.now();
  await l3.methods
    .submit_two_batches(
      tubeVkFieldsA,
      tubeVkHash,
      tubeProofFieldsA,
      artifactA.tubePublicInputs,
      artifactA.settleInputs.nullifiers,
      artifactA.settleInputs.noteHashes,
      artifactA.settleInputs.depositNullifiers,
      artifactA.settleInputs.withdrawalClaims,
      tubeProofFieldsB,
      artifactB.tubePublicInputs,
      artifactB.settleInputs.nullifiers,
      artifactB.settleInputs.noteHashes,
      artifactB.settleInputs.depositNullifiers,
      artifactB.settleInputs.withdrawalClaims,
    )
    .send({ from: admin });
  const submitMs = performance.now() - submitStart;
  console.log(`  L2 submit wall-clock: ${fmt(submitMs)}\n`);

  const nonce = await view(l3.methods.get_batch_nonce(), admin);
  const root = await view(l3.methods.get_latest_root(), admin);
  console.log(`Post-state: nonce=${nonce} (expected 2), root=${root.toString().slice(0, 18)}...\n`);

  // ==================================================================
  // Metrics dump
  // ==================================================================
  const metrics = {
    variant: "ivc-meta-batch",
    subBatches: 2,
    realTxsPerSubBatch: 1,
    paddingPerSubBatch: 7,
    totalSlotCapacity: 16,
    totalRealTxs: 2,
    proving: {
      perTxMs,
      concurrentBatchProveMs: proveConcurrentMs,
      note: "Two batches proved on independent bb instances in parallel",
    },
    da: {
      totalFields: daFields,
      totalBytes: daBytes,
      breakdown: {
        sharedTubeVkFields: tubeVkFieldsA.length,
        perBatchProofFields: tubeProofFieldsA.length,
        perBatchPublicInputs: artifactA.tubePublicInputs.length,
        perBatchNullifiers: artifactA.settleInputs.nullifiers.length,
        perBatchNoteHashes: artifactA.settleInputs.noteHashes.length,
        perBatchDeposits: artifactA.settleInputs.depositNullifiers.length,
        perBatchWithdrawals: artifactA.settleInputs.withdrawalClaims.length,
      },
    },
    l2: {
      submitWallClockMs: submitMs,
      nonceAdvance: Number(nonce),
      note: "submit_two_batches enqueues TWO settle_batch public calls",
    },
    proofSizes: {
      tubeProofBytes: artifactA.tubeProof.length,
      tubeVkBytes: artifactA.tubeVk.length,
    },
    verificationReasoning: "Private circuit contains 2 × verify_honk_proof calls (~2x the kernel-proof constraint load vs submit_batch)",
    executionReasoning: "Public call stack runs settle_batch TWICE at batch=8 sizing (2x storage ops and 2x state-tree churn vs single-batch)",
  };
  writeFileSync(METRICS_OUT, JSON.stringify(metrics, null, 2));
  console.log(`Metrics written to ${METRICS_OUT}`);

  // ==================================================================
  // Comparison print
  // ==================================================================
  console.log("\n=== step8 SUMMARY ===\n");
  console.log(`  Variant: IVC meta-batch via submit_two_batches`);
  console.log(`  Sub-batches: 2 × (1 real + 7 padding) at batch=8`);
  console.log(`  Per-tx proofs wall-clock: ${fmt(perTxMs)}`);
  console.log(`  Concurrent batch proving: ${fmt(proveConcurrentMs)}`);
  console.log(`  L2 submit wall-clock:     ${fmt(submitMs)}`);
  console.log(`  DA on L2 tx:              ${daBytes} bytes (${daFields} fields)`);
  console.log(`  Proof material per batch: ~${artifactA.tubeProof.length + artifactA.tubeVk.length + 32 * 9} bytes (proof + VK + pubs + vkHash)`);
  console.log(`  On-chain nonce advance:   +${Number(nonce)} (two settle_batch calls)`);
  console.log(`  Private verify cost:      2 × verify_honk_proof in kernel`);
  console.log(`  Public execution cost:    2 × settle_batch@batch=8 sequentially`);

  await api.destroy();
  await apiB.destroy();
  console.log("\nDone.");
}

// -------------------------------------------------------------------------
// Clone TestL3State with deposit A's insertions applied.
//
// Deposit has nullifier (deposit_hash) and note_hash. Both get inserted into
// l3State's trees, and the deposit_hash is removed from pendingDeposits.
// We replay that on a fresh clone.
// -------------------------------------------------------------------------
async function cloneL3StateWithDeposit(
  original: TestL3State,
  depProof: TxProofResult,
): Promise<TestL3State> {
  // TestL3State doesn't expose a clone method; fastest path is to create a new
  // state from scratch and replay ALL already-applied operations. Since this
  // test only registered deposits and applied NONE yet (we haven't called
  // buildBatchProof on anything), the cloned state's starting point is genesis
  // + the same pending deposits.
  //
  // Steps:
  //   1. Create fresh TestL3State.
  //   2. Copy all pendingDeposits from original.
  //   3. Apply deposit A's insertions (nullifier + note hash) — this advances
  //      the state to what will be l3State after buildBatchProof(batch A).
  //   4. Drop deposit A from pendingDeposits in the clone (buildBatchProof
  //      would remove it).
  const clone = await TestL3State.create();
  for (const dh of original.pendingDeposits) clone.pendingDeposits.add(dh);
  // Replay notes in original (none at this point in our test).
  // Now apply deposit A's insertions.
  const nullVal = depProof.nullifiers[0];
  const nhVal = depProof.noteHashes[0];
  if (!nullVal.equals(Fr.ZERO)) {
    await clone.insertNullifier(nullVal);
  }
  if (!nhVal.equals(Fr.ZERO)) {
    await clone.noteHashTree.insert(nhVal);
  }
  clone.pendingDeposits.delete(nullVal.toString());
  await clone.syncStateRoot();
  return clone;
}

main().catch((e) => {
  console.error("\nFATAL:", e.message ?? e);
  console.error(e.stack?.split("\n").slice(0, 12).join("\n"));
  process.exit(1);
});
