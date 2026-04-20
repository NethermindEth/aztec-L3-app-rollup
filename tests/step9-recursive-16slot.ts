/**
 * step9-recursive-merged-16slot.ts
 *
 * Recursive pipeline with proof aggregation via wrapper_16.
 *
 * Structure:
 *   - 2 sub-batches, each batch_app_standalone[8] + wrapper[noir-recursive].
 *   - wrapper_16 aggregates both wrapper proofs → 1 UltraHonk[noir-recursive]
 *     proof (500 fields, matching contract ABI) that attests to combined
 *     16-tx state transition.
 *   - Submitted to L2 via new submit_batch_16 method, causing a single
 *     settle_batch_merged public call (nonce += 1).
 *
 * Sub-batches are proved sequentially (each peaks ~8 GiB; concurrent would
 * exceed 16 GiB WSL budget). wrapper_16 runs serially after both complete.
 *
 * Total slot capacity: 16 (2 real deposits + 14 padding).
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
import { computePerTxVkHashesCommit, type TxProofResult } from "./harness/prover.js";
import {
  buildBatchProofRecursive,
  buildWrapper16Proof,
  computeWrapperVkHash,
  computeWrapper16VkHash,
  proveDeposit,
  type BatchArtifact,
} from "./harness/prover-recursive.js";
import {
  BATCH_16_SIZE,
  BATCH_16_NULLIFIERS_COUNT,
  BATCH_16_NOTE_HASHES_COUNT,
  PUB_COUNT_16,
  assertRecursiveSubmitShape,
} from "./harness/recursive-shapes.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_recursive_settlement-L3RecursiveSettlement.json",
);
const METRICS_OUT = resolve(import.meta.dirname ?? ".", "../target/step9-metrics.json");

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

// Clone TestL3State after applying deposit's insertions — so that a second
// sub-batch can be proved against the post-A state in parallel with the
// buildBatchProofRecursive for batch A.
async function cloneL3StateWithDeposit(
  original: TestL3State,
  depProof: TxProofResult,
): Promise<TestL3State> {
  const clone = await TestL3State.create();
  for (const dh of original.pendingDeposits) clone.pendingDeposits.add(dh);
  const nullVal = depProof.nullifiers[0];
  const nhVal = depProof.noteHashes[0];
  if (!nullVal.equals(Fr.ZERO)) await clone.insertNullifier(nullVal);
  if (!nhVal.equals(Fr.ZERO)) await clone.noteHashTree.insert(nhVal);
  clone.pendingDeposits.delete(nullVal.toString());
  await clone.syncStateRoot();
  return clone;
}

async function main() {
  console.log("=== step9: Recursive pipeline with wrapper_16 merged-proof ===\n");

  console.log(`Connecting to ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error("Cannot reach sandbox."); process.exit(1);
  }

  // Primary bb instance used for per-tx deposit proofs, wrapper VK hash,
  // and wrapper_16 prove. Sub-batch proving uses apiA / apiB.
  const api = await Barretenberg.new({ threads: 4 });

  console.log("Computing wrapper + wrapper_16 VK hashes...");
  const vkStart = performance.now();
  const { vkHash: wrapperVkHash } = await computeWrapperVkHash(api);
  const perTxVkHashesCommit = await computePerTxVkHashesCommit(api);
  const { vkHash: pairVkHash } = await computeWrapper16VkHash(api);
  console.log(`  wrapper VK hash: ${wrapperVkHash.toString().slice(0, 18)}...`);
  console.log(`  wrapper_16 VK hash: ${pairVkHash.toString().slice(0, 18)}... (${fmt(performance.now() - vkStart)})\n`);

  // Accounts
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin, aliceL2] = await Promise.all(
    testAccounts.slice(0, 2).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  // Deploy — constructor now takes (initial_state_root, tube_vk_hash, merged_vk_hash).
  console.log("Deploying Token + L3RecursiveSettlement...");
  const { contract: token } = await TokenContract.deploy(wallet, admin, "TestToken", "TT", 18)
    .send({ from: admin });

  const l3State = await TestL3State.create();
  const initialStateRoot = l3State.stateRoot;

  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT_PATH, "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(
    wallet, l3Artifact,
    // step9 only exercises submit_batch_16; pp_vk_hash and quad_vk_hash
    // are set to 0 (submit_batch_64 not called in this test).
    [initialStateRoot.toBigInt(), wrapperVkHash.toBigInt(), pairVkHash.toBigInt(), 0n, 0n, perTxVkHashesCommit.toBigInt()],
    "constructor",
  ).send({ from: admin });

  await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });
  await token.methods.mint_to_private(aliceL2, 10_000n).send({ from: admin });
  console.log(`  Token: ${token.address}`);
  console.log(`  L3:    ${l3.address}\n`);

  // Shared deposit params
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

  // Register 2 deposits on L2
  const saltA = new Fr(0xaaaa_2222n);
  const saltB = new Fr(0xbbbb_2222n);
  await l2Deposit(saltA);
  await l2Deposit(saltB);
  console.log("2 L2 deposits registered\n");

  // Per-tx deposit proofs. A against pre-batch, B against post-A.
  console.log("Proving per-tx deposit proofs...");
  const perTxStart = performance.now();
  const depProofA = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltA);

  // Fork state for batch B (post-A).
  const l3StateB = await cloneL3StateWithDeposit(l3State, depProofA);
  const depProofB = await proveDeposit(api, l3StateB, amount, tokenId, alicePk.x, alicePk.y, saltB);
  const perTxMs = performance.now() - perTxStart;
  console.log(`  Per-tx proofs ready: ${fmt(perTxMs)}\n`);

  // NOTE on concurrency: at sub-batch=8, each batch_app_standalone + wrapper
  // prove peaks ~7-9 GiB RSS. Two concurrent proves overflow the 16 GiB WSL
  // memory budget and the system pages to swap — making the total slower than
  // sequential. So this step runs the two sub-batches SEQUENTIALLY. Concurrent
  // proving (via a 2nd bb instance + Promise.all) is correct in principle and
  // was attempted but regressed to ~19 min vs ~3 min sequential. Would be
  // viable with >=24 GiB WSL memory.
  console.log("Building two RECURSIVE sub-batches SEQUENTIALLY...");

  const subBatchStart = performance.now();
  const subBatchAStart = performance.now();
  const artifactA = await buildBatchProofRecursive(api, l3State, [depProofA]);
  const subBatchAMs = performance.now() - subBatchAStart;
  console.log(`  Sub-batch A prove: ${fmt(subBatchAMs)} (wrapper: ${artifactA.tubeProof.length} bytes)`);

  const subBatchBStart = performance.now();
  const artifactB = await buildBatchProofRecursive(api, l3StateB, [depProofB]);
  const subBatchBMs = performance.now() - subBatchBStart;
  console.log(`  Sub-batch B prove: ${fmt(subBatchBMs)} (wrapper: ${artifactB.tubeProof.length} bytes)`);

  const subBatchMs = performance.now() - subBatchStart;
  console.log(`  Sub-batches total (sequential): ${fmt(subBatchMs)}\n`);

  // wrapper_16 prove (serial).
  console.log("Running wrapper_16 aggregation (serial)...");
  const pairStart = performance.now();
  const pairArtifact = await buildWrapper16Proof(api, artifactA, artifactB);
  const pairMs = performance.now() - pairStart;
  console.log(`  wrapper_16 prove: ${fmt(pairMs)}`);
  console.log(`  merged proof: ${pairArtifact.w16Proof.length} bytes, VK: ${pairArtifact.w16Vk.length} bytes\n`);

  const totalProveMs = subBatchMs + pairMs;

  // Submit via submit_batch_16.
  const mergedVkFields = bytesToBigInts(pairArtifact.w16Vk);
  const mergedProofFields = bytesToBigInts(pairArtifact.w16Proof);

  // DA accounting
  const daFields =
    mergedVkFields.length                       // merged VK
    + 1                                         // merged vk hash
    + mergedProofFields.length                  // single merged proof (500 fields, noir-recursive)
    + pairArtifact.mergedPublicInputs.length    // 9 (8 BatchOutput + wrapper_vk_hash)
    + pairArtifact.mergedNullifiers.length      // 32
    + pairArtifact.mergedNoteHashes.length      // 32
    + pairArtifact.mergedDeposits.length        // 16
    + pairArtifact.mergedWithdrawals.length;    // 16
  const daBytes = daFields * 32;
  console.log(`DA: ${daFields} fields (${daBytes} bytes)\n`);

  // Assert client-to-contract boundary shapes — guards the historical
  // SDK silent-truncation seam (SILENT_FAILURE_REVIEW.md) at the merged
  // submission entry point.
  assertRecursiveSubmitShape(
    "submit_batch_16",
    mergedProofFields,
    mergedVkFields,
    pairArtifact.mergedPublicInputs,
    pairArtifact.mergedNullifiers,
    pairArtifact.mergedNoteHashes,
    pairArtifact.mergedDeposits,
    pairArtifact.mergedWithdrawals,
    PUB_COUNT_16,   // 11: 9 BatchOutput + wrapper_vk_hash + per_tx_vk_hashes_commit
    BATCH_16_NULLIFIERS_COUNT,
    BATCH_16_NOTE_HASHES_COUNT,
    BATCH_16_SIZE,
  );

  // Zero-logs placeholder (tests/messages/ exercises real encryption separately).
  const zeroLogs16 = new Array(512).fill(0n);

  console.log("Submitting via submit_batch_16 (1 L2 tx, 1 settle call)...");
  const submitStart = performance.now();
  await l3.methods
    .submit_batch_16(
      mergedVkFields,
      mergedProofFields,
      pairArtifact.mergedPublicInputs,
      pairVkHash,
      pairArtifact.mergedNullifiers,
      pairArtifact.mergedNoteHashes,
      pairArtifact.mergedDeposits,
      pairArtifact.mergedWithdrawals,
      zeroLogs16,
    )
    .send({ from: admin });
  const submitMs = performance.now() - submitStart;
  console.log(`  L2 submit wall-clock: ${fmt(submitMs)}\n`);

  const nonce = await view(l3.methods.get_batch_nonce(), admin);
  const root = await view(l3.methods.get_latest_root(), admin);
  console.log(`Post-state: nonce=${nonce} (expected 1), root=${root.toString().slice(0, 18)}...\n`);

  // Metrics
  const metrics = {
    variant: "recursive-merged-pair-wrapper",
    subBatches: 2,
    realTxsPerSubBatch: 1,
    paddingPerSubBatch: 7,
    totalSlotCapacity: 16,
    totalRealTxs: 2,
    proving: {
      perTxMs,
      subBatchSequentialMs: subBatchMs,
      subBatchAMs,
      subBatchBMs,
      pairWrapperMs: pairMs,
      totalProveMs,
      note: "Sub-batches proved SEQUENTIALLY; concurrent attempt at sub-batch=8 OOM-swapped past 16 GiB. Would be viable with >=24 GiB WSL memory.",
    },
    da: {
      totalFields: daFields,
      totalBytes: daBytes,
      breakdown: {
        mergedVkFields: mergedVkFields.length,
        mergedProofFields: mergedProofFields.length,
        mergedPublicInputs: pairArtifact.mergedPublicInputs.length,
        mergedNullifiers: pairArtifact.mergedNullifiers.length,
        mergedNoteHashes: pairArtifact.mergedNoteHashes.length,
        mergedDeposits: pairArtifact.mergedDeposits.length,
        mergedWithdrawals: pairArtifact.mergedWithdrawals.length,
      },
    },
    l2: {
      submitWallClockMs: submitMs,
      nonceAdvance: Number(nonce),
      note: "submit_batch_16 enqueues ONE settle_batch_merged public call",
    },
    proofSizes: {
      pairWrapperProofBytes: pairArtifact.w16Proof.length,
      pairWrapperVkBytes: pairArtifact.w16Vk.length,
      wrapperProofBytesPerSubBatch: artifactA.tubeProof.length,
    },
    verificationReasoning: "Private circuit contains 1 × verify_honk_proof (of wrapper_16). wrapper_16 itself contains 2 × verify_honk_proof (of wrapper) — this cost is paid during PROVING, not during L2 verification.",
    executionReasoning: "Public call stack runs settle_batch_merged ONCE at batch=16 sizing (loops over 32/32/16/16 arrays). Compared to IVC meta-batch's 2 × settle_batch@batch=8: same total storage ops and state-tree churn, but one public-call context switch saved.",
  };
  writeFileSync(METRICS_OUT, JSON.stringify(metrics, null, 2));
  console.log(`Metrics written to ${METRICS_OUT}`);

  console.log("\n=== step9 SUMMARY ===\n");
  console.log(`  Variant: Recursive merged via wrapper_16 + submit_batch_16`);
  console.log(`  Sub-batches: 2 × (1 real + 7 padding) at batch=8, aggregated`);
  console.log(`  Per-tx proofs:              ${fmt(perTxMs)}`);
  console.log(`  Sub-batch A prove:          ${fmt(subBatchAMs)}`);
  console.log(`  Sub-batch B prove:          ${fmt(subBatchBMs)}`);
  console.log(`  Sub-batch total (seq):      ${fmt(subBatchMs)}`);
  console.log(`  wrapper_16 prove:         ${fmt(pairMs)}`);
  console.log(`  Total proving:              ${fmt(totalProveMs)}`);
  console.log(`  L2 submit wall-clock:       ${fmt(submitMs)}`);
  console.log(`  DA on L2 tx:                ${daBytes} bytes (${daFields} fields)`);
  console.log(`  On-chain nonce advance:     +${Number(nonce)} (one settle_batch_merged call)`);
  console.log(`  Private verify cost:        1 × verify_honk_proof(wrapper_16) in kernel`);
  console.log(`  Public execution cost:      1 × settle_batch_merged@batch=16`);
  console.log(`  Final on-chain proof size:  ${pairArtifact.w16Proof.length} bytes (identical to wrapper)`);

  await api.destroy();
  console.log("\nDone.");
}

main().catch((e) => {
  console.error("\nFATAL:", e.message ?? e);
  console.error(e.stack?.split("\n").slice(0, 12).join("\n"));
  process.exit(1);
});
