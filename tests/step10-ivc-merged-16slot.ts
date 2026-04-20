/**
 * step10-ivc-merged-16slot.ts
 *
 * Path C: IVC sub-batch proving + pair_tube root-rollup aggregation.
 *
 * Combines the fast IVC sub-batch proving (~4 GiB RAM each, concurrent-friendly)
 * with DA-efficient proof aggregation via a pair_tube circuit that verifies
 * each tube proof under ROOT_ROLLUP_HONK (proof type 5), finalizing both
 * accumulated IPA claims natively in-circuit.
 *
 * Flow:
 *   tube[noir-rollup] (x2, concurrent) -> pair_tube[noir-recursive] -> submit_merged_batch
 *
 * pair_tube's output carries no IPA material, so it is emitted at
 * noir-recursive target as a 500-field UltraHonkZK proof matching the
 * contract's UltraHonkZKProof ABI — no SDK truncation.
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
import {
  proveDeposit,
  buildBatchProof,
  computeTubeVkHash,
  computePairTubeVkHash,
  computePerTxVkHashesCommit,
  buildPairTubeProof,
  type BatchArtifact,
  type TxProofResult,
} from "./harness/prover.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const TARGET_DIR = resolve(import.meta.dirname ?? ".", "../target");
const L3_ARTIFACT_PATH = resolve(TARGET_DIR, "l3_ivc_settlement-L3IvcSettlement.json");
const METRICS_OUT = resolve(TARGET_DIR, "step10-metrics.json");

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
  console.log("=== step10: Path C -- IVC sub-batches + pair_tube root-rollup aggregation ===\n");

  console.log(`Connecting to ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error("Cannot reach sandbox."); process.exit(1);
  }

  const api = await Barretenberg.new({ threads: 4 });

  console.log("Computing tube + pair_tube VK hashes...");
  const vkStart = performance.now();
  const { vkHash: tubeVkHash } = await computeTubeVkHash(api);
  const { vkHash: pairTubeVkHash } = await computePairTubeVkHash(api);
  const perTxVkHashesCommit = await computePerTxVkHashesCommit(api);
  console.log(`  tube VK hash:      ${tubeVkHash.toString().slice(0, 18)}...`);
  console.log(`  pair_tube VK hash: ${pairTubeVkHash.toString().slice(0, 18)}... (${fmt(performance.now() - vkStart)})\n`);

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
    [initialStateRoot.toBigInt(), tubeVkHash.toBigInt(), pairTubeVkHash.toBigInt(), perTxVkHashesCommit.toBigInt()],
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

  const saltA = new Fr(0xaaaa_3333n);
  const saltB = new Fr(0xbbbb_3333n);
  await l2Deposit(saltA);
  await l2Deposit(saltB);
  console.log("2 L2 deposits registered (one per sub-batch)\n");

  // Per-tx deposit proofs
  console.log("Proving per-tx deposit proofs...");
  const perTxStart = performance.now();
  const depProofA = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltA);
  const l3StateB = await cloneL3StateWithDeposit(l3State, depProofA);
  const depProofB = await proveDeposit(api, l3StateB, amount, tokenId, alicePk.x, alicePk.y, saltB);
  const perTxMs = performance.now() - perTxStart;
  console.log(`  Per-tx proofs ready: ${fmt(perTxMs)}\n`);

  // Concurrent IVC batch proving (standard noir-rollup tube proofs)
  console.log("Building two IVC batch proofs CONCURRENTLY...");
  const apiA = api;
  const apiB = await Barretenberg.new({ threads: 4 });

  const proveConcurrentStart = performance.now();
  const [artifactA, artifactB] = await Promise.all([
    buildBatchProof(apiA, l3State, [depProofA]),
    buildBatchProof(apiB, l3StateB, [depProofB]),
  ]);
  const proveConcurrentMs = performance.now() - proveConcurrentStart;
  console.log(`  Concurrent IVC batch proving wall-clock: ${fmt(proveConcurrentMs)}`);
  console.log(`    A tube: ${artifactA.tubeProof.length} bytes, B tube: ${artifactB.tubeProof.length} bytes`);

  if (artifactA.newStateRoot.toBigInt() !== artifactB.oldStateRoot.toBigInt()) {
    throw new Error(`State chain broken: A.new=${artifactA.newStateRoot} B.old=${artifactB.oldStateRoot}`);
  }
  console.log("  State chain A.new == B.old: OK\n");

  // pair_tube aggregation
  console.log("Running pair_tube root-rollup aggregation...");
  const pairStart = performance.now();
  const pairArtifact = await buildPairTubeProof(api, artifactA, artifactB);
  const pairMs = performance.now() - pairStart;
  const pairProofFieldCount = Math.floor(pairArtifact.pairProof.length / 32);
  console.log(`  pair_tube prove: ${fmt(pairMs)}`);
  console.log(`  merged proof: ${pairArtifact.pairProof.length} bytes (${pairProofFieldCount} fields), VK: ${pairArtifact.pairVk.length} bytes\n`);
  if (pairProofFieldCount === 500) {
    console.log("  ^ 500 fields -- matches contract UltraHonkZKProof ABI (no SDK truncation)\n");
  } else if (pairProofFieldCount === 519) {
    console.log("  ^ 519 fields -- will be silently truncated to 500 by the SDK on submit\n");
  } else {
    console.log(`  ^ unexpected field count (${pairProofFieldCount}); check pair_tube proving target\n`);
  }

  const totalProveMs = proveConcurrentMs + pairMs;

  // Submit via submit_merged_batch
  const mergedVkFields = bytesToBigInts(pairArtifact.pairVk);
  const mergedProofFields = bytesToBigInts(pairArtifact.pairProof);

  const daFields =
    mergedVkFields.length
    + 1
    + mergedProofFields.length
    + pairArtifact.mergedPublicInputs.length
    + pairArtifact.mergedNullifiers.length
    + pairArtifact.mergedNoteHashes.length
    + pairArtifact.mergedDeposits.length
    + pairArtifact.mergedWithdrawals.length;
  const daBytes = daFields * 32;
  console.log(`DA: ${daFields} fields (${daBytes} bytes)\n`);

  // Zero-logs placeholder for merged batch (512 fields = 16 tx * 32).
  const zeroLogsMerged = new Array(512).fill(0n);

  console.log("Submitting via submit_merged_batch (1 L2 tx, 1 settle call)...");
  const submitStart = performance.now();
  await l3.methods
    .submit_merged_batch(
      mergedVkFields,
      mergedProofFields,
      pairArtifact.mergedPublicInputs,
      pairTubeVkHash,
      pairArtifact.mergedNullifiers,
      pairArtifact.mergedNoteHashes,
      pairArtifact.mergedDeposits,
      pairArtifact.mergedWithdrawals,
      zeroLogsMerged,
    )
    .send({ from: admin });
  const submitMs = performance.now() - submitStart;
  console.log(`  L2 submit wall-clock: ${fmt(submitMs)}\n`);

  const nonce = await view(l3.methods.get_batch_nonce(), admin);
  const root = await view(l3.methods.get_latest_root(), admin);
  console.log(`Post-state: nonce=${nonce} (expected 1), root=${root.toString().slice(0, 18)}...\n`);

  // Metrics
  const metrics = {
    variant: "ivc-merged-pair-tube",
    description: "Path C: IVC sub-batches (concurrent) + pair_tube root-rollup aggregation -> single merged proof",
    subBatches: 2,
    realTxsPerSubBatch: 1,
    paddingPerSubBatch: 7,
    totalSlotCapacity: 16,
    totalRealTxs: 2,
    proving: {
      perTxMs,
      concurrentIvcBatchProveMs: proveConcurrentMs,
      pairTubeMs: pairMs,
      totalProveMs,
    },
    da: { totalFields: daFields, totalBytes: daBytes },
    l2: { submitWallClockMs: submitMs, nonceAdvance: Number(nonce) },
    proofSizes: {
      pairTubeProofBytes: pairArtifact.pairProof.length,
      pairTubeProofFields: pairProofFieldCount,
      pairTubeVkBytes: pairArtifact.pairVk.length,
      tubeProofBytesPerSubBatch: artifactA.tubeProof.length,
    },
  };
  writeFileSync(METRICS_OUT, JSON.stringify(metrics, null, 2));
  console.log(`Metrics written to ${METRICS_OUT}`);

  console.log("\n=== step10 SUMMARY ===\n");
  console.log(`  Variant: Path C -- IVC sub-batches + pair_tube root-rollup aggregation`);
  console.log(`  Sub-batches: 2 x (1 real + 7 padding) at batch=8  -> 16 slot capacity`);
  console.log(`  Per-tx proofs wall-clock:        ${fmt(perTxMs)}`);
  console.log(`  Concurrent IVC batch proving:    ${fmt(proveConcurrentMs)}`);
  console.log(`  pair_tube aggregation:           ${fmt(pairMs)}`);
  console.log(`  Total proving wall-clock:        ${fmt(totalProveMs)}`);
  console.log(`  L2 submit wall-clock:            ${fmt(submitMs)}`);
  console.log(`  DA on L2 tx:                     ${daBytes} bytes (${daFields} fields)`);
  console.log(`  On-chain nonce advance:          +${Number(nonce)} (one settle_batch_merged call)`);
  console.log(`  Private verify cost:             1 x verify_honk_proof(pair_tube) in kernel`);
  console.log(`  Public execution cost:           1 x settle_batch_merged@batch=16`);
  console.log(`  Final on-chain proof size:       ${pairArtifact.pairProof.length} bytes`);

  await api.destroy();
  await apiB.destroy();
  console.log("\nDone.");
}

main().catch((e) => {
  console.error("\nFATAL:", e.message ?? e);
  console.error(e.stack?.split("\n").slice(0, 12).join("\n"));
  process.exit(1);
});
