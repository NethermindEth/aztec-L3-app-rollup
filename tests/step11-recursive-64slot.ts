/**
 * step11-recursive-quad-64slot.ts
 *
 * Recursive pipeline with 64-slot aggregation via a 3-level binary tree:
 *
 *   wrapper x8  (8 sub-batches, 8 slots each)
 *     -> wrapper_16 x4  (16 slots each)
 *       -> wrapper_32 x2  (32 slots each)
 *         -> wrapper_64 x1  (64 slots)  -->  submit_batch_64
 *
 * Total: 15 sequential proves. Submitted to L2 via submit_batch_64,
 * causing a single settle_batch_quad public call (nonce += 1) that
 * consumes up to 64 deposit slots and registers up to 64 withdrawal
 * claims.
 *
 * IMPORTANT -- SOUNDNESS LIMITATION:
 *   Sandbox (PXE_PROVER=none) treats verify_honk_proof as a no-op -- the
 *   same limitation as step5 and step9. This script exercises prover
 *   correctness + ABI plumbing + contract state machine, but NOT on-chain
 *   proof gate soundness for submit_batch_64. That limitation applies
 *   identically to every submit_* entry point. External bb verify coverage
 *   for the 64-slot path is provided separately by running:
 *       INCLUDE_QUAD=1 npx tsx verify-with-bb-cli.ts
 *       npx tsx verify-negative-tests.ts
 *   See SILENT_FAILURE_REVIEW.md.
 *
 * Runtime and memory: peak RSS per prove is ~7-10 GiB; sequential. Total
 * wall-clock likely 45-75 minutes on a 16-24 GiB WSL host. Not a casual
 * CI test.
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
  buildBatchProofRecursive,
  buildWrapper16Proof,
  buildWrapper32Proof,
  buildWrapper64Proof,
  computeWrapperVkHash,
  computeWrapper16VkHash,
  computeWrapper32VkHash,
  computeWrapper64VkHash,
  proveDeposit,
  type BatchArtifact,
} from "./harness/prover-recursive.js";
import {
  BATCH_64_SIZE,
  BATCH_64_NULLIFIERS_COUNT,
  BATCH_64_NOTE_HASHES_COUNT,
  PUB_COUNT_64,
  assertRecursiveSubmitShape,
} from "./harness/recursive-shapes.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_recursive_settlement-L3RecursiveSettlement.json",
);
const METRICS_OUT = resolve(import.meta.dirname ?? ".", "../target/step11-metrics.json");

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
  console.log("=== step11: Recursive pipeline with wrapper_64 (64-slot) ===\n");

  console.log(`Connecting to ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error("Cannot reach sandbox."); process.exit(1);
  }

  const api = await Barretenberg.new({ threads: 4 });

  // VK hashes for the 4 levels (wrapper, wrapper_16, wrapper_32,
  // wrapper_64). All are immutable constructor args on L3RecursiveSettlement.
  console.log("Computing VK hashes for all 4 aggregation levels...");
  const vkStart = performance.now();
  const { vkHash: wrapperVkHash } = await computeWrapperVkHash(api);
  const { vkHash: pairVkHash } = await computeWrapper16VkHash(api);
  const { vkHash: ppVkHash } = await computeWrapper32VkHash(api);
  const { vkHash: quadVkHash } = await computeWrapper64VkHash(api);
  console.log(`  VK hashes ready (${fmt(performance.now() - vkStart)})\n`);

  // Accounts.
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin, aliceL2] = await Promise.all(
    testAccounts.slice(0, 2).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  // Deploy.
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
    [
      initialStateRoot.toBigInt(),
      wrapperVkHash.toBigInt(),
      pairVkHash.toBigInt(),
      ppVkHash.toBigInt(),
      quadVkHash.toBigInt(),
    ],
    "constructor",
  ).send({ from: admin });

  await token.methods.mint_to_public(l3.address, 10_000_000n).send({ from: admin });
  await token.methods.mint_to_private(aliceL2, 1_000_000n).send({ from: admin });
  console.log(`  Token: ${token.address}`);
  console.log(`  L3:    ${l3.address}\n`);

  // Shared deposit params.
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

  // Register 8 deposits on L2 (one per sub-batch).
  console.log("Registering 8 L2 deposits...");
  const salts: Fr[] = [];
  for (let i = 0; i < 8; i++) {
    const salt = new Fr(BigInt(0xaaaa_0000 + i));
    salts.push(salt);
    await l2Deposit(salt);
  }
  console.log("  8 L2 deposits registered\n");

  // -------------------------------------------------------------------------
  // Level 0: 8 sub-batches (wrapper proofs), sequential.
  // buildBatchProofRecursive mutates l3State in place, so sub-batch i+1
  // picks up post-i state naturally.
  // -------------------------------------------------------------------------
  console.log("Proving 8 sub-batches (wrapper x 8) sequentially...");
  const subStart = performance.now();
  const subBatches: BatchArtifact[] = [];
  for (let i = 0; i < 8; i++) {
    const sStart = performance.now();
    const dep = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, salts[i]);
    const sb = await buildBatchProofRecursive(api, l3State, [dep]);
    subBatches.push(sb);
    console.log(`  sub-batch #${i}: ${fmt(performance.now() - sStart)}`);
  }
  const subMs = performance.now() - subStart;
  console.log(`  total sub-batch proving: ${fmt(subMs)}\n`);

  // -------------------------------------------------------------------------
  // Level 1: 4 wrapper_16s from pairs (0,1), (2,3), (4,5), (6,7).
  // -------------------------------------------------------------------------
  console.log("Proving 4 wrapper_16s (16-slot each)...");
  const pairStart = performance.now();
  const pair01 = await buildWrapper16Proof(api, subBatches[0], subBatches[1]);
  const pair23 = await buildWrapper16Proof(api, subBatches[2], subBatches[3]);
  const pair45 = await buildWrapper16Proof(api, subBatches[4], subBatches[5]);
  const pair67 = await buildWrapper16Proof(api, subBatches[6], subBatches[7]);
  const pairMs = performance.now() - pairStart;
  console.log(`  4 wrapper_16s total: ${fmt(pairMs)}\n`);

  // -------------------------------------------------------------------------
  // Level 2: 2 wrapper_32s from pair pairs (01,23) and (45,67).
  // -------------------------------------------------------------------------
  console.log("Proving 2 wrapper_32s (32-slot each)...");
  const ppStart = performance.now();
  const ppAB = await buildWrapper32Proof(api, pair01, pair23);
  const ppCD = await buildWrapper32Proof(api, pair45, pair67);
  const ppMs = performance.now() - ppStart;
  console.log(`  2 wrapper_32s total: ${fmt(ppMs)}\n`);

  // -------------------------------------------------------------------------
  // Level 3: wrapper_64 (the final 64-slot merged proof).
  // -------------------------------------------------------------------------
  console.log("Proving wrapper_64 (64-slot final)...");
  const quadStart = performance.now();
  const quad = await buildWrapper64Proof(api, ppAB, ppCD);
  const quadMs = performance.now() - quadStart;
  console.log(`  wrapper_64: ${fmt(quadMs)}\n`);

  const totalProveMs = subMs + pairMs + ppMs + quadMs;

  // -------------------------------------------------------------------------
  // Submit via submit_batch_64.
  // -------------------------------------------------------------------------
  const quadVkFields = bytesToBigInts(quad.w64Vk);
  const quadProofFields = bytesToBigInts(quad.w64Proof);

  const daFields =
    quadVkFields.length                  // 115
    + 1                                  // vk hash
    + quadProofFields.length             // 500
    + quad.mergedPublicInputs.length     // 11 (8 BatchOutput + wrapper/pair/pp VK hashes)
    + quad.mergedNullifiers.length       // 128
    + quad.mergedNoteHashes.length       // 128
    + quad.mergedDeposits.length         // 64
    + quad.mergedWithdrawals.length;     // 64
  const daBytes = daFields * 32;
  console.log(`DA: ${daFields} fields (${daBytes} bytes)\n`);

  // Boundary shape assertion at the client-to-contract seam (re-arms the
  // SDK silent-truncation class; see SILENT_FAILURE_REVIEW.md).
  assertRecursiveSubmitShape(
    "submit_batch_64",
    quadProofFields,
    quadVkFields,
    quad.mergedPublicInputs,
    quad.mergedNullifiers,
    quad.mergedNoteHashes,
    quad.mergedDeposits,
    quad.mergedWithdrawals,
    PUB_COUNT_64,   // 11: 8 BatchOutput + wrapper/pair/pp VK hashes
    BATCH_64_NULLIFIERS_COUNT,
    BATCH_64_NOTE_HASHES_COUNT,
    BATCH_64_SIZE,
  );

  console.log("Submitting via submit_batch_64 (1 L2 tx, 1 settle call)...");
  const submitStart = performance.now();
  await l3.methods
    .submit_batch_64(
      quadVkFields,
      quadProofFields,
      quad.mergedPublicInputs,
      quadVkHash.toBigInt(),
      quad.mergedNullifiers,
      quad.mergedNoteHashes,
      quad.mergedDeposits,
      quad.mergedWithdrawals,
    )
    .send({ from: admin });
  const submitMs = performance.now() - submitStart;
  console.log(`  L2 submit wall-clock: ${fmt(submitMs)}\n`);

  const nonce = await view(l3.methods.get_batch_nonce(), admin);
  const root = await view(l3.methods.get_latest_root(), admin);
  console.log(`Post-state: nonce=${nonce} (expected 1), root=${root.toString().slice(0, 18)}...\n`);

  const metrics = {
    variant: "recursive-quad-wrapper",
    subBatches: 8,
    realTxsPerSubBatch: 1,
    paddingPerSubBatch: 7,
    totalSlotCapacity: 64,
    timingMs: {
      subBatches: subMs,
      pairWrappers: pairMs,
      pairPairWrappers: ppMs,
      quadWrapper: quadMs,
      totalProving: totalProveMs,
      l2Submit: submitMs,
    },
    daFields,
    daBytes,
    proofBytes: quad.w64Proof.length,
    vkBytes: quad.w64Vk.length,
  };
  writeFileSync(METRICS_OUT, JSON.stringify(metrics, null, 2));
  console.log(`Metrics: ${METRICS_OUT}`);

  await api.destroy();
}

main().catch((e) => {
  console.error("\nFATAL:", e?.message ?? e);
  console.error(e?.stack?.split("\n").slice(0, 10).join("\n"));
  process.exit(1);
});
