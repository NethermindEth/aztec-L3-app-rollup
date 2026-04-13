/**
 * step7-meta-batch-ivc.ts
 *
 * Minimal cost-comparison test for the IVC path at batch=8.
 *
 * Two submissions on the same contract:
 *   (A) submit_batch          -- 1 batch of 8 (1 real deposit + 7 padding)
 *   (B) submit_two_batches    -- 2 batches of 8 in ONE L2 tx (2 real deposits + 14 padding)
 *
 * Measures, per submission:
 *   - Client wall-clock for proof generation (buildBatchProof)
 *   - DA: byte count of L2-tx function arguments (tube VK + proofs + settle data)
 *   - L2: daGas, l2Gas, teardownGas, publicGas from the tx receipt
 *   - Observations: private verification constraint scaling, public mana scaling
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
import { readFileSync } from "fs";
import { resolve } from "path";

import { TestL3State } from "./harness/state.js";
import {
  proveDeposit,
  buildBatchProof,
  computeTubeVkHash,
  type BatchArtifact,
} from "./harness/prover.js";

// -------------------------------------------------------------------------
// Config
// -------------------------------------------------------------------------

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_ivc_settlement-L3IvcSettlement.json",
);

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

// Convert raw bytes (32 per field) to field array of bigint.
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

// DA accounting helper: count fields going into L2 tx args for each variant.
interface ArgProfile {
  tubeVkFields: number;
  tubeProofFields: number;
  tubePublicInputs: number;
  tubeVkHash: number;
  nullifiers: number;
  noteHashes: number;
  deposits: number;
  withdrawals: number;
}
function argFieldCount(p: ArgProfile): number {
  return p.tubeVkFields + p.tubeProofFields + p.tubePublicInputs +
         p.tubeVkHash + p.nullifiers + p.noteHashes + p.deposits + p.withdrawals;
}

// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

async function main() {
  console.log("=== step7: IVC single-batch vs two-batch meta (batch=8) ===\n");

  // --- Preflight ---
  console.log(`Connecting to ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error("Cannot reach sandbox."); process.exit(1);
  }

  const api = await Barretenberg.new({ threads: 4 });

  console.log("Computing tube VK hash...");
  const tStart = performance.now();
  const { vkHash: tubeVkHash } = await computeTubeVkHash(api);
  console.log(`  VK hash: ${tubeVkHash.toString().slice(0, 18)}... (${fmt(performance.now() - tStart)})\n`);

  // --- Accounts ---
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin, aliceL2] = await Promise.all(
    testAccounts.slice(0, 2).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  // --- Deploy ---
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
    [initialStateRoot.toBigInt(), tubeVkHash.toBigInt()],
    "constructor",
  ).send({ from: admin });

  await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });
  await token.methods.mint_to_private(aliceL2, 10_000n).send({ from: admin });
  console.log(`  Token: ${token.address}`);
  console.log(`  L3:    ${l3.address}\n`);

  // --- Shared setup for 2 deposits ---
  const aliceSecret = new Fr(0xdead_beefn);
  const alicePk = await derivePubkey(aliceSecret);
  const alicePkHash = await l3State.hashPubkey(alicePk.x, alicePk.y);
  const tokenId = new Fr(token.address.toBigInt());
  const amount = new Fr(100n);

  // L2-register a deposit and return the salt used.
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
  // Case A: single submit_batch (1 batch, 1 real tx, 7 padding)
  // ==================================================================
  console.log("=== Case A: submit_batch (1 batch = 1 real + 7 padding) ===");

  const saltA = new Fr(0xaaaa_1111n);
  await l2Deposit(saltA);
  console.log("  L2 deposit A registered");

  const proveStartA = performance.now();
  const depositProofA = await proveDeposit(
    api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltA,
  );
  const artifactA = await buildBatchProof(api, l3State, [depositProofA]);
  const proveMsA = performance.now() - proveStartA;
  console.log(`  Proved in ${fmt(proveMsA)} (tube: ${artifactA.tubeProof.length} bytes)`);

  // Convert to contract args
  const tubeVkFieldsA = bytesToBigInts(artifactA.tubeVk);
  const tubeProofFieldsA = bytesToBigInts(artifactA.tubeProof);

  // DA profile for submit_batch
  const profileA: ArgProfile = {
    tubeVkFields: tubeVkFieldsA.length,       // 115
    tubeProofFields: tubeProofFieldsA.length, // 500
    tubePublicInputs: artifactA.tubePublicInputs.length, // 8
    tubeVkHash: 1,
    nullifiers: artifactA.settleInputs.nullifiers.length,       // 16 (batch=8)
    noteHashes: artifactA.settleInputs.noteHashes.length,       // 16
    deposits: artifactA.settleInputs.depositNullifiers.length,  // 8
    withdrawals: artifactA.settleInputs.withdrawalClaims.length,// 8
  };
  const fieldsA = argFieldCount(profileA);
  const bytesA = fieldsA * 32;
  console.log(`  Args: ${fieldsA} fields (${bytesA} bytes)`);

  const submitStartA = performance.now();
  await l3.methods
    .submit_batch(
      tubeVkFieldsA,
      tubeProofFieldsA,
      artifactA.tubePublicInputs,
      tubeVkHash,
      artifactA.settleInputs.nullifiers,
      artifactA.settleInputs.noteHashes,
      artifactA.settleInputs.depositNullifiers,
      artifactA.settleInputs.withdrawalClaims,
    )
    .send({ from: admin });
  const submitMsA = performance.now() - submitStartA;
  console.log(`  L2 submit+wait: ${fmt(submitMsA)}`);

  const onChainNonceA = await view(l3.methods.get_batch_nonce(), admin);
  const onChainRootA = await view(l3.methods.get_latest_root(), admin);
  console.log(`  Post-state: nonce=${onChainNonceA} root=${onChainRootA.toString().slice(0, 18)}...\n`);

  // ==================================================================
  // Case B: submit_two_batches (2 batches, 2 real + 14 padding, 1 L2 tx)
  // ==================================================================
  console.log("=== Case B: submit_two_batches (2 batches in 1 L2 tx) ===");

  // Prepare batch 1 for case B (fresh state — l3State has already advanced from A;
  // we continue the chain, so B1 old_state = current l3State.stateRoot).
  const saltB1 = new Fr(0xbbbb_1111n);
  const saltB2 = new Fr(0xbbbb_2222n);
  await l2Deposit(saltB1);
  await l2Deposit(saltB2);
  console.log("  L2 deposits B1, B2 registered");

  const proveStartB = performance.now();
  // Batch B1: must be proved against current state, advances state after.
  const depB1 = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltB1);
  const artifactB1 = await buildBatchProof(api, l3State, [depB1]);
  // Batch B2: proved against the state AFTER B1 (l3State has advanced internally).
  const depB2 = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltB2);
  const artifactB2 = await buildBatchProof(api, l3State, [depB2]);
  const proveMsB = performance.now() - proveStartB;
  console.log(`  Proved both in ${fmt(proveMsB)}`);

  // Convert to contract args
  const tubeVkFieldsB1 = bytesToBigInts(artifactB1.tubeVk);
  const tubeProofFieldsB1 = bytesToBigInts(artifactB1.tubeProof);
  const tubeProofFieldsB2 = bytesToBigInts(artifactB2.tubeProof);

  // Sanity: both batches share the same tube VK (same circuit)
  const vkB2 = bytesToBigInts(artifactB2.tubeVk);
  if (tubeVkFieldsB1.length !== vkB2.length || tubeVkFieldsB1.some((v, i) => v !== vkB2[i])) {
    console.warn("  WARN: tube VKs differ between batches (unexpected)");
  } else {
    console.log("  tube VK identical across batches (shared arg)");
  }

  // DA profile for submit_two_batches: ONE vk, TWO proof+settle blocks.
  const profileB: ArgProfile = {
    tubeVkFields: tubeVkFieldsB1.length,                              // 115
    tubeProofFields: tubeProofFieldsB1.length + tubeProofFieldsB2.length, // 2 × 500
    tubePublicInputs: artifactB1.tubePublicInputs.length + artifactB2.tubePublicInputs.length, // 2 × 8
    tubeVkHash: 1,
    nullifiers: artifactB1.settleInputs.nullifiers.length + artifactB2.settleInputs.nullifiers.length, // 2 × 16
    noteHashes: artifactB1.settleInputs.noteHashes.length + artifactB2.settleInputs.noteHashes.length, // 2 × 16
    deposits: artifactB1.settleInputs.depositNullifiers.length + artifactB2.settleInputs.depositNullifiers.length, // 2 × 8
    withdrawals: artifactB1.settleInputs.withdrawalClaims.length + artifactB2.settleInputs.withdrawalClaims.length, // 2 × 8
  };
  const fieldsB = argFieldCount(profileB);
  const bytesB = fieldsB * 32;
  console.log(`  Args: ${fieldsB} fields (${bytesB} bytes)`);

  const submitStartB = performance.now();
  await l3.methods
    .submit_two_batches(
      tubeVkFieldsB1,
      tubeVkHash,
      tubeProofFieldsB1,
      artifactB1.tubePublicInputs,
      artifactB1.settleInputs.nullifiers,
      artifactB1.settleInputs.noteHashes,
      artifactB1.settleInputs.depositNullifiers,
      artifactB1.settleInputs.withdrawalClaims,
      tubeProofFieldsB2,
      artifactB2.tubePublicInputs,
      artifactB2.settleInputs.nullifiers,
      artifactB2.settleInputs.noteHashes,
      artifactB2.settleInputs.depositNullifiers,
      artifactB2.settleInputs.withdrawalClaims,
    )
    .send({ from: admin });
  const submitMsB = performance.now() - submitStartB;
  console.log(`  L2 submit+wait: ${fmt(submitMsB)}`);

  const onChainNonceB = await view(l3.methods.get_batch_nonce(), admin);
  const onChainRootB = await view(l3.methods.get_latest_root(), admin);
  console.log(`  Post-state: nonce=${onChainNonceB} root=${onChainRootB.toString().slice(0, 18)}...\n`);

  // ==================================================================
  // Comparison
  // ==================================================================
  console.log("=== COMPARISON ===\n");
  console.log("Client-side proving (wall-clock):");
  console.log(`  A  (1 batch):        ${fmt(proveMsA)}`);
  console.log(`  B  (2 batches):      ${fmt(proveMsB)}       ratio B/A = ${(proveMsB/proveMsA).toFixed(2)}x`);
  console.log(`  B per-batch:         ${fmt(proveMsB / 2)}\n`);

  console.log("L2 submission wall-clock (submit + wait):");
  console.log(`  A (submit_batch):         ${fmt(submitMsA)}`);
  console.log(`  B (submit_two_batches):   ${fmt(submitMsB)}\n`);

  console.log("Function-arg DA (fields -> bytes):");
  console.log(`  A: ${fieldsA.toString().padStart(4)} fields = ${bytesA.toString().padStart(6)} bytes`);
  console.log(`      vk=${profileA.tubeVkFields} proof=${profileA.tubeProofFields} pub=${profileA.tubePublicInputs}`);
  console.log(`      nulls=${profileA.nullifiers} nh=${profileA.noteHashes} dep=${profileA.deposits} wit=${profileA.withdrawals} vkHash=1`);
  console.log(`  B: ${fieldsB.toString().padStart(4)} fields = ${bytesB.toString().padStart(6)} bytes`);
  console.log(`      vk=${profileB.tubeVkFields} (shared) proof=${profileB.tubeProofFields} (2x) pub=${profileB.tubePublicInputs} (2x)`);
  console.log(`      nulls=${profileB.nullifiers} (2x) nh=${profileB.noteHashes} (2x) dep=${profileB.deposits} (2x) wit=${profileB.withdrawals} (2x) vkHash=1`);
  console.log(`  Ratio B/A:            ${(bytesB/bytesA).toFixed(2)}x`);
  console.log(`  DA per batch (A):     ${bytesA.toString().padStart(6)} bytes`);
  console.log(`  DA per batch (B):     ${(bytesB/2).toFixed(0).padStart(6)} bytes`);
  console.log(`  Savings per batch:    ${(bytesA - bytesB/2).toFixed(0)} bytes (${(100*(1 - bytesB/(2*bytesA))).toFixed(1)}% off baseline)\n`);

  console.log("On-chain state outcomes:");
  console.log(`  After Case A: nonce = ${onChainNonceA} (expected 1)`);
  console.log(`  After Case B: nonce = ${onChainNonceB} (expected 3 — A's 1 + B's 2)`);
  console.log(`  A root matches local: ${onChainRootA === l3State.stateRoot.toBigInt() || "(drifted, see note)"}`);
  console.log("\nNote: gas receipts aren't surfaced in this Aztec.js version via .send();");
  console.log("      approximate verification/public cost separately from the private-circuit");
  console.log("      constraint count (submit_two_batches compiles with 2x verify_honk_proof)");
  console.log("      and settle_batch's per-batch public mana (runs 2x inside Case B's L2 tx).");

  await api.destroy();
  console.log("\nDone.");
}

main().catch((e) => {
  console.error("\nFATAL:", e.message ?? e);
  console.error(e.stack?.split("\n").slice(0, 12).join("\n"));
  process.exit(1);
});
