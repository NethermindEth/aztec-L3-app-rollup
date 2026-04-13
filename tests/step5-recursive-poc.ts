/**
 * Recursive UltraHonk PoC -- full e2e lifecycle.
 *
 * Same lifecycle as step4-full-lifecycle.ts but uses the recursive
 * UltraHonk wrapper pipeline instead of IVC/Chonk/tube:
 *
 *   batch_app (UltraHonk) -> wrapper (UltraHonk) -> L2 verification
 *
 * No IVC kernels, no Chonk, no AztecClientBackend.
 *
 * Tests:
 *   1. Deploy with wrapper VK hash
 *   2. Deposit (Alice)
 *   3. Payment (Alice -> Bob)
 *   4. Withdraw (Bob)
 *   5. Claim on L2 (Bob)
 *   6. Double-claim rejection
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
  buildBatchProofRecursive,
  computeWrapperVkHash,
  proveDeposit,
  provePayment,
  proveWithdraw,
  type TxProofResult,
  type BatchArtifact,
} from "./harness/prover-recursive.js";

// -------------------------------------------------------------------------
// Config
// -------------------------------------------------------------------------

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_recursive_settlement-L3RecursiveSettlement.json",
);

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(`ASSERT FAILED: ${msg}`);
}

async function derivePubkey(secret: Fr) {
  return Grumpkin.mul(Grumpkin.generator, secret);
}

async function view(method: any, from: any): Promise<bigint> {
  const r = await method.simulate({ from });
  return BigInt((r.result ?? r).toString());
}

// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

async function main() {
  console.log("=== Recursive UltraHonk PoC ===\n");
  console.log(`Connecting to sandbox at ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try {
    await waitForNode(node);
  } catch {
    console.error(`Cannot reach sandbox. Run 'docker compose up -d' in tests/.`);
    process.exit(1);
  }
  console.log("Connected.\n");

  const api = await Barretenberg.new({ threads: 4 });

  // Compute wrapper VK hash (replaces tube VK hash).
  console.log("Computing wrapper VK hash...");
  const startVk = performance.now();
  const { vkHash: wrapperVkHash } = await computeWrapperVkHash(api);
  console.log(`  wrapper VK hash: ${wrapperVkHash.toString().slice(0, 18)}...`);
  console.log(`  (${((performance.now() - startVk) / 1000).toFixed(1)}s)\n`);

  // Wallet + accounts.
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin, aliceL2, bobL2] = await Promise.all(
    testAccounts.slice(0, 3).map(async (acc: any) =>
      (await wallet.createSchnorrAccount(acc.secret, acc.salt, acc.signingKey)).address,
    ),
  );
  console.log(`  admin:   ${admin}`);
  console.log(`  aliceL2: ${aliceL2}`);
  console.log(`  bobL2:   ${bobL2}`);

  // =====================================================================
  // Step 1: Deploy
  // =====================================================================
  console.log("\n=== Step 1: Deploy ===");

  const { contract: token } = await TokenContract.deploy(wallet, admin, "TestToken", "TT", 18)
    .send({ from: admin });
  console.log(`  Token: ${token.address}`);

  const l3State = await TestL3State.create();
  const initialStateRoot = l3State.stateRoot;

  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT_PATH, "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(
    wallet,
    l3Artifact,
    [initialStateRoot.toBigInt(), wrapperVkHash.toBigInt()],
    "constructor",
  ).send({ from: admin });
  console.log(`  L3:    ${l3.address}`);

  await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });
  console.log(`  L3 funded with 1M public tokens`);

  assert(
    (await view(l3.methods.get_latest_root(), admin)) === initialStateRoot.toBigInt(),
    "initial root",
  );
  assert((await view(l3.methods.get_batch_nonce(), admin)) === 0n, "initial nonce");
  console.log("  PASS\n");

  // Helper: build recursive batch and submit.
  async function submitRecursiveBatch(
    txProofs: TxProofResult[],
    label: string,
  ): Promise<BatchArtifact> {
    console.log(`  Building recursive batch (${label})...`);
    const startBatch = performance.now();
    const artifact = await buildBatchProofRecursive(api, l3State, txProofs);
    const elapsed = ((performance.now() - startBatch) / 1000).toFixed(1);
    console.log(
      `    ${artifact.depositCount}D / ${artifact.paymentCount}P / ` +
        `${artifact.withdrawCount}W / ${artifact.paddingCount}pad`,
    );
    console.log(`    Wrapper proof: ${artifact.tubeProof.length} bytes (${elapsed}s)`);

    const tubeVkFields = vkBytesToFields(artifact.tubeVk);
    const tubeProofFields = proofBytesToFields(artifact.tubeProof);

    await l3.methods
      .submit_batch(
        tubeVkFields,
        tubeProofFields,
        artifact.tubePublicInputs,
        wrapperVkHash,
        artifact.settleInputs.nullifiers,
        artifact.settleInputs.noteHashes,
        artifact.settleInputs.depositNullifiers,
        artifact.settleInputs.withdrawalClaims,
      )
      .send({ from: admin });

    const onChainRoot = await view(l3.methods.get_latest_root(), admin);
    assert(
      onChainRoot === l3State.stateRoot.toBigInt(),
      `root mismatch after ${label}: on-chain=${onChainRoot}, local=${l3State.stateRoot.toBigInt()}`,
    );
    console.log(`    Root matches local state model`);
    return artifact;
  }

  // =====================================================================
  // Step 2: Deposit (Alice)
  // =====================================================================
  console.log("=== Step 2: Deposit (Alice) ===");

  const aliceSecret = new Fr(0xdead_beefn);
  const alicePk = await derivePubkey(aliceSecret);
  const alicePkHash = await l3State.hashPubkey(alicePk.x, alicePk.y);
  const tokenId = new Fr(token.address.toBigInt());
  const depositAmount = new Fr(500n);
  const depositSalt = Fr.random();

  console.log("  Minting 1000 private tokens to Alice...");
  await token.methods.mint_to_private(aliceL2, 1000n).send({ from: admin });

  const depositNonce = Fr.random();
  const transferAction = token.methods.transfer_to_public(
    aliceL2, l3.address, depositAmount.toBigInt(), depositNonce,
  );
  const authwit = await wallet.createAuthWit(aliceL2, {
    caller: l3.address,
    action: transferAction,
  });
  console.log("  Authwit created");

  await l3.methods
    .deposit(token.address, depositAmount, alicePk.x, alicePk.y, depositSalt, depositNonce)
    .send({ from: aliceL2, authWitnesses: [authwit] });
  console.log("  deposit() OK");

  const depositHash = await l3State.depositHash(alicePkHash, depositAmount, tokenId, depositSalt);
  l3State.registerDeposit(depositHash);

  console.log("  Proving deposit circuit...");
  const depositProof = await proveDeposit(
    api, l3State, depositAmount, tokenId, alicePk.x, alicePk.y, depositSalt,
  );
  console.log(`  Deposit proved (${depositProof.proof.length} bytes)`);

  const batch1 = await submitRecursiveBatch([depositProof], "deposit batch");

  assert((await view(l3.methods.get_batch_nonce(), admin)) === 1n, "nonce=1");
  assert(batch1.depositCount === 1, "1 deposit in batch");

  const aliceNoteIdx = batch1.noteInsertionIndices[0][0];
  assert(aliceNoteIdx >= 0, "deposit note inserted in tree");
  const aliceNote = l3State.trackNote(
    alicePkHash, depositAmount, tokenId, depositSalt,
    depositProof.noteHashes[0], aliceNoteIdx,
  );
  console.log(`  Alice's note at tree index ${aliceNoteIdx}`);
  console.log("  PASS\n");

  // =====================================================================
  // Step 3: Payment (Alice -> Bob)
  // =====================================================================
  console.log("=== Step 3: Payment (Alice -> Bob) ===");

  const bobSecret = new Fr(0xcafe_baben);
  const bobPk = await derivePubkey(bobSecret);
  const bobPkHash = await l3State.hashPubkey(bobPk.x, bobPk.y);
  const paymentSalts: [Fr, Fr] = [Fr.random(), Fr.random()];

  console.log("  Proving payment circuit (Alice -> Bob, 500)...");
  const paymentProof = await provePayment(
    api, l3State, aliceSecret, [aliceNote],
    bobPk.x, bobPk.y, depositAmount, paymentSalts,
  );
  console.log(`  Payment proved (${paymentProof.proof.length} bytes)`);

  l3State.spendNote(aliceNote);
  const batch2 = await submitRecursiveBatch([paymentProof], "payment batch");

  assert((await view(l3.methods.get_batch_nonce(), admin)) === 2n, "nonce=2");
  assert(batch2.paymentCount === 1, "1 payment in batch");

  const bobNoteIdx = batch2.noteInsertionIndices[0][0];
  assert(bobNoteIdx >= 0, "recipient note inserted");
  const bobNote = l3State.trackNote(
    bobPkHash, depositAmount, tokenId, paymentSalts[0],
    paymentProof.noteHashes[0], bobNoteIdx,
  );
  console.log(`  Bob's note at tree index ${bobNoteIdx}`);
  console.log("  PASS\n");

  // =====================================================================
  // Step 4: Withdraw (Bob)
  // =====================================================================
  console.log("=== Step 4: Withdraw (Bob) ===");

  const claimSalt = Fr.random();
  const l2BobRecipient = new Fr(bobL2.toBigInt());

  console.log("  Proving withdraw circuit (Bob, 500)...");
  const withdrawProof = await proveWithdraw(
    api, l3State, bobSecret, [bobNote],
    tokenId, l2BobRecipient, claimSalt, depositAmount, Fr.random(),
  );
  console.log(`  Withdraw proved (${withdrawProof.proof.length} bytes)`);

  l3State.spendNote(bobNote);
  const batch3 = await submitRecursiveBatch([withdrawProof], "withdrawal batch");

  assert((await view(l3.methods.get_batch_nonce(), admin)) === 3n, "nonce=3");
  assert(batch3.withdrawCount === 1, "1 withdrawal in batch");
  console.log("  PASS\n");

  // =====================================================================
  // Step 5: Claim on L2 (Bob)
  // =====================================================================
  console.log("=== Step 5: Claim (Bob on L2) ===");

  const balBefore = await view(token.methods.balance_of_public(bobL2), admin);
  const claimHash = withdrawProof.noteHashes[0];

  await l3.methods
    .claim_withdrawal(token.address, depositAmount, bobL2, claimSalt, claimHash)
    .send({ from: bobL2 });

  const balAfter = await view(token.methods.balance_of_public(bobL2), admin);
  console.log(`  Bob L2 balance: ${balBefore} -> ${balAfter}`);
  assert(balAfter === balBefore + 500n, `expected +500, got +${balAfter - balBefore}`);
  console.log("  PASS\n");

  // =====================================================================
  // Step 6: Double-claim rejection
  // =====================================================================
  console.log("=== Step 6: Double-claim rejection ===");
  try {
    await l3.methods
      .claim_withdrawal(token.address, depositAmount, bobL2, claimSalt, claimHash)
      .send({ from: bobL2 });
    assert(false, "second claim should revert");
  } catch (e: any) {
    const msg = e.message ?? "";
    assert(msg.includes("withdrawal not pending"), `unexpected error: ${msg.slice(0, 100)}`);
    console.log("  PASS: correctly rejected\n");
  }

  // =====================================================================
  // Summary
  // =====================================================================
  const finalNonce = await view(l3.methods.get_batch_nonce(), admin);
  const finalRoot = await view(l3.methods.get_latest_root(), admin);

  console.log("=== All steps passed ===");
  console.log(`  Pipeline: batch_app (UltraHonk) -> wrapper (UltraHonk) -> L2`);
  console.log(`  No IVC kernels, no Chonk, no AztecClientBackend`);
  console.log(`  Batches settled: ${finalNonce}`);
  console.log(`  Final root: ${finalRoot}`);
  console.log(`  Root matches local: ${finalRoot === l3State.stateRoot.toBigInt()}`);
  console.log(`  Nullifier tree size: ${l3State.nullifierTreeStartIndex}`);
  console.log(`  Note hash tree size: ${l3State.noteHashTreeStartIndex}`);

  await api.destroy();
  console.log("\nDone.");
}

// -------------------------------------------------------------------------
// VK / Proof byte-to-field conversion
// -------------------------------------------------------------------------

function bytesToBigInts(buf: Uint8Array, fieldSize = 32): bigint[] {
  const count = Math.floor(buf.length / fieldSize);
  const fields: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const slice = buf.slice(i * fieldSize, (i + 1) * fieldSize);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    fields.push(BigInt(hex));
  }
  return fields;
}

function vkBytesToFields(vk: Uint8Array): bigint[] {
  return bytesToBigInts(vk);
}

function proofBytesToFields(proof: Uint8Array): bigint[] {
  return bytesToBigInts(proof);
}

// -------------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------------

main().catch((e) => {
  console.error("\nFATAL:", e.message ?? e);
  console.error(e.stack?.split("\n").slice(0, 10).join("\n"));
  process.exit(1);
});
