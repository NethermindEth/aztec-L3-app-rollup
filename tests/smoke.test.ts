/**
 * L3 Payments -- Full lifecycle smoke test (e2e).
 *
 * Real proofs end-to-end:
 *   - Per-tx UltraHonk proofs (deposit, payment, withdraw, padding)
 *   - batch_app execution with Merkle insertion witnesses
 *   - IVC kernel chain (init -> tail -> hiding)
 *   - Chonk proof via AztecClientBackend
 *   - Tube circuit proof (UltraHonk, rollup-targeted)
 *   - submit_batch on L2 (private function verifying tube proof)
 *
 * Prerequisites:
 *   npm run sandbox:up
 *   npm run build:artifacts
 *   npm run smoke
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
import { L3Harness } from "./harness/actions.js";
import { computeTubeVkHash } from "./harness/prover.js";

// -------------------------------------------------------------------------
// Config
// -------------------------------------------------------------------------

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_ivc_settlement-L3IvcSettlement.json",
);

function loadL3Artifact() {
  return loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT_PATH, "utf-8")) as NoirCompiledContract,
  );
}

function assert(cond: boolean, msg: string) {
  if (!cond) throw new Error(`ASSERT: ${msg}`);
}

async function derivePubkey(secret: Fr) {
  const pk = await Grumpkin.mul(Grumpkin.generator, secret);
  return { x: pk.x, y: pk.y };
}

// View helper: call .simulate({ from }) and extract .result.
async function view(method: any, from: any): Promise<any> {
  const r = await method.simulate({ from });
  return r.result ?? r;
}

// -------------------------------------------------------------------------
// Main
// -------------------------------------------------------------------------

async function main() {
  // -- Preflight --
  console.log(`Connecting to sandbox at ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error(`Cannot reach sandbox at ${NODE_URL}. Run 'npm run sandbox:up'.`);
    process.exit(1);
  }
  console.log("Connected.\n");

  const api = await Barretenberg.new({ threads: 4 });

  // -- Compute tube VK hash (deterministic from compiled circuit) --
  console.log("Computing tube VK hash...");
  const { vkHash: tubeVkHash } = await computeTubeVkHash(api);
  console.log(`Tube VK hash: ${tubeVkHash.toString().slice(0, 18)}...\n`);

  // -- Wallet + accounts --
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin, user] = await Promise.all(
    testAccounts.slice(0, 2).map(async (acc: any) =>
      (await wallet.createSchnorrAccount(acc.secret, acc.salt, acc.signingKey)).address,
    ),
  );

  // =====================================================================
  // Step 1: Deploy
  // =====================================================================
  console.log("=== Step 1: Deploy ===");

  const { contract: token } = await TokenContract.deploy(wallet, admin, "TestToken", "TT", 18)
    .send({ from: admin });
  await token.methods.mint_to_public(admin, 1_000_000n).send({ from: admin });

  const l3State = await TestL3State.create();
  const initialStateRoot = l3State.stateRoot;
  const { contract: l3 } = await Contract.deploy(
    wallet, loadL3Artifact(), [initialStateRoot.toBigInt(), tubeVkHash.toBigInt(), 0n, 0n], "constructor",
  ).send({ from: admin });

  // Fund L3 contract for withdrawal payouts.
  await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });

  const harness = new L3Harness(
    api, l3State, l3, token, token.address,
    async (method) => { await method.send({ from: admin }); },
    async (method) => { await method.send({ from: admin }); },
  );

  console.log(`  Token:  ${token.address}`);
  console.log(`  L3:     ${l3.address}`);

  // Verify initial state via .simulate({ from }).
  const readRoot = await view(l3.methods.get_latest_root(), admin);
  console.log(`  on-chain root:  ${readRoot} (type: ${typeof readRoot}, ctor: ${readRoot?.constructor?.name})`);
  console.log(`  local root:     ${initialStateRoot.toString()}`);
  console.log(`  on-chain bigint: ${BigInt(readRoot.toString())}`);
  console.log(`  local bigint:    ${initialStateRoot.toBigInt()}`);
  assert(BigInt(readRoot.toString()) === initialStateRoot.toBigInt(), "initial root mismatch");
  const readNonce = await view(l3.methods.get_batch_nonce(), admin);
  assert(readNonce.toString() === "0", "initial nonce mismatch");
  console.log("  PASS\n");

  // =====================================================================
  // Step 2: Deposit
  // =====================================================================
  console.log("=== Step 2: Deposit ===");

  const ownerSecret = new Fr(0xdead_beefn);
  const ownerPk = await derivePubkey(ownerSecret);
  const ownerPkHash = await l3State.hashPubkey(ownerPk.x, ownerPk.y);
  const tokenId = new Fr(0x42n);
  const depositAmount = new Fr(500n);
  const depositSalt = Fr.random();

  const { depositHash, noteHash: depositNoteHash, proof: dProof } = await harness.deposit(
    ownerPk.x, ownerPk.y, depositAmount, tokenId, depositSalt,
  );
  console.log(`  Deposit proved (${dProof.proof.length} bytes)`);

  const batch1 = await harness.submitBatch();
  console.log(`  Batch 1: ${batch1.depositCount}D/${batch1.paymentCount}P/${batch1.withdrawCount}W/${batch1.paddingCount}pad`);
  console.log(`  Tube proof: ${batch1.tubeProof.length} bytes`);

  const root1 = await view(l3.methods.get_latest_root(), admin);
  const nonce1 = await view(l3.methods.get_batch_nonce(), admin);
  console.log(`  on-chain root: ${root1}, nonce: ${nonce1}`);
  assert(root1.toString() === batch1.newStateRoot.toString(), "root after deposit");
  assert(nonce1.toString() === "1", "nonce=1");
  assert(batch1.depositCount === 1, "1 deposit");
  assert(batch1.paddingCount === 7, "7 padding (IVC batch size 8, 1 real tx)");

  const depositTreeIdx = batch1.noteInsertionIndices[0][0];
  assert(depositTreeIdx >= 0, "deposit note inserted");
  const depositedNote = l3State.trackNote(
    ownerPkHash, depositAmount, tokenId, depositSalt, depositNoteHash, depositTreeIdx,
  );
  console.log(`  Note tracked at tree index ${depositTreeIdx}`);
  console.log("  PASS\n");

  // =====================================================================
  // Step 3: Transfer
  // =====================================================================
  console.log("=== Step 3: Transfer ===");

  const recipientPkX = Fr.random();
  const recipientPkY = Fr.random();
  const recipientPkHash = await l3State.hashPubkey(recipientPkX, recipientPkY);
  const paymentSalt0 = Fr.random();
  const paymentSalt1 = Fr.random();

  const pProof = await harness.payment(
    ownerSecret, [depositedNote],
    recipientPkX, recipientPkY,
    depositAmount,
    [paymentSalt0, paymentSalt1],
  );
  console.log(`  Payment proved (${pProof.proof.length} bytes)`);

  l3State.spendNote(depositedNote);
  const batch2 = await harness.submitBatch();
  console.log(`  Batch 2: ${batch2.depositCount}D/${batch2.paymentCount}P/${batch2.withdrawCount}W/${batch2.paddingCount}pad`);

  const root2 = await view(l3.methods.get_latest_root(), admin);
  const nonce2 = await view(l3.methods.get_batch_nonce(), admin);
  console.log(`  on-chain root: ${root2}, nonce: ${nonce2}`);
  assert(root2.toString() === batch2.newStateRoot.toString(), "root after payment");
  assert(nonce2.toString() === "2", "nonce=2");
  assert(batch2.paymentCount === 1, "1 payment");

  const recipientTreeIdx = batch2.noteInsertionIndices[0][0];
  assert(recipientTreeIdx >= 0, "recipient note inserted");
  const recipientNote = l3State.trackNote(
    recipientPkHash, depositAmount, tokenId, paymentSalt0, pProof.noteHashes[0], recipientTreeIdx,
  );
  assert(depositedNote.spent, "deposited note spent");
  assert(!recipientNote.spent, "recipient note live");
  assert(l3State.unspentNotes(ownerPkHash).length === 0, "owner 0 unspent");
  assert(l3State.unspentNotes(recipientPkHash).length === 1, "recipient 1 unspent");
  console.log("  PASS\n");

  // =====================================================================
  // Step 4: Withdraw
  // =====================================================================
  console.log("=== Step 4: Withdraw ===");

  const withdrawerSecret = new Fr(0xcafe_baben);
  const withdrawerPk = await derivePubkey(withdrawerSecret);
  const withdrawerPkHash = await l3State.hashPubkey(withdrawerPk.x, withdrawerPk.y);

  const wDepositSalt = Fr.random();
  const { proof: wdProof } = await harness.deposit(
    withdrawerPk.x, withdrawerPk.y, new Fr(300n), tokenId, wDepositSalt,
  );
  console.log(`  Withdrawer deposit proved (${wdProof.proof.length} bytes)`);

  const batch3 = await harness.submitBatch();
  const wNoteIdx = batch3.noteInsertionIndices[0][0];
  const withdrawableNote = l3State.trackNote(
    withdrawerPkHash, new Fr(300n), tokenId, wDepositSalt, wdProof.noteHashes[0], wNoteIdx,
  );

  const claimSalt = Fr.random();
  const withdrawAmount = new Fr(300n);
  const l2Recipient = Fr.fromString(user.toString());

  const wProof = await harness.withdraw(
    withdrawerSecret, [withdrawableNote],
    tokenId, l2Recipient, claimSalt, withdrawAmount, Fr.random(),
  );
  console.log(`  Withdraw proved (${wProof.proof.length} bytes)`);

  l3State.spendNote(withdrawableNote);
  const batch4 = await harness.submitBatch();
  console.log(`  Batch 4: ${batch4.depositCount}D/${batch4.paymentCount}P/${batch4.withdrawCount}W/${batch4.paddingCount}pad`);

  const root4 = await view(l3.methods.get_latest_root(), admin);
  const nonce4 = await view(l3.methods.get_batch_nonce(), admin);
  console.log(`  on-chain root: ${root4}, nonce: ${nonce4}`);
  assert(root4.toString() === batch4.newStateRoot.toString(), "root after withdraw");
  assert(nonce4.toString() === "4", "nonce=4");
  assert(batch4.withdrawCount === 1, "1 withdrawal");
  assert(withdrawableNote.spent, "withdrawable note spent");
  console.log("  PASS\n");

  // =====================================================================
  // Step 5: Claim on L2
  // =====================================================================
  console.log("=== Step 5: Claim ===");

  const balBefore = await view(token.methods.balance_of_public(user), admin);
  await harness.claimWithdrawal(withdrawAmount, user, claimSalt);
  const balAfter = await view(token.methods.balance_of_public(user), admin);

  console.log(`  User balance: ${balBefore} -> ${balAfter}`);
  assert(
    BigInt(balAfter.toString()) === BigInt(balBefore.toString()) + 300n,
    `user should gain 300 (before=${balBefore}, after=${balAfter})`,
  );
  console.log("  PASS\n");

  // =====================================================================
  // Summary
  // =====================================================================
  console.log("=== All steps passed ===");
  console.log(`  Batches settled: 4`);
  console.log(`  Real tx proofs: 4 (2 deposits + 1 payment + 1 withdrawal)`);
  console.log(`  Tube proofs generated: 4`);
  console.log(`  Final L3 root: ${root4}`);
  console.log(`  Nullifier tree size: ${l3State.nullifierTreeStartIndex}`);
  console.log(`  Note hash tree size: ${l3State.noteHashTreeStartIndex}`);

  await api.destroy();
}

main().catch((e) => {
  console.error("\nSmoke test FAILED:", e.message ?? e);
  console.error(e.stack);
  process.exit(1);
});
