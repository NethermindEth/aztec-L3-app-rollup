/**
 * Step 3: submit_batch() accepts valid inputs.
 *
 * Calls the real submit_batch private function with:
 *   - Correct public inputs (state roots, hashes, tree indices)
 *   - Dummy proof bytes (sandbox doesn't verify proofs)
 *   - A pending deposit registered via real deposit()
 *
 * Verifies:
 *   - State root advances
 *   - Batch nonce increments
 *   - Deposit is consumed
 */

import { Fr } from "@aztec/aztec.js/fields";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/stdlib/abi";
import type { NoirCompiledContract } from "@aztec/stdlib/noir";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { TokenContract } from "@aztec/noir-contracts.js/Token";
import { readFileSync } from "fs";
import { resolve } from "path";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT = resolve(import.meta.dirname ?? ".", "../target/l3_settlement-L3Settlement.json");

const VK_LEN = 115;
const PROOF_LEN = 500;
const BATCH_OUTPUT_FIELDS = 8;
// NOTE: reduced to 4 for testing (Chonk ECCVM limit).
const BATCH_NULL_COUNT = 8;
const BATCH_NH_COUNT = 8;
const MAX_BATCH = 4;

async function view(method: any, from: any): Promise<any> {
  const r = await method.simulate({ from });
  return r.result ?? r;
}

async function main() {
  console.log("Connecting...");
  const node = createAztecNodeClient(NODE_URL);
  await waitForNode(node);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });

  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const accs = await getInitialTestAccountsData();
  const [admin, depositor] = await Promise.all(
    accs.slice(0, 2).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  // Deploy Token + L3 (tube_vk_hash = 0 since sandbox ignores proof verification).
  console.log("Deploying...");
  const { contract: token } = await TokenContract.deploy(wallet, admin, "T", "T", 18)
    .send({ from: admin });

  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT, "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(wallet, l3Artifact, [0n, 0n], "constructor")
    .send({ from: admin });
  console.log(`Token: ${token.address}`);
  console.log(`L3:    ${l3.address}`);

  // Register a deposit via the real deposit() function.
  console.log("\nRegistering deposit via real deposit()...");
  await token.methods.mint_to_private(depositor, 1000n).send({ from: admin });

  const nonce = Fr.random();
  const depositSalt = Fr.random();
  const pkX = Fr.random();
  const pkY = Fr.random();
  const depositAmount = 500n;

  const transferAction = token.methods.transfer_to_public(depositor, l3.address, depositAmount, nonce);
  const witness = await wallet.createAuthWit(depositor, { caller: l3.address, action: transferAction });

  await l3.methods.deposit(token.address, depositAmount, pkX, pkY, depositSalt, nonce)
    .send({ from: depositor, authWitnesses: [witness] });
  console.log("  deposit() OK");

  // Compute the deposit_hash (must match what the contract computed).
  const pkHash = await poseidon2Hash([pkX, pkY]);
  const depositHash = await poseidon2Hash([pkHash, new Fr(depositAmount), new Fr(token.address.toBigInt()), depositSalt]);
  console.log(`  deposit_hash: ${depositHash.toString().slice(0, 18)}...`);

  // Build valid submit_batch inputs.
  // The batch has 1 deposit with deposit_hash as its nullifier.
  console.log("\nBuilding submit_batch inputs...");

  const nullifiers = new Array(BATCH_NULL_COUNT).fill(Fr.ZERO);
  nullifiers[0] = depositHash; // deposit's nullifier slot

  const noteHashes = new Array(BATCH_NH_COUNT).fill(Fr.ZERO);
  // deposit's note_hash = deposit_hash (same preimage as Note::hash for deposits)
  noteHashes[0] = depositHash;

  const depositNullifiers = new Array(MAX_BATCH).fill(Fr.ZERO);
  depositNullifiers[0] = depositHash;

  const withdrawalClaims = new Array(MAX_BATCH).fill(Fr.ZERO);

  const nullifiersBatchHash = await poseidon2Hash(nullifiers);
  const noteHashesBatchHash = await poseidon2Hash(noteHashes);
  const depositNullifiersHash = await poseidon2Hash(depositNullifiers);
  const withdrawalClaimsHash = await poseidon2Hash(withdrawalClaims);

  const oldStateRoot = new Fr(0n); // matches constructor
  const newStateRoot = Fr.random(); // synthetic — sandbox doesn't verify the proof

  const publicInputs = [
    oldStateRoot,
    newStateRoot,
    nullifiersBatchHash,
    noteHashesBatchHash,
    depositNullifiersHash,
    withdrawalClaimsHash,
    new Fr(1n), // nullifier_tree_start_index (constructor sets to 1)
    new Fr(0n), // note_hash_tree_start_index (constructor sets to 0)
  ];

  const dummyVk = new Array(VK_LEN).fill(0n);
  const dummyProof = new Array(PROOF_LEN).fill(0n);
  const tubeVkHash = new Fr(0n); // matches constructor

  // Call submit_batch.
  console.log("Calling submit_batch...");
  try {
    await l3.methods.submit_batch(
      dummyVk, dummyProof, publicInputs, tubeVkHash,
      nullifiers, noteHashes, depositNullifiers, withdrawalClaims,
    ).send({ from: admin });
    console.log("  submit_batch OK");
  } catch (e: any) {
    console.log(`  FAILED: ${e.message.slice(0, 300)}`);
    return;
  }

  // Verify state.
  console.log("\nVerifying state...");
  const root = await view(l3.methods.get_latest_root(), admin);
  const batchNonce = await view(l3.methods.get_batch_nonce(), admin);
  console.log(`  latest_root: ${root}`);
  console.log(`  batch_nonce: ${batchNonce}`);
  console.log(`  expected root: ${newStateRoot.toBigInt()}`);

  const rootMatch = BigInt(root.toString()) === newStateRoot.toBigInt();
  const nonceMatch = BigInt(batchNonce.toString()) === 1n;

  console.log(`  root matches: ${rootMatch}`);
  console.log(`  nonce matches: ${nonceMatch}`);

  if (rootMatch && nonceMatch) {
    console.log("\n  PASS: submit_batch accepted, state advanced, deposit consumed.");
  } else {
    console.log("\n  FAIL: state did not advance as expected.");
  }

  // Verify deposit was consumed — try to submit again with same deposit.
  console.log("\nProbe: resubmit same deposit (should fail)...");
  try {
    const newStateRoot2 = Fr.random();
    const publicInputs2 = [...publicInputs];
    publicInputs2[0] = newStateRoot; // old = previous new
    publicInputs2[1] = newStateRoot2;
    // Tree indices advanced: null +1, nh +1
    publicInputs2[6] = new Fr(2n);
    publicInputs2[7] = new Fr(1n);

    await l3.methods.submit_batch(
      dummyVk, dummyProof, publicInputs2, tubeVkHash,
      nullifiers, noteHashes, depositNullifiers, withdrawalClaims,
    ).send({ from: admin });
    console.log("  UNEXPECTED: second submit succeeded (deposit should be consumed)");
  } catch (e: any) {
    const msg = e.message?.slice(0, 200) ?? "";
    if (msg.includes("deposit not in pending list")) {
      console.log("  PASS: correctly rejected — deposit already consumed.");
    } else {
      console.log(`  Failed with: ${msg}`);
    }
  }

  console.log("\nDone.");
}

main().catch((e) => {
  console.error("FATAL:", e.message);
  console.error(e.stack?.split("\n").slice(0, 8).join("\n"));
  process.exit(1);
});
