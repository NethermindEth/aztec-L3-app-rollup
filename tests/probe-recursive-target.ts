/**
 * probe-recursive-target.ts
 *
 * Quick diagnostic: can wrapper_16 be proved at noir-recursive target
 * (producing 500-field proofs matching the contract ABI)?
 *
 * The recursive pipeline has no Chonk/IPA anywhere — all inner proofs are
 * noir-recursive UltraHonk. If wrapper_16 can also be proved at
 * noir-recursive, Design B can close the 519/500 gap without any
 * Aztec platform changes.
 */

import { Barretenberg, UltraHonkBackend } from "@aztec/bb.js";
import { Fr } from "@aztec/aztec.js/fields";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/stdlib/abi";
import type { NoirCompiledContract } from "@aztec/stdlib/noir";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { TokenContract } from "@aztec/noir-contracts.js/Token";
import { readFileSync } from "fs";
import { resolve } from "path";

import { TestL3State } from "./harness/state.js";
import type { TxProofResult } from "./harness/prover.js";
import {
  buildBatchProofRecursive,
  buildWrapper16Proof,
  proveDeposit,
} from "./harness/prover-recursive.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const TARGET_DIR = resolve(import.meta.dirname ?? ".", "../target");

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
  console.log("=== Probe: Can wrapper_16 produce noir-recursive (500-field) proofs? ===\n");

  const api = await Barretenberg.new({ threads: 4 });

  // Step 1: Build two recursive sub-batches with wrapper at noir-recursive.
  console.log("Building two recursive sub-batches...");
  const l3State = await TestL3State.create();
  const aliceSecret = new Fr(0xdead_beefn);
  const alicePk = await Grumpkin.mul(Grumpkin.generator, aliceSecret);
  const tokenId = new Fr(1n);
  const amount = new Fr(100n);
  const saltA = new Fr(0xaaaa_5555n);
  const saltB = new Fr(0xbbbb_5555n);

  const alicePkHash = await l3State.hashPubkey(alicePk.x, alicePk.y);
  const dHashA = await l3State.depositHash(alicePkHash, amount, tokenId, saltA);
  const dHashB = await l3State.depositHash(alicePkHash, amount, tokenId, saltB);
  l3State.registerDeposit(dHashA);
  l3State.registerDeposit(dHashB);

  const depProofA = await proveDeposit(api, l3State, amount, tokenId, alicePk.x, alicePk.y, saltA);
  const l3StateB = await cloneL3StateWithDeposit(l3State, depProofA);
  const depProofB = await proveDeposit(api, l3StateB, amount, tokenId, alicePk.x, alicePk.y, saltB);

  console.log("  Building sub-batch A...");
  const artifactA = await buildBatchProofRecursive(api, l3State, [depProofA]);
  console.log(`    wrapper proof A: ${artifactA.tubeProof.length} bytes (${artifactA.tubeProof.length / 32} fields)`);

  console.log("  Building sub-batch B...");
  const artifactB = await buildBatchProofRecursive(api, l3StateB, [depProofB]);
  console.log(`    wrapper proof B: ${artifactB.tubeProof.length} bytes (${artifactB.tubeProof.length / 32} fields)\n`);

  // Step 2: Build wrapper_16 proof at noir-recursive (current behavior).
  console.log("Building wrapper_16 proof at noir-recursive (current default)...");
  const pairArtifact = await buildWrapper16Proof(api, artifactA, artifactB);
  const pairFields = pairArtifact.w16Proof.length / 32;
  console.log(`  noir-recursive: ${pairArtifact.w16Proof.length} bytes (${pairFields} fields)\n`);

  // Step 3: Verify it's 500 fields (not 519).
  console.log("Building wrapper_16 proof at noir-recursive (the test)...");
  try {
    const { Noir } = await import("@aztec/noir-noir_js");
    const pairCircuit = JSON.parse(readFileSync(resolve(TARGET_DIR, "l3_wrapper_16.json"), "utf-8"));
    const pairBackend = new UltraHonkBackend(pairCircuit.bytecode, api);

    // Re-execute to get witness (buildWrapper16Proof doesn't expose it).
    const p2h = async (inputs: Fr[]) => poseidon2Hash(inputs);
    const f2s = (f: Fr) => f.toString();

    const mergedNullifiers = [...artifactA.settleInputs.nullifiers, ...artifactB.settleInputs.nullifiers];
    const mergedNoteHashes = [...artifactA.settleInputs.noteHashes, ...artifactB.settleInputs.noteHashes];
    const mergedDeposits = [...artifactA.settleInputs.depositNullifiers, ...artifactB.settleInputs.depositNullifiers];
    const mergedWithdrawals = [...artifactA.settleInputs.withdrawalClaims, ...artifactB.settleInputs.withdrawalClaims];

    const wrapperVkFields = vkToFields(artifactA.tubeVk);
    const wrapperVkHash = await p2h(wrapperVkFields);

    const VK_FIELDS = 115;
    const PROOF_FIELDS = 500;
    const bytesToFieldStrings = (buf: Uint8Array, n: number) => {
      const fields: string[] = [];
      for (let i = 0; i < n; i++) {
        const slice = buf.slice(i * 32, (i + 1) * 32);
        const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
        fields.push(BigInt(hex).toString());
      }
      return fields;
    };

    const pairNoir = new Noir(pairCircuit);
    const { witness } = await pairNoir.execute({
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
      merged_nullifiers_hash: f2s(await p2h(mergedNullifiers)),
      merged_note_hashes_hash: f2s(await p2h(mergedNoteHashes)),
      merged_deposit_nullifiers_hash: f2s(await p2h(mergedDeposits)),
      merged_withdrawal_claims_hash: f2s(await p2h(mergedWithdrawals)),
      nullifier_tree_start_index: f2s(artifactA.nullifierTreeStartIndex),
      note_hash_tree_start_index: f2s(artifactA.noteHashTreeStartIndex),
    });

    // THE KEY TEST: prove at noir-recursive instead of noir-rollup
    const proofData = await pairBackend.generateProof(witness, { verifierTarget: "noir-recursive" });
    const recursiveFields = proofData.proof.length / 32;
    console.log(`  noir-recursive: ${proofData.proof.length} bytes (${recursiveFields} fields)`);

    const vk = await pairBackend.getVerificationKey({ verifierTarget: "noir-recursive" });
    const valid = await pairBackend.verifyProof(proofData, { verifierTarget: "noir-recursive" });
    console.log(`  verified: ${valid}`);

    if (recursiveFields === 500) {
      console.log("\n  *** SUCCESS: wrapper_16 at noir-recursive produces 500-field proofs ***");
      console.log("  Design B can close the 519/500 gap by switching the final prove target.");

      // Step 4: Try submitting to a real contract.
      console.log("\n  Testing contract submission with 500-field proof...");
      const node = createAztecNodeClient(NODE_URL);
      try { await waitForNode(node); } catch {
        console.log("  Sandbox not running — skipping contract test.\n");
        await api.destroy();
        return;
      }

      const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
      const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
      const testAccounts = await getInitialTestAccountsData();
      const [admin] = await Promise.all(
        testAccounts.slice(0, 1).map(async (a: any) =>
          (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
        ),
      );

      // Compute VK hashes at noir-recursive target.
      const wrapperVkForContract = await (async () => {
        const wc = JSON.parse(readFileSync(resolve(TARGET_DIR, "l3_wrapper.json"), "utf-8"));
        const wb = new UltraHonkBackend(wc.bytecode, api);
        const v = await wb.getVerificationKey({ verifierTarget: "noir-recursive" });
        return await p2h(vkToFields(v));
      })();
      const pairVkForContract = await p2h(vkToFields(vk));

      const l3Artifact = loadContractArtifact(
        JSON.parse(readFileSync(resolve(TARGET_DIR, "l3_recursive_settlement-L3RecursiveSettlement.json"), "utf-8")) as NoirCompiledContract,
      );

      const contractState = await TestL3State.create();
      const { contract: token } = await TokenContract.deploy(wallet, admin, "T", "T", 18).send({ from: admin });
      const { contract: l3 } = await Contract.deploy(
        wallet, l3Artifact,
        [contractState.stateRoot.toBigInt(), wrapperVkForContract.toBigInt(), pairVkForContract.toBigInt(), 0n, 0n, 0n],
        "constructor",
      ).send({ from: admin });
      await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });

      // Register deposits on the contract.
      const aliceL2 = (await Promise.all(
        testAccounts.slice(1, 2).map(async (a: any) =>
          (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
        ),
      ))[0];
      await token.methods.mint_to_private(aliceL2, 10_000n).send({ from: admin });

      for (const salt of [saltA, saltB]) {
        const nonce = Fr.random();
        const action = token.methods.transfer_to_public(aliceL2, l3.address, amount.toBigInt(), nonce);
        const authwit = await wallet.createAuthWit(aliceL2, { caller: l3.address, action });
        await l3.methods.deposit(token.address, amount, alicePk.x, alicePk.y, salt, nonce)
          .send({ from: aliceL2, authWitnesses: [authwit] });
      }

      const mergedVkFields = bytesToBigInts(vk);
      const mergedProofFields = bytesToBigInts(proofData.proof);
      console.log(`  Submitting ${mergedProofFields.length}-field proof to contract (ABI expects 500)...`);

      try {
        await l3.methods.submit_batch_16(
          mergedVkFields,
          mergedProofFields,
          proofData.publicInputs,
          pairVkForContract,
          mergedNullifiers,
          mergedNoteHashes,
          mergedDeposits,
          mergedWithdrawals,
        ).send({ from: admin });

        const nonce = await (async () => {
          const r = await l3.methods.get_batch_nonce().simulate({ from: admin });
          return BigInt((r.result ?? r).toString());
        })();
        console.log(`  Contract accepted! nonce=${nonce}`);
        console.log("\n  *** Design B with noir-recursive final proof: WORKS ***");
      } catch (e: any) {
        console.log(`  Contract rejected: ${(e.message ?? "").slice(0, 150)}`);
      }
    } else {
      console.log(`\n  noir-recursive produced ${recursiveFields} fields (expected 500)`);
    }
  } catch (e: any) {
    console.log(`  FAILED: ${e.message ?? e}`);
    console.log("  wrapper_16 cannot be proved at noir-recursive target.\n");
  }

  await api.destroy();
  console.log("\nDone.");
}

main().catch((e) => {
  console.error("\nFATAL:", e.message ?? e);
  console.error(e.stack?.split("\n").slice(0, 10).join("\n"));
  process.exit(1);
});
