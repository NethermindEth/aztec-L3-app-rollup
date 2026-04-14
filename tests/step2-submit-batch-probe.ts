/**
 * Step 2: Does the sandbox actually verify proofs in submit_batch?
 *
 * Probe 1: Call submit_batch with zeroed proof/VK — observe what happens.
 * Probe 2: Flip one byte in the proof — does the failure change?
 * Probe 3: Flip tube_vk_hash — does the failure change?
 *
 * This tells us whether the sandbox is a passthrough or a real verifier
 * for private proof verification.
 */

import { Fr } from "@aztec/aztec.js/fields";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/stdlib/abi";
import type { NoirCompiledContract } from "@aztec/stdlib/noir";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { readFileSync } from "fs";
import { resolve } from "path";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_ivc_settlement-L3IvcSettlement.json",
);

// Constants matching the IVC circuit (batch size 8).
const ULTRA_HONK_VK_LENGTH = 115;
const ULTRA_HONK_PROOF_LENGTH = 500;
const BATCH_OUTPUT_FIELDS = 8;
const BATCH_NULLIFIERS_COUNT = 16;
const BATCH_NOTE_HASHES_COUNT = 16;
const MAX_BATCH_SIZE = 8;

async function main() {
  console.log("Connecting...");
  const node = createAztecNodeClient(NODE_URL);
  await waitForNode(node);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });

  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const accs = await getInitialTestAccountsData();
  const [admin] = await Promise.all(
    accs.slice(0, 1).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  // Deploy L3 with tube_vk_hash = 0 (we're testing whether it checks at all).
  console.log("Deploying L3IvcSettlement...");
  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT, "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(wallet, l3Artifact, [0n, 0n, 0n], "constructor")
    .send({ from: admin });
  console.log(`L3: ${l3.address}\n`);

  // Build minimal submit_batch args — all zeros.
  const zeroVk = new Array(ULTRA_HONK_VK_LENGTH).fill(0n);
  const zeroProof = new Array(ULTRA_HONK_PROOF_LENGTH).fill(0n);
  const zeroPublicInputs = new Array(BATCH_OUTPUT_FIELDS).fill(0n);
  const zeroNullifiers = new Array(BATCH_NULLIFIERS_COUNT).fill(0n);
  const zeroNoteHashes = new Array(BATCH_NOTE_HASHES_COUNT).fill(0n);
  const zeroDeposits = new Array(MAX_BATCH_SIZE).fill(0n);
  const zeroWithdrawals = new Array(MAX_BATCH_SIZE).fill(0n);

  // --- Probe 1: All zeros ---
  console.log("=== Probe 1: submit_batch with all-zero proof ===");
  try {
    await l3.methods.submit_batch(
      zeroVk, zeroProof, zeroPublicInputs, 0n,
      zeroNullifiers, zeroNoteHashes, zeroDeposits, zeroWithdrawals,
    ).send({ from: admin });
    console.log("  RESULT: succeeded (sandbox does NOT verify proofs)\n");
  } catch (e: any) {
    const msg = e.message?.slice(0, 300) ?? String(e);
    console.log(`  RESULT: failed\n  ${msg}\n`);
  }

  // --- Probe 2: Flip one byte in the proof ---
  console.log("=== Probe 2: submit_batch with one flipped proof byte ===");
  const corruptProof = [...zeroProof];
  corruptProof[0] = 1n; // flip first byte
  try {
    await l3.methods.submit_batch(
      zeroVk, corruptProof, zeroPublicInputs, 0n,
      zeroNullifiers, zeroNoteHashes, zeroDeposits, zeroWithdrawals,
    ).send({ from: admin });
    console.log("  RESULT: succeeded\n");
  } catch (e: any) {
    const msg = e.message?.slice(0, 300) ?? String(e);
    console.log(`  RESULT: failed\n  ${msg}\n`);
  }

  // --- Probe 3: Flip tube_vk_hash ---
  console.log("=== Probe 3: submit_batch with non-zero tube_vk_hash ===");
  try {
    await l3.methods.submit_batch(
      zeroVk, zeroProof, zeroPublicInputs, 1n, // vk_hash = 1 instead of 0
      zeroNullifiers, zeroNoteHashes, zeroDeposits, zeroWithdrawals,
    ).send({ from: admin });
    console.log("  RESULT: succeeded\n");
  } catch (e: any) {
    const msg = e.message?.slice(0, 300) ?? String(e);
    console.log(`  RESULT: failed\n  ${msg}\n`);
  }

  // --- Probe 4: Shape-boundary test ---
  // The contract ABI declares tube_proof as [Field; 500] (UltraHonkZKProof).
  // Tube proofs from the IVC pipeline are 519 fields (RollupHonk with IPA).
  // This probe tests how the SDK handles mismatched array lengths.
  console.log("=== Probe 4: Shape-boundary test (proof array lengths) ===");
  const testLengths = [499, 500, 501, 519];
  for (const len of testLengths) {
    const proofArr = new Array(len).fill(0n);
    try {
      await l3.methods.submit_batch(
        zeroVk, proofArr, zeroPublicInputs, 0n,
        zeroNullifiers, zeroNoteHashes, zeroDeposits, zeroWithdrawals,
      ).send({ from: admin });
      console.log(`  proof[${len}]: ACCEPTED`);
    } catch (e: any) {
      const msg = (e.message ?? String(e)).slice(0, 150);
      // Distinguish SDK/ABI errors from kernel/execution errors
      const isAbiError = msg.includes("abi") || msg.includes("encode") ||
                         msg.includes("length") || msg.includes("size") ||
                         msg.includes("array") || msg.includes("expected");
      const label = isAbiError ? "REJECTED (ABI/SDK layer)" : "REJECTED (kernel/execution)";
      console.log(`  proof[${len}]: ${label}`);
      console.log(`    ${msg}`);
    }
  }
  console.log();

  // Interpretation guide:
  console.log("Interpretation:");
  console.log("  If 499 rejected, 500 accepted, 501/519 rejected => SDK enforces exact length");
  console.log("  If 499 rejected, 500/501/519 all accepted      => SDK truncates/pads silently");
  console.log("  If all accepted                                 => no array length enforcement\n");

  console.log("Done.");
}

main().catch((e) => {
  console.error("FATAL:", e.message);
  console.error(e.stack?.split("\n").slice(0, 8).join("\n"));
  process.exit(1);
});
