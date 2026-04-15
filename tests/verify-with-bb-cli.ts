/**
 * verify-with-bb-cli.ts
 *
 * External soundness check: produce recursive proofs using bb.js locally
 * (no sandbox needed), dump proof/public_inputs/vk as raw 32-byte-per-field
 * binary files, and call the `bb` CLI verifier out-of-process to
 * independently confirm the proofs verify.
 *
 * Motivation: the Aztec sandbox's `verify_honk_proof` is a no-op under
 * PXE_PROVER=none, and TXE's ACIR simulator stubs it too. bb.js's
 * in-process verifyProof() call is the same binding as the prover. A
 * separate `bb` process gives a soundness signal independent of the JS
 * glue and covers all `submit_*` contract entry points (see
 * SILENT_FAILURE_REVIEW.md).
 *
 * Scope:
 *   - default: wrapper (8 slots) + wrapper_16 (16 slots) — ~15-20 min
 *   - INCLUDE_64=1: also wrapper_32 (32 slots) + wrapper_64 (64
 *     slots). Adds 6 sub-batches, 3 more wrapper_16s, 2 wrapper_32s,
 *     and 1 wrapper_64 — ~45-75 additional minutes depending on host.
 *
 * Run:
 *   npx tsx verify-with-bb-cli.ts                # 16-slot only
 *   INCLUDE_64=1 npx tsx verify-with-bb-cli.ts # full chain including quad
 *
 * Requires:
 *   - Circuits compiled under ../target (aztec compile --workspace --force)
 *   - `bb` on PATH (WSL: ~/.aztec/current/node_modules/.bin/bb)
 *   - WSL memory >= 16 GiB; >= 24 GiB recommended for INCLUDE_64
 */

import { Barretenberg } from "@aztec/bb.js";
import { Fr } from "@aztec/aztec.js/fields";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { mkdirSync, writeFileSync } from "fs";
import { resolve } from "path";
import { spawnSync } from "child_process";

import { TestL3State } from "./harness/state.js";
import {
  buildBatchProofRecursive,
  buildWrapper16Proof,
  buildWrapper32Proof,
  buildWrapper64Proof,
  proveDeposit,
  type BatchArtifact,
} from "./harness/prover-recursive.js";
import {
  ARTIFACT_DIR_PATH, MANIFEST_FILENAME, VERIFIER_TARGET,
  fieldStringsToBytes, vkBytesToFr,
} from "./verify-shared.js";

const ARTIFACT_DIR = ARTIFACT_DIR_PATH;
const INCLUDE_64 = process.env.INCLUDE_64 === "1";

function runBbVerify(label: string, proofPath: string, publicInputsPath: string, vkPath: string): boolean {
  console.log(`\n>>> bb verify (${label}) -t ${VERIFIER_TARGET}`);
  const result = spawnSync(
    "bb",
    [
      "verify",
      "-t", VERIFIER_TARGET,
      "-p", proofPath,
      "-i", publicInputsPath,
      "-k", vkPath,
    ],
    { stdio: "inherit" },
  );
  console.log(`>>> bb verify exit code: ${result.status}`);
  if (result.error) {
    console.error(`>>> spawn error: ${result.error.message}`);
  }
  return result.status === 0;
}

function writeArtifacts(
  prefix: string,
  proof: Uint8Array,
  publicInputs: string[],
  vk: Uint8Array,
) {
  const proofPath = resolve(ARTIFACT_DIR, `${prefix}_proof.bin`);
  const piPath = resolve(ARTIFACT_DIR, `${prefix}_public_inputs.bin`);
  const vkPath = resolve(ARTIFACT_DIR, `${prefix}_vk.bin`);
  writeFileSync(proofPath, proof);
  writeFileSync(piPath, fieldStringsToBytes(publicInputs));
  writeFileSync(vkPath, vk);
  console.log(`  proof:          ${proof.length} bytes (${proof.length / 32} fields)`);
  console.log(`  public_inputs:  ${publicInputs.length} fields`);
  console.log(`  vk:             ${vk.length} bytes (${vk.length / 32} fields)`);
  return { proofPath, piPath, vkPath };
}

interface ManifestEntry {
  vkHash: string;
  proofBytes: number;
  publicInputsFields: number;
  vkBytes: number;
  artifacts: { proof: string; publicInputs: string; vk: string };
}

async function manifestEntry(vk: Uint8Array, proof: Uint8Array, publicInputs: string[], prefix: string): Promise<ManifestEntry> {
  return {
    vkHash: (await poseidon2Hash(vkBytesToFr(vk))).toString(),
    proofBytes: proof.length,
    publicInputsFields: publicInputs.length,
    vkBytes: vk.length,
    artifacts: {
      proof: `${prefix}_proof.bin`,
      publicInputs: `${prefix}_public_inputs.bin`,
      vk: `${prefix}_vk.bin`,
    },
  };
}

// Produce a single sub-batch (BatchArtifact) from its own fresh deposit,
// threading and MUTATING the given state: buildBatchProofRecursive advances
// state.nullifierTree / noteHashTree / stateRoot, so sub-batch i+1 passed
// the same state object picks up the post-i root naturally.
async function proveSubBatch(
  api: Barretenberg,
  state: TestL3State,
  alicePkX: Fr, alicePkY: Fr, amount: Fr, tokenId: Fr, salt: Fr,
  label: string,
): Promise<BatchArtifact> {
  console.log(`Proving deposit ${label}...`);
  const dep = await proveDeposit(api, state, amount, tokenId, alicePkX, alicePkY, salt);
  console.log(`Building recursive sub-batch ${label}...`);
  return buildBatchProofRecursive(api, state, [dep]);
}

async function main() {
  mkdirSync(ARTIFACT_DIR, { recursive: true });
  console.log(`Artifact dir: ${ARTIFACT_DIR}`);
  console.log(`Scope: wrapper + wrapper_16${INCLUDE_64 ? " + wrapper_32 + wrapper_64 (INCLUDE_64=1)" : ""}\n`);

  const api = await Barretenberg.new({ threads: 4 });

  const aliceSecret = new Fr(0xdead_beefn);
  const alicePk = await Grumpkin.mul(Grumpkin.generator, aliceSecret);
  const tokenId = new Fr(1n);
  const amount = new Fr(100n);

  // Build state with enough registered deposits for the chosen scope.
  const numSubBatches = INCLUDE_64 ? 8 : 2;
  const salts: Fr[] = [];
  for (let i = 0; i < numSubBatches; i++) {
    salts.push(new Fr(BigInt(0xaaaa_0000 + i)));
  }

  // Fresh state with all deposits pre-registered (deposit registration is
  // independent of proving order; they just need to exist in pending).
  const state0 = await TestL3State.create();
  const alicePkHash = await state0.hashPubkey(alicePk.x, alicePk.y);
  for (const salt of salts) {
    const dh = await state0.depositHash(alicePkHash, amount, tokenId, salt);
    state0.registerDeposit(dh);
  }

  // Thread one state through all sub-batches. buildBatchProofRecursive
  // mutates state in-place (advances nullifier/note trees and stateRoot),
  // so sub-batch i+1 automatically sees the post-i state as its old root.
  const subBatches: BatchArtifact[] = [];
  for (let i = 0; i < numSubBatches; i++) {
    const sb = await proveSubBatch(
      api, state0, alicePk.x, alicePk.y, amount, tokenId, salts[i],
      `#${i}`,
    );
    subBatches.push(sb);
  }

  // -------------------------------------------------------------------------
  // Always: dump wrapper (sub-batch #0) artifacts + positive bb verify.
  // -------------------------------------------------------------------------
  const artifactA = subBatches[0];
  console.log(`\nWrote wrapper (8-slot) artifacts:`);
  const wrapperPaths = writeArtifacts(
    "wrapper",
    artifactA.tubeProof,
    artifactA.tubePublicInputs.map((f) => f.toString()),
    artifactA.tubeVk,
  );
  const wrapperOk = runBbVerify("wrapper (8-slot)", wrapperPaths.proofPath, wrapperPaths.piPath, wrapperPaths.vkPath);

  // -------------------------------------------------------------------------
  // Always: wrapper_16 (16 slots) from sub-batches 0 and 1.
  // -------------------------------------------------------------------------
  console.log("\nBuilding wrapper_16 merged proof (16-slot)...");
  const pair = await buildWrapper16Proof(api, subBatches[0], subBatches[1]);
  console.log(`\nWrote wrapper_16 (16-slot merged) artifacts:`);
  const pairPaths = writeArtifacts(
    "wrapper_16",
    pair.w16Proof,
    pair.mergedPublicInputs,
    pair.w16Vk,
  );
  const pairOk = runBbVerify("wrapper_16 (16-slot merged)", pairPaths.proofPath, pairPaths.piPath, pairPaths.vkPath);

  // -------------------------------------------------------------------------
  // Optional (INCLUDE_64): wrapper_32 + wrapper_64.
  //
  // Builds 3 more wrapper_16s from sub-batches (2,3), (4,5), (6,7), then
  // 2 wrapper_32s from those, then 1 wrapper_64.
  // -------------------------------------------------------------------------
  let ppEntry: ManifestEntry | undefined;
  let quadEntry: ManifestEntry | undefined;
  let ppOk = true;
  let quadOk = true;

  if (INCLUDE_64) {
    console.log("\nBuilding wrapper_16s for sub-batches (2,3), (4,5), (6,7)...");
    const pair23 = await buildWrapper16Proof(api, subBatches[2], subBatches[3]);
    const pair45 = await buildWrapper16Proof(api, subBatches[4], subBatches[5]);
    const pair67 = await buildWrapper16Proof(api, subBatches[6], subBatches[7]);

    console.log("\nBuilding wrapper_32s (32 slots each)...");
    const ppAB = await buildWrapper32Proof(api, pair, pair23);
    const ppCD = await buildWrapper32Proof(api, pair45, pair67);

    console.log("\nBuilding wrapper_64 (64-slot merged)...");
    const quad = await buildWrapper64Proof(api, ppAB, ppCD);

    // Dump the FIRST wrapper_32 (ppAB) as the representative 32-slot
    // artifact for external verification and negatives.
    console.log(`\nWrote wrapper_32 (32-slot merged) artifacts:`);
    const ppPaths = writeArtifacts("wrapper_32", ppAB.w32Proof, ppAB.mergedPublicInputs, ppAB.w32Vk);
    ppOk = runBbVerify("wrapper_32 (32-slot merged)", ppPaths.proofPath, ppPaths.piPath, ppPaths.vkPath);

    console.log(`\nWrote wrapper_64 (64-slot merged) artifacts:`);
    const quadPaths = writeArtifacts("wrapper_64", quad.w64Proof, quad.mergedPublicInputs, quad.w64Vk);
    quadOk = runBbVerify("wrapper_64 (64-slot merged)", quadPaths.proofPath, quadPaths.piPath, quadPaths.vkPath);

    ppEntry = await manifestEntry(ppAB.w32Vk, ppAB.w32Proof, ppAB.mergedPublicInputs, "wrapper_32");
    quadEntry = await manifestEntry(quad.w64Vk, quad.w64Proof, quad.mergedPublicInputs, "wrapper_64");

    // Sidecar for probe-chain-binding-64.ts -- contains the merged settle
    // arrays + VK hashes needed to call submit_batch_64 without re-proving.
    const batch64Payload = {
      mergedPublicInputs: quad.mergedPublicInputs,
      mergedNullifiers: quad.mergedNullifiers.map((f) => f.toString()),
      mergedNoteHashes: quad.mergedNoteHashes.map((f) => f.toString()),
      mergedDeposits: quad.mergedDeposits.map((f) => f.toString()),
      mergedWithdrawals: quad.mergedWithdrawals.map((f) => f.toString()),
      wrapperVkHash: (await poseidon2Hash(vkBytesToFr(subBatches[0].tubeVk))).toString(),
      w16VkHash: (await poseidon2Hash(vkBytesToFr(pair.w16Vk))).toString(),
      w32VkHash: (await poseidon2Hash(vkBytesToFr(ppAB.w32Vk))).toString(),
      w64VkHash: (await poseidon2Hash(vkBytesToFr(quad.w64Vk))).toString(),
    };
    writeFileSync(resolve(ARTIFACT_DIR, "batch_64_submit_payload.json"), JSON.stringify(batch64Payload, null, 2));
    console.log(`\nWrote batch_64_submit_payload.json (for probe-chain-binding-64.ts)`);
  }

  // -------------------------------------------------------------------------
  // Manifest.
  // -------------------------------------------------------------------------
  const manifest: Record<string, unknown> = {
    generatedAt: new Date().toISOString(),
    verifierTarget: VERIFIER_TARGET,
    scope: INCLUDE_64 ? "full-chain" : "wrapper+wrapper_16",
    wrapper: await manifestEntry(
      artifactA.tubeVk, artifactA.tubeProof,
      artifactA.tubePublicInputs.map((f) => f.toString()),
      "wrapper",
    ),
    wrapper_16: await manifestEntry(pair.w16Vk, pair.w16Proof, pair.mergedPublicInputs, "wrapper_16"),
  };
  if (ppEntry) manifest.wrapper_32 = ppEntry;
  if (quadEntry) manifest.wrapper_64 = quadEntry;
  writeFileSync(resolve(ARTIFACT_DIR, MANIFEST_FILENAME), JSON.stringify(manifest, null, 2));
  console.log(`\nWrote ${MANIFEST_FILENAME}`);

  await api.destroy();

  console.log("\n=== Summary ===");
  console.log(`  wrapper (8-slot):               ${wrapperOk ? "OK" : "FAIL"}`);
  console.log(`  wrapper_16 (16-slot merged):  ${pairOk ? "OK" : "FAIL"}`);
  if (INCLUDE_64) {
    console.log(`  wrapper_32 (32-slot):    ${ppOk ? "OK" : "FAIL"}`);
    console.log(`  wrapper_64 (64-slot merged):  ${quadOk ? "OK" : "FAIL"}`);
  }

  const allOk = wrapperOk && pairOk && ppOk && quadOk;
  if (!allOk) {
    console.error("\nbb verify FAILED for at least one proof");
    process.exit(1);
  }
  console.log("\nbb verify OK -- all produced proofs externally valid.");
}

main().catch((e) => {
  console.error("\nFATAL:", e?.message ?? e);
  console.error(e?.stack?.split("\n").slice(0, 10).join("\n"));
  process.exit(1);
});
