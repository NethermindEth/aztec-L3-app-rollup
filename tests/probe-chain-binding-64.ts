/**
 * probe-chain-binding-64.ts
 *
 * Soundness probe for the inner-VK chain binding on submit_batch_64.
 *
 * Replays a valid wrapper_64 proof produced by verify-with-bb-cli.ts
 * against a contract deployed with a DELIBERATELY WRONG inner VK hash.
 * The contract's chain-binding assertion in submit_batch_64 should
 * reject before verify_honk_proof even runs, e.g.:
 *
 *   submit_batch_64: inner wrapper_vk_hash does not match committed
 *   tube_vk_hash
 *
 * This is a plumbing test, not a proof-gate test -- the assertion is a
 * plain Noir assert, not a verify_honk_proof call, so it fires even
 * under sandbox / TXE where verify_honk_proof is a no-op. Probes each
 * of the 3 chain-binding slots (wrapper / wrapper_16 / wrapper_32).
 *
 * Requires:
 *   - Sandbox running (`npm run sandbox:up`).
 *   - Artifacts produced by `npm run verify:recursive:64`:
 *       tests/bb-verify-artifacts/wrapper_64_{proof,public_inputs,vk}.bin
 *       tests/bb-verify-artifacts/batch_64_submit_payload.json
 *
 * Run:
 *   npm run probe:chain:64
 */

import { Fr } from "@aztec/aztec.js/fields";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/stdlib/abi";
import type { NoirCompiledContract } from "@aztec/stdlib/noir";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { TokenContract } from "@aztec/noir-contracts.js/Token";
import { existsSync, readFileSync } from "fs";
import { resolve } from "path";

import { TestL3State } from "./harness/state.js";
import { ARTIFACT_DIR_PATH } from "./verify-shared.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_recursive_settlement-L3RecursiveSettlement.json",
);

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

interface Batch64Payload {
  mergedPublicInputs: string[];
  mergedNullifiers: string[];
  mergedNoteHashes: string[];
  mergedDeposits: string[];
  mergedWithdrawals: string[];
  wrapperVkHash: string;  // 8-slot wrapper VK hash -- contract's tube_vk_hash
  w16VkHash: string;      // wrapper_16 VK hash -- contract's vk_hash_16
  w32VkHash: string;      // wrapper_32 VK hash -- contract's vk_hash_32
  w64VkHash: string;      // wrapper_64 VK hash -- contract's vk_hash_64
}

async function main() {
  // Load artifacts from step 1's run.
  const proofPath = resolve(ARTIFACT_DIR_PATH, "wrapper_64_proof.bin");
  const vkPath = resolve(ARTIFACT_DIR_PATH, "wrapper_64_vk.bin");
  const payloadPath = resolve(ARTIFACT_DIR_PATH, "batch_64_submit_payload.json");
  for (const p of [proofPath, vkPath, payloadPath]) {
    if (!existsSync(p)) {
      console.error(`Missing ${p}`);
      console.error("Run npm run verify:recursive:64 first.");
      process.exit(2);
    }
  }
  const quadProof = new Uint8Array(readFileSync(proofPath));
  const quadVk = new Uint8Array(readFileSync(vkPath));
  const payload: Batch64Payload = JSON.parse(readFileSync(payloadPath, "utf-8"));
  const quadProofFields = bytesToBigInts(quadProof);
  const quadVkFields = bytesToBigInts(quadVk);

  // Sandbox.
  console.log(`Connecting to ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error("Cannot reach sandbox. Run `npm run sandbox:up` first."); process.exit(1);
  }

  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin] = await Promise.all(
    testAccounts.slice(0, 1).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  // Token (needed because contract constructor funds a token balance).
  const { contract: token } = await TokenContract.deploy(wallet, admin, "TT", "TT", 18)
    .send({ from: admin });

  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT_PATH, "utf-8")) as NoirCompiledContract,
  );

  // Probe each chain-binding slot by deploying with that slot wrong, submitting
  // the valid quad proof, and expecting the matching assertion to fire.
  const wrong = BigInt("0xdeadbeefcafebabe");

  type Case = { slot: string; deployHashes: bigint[]; expectedMessage: string };
  const cases: Case[] = [
    {
      slot: "tube_vk_hash (PI[8] wrapper_vk_hash)",
      deployHashes: [wrong, BigInt(payload.w16VkHash), BigInt(payload.w32VkHash), BigInt(payload.w64VkHash)],
      expectedMessage: "inner wrapper_vk_hash does not match committed tube_vk_hash",
    },
    {
      slot: "vk_hash_16 (PI[9] w16_vk_hash)",
      deployHashes: [BigInt(payload.wrapperVkHash), wrong, BigInt(payload.w32VkHash), BigInt(payload.w64VkHash)],
      expectedMessage: "inner vk_hash_16 does not match committed vk_hash_16",
    },
    {
      slot: "vk_hash_32 (PI[10] w32_vk_hash)",
      deployHashes: [BigInt(payload.wrapperVkHash), BigInt(payload.w16VkHash), wrong, BigInt(payload.w64VkHash)],
      expectedMessage: "inner vk_hash_32 does not match committed vk_hash_32",
    },
  ];

  let pass = 0, fail = 0;
  for (const c of cases) {
    console.log(`\n=== Deploying with wrong ${c.slot} ===`);
    const state = await TestL3State.create();
    const initialRoot = state.stateRoot.toBigInt();
    const { contract: l3 } = await Contract.deploy(
      wallet, l3Artifact,
      [initialRoot, c.deployHashes[0], c.deployHashes[1], c.deployHashes[2], c.deployHashes[3], 0n],
      "constructor",
    ).send({ from: admin });

    await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });

    console.log(`Submitting valid quad proof; expecting assertion: "${c.expectedMessage}"`);
    let got: string | null = null;
    try {
      await l3.methods
        .submit_batch_64(
          quadVkFields,
          quadProofFields,
          payload.mergedPublicInputs,
          BigInt(payload.w64VkHash),
          payload.mergedNullifiers,
          payload.mergedNoteHashes,
          payload.mergedDeposits,
          payload.mergedWithdrawals,
          new Array(2048).fill(0n), // private_logs (64 tx * 2 outputs * 16 fields)
        )
        .send({ from: admin });
      got = "(call succeeded -- expected revert!)";
    } catch (e: any) {
      got = e?.message ?? String(e);
    }

    const matched = got?.includes(c.expectedMessage);
    if (matched) {
      console.log(`  PASS: rejected with expected assertion`);
      pass++;
    } else {
      console.log(`  FAIL: got: ${(got ?? "").slice(0, 300)}`);
      fail++;
    }
  }

  console.log(`\n=== Summary: PASS=${pass} FAIL=${fail} ===`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error("\nFATAL:", e?.message ?? e);
  process.exit(1);
});
