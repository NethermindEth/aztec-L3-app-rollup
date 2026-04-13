/**
 * Single-batch e2e benchmark for the recursive UltraHonk pipeline.
 *
 * All transactions are deposits, proved in a single batch of MAX_BATCH_SIZE (16).
 * This fills the recursive path's circuit to its compiled capacity.
 *
 * Flow:
 *   1. Register TX_COUNT deposits on L2 via deposit()
 *   2. Generate TX_COUNT deposit proofs (all against same state root)
 *   3. Build one batch proof (batch_app_standalone + wrapper)
 *   4. Submit to L2, verify on-chain state
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
  type TxProofResult,
} from "./harness/prover-recursive.js";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT_PATH = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_recursive_settlement-L3RecursiveSettlement.json",
);
// Recursive pipeline sub-batch size is currently 8, so this bench fills one
// sub-batch exactly with 8 deposits.
const TX_COUNT = 8;

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

function fmtTime(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}m`;
}

async function main() {
  console.log(`=== ${TX_COUNT}-tx Single-Batch E2E (Recursive UltraHonk) ===\n`);
  console.log(`  ${TX_COUNT} deposits in 1 batch of ${TX_COUNT}\n`);

  // Connect.
  console.log(`Connecting to sandbox at ${NODE_URL}...`);
  const node = createAztecNodeClient(NODE_URL);
  try { await waitForNode(node); } catch {
    console.error("Cannot reach sandbox."); process.exit(1);
  }
  console.log("Connected.\n");

  const api = await Barretenberg.new({ threads: 4 });

  // Wrapper VK hash.
  console.log("Computing wrapper VK hash...");
  const vkStart = performance.now();
  const { vkHash: wrapperVkHash } = await computeWrapperVkHash(api);
  console.log(`  ${wrapperVkHash.toString().slice(0, 18)}... (${fmtTime(performance.now() - vkStart)})\n`);

  // Wallet + accounts.
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const testAccounts = await getInitialTestAccountsData();
  const [admin, aliceL2] = await Promise.all(
    testAccounts.slice(0, 2).map(async (acc: any) =>
      (await wallet.createSchnorrAccount(acc.secret, acc.salt, acc.signingKey)).address,
    ),
  );

  // Deploy.
  console.log("Deploying contracts...");
  const { contract: token } = await TokenContract.deploy(wallet, admin, "TestToken", "TT", 18)
    .send({ from: admin });
  const l3State = await TestL3State.create();
  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT_PATH, "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(
    wallet, l3Artifact,
    [l3State.stateRoot.toBigInt(), wrapperVkHash.toBigInt()],
    "constructor",
  ).send({ from: admin });

  await token.methods.mint_to_public(l3.address, 1_000_000n).send({ from: admin });
  // Mint enough private tokens for all deposits.
  await token.methods.mint_to_private(aliceL2, BigInt(TX_COUNT) * 100n).send({ from: admin });
  console.log(`  Token: ${token.address}`);
  console.log(`  L3:    ${l3.address}\n`);

  const tokenId = new Fr(token.address.toBigInt());
  const depositAmount = new Fr(100n);

  // Create identities.
  const secrets: Fr[] = [];
  const pks: { x: Fr; y: Fr }[] = [];
  const pkHashes: Fr[] = [];
  for (let i = 0; i < TX_COUNT; i++) {
    const secret = new Fr(BigInt(0xd000 + i));
    secrets.push(secret);
    const pk = await derivePubkey(secret);
    pks.push(pk);
    pkHashes.push(await l3State.hashPubkey(pk.x, pk.y));
  }

  // Register deposits on L2.
  console.log(`Registering ${TX_COUNT} deposits on L2...`);
  const salts: Fr[] = [];
  const regStart = performance.now();
  for (let i = 0; i < TX_COUNT; i++) {
    const salt = new Fr(BigInt(7000 + i));
    salts.push(salt);
    const nonce = Fr.random();
    const action = token.methods.transfer_to_public(
      aliceL2, l3.address, depositAmount.toBigInt(), nonce,
    );
    const authwit = await wallet.createAuthWit(aliceL2, { caller: l3.address, action });
    await l3.methods
      .deposit(token.address, depositAmount, pks[i].x, pks[i].y, salt, nonce)
      .send({ from: aliceL2, authWitnesses: [authwit] });

    const dHash = await l3State.depositHash(pkHashes[i], depositAmount, tokenId, salt);
    l3State.registerDeposit(dHash);
    console.log(`  ${i + 1}/${TX_COUNT}`);
  }
  const regMs = performance.now() - regStart;
  console.log(`  Registration: ${fmtTime(regMs)}\n`);

  // Phase 1: Generate deposit proofs.
  console.log(`=== Phase 1: Generate ${TX_COUNT} deposit proofs ===`);
  const proofs: TxProofResult[] = [];
  const txStart = performance.now();
  for (let i = 0; i < TX_COUNT; i++) {
    const proof = await proveDeposit(
      api, l3State, depositAmount, tokenId,
      pks[i].x, pks[i].y, salts[i],
    );
    proofs.push(proof);
    console.log(`  ${i + 1}/${TX_COUNT} proved`);
  }
  const txProofMs = performance.now() - txStart;
  console.log(`  Total: ${fmtTime(txProofMs)} (${(TX_COUNT / (txProofMs / 1000)).toFixed(2)} tx/s)\n`);

  // Phase 2: Build single batch proof with all txs.
  console.log(`=== Phase 2: Build batch proof (${TX_COUNT} txs in 1 batch) ===`);
  const batchStart = performance.now();
  const artifact = await buildBatchProofRecursive(api, l3State, proofs);
  const batchProveMs = performance.now() - batchStart;
  console.log(`  batch_app_standalone + wrapper: ${fmtTime(batchProveMs)}`);
  console.log(`  Wrapper proof: ${artifact.tubeProof.length} bytes\n`);

  // Phase 3: Submit to L2.
  console.log("=== Phase 3: Submit to L2 ===");
  const submitStart = performance.now();

  function bytesToBigInts(buf: Uint8Array): bigint[] {
    const count = Math.floor(buf.length / 32);
    const fields: bigint[] = [];
    for (let i = 0; i < count; i++) {
      const slice = buf.slice(i * 32, (i + 1) * 32);
      const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
      fields.push(BigInt(hex));
    }
    return fields;
  }

  await l3.methods
    .submit_batch(
      bytesToBigInts(artifact.tubeVk),
      bytesToBigInts(artifact.tubeProof),
      artifact.tubePublicInputs,
      wrapperVkHash,
      artifact.settleInputs.nullifiers,
      artifact.settleInputs.noteHashes,
      artifact.settleInputs.depositNullifiers,
      artifact.settleInputs.withdrawalClaims,
    )
    .send({ from: admin });
  const l2SubmitMs = performance.now() - submitStart;
  console.log(`  L2 submission: ${fmtTime(l2SubmitMs)}\n`);

  // Verify.
  const onChainRoot = await view(l3.methods.get_latest_root(), admin);
  const onChainNonce = await view(l3.methods.get_batch_nonce(), admin);
  assert(onChainRoot === l3State.stateRoot.toBigInt(), "root mismatch");
  assert(onChainNonce === 1n, "nonce should be 1");

  // Analysis.
  console.log("=== Analysis ===\n");
  console.log(`  TX proof generation:  ${fmtTime(txProofMs)} (${TX_COUNT} proofs)`);
  console.log(`  Batch proving:        ${fmtTime(batchProveMs)} (1 batch, ${TX_COUNT} txs)`);
  console.log(`  L2 submission:        ${fmtTime(l2SubmitMs)}`);
  console.log(`  Total proving:        ${fmtTime(txProofMs + batchProveMs)}`);
  console.log(`  Total e2e:            ${fmtTime(txProofMs + batchProveMs + l2SubmitMs)}`);
  console.log();
  console.log(`  Per-tx proving:       ${fmtTime((txProofMs + batchProveMs) / TX_COUNT)}`);
  console.log(`  Throughput:           ${(TX_COUNT / ((txProofMs + batchProveMs) / 1000)).toFixed(3)} tx/s`);
  console.log();

  const daPerBatch = 28 * 32; // fields * bytes_per_field (from DA optimization)
  console.log(`  DA per batch:         ${daPerBatch} bytes`);
  console.log(`  DA per tx:            ${(daPerBatch / TX_COUNT).toFixed(0)} bytes`);
  console.log();

  console.log("L2 verification:");
  console.log(`  Batch nonce:     ${onChainNonce}`);
  console.log(`  Root matches:    ${onChainRoot === l3State.stateRoot.toBigInt()}`);
  console.log(`  Nullifier tree:  ${l3State.nullifierTreeStartIndex}`);
  console.log(`  Note hash tree:  ${l3State.noteHashTreeStartIndex}`);

  await api.destroy();
  console.log("\nDone.");
}

main().catch((e) => {
  console.error("\nFATAL:", e.message ?? e);
  console.error(e.stack?.split("\n").slice(0, 10).join("\n"));
  process.exit(1);
});
