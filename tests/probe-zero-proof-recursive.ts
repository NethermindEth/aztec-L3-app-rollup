/**
 * Probe: does the recursive contract verify proofs, or is verify_honk_proof a no-op?
 * Submits an all-zero 500-field proof (correct ABI size) to L3RecursiveSettlement.
 */
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
import { loadContractArtifact } from "@aztec/stdlib/abi";
import type { NoirCompiledContract } from "@aztec/stdlib/noir";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { readFileSync } from "fs";
import { resolve } from "path";

async function main() {
  const node = createAztecNodeClient("http://localhost:8080");
  await waitForNode(node);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const accs = await getInitialTestAccountsData();
  const [admin] = await Promise.all(
    accs.slice(0, 1).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  const art = loadContractArtifact(
    JSON.parse(readFileSync(resolve(import.meta.dirname ?? ".", "../target/l3_recursive_settlement-L3RecursiveSettlement.json"), "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(wallet, art, [0n, 0n, 0n, 0n, 0n, 0n], "constructor")
    .send({ from: admin });

  console.log("=== Probe: all-zero 500-field proof against L3RecursiveSettlement ===");
  try {
    await l3.methods.submit_batch(
      new Array(115).fill(0n),   // VK (correct size)
      new Array(500).fill(0n),   // proof (500 fields -- matches ABI exactly)
      new Array(10).fill(0n),    // public inputs (Phase 2: 10-field BatchOutput)
      0n,                        // vk_hash = 0 (matches constructor's stored 0)
      new Array(16).fill(0n),
      new Array(16).fill(0n),
      new Array(8).fill(0n),
      new Array(8).fill(0n),
      new Array(256).fill(0n),   // private_logs (8 tx * 2 outputs * 16 fields)
    ).send({ from: admin });
    console.log("RESULT: ACCEPTED — verify_honk_proof is a no-op on the sandbox");
  } catch (e: any) {
    console.log(`RESULT: REJECTED — ${(e.message ?? "").slice(0, 150)}`);
  }
}

main().catch((e) => { console.error("FATAL:", e.message); process.exit(1); });
