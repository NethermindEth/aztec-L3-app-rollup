/**
 * Minimal sandbox test -- proves the PublicCallRequest.isEmpty failure
 * is an Aztec SDK / artifact format issue, not L3 logic.
 */

import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
import { Fr } from "@aztec/aztec.js/fields";
import { loadContractArtifact } from "@aztec/stdlib/abi";
import type { NoirCompiledContract } from "@aztec/stdlib/noir";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { TokenContract } from "@aztec/noir-contracts.js/Token";
import { readFileSync } from "fs";
import { resolve } from "path";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";
const L3_ARTIFACT = resolve(
  import.meta.dirname ?? ".",
  "../target/l3_ivc_settlement-L3IvcSettlement.json",
);

async function main() {
  console.log("1. Connecting...");
  const node = createAztecNodeClient(NODE_URL);
  await waitForNode(node);
  console.log("   OK");

  console.log("2. Creating wallet + accounts...");
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const accs = await getInitialTestAccountsData();
  const [admin] = await Promise.all(
    accs.slice(0, 1).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );
  console.log("   admin:", admin.toString());

  // --- Token (from noir-contracts.js, same SDK version) ---

  console.log("3. Deploying Token...");
  const { contract: token } = await TokenContract.deploy(wallet, admin, "T", "T", 18)
    .send({ from: admin });
  console.log("   Token:", token.address.toString());

  console.log("4. Token.mint_to_public (simulate)...");
  try {
    const sim = await token.methods.mint_to_public(admin, 100n).simulate();
    console.log("   simulate OK:", sim);
  } catch (e: any) {
    console.log("   simulate FAILED:", e.message.slice(0, 120));
  }

  console.log("5. Token.mint_to_public (send)...");
  try {
    await token.methods.mint_to_public(admin, 100n).send({ from: admin });
    console.log("   send OK");
  } catch (e: any) {
    console.log("   send FAILED:", e.message.slice(0, 120));
  }

  // --- L3Settlement (our contract) ---

  console.log("6. Deploying L3IvcSettlement...");
  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT, "utf-8")) as NoirCompiledContract,
  );
  try {
    const { contract: l3 } = await Contract.deploy(wallet, l3Artifact, [0n, 0n, 0n], "constructor")
      .send({ from: admin });
    console.log("   L3:", l3.address.toString());

    console.log("7. L3.get_latest_root (simulate)...");
    try {
      const root = await l3.methods.get_latest_root().simulate();
      console.log("   simulate OK:", root);
    } catch (e: any) {
      console.log("   simulate FAILED:", e.message.slice(0, 120));
    }

    console.log("8. L3.mint_to_public on Token to L3 (send)...");
    try {
      await token.methods.mint_to_public(l3.address, 1000n).send({ from: admin });
      console.log("   send OK");
    } catch (e: any) {
      console.log("   send FAILED:", e.message.slice(0, 120));
    }
  } catch (e: any) {
    console.log("   deploy FAILED:", e.message.slice(0, 120));
    console.log("   stack:", e.stack?.split("\n").slice(0, 5).join("\n"));
  }

  console.log("\nDone.");
}

main().catch((e) => {
  console.error("FATAL:", e.message);
  console.error(e.stack?.split("\n").slice(0, 8).join("\n"));
  process.exit(1);
});
