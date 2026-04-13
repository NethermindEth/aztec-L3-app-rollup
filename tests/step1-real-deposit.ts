/**
 * Step 1: Real deposit() works in sandbox.
 *
 * 1. Deploy Token + L3Settlement
 * 2. Mint private tokens to depositor
 * 3. Create authwit for L3Settlement to call transfer_to_public
 * 4. Call deposit() from depositor
 * 5. Verify L3 contract received public tokens
 * 6. Verify pending deposit was registered (via batch nonce = 0, root unchanged)
 */

import { Fr } from "@aztec/aztec.js/fields";
import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { Contract } from "@aztec/aztec.js/contracts";
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
  console.log(`admin:     ${admin}`);
  console.log(`depositor: ${depositor}`);

  // 1. Deploy Token + L3
  console.log("\n1. Deploy...");
  const { contract: token } = await TokenContract.deploy(wallet, admin, "T", "T", 18)
    .send({ from: admin });
  console.log(`   Token: ${token.address}`);

  const l3Artifact = loadContractArtifact(
    JSON.parse(readFileSync(L3_ARTIFACT, "utf-8")) as NoirCompiledContract,
  );
  const { contract: l3 } = await Contract.deploy(wallet, l3Artifact, [0n, 0n], "constructor")
    .send({ from: admin });
  console.log(`   L3:    ${l3.address}`);

  // 2. Mint private tokens to depositor
  console.log("\n2. Mint 1000 private tokens to depositor...");
  await token.methods.mint_to_private(depositor, 1000n).send({ from: admin });
  const privBal = await view(token.methods.balance_of_private(depositor), depositor);
  console.log(`   depositor private balance: ${privBal}`);

  // 3. Create authwit for deposit
  console.log("\n3. Create authwit for L3IvcSettlement.deposit -> Token.transfer_to_public...");
  const depositAmount = 500n;
  const nonce = Fr.random();
  const depositSalt = Fr.random();
  const recipientPkX = Fr.random();
  const recipientPkY = Fr.random();

  // The authwit authorizes L3Settlement to call Token.transfer_to_public(depositor, l3, amount, nonce)
  const transferAction = token.methods.transfer_to_public(depositor, l3.address, depositAmount, nonce);

  try {
    const witness = await wallet.createAuthWit(depositor, {
      caller: l3.address,
      action: transferAction,
    });
    console.log("   authwit created");

    // 4. Call deposit() with the authwit attached
    console.log("\n4. Call deposit()...");
    await l3.methods.deposit(
      token.address,
      depositAmount,
      recipientPkX,
      recipientPkY,
      depositSalt,
      nonce,
    ).send({ from: depositor, authWitnesses: [witness] });
    console.log("   OK");
  } catch (e: any) {
    console.log(`   FAILED: ${e.message.slice(0, 300)}`);
    return;
  }

  // 5. Verify L3 contract public balance
  console.log("\n5. Verify state...");
  const l3PubBal = await view(token.methods.balance_of_public(l3.address), admin);
  console.log(`   L3 public balance: ${l3PubBal}`);

  const depositorPrivBal = await view(token.methods.balance_of_private(depositor), depositor);
  console.log(`   depositor private balance: ${depositorPrivBal}`);

  // 6. L3 state should be unchanged (no batch settled yet)
  const root = await view(l3.methods.get_latest_root(), admin);
  const nonceBatch = await view(l3.methods.get_batch_nonce(), admin);
  console.log(`   L3 root: ${root} (should be 0)`);
  console.log(`   L3 nonce: ${nonceBatch} (should be 0)`);

  console.log("\nDone.");
}

main().catch((e) => {
  console.error("FATAL:", e.message);
  console.error(e.stack?.split("\n").slice(0, 8).join("\n"));
  process.exit(1);
});
