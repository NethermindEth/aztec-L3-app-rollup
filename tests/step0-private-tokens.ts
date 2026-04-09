/**
 * Step 0: Verify private token plumbing works in the sandbox.
 *
 * 1. Create account
 * 2. Mint to private
 * 3. Verify balance
 * 4. Transfer private-to-private to prove the note is usable
 */

import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { TokenContract } from "@aztec/noir-contracts.js/Token";

const NODE_URL = process.env.AZTEC_NODE_URL ?? "http://localhost:8080";

async function main() {
  console.log("Connecting...");
  const node = createAztecNodeClient(NODE_URL);
  await waitForNode(node);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });

  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const accs = await getInitialTestAccountsData();
  const [minter, alice, bob] = await Promise.all(
    accs.slice(0, 3).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );
  console.log(`minter: ${minter}`);
  console.log(`alice:  ${alice}`);
  console.log(`bob:    ${bob}`);

  // Deploy token with minter.
  console.log("\n1. Deploy Token...");
  const { contract: token } = await TokenContract.deploy(wallet, minter, "T", "T", 18)
    .send({ from: minter });
  console.log(`   Token: ${token.address}`);

  // Mint to private for alice.
  console.log("\n2. mint_to_private(alice, 500)...");
  try {
    await token.methods.mint_to_private(alice, 500n).send({ from: minter });
    console.log("   OK");
  } catch (e: any) {
    console.log(`   FAILED: ${e.message.slice(0, 200)}`);
    return;
  }

  // Check private balance.
  console.log("\n3. balance_of_private(alice)...");
  try {
    const bal = await token.methods.balance_of_private(alice).simulate({ from: alice });
    const amount = bal.result ?? bal;
    console.log(`   balance: ${amount}`);
    if (BigInt(amount.toString()) !== 500n) {
      console.log(`   UNEXPECTED: expected 500`);
    }
  } catch (e: any) {
    console.log(`   FAILED: ${e.message.slice(0, 200)}`);
  }

  // Transfer private alice -> bob to prove the note is usable.
  console.log("\n4. transfer(bob, 100) from alice...");
  try {
    await token.methods.transfer(bob, 100n).send({ from: alice });
    console.log("   OK");
  } catch (e: any) {
    console.log(`   FAILED: ${e.message.slice(0, 200)}`);
    return;
  }

  // Check balances after transfer.
  console.log("\n5. Final balances...");
  try {
    const aliceBal = await token.methods.balance_of_private(alice).simulate({ from: alice });
    const bobBal = await token.methods.balance_of_private(bob).simulate({ from: bob });
    console.log(`   alice: ${aliceBal.result ?? aliceBal}`);
    console.log(`   bob:   ${bobBal.result ?? bobBal}`);
  } catch (e: any) {
    console.log(`   FAILED: ${e.message.slice(0, 200)}`);
  }

  console.log("\nDone.");
}

main().catch((e) => {
  console.error("FATAL:", e.message);
  console.error(e.stack?.split("\n").slice(0, 5).join("\n"));
  process.exit(1);
});
