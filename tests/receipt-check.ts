import { createAztecNodeClient, waitForNode } from "@aztec/aztec.js/node";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { TokenContract } from "@aztec/noir-contracts.js/Token";

async function main() {
  const node = createAztecNodeClient("http://aztec:8080");
  await waitForNode(node);
  const wallet = await EmbeddedWallet.create(node, { ephemeral: true });
  const { getInitialTestAccountsData } = await import("@aztec/accounts/testing");
  const accs = await getInitialTestAccountsData();
  const [admin] = await Promise.all(
    accs.slice(0, 1).map(async (a: any) =>
      (await wallet.createSchnorrAccount(a.secret, a.salt, a.signingKey)).address,
    ),
  );

  const { contract: token } = await TokenContract.deploy(wallet, admin, "T", "T", 18)
    .send({ from: admin });

  const receipt = await token.methods.mint_to_public(admin, 100n).send({ from: admin });
  console.log("receipt type:", typeof receipt);
  console.log("receipt keys:", Object.keys(receipt));
  console.log("status:", receipt.status);
  console.log("txHash:", receipt.txHash?.toString());
  console.log("revertReason:", receipt.revertReason);

  // Check if receipt has public logs
  const logs = (receipt as any).publicLogs ?? (receipt as any).logs ?? (receipt as any).unencryptedLogs;
  console.log("logs field:", logs);

  // Try reading balance via a different pattern
  const bal = await token.methods.balance_of_public(admin).simulate({ from: admin });
  console.log("balance simulate result:", bal, typeof bal);
}

main().catch((e) => { console.error(e.message); console.error(e.stack?.split("\n").slice(0,5).join("\n")); });
