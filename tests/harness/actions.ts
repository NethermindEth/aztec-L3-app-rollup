/**
 * Actions -- ties TestL3State + prover + contract calls.
 */

import { type Barretenberg } from "@aztec/bb.js";
import { Fr } from "@aztec/aztec.js/fields";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { type Contract } from "@aztec/aztec.js/contracts";
import { type AztecAddress } from "@aztec/aztec.js/addresses";
import { TestL3State, type L3Note } from "./state.js";
import {
  buildBatchProof,
  proveDeposit,
  provePayment,
  proveWithdraw,
  type TxProofResult,
  type BatchArtifact,
} from "./prover.js";

// Convert raw VK/proof bytes (32 bytes per field) to Fr/bigint arrays.
function vkBytesToFields(buf: Uint8Array): Fr[] {
  const count = Math.floor(buf.length / 32);
  const fields: Fr[] = [];
  for (let i = 0; i < count; i++) {
    const slice = buf.slice(i * 32, (i + 1) * 32);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    fields.push(new Fr(BigInt(hex)));
  }
  return fields;
}

function proofBytesToFields(buf: Uint8Array): bigint[] {
  const count = Math.floor(buf.length / 32);
  const fields: bigint[] = [];
  for (let i = 0; i < count; i++) {
    const slice = buf.slice(i * 32, (i + 1) * 32);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    fields.push(BigInt(hex));
  }
  return fields;
}

export class L3Harness {
  private pendingSlots: TxProofResult[] = [];

  constructor(
    public api: Barretenberg,
    public state: TestL3State,
    public l3Contract: Contract,
    public tokenContract: Contract,
    public tokenAddress: AztecAddress,
    public callPublicAsL3: (method: any) => Promise<void>,
    public callPrivate: ((method: any) => Promise<void>) | null = null,
  ) {}

  async deposit(
    recipientPubkeyX: Fr, recipientPubkeyY: Fr,
    amount: Fr, tokenId: Fr, salt: Fr,
  ): Promise<{ depositHash: Fr; noteHash: Fr; proof: TxProofResult }> {
    const pkHash = await this.state.hashPubkey(recipientPubkeyX, recipientPubkeyY);
    const depositHash = await this.state.depositHash(pkHash, amount, tokenId, salt);

    await this.callPublicAsL3(
      this.l3Contract.methods.register_deposit_internal(depositHash),
    );
    this.state.registerDeposit(depositHash);

    const proof = await proveDeposit(this.api, this.state, amount, tokenId, recipientPubkeyX, recipientPubkeyY, salt);
    this.pendingSlots.push(proof);
    return { depositHash, noteHash: proof.noteHashes[0], proof };
  }

  async payment(
    ownerSecret: Fr, inputNotes: L3Note[],
    recipientPubkeyX: Fr, recipientPubkeyY: Fr,
    recipientAmount: Fr, outputSalts: [Fr, Fr],
  ): Promise<TxProofResult> {
    const proof = await provePayment(
      this.api, this.state, ownerSecret, inputNotes,
      recipientPubkeyX, recipientPubkeyY, recipientAmount, outputSalts,
    );
    this.pendingSlots.push(proof);
    return proof;
  }

  async withdraw(
    ownerSecret: Fr, inputNotes: L3Note[],
    l2TokenAddress: Fr, l2RecipientAddress: Fr,
    claimSalt: Fr, withdrawAmount: Fr, changeSalt: Fr,
  ): Promise<TxProofResult> {
    const proof = await proveWithdraw(
      this.api, this.state, ownerSecret, inputNotes,
      l2TokenAddress, l2RecipientAddress, claimSalt, withdrawAmount, changeSalt,
    );
    this.pendingSlots.push(proof);
    return proof;
  }

  async submitBatch(): Promise<BatchArtifact> {
    const slots = [...this.pendingSlots];
    this.pendingSlots = [];

    const artifact = await buildBatchProof(this.api, this.state, slots);

    if (this.callPrivate) {
      const publicInputs = [
        artifact.oldStateRoot,
        artifact.newStateRoot,
        artifact.settleInputs.nullifiersBatchHash,
        artifact.settleInputs.noteHashesBatchHash,
        artifact.settleInputs.depositNullifiersHash,
        artifact.settleInputs.withdrawalClaimsHash,
        artifact.nullifierTreeStartIndex,
        artifact.noteHashTreeStartIndex,
      ];

      // VK is [Field; 115] — convert 32-byte chunks to field values.
      const tubeVkFieldsFr = vkBytesToFields(artifact.tubeVk);
      const tubeVkHash = await poseidon2Hash(tubeVkFieldsFr);
      const tubeVkBigInts = tubeVkFieldsFr.map((f) => f.toBigInt());
      const tubeProofBigInts = proofBytesToFields(artifact.tubeProof);

      await this.callPrivate(
        this.l3Contract.methods.submit_batch(
          tubeVkBigInts,
          tubeProofBigInts,
          publicInputs,
          tubeVkHash,
          artifact.settleInputs.nullifiers,
          artifact.settleInputs.noteHashes,
          artifact.settleInputs.depositNullifiers,
          artifact.settleInputs.withdrawalClaims,
        ),
      );
    } else {
      await this.callPublicAsL3(
        this.l3Contract.methods.settle_batch(
          Fr.ZERO,
          artifact.oldStateRoot,
          artifact.newStateRoot,
          artifact.settleInputs.nullifiersBatchHash,
          artifact.settleInputs.noteHashesBatchHash,
          artifact.settleInputs.depositNullifiersHash,
          artifact.settleInputs.withdrawalClaimsHash,
          artifact.nullifierTreeStartIndex,
          artifact.noteHashTreeStartIndex,
          artifact.settleInputs.nullifiers,
          artifact.settleInputs.noteHashes,
          artifact.settleInputs.depositNullifiers,
          artifact.settleInputs.withdrawalClaims,
        ),
      );
    }

    return artifact;
  }

  async claimWithdrawal(amount: Fr, recipient: AztecAddress, salt: Fr) {
    const secret = await poseidon2Hash([Fr.fromString(recipient.toString()), salt]);
    const claimHash = await poseidon2Hash([
      Fr.fromString(this.tokenAddress.toString()), amount, secret,
    ]);
    await this.callPublicAsL3(
      this.l3Contract.methods.claim_withdrawal(this.tokenAddress, amount, recipient, salt, claimHash),
    );
  }

  async computeClaimHash(tokenAddr: Fr, amount: Fr, recipient: Fr, salt: Fr): Promise<Fr> {
    const secret = await poseidon2Hash([recipient, salt]);
    return poseidon2Hash([tokenAddr, amount, secret]);
  }

  get pendingCount() { return this.pendingSlots.length; }
}
