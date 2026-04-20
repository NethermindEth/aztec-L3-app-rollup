import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import type { Point } from "@aztec/foundation/curves/grumpkin";

import { PRIVATE_LOG_SIZE_IN_FIELDS } from "./constants.js";
import { RecipientCounterWindow } from "./counter-store.js";
import { tryDecryptNoteLog, type NotePreimage } from "./note-log.js";
import { computeSiloedTagForPair } from "./tagging.js";

// An on-chain L3 settlement batch's `private_logs` array, as emitted into
// calldata by settle_batch*. Flat layout: [entry0 (16 fields), entry1, ...].
export interface SettleBatchLogsCalldata {
  /** Flat Fr array of length N * 16 where N is the batch size. */
  privateLogs: Fr[];
  /** Optional: the contract address (app) the call was made to. Used when
   *  the recipient wants to assert the tag was siloed with the expected app. */
  app: Fr;
  /** Optional: block height or tx hash so finalization can be tracked. */
  blockNumber?: number;
  /** Whether this batch lives in a finalized L2 block. */
  finalized: boolean;
}

export interface DecryptedNote {
  note: NotePreimage;
  taggingIndex: bigint;
  /** Position of the log in the batch's flat array. */
  slot: number;
  /** Block number reported by the source calldata entry, if known. */
  blockNumber?: number;
}

export interface KnownSender {
  /** Sender's address (the `local` in the sender's view, `external` for the recipient here). */
  senderAddress: Fr;
  /** Sender's address point (ECDH counterpart). */
  senderAddressPoint: Point;
}

export interface RecipientContext {
  recipientAddress: Fr;
  recipientAddressSecret: Fq;
  /** Known counterparties to scan for. Unknown senders cannot be tag-matched. */
  knownSenders: KnownSender[];
  /** Per-pair sliding-window tracker. */
  window: RecipientCounterWindow;
}

/**
 * Scan a settle_batch* calldata blob for logs addressed to this recipient.
 *
 * Algorithm (matches aztec-packages v4.2 pxe/tagging recipient sync):
 *   1. Integrity check: re-hash privateLogs and (optionally) compare to a
 *      known batch-level `private_logs_hash` from the proof.
 *   2. For each known sender, compute expected siloed tags over the scan
 *      window `(agedMax, finalizedMax + WINDOW_LEN]`.
 *   3. For each 16-field entry in the calldata, check whether its first field
 *      matches any expected siloed tag. Matches are candidates for decryption.
 *   4. Trial-decrypt candidates with the recipient's address secret; drop
 *      entries where the plaintext fails to round-trip.
 *   5. Advance the window's finalized max for observed indices.
 */
export async function scanSettleBatchLogs(
  batch: SettleBatchLogsCalldata,
  recipient: RecipientContext,
): Promise<DecryptedNote[]> {
  if (batch.privateLogs.length % PRIVATE_LOG_SIZE_IN_FIELDS !== 0) {
    throw new Error("privateLogs length must be a multiple of 16");
  }
  const numEntries = batch.privateLogs.length / PRIVATE_LOG_SIZE_IN_FIELDS;

  // Precompute expected siloed tags for each known sender over their current
  // scan window. This gives us an (Fr.toString() -> {sender, index}) lookup.
  const expectedTags = new Map<string, { sender: KnownSender; index: number }>();
  for (const sender of recipient.knownSenders) {
    const range = recipient.window.scanRange(
      recipient.recipientAddress,
      sender.senderAddress,
      batch.app,
    );
    for (let i = range.from; i <= range.to; i++) {
      const tag = await computeSiloedTagForPair({
        // Sender's "local" side is the sender; we reproduce their computation.
        // Crucially we must use the RECIPIENT's address secret and SENDER's
        // address point -- ECDH is symmetric so this yields the same S.
        addressSecretSender: recipient.recipientAddressSecret,
        addressPointRecipient: sender.senderAddressPoint,
        app: batch.app,
        recipient: recipient.recipientAddress,
        index: i,
      });
      expectedTags.set(tag.toString(), { sender, index: i });
    }
  }

  const found: DecryptedNote[] = [];
  for (let slot = 0; slot < numEntries; slot++) {
    const base = slot * PRIVATE_LOG_SIZE_IN_FIELDS;
    const entry = batch.privateLogs.slice(base, base + PRIVATE_LOG_SIZE_IN_FIELDS);
    const tagStr = entry[0].toString();
    const candidate = expectedTags.get(tagStr);
    if (!candidate) continue;

    const decrypted = await tryDecryptNoteLog({
      flat: entry,
      addressSecret: recipient.recipientAddressSecret,
      appAddress: batch.app,
      expectedSiloedTag: entry[0],
    });
    if (!decrypted) continue;

    found.push({
      note: decrypted.note,
      taggingIndex: decrypted.taggingIndex,
      slot,
      blockNumber: batch.blockNumber,
    });

    // Advance this pair's window.
    recipient.window.markSeen(
      recipient.recipientAddress,
      candidate.sender.senderAddress,
      batch.app,
      candidate.index,
      batch.finalized,
    );
  }

  return found;
}

/**
 * Simple in-memory note store. A real wallet would key by note-commitment and
 * track spent/unspent plus block metadata; for the PoC we just keep
 * decrypted notes in insertion order.
 */
export class RecipientNoteStore {
  private notes: DecryptedNote[] = [];

  add(notes: DecryptedNote[]): void {
    for (const n of notes) this.notes.push(n);
  }

  all(): readonly DecryptedNote[] {
    return this.notes;
  }

  /** Recompute the expected note_hash for a stored note so the wallet can
   *  locate the leaf in the L3 note-hash tree. Must match Note::hash() in
   *  circuits/types/src/lib.nr. */
  static async noteHash(note: NotePreimage): Promise<Fr> {
    return poseidon2Hash([
      note.ownerPubkeyHash,
      note.amount,
      note.tokenId,
      note.salt,
    ]);
  }
}
