import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import type { Point } from "@aztec/foundation/curves/grumpkin";

import { L3_MSG_TYPE_NOTE, MESSAGE_PLAINTEXT_LEN, PRIVATE_LOG_SIZE_IN_FIELDS } from "./constants.js";
import { decodeMessage, encodeMessage } from "./encoding.js";
import { decryptMessage, encryptMessage } from "./encryption.js";
import { computeSiloedTagForPair } from "./tagging.js";

// L3-specific glue between the generic Aztec message layer and the L3 Note
// struct (circuits/types/src/lib.nr:41-46).

export interface NotePreimage {
  ownerPubkeyHash: Fr;
  amount: Fr;
  tokenId: Fr;
  salt: Fr;
}

export interface BuildNoteLogParams {
  note: NotePreimage;
  senderAddressSecret: Fq;
  senderEphSk: Fq;
  recipientAddressPoint: Point;
  recipientAddress: Fr;
  appAddress: Fr;
  taggingIndex: number | bigint;
}

export interface NoteLogFields {
  siloedTag: Fr;
  ciphertext: Fr[]; // 15 fields
  flat: Fr[]; // 16 fields = [tag, ct_0..ct_14]
}

export async function buildNoteLog(params: BuildNoteLogParams): Promise<NoteLogFields> {
  const siloedTag = await computeSiloedTagForPair({
    addressSecretSender: params.senderAddressSecret,
    addressPointRecipient: params.recipientAddressPoint,
    app: params.appAddress,
    recipient: params.recipientAddress,
    index: params.taggingIndex,
  });

  // Message layout: expanded metadata | [owner_pubkey_hash, amount, token_id, salt]
  // Metadata carries the tagging index in msg_metadata so the recipient learns
  // which counter was used (useful for syncing their own counter store).
  const encoded = encodeMessage(
    L3_MSG_TYPE_NOTE,
    typeof params.taggingIndex === "bigint" ? params.taggingIndex : BigInt(params.taggingIndex),
    [params.note.ownerPubkeyHash, params.note.amount, params.note.tokenId, params.note.salt],
  );
  // Pad to MESSAGE_PLAINTEXT_LEN (12 fields) with zeros.
  const plaintext = new Array<Fr>(MESSAGE_PLAINTEXT_LEN);
  for (let i = 0; i < MESSAGE_PLAINTEXT_LEN; i++) {
    plaintext[i] = i < encoded.length ? encoded[i] : new Fr(0n);
  }

  const ciphertext = await encryptMessage({
    ephSk: params.senderEphSk,
    addressPoint: params.recipientAddressPoint,
    appAddress: params.appAddress,
    plaintext,
  });

  const flat = new Array<Fr>(PRIVATE_LOG_SIZE_IN_FIELDS);
  flat[0] = siloedTag;
  for (let i = 0; i < ciphertext.length; i++) flat[i + 1] = ciphertext[i];

  return { siloedTag, ciphertext, flat };
}

export interface TryDecryptNoteLogParams {
  flat: Fr[]; // 16-field log from on-chain
  addressSecret: Fq;
  appAddress: Fr;
  expectedSiloedTag?: Fr; // if provided, must match flat[0]
}

export async function tryDecryptNoteLog(
  params: TryDecryptNoteLogParams,
): Promise<{ note: NotePreimage; taggingIndex: bigint } | null> {
  if (params.flat.length !== PRIVATE_LOG_SIZE_IN_FIELDS) return null;
  if (params.expectedSiloedTag && !params.flat[0].equals(params.expectedSiloedTag)) return null;

  const ciphertext = params.flat.slice(1);
  const plaintext = await decryptMessage({
    ciphertext,
    addressSecret: params.addressSecret,
    appAddress: params.appAddress,
  });
  if (!plaintext) return null;

  const decoded = decodeMessage(plaintext);
  if (!decoded) return null;
  if (decoded.msgType !== L3_MSG_TYPE_NOTE) return null;
  if (decoded.msgContent.length < 4) return null;

  const [ownerPubkeyHash, amount, tokenId, salt] = decoded.msgContent;
  return {
    note: { ownerPubkeyHash, amount, tokenId, salt },
    taggingIndex: decoded.msgMetadata,
  };
}
