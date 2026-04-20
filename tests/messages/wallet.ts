import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { Point } from "@aztec/foundation/curves/grumpkin";

import { PRIVATE_LOG_SIZE_IN_FIELDS } from "./constants.js";
import {
  buildNoteLog,
  type BuildNoteLogParams,
  type NoteLogFields,
  type NotePreimage,
} from "./note-log.js";
import { SenderCounterStore } from "./counter-store.js";

// MAX_OUTPUTS_PER_TX matches circuits/types/src/lib.nr -- keep in sync.
export const MAX_OUTPUTS_PER_TX = 2;
export const TX_LOG_PAYLOAD_LEN = MAX_OUTPUTS_PER_TX * PRIVATE_LOG_SIZE_IN_FIELDS; // 32

export interface TxOutputRecipient {
  note: NotePreimage;
  /** Recipient's address (field used as the directional-secret binding). */
  recipientAddress: Fr;
  /** Recipient's address point (Grumpkin pubkey with positive y, Aztec style). */
  recipientAddressPoint: Point;
  /** Optional precomputed ephemeral sk; if omitted, one is generated. Used by
   *  tests for determinism. Must have a positive y when mapped to G. */
  ephSk?: Fq;
}

export interface BuildTxLogsParams {
  /** Sender's address used by tagging scheme (AztecAddress.to_field()). */
  senderAddress: Fr;
  /** Sender's address_secret (ivsk + preaddress, y-normalized). */
  senderAddressSecret: Fq;
  /** L2 contract address that will emit settle_batch; tag is siloed to it. */
  appAddress: Fr;
  /** Exactly MAX_OUTPUTS_PER_TX entries. A null entry produces a zero-log
   *  placeholder (no tag, no ciphertext) to preserve positional layout. */
  outputs: Array<TxOutputRecipient | null>;
  counterStore: SenderCounterStore;
}

export interface BuildTxLogsResult {
  /** Flat [Field; 32] payload -- matches per-tx private_logs witness. */
  privateLogs: Fr[];
  /** poseidon2_hash(privateLogs) -- matches per-tx logs_commit public input. */
  logsCommit: Fr;
  /** Per-output log detail (siloedTag, ciphertext, tagging index used). Null
   *  slots carry null. Indexers use this to build the recipient's expected-tag
   *  set during scan. */
  perOutput: Array<(NoteLogFields & { taggingIndex: number }) | null>;
}

async function generatePositiveEphSk(): Promise<Fq> {
  const halfP = (Fr.MODULUS - 1n) / 2n;
  for (let attempt = 0; attempt < 256; attempt++) {
    const sk = Fq.random();
    const pk = await Grumpkin.mul(Grumpkin.generator, sk);
    if (pk.y.toBigInt() <= halfP) return sk;
  }
  throw new Error("failed to find positive-y eph_sk");
}

export async function buildTxLogs(params: BuildTxLogsParams): Promise<BuildTxLogsResult> {
  if (params.outputs.length !== MAX_OUTPUTS_PER_TX) {
    throw new Error(`outputs must have exactly ${MAX_OUTPUTS_PER_TX} entries`);
  }

  const perOutput: Array<(NoteLogFields & { taggingIndex: number }) | null> = [];
  const flat: Fr[] = new Array(TX_LOG_PAYLOAD_LEN);
  for (let i = 0; i < TX_LOG_PAYLOAD_LEN; i++) flat[i] = new Fr(0n);

  for (let o = 0; o < MAX_OUTPUTS_PER_TX; o++) {
    const out = params.outputs[o];
    if (!out) {
      perOutput.push(null);
      continue;
    }

    const taggingIndex = params.counterStore.reserveNextIndex(
      params.senderAddress,
      out.recipientAddress,
      params.appAddress,
    );

    const ephSk = out.ephSk ?? (await generatePositiveEphSk());

    const buildParams: BuildNoteLogParams = {
      note: out.note,
      senderAddressSecret: params.senderAddressSecret,
      senderEphSk: ephSk,
      recipientAddressPoint: out.recipientAddressPoint,
      recipientAddress: out.recipientAddress,
      appAddress: params.appAddress,
      taggingIndex: BigInt(taggingIndex),
    };
    const log = await buildNoteLog(buildParams);

    // Splice into the flat layout at slot o.
    const base = o * PRIVATE_LOG_SIZE_IN_FIELDS;
    for (let i = 0; i < PRIVATE_LOG_SIZE_IN_FIELDS; i++) flat[base + i] = log.flat[i];
    perOutput.push({ ...log, taggingIndex });
  }

  const logsCommit = await poseidon2Hash(flat);
  return { privateLogs: flat, logsCommit, perOutput };
}

/**
 * Concatenate `MAX_BATCH_SIZE` per-tx log payloads into the flat
 * batch-level array that `batch_app(_standalone)` expects as witness and
 * that the settle_batch* endpoint carries as calldata. Unused slots should
 * be supplied as an array of zeros with length TX_LOG_PAYLOAD_LEN.
 */
export function assembleBatchLogsFlat(perTxPayloads: Fr[][]): Fr[] {
  const out: Fr[] = [];
  for (const payload of perTxPayloads) {
    if (payload.length !== TX_LOG_PAYLOAD_LEN) {
      throw new Error(`per-tx payload must be ${TX_LOG_PAYLOAD_LEN} fields`);
    }
    out.push(...payload);
  }
  return out;
}
