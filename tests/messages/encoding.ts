import { Fr } from "@aztec/foundation/curves/bn254";

import {
  MAX_MESSAGE_CONTENT_LEN,
  MESSAGE_EXPANDED_METADATA_LEN,
  MESSAGE_PLAINTEXT_LEN,
} from "./constants.js";

// Mirrors noir-projects/aztec-nr/aztec/src/messages/encoding.nr at v4.2.

const U64_SHIFT = 1n << 64n;
const U128_MAX = (1n << 128n) - 1n;

export function toExpandedMetadata(msgType: bigint, msgMetadata: bigint): Fr {
  if (msgType < 0n || msgType >= 1n << 64n) throw new Error("msgType out of range");
  if (msgMetadata < 0n || msgMetadata >= 1n << 64n) throw new Error("msgMetadata out of range");
  return new Fr(msgType * U64_SHIFT + msgMetadata);
}

export function fromExpandedMetadata(field: Fr): { msgType: bigint; msgMetadata: bigint } | null {
  const v = field.toBigInt();
  if (v > U128_MAX) return null;
  const msgMetadata = v & ((1n << 64n) - 1n);
  const msgType = (v - msgMetadata) / U64_SHIFT;
  return { msgType, msgMetadata };
}

export function encodeMessage(
  msgType: bigint,
  msgMetadata: bigint,
  msgContent: Fr[],
): Fr[] {
  if (msgContent.length > MAX_MESSAGE_CONTENT_LEN) {
    throw new Error(`msgContent exceeds MAX_MESSAGE_CONTENT_LEN=${MAX_MESSAGE_CONTENT_LEN}`);
  }
  const out: Fr[] = new Array(msgContent.length + MESSAGE_EXPANDED_METADATA_LEN);
  out[0] = toExpandedMetadata(msgType, msgMetadata);
  for (let i = 0; i < msgContent.length; i++) out[i + MESSAGE_EXPANDED_METADATA_LEN] = msgContent[i];
  return out;
}

export function decodeMessage(
  message: Fr[],
): { msgType: bigint; msgMetadata: bigint; msgContent: Fr[] } | null {
  if (message.length < MESSAGE_EXPANDED_METADATA_LEN) return null;
  const meta = fromExpandedMetadata(message[0]);
  if (!meta) return null;
  return {
    msgType: meta.msgType,
    msgMetadata: meta.msgMetadata,
    msgContent: message.slice(MESSAGE_EXPANDED_METADATA_LEN),
  };
}

// Serialize a length-N Fr array to 32 bytes per field (big-endian). Matches
// aztec-nr's fields_to_bytes used for the AES body plaintext.
export function fieldsToBytes32(fields: Fr[]): Uint8Array {
  const out = new Uint8Array(fields.length * 32);
  for (let i = 0; i < fields.length; i++) {
    const buf = fields[i].toBuffer(); // big-endian 32 bytes
    out.set(buf, i * 32);
  }
  return out;
}

export function bytes32ToFields(bytes: Uint8Array): Fr[] {
  if (bytes.length % 32 !== 0) throw new Error("bytes length must be multiple of 32");
  const out: Fr[] = [];
  for (let i = 0; i < bytes.length; i += 32) {
    out.push(Fr.fromBuffer(Buffer.from(bytes.slice(i, i + 32))));
  }
  return out;
}

// Pack bytes into fields at 31 bytes per field (big-endian, zero high byte).
// Matches aztec-nr's bytes_to_fields used for the ciphertext wire layout.
export function bytesToFields31(bytes: Uint8Array): Fr[] {
  if (bytes.length % 31 !== 0) throw new Error("bytes length must be multiple of 31");
  const out: Fr[] = [];
  const buf = Buffer.alloc(32);
  for (let i = 0; i < bytes.length; i += 31) {
    buf.fill(0);
    for (let j = 0; j < 31; j++) buf[j + 1] = bytes[i + j];
    out.push(Fr.fromBuffer(buf));
  }
  return out;
}

export function fieldsToBytes31(fields: Fr[]): Uint8Array {
  const out = new Uint8Array(fields.length * 31);
  for (let i = 0; i < fields.length; i++) {
    const buf = fields[i].toBuffer(); // 32 bytes BE
    for (let j = 0; j < 31; j++) out[i * 31 + j] = buf[j + 1];
  }
  return out;
}

// Used for bound-checking decoded plaintext (the message may be shorter than
// MESSAGE_PLAINTEXT_LEN; trailing zero fields are stripped). Returns the first
// prefix length at which decode_message succeeds.
export function stripTrailingZeros(fields: Fr[]): Fr[] {
  let end = fields.length;
  while (end > 0 && fields[end - 1].isZero()) end--;
  return fields.slice(0, end);
}

export { MAX_MESSAGE_CONTENT_LEN, MESSAGE_PLAINTEXT_LEN };
