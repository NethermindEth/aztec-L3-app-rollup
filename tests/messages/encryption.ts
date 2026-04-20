import { Aes128 } from "@aztec/foundation/crypto/aes128";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { poseidon2HashWithSeparator } from "@aztec/foundation/crypto/poseidon";
import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import { Point } from "@aztec/foundation/curves/grumpkin";

import {
  AES128_PKCS7_EXPANSION_IN_BYTES,
  CIPHERTEXT_BYTES,
  DOM_SEP__APP_SILOED_ECDH_SHARED_SECRET,
  DOM_SEP__ECDH_FIELD_MASK,
  DOM_SEP__ECDH_SUBKEY,
  EPH_PK_X_SIZE_IN_FIELDS,
  FILLED_CIPHERTEXT_BYTES,
  HEADER_CIPHERTEXT_SIZE_IN_BYTES,
  MESSAGE_PLAINTEXT_LEN,
  MESSAGE_PLAINTEXT_SIZE_IN_BYTES,
  PRIVATE_LOG_CIPHERTEXT_LEN,
} from "./constants.js";
import { bytesToFields31, fieldsToBytes31, fieldsToBytes32 } from "./encoding.js";

// Mirrors noir-projects/aztec-nr/aztec/src/messages/encryption/aes128.nr at v4.2.
//
// encrypt() returns PRIVATE_LOG_CIPHERTEXT_LEN (15) fields laid out as
//   [ eph_pk.x, packed_ct_0, ..., packed_ct_13 ]
// where packed_ct_i = bytes_to_field_31(byte_chunk_i) + mask_i (additive mask).

const aes = new Aes128();

async function deriveAppSiloedSharedSecret(sharedPoint: Point, appAddress: Fr): Promise<Fr> {
  return poseidon2HashWithSeparator(
    [sharedPoint.x, sharedPoint.y, appAddress],
    DOM_SEP__APP_SILOED_ECDH_SHARED_SECRET,
  );
}

async function deriveSubkey(sApp: Fr, index: number): Promise<Fr> {
  return poseidon2HashWithSeparator([sApp], DOM_SEP__ECDH_SUBKEY + index);
}

async function deriveFieldMask(sApp: Fr, index: number): Promise<Fr> {
  return poseidon2HashWithSeparator([sApp], DOM_SEP__ECDH_FIELD_MASK + index);
}

// Extract 32 close-to-uniformly-random bytes from two subkey fields. Matches
// `extract_many_close_to_uniformly_random_256_bits_using_poseidon2` in aes128.nr:
// takes the low 16 bytes (i.e. last 16 big-endian bytes) of each field.
async function extractRandom256(sApp: Fr, index: number): Promise<Uint8Array> {
  const rand1 = await deriveSubkey(sApp, 2 * index);
  const rand2 = await deriveSubkey(sApp, 2 * index + 1);
  const b1 = rand1.toBuffer(); // 32 bytes big-endian
  const b2 = rand2.toBuffer();
  const out = new Uint8Array(32);
  for (let i = 0; i < 16; i++) {
    out[i] = b1[32 - i - 1];
    out[16 + i] = b2[32 - i - 1];
  }
  return out;
}

async function deriveKeyIvPair(
  sApp: Fr,
  index: number,
): Promise<{ key: Uint8Array; iv: Uint8Array }> {
  const rand = await extractRandom256(sApp, index);
  return { key: rand.slice(0, 16), iv: rand.slice(16, 32) };
}

export interface EncryptParams {
  ephSk: Fq;
  addressPoint: Point;
  appAddress: Fr;
  plaintext: Fr[]; // exactly MESSAGE_PLAINTEXT_LEN fields (12)
}

export async function encryptMessage(params: EncryptParams): Promise<Fr[]> {
  const { ephSk, addressPoint, appAddress, plaintext } = params;
  if (plaintext.length !== MESSAGE_PLAINTEXT_LEN) {
    throw new Error(`plaintext must be exactly ${MESSAGE_PLAINTEXT_LEN} fields`);
  }

  // 1. ECDH shared point S = eph_sk * address_point.
  const sharedPoint = await Grumpkin.mul(addressPoint, ephSk);
  // 2. App-siloed secret.
  const sApp = await deriveAppSiloedSharedSecret(sharedPoint, appAddress);
  // 3. Two (key, iv) pairs: index 0 for header, index 1 for body.
  const { key: kHdr, iv: ivHdr } = await deriveKeyIvPair(sApp, 0);
  const { key: kBody, iv: ivBody } = await deriveKeyIvPair(sApp, 1);

  // 4. Body ciphertext: AES-128-CBC-PKCS7 over 32-bytes-per-field plaintext.
  const bodyPlainBytes = fieldsToBytes32(plaintext); // 12 * 32 = 384 bytes
  const bodyCt = new Uint8Array(await aes.encryptBufferCBC(bodyPlainBytes, ivBody, kBody));
  if (bodyCt.length !== MESSAGE_PLAINTEXT_SIZE_IN_BYTES + AES128_PKCS7_EXPANSION_IN_BYTES) {
    throw new Error(`unexpected body ct length ${bodyCt.length}`);
  }

  // 5. Header ciphertext: 2-byte BE body length, PKCS#7-padded to 16 bytes.
  const headerPlain = new Uint8Array(2);
  headerPlain[0] = (bodyCt.length >> 8) & 0xff;
  headerPlain[1] = bodyCt.length & 0xff;
  const headerCt = new Uint8Array(await aes.encryptBufferCBC(headerPlain, ivHdr, kHdr));
  if (headerCt.length !== HEADER_CIPHERTEXT_SIZE_IN_BYTES) {
    throw new Error(`unexpected header ct length ${headerCt.length}`);
  }

  // 6. Assemble: header (16) || body (400) || zero-pad to multiple of 31.
  const assembled = new Uint8Array(CIPHERTEXT_BYTES);
  assembled.set(headerCt, 0);
  assembled.set(bodyCt, HEADER_CIPHERTEXT_SIZE_IN_BYTES);
  // Remainder is already zero from Uint8Array init.
  if (FILLED_CIPHERTEXT_BYTES > CIPHERTEXT_BYTES) {
    throw new Error(`filled ${FILLED_CIPHERTEXT_BYTES} > space ${CIPHERTEXT_BYTES}`);
  }

  // 7. Pack 31 bytes per field, mask additively.
  const packed = bytesToFields31(assembled); // 14 fields
  const masked: Fr[] = new Array(packed.length);
  for (let i = 0; i < packed.length; i++) {
    const mask = await deriveFieldMask(sApp, i);
    masked[i] = packed[i].add(mask);
  }

  // 8. Prepend eph_pk.x. Expect caller to have chosen eph_sk such that y-coord
  // is positive (matches aztec-nr's generate_positive_ephemeral_key_pair), so
  // that recipients can reconstruct eph_pk from x alone.
  const ephPk = await Grumpkin.mul(Grumpkin.generator, ephSk);
  const halfP = (Fr.MODULUS - 1n) / 2n;
  if (ephPk.y.toBigInt() > halfP) {
    throw new Error("eph_pk y-coord negative; use positive_ephemeral_key_pair");
  }

  const out: Fr[] = new Array(PRIVATE_LOG_CIPHERTEXT_LEN);
  out[0] = ephPk.x;
  for (let i = 0; i < masked.length; i++) out[EPH_PK_X_SIZE_IN_FIELDS + i] = masked[i];
  return out;
}

export interface DecryptParams {
  ciphertext: Fr[]; // PRIVATE_LOG_CIPHERTEXT_LEN fields
  addressSecret: Fq; // recipient's address_secret
  appAddress: Fr;
}

export async function decryptMessage(params: DecryptParams): Promise<Fr[] | null> {
  const { ciphertext, addressSecret, appAddress } = params;
  if (ciphertext.length !== PRIVATE_LOG_CIPHERTEXT_LEN) return null;

  // Reconstruct eph_pk from x with known positive-y sign.
  const ephPkX = ciphertext[0];
  const ephPk = await pointFromXPositiveY(ephPkX);
  if (!ephPk) return null;

  // S = address_secret * eph_pk (the symmetric counterpart of sender's eph_sk * address_point).
  const sharedPoint = await Grumpkin.mul(ephPk, addressSecret);
  const sApp = await deriveAppSiloedSharedSecret(sharedPoint, appAddress);

  // Unmask and unpack.
  const maskedFields = ciphertext.slice(1);
  const unmasked: Fr[] = new Array(maskedFields.length);
  for (let i = 0; i < maskedFields.length; i++) {
    const mask = await deriveFieldMask(sApp, i);
    unmasked[i] = maskedFields[i].sub(mask);
  }
  const packedBytes = fieldsToBytes31(unmasked); // 434 bytes

  const headerCt = packedBytes.slice(0, HEADER_CIPHERTEXT_SIZE_IN_BYTES);
  const { key: kHdr, iv: ivHdr } = await deriveKeyIvPair(sApp, 0);
  const { key: kBody, iv: ivBody } = await deriveKeyIvPair(sApp, 1);

  let headerPlain: Buffer;
  try {
    headerPlain = await aes.decryptBufferCBC(headerCt, ivHdr, kHdr);
  } catch {
    return null;
  }
  if (headerPlain.length !== 2) return null;
  const bodyLen = (headerPlain[0] << 8) | headerPlain[1];
  if (bodyLen <= 0 || bodyLen > CIPHERTEXT_BYTES - HEADER_CIPHERTEXT_SIZE_IN_BYTES) return null;

  const bodyCt = packedBytes.slice(
    HEADER_CIPHERTEXT_SIZE_IN_BYTES,
    HEADER_CIPHERTEXT_SIZE_IN_BYTES + bodyLen,
  );
  let bodyPlain: Buffer;
  try {
    bodyPlain = await aes.decryptBufferCBC(bodyCt, ivBody, kBody);
  } catch {
    return null;
  }
  if (bodyPlain.length !== MESSAGE_PLAINTEXT_SIZE_IN_BYTES) return null;

  const fields: Fr[] = [];
  for (let i = 0; i < MESSAGE_PLAINTEXT_LEN; i++) {
    fields.push(Fr.fromBuffer(Buffer.from(bodyPlain.slice(i * 32, (i + 1) * 32))));
  }
  return fields;
}

// Recover Grumpkin point from x-coordinate, picking the positive-y branch.
// y^2 = x^3 - 17. The two roots are y and -y; return the one with y <= (p-1)/2.
async function pointFromXPositiveY(x: Fr): Promise<Point | null> {
  // Grumpkin curve: y^2 = x^3 - 17. All arithmetic in Fr.
  const MINUS_17 = new Fr(Fr.MODULUS - 17n);
  const xSquared = x.mul(x);
  const xCubed = xSquared.mul(x);
  const ySquared = xCubed.add(MINUS_17);

  const y = await ySquared.sqrt();
  if (y === null) return null;
  const halfP = (Fr.MODULUS - 1n) / 2n;
  const yPositive = y.toBigInt() <= halfP ? y : new Fr(Fr.MODULUS - y.toBigInt());
  return new Point(x, yPositive, false);
}
