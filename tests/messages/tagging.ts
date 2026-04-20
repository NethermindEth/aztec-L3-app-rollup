import { poseidon2Hash, poseidon2HashWithSeparator } from "@aztec/foundation/crypto/poseidon";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import type { Point } from "@aztec/foundation/curves/grumpkin";

import {
  DOM_SEP__PRIVATE_LOG_FIRST_FIELD,
  DOM_SEP__UNCONSTRAINED_MSG_LOG_TAG,
} from "./constants.js";

// Sender-indexed tagging scheme (replicates Aztec v4.2 pxe/src/tagging).
//
// The shared-secret flow:
//   S               = address_secret_A * address_point_B   (ECDH between
//                                                           sender's address secret
//                                                           and recipient's address point)
//   app_tagging_sec = poseidon2([S.x, S.y, app])
//   ext_secret_AB   = poseidon2([app_tagging_sec, recipient])    // directional
//
// Given an index i (off-chain counter):
//   raw_tag     = poseidon2([ext_secret_AB, i])
//   log_tag     = poseidon2_sep([raw_tag], DOM_SEP__UNCONSTRAINED_MSG_LOG_TAG)
//   siloed_tag  = poseidon2_sep([app, log_tag], DOM_SEP__PRIVATE_LOG_FIRST_FIELD)
//
// The recipient computes the same extended secret (symmetrically via their own
// address_secret * address_point of the sender) and scans on-chain logs whose
// first field matches any siloed_tag for i in (agedMax, finalizedMax + WINDOW_LEN].

export async function computeAppTaggingSecret(
  addressSecretA: Fq,
  addressPointB: Point,
  app: Fr,
): Promise<Fr> {
  // S = address_secret_A * address_point_B
  const shared = await Grumpkin.mul(addressPointB, addressSecretA);
  return poseidon2Hash([shared.x, shared.y, app]);
}

export async function computeDirectionalSecret(
  appTaggingSecret: Fr,
  recipient: Fr,
): Promise<Fr> {
  return poseidon2Hash([appTaggingSecret, recipient]);
}

export async function computeTag(extendedSecret: Fr, index: number | bigint): Promise<Fr> {
  const idxFr = new Fr(typeof index === "bigint" ? index : BigInt(index));
  return poseidon2Hash([extendedSecret, idxFr]);
}

export async function computeLogTag(rawTag: Fr): Promise<Fr> {
  return poseidon2HashWithSeparator([rawTag], DOM_SEP__UNCONSTRAINED_MSG_LOG_TAG);
}

export async function computeSiloedTag(app: Fr, logTag: Fr): Promise<Fr> {
  return poseidon2HashWithSeparator([app, logTag], DOM_SEP__PRIVATE_LOG_FIRST_FIELD);
}

// Convenience: full pipeline from preconditions to the siloed on-chain tag.
export async function computeSiloedTagForPair(args: {
  addressSecretSender: Fq;
  addressPointRecipient: Point;
  app: Fr;
  recipient: Fr;
  index: number | bigint;
}): Promise<Fr> {
  const app_sec = await computeAppTaggingSecret(
    args.addressSecretSender,
    args.addressPointRecipient,
    args.app,
  );
  const ext = await computeDirectionalSecret(app_sec, args.recipient);
  const raw = await computeTag(ext, args.index);
  const log = await computeLogTag(raw);
  return computeSiloedTag(args.app, log);
}
