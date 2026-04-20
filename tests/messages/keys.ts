import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { poseidon2HashWithSeparator } from "@aztec/foundation/crypto/poseidon";
import { sha512ToGrumpkinScalar } from "@aztec/foundation/crypto/sha512";
import type { Point } from "@aztec/foundation/curves/grumpkin";

import {
  DOM_SEP__CONTRACT_ADDRESS_V1,
  DOM_SEP__IVSK_M,
  DOM_SEP__NHK_M,
  DOM_SEP__OVSK_M,
  DOM_SEP__PUBLIC_KEYS_HASH,
  DOM_SEP__TSK_M,
} from "./constants.js";

// Mirrors yarn-project/stdlib/src/keys/derivation.ts at v4.2.
//
// These functions live client-side only -- the circuit receives the derived
// secrets as witness. See Phase 1 plan for the ONCHAIN_UNCONSTRAINED rationale.

export interface MasterKeys {
  nsk_m: Fq;
  ivsk_m: Fq;
  ovsk_m: Fq;
  tsk_m: Fq;
}

export interface MasterPublicKeys {
  npk_m: Point;
  ivpk_m: Point;
  ovpk_m: Point;
  tpk_m: Point;
}

export function deriveMasterKeys(secretKey: Fr): MasterKeys {
  return {
    nsk_m: sha512ToGrumpkinScalar([secretKey, new Fr(BigInt(DOM_SEP__NHK_M))]),
    ivsk_m: sha512ToGrumpkinScalar([secretKey, new Fr(BigInt(DOM_SEP__IVSK_M))]),
    ovsk_m: sha512ToGrumpkinScalar([secretKey, new Fr(BigInt(DOM_SEP__OVSK_M))]),
    tsk_m: sha512ToGrumpkinScalar([secretKey, new Fr(BigInt(DOM_SEP__TSK_M))]),
  };
}

export async function deriveMasterPublicKeys(master: MasterKeys): Promise<MasterPublicKeys> {
  const G = Grumpkin.generator;
  const [npk_m, ivpk_m, ovpk_m, tpk_m] = await Promise.all([
    Grumpkin.mul(G, master.nsk_m),
    Grumpkin.mul(G, master.ivsk_m),
    Grumpkin.mul(G, master.ovsk_m),
    Grumpkin.mul(G, master.tsk_m),
  ]);
  return { npk_m, ivpk_m, ovpk_m, tpk_m };
}

// PublicKeys.hash() in aztec-nr: poseidon2_hash_with_separator of the four
// (x, y) pairs + is_infinite flags.
export async function hashMasterPublicKeys(pub: MasterPublicKeys): Promise<Fr> {
  const inputs = [
    pub.npk_m.x, pub.npk_m.y, new Fr(pub.npk_m.isInfinite ? 1n : 0n),
    pub.ivpk_m.x, pub.ivpk_m.y, new Fr(pub.ivpk_m.isInfinite ? 1n : 0n),
    pub.ovpk_m.x, pub.ovpk_m.y, new Fr(pub.ovpk_m.isInfinite ? 1n : 0n),
    pub.tpk_m.x, pub.tpk_m.y, new Fr(pub.tpk_m.isInfinite ? 1n : 0n),
  ];
  return poseidon2HashWithSeparator(inputs, DOM_SEP__PUBLIC_KEYS_HASH);
}

// Preaddress = h(public_keys_hash, partial_address | DOM_SEP__CONTRACT_ADDRESS_V1).
export async function computePreaddress(publicKeysHash: Fr, partialAddress: Fr): Promise<Fr> {
  return poseidon2HashWithSeparator([publicKeysHash, partialAddress], DOM_SEP__CONTRACT_ADDRESS_V1);
}

// computeAddressSecret: picks (preaddress + ivsk) or Fq.MODULUS - it so that
// the resulting address point has a positive y-coordinate. Matches derivation.ts.
export async function computeAddressSecret(preaddress: Fr, ivsk_m: Fq): Promise<Fq> {
  const candidate = ivsk_m.add(new Fq(preaddress.toBigInt()));
  const candidatePoint = await Grumpkin.mul(Grumpkin.generator, candidate);
  const halfP = (Fr.MODULUS - 1n) / 2n;
  if (candidatePoint.y.toBigInt() > halfP) {
    return new Fq(Fq.MODULUS - candidate.toBigInt());
  }
  return candidate;
}

// addressPoint = preaddress * G + ivpk_m (after y-normalization).
export async function computeAddressPoint(preaddress: Fr, ivpk_m: Point): Promise<Point> {
  const preaddrG = await Grumpkin.mul(Grumpkin.generator, new Fq(preaddress.toBigInt()));
  const sum = await Grumpkin.add(preaddrG, ivpk_m);
  const halfP = (Fr.MODULUS - 1n) / 2n;
  if (sum.y.toBigInt() > halfP) {
    // Negate to pick positive-y representative. Grumpkin: (x, y) -> (x, -y).
    const { Point: GPoint } = await import("@aztec/foundation/curves/grumpkin");
    return new GPoint(sum.x, new Fr(Fr.MODULUS - sum.y.toBigInt()), sum.isInfinite);
  }
  return sum;
}
