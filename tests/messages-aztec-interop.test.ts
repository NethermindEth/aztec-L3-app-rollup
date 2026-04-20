// Aztec SDK interop test: confirms tests/messages/ produces byte-identical
// tags to @aztec/stdlib's Tag / SiloedTag / ExtendedDirectionalAppTaggingSecret
// on fixed vectors.
//
// Why this matters: if our tagging drifts from Aztec's, a real Aztec-wallet
// recipient cannot find L3 note logs on-chain. This test is the load-bearing
// interop guarantee for Phase 1's sender-indexed tagging scheme.
//
// Encryption interop (AES-128-CBC + field masking) is NOT covered here --
// aztec-nr's encryption lives in-Noir and has no standalone TS counterpart
// in the SDK at v4.2. That would require a fixed test vector generated from
// the Noir circuit; deferred to a separate follow-up.

import { Fq, Fr } from "@aztec/foundation/curves/bn254";
import { Grumpkin } from "@aztec/foundation/crypto/grumpkin";
import { poseidon2Hash } from "@aztec/foundation/crypto/poseidon";
import { Point } from "@aztec/foundation/curves/grumpkin";
import { Tag, SiloedTag } from "@aztec/stdlib/logs";

import {
  computeAppTaggingSecret,
  computeDirectionalSecret,
  computeSiloedTagForPair,
  computeTag as ourComputeTag,
  computeLogTag,
  computeSiloedTag,
} from "./messages/index.js";

let failures = 0;
function check(name: string, cond: boolean, detail?: unknown) {
  if (cond) console.log(`  ok   ${name}`);
  else {
    failures++;
    console.log(`  FAIL ${name}`);
    if (detail !== undefined) console.log(`       ${detail}`);
  }
}
async function section(name: string, body: () => Promise<void> | void) {
  console.log(`\n${name}`);
  await body();
}

// ----------------------------------------------------------------------
// Fixed vector (matches the hard-coded reference in aztec-packages v4.2
// noir-projects/aztec-nr/aztec/src/keys/ecdh_shared_secret.nr:test_consistency_with_typescript).
// If the upstream vector changes, this test will loudly detect it.
// ----------------------------------------------------------------------
const SECRET_LO = 0x00000000000000000000000000000000649e7ca01d9de27b21624098b897babdn;
const SECRET_HI = 0x0000000000000000000000000000000023b3127c127b1f29a7adff5cccf8fb06n;
const POINT_X = 0x2688431c705a5ff3e6c6f2573c9e3ba1c1026d2251d0dbbf2d810aa53fd1d186n;
const POINT_Y = 0x1e96887b117afca01c00468264f4f80b5bb16d94c1808a448595f115556e5c8en;
const EXPECTED_SHARED_X = 0x15d55a5b3b2caa6a6207f313f05c5113deba5da9927d6421bcaa164822b911bcn;
const EXPECTED_SHARED_Y = 0x0974c3d0825031ae933243d653ebb1a0b08b90ee7f228f94c5c74739ea3c871en;

async function main() {
  await section("ECDH shared-point anchor (matches aztec-nr hard-coded vector)", async () => {
    const scalar = new Fq((SECRET_HI << 128n) + SECRET_LO);
    const point = new Point(new Fr(POINT_X), new Fr(POINT_Y), false);
    const shared = await Grumpkin.mul(point, scalar);
    check("shared.x matches upstream vector", shared.x.toBigInt() === EXPECTED_SHARED_X);
    check("shared.y matches upstream vector", shared.y.toBigInt() === EXPECTED_SHARED_Y);
  });

  await section("Tag.compute matches our computeTag", async () => {
    const extendedSecret = new Fr(0xfeedbeefcafen);
    const index = 7;
    const ours = await ourComputeTag(extendedSecret, index);
    // @aztec/stdlib Tag.compute wants a PreTag shape.
    const sdk = await Tag.compute({
      extendedSecret: { secret: extendedSecret, app: { toField: () => new Fr(0x1234n) } as any },
      index,
    });
    check("Tag.value === ourComputeTag", sdk.value.equals(ours));
  });

  await section("log_tag + silo math matches SDK", async () => {
    // SDK.SiloedTag.compute(preTag) = silo(app, logTag(tag(preTag))) -- the
    // full three-step chain. We mirror via computeSiloedTagForPair, but here
    // we test just the log_tag + silo steps by feeding in a known extended
    // secret so Tag.compute == known value.
    const extendedSecret = new Fr(0xcafebabefacen);
    const app = new Fr(0x1234n);
    const index = 3;
    // Our pipeline: rawTag = poseidon2([ext, idx]), logTag, siloedTag.
    const rawTag = await ourComputeTag(extendedSecret, index);
    const ourLogTag = await computeLogTag(rawTag);
    const ourSiloedTag = await computeSiloedTag(app, ourLogTag);
    // SDK pipeline: SiloedTag.compute does Tag -> logTag -> silo internally.
    const sdkSiloed = await SiloedTag.compute({
      extendedSecret: { secret: extendedSecret, app: { toField: () => app } as any },
      index,
    });
    check("SiloedTag.compute == our rawTag -> logTag -> siloedTag", sdkSiloed.value.equals(ourSiloedTag));
  });

  await section("ExtendedDirectional: end-to-end ECDH + directional binding", async () => {
    // Side-A secret/point.
    const ivskA = new Fq(0xabcdcafe1234n);
    const preaddrA = new Fr(0xaaaaaaaan);
    // Pick a recipient ivsk and derive address point.
    const ivskB = new Fq(0xdeadbeef5678n);
    const preaddrB = new Fr(0xbbbbbbbbn);
    // Address secrets (y-normalized is nuanced; we use raw secrets for the
    // cross-check since the SAME normalization applies to both sides).
    const addressSecretA = ivskA.add(new Fq(preaddrA.toBigInt()));
    const addressPointB = await Grumpkin.mul(Grumpkin.generator, ivskB.add(new Fq(preaddrB.toBigInt())));
    // Pick y-positive address point B (matches how Aztec selects).
    const halfP = (Fr.MODULUS - 1n) / 2n;
    const apB = addressPointB.y.toBigInt() > halfP
      ? new Point(addressPointB.x, new Fr(Fr.MODULUS - addressPointB.y.toBigInt()), false)
      : addressPointB;
    const asA = addressPointB.y.toBigInt() > halfP
      ? new Fq(Fq.MODULUS - addressSecretA.toBigInt())
      : addressSecretA;

    const app = new Fr(0xc0ffeen);
    const recipient = new Fr(0xdeadbeefn);

    // Our pipeline.
    const appSec = await computeAppTaggingSecret(asA, apB, app);
    const ourExt = await computeDirectionalSecret(appSec, recipient);

    // SDK equivalent math, replicating ExtendedDirectionalAppTaggingSecret.compute
    // without constructing a full CompleteAddress (which needs partialAddress +
    // publicKeys, out of scope here). The algorithm is documented in
    // extended_directional_app_tagging_secret.js:
    //   S = Grumpkin.mul(externalAddressPoint, computeAddressSecret(...))
    //   appSec = poseidon2([S.x, S.y, app])
    //   ext = poseidon2([appSec, recipient])
    const S_sdk = await Grumpkin.mul(apB, asA);
    const appSec_sdk = await poseidon2Hash([S_sdk.x, S_sdk.y, app]);
    const ext_sdk = await poseidon2Hash([appSec_sdk, recipient]);
    check("directional extended secret matches SDK math", ourExt.equals(ext_sdk));

    // Full siloed tag via our computeSiloedTagForPair vs SDK Tag+SiloedTag pipeline.
    const index = 42;
    const oursSiloed = await computeSiloedTagForPair({
      addressSecretSender: asA,
      addressPointRecipient: apB,
      app,
      recipient,
      index,
    });

    // SDK.SiloedTag.compute(preTag) does the full Tag -> logTag -> silo
    // chain, identical to our computeSiloedTagForPair.
    const sdkSiloed = await SiloedTag.compute({
      extendedSecret: { secret: ext_sdk, app: { toField: () => app } as any },
      index,
    });
    check("full siloed tag matches SDK end-to-end", oursSiloed.equals(sdkSiloed.value));
  });

  console.log(`\n${failures === 0 ? "PASS" : `FAIL (${failures} assertion(s))`}`);
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("FATAL:", e);
  process.exit(1);
});
