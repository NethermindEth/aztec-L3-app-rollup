/**
 * verify-negative-tests.ts
 *
 * Fast external-verification soundness check: for each input of
 * `bb verify` (-p proof / -i public_inputs / -k vk), supply a tampered
 * or wrong-but-same-shape value and confirm the proof is rejected.
 *
 * Does NOT re-prove. Consumes artifacts previously written by
 * verify-with-bb-cli.ts into tests/bb-verify-artifacts/ and validates
 * via manifest.json that they still correspond to the current circuit
 * VKs. If circuits changed since regeneration, the stored VK hashes
 * won't match what the circuits currently produce -- exits with a
 * clear regenerate message.
 *
 * Covers wrapper and wrapper_16 unconditionally, plus wrapper_32
 * and wrapper_64 if the manifest includes them (INCLUDE_QUAD=1 mode of
 * verify-with-bb-cli.ts).
 *
 * Run:
 *   npx tsx verify-negative-tests.ts
 */

import { Barretenberg } from "@aztec/bb.js";
import { existsSync, readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { spawnSync } from "child_process";

import {
  computeWrapperVkHash,
  computeWrapper16VkHash,
  computeWrapper32VkHash,
  computeWrapper64VkHash,
} from "./harness/prover-recursive.js";
import { ARTIFACT_DIR_PATH, MANIFEST_FILENAME, VERIFIER_TARGET } from "./verify-shared.js";

interface ManifestEntry {
  vkHash: string;
  artifacts: { proof: string; publicInputs: string; vk: string };
}

interface Manifest {
  generatedAt: string;
  verifierTarget: string;
  scope?: string;
  wrapper: ManifestEntry;
  wrapper_16: ManifestEntry;
  wrapper_32?: ManifestEntry;
  wrapper_64?: ManifestEntry;
}

function abortStale(reason: string): never {
  console.error(`\nArtifacts stale: ${reason}`);
  console.error(`Regenerate with: npm run verify:recursive (or: npx tsx verify-with-bb-cli.ts)`);
  process.exit(2);
}

function tamperFile(path: string): string {
  const outPath = path.replace(/\.bin$/, ".tampered.bin");
  const buf = Buffer.from(readFileSync(path));
  buf[Math.min(100, buf.length - 1)] ^= 0xff;
  writeFileSync(outPath, buf);
  return outPath;
}

// Resolve a ManifestEntry's files to absolute paths.
function resolvePaths(entry: ManifestEntry) {
  const A = (name: string) => resolve(ARTIFACT_DIR_PATH, name);
  return {
    proof: A(entry.artifacts.proof),
    pi: A(entry.artifacts.publicInputs),
    vk: A(entry.artifacts.vk),
  };
}

let pass = 0, fail = 0;
function run(label: string, expect: "ok" | "reject", proof: string, pi: string, vk: string) {
  const result = spawnSync(
    "bb",
    ["verify", "-t", VERIFIER_TARGET, "-p", proof, "-i", pi, "-k", vk],
    { encoding: "utf-8" },
  );
  const ec = result.status ?? 1;
  const summary = (result.stdout + result.stderr)
    .split("\n")
    .filter((l) => /Scheme is:|Proof verified|verification failed|Assertion|parsing/.test(l))
    .slice(0, 2)
    .join(" | ");
  const ok = (expect === "ok" && ec === 0) || (expect === "reject" && ec !== 0);
  console.log(`  ${ok ? "PASS" : "FAIL"}  [${expect.padEnd(6)}]  ${label}  (exit=${ec})  ${summary}`);
  if (ok) pass++; else fail++;
}

// Runs the full 7-case matrix (1 positive + 6 negatives) against one target
// proof set. "Wrong shape" files are supplied via `other` -- they must be
// same-sized binary files of a different proof/VK (e.g. the wrapper set
// when testing wrapper_16).
function runMatrix(
  targetLabel: string,
  target: { proof: string; pi: string; vk: string },
  other: { proof: string; pi: string; vk: string },
) {
  const tp = tamperFile(target.proof);
  const tpi = tamperFile(target.pi);
  const tv = tamperFile(target.vk);

  console.log(`\n=== ${targetLabel} negative tests (target=${VERIFIER_TARGET}) ===`);
  run("positive baseline",                       "ok",     target.proof, target.pi,  target.vk);
  run("proof=other-level (wrong, same shape)",   "reject", other.proof,  target.pi,  target.vk);
  run("proof=tampered (bit-flipped)",            "reject", tp,           target.pi,  target.vk);
  run("public_inputs=other-level's",             "reject", target.proof, other.pi,   target.vk);
  run("public_inputs=tampered",                  "reject", target.proof, tpi,        target.vk);
  run("vk=other-level's",                        "reject", target.proof, target.pi,  other.vk);
  run("vk=tampered",                             "reject", target.proof, target.pi,  tv);
}

async function main() {
  const manifestPath = resolve(ARTIFACT_DIR_PATH, MANIFEST_FILENAME);
  if (!existsSync(manifestPath)) abortStale(`missing ${manifestPath}`);
  const manifest: Manifest = JSON.parse(readFileSync(manifestPath, "utf-8"));

  // -------------------------------------------------------------------------
  // VK freshness: recompute current VK hashes from compiled circuits and
  // compare against the manifest. Any mismatch means circuits changed.
  // -------------------------------------------------------------------------
  console.log("Checking artifact freshness against current circuit VKs...");
  const api = await Barretenberg.new({ threads: 4 });
  const { vkHash: currentWrapperVkHash } = await computeWrapperVkHash(api);
  const { vkHash: currentPairVkHash } = await computeWrapper16VkHash(api);
  let currentW32VkHash: string | undefined;
  let currentW64VkHash: string | undefined;
  if (manifest.wrapper_32) {
    currentW32VkHash = (await computeWrapper32VkHash(api)).vkHash.toString();
  }
  if (manifest.wrapper_64) {
    currentW64VkHash = (await computeWrapper64VkHash(api)).vkHash.toString();
  }
  await api.destroy();

  const checkFresh = (label: string, current: string, manifestVal: string) => {
    if (current !== manifestVal) {
      abortStale(`${label} VK hash mismatch (manifest=${manifestVal.slice(0, 18)}..., current=${current.slice(0, 18)}...)`);
    }
    console.log(`  ${label} VK hash: OK`);
  };
  checkFresh("wrapper", currentWrapperVkHash.toString(), manifest.wrapper.vkHash);
  checkFresh("wrapper_16", currentPairVkHash.toString(), manifest.wrapper_16.vkHash);
  if (manifest.wrapper_32 && currentW32VkHash) {
    checkFresh("wrapper_32", currentW32VkHash, manifest.wrapper_32.vkHash);
  }
  if (manifest.wrapper_64 && currentW64VkHash) {
    checkFresh("wrapper_64", currentW64VkHash, manifest.wrapper_64.vkHash);
  }

  // -------------------------------------------------------------------------
  // Run negative-test matrices. Each level uses the adjacent-smaller level's
  // artifacts as the "wrong, same shape" source.
  // -------------------------------------------------------------------------
  const w = resolvePaths(manifest.wrapper);
  const p = resolvePaths(manifest.wrapper_16);
  runMatrix("wrapper (8-slot)", w, p);
  runMatrix("wrapper_16 (16-slot)", p, w);

  if (manifest.wrapper_32) {
    const pp = resolvePaths(manifest.wrapper_32);
    runMatrix("wrapper_32 (32-slot)", pp, p);
  }

  if (manifest.wrapper_64) {
    const q = resolvePaths(manifest.wrapper_64);
    const other = manifest.wrapper_32 ? resolvePaths(manifest.wrapper_32) : p;
    runMatrix("wrapper_64 (64-slot)", q, other);
  }

  console.log(`\nSummary: PASS=${pass} FAIL=${fail}`);
  if (fail > 0) process.exit(1);
}

main().catch((e) => {
  console.error("FATAL:", e?.message ?? e);
  process.exit(1);
});
