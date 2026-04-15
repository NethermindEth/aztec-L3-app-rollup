/**
 * Shared constants / helpers for verify-with-bb-cli.ts (heavy; produces
 * artifacts) and verify-negative-tests.ts (fast; validates them). Kept in
 * its own file so importing does not trigger any top-level execution.
 */

import { Fr } from "@aztec/aztec.js/fields";
import { resolve } from "path";

export const ARTIFACT_DIR_PATH = resolve(import.meta.dirname ?? ".", "bb-verify-artifacts");
export const MANIFEST_FILENAME = "manifest.json";
export const VERIFIER_TARGET = "noir-recursive";

// Bytes → Fr[] helper (32-byte BE per field — matches bb / bb.js layout).
export function vkBytesToFr(vk: Uint8Array): Fr[] {
  const fields: Fr[] = [];
  for (let i = 0; i < vk.length / 32; i++) {
    const slice = vk.slice(i * 32, (i + 1) * 32);
    const hex = "0x" + Array.from(slice).map((b) => b.toString(16).padStart(2, "0")).join("");
    fields.push(new Fr(BigInt(hex)));
  }
  return fields;
}

// Field-string array → raw 32-byte BE bytes — the on-disk format bb CLI
// consumes for public_inputs.
export function fieldStringsToBytes(fields: string[]): Uint8Array {
  const buf = new Uint8Array(fields.length * 32);
  for (let i = 0; i < fields.length; i++) {
    let v = BigInt(fields[i]);
    for (let j = 31; j >= 0; j--) {
      buf[i * 32 + j] = Number(v & 0xffn);
      v >>= 8n;
    }
  }
  return buf;
}
