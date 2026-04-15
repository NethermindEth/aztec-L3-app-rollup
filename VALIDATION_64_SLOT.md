# 64-slot path validation

> **Date**: 2026-04-15
> **Aztec version**: `v4.2.0-nightly.20260408`
> **Host**: Windows / WSL2 at 16 GiB budget, sandbox down during Step 1.

End-to-end validation of the recursive pipeline extended with a 64-slot aggregator
(`wrapper_64`) built on a 3-level binary tree above `wrapper` / `wrapper_16` /
`wrapper_32`, with inner-VK chain binding enforced by the contract.

## Validation layers

Three independent checks, each answering a distinct question.

### Step 1 -- prove + external verify the full chain

`npm run verify:recursive:64` in `tests/`. ~30-40 min, 15 sequential
proves on one shared `Barretenberg` instance.

| Level | Count | Proves peak RSS | In-process verify | bb CLI verify |
|---|---|---|---|---|
| `wrapper` (8-slot) | 8 | ~8-10 GiB | all `true` | exit 0 |
| `wrapper_16` (16-slot) | 4 | ~8-10 GiB | all `true` | exit 0 |
| `wrapper_32` (32-slot) | 2 | ~8-10 GiB | all `true` | exit 0 |
| `wrapper_64` (64-slot) | 1 | ~8-10 GiB | `true` | exit 0 |

Successful completion of 15 sequential proves means every circuit's witness execution
is constraint-consistent: state-root chain, tree-index chain, merged-hash equalities,
and the VK-hash propagation asserts all satisfy end-to-end. bb CLI verifying each
level's artifacts independently gives external soundness signal (not shared with the
prover's bb.js bindings).

### Step 2 -- tamper matrix (28 cases)

`npm run verify:recursive:negative`. ~1 min, no proving.

For each of the 4 levels, the 7-case matrix runs:
positive baseline (accept) + 6 tamper cases (reject): proof / public_inputs / vk each
swapped for a same-shape-but-wrong artifact, and each bit-flipped at byte 100.

**Result: `PASS=28 FAIL=0`.** Every baseline accepted, every tamper rejected.

Confirms: public inputs are Fiat-Shamir bound to the proof (not cosmetic), VKs are
checked (not swap-safe), proof integrity is enforced (no bit can flip).

### Step 3a -- on-contract chain-binding probe

`npm run probe:chain:64` (sandbox required). Deploys `L3RecursiveSettlement` three
times, each with exactly one wrong inner VK hash (`tube_vk_hash`, then
`vk_hash_16`, then `vk_hash_32`), and submits the valid quad proof via
`submit_batch_64`.

| Deployed with wrong | Public-input checked | Expected assertion | Result |
|---|---|---|---|
| `tube_vk_hash` | `public_inputs[8]` (wrapper_vk_hash) | "inner wrapper_vk_hash does not match committed tube_vk_hash" | PASS (rejected) |
| `vk_hash_16` | `public_inputs[9]` (w16_vk_hash) | "inner vk_hash_16 does not match committed vk_hash_16" | PASS (rejected) |
| `vk_hash_32` | `public_inputs[10]` (w32_vk_hash) | "inner vk_hash_32 does not match committed vk_hash_32" | PASS (rejected) |

**Result: `PASS=3 FAIL=0`.** Each of the three chain-binding asserts fires when its
corresponding committed hash is wrong. These are plain Noir asserts, not
`verify_honk_proof` calls, so they fire under sandbox / TXE where the proof gate is
a no-op.

## Public-input shapes (observed on disk)

Confirms the VK-chain hardening is behaviorally active:

| Artifact | Size | Fields | Chain-binding fields |
|---|---|---|---|
| `wrapper_public_inputs.bin` | 256 B | 8 | -- |
| `wrapper_16_public_inputs.bin` | 288 B | **9** | wrapper_vk_hash |
| `wrapper_32_public_inputs.bin` | 320 B | **10** | wrapper + w16 |
| `wrapper_64_public_inputs.bin` | 352 B | **11** | wrapper + w16 + w32 |

bb CLI accepts all four widths when paired with the matching VK; rejects any
mismatched pairing.

## Memory profile

- Step 1 held within 16 GiB WSL across 15 sequential proves on one shared bb.js
  `Barretenberg` instance. No OOM, no visible RSS-creep failure. Sandbox was down.
- Step 2 is lightweight (~500 MiB-1 GiB for Node + 28 × ~25 MiB per-bb-subprocess).
- Step 3a runs ~2 GiB (sandbox + Node), well within budget once proving is done.

## What these results do NOT establish

- **The `verify_honk_proof` opcode actually executes at submit-time**: still a no-op
  in sandbox / TXE ACIR simulation (`PXE_PROVER=none`). Step 3a validates the
  plumbing that surrounds the opcode (chain-binding asserts before it), not the
  opcode itself. Closing that gap requires real Aztec proof enforcement, which is
  not available locally in this version. See [`SILENT_FAILURE_REVIEW.md`](./SILENT_FAILURE_REVIEW.md).

## Reproduction

```sh
# From tests/ on a 16 GiB WSL host.
# 1. Generate + externally verify all four levels (~30-40 min).
npm run verify:recursive:64

# 2. Tamper matrix (~1 min, no proving).
npm run verify:recursive:negative

# 3a. Chain-binding probe against sandbox.
npm run sandbox:up
npm run probe:chain:64
npm run sandbox:down
```

Artifacts land under `tests/bb-verify-artifacts/`; manifest (VK hashes + file
bindings) is `manifest.json`. Submit payload for step 3a is
`batch_64_submit_payload.json`.
