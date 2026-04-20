# 64-slot Path B validation

> **Host**: 16 GiB WSL2; sandbox down during Step 1.
> **Aztec**: `v4.2.0-nightly.20260408`.

End-to-end validation of the Path B recursive pipeline extended with a 64-slot aggregator (`wrapper_64`) on a 3-level binary tree above `wrapper` / `wrapper_16` / `wrapper_32`, with inner-VK chain binding enforced by the contract.

## Three independent checks

### Step 1 — prove + external bb-verify the full chain

`npm run verify:recursive:64` in `tests/`. ~30–40 min, 15 sequential proves on one shared `Barretenberg` instance.

| Level | Count | Peak RSS | In-process verify | bb CLI verify |
|---|---|---|---|---|
| `wrapper` (8) | 8 | ~8–10 GiB | all `true` | exit 0 |
| `wrapper_16` | 4 | ~8–10 GiB | all `true` | exit 0 |
| `wrapper_32` | 2 | ~8–10 GiB | all `true` | exit 0 |
| `wrapper_64` | 1 | ~8–10 GiB | `true` | exit 0 |

Successful 15 sequential proves means every circuit's witness execution is constraint-consistent: state-root chain, tree-index chain, merged-hash equalities, and VK-hash propagation asserts all satisfy end-to-end. Independent `bb verify` provides out-of-band soundness signal (not shared with the prover's bb.js bindings).

### Step 2 — tamper matrix (28 cases)

`npm run verify:recursive:negative`. ~1 min, no proving.

Per level (4 levels × 7 cases): positive baseline + proof / public_inputs / VK each {swapped with wrong artifact, bit-flipped at byte 100}.

**Result**: `PASS=28 FAIL=0`. Every baseline accepted, every tamper rejected. Confirms public inputs are Fiat-Shamir bound to the proof (not cosmetic), VKs are checked (not swap-safe), proof integrity is enforced.

### Step 3 — contract-side chain-binding probe

`npm run probe:chain:64` (sandbox required). Deploys `L3RecursiveSettlement` three times, each with exactly one wrong inner VK hash, and submits the valid quad proof via `submit_batch_64`.

| Deployed with wrong | Asserted against | Result |
|---|---|---|
| `tube_vk_hash` | `public_inputs[9]` (wrapper_vk_hash) | rejected |
| `vk_hash_16` | `public_inputs[10]` (w16_vk_hash) | rejected |
| `vk_hash_32` | `public_inputs[11]` (w32_vk_hash) | rejected |

**Result**: `PASS=3 FAIL=0`. Each chain-binding assert fires when its committed hash is wrong. These are plain Noir asserts, not `verify_honk_proof` calls, so they fire under sandbox/TXE where the proof gate is a no-op (see `SILENT_FAILURE_REVIEW.md` Problem 1).

## Public-input shapes

Post-Phase 2 (note-discovery, `private_logs_hash` added to `BatchOutput`):

| Artifact | Size | Fields | Chain-binding fields |
|---|---|---|---|
| `wrapper_public_inputs.bin` | 288 B | 9 | — (full BatchOutput) |
| `wrapper_16_public_inputs.bin` | 320 B | 10 | wrapper_vk_hash |
| `wrapper_32_public_inputs.bin` | 352 B | 11 | + w16_vk_hash |
| `wrapper_64_public_inputs.bin` | 384 B | 12 | + w32_vk_hash |

bb CLI accepts each width when paired with its matching VK; rejects mismatched pairings. Artifacts regenerate via `INCLUDE_64=1 npm run verify:recursive:64`; this chain has not been re-run since the Phase 2 circuit changes, so on-disk artifacts under `tests/bb-verify-artifacts/` may still carry the pre-Phase-2 widths (8 / 9 / 10 / 11) until a new prove pass.

## Memory profile

- Step 1 holds within 16 GiB across 15 sequential proves on one shared bb.js `Barretenberg` instance. No OOM, no RSS-creep failure (sandbox was down).
- Step 2 is lightweight (~500 MiB–1 GiB for Node + 28 × ~25 MiB per-bb-subprocess).
- Step 3 runs ~2 GiB (sandbox + Node), well within budget once proving is done.

## What these results do NOT establish

- **The `verify_honk_proof` opcode actually executes at submit-time.** Still a no-op in sandbox/TXE ACIR simulation. Step 3 validates the plumbing around the opcode (chain-binding asserts before it), not the opcode itself. Closing that gap requires real Aztec proof enforcement. See `SILENT_FAILURE_REVIEW.md`.

## Reproduction

```sh
cd tests
# 1. Generate + externally verify all four levels (~30-40 min, 16 GiB).
INCLUDE_64=1 npm run verify:recursive:64

# 2. Tamper matrix (~1 min, no proving).
npm run verify:recursive:negative

# 3. Contract-side chain-binding probe.
npm run sandbox:up
npm run probe:chain:64
npm run sandbox:down
```

Artifacts land under `tests/bb-verify-artifacts/`; manifest (VK hashes + file bindings) is `manifest.json`. Submit payload for Step 3 is `batch_64_submit_payload.json`.
