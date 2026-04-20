# Sub-batch Aggregation

Three ways to collapse *N* 8-slot sub-batches into one L2 submission. All three are implemented and exercised by step-level e2e tests; Path B (recursive) and Path C (IVC + `pair_tube`) now both terminate at a 500-field `UltraHonkZKProof` that matches the contract ABI.

> **Benchmarks in this document are indicative, not targets.** They come from a single 16 GiB WSL host where both paths end up swap-bound at batch=16. Wall-clock figures are included to show *relative* cost shape, not absolute production numbers. Treat ordering of costs as robust and magnitudes as machine-dependent.

---

## Three designs

### Design A — IVC meta-batch (benchmark only)

```
sub-batch 1 -> IVC -> tube proof 1  --+
                                       +--> (2 separate submit_batch calls)
sub-batch 2 -> IVC -> tube proof 2  --+
```

Each tube proof is submitted independently; the contract settles twice. Simple but doubles the on-chain work and carries 519-field tube proofs directly, so the SDK silently truncates them. **Format-broken.** See `step8-ivc-meta-16slot.ts`.

### Design B — Recursive merged (primary path)

```
sub-batch 1 -> batch_app_standalone -> wrapper --+
                                                  +--> wrapper_16 -> submit_batch_16
sub-batch 2 -> batch_app_standalone -> wrapper --+
```

Pure UltraHonk all the way. `wrapper_16` verifies two `wrapper` proofs (each 500-field `noir-recursive`) and emits a single 500-field `noir-recursive` proof. **Format-aligned.** See `step9-recursive-16slot.ts`. This is the primary path.

### Path C — IVC + `pair_tube` (secondary path)

```
sub-batch 1 -> IVC -> tube proof 1 (519-field RollupHonk)  --+
                                                              +--> pair_tube -> submit_merged_batch
sub-batch 2 -> IVC -> tube proof 2 (519-field RollupHonk)  --+
```

`pair_tube` verifies two tube proofs under `ROOT_ROLLUP_HONK` (proof type 5), finalizing both IPA claims natively in-circuit. Its own output is a 500-field `noir-recursive` `UltraHonkZKProof`. **Format-aligned** (since 2026-04-17). See `step10-ivc-merged-16slot.ts` and `SILENT_FAILURE_REVIEW.md`.

---

## On-wire shapes (identical for B and C)

Both B and C produce the same submission shape at batch=16. `submit_batch_16` / `submit_merged_batch` is `#[external("private")]`, so its `tube_vk` (115 fields), `tube_proof` (500 fields), `tube_vk_hash` (1 field), and the non-forwarded entries of `public_inputs` are witness to the Aztec kernel and never reach L1 DA. What hits L1 DA is the enqueued public `settle_batch_16` / `settle_batch_merged` call's arguments:

| Item | Fields | Bytes |
|---|---|---|
| State roots (old + new) | 2 | 64 |
| Merged nullifiers | 32 | 1,024 |
| Merged note hashes | 32 | 1,024 |
| Merged deposit nullifiers | 16 | 512 |
| Merged withdrawal claims | 16 | 512 |
| Insertion counts (null + nh) | 2 | 64 |
| Merged private logs (note-discovery) | 512 | 16,384 |
| **Total L1 DA** | **612** | **19,584** |

One `settle_batch_{16,merged}` public call, nonce += 1. Proof size (16,000 B) and VK size (3,680 B) still matter for kernel proving cost but do not consume L1 DA. Encrypted note logs introduced in Phase 2 (see `DESIGN_DECISIONS.md` §2 extension + `tests/messages/`) dominate the L1 footprint at ~84 %.

---

## Indicative cost comparison (batch=16, 2 real txs, 16 GiB WSL)

| | **Path B** (wrapper_16) | **Path C** (pair_tube ROOT_ROLLUP_HONK) |
|---|---|---|
| Per-tx proving | ~0.7 s | ~0.4 s |
| Sub-batch proving (per sub-batch) | ~10–12 min | ~2.5 min (ClientIVC-folded) |
| Sub-batch concurrency | OOMs past 16 GiB → **sequential** | Concurrent |
| Aggregator proving | ~2.4 min | ~37 min **swap-bound** |
| Total proving wall-clock | ~24 min | ~39 min |
| L2 submit | ~9 s | ~7 s |
| L1 DA / proof size (kernel witness) | 19,584 B / 16,000 B | 19,584 B / 16,000 B |

**Where each path pays.** Path B's leaves don't fit in 16 GiB (each `wrapper` prove peaks ~8 GiB), so they run sequentially on a 16 GiB host. Path C's leaves are cheap (IVC folding) and concurrent, but the `pair_tube` aggregator does cross-curve IPA finalization (Grumpkin ops simulated in BN254 non-native field arithmetic) and pushes past 16 GiB, so proving runs in swap.

**With ≥ 24 GiB neither path is swap-bound.** Projected wall-clock for both paths converges toward ~12–15 min at batch=16; the order of magnitudes — "IVC leaves cheaper, recursive aggregator cheaper" — does not change. See `SCALING.md` for how the balance tilts at larger batch sizes.

---

## Why Path B is the primary path today

- **Uniform UltraHonk everywhere.** No Chonk, no IPA, no curve-cycle arithmetic. Circuits are simpler and gate counts predictable.
- **Aggregator is cheap.** `wrapper_16` gate count is dominated by two `verify_honk_proof` calls — native KZG pairing, no foreign field.
- **No ECCVM-imposed batch cap.** `batch_app_standalone` compiles linearly to at least batch=128 (see `DESIGN_DECISIONS.md` §3). Current batch=8 is a memory choice, not a protocol limit.

Path C's comparative advantage is leaf proving cost (IVC folding vs full recursive recursion). That matters at larger *N*; see `SCALING.md`.

---

## Reproduction

Prerequisites: sandbox up (`cd tests && docker compose up -d`), WSL memory ≥ 16 GiB (≥ 24 GiB recommended for Path C).

```sh
cd tests

# Path B — primary (recursive merged-proof, 16 slots)
npx tsx step9-recursive-16slot.ts

# Path C — secondary (IVC + pair_tube, 16 slots)
npx tsx step10-ivc-merged-16slot.ts

# Design A — benchmark only (format-broken, truncated submission)
npx tsx step8-ivc-meta-16slot.ts
```

Metrics are written to `target/step{8,9,10}-metrics.json`.

---

## Files

| File | Role |
|---|---|
| `circuits/wrapper_16/src/main.nr` | Path B aggregator (2 → 1, 500-field out) |
| `circuits/pair_tube/src/main.nr` | Path C aggregator (2 tubes → 1, ROOT_ROLLUP_HONK, 500-field out) |
| `contract_recursive/src/main.nr` | `submit_batch_16` + chain-binding asserts |
| `contract_ivc/src/main.nr` | `submit_merged_batch` for Path C (+ Design A's `submit_batch` / `submit_two_batches`) |
| `tests/harness/prover.ts` | IVC prover + `buildPairTubeProof` / `computePairTubeVkHash` |
| `tests/harness/prover-recursive.ts` | Recursive prover + `buildWrapper16Proof` |
