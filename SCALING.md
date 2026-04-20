# Aggregation Tree Scaling

How the recursive aggregator tree extends from 16 slots to 32, 64, 128 slots. This is orthogonal to the Path B vs Path C choice in `AGGREGATION.md`; the same tree shape applies to both paths (Path B uses `wrapper_{16,32,64}`, Path C could pair its `pair_tube` output into the same upper levels but is currently only exercised at batch=16).

> **Benchmarks here are from a 16 GiB WSL host.** At every level beyond 16 slots both paths start trading RAM for swap. Numbers are relative; absolute figures will shift with host memory.

---

## Tree shape

Batch sizes grow by binary doubling. Each level consumes two proofs from the level below and emits one:

```
batch=8   : wrapper                 (verifies 1 batch_app_standalone proof)
batch=16  : wrapper_16              (verifies 2 wrapper proofs)
batch=32  : wrapper_32              (verifies 2 wrapper_16 proofs)
batch=64  : wrapper_64              (verifies 2 wrapper_32 proofs)
batch=128 : wrapper_128 (not built) (verifies 2 wrapper_64 proofs)
```

The 64-slot path is exercised by `step11-recursive-64slot.ts` and bb-verified end-to-end by `npm run verify:recursive:64` (see `VALIDATION_64_SLOT.md`). 128-slot would need one more aggregator circuit; no protocol limit prevents it.

## Public-input widening

Each aggregator level publishes the VK hash of the level below, so the `submit_batch_*` asserts can bind the whole chain. This adds one public-input field per level. The 9-field `BatchOutput` (Phase 2, incl. `private_logs_hash`) is the common prefix:

| Level | Public inputs | Added |
|---|---|---|
| `wrapper` (8) | 9 | — (full BatchOutput) |
| `wrapper_16` | 10 | `wrapper_vk_hash` |
| `wrapper_32` | 11 | + `w16_vk_hash` |
| `wrapper_64` | 12 | + `w32_vk_hash` |

Immutable contract storage holds `tube_vk_hash`, `vk_hash_16`, `vk_hash_32`, `vk_hash_64`; `submit_batch_16` / `submit_batch_64` assert each inner hash against the corresponding storage slot. The hardening closes the inner-VK substitution attack class conditional on the proof gate being enforced; the asserts themselves fire under sandbox/TXE since they are plain Noir asserts.

## L1 DA per settlement

`submit_batch_*` is `#[external("private")]`; its `tube_vk` (115 fields), `tube_proof` (500 fields), `tube_vk_hash` (1 field), and the non-forwarded entries of `public_inputs` are **private** witnesses consumed by `verify_honk_proof` inside Aztec's kernel and never posted to L1. What hits L1 DA per settlement is the enqueued public `settle_batch_*` call's arguments. The table below counts only those.

Only 8/16/64 slot sizes are real L1 settle endpoints (`submit_batch`, `submit_batch_16` / `submit_merged_batch`, `submit_batch_64`). `wrapper_32` is an intermediate aggregator with no direct settle target.

| Endpoint | state roots | side-effect arrays (deposits + withdrawals) | insertion counts | nullifiers + note_hashes | private_logs | **Total fields** | **Bytes** |
|---|---|---|---|---|---|---|---|
| 8-slot | 2 | 8 + 8 = 16 | 2 | 16 + 16 = 32 | 256 | **308** | 9,856 |
| 16-slot | 2 | 16 + 16 = 32 | 2 | 32 + 32 = 64 | 512 | **612** | 19,584 |
| 64-slot | 2 | 64 + 64 = 128 | 2 | 128 + 128 = 256 | 2,048 | **2,436** | 77,952 |

`private_logs` dominates DA at every level (~83 %+ of the total). The flat `[tag, ct_0..ct_14]` layout per output (16 fields each, 2 outputs per tx, batch-sized) is the Aztec-format encrypted-note-log payload that the recipient wallet decrypts (see `tests/messages/`).

The settle-level `deposit_nullifiers` + `withdrawal_claims` pair could be collapsed into one `[Field; MAX_BATCH_SIZE]` array plus two section counts, saving MAX_BATCH_SIZE − 2 fields per settlement (62 fields / ~2 KB at 64-slot). Not pursued: the savings are negligible next to the log budget, and the two-array split matches `batch_app`'s internal section routing.

Proof size and VK size stay constant end-to-end because UltraHonk is independent of inner circuit size, but the cost lives in the prover and the L2 kernel proof — not in L1 DA.

## Proving cost shape

- **Aggregator circuits are constant-size.** `wrapper_{16,32,64}` each verify exactly two proofs; their gate count does not scale with batch size. In isolation each aggregator prove is ~2–3 min on a RAM-adequate host, ~10+ min under swap.
- **Leaf cost grows linearly with batch size.** `batch_app_standalone` opcode count scales with tx count (see `DESIGN_DECISIONS.md` §3); Path C's per-tx IVC fold also scales linearly in tx count but with a smaller per-tx constant.
- **Depth adds log(N) aggregator proves.** A 64-slot run proves 8 leaves + 4 × wrapper_16 + 2 × wrapper_32 + 1 × wrapper_64 = 15 proves. On 16 GiB the `verify:recursive:64` harness runs these sequentially in ~30–40 min (peak ~8–10 GiB RSS per prove).
- **Concurrency is memory-bound.** With ≥ 24 GiB WSL, two 8-slot leaves can prove concurrently. Beyond that, parallelism gains flatten because the aggregator levels serialize on each other.

---

## Host memory budget

| Host memory | What fits cleanly | What swaps |
|---|---|---|
| 16 GiB (minimum) | Sequential `wrapper_{16,32,64}` proves; `step9` / `step11` end-to-end at moderate speed | Path C aggregator (`pair_tube` root-rollup); concurrent leaves |
| 24 GiB | Concurrent 2 × wrapper leaves; Path C aggregator | wrapper_64 concurrent with other aggregators |
| 32 GiB+ | Full tree with parallel leaves | — |

The repo's benchmarks were collected on a 16 GiB host. Raising to 24–32 GiB would collapse the wall-clock numbers meaningfully without changing the architectural conclusions.

## When Path C's leaf savings pay back

At batch=16 (2 real txs), Path B's cheaper aggregator wins on total proving time; Path C's IVC leaf savings are not enough to offset the `pair_tube` cross-curve IPA cost.

At larger *N* the balance shifts because leaf count doubles each level while aggregator count grows as *N*/16 (assuming Path C keeps one `pair_tube` per 2 sub-batches and upper levels stay on Path B's `wrapper_*` tree). The crossover point where Path C beats Path B end-to-end depends on:

1. Per-tx IVC savings vs per-tx recursive cost (Path C ~2× cheaper per leaf on our host).
2. `pair_tube`'s one-time ROOT_ROLLUP_HONK cost (swap-free: ~8–15 min projected; swap-bound: ~37 min observed).

This crossover has not been measured; it would need a step12-equivalent at batch=64 or 128 with enough RAM for both paths.

---

## Reproduction

```sh
# Generate + externally verify every level (16 / 32 / 64 slots, ~30-40 min on 16 GiB)
cd tests
INCLUDE_64=1 npm run verify:recursive:64

# Contract-side chain-binding probe at 64 slots (sandbox required)
npm run sandbox:up
npm run probe:chain:64
npm run sandbox:down

# Tamper matrix (28 cases, ~1 min, no proving)
npm run verify:recursive:negative
```

See `VALIDATION_64_SLOT.md` for the detailed 64-slot validation report.
