# Batching Scaling — 32 and 128 tx scenarios

> Extrapolation of the shipped 16-slot batching-of-batches work (`BATCHING_OF_BATCHES.md`) to larger capacities per L2 transaction.

The shipped design settles **16 L3 tx slots per L2 tx** via two 8-slot sub-batches. This doc extrapolates to **32 slots** and **128 slots** using three approaches that trade off DA, proving time, and prover RAM differently.

---

## The three approaches

All three aim at one L2 transaction settling N L3 slots. They differ in *how* the N slots get proven, aggregated, and put on the L2 tx.

### Path A — IVC meta-batch (extend `submit_two_batches` to `submit_N_batches`)

```
sub-batch 1 ──► IVC pipeline ──► tube proof₁ ──┐
sub-batch 2 ──► IVC pipeline ──► tube proof₂ ──┤
sub-batch 3 ──► IVC pipeline ──► tube proof₃ ──┼──► submit_N_batches (L3 contract)
             ...                               │         │
sub-batch K ──► IVC pipeline ──► tube proof_K ─┘         │
                                                         ├──► settle_batch (×K, enqueued sequentially)
                                                         │    Aztec L2 tx (one)
                                                         │    nonce += K
                                                         └─
```

- **Sub-batch size: 8** (Chonk ECCVM 32,768-row cap; cannot grow).
- **Sub-batches per L2 tx: K = N / 8.**
- L2 tx carries **K independent tube proofs** + K sets of batch=8 settle arrays.
- Private circuit does **K × `verify_honk_proof`**.
- Public call stack enqueues **K × `settle_batch`** sequentially.
- Nonce advances by K.
- **Trivial to implement**: extend the existing `submit_two_batches` method to arity K (or build a fan-N version).

### Path B1 — Recursive with small sub-batches + wide aggregators (new)

Sub-batches are **4-slot** (half the ship default). Aggregators are **quad_wrapper** (up to 4 inputs per aggregator), giving a **flatter tree** than binary pair_wrapper.

```
16 × sub-batch[4] ──► wrapper[noir-recursive] each      (leaf level)
    ↓ 4 at a time
4 × quad_wrapper                                          (level 1)
    ↓ 4 at a time
1 × quad_wrapper                                          (level 2, final)
    ↓
submit_merged_batch (L3 contract)
    ↓
settle_batch_merged@batch=N (single public call)
```

- **Sub-batch size: 4** — half the opcode count of sub-batch=8 → ~half prove time and ~half RAM per prover.
- **Aggregator fan-in: up to 4** — tree depth is `ceil(log₄(K))` instead of `log₂(K)`, fewer levels.
- **Sub-batches per L2 tx: K = N / 4.**
- Number of aggregator proves: **K/4 + K/16 + ... ≈ (K - 1) / 3** (geometric, fan-4).
- L2 tx carries **1 merged UltraHonk proof** + batch=N settle arrays.
- Private circuit does **1 × `verify_honk_proof`** (of the root merged proof).
- Public call stack enqueues **1 × `settle_batch_merged`** at batch=N sizing.
- Nonce advances by 1.
- **Circuit work**: need a `quad_wrapper` circuit (analogous to `pair_wrapper` but takes 4 wrapper proofs + 4 settle-data re-feeds). For non-power-of-4 leaf counts, accept active-input bitmasks OR fall back to `pair_wrapper` at the root.

### Path B2 — Recursive with large sub-batches + binary aggregators (current)

The pattern currently shipped. Sub-batches are **8-slot**. Aggregators are **pair_wrapper** (2 inputs per aggregator), giving a **binary tree** of depth `log₂(K)`.

```
K × sub-batch[8] ──► wrapper[noir-recursive] each         (leaf level)
    ↓ 2 at a time
K/2 × pair_wrapper                                         (level 1)
    ↓ 2 at a time
K/4 × pair_wrapper                                         (level 2)
    ↓ ...
1 × pair_wrapper                                           (root)
    ↓
submit_merged_batch
    ↓
settle_batch_merged@batch=N
```

- **Sub-batch size: 8** — as shipped.
- **Aggregator fan-in: 2** — pair_wrapper, as shipped.
- **Sub-batches per L2 tx: K = N / 8.**
- Number of aggregator proves: **K - 1**.
- L2 tx: 1 merged proof + batch=N settle arrays (same as B1).
- Private circuit: 1 × `verify_honk_proof`.
- Public execution: 1 × `settle_batch_merged@batch=N`.
- **Circuit work**: the `pair_wrapper` shipped today already works; just drive it recursively. Need tree-level variants (pair_wrapper over wrappers, pair_wrapper over already-merged proofs of larger batch sizes) OR one generalized circuit.

---

## Baseline measurements (for extrapolation)

All extrapolations below use these observed numbers from the shipped 16-slot tests. Opcode-ratio approximations follow `DESIGN_DECISIONS.md` §3.

| Component | Measured / inferred |
|---|---|
| IVC sub-batch @ batch=8, 1 alone | ~85 s, ~4 GiB peak RSS |
| IVC sub-batch @ batch=8, 2 concurrent | 155 s total (step8 measured) |
| Recursive sub-batch @ batch=8 (batch_app_standalone + wrapper) | ~290 s serial, ~8 GiB peak RSS |
| Recursive sub-batch @ batch=4 (extrapolated) | ~145 s, ~4 GiB peak RSS (half the opcodes) |
| `pair_wrapper` prove | ~60 s, ~3 GiB peak |
| `quad_wrapper` prove (estimated: 2× pair_wrapper verify work) | ~120 s, ~5-6 GiB peak |
| Proof size on L2 (any UltraHonk rollup-target) | 16,608 B |
| VK size | 3,680 B |
| Settle data at batch=N | 192 N bytes |

RAM budget assumption: **16 GiB WSL / 16 GiB host**, as set in the repo docs.

---

## 32-slot scenarios

### Sub-batch counts

| | Path A | Path B1 (batch=4, quad) | Path B2 (batch=8, pair) |
|---|---|---|---|
| Sub-batch size | 8 | 4 | 8 |
| Number of sub-batches | **4** | **8** | **4** |
| Aggregator layout | none (4 tube proofs direct to L2) | 2 × quad_wrapper → 1 pair_wrapper | 2 × pair_wrapper → 1 pair_wrapper |
| Aggregator prove count | 0 | 3 | 3 |
| Aggregator tree depth | 0 | 2 | 2 |

### Costs at 32 slots

| Dimension | **A** | **B1** (batch=4, quad) | **B2** (batch=8, pair) |
|---|---|---|---|
| **L2 proofs posted** | 4 × tube | 1 × merged | 1 × merged |
| **L2 DA (calldata args)** | ~75.5 KB (+87%) | **~26.1 KB** | **~26.1 KB** |
| **Private verify** | 4 × `verify_honk_proof` | 1 × `verify_honk_proof` | 1 × `verify_honk_proof` |
| **Public execution** | 4 × `settle_batch@batch=8` | 1 × `settle_batch_merged@batch=32` | 1 × `settle_batch_merged@batch=32` |
| **Public mana (est.)** | ~1.2 M l2Gas (edges per-tx cap) | ~0.4 M l2Gas | ~0.4 M l2Gas |
| Peak RAM per prover | ~4 GiB | **~4 GiB (leaves)**, ~6 GiB (quad) | ~8 GiB (leaves), ~3 GiB (pair) |
| Max concurrency @ 16 GiB | 3-4 concurrent | **4 concurrent leaves**, 2 concurrent quads | 2 concurrent leaves, 4 concurrent pairs |
| **Proving time (serial)** | 4 × 85s = ~5.7 min | 8 × 145s + 2 × 120s + 60s = ~24 min | 4 × 290s + 3 × 60s = ~22 min |
| **Proving time (16 GiB, 2-conc leaves)** | 2 × 155s = **~5.2 min** | 4 × 145s + 120s + 60s = ~13 min | 2 × 290s + 2 × 60s + 60s = ~13 min |
| **Proving time (16 GiB, 4-conc leaves)** | n/a (~4 × 4 GiB = 16 GiB) | 2 × 145s + 120s + 60s = **~6.7 min** | n/a (~4 × 8 GiB = 32 GiB) |
| **Proving time (≥ 24 GiB host)** | ~4-5 min | ~5-7 min | ~10 min (2-conc leaves max at 16 GiB) |
| Circuit changes | 0 | **new quad_wrapper**; recompile batch_app_standalone at batch=4 | generalize pair_wrapper across tree levels (or compile multiple variants) |
| Contract changes | `submit_four_batches` (trivial extension) | resize `submit_merged_batch` + `settle_batch_merged` to batch=32 | same as B1 |

**Observations at 32 slots:**
- **B1's RAM-concurrency win**: on a 16 GiB host, B1's smaller leaves (4 GiB each) let you run **4 concurrent**, beating both A (limited by mana headroom) and B2 (leaves don't fit 4-conc) on wall-clock with the same RAM budget.
- **A is easiest to implement**: no new circuits, trivial contract extension, but pays ~3× DA and edges the L2 mana ceiling.
- **B2 has more RAM pressure** than B1 at leaf level but fewer total proves; on a 24+ GiB host the difference shrinks.

---

## 128-slot scenarios

At this scale Path A is **infeasible** — it exceeds both the L2 per-tx DA budget and the per-tx mana ceiling by wide margins. Only B1 and B2 remain viable.

### Sub-batch counts

| | Path A | Path B1 (batch=4, quad) | Path B2 (batch=8, pair) |
|---|---|---|---|
| Sub-batch size | 8 | 4 | 8 |
| Number of sub-batches | **16** | **32** | **16** |
| Aggregator layout | none (16 tube proofs direct to L2) | L1: 8 × quad_wrapper; L2: 2 × quad_wrapper; L3: 1 × pair_wrapper | L1: 8; L2: 4; L3: 2; L4: 1 (all pair_wrapper) |
| Aggregator prove count | 0 | **11** (8+2+1) | **15** (8+4+2+1) |
| Aggregator tree depth | 0 | 3 | 4 |

### Costs at 128 slots

| Dimension | **A** | **B1** (batch=4, quad) | **B2** (batch=8, pair) |
|---|---|---|---|
| **L2 proofs posted** | 16 × tube (266 KB) | 1 × merged | 1 × merged |
| **L2 DA (calldata args)** | **~291 KB** (likely exceeds per-tx blob budget) | **~44 KB** | **~44 KB** |
| **Private verify** | 16 × `verify_honk_proof` | 1 × `verify_honk_proof` | 1 × `verify_honk_proof` |
| **Public execution** | 16 × `settle_batch@batch=8` | 1 × `settle_batch_merged@batch=128` | same |
| **Public mana (est.)** | **~4.8 M l2Gas (~5× per-tx cap)** | ~1.5-2 M l2Gas (approaches cap) | ~1.5-2 M l2Gas (approaches cap) |
| Peak RAM per prover | ~4 GiB | ~4 GiB (leaves), ~6 GiB (quad) | ~8 GiB (leaves), ~3 GiB (pair) |
| Max concurrency @ 16 GiB | 3-4 concurrent leaves | **4 concurrent leaves**, 2 concurrent quads | 2 concurrent leaves, 4 concurrent pairs |
| **Proving time (16 GiB, 2-conc leaves)** | ~20 min (8× 2-conc rounds) | 16 × 145s + agg ~10 min = **~49 min** | 8 × 290s + agg ~15 min = **~54 min** |
| **Proving time (16 GiB, 4-conc leaves)** | (concurrency questionable) | 8 × 145s + agg ~10 min = **~29 min** | (4-conc leaves won't fit 16 GiB) |
| **Proving time (≥ 32 GiB, 8-conc leaves)** | ~5 min but **L2 blocks it** | 4 × 145s + agg ~5 min = **~15 min** | 2 × 290s + agg ~5 min = ~15 min |
| **Feasible as single L2 tx?** | **NO** (DA + mana ceilings) | **Yes** | **Yes** |
| Circuit changes | 0 | new quad_wrapper; 3 tree-level variants OR 1 parameterized | pair_wrapper at 4 tree-level variants OR 1 parameterized |
| Contract changes | 16-arity submit method (blocked anyway) | resize to batch=128 (256/256/128/128 arrays) | same as B1 |

**Observations at 128 slots:**
- **B1's flatter tree is a real win at this scale**: 3 aggregator levels vs B2's 4. On a 16 GiB host where only 4 sub-batch proves fit concurrently, B1 finishes in ~29 min vs B2's ~54 min — roughly **1.9× faster** due to both half-size leaves (145 s vs 290 s each) and the wider fan-in.
- **A is blocked by L2 budgets**, not by proving. Any Path-A attempt at 128 must split into multiple L2 txs (defeating amortization).
- **The single `settle_batch_merged@batch=128` public call is the next wall.** ~128 storage reads + writes for deposits + ~128 for withdrawals + 2×256-iteration count loops. Close to the per-tx mana ceiling. A skeleton-proof dry run is strongly advised before committing to a full real-proof run.

---

## Choosing between the three

```
                        RAM per prover
      16 GiB ─────────── 24 GiB ─────────── 32 GiB ─────────── 48+ GiB
┌────────────────────────────────────────────────────────────────────┐
│ DA matters?                                                        │
│                                                                    │
│   YES  ──► 32 slots:    B1 (fastest on 16 GiB)  or  B2              │
│            128 slots:   B1 (fastest on 16 GiB)  or  B2              │
│                                                                    │
│   NO   ──► 32 slots:    A (simplest)                                │
│            128 slots:   blocked by L2 budgets — use B1/B2           │
└────────────────────────────────────────────────────────────────────┘
```

### Decision cheat-sheet

| Situation | Recommended path | Why |
|---|---|---|
| 32 slots, simplest to ship | **A** | Trivial contract extension, no new circuits |
| 32 slots, smallest DA on a 16 GiB host | **B1** | Fits 4-concurrent leaves; fastest wall-clock at this RAM |
| 32 slots, smallest DA on a ≥24 GiB host | **B2** or **B1** | Comparable; B2 has fewer aggregator proves, B1 uses less RAM/prover |
| 128 slots, any RAM | **B1** or **B2** (A blocked) | B1 wins on constrained RAM; B2 marginal with enough RAM |
| Beyond 128 slots | **B1** (shallower trees scale better) | Tree depth grows log₄(N) vs log₂(N) |
| If you might hit the `settle_batch_merged` mana ceiling | Verify with a skeleton-proof tx first | The ceiling applies to both B1 and B2 at large N |

---

## Implementation roadmaps

### Path A (the cheap, size-limited option)

1. Generalize `submit_two_batches` into `submit_N_batches` parameterized on K. Either:
   - Write one method per K (e.g., `submit_four_batches`, `submit_eight_batches`) for clarity, or
   - Use a Noir const-generic `fn submit_N_batches<K>(...)` if the version of noir supports it.
2. Each method takes a shared VK + K × (proof, public_inputs, nullifiers, note_hashes, deposits, withdrawals).
3. Assert `tube_vk_hash == storage.tube_vk_hash.read()` once (shared).
4. K × `verify_honk_proof`.
5. K × state-chain / tree-index-chain asserts between consecutive sub-batches.
6. K × `enqueue_self.settle_batch(...)`.

**Effort**: ~1 hour of contract work. Zero new circuits.

**Max K before L2 budgets refuse**: empirically likely K ≤ 3-4 before tx mana exceeds cap.

### Path B1 (RAM-efficient scaling)

1. **Compile a second `batch_app_standalone` variant at `MAX_BATCH_SIZE = 4`.** Or keep one and const-generic it — but simplest is a second crate `batch_app_standalone_4`.
2. **Compile a `wrapper_4` variant** that verifies `batch_app_standalone_4` proofs. Again, probably cleanest as a sibling crate.
3. **Write `quad_wrapper`**. Input: `wrapper_vk`, 4 × (wrapper_proof, wrapper_public_inputs), 4 × (nullifiers[8], note_hashes[8], deposits[4], withdrawals[4]). Output: the 8 BatchOutput fields over merged arrays (32+32+16+16 for 4 sub-batches of size 4).
4. **Tree-level variants of quad_wrapper** for non-leaf levels: `quad_wrapper_L2` aggregates 4 level-1 merged outputs (each a 16-slot merged batch) into a 64-slot merged batch; `quad_wrapper_L3` aggregates 4 level-2 → 256-slot. For **32-slot**: level-1 quad_wrapper + one pair_wrapper at root (reusing today's pair_wrapper at its current sizing). For **128-slot**: level-1 quad, level-2 quad, level-3 pair_wrapper. Ideal: parameterize or use const-generics to avoid writing multiple crates.
5. **Resize `contract_recursive`**: batch-128 arrays in `submit_merged_batch_large` + `settle_batch_merged_large` (or extend `settle_batch_merged` with configurable sizes — Noir doesn't support runtime-variable arrays, so compile-time variants).
6. **Harness**: `buildBatchProofRecursive` with `{ subBatchSize: 4 }` option that flows through to the right circuit variant. A new `buildQuadWrapperProof` helper. A recursive tree driver that manages sub-batch + aggregator concurrency against a RAM budget.

**Effort**: ~1 week (new circuit, tree variants, contract resize, harness driver).

**Advantage over B2**: every prover in the tree stays at the ~4 GiB leaf baseline, so a 16 GiB host can run 4 concurrent leaves. Tree depth is 1 level shorter per 4× doubling — measurable at 128+ slots.

### Path B2 (binary-tree scaling on the existing pair_wrapper)

1. **Generalize pair_wrapper** to work at any tree level: take two merged proofs of the same size and concatenate. Requires either const-generics or multiple compiled variants (e.g., `pair_wrapper_8`, `pair_wrapper_16`, `pair_wrapper_32`, `pair_wrapper_64`).
2. **Resize `contract_recursive`** to batch=128 (256/256/128/128 arrays).
3. **Harness**: recursive tree driver over pair_wrapper calls, managing the 2-concurrent leaves that fit in 16 GiB.

**Effort**: ~3-4 days (pair_wrapper level variants, contract resize, harness driver).

**Advantage over B1**: reuses the pair_wrapper circuit already in the repo; no new circuit type. Fewer aggregator proves at the same N due to the binary tree having more leaves but smaller aggregators (quad is bigger per prove than pair, so total aggregator work is similar).

---

## Summary table (all three paths, both targets)

| Metric | 32 slots | | | 128 slots | | |
|---|---|---|---|---|---|---|
|| **A** | **B1** | **B2** | **A** | **B1** | **B2** |
| L2 DA | ~76 KB | ~26 KB | ~26 KB | **~291 KB ⚠** | ~44 KB | ~44 KB |
| Public mana | ~1.2 M ⚠ | ~0.4 M | ~0.4 M | **~4.8 M ⚠⚠** | ~1.5-2 M ⚠ | ~1.5-2 M ⚠ |
| Proofs on L2 | 4 | 1 | 1 | 16 | 1 | 1 |
| Private verify | 4 | 1 | 1 | 16 | 1 | 1 |
| Proving time (16 GiB) | ~5 min | ~7 min | ~13 min | ~20 min | **~29 min** | ~54 min |
| Proving time (32 GiB) | ~4 min | ~5 min | ~10 min | blocked by L2 | ~15 min | ~15 min |
| Circuit work | 0 | medium (quad_wrapper + variants) | medium (pair_wrapper variants) | 0 | medium | medium |
| Contract work | trivial | small (resize) | small (resize) | — | small | small |
| Viable at single-L2-tx? | **yes** | **yes** | **yes** | **NO** ❌ | **yes** | **yes** |

⚠ = close to L2 per-tx ceiling; ⚠⚠ = exceeds L2 per-tx ceiling; ❌ = infeasible in single L2 tx.

---

## Two caveats that bind all three at large N

Both B1 and B2 eventually run into the same two walls that aren't proof-architecture problems:

1. **Per-tx L2 mana ceiling on the single `settle_batch_merged@batch=N` call.** The public function's deposit-consume and withdrawal-register loops are O(N). Around N=128 the mana estimate reaches 1.5-2 M l2Gas, close to typical per-tx ceilings. Past ~200-256 slots, you'd start splitting into multiple L2 txs regardless of how clever the proof aggregation was.
2. **Per-tx L2 DA budget**. Settle-data scales linearly with N; at batch=128 it's ~25 KB just for settle arrays. At batch=512 it's ~100 KB. Aztec tx payloads go to blob data with a per-tx allocation budget; exceeding it forces a split.

Both of these are **Aztec protocol limits**, not problems with any design choice here. Past ~128-256 slot capacity per L2 tx, you increase throughput by submitting **more frequent** L2 txs, not **bigger** ones. The three paths differ only in how efficiently they use the single-L2-tx budget.

## Related docs

- [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md) — the 16-slot implementation that ships today; starting point for all extrapolations above.
- [`DESIGN_DECISIONS.md`](./DESIGN_DECISIONS.md) §3 — recursive UltraHonk pipeline rationale and ACIR opcode scaling table.
- [`README.md`](./README.md) — repo overview and single-batch test instructions.
