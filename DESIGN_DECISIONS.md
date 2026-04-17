# Design Decisions

## 1. Minimal DA in `settle_batch` — delegate verification to the kernel proof

### Decision

`settle_batch` (and `settle_batch_{16,64,merged}`) carries only the data needed to mutate public state. All proof verification, hash-consistency checks, and VK-identity checks happen in the private `submit_*` function and are not repeated in public.

Public args:

- `old_state_root`, `new_state_root` — advance the on-chain state
- `deposit_nullifiers` — consume pending deposits
- `withdrawal_claims` — register pending withdrawals
- `null_count`, `nh_count` — advance tree insertion indices
- `nullifiers`, `note_hashes` — carried as args purely for DA (no processing in public)

Not re-accepted in public: `tube_vk_hash`, batch hashes, tree start indices.

### Rationale

Aztec's kernel proof commits to the exact arguments of an enqueued public call. The sequencer must execute public with precisely those committed arguments; deviation invalidates the kernel proof. So `submit_batch`'s verified data can be forwarded to `settle_batch` as arguments without re-checking them in public.

The one runtime check that remains — `old_state_root == storage.latest_root` — guards against two valid batches built against the same historical state. That's not something proof verification can catch (private reads historical public state).

### Walkback

If the kernel-proof trust model is too aggressive during development, re-add hash / VK / tree-index checks in `settle_batch` and emit public logs for nullifiers + note hashes. Costs ~29 extra fields per batch (~928 bytes); restores a redundant check layer.

### Impact

| | Args (fields) | Logs (fields) | Total DA (fields) | Total DA (bytes) |
|---|---|---|---|---|
| Before | 33 | 24 | 57 | 1,824 |
| After | 28 | 0 | 28 | 896 |
| Reduction | | | 29 | 928 (51%) |

## 2. No public logs — DA via function arguments only

Function arguments already land in the transaction envelope posted to DA. Public logs are a separate, additive DA channel. Emitting the same data through both doubles DA with no availability gain.

An L3 this specific (nullifier trees, deposit/withdrawal lifecycle) needs a purpose-built indexer regardless — no generic Aztec indexer understands the state model. A custom indexer decoding `settle_batch` arguments from the call stack is equivalent to consuming logs and costs no more.

Walkback: re-emit `nullifiers` and `note_hashes` as public logs (adds 16 fields / 512 bytes per batch) if third-party tooling needs log-based discovery.

## 3. Two aggregation paths — Path B primary, Path C secondary

The repo implements both aggregation styles and terminates both at the same 500-field `UltraHonkZKProof`.

### Path B — pure recursive UltraHonk (primary)

`batch_app_standalone` → `wrapper` → `wrapper_{16,32,64}`. No IVC, no Chonk, no IPA. The root blocker that previously forced IVC — `batch_app`'s databus annotation (`return_data BatchOutput`) requiring MegaCircuitBuilder — is bypassed by `batch_app_standalone`, which uses explicit `pub Field` outputs. Circuit logic is otherwise identical.

With the ECCVM bottleneck eliminated, opcode count scales linearly with batch size (see table below). Batch=8 is the current setting for memory, not a protocol limit.

| Batch size | ACIR opcodes | Per-tx opcodes |
|---|---|---|
| 4 | 14,661 | 3,665 |
| 8 | 29,313 | 3,664 |
| 16 | 58,617 | 3,664 |
| 32 | 117,225 | 3,663 |
| 64 | 234,441 | 3,663 |
| 128 | 468,873 | 3,663 |

### Path C — IVC + `pair_tube` root-rollup (secondary)

Retains `batch_app` + IVC kernel chain + tube per sub-batch; aggregates two tubes via `pair_tube` using `PROOF_TYPE_ROOT_ROLLUP_HONK` to finalize accumulated IPA claims in-circuit (see `SILENT_FAILURE_REVIEW.md`). `pair_tube`'s output is a 500-field `UltraHonkZKProof` matching the contract ABI.

### Why B is primary

- Uniform UltraHonk / BN254 throughout; no foreign-field / non-native arithmetic.
- Aggregator is cheap (`wrapper_16` gate count is two `verify_honk_proof`s).
- No ECCVM-imposed batch cap.

Path C's per-tx proving is cheaper (IVC folding), which matters at larger batch counts — see `SCALING.md`. Its aggregator is expensive because finalizing IPA in-circuit means simulating Grumpkin EC ops inside a BN254 UltraHonk circuit.

### Walkback

Both paths coexist in the codebase. If the balance tilts (e.g. ECCVM row limit raised, or a MegaHonk-style backend in bb.js) Path C's aggregator becomes cheaper and could be promoted.
