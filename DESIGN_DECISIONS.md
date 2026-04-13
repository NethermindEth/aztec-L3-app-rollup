# Design Decisions

## 1. Minimal DA in `settle_batch` by Delegating Verification to the Kernel Proof

### Decision

The `settle_batch` public function carries only the data it needs to mutate public state. All proof verification, hash consistency checks, and index validation are performed in the private `submit_batch` function and are not repeated in public.

Concretely, `settle_batch` accepts:

- `old_state_root` — to enforce sequential batch ordering
- `new_state_root` — to advance the on-chain state
- `deposit_nullifiers` — to consume pending deposits (public state mutation)
- `withdrawal_claims` — to register pending withdrawals (public state mutation)
- `null_count`, `nh_count` — to advance tree insertion indices
- `nullifiers`, `note_hashes` — carried as args purely for DA (no processing in the function body)

It does **not** accept or re-verify: `tube_vk_hash`, batch hashes, or tree start indices.

### Rationale

In Aztec's execution model, when a private function enqueues a public function call, the kernel proof commits to the exact arguments of that enqueued call. The sequencer must execute the public function with precisely those committed arguments — any deviation invalidates the kernel proof. This means:

1. `submit_batch` verifies the tube proof and extracts the correct public inputs.
2. `submit_batch` constructs the `settle_batch` arguments from verified data.
3. The kernel proof cryptographically binds those arguments to the transaction.
4. No actor can modify the arguments between private execution and public execution.

Re-verifying hashes, VK identity, or tree indices in the public function is therefore redundant with the protocol's proof model. Each redundant field adds 32 bytes of DA cost per batch with no security benefit beyond catching bugs in our own `submit_batch` implementation.

The one check that remains — `old_state_root == storage.latest_root` — is fundamentally different. It guards against a runtime condition (two valid batches built against the same state, where only the first should succeed) that cannot be caught by proof verification alone, since private functions can only read historical public state.

### Walkback

If the kernel proof trust model is considered too aggressive a dependency — for example, during early development when the private function is changing frequently and bugs in argument construction are likely — a moderate alternative is available:

Keep all verification checks in `settle_batch` (hash checks, VK hash check, tree index checks) and re-add public logs for nullifiers and note hashes. This restores the original trust model and gives indexers a standard log-based subscription API at the cost of higher DA.

### Impact

| | Args (fields) | Logs (fields) | Total DA (fields) | Total DA (bytes) |
|---|--------|-------|-------|-------|
| Before | 33 | 24 | 57 | 1,824 |
| After | 28 | 0 | 28 | 896 |
| Reduction | | | 29 | 928 (51%) |

## 2. No Public Logs — DA via Function Arguments Only

### Decision

`settle_batch` does not emit any public logs. All batch data (nullifiers, note hashes, deposit nullifiers, withdrawal claims) is made available for data availability exclusively through the public function arguments.

### Rationale

In Aztec, public function arguments are part of the transaction envelope posted to DA. Public logs are a separate DA channel — also posted. Emitting data as both function arguments and logs doubles the DA cost for that data with no additional availability.

Public logs exist to give indexers a standardized subscription API (`getLogs` by contract address and event type). However, this L3 requires a purpose-built indexer regardless — no generic Aztec indexer understands the L3 state model (nullifier trees, note hash trees, deposit/withdrawal lifecycle). A custom indexer that already knows the contract ABI can decode `settle_batch` arguments from the transaction call stack directly.

### Walkback

If indexer tooling evolves to make log-based discovery significantly easier, or if third-party indexers need to consume L3 state without custom ABI knowledge, public logs can be re-added for nullifiers and note hashes:

```noir
self.context.emit_public_log_unsafe(0, nullifiers);
self.context.emit_public_log_unsafe(1, note_hashes);
```

This would add 16 fields (512 bytes) of DA per batch. Deposit nullifiers and withdrawal claims should still not be logged since they are already in the function arguments and are needed there for state mutations.

## 3. Recursive UltraHonk Pipeline (replacing IVC/Chonk)

### Decision

The proving pipeline uses a two-stage recursive UltraHonk architecture instead of the five-stage IVC/Chonk pipeline:

**Old pipeline (5 stages):** batch_app -> init_kernel -> tail_kernel -> hiding_kernel (Chonk) -> tube (UltraHonk)

**New pipeline (2 stages):** batch_app_standalone (UltraHonk) -> wrapper (UltraHonk)

The three IVC kernel circuits, the Chonk proving step, and the tube circuit are eliminated. The `AztecClientBackend` dependency is removed entirely.

### Rationale

The IVC/Chonk pipeline existed to satisfy Aztec's kernel accumulation API. The three kernel circuits (init, tail, hiding) are trivial pass-throughs (~10 lines each) that add no security or functionality. The Chonk step introduces the ECCVM 32768-row limit that caps batch size at 4 transactions.

The root blocker to replacing this pipeline was that `batch_app` used `return_data BatchOutput` -- a Noir databus annotation that creates CallData/ReturnData block constraints requiring MegaCircuitBuilder. UltraHonkBackend cannot prove circuits with these constraints.

The solution: `batch_app_standalone` replaces `-> return_data BatchOutput` with explicit `pub Field` outputs. The circuit logic is identical. The wrapper circuit then verifies the batch_app_standalone UltraHonk proof and re-exposes the same 8 public inputs for L2 contract verification.

### Batch Size Scaling

With the ECCVM bottleneck eliminated, the circuit compiles and scales linearly at any batch size:

| Batch Size | ACIR Opcodes | Per-TX Opcodes | Compiles? |
|---|---|---|---|
| 4 | 14,661 | 3,665 | Yes |
| 8 | 29,313 | 3,664 | Yes |
| 16 | 58,617 | 3,664 | Yes |
| 32 | 117,225 | 3,663 | Yes |
| 64 | 234,441 | 3,663 | Yes |
| 128 | 468,873 | 3,663 | Yes |

The ceiling is no longer a hard protocol limit. It is determined by proving time (roughly linear with circuit size) and prover memory.

### Measured Performance (batch size 4)

At batch size 4, the recursive pipeline produces a valid end-to-end proof (deposit, payment, withdrawal, claim) with the following per-batch timing:

- batch_app_standalone UltraHonk prove: ~60-80s
- wrapper UltraHonk prove: ~40-50s
- Total per batch: ~110-130s

The wrapper circuit is constant-size regardless of batch size (it verifies one UltraHonk proof). Only the batch_app_standalone circuit grows with batch size.

### Walkback

The IVC/Chonk pipeline remains in the codebase and is untouched. It can be used via `step4-full-lifecycle.ts` with the original `batch_app`, kernel circuits, and tube circuit. The recursive pipeline is a parallel path tested via `step5-recursive-poc.ts`.

If Aztec raises the ECCVM row limit or provides a MegaHonk backend in bb.js, the IVC pipeline could become competitive again for larger batch sizes. The recursive pipeline would still be preferred if UltraHonk proving is faster than Chonk for equivalent circuit sizes.

### Key Files

| File | Role |
|---|---|
| `circuits/batch_app_standalone/src/main.nr` | batch_app with `pub Field` outputs (no databus) |
| `circuits/wrapper/src/main.nr` | Verifies batch_app UltraHonk proof |
| `tests/harness/prover-recursive.ts` | `buildBatchProofRecursive()` + `computeWrapperVkHash()` |
| `tests/step5-recursive-poc.ts` | Full lifecycle e2e test |
| `tests/bench-recursive-100tx.ts` | 100-tx throughput benchmark |
