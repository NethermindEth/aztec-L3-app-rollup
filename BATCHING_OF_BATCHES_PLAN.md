# Batching-of-Batches — Execution Plan

Self-contained plan for adding two "batch of batches" comparison tests to this
repo. Intended to be picked up by a clean-context session and executed without
re-deriving the design decisions.

## Goal

Produce two end-to-end tests that each settle **16 slot-capacity** (2 real
deposits + 14 padding) in a **single L2 transaction**, one using the IVC/Chonk
pipeline and one using the recursive/UltraHonk pipeline with proof aggregation.
Then emit a side-by-side cost comparison: client proving wall-clock, DA bytes,
L2 submit wall-clock, private-circuit verification cost (structural), public
execution cost (structural), peak memory, proof sizes.

## Context to read first

- `DESIGN_DECISIONS.md` §3 — IVC vs Recursive pipeline rationale, Chonk
  ECCVM ceiling rationale.
- `tests/step7-meta-batch-ivc.ts` — existing sequential IVC meta-batch test
  (starting template for step8).
- `contract_ivc/src/main.nr` — already has `submit_two_batches` (built for
  step7).
- `circuits/batch_app_standalone/src/main.nr` — batch=8, `tx_public_inputs[i][4]
  == old_state_root` (all real txs share the pre-batch state root; no
  multi-tx-chaining needed).
- `circuits/batch_app/src/main.nr` — batch=8, checks `tx_public_inputs[i][4]
  == compute_state_root(cur_null_root, cur_nh_root)` (each real tx needs
  intermediate state root — NOT relevant here because we're staying at 1 real
  per batch).
- `tests/harness/prover.ts` — `buildBatchProof` (IVC pipeline).
- `tests/harness/prover-recursive.ts` — `buildBatchProofRecursive` (recursive
  pipeline), `computeWrapperVkHash`.
- `tests/harness/state.ts` — `TestL3State`, `IVC_BATCH_SIZING`,
  `RECURSIVE_BATCH_SIZING` (both at batch=8, 16/16/8/8 arrays).

## Decisions already locked in (do NOT re-question these)

1. **16 slot capacity = 2 real + 14 padding** (1 real per sub-batch). Avoids
   the multi-real-tx-per-batch harness refactor. Both tests use this.
2. **UltraHonk test uses merged-settle** — not split-settle. The pair_wrapper
   proof attests to one combined state transition, and the contract settles it
   as one unit via a new `settle_batch_merged` public method with batch=16
   arrays (32/32/16/16).
3. **Recursive contract gets a new storage slot** `merged_vk_hash`, pinning
   the pair_wrapper VK hash. Existing `tube_vk_hash` stays (pins wrapper VK
   hash, used by `submit_batch`). Constructor signature extends to
   `constructor(initial_state_root, tube_vk_hash, merged_vk_hash)`.
4. **Concurrent proving** on both tests. Create two `Barretenberg` instances
   per test, run the two sub-batch proves in `Promise.all`. The pair_wrapper
   prove on Test 2 is serial after both wrappers complete.
5. **Full comparison** emitted in step7-style format at the end of each test
   (or a joint runner). Dimensions: proving wall-clock, DA bytes, L2 submit
   wall-clock, verification cost (reasoned), execution cost (reasoned), peak
   memory, proof sizes.

## Build order

### Phase 1 — Harness helpers for concurrent proving

File: `tests/harness/prover.ts` (and mirror in `prover-recursive.ts`).

- Export a helper that constructs a second `Barretenberg` instance with its
  own thread pool. Keep the single-api signature backward-compatible.
- No other harness changes needed (the `buildBatchProof` and
  `buildBatchProofRecursive` functions already take `api` as a parameter; we
  just pass different instances in from the test scripts).

### Phase 2 — Test 1 (IVC meta-batch) at `tests/step8-ivc-meta-16slot.ts`

Start from `tests/step7-meta-batch-ivc.ts`. Change:

- Case A (single batch) is kept as baseline.
- Case B (two batches in one L2 tx via `submit_two_batches`) proves the two
  batches concurrently using two bb instances + `Promise.all`.
- Report wall-clock separately for "per-batch if concurrent" vs observed
  total. Expected: concurrent B wall-clock ≈ single-batch wall-clock (~1.4
  min), giving ~2× speedup over step7's sequential 2.9 min.

No contract changes. No circuit changes.

### Phase 3 — `pair_wrapper` circuit

Create `circuits/pair_wrapper/`:

- `Nargo.toml` — deps on `l3_types`, `bb_proof_verification`.
- `src/main.nr` — the circuit itself.

Circuit signature (sketch):

```noir
use l3_types::{poseidon2_hash, BATCH_OUTPUT_FIELDS};
use bb_proof_verification::{verify_honk_proof, UltraHonkVerificationKey, UltraHonkZKProof};

// These MUST match circuits/batch_app_standalone globals (batch=8):
global SUB_BATCH_SIZE: u32 = 8;
global SUB_BATCH_NULLIFIERS: u32 = 16;  // SUB_BATCH_SIZE * 2
global SUB_BATCH_NOTE_HASHES: u32 = 16; // SUB_BATCH_SIZE * 2

// Merged-batch array sizes (doubled):
global MERGED_BATCH_SIZE: u32 = 16;
global MERGED_BATCH_NULLIFIERS: u32 = 32;
global MERGED_BATCH_NOTE_HASHES: u32 = 32;

fn main(
    // Shared
    wrapper_vk: UltraHonkVerificationKey,
    wrapper_vk_hash: Field,
    // Batch A
    wrapper_proof_a: UltraHonkZKProof,
    wrapper_public_inputs_a: [Field; BATCH_OUTPUT_FIELDS],
    nullifiers_a: [Field; SUB_BATCH_NULLIFIERS],
    note_hashes_a: [Field; SUB_BATCH_NOTE_HASHES],
    deposits_a: [Field; SUB_BATCH_SIZE],
    withdrawals_a: [Field; SUB_BATCH_SIZE],
    // Batch B
    wrapper_proof_b: UltraHonkZKProof,
    wrapper_public_inputs_b: [Field; BATCH_OUTPUT_FIELDS],
    nullifiers_b: [Field; SUB_BATCH_NULLIFIERS],
    note_hashes_b: [Field; SUB_BATCH_NOTE_HASHES],
    deposits_b: [Field; SUB_BATCH_SIZE],
    withdrawals_b: [Field; SUB_BATCH_SIZE],
    // Merged public outputs (batch=16 shape)
    old_state_root: pub Field,
    new_state_root: pub Field,
    merged_nullifiers_hash: pub Field,
    merged_note_hashes_hash: pub Field,
    merged_deposit_nullifiers_hash: pub Field,
    merged_withdrawal_claims_hash: pub Field,
    nullifier_tree_start_index: pub Field,
    note_hash_tree_start_index: pub Field,
) {
    // 1. Verify both wrapper proofs.
    verify_honk_proof(wrapper_vk, wrapper_proof_a, wrapper_public_inputs_a, wrapper_vk_hash);
    verify_honk_proof(wrapper_vk, wrapper_proof_b, wrapper_public_inputs_b, wrapper_vk_hash);

    // 2. Re-feed data matches each batch's committed hash.
    assert(poseidon2_hash(nullifiers_a) == wrapper_public_inputs_a[2]);
    assert(poseidon2_hash(note_hashes_a) == wrapper_public_inputs_a[3]);
    assert(poseidon2_hash(deposits_a) == wrapper_public_inputs_a[4]);
    assert(poseidon2_hash(withdrawals_a) == wrapper_public_inputs_a[5]);
    assert(poseidon2_hash(nullifiers_b) == wrapper_public_inputs_b[2]);
    assert(poseidon2_hash(note_hashes_b) == wrapper_public_inputs_b[3]);
    assert(poseidon2_hash(deposits_b) == wrapper_public_inputs_b[4]);
    assert(poseidon2_hash(withdrawals_b) == wrapper_public_inputs_b[5]);

    // 3. State-root chain: B.old == A.new.
    assert(wrapper_public_inputs_a[1] == wrapper_public_inputs_b[0]);

    // 4. Tree-index chain.
    let mut null_count_a: Field = 0;
    for i in 0..SUB_BATCH_NULLIFIERS { if nullifiers_a[i] != 0 { null_count_a += 1; } }
    let mut nh_count_a: Field = 0;
    for i in 0..SUB_BATCH_NOTE_HASHES { if note_hashes_a[i] != 0 { nh_count_a += 1; } }
    assert(wrapper_public_inputs_b[6] == wrapper_public_inputs_a[6] + null_count_a);
    assert(wrapper_public_inputs_b[7] == wrapper_public_inputs_a[7] + nh_count_a);

    // 5. Expose merged outputs.
    assert(old_state_root == wrapper_public_inputs_a[0]);
    assert(new_state_root == wrapper_public_inputs_b[1]);
    let mut merged_nullifiers: [Field; MERGED_BATCH_NULLIFIERS] = [0; MERGED_BATCH_NULLIFIERS];
    for i in 0..SUB_BATCH_NULLIFIERS {
        merged_nullifiers[i] = nullifiers_a[i];
        merged_nullifiers[SUB_BATCH_NULLIFIERS + i] = nullifiers_b[i];
    }
    assert(merged_nullifiers_hash == poseidon2_hash(merged_nullifiers));
    // ... same for note_hashes, deposits, withdrawals ...
    assert(nullifier_tree_start_index == wrapper_public_inputs_a[6]);
    assert(note_hash_tree_start_index == wrapper_public_inputs_a[7]);
}
```

Register in `Nargo.toml` workspace members.

### Phase 4 — Compile pair_wrapper standalone, verify it builds

```bash
wsl -e bash -lc '. ~/.nvm/nvm.sh && export PATH=~/.aztec/current/bin:~/.aztec/current/node_modules/.bin:$PATH && cd /mnt/c/Users/Conor/.claude-worktrees/aztec-l3 && nargo compile --workspace 2>&1 | tail -20'
```

Expected: produces `target/l3_pair_wrapper.json`.

### Phase 5 — Extend `contract_recursive`

File: `contract_recursive/src/main.nr`.

- Add `merged_vk_hash: PublicMutable<Field, Context>` to Storage.
- Extend constructor: add `merged_vk_hash: Field` arg, write to storage.
- Add private method `submit_merged_batch(merged_vk, merged_proof,
  public_inputs[8], merged_vk_hash, nullifiers[32], note_hashes[32],
  deposits[16], withdrawals[16])` — verify, count nonzeros, enqueue
  `settle_batch_merged`.
- Add public `#[only_self]` method `settle_batch_merged(old_state_root,
  new_state_root, deposits[16], withdrawals[16], null_count, nh_count,
  nullifiers[32], note_hashes[32])` — same logic as existing `settle_batch`
  but loops over doubled array sizes.

Update `contract_recursive/src/test/utils.nr` and `lifecycle.nr` to pass
`merged_vk_hash=0` (unused in unit tests) in the `L3RecursiveSettlement::interface().constructor(...)` call.

Recompile:
```bash
wsl -e bash -lc '. ~/.nvm/nvm.sh && export PATH=~/.aztec/current/bin:~/.aztec/current/node_modules/.bin:$PATH && cd /mnt/c/Users/Conor/.claude-worktrees/aztec-l3 && aztec compile --workspace --force 2>&1 | tail -8'
```

Run Noir tests:
```bash
wsl -e bash -lc '. ~/.nvm/nvm.sh && export PATH=~/.aztec/current/bin:~/.aztec/current/node_modules/.bin:$PATH && cd /mnt/c/Users/Conor/.claude-worktrees/aztec-l3/contract_recursive && aztec test 2>&1 | grep -E "Testing|tests passed|tests failed" | tail -8'
```

Expected: 5/5 pass.

### Phase 6 — `buildPairWrapperProof` in `prover-recursive.ts`

Add a function that takes two `BatchArtifact`s (from `buildBatchProofRecursive`)
and the two batches' re-fed nullifier/note-hash/deposit/withdrawal arrays,
runs the pair_wrapper circuit, generates an UltraHonk `noir-rollup` proof,
and returns `{ pairWrapperProof, pairWrapperVk, mergedPublicInputs }`.

Also add `computePairWrapperVkHash(api)` — same pattern as
`computeWrapperVkHash` but points at the `l3_pair_wrapper` artifact.

### Phase 7 — Test 2 (recursive merged-proof) at `tests/step9-recursive-merged-16slot.ts`

- Connect to sandbox, compute pair_wrapper VK hash.
- Deploy Token + L3RecursiveSettlement with
  `constructor(initial_state_root, wrapperVkHash, pairWrapperVkHash)`.
- Register 2 real deposits on L2.
- Two concurrent `Barretenberg` instances.
- `Promise.all` proves both sub-batches (each 1 real + 7 padding).
- Run pair_wrapper prove (serial, one bb instance).
- Submit via `submit_merged_batch`.
- Emit step7-shape comparison table (this test should also re-run step8's
  case for a fair side-by-side — either inline or by reading a saved JSON
  from step8).

### Phase 8 — Joint runner or saved-metrics approach

Simplest: step8 and step9 each print their metrics. A separate
`tests/step10-compare-meta-vs-merged.md` (or similar) captures the numbers
manually or via a minimal consumer script.

If time allows, a single runner `tests/step10-meta-vs-merged.ts` that
executes step8's submission + step9's submission in one process against the
same deployed contracts and prints a combined comparison block.

## Expected numbers (order of magnitude)

For reference when verifying the tests work:

- Concurrent IVC two-batch prove: ~1.4 min (vs sequential 2.9 min in step7)
- pair_wrapper prove: ~45-60 s (verifies 2 UltraHonk proofs, constant-size
  output)
- Concurrent recursive two-sub-batch prove: ~1.4 min
- Total Test 2 proving: concurrent sub-batches + serial pair_wrapper ≈ 2.0-2.2 min
- Final on-chain proof size: 16,608 bytes (same as tube/wrapper — UltraHonk
  rollup-targeted, constant)
- Test 1 DA: ~40.5 KB (measured in step7, same for step8)
- Test 2 DA: ~23 KB proof+VK+pub + batch=16 settle args (48 fields = 1.5 KB +
  extra for the 2 extra deposit/withdrawal slots doubled = 32 * 32 = 1 KB
  more over batch=8) ≈ ~25 KB total
- WSL memory: peak ~10-12 GiB during concurrent proving

## Non-goals

- Multi-real-tx-per-batch prover refactor. Still 1 real + 7 padding per
  sub-batch. If later wanted, that's a separate scope.
- Gas-receipt collection via `node.getTxReceipt(txHash)`. Current tests use
  `.send()` which returns a lightweight result without gasUsed. Verification
  and execution costs are reasoned structurally (constraint count, loop
  bounds). Adding real gas numbers is a follow-up.
- Shared bb-instance optimization. Each concurrent prove gets its own bb
  instance for clean parallelism.

## Files to create or modify

Modified:
- `tests/harness/prover.ts` — concurrent-proving helper (minor).
- `tests/harness/prover-recursive.ts` — concurrent helper + buildPairWrapperProof
  + computePairWrapperVkHash.
- `contract_recursive/src/main.nr` — +merged_vk_hash storage, +extended
  constructor, +submit_merged_batch, +settle_batch_merged.
- `contract_recursive/src/test/utils.nr` — constructor callsite (pass 0 for
  merged_vk_hash).
- `Nargo.toml` — add `circuits/pair_wrapper` to workspace members.

Created:
- `circuits/pair_wrapper/Nargo.toml`
- `circuits/pair_wrapper/src/main.nr`
- `tests/step8-ivc-meta-16slot.ts`
- `tests/step9-recursive-merged-16slot.ts`
- (optional) `tests/step10-meta-vs-merged.ts`

## Environment reminders

- All commands run via WSL. Setup prefix: `wsl -e bash -lc '. ~/.nvm/nvm.sh
  && export PATH=~/.aztec/current/bin:~/.aztec/current/node_modules/.bin:$PATH
  && cd /mnt/c/Users/Conor/.claude-worktrees/aztec-l3 && <cmd>'`.
- Docker sandbox: `cd tests && docker compose up -d` (already running on
  port 8080 in most sessions).
- WSL memory budget: 16 GB (set via `%USERPROFILE%\.wslconfig`).
  batch=8 proving peaks ~4-5 GiB per prover; concurrent 2× proves fit.
- Recompile + AVM-transpile uses `aztec compile --workspace --force` from
  repo root. Runs nargo + bb AVM transpile + strips `__aztec_nr_internals__`
  prefix.

## Success criteria

- step8 runs to EXIT 0, prints comparison block, produces a nonce advance of
  +2 on chain (2 settle_batch calls from submit_two_batches).
- step9 runs to EXIT 0, prints comparison block, produces a nonce advance of
  +1 on chain (1 settle_batch_merged call from submit_merged_batch).
- Noir unit tests in both contracts remain 5/5 green.
- Final side-by-side table emitted: proving / DA / submit wall-clock /
  qualitative verification / qualitative execution / memory / proof sizes.
