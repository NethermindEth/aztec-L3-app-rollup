# Batching-of-Batches on Aztec L3

> Settling **16 L3 transactions in one L2 transaction** via recursive proof aggregation, with IVC benchmarks for comparison.

## Recursive merged-proof (primary design)

The `wrapper_16` circuit recursively verifies two wrapper proofs and outputs a single merged UltraHonk proof. This is the **only path with correct proof format alignment**: it produces 500-field `noir-recursive` proofs matching the contract's `UltraHonkZKProof` ABI.

| | Value |
|---|---|
| **Total L3 tx capacity per L2 tx** | **16 slots** (2 sub-batches × 8) |
| Proofs on the L2 tx | **1** × UltraHonk (16,000 B, 500 fields) |
| L2 function-arg DA | **23,040 bytes** |
| Client proving wall-clock | ~10.7 min sequential / ~5.2 min concurrent (≥24 GiB RAM) |
| Private-circuit verify cost | 1 × `verify_honk_proof` |
| Public execution | 1 × `settle_batch_16` at batch=16 |
| Proof format | 500-field `noir-recursive` — **matches contract ABI** |

End-to-end test: `npx tsx tests/step9-recursive-16slot.ts`

## IVC benchmarks (indicative only)

> **Warning: IVC paths have an unresolved proof format mismatch.** IVC tube proofs are 519-field `noir-rollup` (RollupHonk with IPA material). The contract ABI declares 500-field `UltraHonkZKProof`. The SDK silently truncates the excess 19 fields. The sandbox does not enforce proof verification (`PXE_PROVER=none`), so these tests pass but proof soundness is not validated. **These results are for benchmarking proving speed only, not for production use.** See [`SILENT_FAILURE_REVIEW.md`](./SILENT_FAILURE_REVIEW.md).

Two IVC-based batching designs were built for comparison:

- **Design A — IVC meta-batch** sends **two tube proofs** in one L2 tx (no aggregation). Faster proving (~2.6 min) but higher DA (40,512 B) and 2 × `verify_honk_proof` in the kernel.
- **Path C — IVC + RollupHonk aggregation** aggregates two tube proofs into **one proof** via `pair_tube` using `verify_rolluphonk_proof`. Gets the recursive design's DA savings with IVC's proving speed (~3.9 min).

### Indicative comparison at 16 slots

| | **Recursive merged** | **IVC meta-batch (A)** | **IVC + pair_tube (C)** |
|---|---|---|---|
| **Proof format** | **500 fields (correct)** | 519 fields (truncated) | 519 fields (truncated) |
| **Production-ready?** | Pending sandbox verification | **No** (format mismatch) | **No** (format mismatch) |
| **Proving time** | ~10.7 min | **~2.6 min** | **~3.9 min** |
| **L2 DA** | **23,040 B** | 40,512 B | 23,648 B |
| **L2 proofs** | 1 (500 fields) | 2 (519 fields each) | 1 (519 fields) |
| **Nonce advance** | +1 | +2 | +1 |
| **RAM per sub-batch** | ~8 GiB | ~4 GiB | ~4 GiB |
| **2 concurrent @ 16 GiB** | no (OOM) | yes | yes |

The IVC paths prove faster because IVC sub-batches are ~4 GiB each (allowing 2 concurrent on 16 GiB), vs ~8 GiB for recursive sub-batches. If Aztec resolves the `noir-rollup` proof format issue (RollupHonk support in MegaBuilder, or IPA-free `noir-recursive` tube proving), the IVC paths would become viable for production.

---

## Glossary — what the numbers mean

To avoid confusion, here's what each quantity counts:

- **L3 tx** — one of {deposit, payment, withdraw}. A single user-level action.
- **L3 tx slot** — a fixed position inside a batch proof. Each sub-batch proof has exactly 8 slots. Real slots contain one tx's proof; remaining slots are filled with a padding proof. In these tests the harness supports only **1 real tx per sub-batch** (+ 7 padding); the circuits support more (see *Caveats* below).
- **Sub-batch** — one independent batch proof. Each sub-batch covers up to 8 L3 tx slots. `batch_app` (IVC) and `batch_app_standalone` (recursive) are both compiled at `MAX_BATCH_SIZE = 8`.
- **L2 tx** — one Aztec transaction submitted to the sandbox. Both designs bundle **2 sub-batches into 1 L2 tx**, giving 16 L3 tx slots of capacity per L2 tx.
- **Slot capacity** vs **real txs**: this repo's tests always exercise 16 slots but ship only 2 real txs + 14 padding (see *Caveats*). When we say "handle 16 tx", we mean 16 *slots* of capacity.

---

## Design A — IVC meta-batch (indicative benchmark — proof format mismatch)

> **Warning**: IVC tube proofs are 519-field `noir-rollup`. The contract ABI expects 500 fields. The SDK silently truncates. Results below are for proving-speed benchmarking only.

Two independent IVC pipelines produce two tube proofs. The L3 contract's `submit_two_batches` method verifies both proofs in one private-function invocation and enqueues two sequential `settle_batch` public calls.

```
                                                                         ┌─ tube proof₁ ──┐
sub-batch 1 (8 slots) ──► batch_app ──► IVC kernels ──► Chonk ──► tube ──►                │
                                                                         │                │    ┌─► settle_batch (batch=8)
                                                                         │ submit_two_    ├────┤
                                                                         │  batches       │    └─► settle_batch (batch=8)
                                                                         │ (L3 contract)  │
sub-batch 2 (8 slots) ──► batch_app ──► IVC kernels ──► Chonk ──► tube ──►                │    One Aztec L2 tx
                                                                         │                │    nonce += 2
                                                                         └─ tube proof₂ ──┘
```

**Total capacity per L2 tx**: **16 L3 tx slots** (= 2 sub-batches × 8 slots each).

**Circuits**: per-tx × 8 per sub-batch (× 2 sub-batches = 16 per-tx proofs total), `batch_app`, `init_kernel`, `tail_kernel`, `hiding_kernel`, Chonk (via `AztecClientBackend`), `tube`. Run once per sub-batch.

**Contract method** (`contract_ivc/src/main.nr`):
```noir
fn submit_two_batches(
    tube_vk, tube_vk_hash,
    tube_proof_1, public_inputs_1, nullifiers_1, note_hashes_1, deposits_1, withdrawals_1,
    tube_proof_2, public_inputs_2, nullifiers_2, note_hashes_2, deposits_2, withdrawals_2,
) {
    assert(tube_vk_hash == self.storage.tube_vk_hash.read(), "...");  // bind to committed VK
    verify_honk_proof(tube_vk, tube_proof_1, public_inputs_1, tube_vk_hash);
    verify_honk_proof(tube_vk, tube_proof_2, public_inputs_2, tube_vk_hash);
    assert(public_inputs_1[1] == public_inputs_2[0], "state chain");   // B.old == A.new
    // ... tree index chain checks ...
    self.enqueue_self.settle_batch(...sub-batch 1 data (batch=8 arrays)...);
    self.enqueue_self.settle_batch(...sub-batch 2 data (batch=8 arrays)...);
}
```

Two `verify_honk_proof` calls in the private circuit. Two `settle_batch` public calls in the same L2 tx.

---

## Design B — Recursive merged-proof (primary design — correct proof format)

Two independent recursive pipelines produce two wrapper proofs. The `wrapper_16` circuit recursively verifies both and emits one merged UltraHonk proof at `noir-recursive` target (500 fields, matching the contract's `UltraHonkZKProof` ABI). The L3 contract's `submit_batch_16` verifies that one proof and settles via `settle_batch_16` with batch=16 arrays.

```
                                                                               ┌─ wrapper proof₁ ─┐
sub-batch 1 (8 slots) ──► batch_app_standalone ──► wrapper[noir-recursive] ───►                  │
                                                                               │                  │
                                                                               │   wrapper_16   │ ──► 1 merged UltraHonk ──► submit_batch_16 ──► settle_batch_16 (batch=16)
                                                                               │                  │
sub-batch 2 (8 slots) ──► batch_app_standalone ──► wrapper[noir-recursive] ───►                  │    One Aztec L2 tx
                                                                               │                  │    nonce += 1
                                                                               └─ wrapper proof₂ ─┘
```

**Total capacity per L2 tx**: **16 L3 tx slots** (= 2 sub-batches × 8 slots each, aggregated into one merged batch).

**Circuits**: per-tx × 8 per sub-batch (× 2 sub-batches = 16 per-tx proofs total), `batch_app_standalone` × 2, `wrapper` × 2 (at `noir-recursive` target so they can be recursively verified), **`wrapper_16`** (new, 1×).

**New circuit** (`circuits/wrapper_16/src/main.nr`):
```noir
fn main(
    wrapper_vk, wrapper_vk_hash,
    wrapper_proof_a, wrapper_public_inputs_a,
    wrapper_proof_b, wrapper_public_inputs_b,
    // Re-fed settle-data arrays from both sub-batches so poseidon hashes match:
    nullifiers_a[16], note_hashes_a[16], deposits_a[8], withdrawals_a[8],
    nullifiers_b[16], note_hashes_b[16], deposits_b[8], withdrawals_b[8],
    // Merged BatchOutput public inputs (batch=16 shape):
    old_state_root: pub Field,          // = A.old
    new_state_root: pub Field,          // = B.new
    merged_nullifiers_hash: pub Field,  // poseidon2(concat(a, b)) over 32 fields
    merged_note_hashes_hash: pub Field, // concat over 32 fields
    merged_deposit_nullifiers_hash: pub Field,   // concat over 16 fields
    merged_withdrawal_claims_hash: pub Field,    // concat over 16 fields
    nullifier_tree_start_index: pub Field,  // = A.null_start
    note_hash_tree_start_index: pub Field,  // = A.nh_start
) {
    verify_honk_proof(wrapper_vk, wrapper_proof_a, wrapper_public_inputs_a, wrapper_vk_hash);
    verify_honk_proof(wrapper_vk, wrapper_proof_b, wrapper_public_inputs_b, wrapper_vk_hash);
    // + hash-consistency checks (re-fed arrays match each wrapper's committed hash)
    // + state-root chain (A.new == B.old)
    // + tree-index chain (B.null_start == A.null_start + A.null_count, etc.)
    // + build concatenated arrays and compute combined hashes
}
```

**Contract method** (`contract_recursive/src/main.nr`):
```noir
fn submit_batch_16(merged_vk, merged_proof, public_inputs[8], vk_hash_16,
                      nullifiers[32], note_hashes[32], deposits[16], withdrawals[16]) {
    assert(vk_hash_16 == self.storage.vk_hash_16.read(), "...");  // bind to committed VK
    verify_honk_proof(merged_vk, merged_proof, public_inputs, vk_hash_16);
    // ... count nonzeros ...
    self.enqueue_self.settle_batch_16(
        ..., nullifiers[32], note_hashes[32]  // batch=16-sized merged arrays
    );
}
```

One `verify_honk_proof` call in the private circuit. One `settle_batch_16` public call (batch=16 arrays: 32 nullifier slots, 32 note-hash slots, 16 deposit slots, 16 withdrawal slots).

The 2× wrapper verification work still happens — but it's amortized inside the client's `wrapper_16` prove rather than on the L2 tx's kernel circuit.

---

## Why this is NOT "IVC is 8 and Recursive is 16"

Both paths have **identical** slot capacity per L2 tx: **16**.

The difference is not capacity, it's proof topology:

| Layer | Design A (IVC) | Design B (Recursive) |
|---|---|---|
| L3 per-tx circuits | 16 (8 per sub-batch × 2) | 16 (8 per sub-batch × 2) |
| Sub-batch circuit size | `batch_app` at `MAX_BATCH_SIZE = 8` | `batch_app_standalone` at `MAX_BATCH_SIZE = 8` |
| Sub-batches per L2 tx | 2 | 2 |
| L2-posted proofs | 2 independent tube proofs | 1 merged UltraHonk proof (via wrapper_16) |
| L2-posted settle arrays | 2 × (16 nullifiers + 16 note-hashes + 8 deposits + 8 withdrawals) | 1 × (32 nullifiers + 32 note-hashes + 16 deposits + 16 withdrawals) |
| Total settle data on L2 | same bytes in both | same bytes in both |

The settle-data byte count is identical between the two designs — what differs is the **proof** byte count (1 vs 2 copies).

---

## Key correctness checks (shared by both designs)

1. **Proof integrity** — `verify_honk_proof(vk, proof, pub_inputs, vk_hash)` checks `hash(vk) == vk_hash` and proof validity.
2. **Circuit binding** — contract asserts `vk_hash == self.storage.*_vk_hash.read()`, where the storage slot is `PublicImmutable<Field>` set once at deployment. Blocks foreign-circuit proofs.
3. **State-root chain** — sub-batch 2's `old_state_root` == sub-batch 1's `new_state_root`.
4. **Tree-index chain** — sub-batch 2's start indices == sub-batch 1's start + its non-zero count.
5. **Atomicity** — both sub-batches land or neither does (Aztec tx semantics + in-circuit chain assertions).

---

## Reproducing the measurements

### Prerequisites

- **OS**: Linux, or Windows 11 with WSL2.
- **Memory**: ≥ 16 GiB RAM. For Design B concurrent sub-batch proving (optional, gives ~2× speedup), ≥ 24 GiB RAM.
- **Docker** (for the Aztec sandbox).
- **Node.js** (via `aztec-up` → nvm).
- **Aztec CLI toolchain**: `@aztec/aztec` v4.2.0-nightly.20260408 (pinned).

### One-time setup

**On Windows with WSL2:**

1. Configure WSL2 memory. Create `%USERPROFILE%\.wslconfig`:
   ```ini
   [wsl2]
   memory=16GB
   swap=16GB
   ```
   Then `wsl --shutdown` from a Windows shell to apply.

2. Install the Aztec toolchain inside WSL:
   ```bash
   bash -c "$(curl -fsSL https://install.aztec-labs.com/aztec-up)"
   aztec-up install 4.2.0-nightly.20260408
   ```

3. Add to `~/.bashrc` (or equivalent) so `aztec`, `nargo`, and `bb` are on PATH:
   ```bash
   . ~/.nvm/nvm.sh
   export PATH="$HOME/.aztec/current/bin:$HOME/.aztec/current/node_modules/.bin:$PATH"
   ```

**On native Linux**: same as steps 2 and 3.

### Clone and compile

```bash
git clone <this-repo>
cd <this-repo>

# Compile all circuits + both contracts, AVM-transpile, strip internal prefixes:
aztec compile --workspace --force

# Compile wrapper_16 as a standalone bin crate:
cd circuits/wrapper_16 && nargo compile && cd ../..
```

Expected `target/` artifacts (both paths share per-tx circuits):

| File | Used by |
|---|---|
| `l3_deposit.json`, `l3_payment.json`, `l3_withdraw.json`, `l3_padding.json` | Both designs (per-tx proofs) |
| `l3_batch_app.json` (MAX_BATCH_SIZE=8) | Design A only |
| `l3_init_kernel.json`, `l3_tail_kernel.json`, `l3_hiding_kernel.json`, `l3_tube.json` | Design A only |
| `l3_batch_app_standalone.json` (MAX_BATCH_SIZE=8) | Design B only |
| `l3_wrapper.json` | Design B only |
| `l3_wrapper_16.json` | Design B only |
| `l3_ivc_settlement-L3IvcSettlement.json` | Design A contract |
| `l3_recursive_settlement-L3RecursiveSettlement.json` | Design B contract |
| `token_contract-Token.json` | Both (L2 token the deposits transfer) |

### Run the Noir unit tests

```bash
cd contract_ivc && aztec test && cd ..
cd contract_recursive && aztec test && cd ..
```

Expected: 5/5 passing in each.

### Start the sandbox

```bash
cd tests
docker compose up -d
# Wait ~30 seconds, then sanity check:
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"node_getNodeInfo","params":[]}' \
  | grep nodeVersion
```

Should show `"nodeVersion":"4.2.0-nightly.20260408"`.

### Install test dependencies

```bash
cd tests
npm install
```

### Run the two e2e tests

**Design A — IVC meta-batch (16 slot capacity via submit_two_batches):**
```bash
cd tests
npx tsx step8-ivc-meta-16slot.ts
```

**Design B — Recursive merged-proof (16 slot capacity via wrapper_16 + submit_batch_16):**
```bash
cd tests
npx tsx step9-recursive-16slot.ts
```

For long runs under WSL, run detached and tail:
```bash
nohup npx tsx step8-ivc-meta-16slot.ts > /tmp/step8.log 2>&1 &
tail -f /tmp/step8.log
```

### Expected output

Each test prints a `=== SUMMARY ===` block at the end. Representative values (Windows 11 host, 16 GiB WSL):

**step8 (Design A, IVC meta-batch):**
```
  Sub-batches: 2 × (1 real + 7 padding) at batch=8  -> 16 slot capacity
  Per-tx proofs wall-clock: 328 ms
  Concurrent batch proving: 2.59 min
  L2 submit wall-clock:     5.7 s
  DA on L2 tx:              40512 bytes (1266 fields)
  On-chain nonce advance:   +2 (two settle_batch calls)
  Private verify cost:      2 × verify_honk_proof in kernel
  Public execution cost:    2 × settle_batch@batch=8 sequentially
```

**step9 (Design B, Recursive merged-proof):**
```
  Sub-batches: 2 × (1 real + 7 padding) at batch=8, aggregated -> 16 slot capacity
  Per-tx proofs:              401 ms
  Sub-batch A prove:          4.86 min
  Sub-batch B prove:          4.94 min
  Sub-batch total (seq):      9.80 min
  wrapper_16 prove:         53.5 s
  Total proving:              10.69 min
  L2 submit wall-clock:       5.9 s
  DA on L2 tx:                23648 bytes (739 fields)
  On-chain nonce advance:     +1 (one settle_batch_16 call)
  Private verify cost:        1 × verify_honk_proof(wrapper_16) in kernel
  Public execution cost:      1 × settle_batch_16@batch=16
  Final on-chain proof size:  16608 bytes (identical to wrapper)
```

Structured metrics are emitted to:
- `target/step8-metrics.json`
- `target/step9-metrics.json`

---

## Why the wall-clock numbers diverge

Both designs do the same ZK work: 16 per-tx UltraHonk proofs + 2 sub-batch proofs. Design B additionally runs `wrapper_16` (~1 min). So at a minimum, Design B is ≈ 1 min slower.

The larger delta comes from **concurrency limits under memory pressure**:

- Design A's sub-batch proving is **IVC/Chonk** (via `AztecClientBackend.prove`). Each sub-batch prove peaks ~4-5 GiB RSS. Two concurrent fit in 16 GiB — `Promise.all` gives near-linear speedup (~2× over sequential).
- Design B's sub-batch proving is **UltraHonk-to-UltraHonk** (`batch_app_standalone` + `wrapper`). Each sub-batch prove peaks ~7-9 GiB RSS. Two concurrent exceed 16 GiB and spill to swap — empirically this made two concurrent proves take **~19 min** vs ~9.8 min sequential, so step9 runs sub-batches **sequentially** to fit the 16 GiB budget.

If you run step9 on a host with ≥ 24 GiB RAM, you can re-enable concurrent sub-batch proving. Change this block in `step9-recursive-16slot.ts`:
```ts
const artifactA = await buildBatchProofRecursive(api, l3State, [depProofA]);
const artifactB = await buildBatchProofRecursive(api, l3StateB, [depProofB]);
```
to:
```ts
const apiB = await Barretenberg.new({ threads: 4 });
const [artifactA, artifactB] = await Promise.all([
  buildBatchProofRecursive(api,  l3State,  [depProofA]),
  buildBatchProofRecursive(apiB, l3StateB, [depProofB]),
]);
```

Expected projection with enough RAM: ≈ 5 min total proving (vs 10.7 min sequential).

---

## Why the DA numbers differ

Both designs post the same per-batch settle data; what differs is the **proof** material.

Breakdown of L2 function arguments:

| | Shared VK | Proofs | Pub inputs | Settle data | Total |
|---|---|---|---|---|---|
| Design A | 115 × 32 = 3,680 B | **2** × 519 × 32 = 33,216 B | 2 × 8 × 32 = 512 B | 2 × 48 × 32 = 3,072 B | **40,512 B** |
| Design B | 115 × 32 = 3,680 B | **1** × 500 × 32 = 16,000 B | 1 × 8 × 32 = 256 B | 1 × 96 × 32 = 3,072 B | **23,040 B** |

Design B saves one entire proof body plus IPA overhead on calldata (−17,472 B or −43%). The settle data (nullifiers, note-hashes, deposits, withdrawals) is the same total bytes in both: Design A posts 2 × (16+16+8+8) = 96 fields, Design B posts 1 × (32+32+16+16) = 96 fields. Design B's proof is also smaller (500 fields vs 519) because it uses `noir-recursive` target which omits IPA material.

The trade-off: you paid for `wrapper_16` proving (~1 min extra) to earn that DA reduction.

---

## Circuit-binding security (vk_hash)

Both contracts store VK hashes in **`PublicImmutable<Field>`** slots, initialized once in the constructor. Every submit method asserts the caller-supplied `vk_hash` equals the stored value *before* calling `verify_honk_proof`:

```noir
// contract_ivc, submit_batch and submit_two_batches:
assert(tube_vk_hash == self.storage.tube_vk_hash.read(), "...");
verify_honk_proof(tube_vk, tube_proof, public_inputs, tube_vk_hash);

// contract_recursive, submit_batch_16:
assert(vk_hash_16 == self.storage.vk_hash_16.read(), "...");
verify_honk_proof(merged_vk, merged_proof, public_inputs, vk_hash_16);
```

Without this binding, `verify_honk_proof` only enforces internal `vk`/`vk_hash` consistency. An attacker could submit a valid UltraHonk proof from any circuit paired with its matching hash. The `PublicImmutable` check rules that out — only proofs from the circuit committed at deployment are accepted.

---

## File map

| File | Role |
|---|---|
| `circuits/wrapper_16/{Nargo.toml,src/main.nr}` | Design B aggregator (verifies 2 UltraHonk wrapper proofs → 1 merged proof) |
| `circuits/pair_tube/{Nargo.toml,src/main.nr}` | Path C aggregator (verifies 2 RollupHonk tube proofs → 1 merged proof via `verify_rolluphonk_proof`) |
| `circuits/batch_app_standalone/src/main.nr` | Recursive sub-batch circuit (`MAX_BATCH_SIZE = 8`) |
| `circuits/wrapper/src/main.nr` | Verifies `batch_app_standalone`; verifier target selected at prove time |
| `circuits/batch_app/src/main.nr` | IVC sub-batch circuit (`MAX_BATCH_SIZE = 8`) |
| `circuits/{init,tail,hiding}_kernel/`, `circuits/tube/` | IVC kernels + rollup-target compressor |
| `contract_ivc/src/main.nr` | `L3IvcSettlement`: `submit_batch`, `submit_two_batches`, `submit_merged_batch` (Path C) |
| `contract_recursive/src/main.nr` | `L3RecursiveSettlement`: `submit_batch` (8-slot), `submit_batch_16`, `submit_batch_64` + matching settle helpers |
| `tests/harness/prover.ts` | IVC prover (`buildBatchProof`, `computeTubeVkHash`, `buildPairTubeProof`, `computePairTubeVkHash`) |
| `tests/harness/prover-recursive.ts` | Recursive prover (`buildBatchProofRecursive`, `buildWrapper16Proof`, `buildWrapper32Proof`, `buildWrapper64Proof`, `computeWrapper*VkHash`) |
| `tests/harness/state.ts` | `TestL3State` + shared batch sizings (both `IVC_BATCH_SIZING` and `RECURSIVE_BATCH_SIZING` at 8/16/16) |
| `tests/step8-ivc-meta-16slot.ts` | **Design A e2e test** |
| `tests/step9-recursive-16slot.ts` | **Design B e2e test** |
| `tests/step10-ivc-merged-16slot.ts` | **Path C e2e test** (IVC sub-batches + pair_tube RollupHonk aggregation) |
| `target/step8-metrics.json`, `target/step9-metrics.json`, `target/step10-metrics.json` | Metrics JSON written by each run |

---

## Caveats and honest limits

1. **1 real tx per sub-batch + 7 padding**. The tests use 16 slot capacity but ship 2 real + 14 padding (1 real per sub-batch). The prover harness generates per-tx proofs against a single state snapshot, which only works for the first tx in each batch. Multi-real-tx-per-batch needs intermediate state roots (a separate refactor — see `DESIGN_DECISIONS.md` and the skip note in `step4-full-lifecycle.ts`). The **circuits** already support multi-tx; the Noir unit tests in both contracts exercise it with synthetic state.

2. **Sandbox proof-verification gap**. Earlier drafts assumed the sandbox still enforced private-kernel `verify_honk_proof` calls. The newer probe suite (`step2-submit-batch-probe.ts`, plus the tail-corruption checks in `step4-full-lifecycle.ts`) shows that in the default sandbox mode (`PXE_PROVER=none`), corrupted or fabricated proofs can still be accepted, while plain Noir `assert` checks still fire. These e2e tests therefore validate contract logic and plumbing, not proof soundness.

3. **Proof format alignment varies by path**. Design B (recursive) produces 500-field `noir-recursive` proofs matching the contract's `UltraHonkZKProof` ABI — this is the only path with correct format alignment. Designs A and C produce 519-field `noir-rollup` proofs; the Aztec.js SDK silently truncates the excess 19 fields (IPA claim + IPA proof) during ABI encoding. When Aztec enables real proof verification, Design B should work correctly; Designs A and C will need Aztec platform changes (RollupHonk support in MegaBuilder, or IPA-free tube proving). See [`SILENT_FAILURE_REVIEW.md`](./SILENT_FAILURE_REVIEW.md).

4. **Gas-receipt surfacing**. The Aztec.js version in 4.2.0-nightly.20260408 doesn't expose `gasUsed` from `.send()`. Public execution cost is reasoned structurally (loop bounds in `settle_batch*`). Adding real gas figures is a drop-in follow-up via `node.getTxReceipt(txHash)`.

5. **Concurrent proving for Design B needs more RAM than shipped**. step9 runs sub-batches sequentially to fit 16 GiB. With ≥ 24 GiB RAM, concurrent sub-batch proving gives ~2× speedup (edit step9 per the section above).

6. **16 GiB WSL memory is required for step9**. Default WSL2 is ~50% of host RAM. Without the `.wslconfig` memory boost, `bb` OOMs during `batch_app_standalone` proving.

---

## Path C — IVC + pair_tube RollupHonk aggregation (indicative benchmark — proof format mismatch)

> **Warning**: Like Design A, this path produces 519-field `noir-rollup` proofs. The contract ABI expects 500 fields. The SDK silently truncates. The client-side `pair_tube` aggregation (using `verify_rolluphonk_proof` in a standalone circuit) is sound, but the contract-level verification is not. Results below are for benchmarking only.

A third approach that combines the fast IVC sub-batch proving (~4 GiB RAM per sub-batch, highly concurrent-friendly) with DA-efficient proof aggregation via a new `pair_tube` circuit.

```
sub-batch 1 (8 slots) ──► IVC pipeline ──► tube proof₁ [RollupHonk, 519 fields] ──┐
                                                                                    │
                                                                                    ├──► pair_tube ──► 1 merged RollupHonk proof
                                                                                    │                        │
sub-batch 2 (8 slots) ──► IVC pipeline ──► tube proof₂ [RollupHonk, 519 fields] ──┘                        ↓
                                                                                           submit_merged_batch (L3IvcSettlement)
                                                                                                        │
                                                                                           settle_batch_merged (batch=16)
                                                                                           One Aztec L2 tx, nonce += 1
```

### How it works

Tube proofs are RollupHonk proofs (519 fields) carrying IPA accumulation material from the Chonk compression step. Standard `verify_honk_proof` (which expects `noir-recursive` UltraHonk, 500 fields) cannot verify them — this was the initial blocker.

The solution uses `verify_rolluphonk_proof` from `bb_proof_verification`, which is designed for in-circuit verification of RollupHonk proofs (`PROOF_TYPE_ROLLUP_HONK = 4`). The `pair_tube` circuit is structurally identical to `wrapper_16` but uses the RollupHonk types:

| | `wrapper_16` (Design B) | `pair_tube` (Path C) |
|---|---|---|
| Verifier function | `verify_honk_proof` | `verify_rolluphonk_proof` |
| Proof type | `UltraHonkZKProof` (500 fields) | `RollupHonkProof` (519 fields) |
| VK type | `UltraHonkVerificationKey` (115 fields) | `RollupHonkVerificationKey` (115 fields) |
| Inner proofs | wrapper proofs (`noir-recursive`) | tube proofs (`noir-rollup`) |

### Three-way comparison at 16 slots

| | **Design A — IVC meta-batch** | **Design B — Recursive merged** | **Path C — IVC + pair_tube** |
|---|---|---|---|
| **Sub-batch proving** | ~2.6 min (concurrent IVC) | ~9.8 min (sequential recursive) | **~2.8 min** (concurrent IVC) |
| **Aggregation** | — | ~53 s wrapper_16 | **~65 s** pair_tube |
| **Total proving** | **~2.6 min** | ~10.7 min | **~3.9 min** |
| **L2 DA** | 40,512 B | **23,040 B** | **23,648 B** |
| **L2 proofs** | 2 (519 fields each) | 1 (500 fields) | 1 (519 fields) |
| **Proof format correct?** | No (519→500 truncation) | **Yes** (500 matches ABI) | No (519→500 truncation) |
| **Private verify** | 2 × verify_honk_proof | 1 × verify_honk_proof | **1 × verify_honk_proof** |
| **Public execution** | 2 × settle_batch@8 | 1 × settle_batch_16@16 | **1 × settle_batch_16@16** |
| **Nonce advance** | +2 | +1 | **+1** |
| **RAM per sub-batch** | ~4 GiB | ~8 GiB | **~4 GiB** |
| **2 concurrent @ 16 GiB** | yes | no (OOM) | **yes** |

Path C gets Design B's 42% DA reduction while proving ~2.7× faster (3.9 min vs 10.7 min at 16 GiB).

### Running the benchmark

```bash
cd tests
npx tsx step10-ivc-merged-16slot.ts   # Path C: IVC + pair_tube RollupHonk aggregation
```

Metrics are written to `target/step10-metrics.json`.

### Implementation details

- **New circuit**: `pair_tube` — uses `verify_rolluphonk_proof` / `RollupHonkProof` / `RollupHonkVerificationKey` from `bb_proof_verification`.
- **Contract**: `L3IvcSettlement` gains `submit_merged_batch` + `settle_batch_merged` + `merged_vk_hash` storage (structurally the same as the recursive contract's `submit_batch_16` path, but the IVC contract retains its original pre-rename method names).
- **Prover**: `buildPairTubeProof` and `computePairTubeVkHash` in `prover.ts`. Tube proofs stay at `noir-rollup` target (standard IVC output). pair_tube is proved at `noir-rollup` target for L2 submission.

### Note on the initial blocker

The first implementation attempt tried to verify tube proofs via `verify_honk_proof` (the UltraHonk recursive verifier), which failed in two ways:
1. `noir-recursive` tube proving: `"IPA proofs present when not expected"` — Chonk's IPA material is incompatible with the `noir-recursive` prover.
2. Wrapping `noir-rollup` tube proofs for UltraHonk recursive verification: field arithmetic mismatch (`remainder_1024.lo`) — `verify_honk_proof` expects the `noir-recursive` algebraic structure.

The fix was recognizing that `bb_proof_verification` provides `verify_rolluphonk_proof` specifically for in-circuit verification of `noir-rollup` (RollupHonk) proofs with IPA material.

---

## Where to go from here

- **Push sub-batch size**: `batch_app_standalone` compiles to batch=128 per `DESIGN_DECISIONS.md` §3. The ceiling is prover memory and wall-clock, not protocol. For IVC, the Chonk ECCVM 32,768-row ceiling limits batch=8 as the last known-good size — higher may not compile through the IVC/Chonk path.
- **Generalize aggregation**: Both `wrapper_16` and `pair_tube` extend to binary trees with level-specific variants for larger array sizes. Each extra tree level adds one aggregator prove (~60-65 s) and doubles the settle data. `pair_tube` also supports `quad_tube` (4-input) for flatter trees at larger scales.
- **Multi-real-tx prover**: refactor `buildBatchProof` / `buildBatchProofRecursive` to chain per-tx state roots so each sub-batch can hold 8 real txs. Combined with the current 2-sub-batch bundling, that gives **16 real txs per L2 tx**.
- **Measure L2 gas**: hook up `node.getTxReceipt(txHash)` to fill `daGas` / `l2Gas` / `publicGas` into the metrics JSON.
