# Batching-of-Batches on Aztec L3

> Two ways to settle multiple L3 state transitions in one L2 transaction, with measurements.

This doc explains two proof designs that let a single Aztec L2 transaction commit to more L3 activity than a single batch proof would cover. Both ship as end-to-end tests (`step8-*` and `step9-*`) that you can run yourself to reproduce the measurements in the table below.

---

## TL;DR

Two ways to settle 16 L3 slots (two sub-batches of 8) in **one L2 tx**:

| | **Design A — IVC meta-batch** | **Design B — Recursive merged-proof** |
|---|---|---|
| How it works | L2 tx carries **two independent** tube proofs (one per sub-batch). Contract verifies both and settles twice in the same tx. | A new `pair_wrapper` circuit recursively verifies both wrapper proofs and produces **one** merged UltraHonk proof. Contract verifies once and settles once. |
| Proofs on L2 | 2 × 16,608 bytes | 1 × 16,608 bytes |
| Nonce advance | +2 | +1 |
| DA (calldata args) | **40,512 bytes** | **23,648 bytes** |
| Client proving (concurrent) | ≈ 2.6 min | ≈ 5.2 min (needs >16 GiB RAM) / 10.7 min (sequential, fits 16 GiB) |
| Private kernel verify cost | 2 × `verify_honk_proof` | 1 × `verify_honk_proof` |
| Public execution | 2 × `settle_batch` @ batch=8 | 1 × `settle_batch_merged` @ batch=16 |
| New circuits needed | 0 | 1 (`pair_wrapper`) |
| On-chain proof size (invariant) | 16,608 bytes | 16,608 bytes |

**Rule of thumb**: meta-batch is simpler and faster to prove; merged-proof is smaller DA and cheaper kernel verify at the cost of an extra aggregator prove.

---

## The two designs

### Design A — IVC meta-batch

Two independent IVC pipelines produce two tube proofs. The L3 contract's `submit_two_batches` method verifies both proofs in the same private-function invocation and enqueues two sequential `settle_batch` public calls.

```
                                                                         ┌─ tube proof₁ ──┐
sub-batch 1 ──► batch_app ──► IVC kernels ──► Chonk ──► tube ───────────►│                │
(8 tx slots)                                                             │                │    ┌─ settle_batch (batch=8)
                                                                         │ submit_two_    ├───►│
                                                                         │  batches       │    └─ settle_batch (batch=8)
                                                                         │ (L3 contract)  │
sub-batch 2 ──► batch_app ──► IVC kernels ──► Chonk ──► tube ───────────►│                │    Aztec L2 tx (one)
(8 tx slots)                                                             │                │    nonce += 2
                                                                         └─ tube proof₂ ──┘
```

**Circuits**: per-tx × 8, `batch_app`, `init_kernel`, `tail_kernel`, `hiding_kernel`, Chonk (via `AztecClientBackend`), `tube`. Same set as single-batch IVC — just run twice in parallel.

**Contract method** (`contract_ivc/src/main.nr`):
```noir
fn submit_two_batches(
    tube_vk, tube_vk_hash,
    tube_proof_1, public_inputs_1, nullifiers_1, note_hashes_1, deposits_1, withdrawals_1,
    tube_proof_2, public_inputs_2, nullifiers_2, note_hashes_2, deposits_2, withdrawals_2,
) {
    assert(tube_vk_hash == self.storage.tube_vk_hash.read(), "...");
    verify_honk_proof(tube_vk, tube_proof_1, public_inputs_1, tube_vk_hash);
    verify_honk_proof(tube_vk, tube_proof_2, public_inputs_2, tube_vk_hash);
    assert(public_inputs_1[1] == public_inputs_2[0], "state chain");
    // ... tree index chain checks ...
    self.enqueue_self.settle_batch(...batch 1...);
    self.enqueue_self.settle_batch(...batch 2...);
}
```

Two `verify_honk_proof` calls in the private circuit. Two `settle_batch` public calls in the same L2 tx.

### Design B — Recursive merged-proof

Two independent recursive pipelines produce two wrapper proofs. A new `pair_wrapper` circuit recursively verifies both and emits one merged UltraHonk proof, which the L3 contract's `submit_merged_batch` verifies once and settles via `settle_batch_merged` with batch=16 arrays.

```
                                                                         ┌─ wrapper proof₁ ─┐
sub-batch 1 ──► batch_app_standalone ──► wrapper[noir-recursive] ───────►│                  │
(8 tx slots)                                                             │                  │
                                                                         │   pair_wrapper   │
                                                                         │                  │ ──► 1 merged UltraHonk proof ──► submit_merged_batch ──► settle_batch_merged (batch=16)
                                                                         │                  │
sub-batch 2 ──► batch_app_standalone ──► wrapper[noir-recursive] ───────►│                  │    Aztec L2 tx (one)
(8 tx slots)                                                             │                  │    nonce += 1
                                                                         └─ wrapper proof₂ ─┘
```

**Circuits**: per-tx × 8, `batch_app_standalone`, `wrapper` × 2 (at `noir-recursive` target so they can be recursively verified), **`pair_wrapper`** (new). No IVC kernels, no Chonk.

**New circuit** (`circuits/pair_wrapper/src/main.nr`):
```noir
fn main(
    wrapper_vk, wrapper_vk_hash,
    wrapper_proof_a, wrapper_public_inputs_a,
    wrapper_proof_b, wrapper_public_inputs_b,
    // Re-fed settle data arrays from both sub-batches (for combined hashing):
    nullifiers_a, note_hashes_a, deposits_a, withdrawals_a,
    nullifiers_b, note_hashes_b, deposits_b, withdrawals_b,
    // Merged BatchOutput public inputs (batch=16 shape):
    old_state_root: pub Field,          // = A.old
    new_state_root: pub Field,          // = B.new
    merged_nullifiers_hash: pub Field,  // poseidon2(concat(a, b))
    merged_note_hashes_hash: pub Field,
    merged_deposit_nullifiers_hash: pub Field,
    merged_withdrawal_claims_hash: pub Field,
    nullifier_tree_start_index: pub Field,  // = A.null_start
    note_hash_tree_start_index: pub Field,  // = A.nh_start
) {
    verify_honk_proof(wrapper_vk, wrapper_proof_a, wrapper_public_inputs_a, wrapper_vk_hash);
    verify_honk_proof(wrapper_vk, wrapper_proof_b, wrapper_public_inputs_b, wrapper_vk_hash);
    // + hash-consistency, state-root chain, tree-index chain checks
    // + build merged arrays and compute combined hashes
}
```

**Contract method** (`contract_recursive/src/main.nr`):
```noir
fn submit_merged_batch(merged_vk, merged_proof, public_inputs, merged_vk_hash, ...) {
    assert(merged_vk_hash == self.storage.merged_vk_hash.read(), "...");
    verify_honk_proof(merged_vk, merged_proof, public_inputs, merged_vk_hash);
    // count nonzeros, then
    self.enqueue_self.settle_batch_merged(...);  // single public call, batch=16 arrays
}
```

One `verify_honk_proof` call in the private circuit (the expensive 2× wrapper verification work happens inside `pair_wrapper` at proving time, not in the L2 tx's kernel circuit). One `settle_batch_merged` public call.

### Key correctness checks in both designs

Both designs enforce:

1. **Proof integrity** — `verify_honk_proof` checks internal `vk` / `vk_hash` consistency and proof validity against public inputs.
2. **Circuit binding** — contract asserts the supplied `vk_hash` equals the **`PublicImmutable`** slot committed at deployment. Proofs from foreign circuits are rejected.
3. **State-root chain** — sub-batch 2's `old_state_root` must equal sub-batch 1's `new_state_root`.
4. **Tree-index chain** — sub-batch 2's nullifier/note-hash start indices must equal sub-batch 1's start + its non-zero count.
5. **Atomicity** — both sub-batches land or neither does (Aztec tx semantics + the chain-assert in the private fn / pair_wrapper).

---

## Reproducing the measurements

### Prerequisites

- **OS**: Linux, or Windows 11 with WSL2.
- **Memory**: ≥ 16 GiB RAM. For Design B concurrent proving (not used in the shipped step9), ≥ 24 GiB RAM.
- **Docker** (for the Aztec sandbox).
- **Node.js** (provided by `aztec-up`, via nvm).
- **Aztec CLI toolchain**: `@aztec/aztec` v4.2.0-nightly.20260408 (pinned by the repo).

### One-time setup

**On Windows with WSL2:**

1. Configure WSL2 memory. Create or edit `%USERPROFILE%\.wslconfig`:
   ```ini
   [wsl2]
   memory=16GB
   swap=16GB
   ```
   Then run `wsl --shutdown` from a Windows shell to apply.

2. Install the Aztec toolchain inside WSL:
   ```bash
   # Install the aztec-up version manager:
   bash -c "$(curl -fsSL https://install.aztec-labs.com/aztec-up)"

   # Install the pinned version:
   aztec-up install 4.2.0-nightly.20260408
   ```

   This pulls node via nvm, nargo, foundry, and the aztec npm packages into `~/.aztec/`.

3. Add to your shell profile the PATH setup that makes `aztec`, `nargo`, and `bb` reachable:
   ```bash
   . ~/.nvm/nvm.sh
   export PATH="$HOME/.aztec/current/bin:$HOME/.aztec/current/node_modules/.bin:$PATH"
   ```

**On native Linux**: same as step 2+3 above (skip the `.wslconfig` step).

### Clone and compile

```bash
git clone <this-repo>
cd <this-repo>

# Compile all circuits + both contracts, AVM-transpile, strip internal prefixes:
aztec compile --workspace --force

# Compile pair_wrapper as a standalone circuit (nargo handles it directly):
cd circuits/pair_wrapper && nargo compile && cd ../..
```

Expected `target/` contents:
- `l3_batch_app.json`, `l3_init_kernel.json`, `l3_tail_kernel.json`, `l3_hiding_kernel.json`, `l3_tube.json` — IVC circuits
- `l3_batch_app_standalone.json`, `l3_wrapper.json`, `l3_pair_wrapper.json` — recursive circuits
- `l3_deposit.json`, `l3_payment.json`, `l3_withdraw.json`, `l3_padding.json` — per-tx circuits
- `l3_ivc_settlement-L3IvcSettlement.json`, `l3_recursive_settlement-L3RecursiveSettlement.json` — contracts
- `token_contract-Token.json` — Token contract (pulled from aztec-packages deps)

### Run the Noir unit tests

Before running the e2e tests, sanity-check that both contracts' Noir unit tests pass:

```bash
cd contract_ivc && aztec test && cd ..
cd contract_recursive && aztec test && cd ..
```

Expected: 5/5 passing in each, covering deploy, deposit+immediate-withdraw, full lifecycle, double-claim rejection, state-root-chain rejection.

### Start the sandbox

The Aztec sandbox is an L2 node + Anvil L1 node running in Docker.

```bash
cd tests
docker compose up -d
# Wait ~30 seconds for the sandbox to initialize.
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"node_getNodeInfo","params":[]}' \
  | grep nodeVersion
```

Should print a line with `"nodeVersion":"4.2.0-nightly.20260408"`.

### Install test dependencies

```bash
cd tests
npm install
```

### Run the tests

**Design A — IVC meta-batch (step8):**
```bash
cd tests
npx tsx step8-ivc-meta-16slot.ts
```

**Design B — Recursive merged-proof (step9):**
```bash
cd tests
npx tsx step9-recursive-merged-16slot.ts
```

Each test takes several minutes. They deploy fresh contracts, register 2 L2→L3 deposits, build the proofs, submit via the respective method, and verify the on-chain state advanced correctly.

For long-running tests under WSL, it's useful to run detached and tail the log:

```bash
cd tests
nohup npx tsx step8-ivc-meta-16slot.ts > /tmp/step8.log 2>&1 &
tail -f /tmp/step8.log
```

### Expected output

Both tests print a `=== SUMMARY ===` block at the end. Representative values (measured on a Windows 11 host with 16 GiB WSL allocation):

**step8 (IVC meta-batch):**
```
  Per-tx proofs wall-clock: 328 ms
  Concurrent batch proving: 2.59 min
  L2 submit wall-clock:     5.7 s
  DA on L2 tx:              40512 bytes (1266 fields)
  On-chain nonce advance:   +2 (two settle_batch calls)
  Private verify cost:      2 × verify_honk_proof in kernel
  Public execution cost:    2 × settle_batch@batch=8 sequentially
```

**step9 (Recursive merged-proof):**
```
  Per-tx proofs:              401 ms
  Sub-batch A prove:          4.86 min
  Sub-batch B prove:          4.94 min
  Sub-batch total (seq):      9.80 min
  pair_wrapper prove:         53.5 s
  Total proving:              10.69 min
  L2 submit wall-clock:       5.9 s
  DA on L2 tx:                23648 bytes (739 fields)
  On-chain nonce advance:     +1 (one settle_batch_merged call)
  Private verify cost:        1 × verify_honk_proof(pair_wrapper) in kernel
  Public execution cost:      1 × settle_batch_merged@batch=16
  Final on-chain proof size:  16608 bytes (identical to wrapper)
```

Both tests also write a structured metrics JSON to:
- `target/step8-metrics.json`
- `target/step9-metrics.json`

---

## Why the wall-clock numbers diverge

Design A's sub-batch proving is **IVC/Chonk** (via `AztecClientBackend.prove`). At batch=8 each sub-batch prove peaks ~4-5 GiB RSS. Two concurrent fit in 16 GiB, so `Promise.all` gives near-linear speedup.

Design B's sub-batch proving is **UltraHonk-to-UltraHonk recursion** (batch_app_standalone + wrapper). Each sub-batch prove peaks ~7-9 GiB RSS. Two concurrent exceed 16 GiB and spill to swap — in practice this made them take **~19 min** (tested once, then reverted). So step9 runs sub-batches **sequentially**, which doubles the linear-time cost but is still faster than the swap-thrashed concurrent path.

If you run step9 on a host with ≥24 GiB RAM, you can re-enable concurrent sub-batch proving by replacing the sequential block in `step9-recursive-merged-16slot.ts` with a `Promise.all` using a second `Barretenberg` instance. Expected projection: ~5 min total proving (vs 10.7 min sequential).

---

## Why the DA numbers differ

Both designs post the same per-batch settle data (nullifiers, note-hashes, deposit-nullifiers, withdrawal-claims) — so settle data scales identically with slot count.

The difference is **proof material**:

| | Shared VK | Proofs | Pub inputs | Settle data | Total |
|---|---|---|---|---|---|
| Design A | 115 × 32 = 3,680 B | **2** × 519 × 32 = 33,216 B | 2 × 8 × 32 = 512 B | 2 × 48 × 32 = 3,072 B | **40,512 B** |
| Design B | 115 × 32 = 3,680 B | **1** × 519 × 32 = 16,608 B | 1 × 8 × 32 = 256 B | 1 × 96 × 32 = 3,072 B | **23,648 B** |

Design B saves one entire proof body on calldata (~16,864 bytes or **-42%**). The trade-off: you paid for `pair_wrapper` proving (~1 min) to earn that DA reduction.

---

## Circuit-binding security (vk_hash)

Both contracts store VK hashes in **`PublicImmutable<Field>`** slots, initialized once in the constructor. Every submit method asserts the caller-supplied `vk_hash` matches the stored value before invoking `verify_honk_proof`:

```noir
// contract_ivc — submit_batch and submit_two_batches:
assert(
    tube_vk_hash == self.storage.tube_vk_hash.read(),
    "submit_*: tube_vk_hash does not match contract's committed hash",
);
verify_honk_proof(tube_vk, tube_proof, public_inputs, tube_vk_hash);
```

Without this check, `verify_honk_proof` only enforces internal consistency between the passed `vk` and its hash. A malicious caller could otherwise submit any valid UltraHonk proof from any circuit paired with its own matching hash. The `PublicImmutable` binding rules out foreign-circuit proofs at L2.

---

## File map

| File | Purpose |
|---|---|
| `circuits/pair_wrapper/{Nargo.toml,src/main.nr}` | **New**: aggregator circuit, verifies 2 wrappers → 1 merged proof. |
| `circuits/batch_app_standalone/src/main.nr` | Recursive-path batch circuit (`MAX_BATCH_SIZE = 8`). |
| `circuits/wrapper/src/main.nr` | Verifies `batch_app_standalone` proof; target chosen at prove time. |
| `circuits/batch_app/src/main.nr` | IVC-path batch circuit (`MAX_BATCH_SIZE = 8`). |
| `circuits/{init,tail,hiding}_kernel`, `circuits/tube` | IVC kernels + rollup-target compressor. |
| `contract_ivc/src/main.nr` | `L3IvcSettlement`: `submit_batch`, `submit_two_batches`. |
| `contract_recursive/src/main.nr` | `L3RecursiveSettlement`: `submit_batch`, **new** `submit_merged_batch`, `settle_batch_merged`. |
| `tests/harness/prover.ts` | IVC pipeline prover (`buildBatchProof`, `computeTubeVkHash`). |
| `tests/harness/prover-recursive.ts` | Recursive pipeline prover (`buildBatchProofRecursive`, **new** `buildPairWrapperProof`, **new** `computePairWrapperVkHash`). |
| `tests/harness/state.ts` | Shared `TestL3State` (trees, notes, state root) + batch sizings. |
| `tests/step8-ivc-meta-16slot.ts` | **Design A e2e test**. |
| `tests/step9-recursive-merged-16slot.ts` | **Design B e2e test**. |
| `target/step8-metrics.json`, `target/step9-metrics.json` | Metrics emitted by each run. |

---

## Caveats and honest limits

1. **1 real tx per sub-batch, 7 padding.** The tests use 16 slot capacity = 2 real + 14 padding, matching the current prover harness. It generates all tx proofs against a single state snapshot, which only works for the first tx in each batch. Multi-real-tx batches require intermediate state roots between per-tx proofs — a separate refactor (see `DESIGN_DECISIONS.md` and the skip note in `step4-full-lifecycle.ts` step 9). The circuits themselves support multi-tx; the Noir unit tests in both contracts exercise it with synthetic state.

2. **Sandbox `realProofs: false`**. The Aztec sandbox disables the outer **rollup proof** (the one over a whole L2 block). It does NOT disable private-kernel proof verification, which is what enforces the `verify_honk_proof` calls inside submit methods. Proof check coverage was confirmed experimentally by the step4 corrupt-proof probe, which the sandbox correctly rejects.

3. **Gas-receipt surfacing**. The Aztec.js version shipped with 4.2.0-nightly.20260408 doesn't expose a receipt-with-gasUsed from `.send()`. Public execution cost is reasoned structurally (loop bounds in `settle_batch*`) rather than measured. Adding real gas figures is a drop-in follow-up via `node.getTxReceipt(txHash)`.

4. **Concurrent recursive proving needs more RAM than shipped**. The step9 uses sequential sub-batch proving because concurrent exceeded the 16 GiB WSL budget and spilled to swap. A host with ≥24 GiB RAM can enable concurrent proving for an approximate 2× speedup.

5. **16 GiB WSL memory is a hard requirement for step9**. Default WSL2 is ~50% of host RAM. On low-RAM hosts, either set `.wslconfig` as documented or step9's `bb` worker will OOM during `batch_app_standalone` proving.

---

## Where to go from here

- **Push batch size**: batch_app_standalone compiles to batch=128 per the ACIR-opcode table in `DESIGN_DECISIONS.md` §3. The ceiling is prover memory and wall-clock, not protocol. For IVC, batch=8 was tested end-to-end but batch sizes above that hit the Chonk ECCVM 32,768-row ceiling.
- **Generalize aggregation**: `pair_wrapper` trivially extends to a binary tree (`pair_wrapper(pair_wrapper(w1,w2), pair_wrapper(w3,w4))` → batch=32, etc.) with no new circuits, just more layer-2 invocations. Each extra layer adds one `pair_wrapper` prove (~1 min) and doubles the underlying settle data.
- **Multi-real-tx prover**: refactor `buildBatchProof` / `buildBatchProofRecursive` to generate per-tx proofs against intermediate state roots, unlocking higher real throughput per batch.
- **Measure L2 gas**: hook up `node.getTxReceipt(txHash)` to populate `daGas` / `l2Gas` / `publicGas` into the metrics JSON.
