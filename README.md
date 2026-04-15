# Aztec L3 Payment Rollup

A ZK payment rollup that settles on Aztec L2 with real proofs. The **recursive pipeline** is the primary proving path — it produces correctly-formatted proofs for on-chain verification. An IVC pipeline is also implemented for benchmarking but has an unresolved proof format mismatch (see [IVC pipeline status](#ivc-pipeline-status) below).

> **Sandbox testing limitation.** The Aztec sandbox (`PXE_PROVER=none`) does not enforce `verify_honk_proof` calls in contract private functions — the opcode is a no-op during ACIR simulation. E2e tests validate contract logic and proof plumbing, but not proof soundness. The recursive pipeline has correct proof format alignment (500-field `noir-recursive` proofs matching the `UltraHonkZKProof` ABI), so verification should be sound once Aztec enables real proving. See [`SILENT_FAILURE_REVIEW.md`](./SILENT_FAILURE_REVIEW.md) for details.

## Architecture

The recursive pipeline processes batches of up to **8 L3 tx slots** per sub-batch. Per-tx circuits (deposit / payment / withdraw / padding) are shared with the IVC pipeline. The state model uses an indexed nullifier tree + append-only note-hash tree (depth 20).

```
User tx  -->  Per-tx proof (UltraHonk)
              |
              v
           batch_app_standalone  (aggregates up to 8 txs; explicit pub inputs, no databus)
              |
              v
           wrapper  (verifies batch_app_standalone UltraHonk proof)
              |
              v
           L2 contract: submit_batch() verifies wrapper proof, settles state
```

Contract: `L3RecursiveSettlement`. No IVC kernels, no Chonk, no `AztecClientBackend`. The circuit compiles linearly up to batch=128 per `DESIGN_DECISIONS.md` §3; batch=8 is the current setting to keep proving times reasonable within a 16 GiB memory budget.

All proofs are generated at `noir-recursive` target, producing 500-field `UltraHonkZKProof`s that match the contract ABI.

## Batching: 16 slots per L2 tx

Two sub-batches of 8 can be aggregated into a single L2 transaction via `wrapper_16`:

```
sub-batch 1 (8 slots) --> batch_app_standalone --> wrapper [noir-recursive] --+
                                                                              |
                                                                              +--> wrapper_16 --> 1 merged proof [noir-recursive]
                                                                              |                           |
sub-batch 2 (8 slots) --> batch_app_standalone --> wrapper [noir-recursive] --+                           v
                                                                                          submit_batch_16 (L3RecursiveSettlement)
                                                                                                          |
                                                                                          settle_batch_16 (batch=16)
                                                                                          One Aztec L2 tx, nonce += 1
```

- **1 merged proof** on L2 (16,000 bytes, 500 fields)
- **23,040 bytes DA** (43% less than posting 2 separate proofs)
- **1 `settle_batch_16` call** (nonce += 1)

End-to-end test:

```sh
npx tsx tests/step9-recursive-16slot.ts
```

See [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md) for architecture, reproduction steps, and measurements. See [`BATCHING_SCALING.md`](./BATCHING_SCALING.md) for extrapolation to 32 and 128 slots.

## Prerequisites

- Docker (for the Aztec sandbox).
- Node.js 20+ (provided by `aztec-up` via nvm).
- Aztec toolchain (`aztec`, `nargo`, `bb`), installed via `aztec-up`.

All pinned to `aztec v4.2.0-nightly.20260408`.

### WSL users (Windows)

All commands below run inside WSL. Memory matters: the recursive pipeline's proving peaks at ~8 GiB; batching step9 needs ≥ 16 GiB WSL budget. Set `%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
memory=16GB
swap=16GB
```

Apply with `wsl --shutdown` from a Windows shell.

### Install the toolchain

```sh
# Inside WSL (or native Linux):
bash -c "$(curl -fsSL https://install.aztec-labs.com/aztec-up)"
aztec-up install 4.2.0-nightly.20260408
```

Add to your shell profile:

```sh
. ~/.nvm/nvm.sh
export PATH="$HOME/.aztec/current/bin:$HOME/.aztec/current/node_modules/.bin:$PATH"
```

## Compile

```sh
# From repo root — compiles all circuits + both contracts, AVM-transpiles,
# and strips internal function-name prefixes:
aztec compile --workspace --force

# wrapper_16 and pair_tube are standalone bin crates (not contracts):
cd circuits/wrapper_16 && nargo compile && cd ../..
cd circuits/pair_tube && nargo compile && cd ../..
```

Expected `target/` contents:

| File | Pipeline |
|---|---|
| `l3_deposit.json`, `l3_payment.json`, `l3_withdraw.json`, `l3_padding.json` | Shared (per-tx) |
| `l3_batch_app_standalone.json`, `l3_wrapper.json` | Recursive per-sub-batch (8-slot) |
| `l3_wrapper_16.json`, `l3_wrapper_32.json`, `l3_wrapper_64.json` | Recursive aggregators (16 / 32 / 64 slots) |
| `l3_batch_app.json`, `l3_init_kernel.json`, `l3_tail_kernel.json`, `l3_hiding_kernel.json`, `l3_tube.json` | IVC (benchmark only) |
| `l3_pair_tube.json` | IVC + RollupHonk aggregation (benchmark only) |
| `l3_recursive_settlement-L3RecursiveSettlement.json` | Recursive contract |
| `l3_ivc_settlement-L3IvcSettlement.json` | IVC contract (benchmark only) |
| `token_contract-Token.json` | Token (L2 dep) |

## Run tests

### 1. Start the sandbox

```sh
cd tests
docker compose up -d
# Wait ~30s, then verify:
curl -s -X POST http://localhost:8080/ \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"node_getNodeInfo","params":[]}' \
  | grep nodeVersion
```

### 2. Install test dependencies

```sh
cd tests
npm install
```

### 3. Run the tests you care about

**Noir unit tests** (per contract):

```sh
cd contract_recursive && aztec test && cd ..
cd contract_ivc && aztec test && cd ..       # IVC contract (benchmark only)
```

Expected counts: **15/15** in `contract_recursive` (5 lifecycle + 5 16-slot + 5 64-slot state-machine tests), **5/5** in `contract_ivc`.

**Recursive single-batch e2e** (step5):

```sh
cd tests
npx tsx step5-recursive-poc.ts
```

**Recursive merged-proof e2e** (step9) — 16 slot capacity per L2 tx:

```sh
cd tests
npx tsx step9-recursive-16slot.ts
```

See [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md) for expected numbers and full cost comparison.

**Proof verification probes** — diagnostic tests for sandbox behavior:

```sh
npm run step2   # Shape-boundary probe: confirms verify_honk_proof is a no-op
```

### Other step tests

```sh
npm run step0   # Private token mint + transfer (sandbox plumbing)
npm run step1   # Real deposit() with authwit
npm run step3   # submit_batch with valid public inputs
```

### Stop the sandbox

```sh
cd tests
docker compose down -v
```

## IVC pipeline status

> **The IVC pipeline has an unresolved proof format mismatch.** Tube proofs are 519-field `noir-rollup` (RollupHonk with IPA material). The contract ABI declares 500-field `UltraHonkZKProof`. The Aztec.js SDK silently truncates the excess 19 fields. This affects all IVC-based paths (Design A, Path C). See [`SILENT_FAILURE_REVIEW.md`](./SILENT_FAILURE_REVIEW.md).

The IVC pipeline was built to benchmark against the recursive pipeline. It shares the same per-tx circuits and state model but uses a different aggregation path:

```
batch_app --> IVC kernel chain (init -> tail -> hiding) --> Chonk --> tube
```

Batch size is capped at 8 by the Chonk ECCVM 32,768-row limit. The tube proof cannot be generated at `noir-recursive` target (IPA material from Chonk prevents it), and `verify_rolluphonk_proof` is not supported in Aztec contract private functions (MegaBuilder limitation).

**IVC benchmark tests** (proof format mismatch — results are indicative, not production-valid):

```sh
npx tsx tests/step4-full-lifecycle.ts          # IVC single-batch lifecycle
npx tsx tests/step8-ivc-meta-16slot.ts         # Design A: 2 tube proofs, 2 settles
npx tsx tests/step10-ivc-merged-16slot.ts      # Path C: pair_tube RollupHonk aggregation
```

These tests validate the IVC proving pipeline and contract logic, but on-chain proof verification is not enforced due to the format mismatch. The client-side proving (including pair_tube's `verify_rolluphonk_proof` in standalone circuits) is sound.

## Project structure

```
circuits/
  types/                 Shared types, Merkle helpers (no batch-size constants)
  deposit/               Binds L2 deposit to L3 note creation (shared)
  payment/               Private transfer between L3 accounts (shared)
  withdraw/              Burns L3 note, creates L2 withdrawal claim (shared)
  padding/               Fills unused batch slots, all-zero proof (shared)

  # Recursive pipeline (primary)
  batch_app_standalone/  Aggregates 8 txs, explicit pub outputs (no databus)
  wrapper/               Verifies batch_app_standalone UltraHonk proof (8-slot)
  wrapper_16/            Aggregates 2 wrapper proofs  -> 16-slot merged proof
  wrapper_32/            Aggregates 2 wrapper_16 proofs -> 32-slot (intermediate)
  wrapper_64/            Aggregates 2 wrapper_32 proofs -> 64-slot merged proof

  # IVC pipeline (benchmark only — proof format mismatch, see above)
  batch_app/             Aggregates 8 txs, IVC-threaded output (databus)
  init_kernel/           IVC: verifies batch_app (OINK proof type)
  tail_kernel/           IVC: continues fold (HN_TAIL proof type)
  hiding_kernel/         IVC: final fold, exposes public output (HN_FINAL)
  tube/                  Compresses Chonk proof to UltraHonk
  pair_tube/             Aggregates 2 RollupHonk tube proofs via verify_rolluphonk_proof

contract_recursive/      L3RecursiveSettlement — primary contract
                         Methods: submit_batch (8-slot), submit_batch_16, submit_batch_64
                                  + matching settle_batch / settle_batch_16 / settle_batch_64
                         Immutable VK hashes: tube_vk_hash, vk_hash_16, vk_hash_32, vk_hash_64
contract_ivc/            L3IvcSettlement — benchmark only (method names retained pre-rename)
                         Methods: submit_batch, submit_two_batches, submit_merged_batch

tests/
  harness/
    state.ts                         Shared state model, parameterized batch sizing
    prover.ts                        IVC prover (buildBatchProof, buildPairTubeProof)
    prover-recursive.ts              Recursive prover (buildBatchProofRecursive,
                                     buildWrapper16Proof / Wrapper32Proof / Wrapper64Proof,
                                     computeWrapper*VkHash)
    recursive-shapes.ts              Recursive-path shape constants + boundary
                                     assertRecursiveSubmitShape()
    actions.ts                       High-level IVC test actions
  step5-recursive-poc.ts                Recursive e2e test (8-slot, single-batch)
  step9-recursive-16slot.ts             Recursive merged-proof (16 slots)
  step11-recursive-64slot.ts            Recursive aggregated-proof (64 slots)
  step4-full-lifecycle.ts               IVC e2e (benchmark only)
  step8-ivc-meta-16slot.ts              IVC meta-batch (benchmark only)
  step10-ivc-merged-16slot.ts           IVC + pair_tube (benchmark only)
  verify-with-bb-cli.ts                 External bb-CLI verification, positive + artifact dump
  verify-negative-tests.ts              Tamper matrix across all recursive levels
  probe-chain-binding-64.ts             Contract-side inner-VK chain-binding probe (64-slot)
  probe-recursive-target.ts             Diagnostic: noir-recursive proof format validation
  step2-submit-batch-probe.ts           Proof verification diagnostic probes
```

## Known limitations

- **Proof gate is a no-op locally.** `verify_honk_proof` is not enforced in either `PXE_PROVER=none` sandbox runs or TestEnvironment (`aztec test`) — both use the same ACIR simulator. This applies to every `submit_*` entry point: `submit_batch`, `submit_batch_16`, `submit_batch_64`. Sandbox e2e tests (step5/step9/step11) validate prover correctness + contract state machine + ABI plumbing, but **not** on-chain gate soundness. Local soundness for each aggregation level is covered via external `bb verify`:
    - `npm run verify:recursive` — wrapper (8-slot) + wrapper_16 (16-slot) artifacts + positive bb verify.
    - `INCLUDE_64=1 npm run verify:recursive:64` — adds wrapper_32 (32-slot) + wrapper_64 (64-slot).
    - `npm run verify:recursive:negative` — validates artifact freshness against current circuit VKs, then runs the 7-case tamper matrix (baseline + 6 rejections) for **each** level present in the manifest (wrapper, wrapper_16, and — when the quad scope is present — wrapper_32 and wrapper_64).

  **Inner-VK chain binding** is enforced at every aggregator level: `wrapper_16` / `wrapper_32` / `wrapper_64` each publish the VK hash(es) of the proofs they recursively verified, and `submit_batch_16` / `submit_batch_64` assert those against immutable contract-storage commitments. This closes the inner-VK substitution attack class for both the 16-slot and 64-slot paths. See [`SILENT_FAILURE_REVIEW.md`](./SILENT_FAILURE_REVIEW.md) for the hardening note.
- **IVC proof format mismatch.** Tube proofs are 519-field `noir-rollup`; contracts expect 500-field `UltraHonkZKProof`. The recursive pipeline does not have this issue.
- **Batch size is 8.** IVC is capped by Chonk ECCVM. Recursive has no protocol cap but is kept at 8 for memory budget reasons.
- **1 real tx per sub-batch in the harness.** The circuits support multi-tx (tested in Noir unit tests); the prover harness needs a refactor to chain intermediate state roots.
- **No sequencer/node.** The prover is a test harness, not a production node.
- **No forced exit.** If the operator stops, users cannot withdraw without a new operator.

## Further reading

- [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md) — 16-slot batching: recursive merged-proof architecture, IVC benchmarks (indicative), reproduction steps, and cost comparison.
- [`BATCHING_SCALING.md`](./BATCHING_SCALING.md) — extrapolation to 32 and 128 slots.
- [`DESIGN_DECISIONS.md`](./DESIGN_DECISIONS.md) — DA minimization, IVC vs recursive rationale, sizing decisions.
- [`SILENT_FAILURE_REVIEW.md`](./SILENT_FAILURE_REVIEW.md) — proof verification gap analysis with empirical evidence.
