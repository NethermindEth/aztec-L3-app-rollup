# Aztec L3 Payment Rollup

A ZK payment rollup that settles on Aztec L2 with real proofs end-to-end.

**Both proving pipelines in this repo process the same batch size:**

- Each batch proof covers up to **8 L3 tx slots** (`MAX_BATCH_SIZE = 8`).
- Two pipelines differ in **how** those 8 slots get proven and compressed into a single L2-verifiable proof.
- For handling more txs per L2 transaction (16 slot capacity via 2 sub-batches × 8), see [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md).

## Two pipelines, identical batch size

Both pipelines share the per-tx circuits (deposit / payment / withdraw / padding) and the state model (indexed nullifier tree + append-only note-hash tree, depth 20). They diverge at the batch-aggregation step, compile to different Noir artifacts, and deploy to different contracts.

### IVC pipeline (batch size 8, contract: `L3IvcSettlement`)

```
User tx  -->  Per-tx proof (UltraHonk)
              |
              v
           batch_app  (aggregates up to 8 txs, validates Merkle insertions)
              |
              v
           IVC kernel chain (init -> tail -> hiding)
              |
              v
           Chonk proof (AztecClientBackend)
              |
              v
           Tube proof (UltraHonk, rollup-targeted)
              |
              v
           L2 contract: submit_batch() verifies tube proof, settles state
```

Batch size is **capped at 8** by the Chonk ECCVM 32,768-row limit.

### Recursive pipeline (batch size 8, contract: `L3RecursiveSettlement`)

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

No IVC kernels, no Chonk, no `AztecClientBackend`. The circuit compiles linearly up to batch=128 per `DESIGN_DECISIONS.md` §3; batch=8 is the current shipped setting to keep dev-loop proving times reasonable and allow concurrent sub-batch proving within a 16 GiB WSL memory budget (see `BATCHING_OF_BATCHES.md`).

### Shared

- **Per-tx circuits**: deposit, payment, withdraw, padding — identical for both pipelines.
- **State model**: indexed nullifier tree + append-only note-hash tree (depth 20), roots committed to L2.

## Going bigger than 8 per L2 tx

Both pipelines support combining **two 8-slot sub-batches into one L2 transaction** (16 slot capacity per L2 tx):

- **IVC meta-batch** (`submit_two_batches`): two independent tube proofs verified in one L2 tx, two `settle_batch` calls. No new circuit.
- **Recursive merged-proof** (`submit_merged_batch` + `pair_wrapper`): a new aggregator circuit recursively verifies two wrapper proofs → one merged UltraHonk proof, one `settle_batch_merged` call.

End-to-end tests for both:

```sh
npx tsx tests/step8-ivc-meta-16slot.ts       # IVC meta-batch (Design A)
npx tsx tests/step9-recursive-merged-16slot.ts  # Recursive merged-proof (Design B)
```

See [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md) for architecture diagrams, reproduction steps, and side-by-side cost comparison.

## Prerequisites

- Docker (for the Aztec sandbox).
- Node.js 20+ (provided by `aztec-up` via nvm).
- Aztec toolchain (`aztec`, `nargo`, `bb`), installed via `aztec-up`.

All pinned to `aztec v4.2.0-nightly.20260408`.

### WSL users (Windows)

All commands below run inside WSL. Memory matters: the recursive pipeline's proving peaks at ~8 GiB; `batching-of-batches` step9 needs ≥ 16 GiB WSL budget. Set `%USERPROFILE%\.wslconfig`:

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

# pair_wrapper is a standalone bin crate (not a contract):
cd circuits/pair_wrapper && nargo compile && cd ../..
```

Expected `target/` contents:

| File | Pipeline |
|---|---|
| `l3_deposit.json`, `l3_payment.json`, `l3_withdraw.json`, `l3_padding.json` | Shared (per-tx) |
| `l3_batch_app.json`, `l3_init_kernel.json`, `l3_tail_kernel.json`, `l3_hiding_kernel.json`, `l3_tube.json` | IVC |
| `l3_batch_app_standalone.json`, `l3_wrapper.json`, `l3_pair_wrapper.json` | Recursive |
| `l3_ivc_settlement-L3IvcSettlement.json` | IVC contract |
| `l3_recursive_settlement-L3RecursiveSettlement.json` | Recursive contract |
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
cd contract_ivc && aztec test && cd ..
cd contract_recursive && aztec test && cd ..
```

5/5 passing expected in each.

**IVC single-batch e2e** (step4) — full lifecycle at batch=8, exercises the IVC pipeline through deposit / payment / withdraw / claim / corrupt-proof rejection:

```sh
cd tests
npm run e2e   # runs step4-full-lifecycle.ts
```

| Step | What it tests |
|------|---------------|
| 1 | Deploy Token + `L3IvcSettlement` with real tube VK hash |
| 2 | Real `deposit()` with authwit + private token transfer |
| 3 | Payment (Alice -> Bob) with real proofs |
| 4 | Withdrawal (Bob) with real proofs |
| 5 | `claim_withdrawal()` on L2, balance changed |
| 6 | Double-claim rejection |
| 7 | Change notes (partial payment with change) |
| 8 | Two-input spend (consume 2 notes in one tx) |
| 9 | Multi-tx batch (skipped — see *Known limitations*) |
| 10 | Corrupt-proof rejection (sandbox performs real proof verification) |

Takes ~8-12 minutes.

**Recursive single-batch e2e** (step5):

```sh
cd tests
npx tsx step5-recursive-poc.ts
```

**Batching-of-batches e2e** (step8 / step9) — 16 slot capacity per L2 tx:

```sh
cd tests
npx tsx step8-ivc-meta-16slot.ts       # Design A: IVC meta-batch
npx tsx step9-recursive-merged-16slot.ts  # Design B: Recursive merged-proof
```

See [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md) for expected numbers and full cost comparison.

### Other step tests

```sh
npm run step0   # Private token mint + transfer (sandbox plumbing)
npm run step1   # Real deposit() with authwit
npm run step2   # Proof verification probe (does sandbox verify?)
npm run step3   # submit_batch with valid public inputs
```

### Stop the sandbox

```sh
cd tests
docker compose down -v
```

## Project structure

```
circuits/
  types/                 Shared types, Merkle helpers (no batch-size constants)
  deposit/               Binds L2 deposit to L3 note creation (shared)
  payment/               Private transfer between L3 accounts (shared)
  withdraw/              Burns L3 note, creates L2 withdrawal claim (shared)
  padding/               Fills unused batch slots, all-zero proof (shared)

  # IVC pipeline (batch size 8)
  batch_app/             Aggregates 8 txs, validates tree insertions, IVC-threaded output
  init_kernel/           IVC: verifies batch_app (OINK proof type)
  tail_kernel/           IVC: continues fold (HN_TAIL proof type)
  hiding_kernel/         IVC: final fold, exposes public output (HN_FINAL)
  tube/                  Compresses Chonk proof to UltraHonk for L2 verification

  # Recursive pipeline (batch size 8)
  batch_app_standalone/  Aggregates 8 txs, explicit pub outputs (no databus)
  wrapper/               Verifies batch_app_standalone UltraHonk proof for L2
  pair_wrapper/          Aggregates 2 wrapper proofs -> 1 merged UltraHonk proof
                         (used by the recursive merged-proof e2e test)

contract_ivc/            L3IvcSettlement (batch size 8), Noir unit tests
                         Methods: submit_batch, submit_two_batches
contract_recursive/      L3RecursiveSettlement (batch size 8), Noir unit tests
                         Methods: submit_batch, submit_merged_batch, settle_batch_merged

tests/
  harness/
    state.ts                         Shared state model, parameterized batch sizing
    prover.ts                        IVC prover (buildBatchProof, computeTubeVkHash)
    prover-recursive.ts              Recursive prover (buildBatchProofRecursive,
                                     buildPairWrapperProof, computePairWrapperVkHash)
    actions.ts                       High-level IVC test actions
  step0-3*, step4-full-lifecycle.ts     IVC e2e tests (single-batch)
  step5-recursive-poc.ts                Recursive e2e test (single-batch)
  step8-ivc-meta-16slot.ts              Design A: IVC meta-batch (see BATCHING_OF_BATCHES.md)
  step9-recursive-merged-16slot.ts      Design B: Recursive merged-proof
  bench-recursive-20tx.ts,
  bench-recursive-100tx.ts              Recursive throughput benchmarks
```

## Known limitations

- **Batch size is 8 in both pipelines.**
  - **IVC** is capped by the Chonk ECCVM 32,768-row limit.
  - **Recursive** has no protocol cap but is kept at 8 so sub-batch proving stays around 4 GiB/prover — small enough that two sub-batches can prove concurrently within a 16 GiB WSL memory budget (the basis for `BATCHING_OF_BATCHES.md` Design A). Can be raised by editing `circuits/batch_app_standalone/src/main.nr` if you have more RAM.
- **1 real tx per sub-batch in the harness.** The current prover harness generates all tx proofs against a single state snapshot — so each batch carries 1 real tx + 7 padding. The circuits themselves support multi-tx (exercised in the Noir unit tests with synthetic state); a prover-side refactor to chain intermediate state roots between per-tx proofs is future work.
- **No sequencer/node.** The prover is a test harness, not a production node.
- **No forced exit.** If the operator stops, users cannot withdraw without a new operator.
- **Contract post-processing.** `aztec compile --workspace` handles AVM transpilation and function-name-prefix stripping in one pass (replacing the legacy `aztec-nargo compile` + separate `bb-avm aztec_process` + prefix-strip script flow).

## Further reading

- [`BATCHING_OF_BATCHES.md`](./BATCHING_OF_BATCHES.md) — two ways to settle 16 slot capacity in one L2 tx: IVC meta-batch vs recursive merged-proof, with architecture, reproduction, and side-by-side cost comparison.
- [`BATCHING_SCALING.md`](./BATCHING_SCALING.md) — extrapolation to 32-slot and 128-slot targets. Three approaches (A: IVC meta-batch, B1: small sub-batches + quad aggregator, B2: binary pair_wrapper tree), with DA / mana / RAM tradeoffs and implementation roadmaps.
- [`DESIGN_DECISIONS.md`](./DESIGN_DECISIONS.md) — DA minimization, the single-batch IVC vs recursive decision, sizing rationale.
