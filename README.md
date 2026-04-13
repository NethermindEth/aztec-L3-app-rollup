# Aztec L3 Payment Rollup

A ZK payment rollup that settles on Aztec L2 with real proofs end-to-end.

Two fully separate proving pipelines ship in this repo. They share the per-tx
circuits and the shared state model, but diverge at the batch-aggregation step,
compile to different Noir artifacts, and deploy to different contracts.

## Pipelines

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

Batch size is capped at 8 by the Chonk ECCVM 32768-row limit.

### Recursive pipeline (batch size 16, contract: `L3RecursiveSettlement`)

```
User tx  -->  Per-tx proof (UltraHonk)
              |
              v
           batch_app_standalone  (aggregates up to 16 txs; explicit pub inputs, no databus)
              |
              v
           wrapper  (verifies batch_app_standalone UltraHonk proof)
              |
              v
           L2 contract: submit_batch() verifies wrapper proof, settles state
```

No IVC kernels, no Chonk, no AztecClientBackend. Scales linearly — batch size is
bounded by proving time / memory, not by a hard protocol limit. See
`DESIGN_DECISIONS.md` §3.

**Shared circuits** (Noir): deposit, payment, withdraw, padding

**Shared state**: indexed nullifier tree + append-only note hash tree (depth 20),
roots committed to L2

## Prerequisites

- Docker (for the Aztec sandbox)
- Node.js 20+ (for running tests)
- `aztec-nargo` (for compiling circuits — install via `aztec-up`)

All pinned to `aztec v4.2.0-nightly.20260408`.

## Compile

Compile all circuits and the contract:

```sh
aztec-nargo compile
```

Each contract artifact also needs AVM transpilation and VK generation. Do this
inside the Aztec Docker container for whichever contract(s) you're using:

```sh
# Start sandbox first (see below), then:

# IVC contract:
docker exec -w /path/to/project tests-aztec-1 \
  /usr/src/barretenberg/cpp/build/bin/bb-avm aztec_process \
  -i target/l3_ivc_settlement-L3IvcSettlement.json

# Recursive contract:
docker exec -w /path/to/project tests-aztec-1 \
  /usr/src/barretenberg/cpp/build/bin/bb-avm aztec_process \
  -i target/l3_recursive_settlement-L3RecursiveSettlement.json
```

Then strip the internal function name prefix for whichever artifact(s) you built:

```sh
node -e "
const fs = require('fs');
for (const p of [
  'target/l3_ivc_settlement-L3IvcSettlement.json',
  'target/l3_recursive_settlement-L3RecursiveSettlement.json',
]) {
  if (!fs.existsSync(p)) continue;
  const a = JSON.parse(fs.readFileSync(p, 'utf8'));
  for (const fn of a.functions) {
    if (fn.name.startsWith('__aztec_nr_internals__'))
      fn.name = fn.name.slice('__aztec_nr_internals__'.length);
  }
  fs.writeFileSync(p, JSON.stringify(a));
}
"
```

## Run tests

### 1. Start the sandbox

```sh
cd tests
docker compose up -d
```

Wait ~30s for the Aztec node to initialize. Verify with:

```sh
curl -s http://localhost:8080/api/status
```

### 2. Install dependencies

```sh
cd tests
npm install
```

### 3. Run the full e2e test

```sh
npm run e2e
```

This runs `step4-full-lifecycle.ts`, which takes ~5-7 minutes and exercises:

| Step | What it tests |
|------|---------------|
| 1 | Deploy Token + L3Settlement with real tube VK hash |
| 2 | Real `deposit()` with authwit + private token transfer |
| 3 | Payment (Alice -> Bob) with real proofs |
| 4 | Withdrawal (Bob) with real proofs |
| 5 | `claim_withdrawal()` on L2, assert balance changed |
| 6 | Double-claim rejection |
| 7 | Change notes: partial payment (500 -> 300 + 200 change) |
| 8 | Two-input spend: consume 2 notes in one tx |
| 9 | Multi-tx batch (skipped, needs prover refactoring) |
| 10 | Corrupt proof rejection (sandbox verifies proofs) |

Every batch generates real ZK proofs through the full pipeline: per-tx UltraHonk -> batch_app -> IVC kernels -> Chonk -> tube.

### Individual step tests

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

  # Recursive pipeline (batch size 16)
  batch_app_standalone/  Aggregates 16 txs, explicit pub outputs (no databus)
  wrapper/               Verifies batch_app_standalone UltraHonk proof for L2

contract_ivc/            L3IvcSettlement (batch size 8), Noir unit tests
contract_recursive/      L3RecursiveSettlement (batch size 16), Noir unit tests

tests/
  harness/
    state.ts                       Shared state model, parameterized batch sizing
    prover.ts                      IVC prover (batch 8)
    prover-recursive.ts            Recursive prover (batch 16)
    actions.ts                     High-level IVC test actions
  step0-3*, step4-full-lifecycle.ts    IVC e2e tests
  step5-recursive-poc.ts               Recursive e2e test
  bench-recursive-20tx.ts,
  bench-recursive-100tx.ts             Recursive throughput benchmarks
```

## Known limitations

- **IVC batch size 8**: Capped by the Chonk ECCVM 32768-row limit. See
  `circuits/batch_app/src/main.nr` comment.
- **Recursive batch size 16**: No protocol-level bound; chosen to give prover
  time/memory headroom. Can be raised in `circuits/batch_app_standalone/src/main.nr`.
- **Single-tx batches in current bench runs**: The prover generates all tx
  proofs against one state snapshot. Multi-tx batches require intermediate
  state roots between proofs (prover refactoring needed). Both batch circuits
  support multi-tx; the Noir contract tests exercise it.
- **No sequencer/node**: The prover is a test harness, not a production node.
- **No forced exit**: If the operator stops, users cannot withdraw without a
  new operator.
- **Contract post-processing**: The `aztec-nargo compile` output needs AVM
  transpilation + function name stripping for both contracts (see Compile
  section above).
