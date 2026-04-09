# Aztec L3 Payment Rollup

A ZK payment rollup that settles on Aztec L2 with real proofs end-to-end.

## Architecture

```
User tx  -->  Per-tx proof (UltraHonk)
              |
              v
           batch_app (aggregates txs, validates Merkle insertions)
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

**Circuits** (Noir): deposit, payment, withdraw, padding, batch_app, 3 IVC kernels, tube

**Contract** (L3Settlement): deposit with authwit, batch settlement with proof verification, withdrawal claiming

**State**: indexed nullifier tree + append-only note hash tree (depth 20), roots committed to L2

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

The contract artifact also needs AVM transpilation and VK generation. This must be done inside the Aztec Docker container:

```sh
# Start sandbox first (see below), then:
docker exec -w /path/to/project tests-aztec-1 \
  /usr/src/barretenberg/cpp/build/bin/bb-avm aztec_process \
  -i target/l3_settlement-L3Settlement.json
```

Then strip the internal function name prefix:

```sh
node -e "
const fs = require('fs');
const p = 'target/l3_settlement-L3Settlement.json';
const a = JSON.parse(fs.readFileSync(p, 'utf8'));
for (const fn of a.functions) {
  if (fn.name.startsWith('__aztec_nr_internals__'))
    fn.name = fn.name.slice('__aztec_nr_internals__'.length);
}
fs.writeFileSync(p, JSON.stringify(a));
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
  types/          Shared types, constants, Merkle tree helpers
  deposit/        Binds L2 deposit to L3 note creation
  payment/        Private transfer between L3 accounts
  withdraw/       Burns L3 note, creates L2 withdrawal claim
  padding/        Fills unused batch slots (all-zero proof)
  batch_app/      Aggregates txs, validates tree insertions
  init_kernel/    IVC: verifies batch_app (OINK proof type)
  tail_kernel/    IVC: continues fold (HN_TAIL proof type)
  hiding_kernel/  IVC: final fold, exposes public output (HN_FINAL)
  tube/           Compresses Chonk proof to UltraHonk for L2 verification
contract/
  src/main.nr     L3Settlement contract (deposit, submit_batch, claim)
  src/test/       Noir unit tests (deploy, settle, lifecycle, withdrawal)
tests/
  harness/        TypeScript test infrastructure
    state.ts      L3 state management (Merkle trees, note tracking)
    prover.ts     Real proof generation + batch pipeline
    actions.ts    High-level test actions (deposit, payment, withdraw)
  step4-full-lifecycle.ts   Full e2e test with real proofs
```

## Known limitations

- **Batch size 4**: Reduced from 32 due to Chonk ECCVM circuit size limit (32768 rows). See comment in `circuits/types/src/lib.nr`.
- **Single-tx batches only**: The prover generates all tx proofs against one state snapshot. Multi-tx batches require intermediate state roots between proofs (prover refactoring needed). The circuit supports multi-tx; the contract Noir tests exercise it.
- **No sequencer/node**: The prover is a test harness, not a production node.
- **No forced exit**: If the operator stops, users cannot withdraw without a new operator.
- **Contract post-processing**: The `aztec-nargo compile` output needs AVM transpilation + function name stripping (see Compile section above).
