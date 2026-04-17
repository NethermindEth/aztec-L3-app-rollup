# Aztec L3 Payment Rollup

A ZK payment rollup that settles on Aztec L2 with real proofs. Two aggregation paths both terminate at a 500-field `UltraHonkZKProof` matching the contract ABI:

- **Path B (primary)** — pure recursive UltraHonk: `batch_app_standalone` → `wrapper` → `wrapper_16/32/64`. See `step9-recursive-16slot.ts`.
- **Path C (secondary)** — IVC per-tx + `pair_tube` root-rollup aggregation (2026-04-17). See `step10-ivc-merged-16slot.ts`.

Both paths were validated end-to-end against a live Aztec sandbox; the recursive tree additionally passes external `bb verify` at every level (see `VALIDATION_64_SLOT.md`).

> **Sandbox testing caveat.** The Aztec sandbox (`PXE_PROVER=none`) and `aztec test` TXE do not enforce `verify_honk_proof` — the opcode is a no-op during ACIR simulation. E2e tests validate prover correctness, contract state machine, and ABI plumbing, but not on-chain gate soundness. Local soundness signal is external `bb verify`. Plain Noir asserts (inner-VK chain binding, state-root chain) *are* enforced. See `SILENT_FAILURE_REVIEW.md`.

> **Benchmarks are from a 16 GiB WSL host.** Both paths trade RAM for swap at batch=16; wall-clock figures are indicative, not targets. Architectural conclusions (which path pays where) are robust; absolute numbers will shift meaningfully with ≥ 24 GiB.

## Architecture

Per-tx circuits (`deposit` / `payment` / `withdraw` / `padding`) and the state model (indexed nullifier tree + append-only note-hash tree, both depth 20) are shared across both paths.

```
User tx  ->  per-tx proof (UltraHonk)
             |
             v   Path B                                Path C
           batch_app_standalone                      batch_app -> IVC kernels -> tube
             |                                               |
           wrapper                                         (tube proof, 519-field)
             |                                               |
           wrapper_16        <--- aggregator --->          pair_tube  (ROOT_ROLLUP_HONK,
             |                                               |        finalizes IPA in-circuit)
             v                                               v
         submit_batch_16                            submit_merged_batch
         (L3RecursiveSettlement)                    (L3IvcSettlement)
```

Both `submit_*` entry points consume a 500-field `UltraHonkZKProof`. Inner-VK chain binding is enforced at every aggregator level.

Details: `AGGREGATION.md` (design comparison), `SCALING.md` (tree shape to 64/128), `DESIGN_DECISIONS.md` (DA minimization, IVC vs recursive rationale), `SILENT_FAILURE_REVIEW.md` (proof-verification gap analysis).

## Prerequisites

- Docker (sandbox).
- Node.js 20+ (via `aztec-up` / nvm).
- Aztec toolchain (`aztec`, `nargo`, `bb`), pinned to `v4.2.0-nightly.20260408`.

### WSL memory

Set `%USERPROFILE%\.wslconfig`:

```ini
[wsl2]
memory=16GB
swap=16GB
```

(≥ 24 GB recommended for Path C aggregator and concurrent recursive leaves.) Apply with `wsl --shutdown`.

### Toolchain

```sh
bash -c "$(curl -fsSL https://install.aztec-labs.com/aztec-up)"
aztec-up install 4.2.0-nightly.20260408
. ~/.nvm/nvm.sh
export PATH="$HOME/.aztec/current/bin:$HOME/.aztec/current/node_modules/.bin:$PATH"
```

## Build

```sh
aztec compile --workspace --force
# Standalone bin crates (not contracts):
cd circuits/wrapper_16 && nargo compile && cd ../..
cd circuits/wrapper_32 && nargo compile && cd ../..
cd circuits/wrapper_64 && nargo compile && cd ../..
cd circuits/pair_tube  && nargo compile && cd ../..
```

## Run

Sandbox up:

```sh
cd tests
docker compose up -d
npm install
```

Noir unit tests:

```sh
cd contract_recursive && aztec test && cd ..   # 15/15
cd contract_ivc       && aztec test && cd ..   # 5/5
```

End-to-end (pick one):

```sh
cd tests
npx tsx step5-recursive-poc.ts          # Path B single-batch (8 slots)
npx tsx step9-recursive-16slot.ts       # Path B merged (16 slots)  *** primary ***
npx tsx step11-recursive-64slot.ts      # Path B aggregated (64 slots)
npx tsx step10-ivc-merged-16slot.ts     # Path C IVC + pair_tube (16 slots)
npx tsx step8-ivc-meta-16slot.ts        # Design A (benchmark only, format-broken)
```

Soundness via external `bb verify`:

```sh
npm run verify:recursive               # wrapper + wrapper_16 bb-verify
INCLUDE_64=1 npm run verify:recursive:64   # + wrapper_32 + wrapper_64
npm run verify:recursive:negative      # 28-case tamper matrix
npm run probe:chain:64                 # contract-side chain-binding probe
```

Sandbox down:

```sh
docker compose down -v
```

## Project layout

```
circuits/
  # Shared per-tx
  types/ deposit/ payment/ withdraw/ padding/

  # Path B (primary)
  batch_app_standalone/      Aggregates 8 txs, pub outputs (no databus)
  wrapper/                   Verifies batch_app_standalone proof
  wrapper_16/ wrapper_32/ wrapper_64/
                             Binary-tree aggregators (constant-size)

  # Path C + IVC plumbing
  batch_app/                 IVC-threaded batch (databus)
  init_kernel/ tail_kernel/ hiding_kernel/  IVC kernel chain
  tube/                      Chonk -> UltraHonk compression
  pair_tube/                 Aggregates 2 tube proofs (ROOT_ROLLUP_HONK,
                             finalizes IPA in-circuit, 500-field output)

contract_recursive/          L3RecursiveSettlement
                             submit_batch (8), submit_batch_16, submit_batch_64
                             Immutable VK-hash chain: tube_vk_hash, vk_hash_16, vk_hash_32, vk_hash_64

contract_ivc/                L3IvcSettlement
                             submit_batch (Design A), submit_two_batches, submit_merged_batch (Path C)

tests/
  harness/                   Shared state, prover (IVC + recursive), recursive-shapes
  step5 / step9 / step11     Path B e2e
  step10                     Path C e2e
  step8                      Design A e2e (benchmark only)
  step2-submit-batch-probe   Sandbox no-op diagnostic
  verify-*                   External bb-verify + tamper matrix
  probe-*                    Chain-binding probes
```

## Known limitations

- **Sandbox proof gate is a no-op** (Problem 1 in `SILENT_FAILURE_REVIEW.md`). Soundness must be asserted out-of-band via `bb verify`.
- **Design A is format-broken.** Raw tube submission in `contract_ivc.submit_batch` still posts a 519-field proof that the SDK silently truncates to 500. Unblocking it would need the same `ROOT_ROLLUP_HONK` wrapping `pair_tube` uses.
- **Batch size is 8 per sub-batch.** Chonk ECCVM caps IVC at 8; recursive has no protocol cap (see `DESIGN_DECISIONS.md` §3). Current setting is a memory choice.
- **Harness proves 1 real tx per sub-batch.** Circuits support multi-tx (covered by Noir unit tests); the prover harness would need refactoring to chain intermediate state roots.
- **No sequencer / no forced exit.** The prover is a test harness, not a production node. If the operator stops, users cannot withdraw without a new operator.
