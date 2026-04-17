# Proof Verification Gap

> **Aztec version**: `v4.2.0-nightly.20260408`.
> **Scope**: all `submit_*` entry points on `L3RecursiveSettlement` and `L3IvcSettlement`.

Two independent issues affect on-chain proof verification on this Aztec version. One is a sandbox-layer limitation we cannot fix from this repo; the other was a proof-format mismatch that we closed at the circuit level on 2026-04-17.

---

## Problem 1: sandbox / TXE do not enforce `verify_honk_proof`

`PXE_PROVER=none` (the sandbox default) and the `aztec test` TestEnvironment share the same ACIR simulator. `verify_honk_proof` compiles to a `RecursiveAggregation` opcode that simulator treats as a no-op. Plain Noir `assert`s *are* enforced.

Empirically (via `tests/step2-submit-batch-probe.ts`):

```
submit_batch with all-zero proof          -> ACCEPTED
submit_batch with one flipped proof byte  -> ACCEPTED
submit_batch with wrong tube_vk_hash      -> REJECTED (Noir assert, not verify_honk_proof)
proof[519] via the SDK                    -> ACCEPTED (silently truncated to 500)
```

Soundness of a prove/verify pair is checked **out of band** via external `bb verify`, not via the sandbox. See:
- `tests/verify-with-bb-cli.ts` — positive verification of every aggregator level.
- `tests/verify-negative-tests.ts` — 7-case tamper matrix per level (proof / public inputs / VK × {swap, bit-flip}).

This is a platform limitation, not a repo bug. It will only close when Aztec enables real kernel proving locally.

## Problem 2: proof format mismatch (closed 2026-04-17)

Previously, both IVC paths (Design A raw tube, Path C with `pair_tube`) submitted **519-field `RollupHonk`** proofs to contracts whose ABI declared a **500-field `UltraHonkZKProof`**. The SDK silently truncated the 19 excess fields (IPA claim + IPA proof), discarding the data that would have carried soundness.

**Fix**: `pair_tube` now verifies its two input tube proofs under **`PROOF_TYPE_ROOT_ROLLUP_HONK`** (enum value 5 in barretenberg's `recursion_constraint.hpp`). That variant finalizes the accumulated IPA claims **natively in-circuit**, so `pair_tube`'s own proof carries no IPA material and is emitted at `noir-recursive` target as a clean 500-field `UltraHonkZKProof`. The barretenberg invariant `is_root_rollup => nested_ipa_claims == 2` matches `pair_tube`'s 2-tube topology by construction.

The proof-type constant isn't exposed as a helper in `bb_proof_verification` at this Aztec tag, so `pair_tube` calls `std::verify_proof_with_type` directly.

**Empirical confirmation** (step10, 2026-04-17):

- `pair_tube` proof: **500 fields / 16,000 bytes** (log: `Generated proof for circuit with 8 public inputs and 500 fields`).
- In-circuit verify: `pair_tube verified: true`.
- `submit_merged_batch`: nonce advanced to 1, root updated. No SDK truncation.

Design A (raw tube submission in `contract_ivc.submit_batch`) is not affected by this fix and is still format-broken. Closing it would require applying the same `ROOT_ROLLUP_HONK` wrapping to its submission path.

## Inner-VK chain binding (2026-04-15 hardening)

Each aggregator (`wrapper_16/32/64`) now publishes the VK hash(es) of the proofs it recursively verified as extra public inputs. `submit_batch_16` / `submit_batch_64` assert the full chain against immutable contract-storage slots:

```
tube_vk_hash -> vk_hash_16 -> vk_hash_32 -> vk_hash_64
```

This closes the inner-VK substitution class **conditional on** the proof gate being enforced. Under the sandbox/TXE no-op (Problem 1), the chain-binding asserts still fire (they are plain Noir asserts), which is why `probe-chain-binding-64.ts` can exercise them locally.

## Current path status

| Path | Client-side proving | On-wire format | Contract verification | Status |
|---|---|---|---|---|
| **Path B — Recursive** (`submit_batch_16/64`) | Sound | 500-field `noir-recursive` UltraHonkZK | No-op locally (Problem 1) | Format-ready |
| **Path C — IVC + `pair_tube`** (`submit_merged_batch`) | Sound | 500-field `noir-recursive` UltraHonkZK | No-op locally (Problem 1) | Format-ready (2026-04-17) |
| **Design A — IVC raw tube** (`contract_ivc.submit_batch`) | Sound | 519-field, SDK-truncated | No-op locally (Problem 1) | Format-broken |

When Aztec enables real proof enforcement in the private kernel, Path B and Path C will both verify without further changes.

## Files involved

| File | Role |
|---|---|
| `circuits/pair_tube/src/main.nr` | Uses `std::verify_proof_with_type(.., PROOF_TYPE_ROOT_ROLLUP_HONK=5)` to finalize IPA in-circuit; emits 500-field output |
| `circuits/wrapper_16/{32,64}/src/main.nr` | Recursive aggregators; publish inner VK hash(es) for chain binding |
| `contract_recursive/src/main.nr` | Uses `verify_honk_proof` with 500-field `UltraHonkZKProof`; chain-binding asserts |
| `contract_ivc/src/main.nr` | Same ABI; `submit_merged_batch` consumes Path C's 500-field output |
| `tests/step2-submit-batch-probe.ts` | Probes that confirm Problem 1 |
| `tests/verify-{with-bb-cli,negative-tests}.ts` | External bb-verify soundness signal |
