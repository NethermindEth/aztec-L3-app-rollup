use super::utils::{
    TestL3, BATCH_64_SIZE, BATCH_64_NULLIFIERS_COUNT, BATCH_64_NOTE_HASHES_COUNT,
};
use aztec::oracle::random::random;

// Contract-side tests for the 64-slot (wrapper_64-aggregated) entry points:
//   - submit_batch_64  (private, proof-gated -- bypassed in unit tests)
//   - settle_batch_64  (public, only_self)
//
// IMPORTANT: TXE ACIR simulation treats verify_honk_proof as a no-op, so
// the proof gate on submit_batch_64 cannot be exercised here. These tests
// cover only the state-machine side (settle_batch_64): stale-root detection,
// four-quarter pending-deposit consumption, withdrawal-claim registration
// across quarters, and single-nonce advancement per 64-slot settle.
// Soundness of the 64-slot aggregation itself is validated externally via
// `bb verify` -- see tests/verify-with-bb-cli.ts and SILENT_FAILURE_REVIEW.md.
//
// State-root chaining and tree-index advancement across the 8 underlying
// sub-batches are proof-side invariants enforced inside wrapper_16,
// wrapper_32, and wrapper_64; they are not retested here.

// --------------------------------------------------------------------------
// settle_64_advances_nonce_exactly_once
// --------------------------------------------------------------------------

#[test]
unconstrained fn settle_64_advances_nonce_exactly_once() {
    let mut l3 = TestL3::setup();

    // One nonzero nullifier + note hash per quarter (positions 0, 32, 64, 96).
    let mut nullifiers = [0 as Field; BATCH_64_NULLIFIERS_COUNT];
    let mut note_hashes = [0 as Field; BATCH_64_NOTE_HASHES_COUNT];
    for q in 0..4 {
        nullifiers[q * 32] = 0xaaa0 + q as Field;
        note_hashes[q * 32] = 0xaaa1 + q as Field;
    }
    let deposits = [0 as Field; BATCH_64_SIZE];
    let withdrawals = [0 as Field; BATCH_64_SIZE];

    l3.settle_64(nullifiers, note_hashes, deposits, withdrawals, 0x9999);

    assert(l3.batch_nonce() == 1, "64-slot settle must advance nonce by exactly 1");
    assert(l3.latest_root() == 0x9999, "root advances once to the new root");
}

// --------------------------------------------------------------------------
// settle_64_registers_all_four_quarters_withdrawals
//
// A 64-slot batch can register withdrawals from each of the 4 "quarters"
// (wrapper_32 halves of halves). All must be independently claimable on L2.
// --------------------------------------------------------------------------

#[test]
unconstrained fn settle_64_registers_all_four_quarters_withdrawals() {
    let mut l3 = TestL3::setup();
    let u0 = l3.env.create_light_account();
    let u1 = l3.env.create_light_account();
    let u2 = l3.env.create_light_account();
    let u3 = l3.env.create_light_account();

    let salt0 = random();
    let salt1 = random();
    let salt2 = random();
    let salt3 = random();
    let amounts = [100, 200, 300, 400];
    let claim0 = TestL3::compute_claim_hash(l3.token, amounts[0], u0, salt0);
    let claim1 = TestL3::compute_claim_hash(l3.token, amounts[1], u1, salt1);
    let claim2 = TestL3::compute_claim_hash(l3.token, amounts[2], u2, salt2);
    let claim3 = TestL3::compute_claim_hash(l3.token, amounts[3], u3, salt3);

    let mut nullifiers = [0 as Field; BATCH_64_NULLIFIERS_COUNT];
    let mut note_hashes = [0 as Field; BATCH_64_NOTE_HASHES_COUNT];
    // Each quarter's withdraw nullifier + claim note hash:
    nullifiers[0] = 0xc0a0;   note_hashes[0] = claim0;
    nullifiers[32] = 0xc0b0;  note_hashes[32] = claim1;
    nullifiers[64] = 0xc0c0;  note_hashes[64] = claim2;
    nullifiers[96] = 0xc0d0;  note_hashes[96] = claim3;

    let deposits = [0 as Field; BATCH_64_SIZE];
    let mut withdrawals = [0 as Field; BATCH_64_SIZE];
    // deposit_nullifiers / withdrawal_claims are batch=64 sized with 16 slots
    // per quarter; put one claim per quarter at positions 0, 16, 32, 48.
    withdrawals[0] = claim0;
    withdrawals[16] = claim1;
    withdrawals[32] = claim2;
    withdrawals[48] = claim3;

    l3.settle_64(nullifiers, note_hashes, deposits, withdrawals, 0x8888);

    let before0 = l3.token_balance(u0);
    l3.claim_withdrawal(u0, amounts[0], salt0);
    assert(l3.token_balance(u0) == before0 + amounts[0] as u128, "u0 claim succeeds");

    let before1 = l3.token_balance(u1);
    l3.claim_withdrawal(u1, amounts[1], salt1);
    assert(l3.token_balance(u1) == before1 + amounts[1] as u128, "u1 claim succeeds");

    let before2 = l3.token_balance(u2);
    l3.claim_withdrawal(u2, amounts[2], salt2);
    assert(l3.token_balance(u2) == before2 + amounts[2] as u128, "u2 claim succeeds");

    let before3 = l3.token_balance(u3);
    l3.claim_withdrawal(u3, amounts[3], salt3);
    assert(l3.token_balance(u3) == before3 + amounts[3] as u128, "u3 claim succeeds");
}

// --------------------------------------------------------------------------
// settle_64_consumes_deposits_from_all_four_quarters
// --------------------------------------------------------------------------

#[test]
unconstrained fn settle_64_consumes_deposits_from_all_four_quarters() {
    let mut l3 = TestL3::setup();

    let dep0: Field = 0xd0a0;
    let dep1: Field = 0xd0b0;
    let dep2: Field = 0xd0c0;
    let dep3: Field = 0xd0d0;
    l3.register_deposit(dep0);
    l3.register_deposit(dep1);
    l3.register_deposit(dep2);
    l3.register_deposit(dep3);

    let mut nullifiers = [0 as Field; BATCH_64_NULLIFIERS_COUNT];
    nullifiers[0] = dep0;
    nullifiers[32] = dep1;
    nullifiers[64] = dep2;
    nullifiers[96] = dep3;
    let mut note_hashes = [0 as Field; BATCH_64_NOTE_HASHES_COUNT];
    note_hashes[0] = 0xd0a1;
    note_hashes[32] = 0xd0b1;
    note_hashes[64] = 0xd0c1;
    note_hashes[96] = 0xd0d1;
    let mut deposits = [0 as Field; BATCH_64_SIZE];
    deposits[0] = dep0;
    deposits[16] = dep1;
    deposits[32] = dep2;
    deposits[48] = dep3;
    let withdrawals = [0 as Field; BATCH_64_SIZE];

    l3.settle_64(nullifiers, note_hashes, deposits, withdrawals, 0x7777);

    assert(l3.batch_nonce() == 1, "single 64-slot batch, nonce = 1");
}

// --------------------------------------------------------------------------
// settle_64_stale_root_fails
// --------------------------------------------------------------------------

#[test(should_fail)]
unconstrained fn settle_64_stale_root_fails() {
    let mut l3 = TestL3::setup();

    // First 64-slot settle advances root 0 -> 0x1111.
    l3.settle_64(
        [0; BATCH_64_NULLIFIERS_COUNT],
        [0; BATCH_64_NOTE_HASHES_COUNT],
        [0; BATCH_64_SIZE],
        [0; BATCH_64_SIZE],
        0x1111,
    );

    // Replay with stale old_state_root -- simulated by resetting our tracked
    // state_root. Contract's latest_root is now 0x1111, so old_state_root=0
    // must be rejected.
    l3.state_root = 0;
    l3.settle_64(
        [0; BATCH_64_NULLIFIERS_COUNT],
        [0; BATCH_64_NOTE_HASHES_COUNT],
        [0; BATCH_64_SIZE],
        [0; BATCH_64_SIZE],
        0x2222,
    );
}

// --------------------------------------------------------------------------
// settle_64_duplicate_deposit_across_quarters_fails
//
// If the same deposit_hash appears in multiple quarters (registered once,
// consumed twice or more), the second consumption must fail -- the first
// already cleared the pending bit.
// --------------------------------------------------------------------------

#[test(should_fail)]
unconstrained fn settle_64_duplicate_deposit_across_quarters_fails() {
    let mut l3 = TestL3::setup();

    let dup: Field = 0xdede;
    l3.register_deposit(dup);

    let mut nullifiers = [0 as Field; BATCH_64_NULLIFIERS_COUNT];
    nullifiers[0] = dup;
    nullifiers[32] = dup;  // same value in a different quarter
    let mut note_hashes = [0 as Field; BATCH_64_NOTE_HASHES_COUNT];
    note_hashes[0] = 0xded1;
    note_hashes[32] = 0xded2;
    let mut deposits = [0 as Field; BATCH_64_SIZE];
    deposits[0] = dup;   // quarter 0 consume
    deposits[16] = dup;  // quarter 1 consume -- must fail (already cleared)
    let withdrawals = [0 as Field; BATCH_64_SIZE];

    l3.settle_64(nullifiers, note_hashes, deposits, withdrawals, 0x6666);
}
