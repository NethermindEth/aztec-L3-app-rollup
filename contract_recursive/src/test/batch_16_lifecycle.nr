use super::utils::{
    TestL3, BATCH_16_SIZE, BATCH_16_NULLIFIERS_COUNT, BATCH_16_NOTE_HASHES_COUNT,
};
use aztec::oracle::random::random;

// Contract-side tests for the 16-slot (wrapper_16-aggregated) entry points:
//   - submit_batch_16 (private, proof-gated -- bypassed in unit tests)
//   - settle_batch_16 (public, only_self)
//
// These cover the contract-side invariants that are NOT enforced inside the
// wrapper_16 circuit: stale root detection, pending-deposit consumption,
// withdrawal-claim registration, and single-nonce advancement per 16-slot
// settle (vs the IVC submit_two_batches which advances nonce twice).
//
// Index chaining (nullifier_tree / note_hash_tree start index advancement
// across halves A and B) is already enforced inside wrapper_16 via the
// in-circuit state-root chain A.new == B.old and is not retested here.

// --------------------------------------------------------------------------
// settle_16_advances_nonce_exactly_once
//
// A 16-slot batch represents 2 sub-batches worth of work but must advance
// the nonce exactly once (contrast: IVC submit_two_batches advances by 2).
// --------------------------------------------------------------------------

#[test]
unconstrained fn settle_16_advances_nonce_exactly_once() {
    let mut l3 = TestL3::setup();

    let mut nullifiers = [0 as Field; BATCH_16_NULLIFIERS_COUNT];
    nullifiers[0] = 0xaaa0;   // half A
    nullifiers[16] = 0xbbb0;  // half B
    let mut note_hashes = [0 as Field; BATCH_16_NOTE_HASHES_COUNT];
    note_hashes[0] = 0xaaa1;
    note_hashes[16] = 0xbbb1;
    let deposits = [0 as Field; BATCH_16_SIZE];
    let withdrawals = [0 as Field; BATCH_16_SIZE];

    l3.settle_16(nullifiers, note_hashes, deposits, withdrawals, 0x9999);

    assert(l3.batch_nonce() == 1, "16-slot settle must advance nonce by exactly 1");
    assert(l3.latest_root() == 0x9999, "root advances once to the new root");
}

// --------------------------------------------------------------------------
// settle_16_registers_both_halves_withdrawals
//
// A 16-slot batch can register withdrawal claims from BOTH halves. Both
// must be claimable on L2 from a single pending_withdrawals write pass.
// --------------------------------------------------------------------------

#[test]
unconstrained fn settle_16_registers_both_halves_withdrawals() {
    let mut l3 = TestL3::setup();
    let user_a = l3.env.create_light_account();
    let user_b = l3.env.create_light_account();

    let salt_a = random();
    let salt_b = random();
    let claim_a = TestL3::compute_claim_hash(l3.token, 300, user_a, salt_a);
    let claim_b = TestL3::compute_claim_hash(l3.token, 700, user_b, salt_b);

    let mut nullifiers = [0 as Field; BATCH_16_NULLIFIERS_COUNT];
    nullifiers[0] = 0xc001;   // withdrawal A burn nullifier (half A)
    nullifiers[16] = 0xc002;  // withdrawal B burn nullifier (half B)
    let mut note_hashes = [0 as Field; BATCH_16_NOTE_HASHES_COUNT];
    note_hashes[0] = claim_a;    // claim_a occupies slot 0 (half A)
    note_hashes[16] = claim_b;   // claim_b occupies slot 16 (half B)
    let deposits = [0 as Field; BATCH_16_SIZE];
    let mut withdrawals = [0 as Field; BATCH_16_SIZE];
    withdrawals[0] = claim_a;   // registered from half A
    withdrawals[8] = claim_b;   // registered from half B

    l3.settle_16(nullifiers, note_hashes, deposits, withdrawals, 0x8888);

    // Both halves' claims should be independently redeemable.
    let before_a = l3.token_balance(user_a);
    l3.claim_withdrawal(user_a, 300, salt_a);
    assert(l3.token_balance(user_a) == before_a + 300, "user_a claim succeeds");

    let before_b = l3.token_balance(user_b);
    l3.claim_withdrawal(user_b, 700, salt_b);
    assert(l3.token_balance(user_b) == before_b + 700, "user_b claim succeeds");
}

// --------------------------------------------------------------------------
// settle_16_consumes_deposits_from_both_halves
//
// Two distinct deposits, one registered for each half, both consumed in a
// single 16-slot settle.
// --------------------------------------------------------------------------

#[test]
unconstrained fn settle_16_consumes_deposits_from_both_halves() {
    let mut l3 = TestL3::setup();

    let dep_a: Field = 0xd0a0;
    let dep_b: Field = 0xd0b0;
    l3.register_deposit(dep_a);
    l3.register_deposit(dep_b);

    let mut nullifiers = [0 as Field; BATCH_16_NULLIFIERS_COUNT];
    nullifiers[0] = dep_a;    // half A deposit nullifier slot
    nullifiers[16] = dep_b;   // half B deposit nullifier slot
    let mut note_hashes = [0 as Field; BATCH_16_NOTE_HASHES_COUNT];
    note_hashes[0] = 0xd0a1;
    note_hashes[16] = 0xd0b1;
    let mut deposits = [0 as Field; BATCH_16_SIZE];
    deposits[0] = dep_a;    // consumed from half A
    deposits[8] = dep_b;    // consumed from half B
    let withdrawals = [0 as Field; BATCH_16_SIZE];

    l3.settle_16(nullifiers, note_hashes, deposits, withdrawals, 0x7777);

    assert(l3.batch_nonce() == 1, "single 16-slot batch, nonce = 1");
}

// --------------------------------------------------------------------------
// settle_16_stale_root_fails
//
// Calling settle_batch_16 with an old_state_root that does not match
// the contract's current latest_root must abort. Guards against replay
// and against two halves referring to a common stale root.
// --------------------------------------------------------------------------

#[test(should_fail)]
unconstrained fn settle_16_stale_root_fails() {
    let mut l3 = TestL3::setup();

    // First 16-slot settle -- advances root 0 -> 0x1111.
    l3.settle_16(
        [0; BATCH_16_NULLIFIERS_COUNT],
        [0; BATCH_16_NOTE_HASHES_COUNT],
        [0; BATCH_16_SIZE],
        [0; BATCH_16_SIZE],
        0x1111,
    );

    // Replay with stale root: simulate by pointing our tracked state_root
    // back to 0, then attempt another 16-slot settle. The contract's
    // latest_root is now 0x1111, so old_state_root=0 must be rejected.
    l3.state_root = 0;
    l3.settle_16(
        [0; BATCH_16_NULLIFIERS_COUNT],
        [0; BATCH_16_NOTE_HASHES_COUNT],
        [0; BATCH_16_SIZE],
        [0; BATCH_16_SIZE],
        0x2222,
    );
}

// --------------------------------------------------------------------------
// settle_16_duplicate_deposit_across_halves_fails
//
// If the same deposit_hash appears in both halves of the 16-slot deposit
// array (so it is registered once but consumed twice), the second
// consumption must fail because the first already cleared the pending bit.
// --------------------------------------------------------------------------

#[test(should_fail)]
unconstrained fn settle_16_duplicate_deposit_across_halves_fails() {
    let mut l3 = TestL3::setup();

    let dup: Field = 0xdede;
    l3.register_deposit(dup);

    let mut nullifiers = [0 as Field; BATCH_16_NULLIFIERS_COUNT];
    nullifiers[0] = dup;
    nullifiers[16] = dup;  // NB: same nullifier -- in a real run wrapper_16
                           // would never build this, but we're testing the
                           // contract's defense-in-depth.
    let mut note_hashes = [0 as Field; BATCH_16_NOTE_HASHES_COUNT];
    note_hashes[0] = 0xded1;
    note_hashes[16] = 0xded2;
    let mut deposits = [0 as Field; BATCH_16_SIZE];
    deposits[0] = dup;  // half A consume
    deposits[8] = dup;  // half B consume -- must fail (already cleared)
    let withdrawals = [0 as Field; BATCH_16_SIZE];

    l3.settle_16(nullifiers, note_hashes, deposits, withdrawals, 0x6666);
}
