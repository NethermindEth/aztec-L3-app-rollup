use super::utils::TestL3;
use aztec::oracle::random::random;

// Full lifecycle: deposit -> transfer -> withdrawal -> claim.
// Each step settles a batch that advances the L3 state.
//
// Recursive pipeline: sub-batch size 8 -> 16 nullifier slots / 16 note-hash slots
// / 8 deposit & withdrawal-claim slots.

#[test]
unconstrained fn full_deposit_transfer_withdraw_claim() {
    let mut l3 = TestL3::setup();
    let user = l3.env.create_light_account();

    // ----------------------------------------------------------------
    // Step 1: Deposit -- register on L2, then settle a batch consuming it.
    // ----------------------------------------------------------------
    let deposit_hash: Field = 0xd001;
    let deposit_note_hash: Field = 0xd002;

    l3.register_deposit(deposit_hash);

    let mut nullifiers_1 = [0 as Field; 16];
    nullifiers_1[0] = deposit_hash;             // deposit's nullifier slot
    let mut note_hashes_1 = [0 as Field; 16];
    note_hashes_1[0] = deposit_note_hash;       // deposit's note hash slot
    let mut deposits_1 = [0 as Field; 8];
    deposits_1[0] = deposit_hash;               // consumed deposit
    let withdrawals_1 = [0 as Field; 8];

    l3.settle(nullifiers_1, note_hashes_1, deposits_1, withdrawals_1, 0x1111);

    assert(l3.latest_root() == 0x1111, "root after deposit batch");
    assert(l3.batch_nonce() == 1, "nonce after deposit batch");

    // ----------------------------------------------------------------
    // Step 2: Transfer -- consume the deposited note, create a new note.
    // ----------------------------------------------------------------
    let payment_nullifier: Field = 0xa001;      // nullifier of the spent note
    let recipient_note_hash: Field = 0xa002;    // new note for recipient
    let change_note_hash: Field = 0xa003;       // change back to sender

    let mut nullifiers_2 = [0 as Field; 16];
    nullifiers_2[0] = payment_nullifier;
    let mut note_hashes_2 = [0 as Field; 16];
    note_hashes_2[0] = recipient_note_hash;
    note_hashes_2[1] = change_note_hash;
    let deposits_2 = [0 as Field; 8];
    let withdrawals_2 = [0 as Field; 8];

    l3.settle(nullifiers_2, note_hashes_2, deposits_2, withdrawals_2, 0x2222);

    assert(l3.latest_root() == 0x2222, "root after transfer batch");
    assert(l3.batch_nonce() == 2, "nonce after transfer batch");

    // ----------------------------------------------------------------
    // Step 3: Withdrawal -- consume an L3 note, produce a claim hash.
    // ----------------------------------------------------------------
    let withdraw_nullifier: Field = 0xb001;
    let claim_salt = random();
    let claim_hash = TestL3::compute_claim_hash(l3.token, 500, user, claim_salt);

    let mut nullifiers_3 = [0 as Field; 16];
    nullifiers_3[0] = withdraw_nullifier;
    let mut note_hashes_3 = [0 as Field; 16];
    note_hashes_3[0] = claim_hash;              // claim occupies a note hash slot
    let deposits_3 = [0 as Field; 8];
    let mut withdrawals_3 = [0 as Field; 8];
    withdrawals_3[0] = claim_hash;              // registered as pending withdrawal

    l3.settle(nullifiers_3, note_hashes_3, deposits_3, withdrawals_3, 0x3333);

    assert(l3.latest_root() == 0x3333, "root after withdrawal batch");
    assert(l3.batch_nonce() == 3, "nonce after withdrawal batch");

    // ----------------------------------------------------------------
    // Step 4: Claim -- redeem the withdrawal on L2.
    // ----------------------------------------------------------------
    let user_balance_before = l3.token_balance(user);

    l3.claim_withdrawal(user, 500, claim_salt);

    let user_balance_after = l3.token_balance(user);
    assert(
        user_balance_after == user_balance_before + 500,
        "user should receive 500 tokens",
    );
}

#[test]
unconstrained fn deposit_and_immediate_withdrawal() {
    let mut l3 = TestL3::setup();
    let user = l3.env.create_light_account();

    // Register deposit.
    let deposit_hash: Field = 0xe001;
    l3.register_deposit(deposit_hash);

    // Single batch: deposit + withdrawal in one settle.
    let claim_salt = random();
    let claim_hash = TestL3::compute_claim_hash(l3.token, 200, user, claim_salt);

    let mut nullifiers = [0 as Field; 16];
    nullifiers[0] = deposit_hash;       // deposit nullifier (slot 0)
    nullifiers[2] = 0xf001;             // withdrawal nullifier (slot 1, tx index 1)
    let mut note_hashes = [0 as Field; 16];
    note_hashes[0] = 0xe002;            // deposit note hash
    note_hashes[2] = claim_hash;        // withdrawal claim hash
    let mut deposits = [0 as Field; 8];
    deposits[0] = deposit_hash;
    let mut withdrawals = [0 as Field; 8];
    withdrawals[1] = claim_hash;        // tx index 1 is the withdrawal

    l3.settle(nullifiers, note_hashes, deposits, withdrawals, 0x4444);

    // Claim on L2.
    let balance_before = l3.token_balance(user);
    l3.claim_withdrawal(user, 200, claim_salt);
    let balance_after = l3.token_balance(user);
    assert(balance_after == balance_before + 200, "user should receive 200 tokens");

    assert(l3.batch_nonce() == 1, "single batch");
}

#[test(should_fail)]
unconstrained fn double_claim_fails() {
    let mut l3 = TestL3::setup();
    let user = l3.env.create_light_account();

    let claim_salt = random();
    let claim_hash = TestL3::compute_claim_hash(l3.token, 100, user, claim_salt);

    // Settle batch with a withdrawal.
    let mut nullifiers = [0 as Field; 16];
    nullifiers[0] = 0xc001;
    let mut note_hashes = [0 as Field; 16];
    note_hashes[0] = claim_hash;
    let mut withdrawals = [0 as Field; 8];
    withdrawals[0] = claim_hash;

    l3.settle(nullifiers, note_hashes, [0; 8], withdrawals, 0x5555);

    // First claim succeeds.
    l3.claim_withdrawal(user, 100, claim_salt);

    // Second claim should fail (already consumed).
    l3.claim_withdrawal(user, 100, claim_salt);
}

#[test(should_fail)]
unconstrained fn settle_with_wrong_root_chain_fails() {
    let mut l3 = TestL3::setup();

    // First batch.
    l3.settle([0; 16], [0; 16], [0; 8], [0; 8], 0xaaaa);

    // Tamper with internal state to simulate wrong chain.
    l3.state_root = 0xb0905;

    // Second batch should fail (old_state_root mismatch).
    l3.settle([0; 16], [0; 16], [0; 8], [0; 8], 0xbbbb);
}
