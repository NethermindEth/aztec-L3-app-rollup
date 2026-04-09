use crate::L3Settlement;
use aztec::{
    oracle::random::random,
    protocol::{address::AztecAddress, hash::poseidon2_hash, traits::ToField},
    test::helpers::test_environment::TestEnvironment,
};

// Calls settle_batch from the contract's own address (bypasses #[only_self]).
// This tests the full settlement logic without needing a real tube proof.

unconstrained fn deploy_l3() -> (TestEnvironment, AztecAddress) {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let l3_init = L3Settlement::interface().constructor(0, 0);
    let l3 = env.deploy("L3Settlement").with_public_initializer(deployer, l3_init);
    (env, l3)
}

#[test]
unconstrained fn settle_empty_batch() {
    let (mut env, l3) = deploy_l3();

    // All-zero arrays.
    let nullifiers = [0 as Field; 8];
    let note_hashes = [0 as Field; 8];
    let deposit_nullifiers = [0 as Field; 4];
    let withdrawal_claims = [0 as Field; 4];

    let nullifiers_hash = poseidon2_hash(nullifiers);
    let note_hashes_hash = poseidon2_hash(note_hashes);
    let deposit_hash = poseidon2_hash(deposit_nullifiers);
    let withdrawal_hash = poseidon2_hash(withdrawal_claims);

    let new_state_root: Field = 0xbeef;

    // Call as the contract itself.
    env.call_public(
        l3,
        L3Settlement::at(l3).settle_batch(
            0,               // tube_vk_hash
            0,               // old_state_root
            new_state_root,
            nullifiers_hash,
            note_hashes_hash,
            deposit_hash,
            withdrawal_hash,
            1,               // nullifier_tree_start_index (genesis = 1)
            0,               // note_hash_tree_start_index (genesis = 0)
            nullifiers,
            note_hashes,
            deposit_nullifiers,
            withdrawal_claims,
        ),
    );

    // State should advance.
    let root: Field = env.view_public(L3Settlement::at(l3).get_latest_root());
    assert(root == new_state_root, "root should be new_state_root");

    let nonce: Field = env.view_public(L3Settlement::at(l3).get_batch_nonce());
    assert(nonce == 1, "nonce should be 1");
}

#[test]
unconstrained fn settle_batch_consumes_deposit() {
    let (mut env, l3) = deploy_l3();

    // Register a pending deposit (call as the contract itself).
    let deposit_id: Field = 0x1234abcd;
    env.call_public(l3, L3Settlement::at(l3).register_deposit_internal(deposit_id));

    // Build arrays: deposit_id appears as a nullifier and a deposit_nullifier.
    let mut nullifiers = [0 as Field; 8];
    nullifiers[0] = deposit_id;
    let note_hashes = [0 as Field; 8];
    let mut deposit_nullifiers = [0 as Field; 4];
    deposit_nullifiers[0] = deposit_id;
    let withdrawal_claims = [0 as Field; 4];

    let nullifiers_hash = poseidon2_hash(nullifiers);
    let note_hashes_hash = poseidon2_hash(note_hashes);
    let deposit_hash = poseidon2_hash(deposit_nullifiers);
    let withdrawal_hash = poseidon2_hash(withdrawal_claims);

    let new_root: Field = 0xdead;

    env.call_public(
        l3,
        L3Settlement::at(l3).settle_batch(
            0, 0, new_root,
            nullifiers_hash, note_hashes_hash,
            deposit_hash, withdrawal_hash,
            1, 0,
            nullifiers, note_hashes,
            deposit_nullifiers, withdrawal_claims,
        ),
    );

    // Root and nonce advanced.
    let root: Field = env.view_public(L3Settlement::at(l3).get_latest_root());
    assert(root == new_root, "root should advance");
    let nonce: Field = env.view_public(L3Settlement::at(l3).get_batch_nonce());
    assert(nonce == 1, "nonce should be 1");
}

#[test(should_fail)]
unconstrained fn settle_batch_rejects_unregistered_deposit() {
    let (mut env, l3) = deploy_l3();

    // Do NOT register the deposit.
    let fake_deposit: Field = 0xfa0e0001;

    let mut nullifiers = [0 as Field; 8];
    nullifiers[0] = fake_deposit;
    let note_hashes = [0 as Field; 8];
    let mut deposit_nullifiers = [0 as Field; 4];
    deposit_nullifiers[0] = fake_deposit;
    let withdrawal_claims = [0 as Field; 4];

    let nullifiers_hash = poseidon2_hash(nullifiers);
    let note_hashes_hash = poseidon2_hash(note_hashes);
    let deposit_hash = poseidon2_hash(deposit_nullifiers);
    let withdrawal_hash = poseidon2_hash(withdrawal_claims);

    // Should fail: "deposit not in pending list".
    env.call_public(
        l3,
        L3Settlement::at(l3).settle_batch(
            0, 0, 0xbeef,
            nullifiers_hash, note_hashes_hash,
            deposit_hash, withdrawal_hash,
            1, 0,
            nullifiers, note_hashes,
            deposit_nullifiers, withdrawal_claims,
        ),
    );
}

#[test(should_fail)]
unconstrained fn settle_batch_rejects_double_consumption() {
    let (mut env, l3) = deploy_l3();

    let deposit_id: Field = 0xabcdef;
    env.call_public(l3, L3Settlement::at(l3).register_deposit_internal(deposit_id));

    let mut nullifiers = [0 as Field; 8];
    nullifiers[0] = deposit_id;
    let note_hashes = [0 as Field; 8];
    let mut deposit_nullifiers = [0 as Field; 4];
    deposit_nullifiers[0] = deposit_id;
    let withdrawal_claims = [0 as Field; 4];

    let nullifiers_hash = poseidon2_hash(nullifiers);
    let note_hashes_hash = poseidon2_hash(note_hashes);
    let deposit_hash = poseidon2_hash(deposit_nullifiers);
    let withdrawal_hash = poseidon2_hash(withdrawal_claims);

    // First settle succeeds.
    env.call_public(
        l3,
        L3Settlement::at(l3).settle_batch(
            0, 0, 0x1111,
            nullifiers_hash, note_hashes_hash,
            deposit_hash, withdrawal_hash,
            1, 0,
            nullifiers, note_hashes,
            deposit_nullifiers, withdrawal_claims,
        ),
    );

    // Second settle with the same deposit should fail (already consumed).
    // State has changed: old_state_root is now 0x1111, indices advanced.
    env.call_public(
        l3,
        L3Settlement::at(l3).settle_batch(
            0, 0x1111, 0x2222,
            nullifiers_hash, note_hashes_hash,
            deposit_hash, withdrawal_hash,
            2, 0, // nullifier index advanced by 1
            nullifiers, note_hashes,
            deposit_nullifiers, withdrawal_claims,
        ),
    );
}

#[test]
unconstrained fn settle_batch_chains_state_roots() {
    let (mut env, l3) = deploy_l3();

    let empty_nullifiers = [0 as Field; 8];
    let empty_note_hashes = [0 as Field; 8];
    let empty_deposits = [0 as Field; 4];
    let empty_withdrawals = [0 as Field; 4];
    let nh = poseidon2_hash(empty_nullifiers);
    let nhh = poseidon2_hash(empty_note_hashes);
    let dh = poseidon2_hash(empty_deposits);
    let wh = poseidon2_hash(empty_withdrawals);

    // Batch 1: 0 -> 0xaaaa
    env.call_public(l3, L3Settlement::at(l3).settle_batch(
        0, 0, 0xaaaa, nh, nhh, dh, wh, 1, 0,
        empty_nullifiers, empty_note_hashes, empty_deposits, empty_withdrawals,
    ));

    let root1: Field = env.view_public(L3Settlement::at(l3).get_latest_root());
    assert(root1 == 0xaaaa, "root after batch 1");

    // Batch 2: 0xaaaa -> 0xbbbb
    env.call_public(l3, L3Settlement::at(l3).settle_batch(
        0, 0xaaaa, 0xbbbb, nh, nhh, dh, wh, 1, 0,
        empty_nullifiers, empty_note_hashes, empty_deposits, empty_withdrawals,
    ));

    let root2: Field = env.view_public(L3Settlement::at(l3).get_latest_root());
    assert(root2 == 0xbbbb, "root after batch 2");

    let nonce: Field = env.view_public(L3Settlement::at(l3).get_batch_nonce());
    assert(nonce == 2, "nonce after 2 batches");
}

#[test(should_fail)]
unconstrained fn settle_batch_rejects_wrong_old_root() {
    let (mut env, l3) = deploy_l3();

    let empty_nullifiers = [0 as Field; 8];
    let empty_note_hashes = [0 as Field; 8];
    let empty_deposits = [0 as Field; 4];
    let empty_withdrawals = [0 as Field; 4];
    let nh = poseidon2_hash(empty_nullifiers);
    let nhh = poseidon2_hash(empty_note_hashes);
    let dh = poseidon2_hash(empty_deposits);
    let wh = poseidon2_hash(empty_withdrawals);

    // old_state_root = 0x9999 but stored root is 0. Should fail.
    env.call_public(l3, L3Settlement::at(l3).settle_batch(
        0, 0x9999, 0xaaaa, nh, nhh, dh, wh, 1, 0,
        empty_nullifiers, empty_note_hashes, empty_deposits, empty_withdrawals,
    ));
}
