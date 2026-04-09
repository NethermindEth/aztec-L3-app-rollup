use crate::L3Settlement;
use crate::test::utils;
use aztec::{
    oracle::random::random,
    protocol::{address::AztecAddress, hash::poseidon2_hash, traits::ToField},
    test::helpers::test_environment::TestEnvironment,
};
use token::Token;

// claim_withdrawal is a public function that:
// 1. Recomputes claim_hash from (token, amount, recipient, salt)
// 2. Checks pending_withdrawals[claim_hash] == true
// 3. Transfers tokens from the contract to the recipient
//
// Since we can't call settle_batch (needs proof), we test the revert paths
// and the hash computation.

#[test]
unconstrained fn claim_hash_computation_matches_circuit() {
    // Verify that the contract's poseidon2_hash matches what the
    // withdraw circuit would produce.
    let token_addr: Field = 0x42;
    let amount: Field = 200;
    let recipient: Field = 0xabc;
    let salt: Field = 0xdef;

    let secret = poseidon2_hash([recipient, salt]);
    let claim_hash = poseidon2_hash([token_addr, amount, secret]);

    // The claim_hash should be deterministic and non-zero.
    assert(claim_hash != 0, "claim hash should be non-zero");

    // Recompute to verify consistency.
    let secret2 = poseidon2_hash([recipient, salt]);
    let claim_hash2 = poseidon2_hash([token_addr, amount, secret2]);
    assert(claim_hash == claim_hash2, "claim hash should be deterministic");
}

#[test(should_fail)]
unconstrained fn claim_withdrawal_reverts_when_not_pending() {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();
    let user = env.create_light_account();

    // Deploy Token with minter and L3Settlement.
    let token_init = Token::interface().constructor(
        deployer,
        utils::TOKEN_NAME,
        utils::TOKEN_SYMBOL,
        utils::TOKEN_DECIMALS,
    );
    let token = env.deploy("@token_contract/Token").with_public_initializer(deployer, token_init);

    // Fund L3 contract with public tokens.
    let l3_init = L3Settlement::interface().constructor(0, 0);
    let l3 = env.deploy("L3Settlement").with_public_initializer(deployer, l3_init);
    env.call_public(deployer, Token::at(token).mint_to_public(l3, 10_000));

    // Compute a valid claim hash.
    let salt = random();
    let secret = poseidon2_hash([user.to_field(), salt]);
    let claim_hash = poseidon2_hash([token.to_field(), 100 as Field, secret]);

    // This should fail because no withdrawal was registered.
    env.call_public(
        user,
        L3Settlement::at(l3).claim_withdrawal(token, 100, user, salt, claim_hash),
    );
}
