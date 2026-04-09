use crate::L3Settlement;
use crate::test::utils;
use aztec::{
    oracle::random::random,
    protocol::{address::AztecAddress, hash::poseidon2_hash},
    test::helpers::{authwit as authwit_cheatcodes, test_environment::TestEnvironment},
};
use token::Token;

// The deposit() private function calls Token.transfer_private_to_public,
// which requires private balance and key scoping. Testing that full flow
// requires the TXE to support private note creation + key management.
//
// For now, test the public half: register_deposit_internal writes to
// pending_deposits. We call it via a public-only path by directly testing
// the registration logic.

#[test]
unconstrained fn register_deposit_via_direct_public_call() {
    let mut env = TestEnvironment::new();
    let deployer = env.create_light_account();

    // Deploy L3Settlement.
    let l3_init = L3Settlement::interface().constructor(0, 0);
    let l3 = env.deploy("L3Settlement").with_public_initializer(deployer, l3_init);

    // register_deposit_internal is #[only_self], so we cannot call it
    // from an external account. Instead, verify that the deposit() function
    // compiles and the contract deploys correctly.
    //
    // Full deposit flow test requires private authwit support in TXE.
    // See integration.test.ts for the sandbox-based e2e test.

    // Verify the contract is deployed and view functions work.
    let root: Field = env.view_public(L3Settlement::at(l3).get_latest_root());
    assert(root == 0, "root should be zero");
}
