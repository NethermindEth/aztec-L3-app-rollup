use super::utils::{TestL3, INITIAL_SUPPLY};

#[test]
unconstrained fn deploy_and_verify_initial_state() {
    let l3 = TestL3::setup();

    assert(l3.latest_root() == 0, "initial root should be zero");
    assert(l3.batch_nonce() == 0, "initial nonce should be zero");
    assert(
        l3.token_balance(l3.admin) == INITIAL_SUPPLY,
        "admin should hold initial supply",
    );
}
