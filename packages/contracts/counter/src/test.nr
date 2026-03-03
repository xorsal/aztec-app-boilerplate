use crate::Counter;
use aztec::test::helpers::test_environment::TestEnvironment;

#[test]
unconstrained fn test_deploy_and_read() {
    let mut env = TestEnvironment::new();
    let owner = env.create_light_account();

    let initializer = Counter::interface().constructor(owner);
    let counter_address =
        env.deploy("Counter").with_public_initializer(owner, initializer);

    // Verify counter starts at 0
    let value: u128 = env.view_public(Counter::at(counter_address).get_counter());
    assert(value == 0);
}
