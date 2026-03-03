use aztec::macros::aztec;
pub mod test;

#[aztec]
pub contract Counter {
    use aztec::{
        macros::{functions::{external, initializer, only_self, view}, storage::storage},
        protocol::address::AztecAddress,
        state_vars::{PublicImmutable, PublicMutable},
    };

    #[storage]
    struct Storage<Context> {
        owner: PublicImmutable<AztecAddress, Context>,
        counter: PublicMutable<u128, Context>,
    }

    /// Initialize the contract with an owner address.
    #[external("public")]
    #[initializer]
    fn constructor(owner: AztecAddress) {
        self.storage.owner.initialize(owner);
    }

    /// Retrieve the owner address.
    #[external("public")]
    #[view]
    fn get_owner() -> AztecAddress {
        self.storage.owner.read()
    }

    /// Private entry point that enqueues a public call to increment.
    /// Demonstrates the private-to-public call pattern.
    #[external("private")]
    fn increment() {
        self.enqueue_self.increment_internal();
    }

    /// Read the current counter value.
    #[external("public")]
    #[view]
    fn get_counter() -> u128 {
        self.storage.counter.read()
    }

    /// Internal-only public function that performs the actual increment.
    #[external("public")]
    #[only_self]
    fn increment_internal() {
        let current_value = self.storage.counter.read();
        self.storage.counter.write(current_value + 1);
    }
}
