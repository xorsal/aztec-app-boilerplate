/**
 * EIP-712 Account Contract
 *
 * This account contract verifies EIP-712 typed data signatures, enabling human-readable
 * authorization requests via MetaMask. Unlike standard account contracts that sign opaque
 * hashes, this contract:
 *
 * 1. Receives function arguments as plaintext via capsule
 * 2. Computes EIP-712 hashStruct using keccak256
 * 3. Verifies the ECDSA signature over the EIP-712 payload
 *
 * This provides cryptographic binding between what users see in MetaMask and what
 * the circuit verifies.
 */

use ::aztec::macros::aztec;

mod ecdsa_public_key_note;
mod eip712;

#[aztec]
pub contract Eip712Account {
    use ::aztec::{
        authwit::entrypoint::app::AppPayload,
        macros::{
            functions::{allow_phase_change, external, initializer, noinitcheck, view},
            storage::storage,
        },
        messages::message_delivery::MessageDelivery,
        oracle::notes::{get_sender_for_tags, set_sender_for_tags},
        protocol::{
            constants::DOM_SEP__TX_NULLIFIER,
            hash::poseidon2_hash_with_separator,
            traits::Serialize,
        },
        state_vars::SinglePrivateImmutable,
    };

    use crate::ecdsa_public_key_note::EcdsaPublicKeyNote;
    use crate::eip712::{
        ACCOUNT_MAX_CALLS, APP_PAYLOAD_SERIALIZED_LEN, compute_aztec_args_hash,
        compute_eip712_payload, compute_function_selector, compute_inner_hash, Eip712AuthwitWitness,
        Eip712Witness5, EMPTY_FUNCTION_CALL_HASH, extract_args_hash, extract_function_selector,
        extract_is_public, extract_target_address, field_to_bytes32, hash_app_domain,
        hash_authwit_app_domain, hash_entrypoint_authorization_5, hash_function_call,
        hash_function_call_authorization, hash_function_calls_array, load_eip712_authwit_witness,
        load_eip712_witness_5,
    };

    // =========================================================================
    // Constants
    // =========================================================================

    // Pre-computed hashes for AppDomain strings (computed once, used for all txs)
    // keccak256("EVM Aztec Wallet")
    global APP_DOMAIN_NAME_HASH: [u8; 32] = [
        0x35, 0xe6, 0xe0, 0x18, 0x69, 0xe8, 0x48, 0x54, 0xdd, 0x01, 0x10, 0xc3, 0xf3, 0x33, 0x8d,
        0xda, 0x29, 0x49, 0x9e, 0xa7, 0xe6, 0x2e, 0x43, 0x38, 0x33, 0x65, 0x55, 0xbe, 0xe5, 0x2e,
        0xa8, 0xe9,
    ];

    // keccak256("1.0.0")
    global APP_DOMAIN_VERSION_HASH: [u8; 32] = [
        0x06, 0xc0, 0x15, 0xbd, 0x22, 0xb4, 0xc6, 0x96, 0x90, 0x93, 0x3c, 0x10, 0x58, 0x87, 0x8e,
        0xbd, 0xfe, 0xf3, 0x1f, 0x9a, 0xaa, 0xe4, 0x0b, 0xbe, 0x86, 0xd8, 0xa0, 0x9f, 0xe1, 0xb2,
        0x97, 0x2c,
    ];

    // Pre-computed domain separator for "Aztec" rollup with chainId=31337
    // Computed as: keccak256(abi.encode(
    //   keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    //   keccak256("Aztec"),
    //   keccak256("1"),
    //   31337,
    //   0x0000000000000000000000000000000000000001
    // ))
    // Result: 0x0c4d2d20583d2ee0c940ac2789fd85e2758be2b7546e627efa99bab898e5a141
    global DOMAIN_SEPARATOR: [u8; 32] = [
        0x0c, 0x4d, 0x2d, 0x20, 0x58, 0x3d, 0x2e, 0xe0, 0xc9, 0x40, 0xac, 0x27, 0x89, 0xfd, 0x85,
        0xe2, 0x75, 0x8b, 0xe2, 0xb7, 0x54, 0x6e, 0x62, 0x7e, 0xfa, 0x99, 0xba, 0xb8, 0x98, 0xe5,
        0xa1, 0x41,
    ];

    // =========================================================================
    // Storage
    // =========================================================================

    #[storage]
    struct Storage<Context> {
        signing_public_key: SinglePrivateImmutable<EcdsaPublicKeyNote, Context>,
    }

    // =========================================================================
    // Constructor
    // =========================================================================

    /// Creates a new account with an ECDSA secp256k1 public key for signature verification
    #[external("private")]
    #[initializer]
    fn constructor(signing_pub_key_x: [u8; 32], signing_pub_key_y: [u8; 32]) {
        let pub_key_note = EcdsaPublicKeyNote::new(signing_pub_key_x, signing_pub_key_y);

        // Safety: The sender for tags is only used for unconstrained tagging
        let original_sender = unsafe { get_sender_for_tags().unwrap_or(self.address) };
        // Safety: Same as above - only for unconstrained tagging
        unsafe { set_sender_for_tags(self.address) };

        self.storage.signing_public_key.initialize(pub_key_note).deliver(
            MessageDelivery.ONCHAIN_CONSTRAINED,
        );

        // Safety: Same as above - only for unconstrained tagging
        unsafe { set_sender_for_tags(original_sender) };
    }

    // =========================================================================
    // Entrypoint
    // =========================================================================

    /// Main entrypoint for executing transactions with EIP-712 signature verification.
    /// Supports up to 5 function calls in a single transaction.
    ///
    /// This function:
    /// 1. Gets all 5 function call details via capsule
    /// 2. Computes the EIP-712 hash over the array of calls
    /// 3. Verifies the single ECDSA signature covers all calls
    /// 4. Executes the calls from the app_payload
    ///
    /// Note: This does NOT use AccountActions.entrypoint because its revertible phase
    /// handling conflicts with EXTERNAL fee payment (SponsoredFPC). We replicate the
    /// logic here with correct EXTERNAL handling.
    #[external("private")]
    #[noinitcheck]
    #[allow_phase_change]
    fn entrypoint(app_payload: AppPayload, fee_payment_method: u8, cancellable: bool) {
        // Safety: The sender for tags is only used for unconstrained tagging
        unsafe { set_sender_for_tags(self.address) };

        // Load public key from storage
        let public_key = self.storage.signing_public_key.get_note();

        // Load EIP-712 witness data from capsule (5-call version)
        // Safety: Capsule data will be validated against AppPayload below
        let witness: Eip712Witness5 = unsafe {
            load_eip712_witness_5(self.address).expect(
                f"EIP-712 witness capsule (5-call) not found",
            )
        };

        // Combine signature_r and signature_s into a single 64-byte array
        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        // Serialize AppPayload to extract function call data
        let serialized_payload: [Field; APP_PAYLOAD_SERIALIZED_LEN] = app_payload.serialize();

        // =====================================================================
        // Verify all 5 calls and compute EIP-712 hashes
        // =====================================================================

        let mut call_hashes: [[u8; 32]; ACCOUNT_MAX_CALLS] = [[0; 32]; ACCOUNT_MAX_CALLS];
        let mut has_any_call = false;

        for call_idx in 0..ACCOUNT_MAX_CALLS {
            let stored_target = extract_target_address(serialized_payload, call_idx);

            if stored_target != 0 {
                has_any_call = true;

                // 1. Verify target address matches
                assert(
                    witness.target_addresses[call_idx] == stored_target,
                    "AuthWit target_address mismatch with AppPayload",
                );

                // 2. Compute selector from function signature (derived, not from witness)
                let computed_selector = compute_function_selector(
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                );
                let stored_selector = extract_function_selector(serialized_payload, call_idx);
                assert(
                    computed_selector == stored_selector,
                    "AuthWit function_selector mismatch with AppPayload",
                );

                // 3. Verify args_hash matches
                // Extract is_public flag to use the correct hash separator
                // For public functions, selector is prepended to args in the AppPayload's args_hash
                let is_public = extract_is_public(serialized_payload, call_idx);
                let computed_args_hash = compute_aztec_args_hash(
                    witness.function_args[call_idx],
                    witness.args_lengths[call_idx],
                    is_public,
                    computed_selector as Field, // Use computed selector for args_hash
                );
                let stored_args_hash = extract_args_hash(serialized_payload, call_idx);
                assert(
                    computed_args_hash == stored_args_hash,
                    "AuthWit args_hash mismatch with AppPayload",
                );

                // 4. Compute EIP-712 hashStruct(FunctionCall)
                // Note: selector is NOT included in EIP-712 hash - it's derived from signature
                // is_private is the opposite of is_public (for EIP-712 clear signing display)
                let is_private = !is_public;
                let target_bytes = field_to_bytes32(witness.target_addresses[call_idx]);
                call_hashes[call_idx] = hash_function_call(
                    target_bytes,
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                    witness.function_args[call_idx],
                    witness.args_lengths[call_idx],
                    is_private,
                );
            } else {
                // Empty call slot - use pre-computed empty hash
                call_hashes[call_idx] = EMPTY_FUNCTION_CALL_HASH;
            }
        }

        // Must have at least one non-empty call
        assert(has_any_call, "AppPayload must have at least one function call");

        // =====================================================================
        // Compute EIP-712 message hash over all 5 calls
        // =====================================================================

        // Hash the array of function calls
        let function_calls_array_hash = hash_function_calls_array(call_hashes);

        // Compute AppDomain hash
        let chain_id_bytes = field_to_bytes32(witness.chain_id);
        let app_domain_hash = hash_app_domain(
            APP_DOMAIN_NAME_HASH,
            APP_DOMAIN_VERSION_HASH,
            chain_id_bytes,
            witness.salt,
        );

        // Compute EntrypointAuthorization hash (5-call version)
        let tx_nonce_bytes = field_to_bytes32(app_payload.tx_nonce);
        let message_hash = hash_entrypoint_authorization_5(
            app_domain_hash,
            function_calls_array_hash,
            tx_nonce_bytes,
        );

        // Compute final EIP-712 payload
        let eip712_payload = compute_eip712_payload(DOMAIN_SEPARATOR, message_hash);

        // Verify ECDSA signature
        assert(
            std::ecdsa_secp256k1::verify_signature(
                public_key.x,
                public_key.y,
                ecdsa_signature,
                eip712_payload,
            ),
            "Invalid EIP-712 signature",
        );

        // Handle fee payment
        if fee_payment_method == 1 {
            // PREEXISTING_FEE_JUICE
            self.context.set_as_fee_payer();
            self.context.end_setup();
        } else if fee_payment_method == 2 {
            // FEE_JUICE_WITH_CLAIM
            self.context.set_as_fee_payer();
        }

        // Execute the calls
        app_payload.execute_calls(self.context);

        // Handle cancellability
        if cancellable {
            let tx_nullifier = poseidon2_hash_with_separator(
                [app_payload.tx_nonce],
                DOM_SEP__TX_NULLIFIER,
            );
            self.context.push_nullifier(tx_nullifier);
        }
    }

    // =========================================================================
    // Authwit Verification
    // =========================================================================

    /// Verify a private authorization witness for EIP-712 signed authwits.
    ///
    /// This function is called by other contracts (e.g., Token.transfer_from)
    /// when they need authorization to act on behalf of this account.
    #[external("private")]
    #[noinitcheck]
    #[view]
    fn verify_private_authwit(inner_hash: Field) -> Field {
        // Load public key from storage
        let public_key = self.storage.signing_public_key.get_note();

        // Load EIP-712 authwit witness from capsule
        // Safety: Capsule data will be validated below
        let witness: Eip712AuthwitWitness = unsafe {
            load_eip712_authwit_witness(self.address).expect(
                f"EIP-712 authwit witness capsule not found",
            )
        };

        // =====================================================================
        // Step 1: Verify witness inner_hash matches the parameter
        // =====================================================================
        assert(
            witness.inner_hash == inner_hash,
            "Authwit witness inner_hash does not match request",
        );

        // =====================================================================
        // Step 2: Verify the inner_hash can be reconstructed from witness data
        // =====================================================================
        // Note: Authwits are typically used for private function authorization (approvals, transfers)
        // so we use is_public=false here. The inner_hash is computed with FUNCTION_ARGS separator.
        let computed_args_hash = compute_aztec_args_hash(
            witness.function_args,
            witness.args_length,
            false, // Authwits use FUNCTION_ARGS separator (private function pattern)
            0, // No selector for private functions
        );

        let computed_selector =
            compute_function_selector(witness.function_signature, witness.signature_length);

        let reconstructed_inner_hash = compute_inner_hash(
            witness.target_address,
            computed_selector,
            computed_args_hash,
        );

        assert(
            reconstructed_inner_hash == inner_hash,
            "Authwit witness data does not match inner_hash",
        );

        // =====================================================================
        // Step 3: Compute EIP-712 FunctionCallAuthorization hash
        // =====================================================================

        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        // Compute hashStruct(FunctionCall)
        // Note: selector is NOT included in EIP-712 hash - it's derived from signature
        // Authwits are used for private function authorization, so is_private = true
        let target_bytes = field_to_bytes32(witness.target_address);
        let function_call_hash = hash_function_call(
            target_bytes,
            witness.function_signature,
            witness.signature_length,
            witness.function_args,
            witness.args_length,
            true, // is_private: authwits are for private functions
        );

        // Compute hashStruct(AuthwitAppDomain)
        let chain_id_bytes = field_to_bytes32(witness.chain_id);
        let verifying_contract_bytes = field_to_bytes32(witness.verifying_contract);
        let authwit_domain_hash = hash_authwit_app_domain(chain_id_bytes, verifying_contract_bytes);

        // Compute hashStruct(FunctionCallAuthorization)
        let message_hash =
            hash_function_call_authorization(authwit_domain_hash, function_call_hash);

        // Compute final EIP-712 payload
        let eip712_payload = compute_eip712_payload(DOMAIN_SEPARATOR, message_hash);

        // =====================================================================
        // Step 4: Verify ECDSA signature
        // =====================================================================
        assert(
            std::ecdsa_secp256k1::verify_signature(
                public_key.x,
                public_key.y,
                ecdsa_signature,
                eip712_payload,
            ),
            "Invalid EIP-712 authwit signature",
        );

        // Return IS_VALID_SELECTOR (0x47dacd73) on success per AccountInterface spec
        0x47dacd73
    }

}
