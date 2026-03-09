/**
 * EIP-712 V2 Account Contract
 *
 * V2 of the EIP-712 account contract introduces variable argument types:
 * each argument can be bytes32, uint256, or address, enabling human-readable
 * display in MetaMask (e.g., addresses as address type instead of uint256 decimals).
 *
 * Key differences from V1:
 * - Per-call-count entrypoints (entrypoint_1 through entrypoint_4)
 * - Per-slot FunctionCallN->ArgumentsN types
 * - Variable argument types per function call (not fixed uint256[])
 * - Merkle tree whitelist constraining valid type_hash(FunctionCall) values
 * - AccountData and TxMetadata sub-structs in the authorization message
 * - Per-call is_public, hide_msg_sender, is_static flags in EIP-712
 */

use ::aztec::macros::aztec;

mod ecdsa_public_key_note;
mod eip712_v2;
mod test;

#[aztec]
pub contract Eip712AccountV2 {
    use ::aztec::{
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
    use crate::eip712_v2::{
        AppPayload1, AppPayload2, AppPayload3, AppPayload4,
        APP_PAYLOAD_1_SERIALIZED_LEN, APP_PAYLOAD_2_SERIALIZED_LEN,
        APP_PAYLOAD_3_SERIALIZED_LEN, APP_PAYLOAD_4_SERIALIZED_LEN,
        MERKLE_ROOT_FC_AUTH,
        Eip712WitnessV2_1, Eip712WitnessV2_2, Eip712WitnessV2_3, Eip712WitnessV2_4,
        Eip712AuthwitWitnessV2,
        load_eip712_witness_v2_1, load_eip712_witness_v2_2,
        load_eip712_witness_v2_3, load_eip712_witness_v2_4,
        load_eip712_authwit_witness_v2,
        get_merkle_root_fc,
        compute_aztec_args_hash, compute_eip712_payload, compute_function_selector,
        compute_inner_hash, type_hash_to_field,
        verify_arguments_whitelist,
        extract_args_hash, extract_function_selector, extract_target_address, extract_is_public,
    };

    // =========================================================================
    // Constants
    // =========================================================================

    // Pre-computed domain separator for "Aztec" rollup with chainId=31337
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
    // Entrypoint_1 (1 call)
    // =========================================================================

    #[external("private")]
    #[noinitcheck]
    #[allow_phase_change]
    fn entrypoint_1(app_payload: AppPayload1, fee_payment_method: u8, cancellable: bool) {
        // Safety: The sender for tags is only used for unconstrained tagging
        unsafe { set_sender_for_tags(self.address) };

        let public_key = self.storage.signing_public_key.get_note();

        // Safety: Capsule data will be validated against AppPayload below
        let witness: Eip712WitnessV2_1 = unsafe {
            load_eip712_witness_v2_1(self.address).expect(
                f"EIP-712 V2 witness capsule not found",
            )
        };

        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        let serialized_payload: [Field; APP_PAYLOAD_1_SERIALIZED_LEN] = app_payload.serialize();

        let mut has_any_call = false;

        for call_idx in 0..1 {
            let stored_target = extract_target_address(serialized_payload, call_idx);

            // Verify FC type_hash via per-slot Merkle tree
            let fc_type_hash_field = type_hash_to_field(witness.fc_type_hashes[call_idx]);
            verify_arguments_whitelist(
                fc_type_hash_field,
                witness.merkle_proofs[call_idx],
                witness.merkle_leaf_indices[call_idx],
                get_merkle_root_fc(call_idx),
            );

            if stored_target != 0 {
                has_any_call = true;

                assert(
                    witness.target_addresses[call_idx] == stored_target,
                    "V2 target_address mismatch with AppPayload",
                );

                let computed_selector = compute_function_selector(
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                );
                let stored_selector = extract_function_selector(serialized_payload, call_idx);
                assert(
                    computed_selector == stored_selector,
                    "V2 function_selector mismatch with AppPayload",
                );

                let is_public = extract_is_public(serialized_payload, call_idx);
                let computed_args_hash = compute_aztec_args_hash(
                    witness.function_args[call_idx],
                    witness.args_lengths[call_idx],
                    is_public,
                    computed_selector as Field,
                );
                let stored_args_hash = extract_args_hash(serialized_payload, call_idx);
                assert(
                    computed_args_hash == stored_args_hash,
                    "V2 args_hash mismatch with AppPayload",
                );
            }
        }

        assert(has_any_call, "AppPayload must have at least one function call");

        // Assemble entrypoint_data from precomputed hashes
        // entrypoint_type_hash(32) + account_data_hash(32) + 1*call_hash(32) + tx_metadata_hash(32) = 128 bytes
        let mut entrypoint_data: [u8; 128] = [0; 128];
        for i in 0..32 { entrypoint_data[i] = witness.entrypoint_type_hash[i]; }
        for i in 0..32 { entrypoint_data[32 + i] = witness.account_data_hash[i]; }
        for call_idx in 0..1 {
            for i in 0..32 { entrypoint_data[64 + call_idx * 32 + i] = witness.call_hashes[call_idx][i]; }
        }
        for i in 0..32 { entrypoint_data[96 + i] = witness.tx_metadata_hash[i]; }
        let message_hash = keccak256::keccak256(entrypoint_data, 128);

        let eip712_payload = compute_eip712_payload(DOMAIN_SEPARATOR, message_hash);

        assert(
            std::ecdsa_secp256k1::verify_signature(
                public_key.x, public_key.y, ecdsa_signature, eip712_payload,
            ),
            "Invalid EIP-712 V2 signature",
        );

        if fee_payment_method == 1 {
            self.context.set_as_fee_payer();
            self.context.end_setup();
        } else if fee_payment_method == 2 {
            self.context.set_as_fee_payer();
        }

        app_payload.execute_calls(self.context);

        if cancellable {
            let tx_nullifier = poseidon2_hash_with_separator([app_payload.tx_nonce], DOM_SEP__TX_NULLIFIER);
            self.context.push_nullifier(tx_nullifier);
        }
    }

    // =========================================================================
    // Entrypoint_2 (2 calls)
    // =========================================================================

    #[external("private")]
    #[noinitcheck]
    #[allow_phase_change]
    fn entrypoint_2(app_payload: AppPayload2, fee_payment_method: u8, cancellable: bool) {
        // Safety: The sender for tags is only used for unconstrained tagging
        unsafe { set_sender_for_tags(self.address) };

        let public_key = self.storage.signing_public_key.get_note();

        // Safety: Capsule data will be validated against AppPayload below
        let witness: Eip712WitnessV2_2 = unsafe {
            load_eip712_witness_v2_2(self.address).expect(
                f"EIP-712 V2 witness capsule not found",
            )
        };

        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        let serialized_payload: [Field; APP_PAYLOAD_2_SERIALIZED_LEN] = app_payload.serialize();

        let mut has_any_call = false;

        for call_idx in 0..2 {
            let stored_target = extract_target_address(serialized_payload, call_idx);

            let fc_type_hash_field = type_hash_to_field(witness.fc_type_hashes[call_idx]);
            verify_arguments_whitelist(
                fc_type_hash_field,
                witness.merkle_proofs[call_idx],
                witness.merkle_leaf_indices[call_idx],
                get_merkle_root_fc(call_idx),
            );

            if stored_target != 0 {
                has_any_call = true;

                assert(
                    witness.target_addresses[call_idx] == stored_target,
                    "V2 target_address mismatch with AppPayload",
                );

                let computed_selector = compute_function_selector(
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                );
                let stored_selector = extract_function_selector(serialized_payload, call_idx);
                assert(
                    computed_selector == stored_selector,
                    "V2 function_selector mismatch with AppPayload",
                );

                let is_public = extract_is_public(serialized_payload, call_idx);
                let computed_args_hash = compute_aztec_args_hash(
                    witness.function_args[call_idx],
                    witness.args_lengths[call_idx],
                    is_public,
                    computed_selector as Field,
                );
                let stored_args_hash = extract_args_hash(serialized_payload, call_idx);
                assert(
                    computed_args_hash == stored_args_hash,
                    "V2 args_hash mismatch with AppPayload",
                );
            }
        }

        assert(has_any_call, "AppPayload must have at least one function call");

        // Assemble entrypoint_data from precomputed hashes
        // entrypoint_type_hash(32) + account_data_hash(32) + 2*call_hash(32) + tx_metadata_hash(32) = 160 bytes
        let mut entrypoint_data: [u8; 160] = [0; 160];
        for i in 0..32 { entrypoint_data[i] = witness.entrypoint_type_hash[i]; }
        for i in 0..32 { entrypoint_data[32 + i] = witness.account_data_hash[i]; }
        for call_idx in 0..2 {
            for i in 0..32 { entrypoint_data[64 + call_idx * 32 + i] = witness.call_hashes[call_idx][i]; }
        }
        for i in 0..32 { entrypoint_data[128 + i] = witness.tx_metadata_hash[i]; }
        let message_hash = keccak256::keccak256(entrypoint_data, 160);

        let eip712_payload = compute_eip712_payload(DOMAIN_SEPARATOR, message_hash);

        assert(
            std::ecdsa_secp256k1::verify_signature(
                public_key.x, public_key.y, ecdsa_signature, eip712_payload,
            ),
            "Invalid EIP-712 V2 signature",
        );

        if fee_payment_method == 1 {
            self.context.set_as_fee_payer();
            self.context.end_setup();
        } else if fee_payment_method == 2 {
            self.context.set_as_fee_payer();
        }

        app_payload.execute_calls(self.context);

        if cancellable {
            let tx_nullifier = poseidon2_hash_with_separator([app_payload.tx_nonce], DOM_SEP__TX_NULLIFIER);
            self.context.push_nullifier(tx_nullifier);
        }
    }

    // =========================================================================
    // Entrypoint_3 (3 calls)
    // =========================================================================

    #[external("private")]
    #[noinitcheck]
    #[allow_phase_change]
    fn entrypoint_3(app_payload: AppPayload3, fee_payment_method: u8, cancellable: bool) {
        // Safety: The sender for tags is only used for unconstrained tagging
        unsafe { set_sender_for_tags(self.address) };

        let public_key = self.storage.signing_public_key.get_note();

        // Safety: Capsule data will be validated against AppPayload below
        let witness: Eip712WitnessV2_3 = unsafe {
            load_eip712_witness_v2_3(self.address).expect(
                f"EIP-712 V2 witness capsule not found",
            )
        };

        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        let serialized_payload: [Field; APP_PAYLOAD_3_SERIALIZED_LEN] = app_payload.serialize();

        let mut has_any_call = false;

        for call_idx in 0..3 {
            let stored_target = extract_target_address(serialized_payload, call_idx);

            let fc_type_hash_field = type_hash_to_field(witness.fc_type_hashes[call_idx]);
            verify_arguments_whitelist(
                fc_type_hash_field,
                witness.merkle_proofs[call_idx],
                witness.merkle_leaf_indices[call_idx],
                get_merkle_root_fc(call_idx),
            );

            if stored_target != 0 {
                has_any_call = true;

                assert(
                    witness.target_addresses[call_idx] == stored_target,
                    "V2 target_address mismatch with AppPayload",
                );

                let computed_selector = compute_function_selector(
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                );
                let stored_selector = extract_function_selector(serialized_payload, call_idx);
                assert(
                    computed_selector == stored_selector,
                    "V2 function_selector mismatch with AppPayload",
                );

                let is_public = extract_is_public(serialized_payload, call_idx);
                let computed_args_hash = compute_aztec_args_hash(
                    witness.function_args[call_idx],
                    witness.args_lengths[call_idx],
                    is_public,
                    computed_selector as Field,
                );
                let stored_args_hash = extract_args_hash(serialized_payload, call_idx);
                assert(
                    computed_args_hash == stored_args_hash,
                    "V2 args_hash mismatch with AppPayload",
                );
            }
        }

        assert(has_any_call, "AppPayload must have at least one function call");

        // Assemble entrypoint_data from precomputed hashes
        // entrypoint_type_hash(32) + account_data_hash(32) + 3*call_hash(32) + tx_metadata_hash(32) = 192 bytes
        let mut entrypoint_data: [u8; 192] = [0; 192];
        for i in 0..32 { entrypoint_data[i] = witness.entrypoint_type_hash[i]; }
        for i in 0..32 { entrypoint_data[32 + i] = witness.account_data_hash[i]; }
        for call_idx in 0..3 {
            for i in 0..32 { entrypoint_data[64 + call_idx * 32 + i] = witness.call_hashes[call_idx][i]; }
        }
        for i in 0..32 { entrypoint_data[160 + i] = witness.tx_metadata_hash[i]; }
        let message_hash = keccak256::keccak256(entrypoint_data, 192);

        let eip712_payload = compute_eip712_payload(DOMAIN_SEPARATOR, message_hash);

        assert(
            std::ecdsa_secp256k1::verify_signature(
                public_key.x, public_key.y, ecdsa_signature, eip712_payload,
            ),
            "Invalid EIP-712 V2 signature",
        );

        if fee_payment_method == 1 {
            self.context.set_as_fee_payer();
            self.context.end_setup();
        } else if fee_payment_method == 2 {
            self.context.set_as_fee_payer();
        }

        app_payload.execute_calls(self.context);

        if cancellable {
            let tx_nullifier = poseidon2_hash_with_separator([app_payload.tx_nonce], DOM_SEP__TX_NULLIFIER);
            self.context.push_nullifier(tx_nullifier);
        }
    }

    // =========================================================================
    // Entrypoint_4 (4 calls)
    // =========================================================================

    #[external("private")]
    #[noinitcheck]
    #[allow_phase_change]
    fn entrypoint_4(app_payload: AppPayload4, fee_payment_method: u8, cancellable: bool) {
        // Safety: The sender for tags is only used for unconstrained tagging
        unsafe { set_sender_for_tags(self.address) };

        let public_key = self.storage.signing_public_key.get_note();

        // Safety: Capsule data will be validated against AppPayload below
        let witness: Eip712WitnessV2_4 = unsafe {
            load_eip712_witness_v2_4(self.address).expect(
                f"EIP-712 V2 witness capsule not found",
            )
        };

        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        let serialized_payload: [Field; APP_PAYLOAD_4_SERIALIZED_LEN] = app_payload.serialize();

        let mut has_any_call = false;

        for call_idx in 0..4 {
            let stored_target = extract_target_address(serialized_payload, call_idx);

            let fc_type_hash_field = type_hash_to_field(witness.fc_type_hashes[call_idx]);
            verify_arguments_whitelist(
                fc_type_hash_field,
                witness.merkle_proofs[call_idx],
                witness.merkle_leaf_indices[call_idx],
                get_merkle_root_fc(call_idx),
            );

            if stored_target != 0 {
                has_any_call = true;

                assert(
                    witness.target_addresses[call_idx] == stored_target,
                    "V2 target_address mismatch with AppPayload",
                );

                let computed_selector = compute_function_selector(
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                );
                let stored_selector = extract_function_selector(serialized_payload, call_idx);
                assert(
                    computed_selector == stored_selector,
                    "V2 function_selector mismatch with AppPayload",
                );

                let is_public = extract_is_public(serialized_payload, call_idx);
                let computed_args_hash = compute_aztec_args_hash(
                    witness.function_args[call_idx],
                    witness.args_lengths[call_idx],
                    is_public,
                    computed_selector as Field,
                );
                let stored_args_hash = extract_args_hash(serialized_payload, call_idx);
                assert(
                    computed_args_hash == stored_args_hash,
                    "V2 args_hash mismatch with AppPayload",
                );
            }
        }

        assert(has_any_call, "AppPayload must have at least one function call");

        // Assemble entrypoint_data from precomputed hashes
        // entrypoint_type_hash(32) + account_data_hash(32) + 4*call_hash(32) + tx_metadata_hash(32) = 224 bytes
        let mut entrypoint_data: [u8; 224] = [0; 224];
        for i in 0..32 { entrypoint_data[i] = witness.entrypoint_type_hash[i]; }
        for i in 0..32 { entrypoint_data[32 + i] = witness.account_data_hash[i]; }
        for call_idx in 0..4 {
            for i in 0..32 { entrypoint_data[64 + call_idx * 32 + i] = witness.call_hashes[call_idx][i]; }
        }
        for i in 0..32 { entrypoint_data[192 + i] = witness.tx_metadata_hash[i]; }
        let message_hash = keccak256::keccak256(entrypoint_data, 224);

        let eip712_payload = compute_eip712_payload(DOMAIN_SEPARATOR, message_hash);

        assert(
            std::ecdsa_secp256k1::verify_signature(
                public_key.x, public_key.y, ecdsa_signature, eip712_payload,
            ),
            "Invalid EIP-712 V2 signature",
        );

        if fee_payment_method == 1 {
            self.context.set_as_fee_payer();
            self.context.end_setup();
        } else if fee_payment_method == 2 {
            self.context.set_as_fee_payer();
        }

        app_payload.execute_calls(self.context);

        if cancellable {
            let tx_nullifier = poseidon2_hash_with_separator([app_payload.tx_nonce], DOM_SEP__TX_NULLIFIER);
            self.context.push_nullifier(tx_nullifier);
        }
    }

    // =========================================================================
    // Authwit Verification (with precomputed hashes)
    // =========================================================================

    #[external("private")]
    #[noinitcheck]
    #[view]
    fn verify_private_authwit(inner_hash: Field) -> pub Field {
        let public_key = self.storage.signing_public_key.get_note();

        let witness: Eip712AuthwitWitnessV2 = unsafe {
            load_eip712_authwit_witness_v2(self.address).expect(
                f"EIP-712 V2 authwit witness capsule not found",
            )
        };

        assert(
            witness.inner_hash == inner_hash,
            "V2 authwit witness inner_hash does not match request",
        );

        // Compute function selector once - used for both args_hash and inner_hash
        let computed_selector = compute_function_selector(
            witness.function_signature,
            witness.signature_length,
        );

        let computed_args_hash = compute_aztec_args_hash(
            witness.function_args,
            witness.args_length,
            witness.is_public,
            computed_selector as Field,
        );

        let reconstructed_inner_hash = compute_inner_hash(
            witness.target_address,
            computed_selector,
            computed_args_hash,
        );

        assert(
            reconstructed_inner_hash == inner_hash,
            "V2 authwit witness data does not match inner_hash",
        );

        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        // Verify fc_auth_type_hash via Merkle tree
        let fc_auth_type_hash_field = type_hash_to_field(witness.fc_auth_type_hash);
        verify_arguments_whitelist(
            fc_auth_type_hash_field,
            witness.merkle_proof,
            witness.merkle_leaf_index,
            MERKLE_ROOT_FC_AUTH,
        );

        // Use precomputed authwit message hash
        let eip712_payload = compute_eip712_payload(DOMAIN_SEPARATOR, witness.authwit_message_hash);

        assert(
            std::ecdsa_secp256k1::verify_signature(
                public_key.x, public_key.y, ecdsa_signature, eip712_payload,
            ),
            "Invalid EIP-712 V2 authwit signature",
        );

        0x47dacd73
    }
}
