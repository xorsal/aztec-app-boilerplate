/**
 * EIP-712 V2 Account Contract
 *
 * V2 of the EIP-712 account contract introduces variable argument types:
 * each argument can be bytes32, uint256, or int256, enabling human-readable
 * display in MetaMask (e.g., addresses as bytes32 hex instead of uint256 decimals).
 *
 * Key differences from V1:
 * - 4-call entrypoint with unified FunctionCall->Arguments type
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
        AppPayload2, ACCOUNT_MAX_CALLS, APP_PAYLOAD_SERIALIZED_LEN,
        MERKLE_ROOT_FC, MERKLE_ROOT_FC_AUTH,
        Eip712WitnessV2_2, Eip712AuthwitWitnessV2,
        compute_aztec_args_hash, compute_eip712_payload, compute_function_selector,
        compute_inner_hash, type_hash_to_field,
        verify_arguments_whitelist, hash_struct_arguments,
        hash_struct_function_call_v2, hash_struct_account_data, hash_struct_tx_metadata,
        hash_struct_authwit_app_domain, hash_string, field_to_bytes32,
        build_encode_type_entrypoint,
        extract_args_hash, extract_function_selector, extract_target_address, extract_is_public,
        load_eip712_witness_v2_2, load_eip712_authwit_witness_v2,
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
    // Entrypoint (4-call unified FunctionCall type with variable argument types)
    // =========================================================================

    #[external("private")]
    #[noinitcheck]
    #[allow_phase_change]
    fn entrypoint(app_payload: AppPayload2, fee_payment_method: u8, cancellable: bool) {
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

        let serialized_payload: [Field; APP_PAYLOAD_SERIALIZED_LEN] = app_payload.serialize();

        // =====================================================================
        // Verify all calls and compute EIP-712 hashes
        // =====================================================================

        // Verify shared FunctionCall type_hash via Merkle tree ONCE (all calls share the same type)
        let fc_type_hash_field = type_hash_to_field(witness.fc_type_hash);
        verify_arguments_whitelist(
            fc_type_hash_field,
            witness.merkle_proof,
            witness.merkle_leaf_index,
            MERKLE_ROOT_FC,
        );

        let mut call_hashes: [[u8; 32]; ACCOUNT_MAX_CALLS] = [[0; 32]; ACCOUNT_MAX_CALLS];
        let mut has_any_call = false;

        for call_idx in 0..ACCOUNT_MAX_CALLS {
            let stored_target = extract_target_address(serialized_payload, call_idx);

            if stored_target != 0 {
                has_any_call = true;

                // 1. Verify target address matches
                assert(
                    witness.target_addresses[call_idx] == stored_target,
                    "V2 target_address mismatch with AppPayload",
                );

                // 2. Compute selector from function signature
                let computed_selector = compute_function_selector(
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                );
                let stored_selector = extract_function_selector(serialized_payload, call_idx);
                assert(
                    computed_selector == stored_selector,
                    "V2 function_selector mismatch with AppPayload",
                );

                // 3. Verify args_hash matches
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

                // 4. Compute hashStruct(Arguments) using shared type_hash
                let args_struct_hash = hash_struct_arguments(
                    witness.args_type_hash,
                    witness.function_args[call_idx],
                    witness.args_lengths[call_idx],
                );

                // 5. Compute hashStruct(FunctionCall) using shared type_hash
                let target_bytes = field_to_bytes32(witness.target_addresses[call_idx]);
                let sig_hash = hash_string(
                    witness.function_signatures[call_idx],
                    witness.signature_lengths[call_idx],
                );
                call_hashes[call_idx] = hash_struct_function_call_v2(
                    witness.fc_type_hash,
                    target_bytes,
                    sig_hash,
                    args_struct_hash,
                    witness.is_public[call_idx],
                    witness.hide_msg_sender[call_idx],
                    witness.is_static[call_idx],
                );
            } else {
                // Empty call slot - still needs valid EIP-712 hash
                let empty_args: [Field; 20] = [0; 20];
                let empty_args_struct_hash = hash_struct_arguments(
                    witness.args_type_hash,
                    empty_args,
                    0,
                );

                let zero_bytes: [u8; 32] = [0; 32];
                let empty_sig_hash = hash_string([0; 128], 0);

                call_hashes[call_idx] = hash_struct_function_call_v2(
                    witness.fc_type_hash,
                    zero_bytes,
                    empty_sig_hash,
                    empty_args_struct_hash,
                    false,
                    false,
                    false,
                );
            }
        }

        assert(has_any_call, "AppPayload must have at least one function call");

        // =====================================================================
        // Compute EntrypointAuthorization hash
        // =====================================================================

        // Build full encode_type for EntrypointAuthorization (single shared args type)
        let (entrypoint_encode_type, entrypoint_encode_type_len) = build_encode_type_entrypoint(
            witness.args_type_string,
            witness.args_type_string_length,
        );
        let entrypoint_type_hash = keccak256::keccak256(entrypoint_encode_type, entrypoint_encode_type_len);

        // Compute hashStruct(AccountData)
        let account_address_bytes = field_to_bytes32(witness.account_address);
        let account_data_hash = hash_struct_account_data(
            account_address_bytes,
            witness.wallet_name,
            witness.wallet_name_length,
            witness.wallet_version,
            witness.wallet_version_length,
        );

        // Compute hashStruct(TxMetadata)
        let tx_nonce_bytes = field_to_bytes32(app_payload.tx_nonce);
        let tx_metadata_hash = hash_struct_tx_metadata(
            fee_payment_method,
            cancellable,
            tx_nonce_bytes,
        );

        // Compute hashStruct(EntrypointAuthorization)
        // typeHash || accountDataHash || fc1Hash || fc2Hash || fc3Hash || fc4Hash || txMetadataHash
        let mut entrypoint_data: [u8; 224] = [0; 224];
        for i in 0..32 {
            entrypoint_data[i] = entrypoint_type_hash[i];
        }
        for i in 0..32 {
            entrypoint_data[32 + i] = account_data_hash[i];
        }
        for call_idx in 0..ACCOUNT_MAX_CALLS {
            for i in 0..32 {
                entrypoint_data[64 + call_idx * 32 + i] = call_hashes[call_idx][i];
            }
        }
        for i in 0..32 {
            entrypoint_data[192 + i] = tx_metadata_hash[i];
        }
        let message_hash = keccak256::keccak256(entrypoint_data, 224);

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
            "Invalid EIP-712 V2 signature",
        );

        // Handle fee payment
        if fee_payment_method == 1 {
            self.context.set_as_fee_payer();
            self.context.end_setup();
        } else if fee_payment_method == 2 {
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
    // Authwit Verification (with variable argument types)
    // =========================================================================

    #[external("private")]
    #[noinitcheck]
    #[view]
    fn verify_private_authwit(inner_hash: Field) -> pub Field {
        let public_key = self.storage.signing_public_key.get_note();

        // Safety: Capsule data will be validated below
        let witness: Eip712AuthwitWitnessV2 = unsafe {
            load_eip712_authwit_witness_v2(self.address).expect(
                f"EIP-712 V2 authwit witness capsule not found",
            )
        };

        // Step 1: Verify witness inner_hash matches the parameter
        assert(
            witness.inner_hash == inner_hash,
            "V2 authwit witness inner_hash does not match request",
        );

        // Step 2: Verify inner_hash can be reconstructed
        let computed_args_hash = compute_aztec_args_hash(
            witness.function_args,
            witness.args_length,
            witness.is_public,
            if witness.is_public {
                compute_function_selector(witness.function_signature, witness.signature_length) as Field
            } else {
                0
            },
        );

        let computed_selector = compute_function_selector(
            witness.function_signature,
            witness.signature_length,
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

        // Step 3: Compute EIP-712 FunctionCallAuthorization hash
        let mut ecdsa_signature: [u8; 64] = [0; 64];
        for i in 0..32 {
            ecdsa_signature[i] = witness.signature_r[i];
            ecdsa_signature[32 + i] = witness.signature_s[i];
        }

        // Verify type_hash(FunctionCallAuthorization) via Merkle tree (Approach 2)
        let fc_auth_type_hash_field = type_hash_to_field(witness.fc_auth_type_hash);
        verify_arguments_whitelist(
            fc_auth_type_hash_field,
            witness.merkle_proof,
            witness.merkle_leaf_index,
            MERKLE_ROOT_FC_AUTH,
        );

        // Compute hashStruct(Arguments) using oracle-provided type_hash
        let args_struct_hash = hash_struct_arguments(
            witness.args_type_hash,
            witness.function_args,
            witness.args_length,
        );

        // Compute hashStruct(AuthwitAppDomain)
        let chain_id_bytes = field_to_bytes32(witness.chain_id);
        let verifying_contract_bytes = field_to_bytes32(witness.verifying_contract);
        let authwit_domain_hash = hash_struct_authwit_app_domain(chain_id_bytes, verifying_contract_bytes);

        // Compute hashStruct(FunctionCallAuthorization)
        // typeHash || appDomainHash || contract || sigHash || argsHash || isPublic
        let target_bytes = field_to_bytes32(witness.target_address);
        let sig_hash = hash_string(witness.function_signature, witness.signature_length);

        let mut authwit_data: [u8; 192] = [0; 192];
        for i in 0..32 {
            authwit_data[i] = witness.fc_auth_type_hash[i];
        }
        for i in 0..32 {
            authwit_data[32 + i] = authwit_domain_hash[i];
        }
        for i in 0..32 {
            authwit_data[64 + i] = target_bytes[i];
        }
        for i in 0..32 {
            authwit_data[96 + i] = sig_hash[i];
        }
        for i in 0..32 {
            authwit_data[128 + i] = args_struct_hash[i];
        }
        if witness.is_public {
            authwit_data[191] = 1;
        }
        let message_hash = keccak256::keccak256(authwit_data, 192);

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
            "Invalid EIP-712 V2 authwit signature",
        );

        // Return IS_VALID_SELECTOR
        0x47dacd73
    }
}
