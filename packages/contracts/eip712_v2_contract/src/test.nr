use crate::eip712_v2::{
    ACCOUNT_DATA_DEF, ACCOUNT_DATA_DEF_LEN,
    ACCOUNT_DATA_TYPE_HASH, TX_METADATA_TYPE_HASH,
    FC_PRIMARY, FC_PRIMARY_LEN,
    MAX_ARGS_TYPE_STRING_LEN, MAX_SERIALIZED_ARGS, MAX_SIGNATURE_SIZE,
    compute_type_hash, type_hash_to_field, hash_string, field_to_bytes32,
    hash_struct_arguments, hash_struct_account_data, hash_struct_tx_metadata,
    build_encode_type_fc, build_encode_type_entrypoint, compute_eip712_payload,
};

// =============================================================================
// 1. compute_type_hash
// =============================================================================

#[test]
fn test_compute_type_hash_account_data() {
    // compute_type_hash of "AccountData(bytes32 address,string walletName,string version)"
    // should match the comptime ACCOUNT_DATA_TYPE_HASH
    let result = compute_type_hash(ACCOUNT_DATA_DEF, ACCOUNT_DATA_DEF_LEN);
    assert(result == ACCOUNT_DATA_TYPE_HASH, "AccountData type hash mismatch");
}

#[test]
fn test_compute_type_hash_tx_metadata() {
    // compute_type_hash of "TxMetadata(uint8 feePaymentMethod,bool cancellable,uint256 txNonce)"
    // should match the comptime TX_METADATA_TYPE_HASH
    let tx_metadata_def: [u8; 67] = [
        0x54, 0x78, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x28, 0x75,
        0x69, 0x6e, 0x74, 0x38, 0x20, 0x66, 0x65, 0x65, 0x50, 0x61, 0x79, 0x6d,
        0x65, 0x6e, 0x74, 0x4d, 0x65, 0x74, 0x68, 0x6f, 0x64, 0x2c, 0x62, 0x6f,
        0x6f, 0x6c, 0x20, 0x63, 0x61, 0x6e, 0x63, 0x65, 0x6c, 0x6c, 0x61, 0x62,
        0x6c, 0x65, 0x2c, 0x75, 0x69, 0x6e, 0x74, 0x32, 0x35, 0x36, 0x20, 0x74,
        0x78, 0x4e, 0x6f, 0x6e, 0x63, 0x65, 0x29,
    ];
    let result = compute_type_hash(tx_metadata_def, 67);
    assert(result == TX_METADATA_TYPE_HASH, "TxMetadata type hash mismatch");
}

#[test]
fn test_compute_type_hash_arguments1() {
    // keccak256("Arguments1(bytes32 argument1)")
    let args1_def: [u8; 29] = [
        0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x31, 0x28, 0x62,
        0x79, 0x74, 0x65, 0x73, 0x33, 0x32, 0x20, 0x61, 0x72, 0x67, 0x75, 0x6d,
        0x65, 0x6e, 0x74, 0x31, 0x29,
    ];
    let expected: [u8; 32] = [
        0x01, 0xf9, 0xa6, 0x06, 0xd1, 0x0f, 0x6e, 0x53, 0x42, 0xbe, 0x7a, 0x56,
        0xbd, 0xc8, 0x43, 0x91, 0xa9, 0x63, 0x9b, 0x39, 0x27, 0x36, 0x61, 0x6b,
        0x37, 0xc3, 0x2c, 0x75, 0x66, 0x07, 0x76, 0x63,
    ];
    let result = compute_type_hash(args1_def, 29);
    assert(result == expected, "Arguments1 type hash mismatch");
}

// =============================================================================
// 2. type_hash_to_field
// =============================================================================

#[test]
fn test_type_hash_to_field() {
    // AccountData type hash = 0x04e419c4...261c
    // Since this value < BN254 prime, mod reduction is identity
    let result = type_hash_to_field(ACCOUNT_DATA_TYPE_HASH);

    // Reconstruct expected field from bytes manually
    let mut expected: Field = 0;
    for i in 0..32 {
        expected = expected * 256 + (ACCOUNT_DATA_TYPE_HASH[i] as Field);
    }
    assert(result == expected, "type_hash_to_field mismatch");
}

#[test]
fn test_type_hash_to_field_known_value() {
    // A small known hash to verify: all zeros except last byte = 0x2a (42)
    let mut small_hash: [u8; 32] = [0; 32];
    small_hash[31] = 42;
    let result = type_hash_to_field(small_hash);
    assert(result == 42, "type_hash_to_field for small value mismatch");
}

// =============================================================================
// 3. hash_string
// =============================================================================

#[test]
fn test_hash_string_increment() {
    // keccak256("increment()") = 0xd09de08a...ed8d
    let mut sig: [u8; 128] = [0; 128];
    // "increment()" = [0x69, 0x6e, 0x63, 0x72, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x28, 0x29]
    sig[0] = 0x69;
    sig[1] = 0x6e;
    sig[2] = 0x63;
    sig[3] = 0x72;
    sig[4] = 0x65;
    sig[5] = 0x6d;
    sig[6] = 0x65;
    sig[7] = 0x6e;
    sig[8] = 0x74;
    sig[9] = 0x28;
    sig[10] = 0x29;

    let expected: [u8; 32] = [
        0xd0, 0x9d, 0xe0, 0x8a, 0xb1, 0xa9, 0x74, 0xaa, 0xdf, 0x0a, 0x76, 0xe6,
        0xf9, 0x9a, 0x2e, 0xc2, 0x0e, 0x43, 0x1f, 0x22, 0xbb, 0xc1, 0x01, 0xa6,
        0xc3, 0xf7, 0x18, 0xe5, 0x36, 0x46, 0xed, 0x8d,
    ];
    let result = hash_string(sig, 11);
    assert(result == expected, "hash_string(increment()) mismatch");
}

// =============================================================================
// 4. hash_struct_arguments
// =============================================================================

#[test]
fn test_hash_struct_arguments_one_arg() {
    // type_hash = keccak256("Arguments1(bytes32 argument1)")
    let type_hash: [u8; 32] = [
        0x01, 0xf9, 0xa6, 0x06, 0xd1, 0x0f, 0x6e, 0x53, 0x42, 0xbe, 0x7a, 0x56,
        0xbd, 0xc8, 0x43, 0x91, 0xa9, 0x63, 0x9b, 0x39, 0x27, 0x36, 0x61, 0x6b,
        0x37, 0xc3, 0x2c, 0x75, 0x66, 0x07, 0x76, 0x63,
    ];

    let mut args: [Field; MAX_SERIALIZED_ARGS] = [0; MAX_SERIALIZED_ARGS];
    args[0] = 0x1234;

    let expected: [u8; 32] = [
        0x0b, 0x74, 0x4b, 0x70, 0xa2, 0x2c, 0x1d, 0x70, 0x9d, 0x9f, 0x75, 0xe4,
        0xcc, 0xd7, 0x14, 0x87, 0xcc, 0x77, 0xcf, 0xa6, 0xb0, 0xb8, 0x73, 0x44,
        0x63, 0xb8, 0x1b, 0xce, 0x88, 0x48, 0x21, 0xee,
    ];

    let result = hash_struct_arguments(type_hash, args, 1);
    assert(result == expected, "hash_struct_arguments mismatch");
}

// =============================================================================
// 5. hash_struct_account_data
// =============================================================================

#[test]
fn test_hash_struct_account_data() {
    // address = field_to_bytes32(0xabcd)
    let address = field_to_bytes32(0xabcd);

    // wallet_name = "TestWallet" (10 bytes)
    let mut wallet_name: [u8; MAX_SIGNATURE_SIZE] = [0; MAX_SIGNATURE_SIZE];
    let wn_bytes: [u8; 10] = [0x54, 0x65, 0x73, 0x74, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74];
    for i in 0..10 {
        wallet_name[i] = wn_bytes[i];
    }

    // version = "1.0.0" (5 bytes)
    let mut version: [u8; 32] = [0; 32];
    let v_bytes: [u8; 5] = [0x31, 0x2e, 0x30, 0x2e, 0x30];
    for i in 0..5 {
        version[i] = v_bytes[i];
    }

    let expected: [u8; 32] = [
        0x0a, 0x17, 0x79, 0x80, 0x03, 0xf9, 0x1e, 0x46, 0x94, 0x25, 0xd5, 0x0d,
        0x72, 0x98, 0x02, 0x15, 0x6f, 0x30, 0xed, 0x47, 0x65, 0x66, 0xf9, 0xee,
        0x06, 0x20, 0x07, 0x2f, 0x1a, 0xe3, 0xe8, 0x53,
    ];

    let result = hash_struct_account_data(address, wallet_name, 10, version, 5);
    assert(result == expected, "hash_struct_account_data mismatch");
}

// =============================================================================
// 6. hash_struct_tx_metadata
// =============================================================================

#[test]
fn test_hash_struct_tx_metadata() {
    // fee_payment_method=1, cancellable=true, tx_nonce=field_to_bytes32(42)
    let tx_nonce = field_to_bytes32(42);

    let expected: [u8; 32] = [
        0x80, 0x5f, 0xc3, 0x86, 0x1b, 0xbb, 0x26, 0x76, 0x18, 0x64, 0x22, 0x1a,
        0xf9, 0x18, 0xb6, 0x5f, 0x75, 0x96, 0x42, 0x1d, 0x91, 0x84, 0xc3, 0xb1,
        0xb0, 0xe5, 0x4c, 0x6b, 0xd1, 0xc7, 0x6a, 0xbd,
    ];

    let result = hash_struct_tx_metadata(1, true, tx_nonce);
    assert(result == expected, "hash_struct_tx_metadata mismatch");
}

// =============================================================================
// 7. field_to_bytes32
// =============================================================================

#[test]
fn test_field_to_bytes32_small() {
    let result = field_to_bytes32(42);
    // 42 in big-endian 32 bytes: 31 zeros then 0x2a
    for i in 0..31 {
        assert(result[i] == 0, "field_to_bytes32(42) should have leading zeros");
    }
    assert(result[31] == 42, "field_to_bytes32(42) last byte should be 42");
}

#[test]
fn test_field_to_bytes32_zero() {
    let result = field_to_bytes32(0);
    for i in 0..32 {
        assert(result[i] == 0, "field_to_bytes32(0) should be all zeros");
    }
}

#[test]
fn test_field_to_bytes32_0x1234() {
    let result = field_to_bytes32(0x1234);
    // 0x1234 = 4660 in big-endian: [..., 0x00, 0x12, 0x34]
    for i in 0..30 {
        assert(result[i] == 0, "field_to_bytes32(0x1234) leading zeros");
    }
    assert(result[30] == 0x12, "field_to_bytes32(0x1234) byte 30");
    assert(result[31] == 0x34, "field_to_bytes32(0x1234) byte 31");
}

// =============================================================================
// 8. build_encode_type_fc
// =============================================================================

#[test]
fn test_build_encode_type_fc() {
    // FC_PRIMARY + "Arguments(bytes32 argument1)" = 122 + 28 = 150 bytes
    let mut args_type_str: [u8; MAX_ARGS_TYPE_STRING_LEN] = [0; MAX_ARGS_TYPE_STRING_LEN];
    // "Arguments(bytes32 argument1)" = 28 bytes
    let args_bytes: [u8; 28] = [
        0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x28, 0x62, 0x79,
        0x74, 0x65, 0x73, 0x33, 0x32, 0x20, 0x61, 0x72, 0x67, 0x75, 0x6d, 0x65,
        0x6e, 0x74, 0x31, 0x29,
    ];
    for i in 0..28 {
        args_type_str[i] = args_bytes[i];
    }

    let (result, len) = build_encode_type_fc(args_type_str, 28);

    assert(len == 150, "build_encode_type_fc length should be 150");

    // Verify first part is FC_PRIMARY
    for i in 0..FC_PRIMARY_LEN {
        assert(result[i] == FC_PRIMARY[i], "FC_PRIMARY bytes mismatch");
    }

    // Verify second part is args definition
    for i in 0..28 {
        assert(
            result[FC_PRIMARY_LEN + i] == args_bytes[i],
            "args type string bytes mismatch in encode_type_fc",
        );
    }
}

// =============================================================================
// 9. build_encode_type_entrypoint
// =============================================================================

#[test]
fn test_build_encode_type_entrypoint() {
    // args_def = "Arguments(bytes32 argument1)" (28 bytes)
    let mut args_def: [u8; MAX_ARGS_TYPE_STRING_LEN] = [0; MAX_ARGS_TYPE_STRING_LEN];
    let a: [u8; 28] = [
        0x41, 0x72, 0x67, 0x75, 0x6d, 0x65, 0x6e, 0x74, 0x73, 0x28, 0x62, 0x79,
        0x74, 0x65, 0x73, 0x33, 0x32, 0x20, 0x61, 0x72, 0x67, 0x75, 0x6d, 0x65,
        0x6e, 0x74, 0x31, 0x29,
    ];
    for i in 0..28 {
        args_def[i] = a[i];
    }

    let (result, len) = build_encode_type_entrypoint(args_def, 28);

    // Expected length: 178 + 61 + 28 + 122 + 67 = 456
    assert(len == 456, "build_encode_type_entrypoint length should be 456");

    // Verify the result hashes to the expected type_hash
    let type_hash = keccak256::keccak256(result, len);
    let expected_hash: [u8; 32] = [
        0xf5, 0xf3, 0x52, 0xbe, 0xe5, 0xbf, 0xa8, 0x89, 0xe7, 0x5c, 0xf3, 0xd8,
        0xa5, 0xaf, 0xdc, 0x3d, 0x69, 0x60, 0x35, 0x3d, 0x04, 0x71, 0x5a, 0x15,
        0xeb, 0xcb, 0x71, 0x93, 0x53, 0x7a, 0xaa, 0xd7,
    ];
    assert(type_hash == expected_hash, "entrypoint encode_type hash mismatch");
}

// =============================================================================
// 10. compute_eip712_payload
// =============================================================================

#[test]
fn test_compute_eip712_payload() {
    // domain_separator from the contract constant
    let domain_separator: [u8; 32] = [
        0x0c, 0x4d, 0x2d, 0x20, 0x58, 0x3d, 0x2e, 0xe0, 0xc9, 0x40, 0xac, 0x27,
        0x89, 0xfd, 0x85, 0xe2, 0x75, 0x8b, 0xe2, 0xb7, 0x54, 0x6e, 0x62, 0x7e,
        0xfa, 0x99, 0xba, 0xb8, 0x98, 0xe5, 0xa1, 0x41,
    ];
    // message_hash = field_to_bytes32(999)
    let message_hash = field_to_bytes32(999);

    let expected: [u8; 32] = [
        0x20, 0xa9, 0x8d, 0x9c, 0xb7, 0xb2, 0x0b, 0xf9, 0x53, 0xcf, 0x5f, 0x3d,
        0x9d, 0xc8, 0xc4, 0xb9, 0xc8, 0xb7, 0x24, 0x4c, 0xb6, 0x39, 0xa5, 0xa0,
        0xf4, 0xa2, 0x6d, 0xfc, 0xd2, 0x0e, 0x95, 0x02,
    ];

    let result = compute_eip712_payload(domain_separator, message_hash);
    assert(result == expected, "compute_eip712_payload mismatch");
}
