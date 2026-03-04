/**
 * EIP-712 Hash Functions for Aztec Account Contract
 *
 * This module computes EIP-712 hashes that match what viem/ethers compute in TypeScript.
 * The signature over these hashes provides cryptographic binding between what the user
 * sees in MetaMask and what the circuit verifies.
 */

use keccak256::keccak256;
use ::aztec::oracle::capsules;
use ::aztec::protocol::{
    constants::{DOM_SEP__AUTHWIT_INNER, DOM_SEP__FUNCTION_ARGS, DOM_SEP__PUBLIC_CALLDATA},
    hash::{poseidon2_hash_subarray, poseidon2_hash_with_separator},
    traits::{Deserialize, Serialize},
    utils::{reader::Reader, writer::Writer},
};

// =============================================================================
// Pre-computed Type Hashes (from verify-signature.ts)
// =============================================================================

// keccak256("FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)")
// Note: selector is NOT included - it's derived from functionSignature via Poseidon2
global FUNCTION_CALL_TYPE_HASH: [u8; 32] = [
    0xbc, 0xb4, 0x42, 0x55, 0x87, 0xc5, 0x5d, 0x02, 0x21, 0x39, 0x40, 0xc3, 0x1e, 0x39, 0x32, 0xab,
    0x28, 0x67, 0x74, 0x42, 0xf7, 0x8c, 0x4d, 0x15, 0x12, 0xa6, 0xd6, 0x6b, 0xf6, 0xd9, 0x6e, 0x86,
];

// keccak256("AppDomain(string name,string version,uint256 chainId,bytes32 salt)")
global APP_DOMAIN_TYPE_HASH: [u8; 32] = [
    0xca, 0x22, 0x12, 0xa9, 0x3d, 0x16, 0xa0, 0x15, 0x7a, 0xb9, 0xc7, 0x31, 0xe0, 0xce, 0x9d, 0x0a,
    0xe0, 0xcb, 0x45, 0x71, 0x38, 0x2c, 0x7b, 0xfe, 0x48, 0xf9, 0xaf, 0x5d, 0x2c, 0xd4, 0xd9, 0xf7,
];

// keccak256("EntrypointAuthorization(AppDomain appDomain,FunctionCall[5] functionCalls,uint256 txNonce)AppDomain(...)FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)")
global ENTRYPOINT_AUTHORIZATION_5_TYPE_HASH: [u8; 32] = [
    0xc9, 0x84, 0xd9, 0x56, 0x32, 0x26, 0x80, 0x2b, 0x62, 0xdf, 0x86, 0x1b, 0x31, 0x70, 0x94, 0xab,
    0x66, 0x73, 0x54, 0x73, 0x12, 0xfe, 0x52, 0xb8, 0xca, 0xa2, 0xb7, 0x67, 0xad, 0x3a, 0xd9, 0xe7,
];

// keccak256("AuthwitAppDomain(uint256 chainId,bytes32 verifyingContract)")
global AUTHWIT_APP_DOMAIN_TYPE_HASH: [u8; 32] = [
    0xa3, 0x78, 0x92, 0x02, 0x45, 0x0c, 0x41, 0x89, 0x90, 0xe2, 0x37, 0x24, 0x23, 0xa0, 0xa0, 0xe5,
    0x4a, 0x0d, 0x05, 0x8d, 0xc6, 0xd9, 0x38, 0x32, 0x00, 0xef, 0x42, 0xba, 0x77, 0x71, 0x66, 0x8c,
];

// keccak256("FunctionCallAuthorization(AuthwitAppDomain appDomain,FunctionCall functionCall)AuthwitAppDomain(...)FunctionCall(bytes32 contract,string functionSignature,uint256[] arguments,bool isPrivate)")
global FUNCTION_CALL_AUTHORIZATION_TYPE_HASH: [u8; 32] = [
    0x08, 0xd9, 0x8e, 0x46, 0x71, 0xb9, 0x17, 0x57, 0x9f, 0xdc, 0x62, 0x4c, 0xd5, 0x64, 0xad, 0x4a,
    0x1d, 0xc7, 0x29, 0x91, 0xe6, 0x45, 0xf7, 0x12, 0x65, 0x4b, 0xa2, 0x82, 0x19, 0xff, 0xb5, 0xe1,
];

// Hash of empty FunctionCall struct (for padding empty slots in 5-call array)
// hashStruct(FunctionCall{contract: 0, functionSignature: "", arguments: [], isPrivate: true})
// Note: selector is NOT included in the hash
pub global EMPTY_FUNCTION_CALL_HASH: [u8; 32] = [
    0x7a, 0x9f, 0x1a, 0xbe, 0xd0, 0xf1, 0x7b, 0xe2, 0x96, 0x36, 0x0b, 0xf4, 0x0a, 0xff, 0x57, 0x23,
    0x9f, 0xff, 0xf0, 0xbd, 0x19, 0x3d, 0x2e, 0x7c, 0xb1, 0x04, 0x6a, 0x5e, 0x14, 0xcf, 0x88, 0x46,
];

// =============================================================================
// Constants
// =============================================================================

pub global MAX_SERIALIZED_ARGS: u32 = 20; // Max function arguments
pub global MAX_SIGNATURE_SIZE: u32 = 128; // Max function signature string length
pub global ACCOUNT_MAX_CALLS: u32 = 5; // 5 function calls per entrypoint (per Aztec AppPayload spec)

// Capsule slots for EIP-712 witness data
pub global EIP712_WITNESS_5_SLOT: Field = 0x1234567890abcdf0; // 5-call entrypoint
pub global EIP712_AUTHWIT_SLOT: Field = 0xabcdef1234567890; // Individual authwit

// =============================================================================
// 5-Call Witness Structure
// =============================================================================

/// EIP-712 witness data for 5 function calls (per Aztec AppPayload spec)
///
/// Note: selector is NOT included - it's derived from function_signature via Poseidon2
pub struct Eip712Witness5 {
    // ECDSA signature (r || s), 64 bytes - shared across all calls
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],

    // Per-call data (5 function calls)
    pub function_signatures: [[u8; MAX_SIGNATURE_SIZE]; ACCOUNT_MAX_CALLS],
    pub signature_lengths: [u32; ACCOUNT_MAX_CALLS],
    pub function_args: [[Field; MAX_SERIALIZED_ARGS]; ACCOUNT_MAX_CALLS],
    pub args_lengths: [u32; ACCOUNT_MAX_CALLS],
    pub target_addresses: [Field; ACCOUNT_MAX_CALLS],

    // Shared metadata
    pub chain_id: Field,
    pub salt: [u8; 32],
}

// Serialization size: 145 Fields
pub global EIP712_WITNESS_5_SERIALIZED_LEN: u32 = 145;

impl Serialize for Eip712Witness5 {
    let N: u32 = EIP712_WITNESS_5_SERIALIZED_LEN;

    fn serialize(self) -> [Field; Self::N] {
        let mut result: [Field; EIP712_WITNESS_5_SERIALIZED_LEN] =
            [0; EIP712_WITNESS_5_SERIALIZED_LEN];

        // [0-2]: Signature (64 bytes: 31+31+2)
        result[0] = pack_bytes_31(self.signature_r, 0);
        let mut combined: [u8; 31] = [0; 31];
        combined[0] = self.signature_r[31];
        for i in 0..30 {
            combined[i + 1] = self.signature_s[i];
        }
        result[1] = pack_bytes_to_field(combined);
        result[2] = (self.signature_s[30] as Field) * 256 + (self.signature_s[31] as Field);

        // [3-142]: 5 calls, each 28 fields
        for call_idx in 0..ACCOUNT_MAX_CALLS {
            let base = 3 + call_idx * 28;

            // Function signature (128 bytes = 5 fields: 31+31+31+31+4)
            for i in 0..4 {
                let mut chunk: [u8; 31] = [0; 31];
                for j in 0..31 {
                    chunk[j] = self.function_signatures[call_idx][i * 31 + j];
                }
                result[base + i] = pack_bytes_to_field(chunk);
            }
            // Last 4 bytes
            let mut last_chunk: Field = 0;
            for i in 0..4 {
                last_chunk =
                    last_chunk * 256 + (self.function_signatures[call_idx][124 + i] as Field);
            }
            result[base + 4] = last_chunk;

            // Signature length
            result[base + 5] = self.signature_lengths[call_idx] as Field;

            // Function args (20 fields)
            for i in 0..MAX_SERIALIZED_ARGS {
                result[base + 6 + i] = self.function_args[call_idx][i];
            }

            // Args length
            result[base + 26] = self.args_lengths[call_idx] as Field;

            // Target address
            result[base + 27] = self.target_addresses[call_idx];
        }

        // [143]: chain_id
        result[143] = self.chain_id;

        // [144]: salt (first 31 bytes)
        result[144] = pack_bytes_31(self.salt, 0);

        result
    }

    fn stream_serialize<let K: u32>(self, writer: &mut Writer<K>) {
        let serialized = self.serialize();
        writer.write_array(serialized);
    }
}

impl Deserialize for Eip712Witness5 {
    let N: u32 = EIP712_WITNESS_5_SERIALIZED_LEN;

    fn deserialize(fields: [Field; Self::N]) -> Self {
        // [0-2]: Signature
        let sig_bytes = unpack_signature_from_fields([fields[0], fields[1], fields[2]]);
        let mut signature_r: [u8; 32] = [0; 32];
        let mut signature_s: [u8; 32] = [0; 32];
        for i in 0..32 {
            signature_r[i] = sig_bytes[i];
            signature_s[i] = sig_bytes[32 + i];
        }

        // [3-142]: 5 calls, each 28 fields
        let mut function_signatures: [[u8; MAX_SIGNATURE_SIZE]; ACCOUNT_MAX_CALLS] =
            [[0; MAX_SIGNATURE_SIZE]; ACCOUNT_MAX_CALLS];
        let mut signature_lengths: [u32; ACCOUNT_MAX_CALLS] = [0; ACCOUNT_MAX_CALLS];
        let mut function_args: [[Field; MAX_SERIALIZED_ARGS]; ACCOUNT_MAX_CALLS] =
            [[0; MAX_SERIALIZED_ARGS]; ACCOUNT_MAX_CALLS];
        let mut args_lengths: [u32; ACCOUNT_MAX_CALLS] = [0; ACCOUNT_MAX_CALLS];
        let mut target_addresses: [Field; ACCOUNT_MAX_CALLS] = [0; ACCOUNT_MAX_CALLS];

        for call_idx in 0..ACCOUNT_MAX_CALLS {
            let base = 3 + call_idx * 28;

            // Function signature (5 fields)
            function_signatures[call_idx] = unpack_func_sig_from_fields([
                fields[base],
                fields[base + 1],
                fields[base + 2],
                fields[base + 3],
                fields[base + 4],
            ]);

            // Signature length
            signature_lengths[call_idx] = fields[base + 5] as u32;

            // Function args (20 fields)
            for i in 0..MAX_SERIALIZED_ARGS {
                function_args[call_idx][i] = fields[base + 6 + i];
            }

            // Args length
            args_lengths[call_idx] = fields[base + 26] as u32;

            // Target address
            target_addresses[call_idx] = fields[base + 27];
        }

        // [143]: chain_id
        let chain_id = fields[143];

        // [144]: salt
        let salt = unpack_salt_from_field(fields[144]);

        Eip712Witness5 {
            signature_r,
            signature_s,
            function_signatures,
            signature_lengths,
            function_args,
            args_lengths,
            target_addresses,
            chain_id,
            salt,
        }
    }

    fn stream_deserialize<let K: u32>(reader: &mut Reader<K>) -> Self {
        let fields: [Field; EIP712_WITNESS_5_SERIALIZED_LEN] = reader.read_array();
        Deserialize::deserialize(fields)
    }
}

/// Load EIP-712 witness for 5 calls from capsule storage
pub unconstrained fn load_eip712_witness_5(
    contract_address: ::aztec::protocol::address::AztecAddress,
) -> Option<Eip712Witness5> {
    capsules::load(contract_address, EIP712_WITNESS_5_SLOT)
}

// =============================================================================
// Individual Authwit Witness Structure
// =============================================================================

/// EIP-712 witness data for individual authorization (authwit)
pub struct Eip712AuthwitWitness {
    // ECDSA signature (r || s), 64 bytes
    pub signature_r: [u8; 32],
    pub signature_s: [u8; 32],

    // Function call data
    pub function_signature: [u8; MAX_SIGNATURE_SIZE],
    pub signature_length: u32,
    pub function_args: [Field; MAX_SERIALIZED_ARGS],
    pub args_length: u32,
    pub target_address: Field,

    // Authwit-specific domain
    pub chain_id: Field,
    pub verifying_contract: Field,

    // For verification against inner_hash
    pub inner_hash: Field,
}

pub global EIP712_AUTHWIT_SERIALIZED_LEN: u32 = 34;

impl Serialize for Eip712AuthwitWitness {
    let N: u32 = EIP712_AUTHWIT_SERIALIZED_LEN;

    fn serialize(self) -> [Field; Self::N] {
        let mut result: [Field; EIP712_AUTHWIT_SERIALIZED_LEN] = [0; EIP712_AUTHWIT_SERIALIZED_LEN];

        // [0-2]: Signature
        result[0] = pack_bytes_31(self.signature_r, 0);
        let mut combined: [u8; 31] = [0; 31];
        combined[0] = self.signature_r[31];
        for i in 0..30 {
            combined[i + 1] = self.signature_s[i];
        }
        result[1] = pack_bytes_to_field(combined);
        result[2] = (self.signature_s[30] as Field) * 256 + (self.signature_s[31] as Field);

        // [3-7]: Function signature
        for i in 0..4 {
            let mut chunk: [u8; 31] = [0; 31];
            for j in 0..31 {
                chunk[j] = self.function_signature[i * 31 + j];
            }
            result[3 + i] = pack_bytes_to_field(chunk);
        }
        let mut last_chunk: Field = 0;
        for i in 0..4 {
            last_chunk = last_chunk * 256 + (self.function_signature[124 + i] as Field);
        }
        result[7] = last_chunk;

        // [8]: Signature length
        result[8] = self.signature_length as Field;

        // [9-28]: Function args
        for i in 0..MAX_SERIALIZED_ARGS {
            result[9 + i] = self.function_args[i];
        }

        // [29]: Args length
        result[29] = self.args_length as Field;

        // [30]: Target address
        result[30] = self.target_address;

        // [31]: Chain ID
        result[31] = self.chain_id;

        // [32]: Verifying contract
        result[32] = self.verifying_contract;

        // [33]: Inner hash
        result[33] = self.inner_hash;

        result
    }

    fn stream_serialize<let K: u32>(self, writer: &mut Writer<K>) {
        let serialized = self.serialize();
        writer.write_array(serialized);
    }
}

impl Deserialize for Eip712AuthwitWitness {
    let N: u32 = EIP712_AUTHWIT_SERIALIZED_LEN;

    fn deserialize(fields: [Field; Self::N]) -> Self {
        // [0-2]: Signature
        let sig_bytes = unpack_signature_from_fields([fields[0], fields[1], fields[2]]);
        let mut signature_r: [u8; 32] = [0; 32];
        let mut signature_s: [u8; 32] = [0; 32];
        for i in 0..32 {
            signature_r[i] = sig_bytes[i];
            signature_s[i] = sig_bytes[32 + i];
        }

        // [3-7]: Function signature
        let function_signature =
            unpack_func_sig_from_fields([fields[3], fields[4], fields[5], fields[6], fields[7]]);

        // [8]: Signature length
        let signature_length = fields[8] as u32;

        // [9-28]: Function args
        let mut function_args: [Field; MAX_SERIALIZED_ARGS] = [0; MAX_SERIALIZED_ARGS];
        for i in 0..MAX_SERIALIZED_ARGS {
            function_args[i] = fields[9 + i];
        }

        // [29]: Args length
        let args_length = fields[29] as u32;

        // [30]: Target address
        let target_address = fields[30];

        // [31]: Chain ID
        let chain_id = fields[31];

        // [32]: Verifying contract
        let verifying_contract = fields[32];

        // [33]: Inner hash
        let inner_hash = fields[33];

        Eip712AuthwitWitness {
            signature_r,
            signature_s,
            function_signature,
            signature_length,
            function_args,
            args_length,
            target_address,
            chain_id,
            verifying_contract,
            inner_hash,
        }
    }

    fn stream_deserialize<let K: u32>(reader: &mut Reader<K>) -> Self {
        let fields: [Field; EIP712_AUTHWIT_SERIALIZED_LEN] = reader.read_array();
        Deserialize::deserialize(fields)
    }
}

/// Load EIP-712 authwit witness from capsule storage
pub unconstrained fn load_eip712_authwit_witness(
    contract_address: ::aztec::protocol::address::AztecAddress,
) -> Option<Eip712AuthwitWitness> {
    capsules::load(contract_address, EIP712_AUTHWIT_SLOT)
}

// =============================================================================
// Byte Packing/Unpacking Helpers
// =============================================================================

/// Pack first 31 bytes starting at offset into a Field (big-endian)
fn pack_bytes_31<let N: u32>(bytes: [u8; N], offset: u32) -> Field {
    let mut result: Field = 0;
    for i in 0..31 {
        if offset + i < N {
            result = result * 256 + (bytes[offset + i] as Field);
        }
    }
    result
}

/// Pack exactly 31 bytes into a Field (big-endian)
fn pack_bytes_to_field(bytes: [u8; 31]) -> Field {
    let mut result: Field = 0;
    for i in 0..31 {
        result = result * 256 + (bytes[i] as Field);
    }
    result
}

/// Unpack signature from 3 fields (64 bytes packed as 31+31+2)
fn unpack_signature_from_fields(fields: [Field; 3]) -> [u8; 64] {
    let mut sig: [u8; 64] = [0; 64];

    // First 31 bytes from field 0
    let b0: [u8; 31] = fields[0].to_be_bytes();
    for i in 0..31 {
        sig[i] = b0[i];
    }

    // Next 31 bytes from field 1
    let b1: [u8; 31] = fields[1].to_be_bytes();
    for i in 0..31 {
        sig[31 + i] = b1[i];
    }

    // Last 2 bytes from field 2
    let b2: [u8; 2] = fields[2].to_be_bytes();
    sig[62] = b2[0];
    sig[63] = b2[1];

    sig
}

/// Unpack function signature from 5 fields (128 bytes packed as 31+31+31+31+4)
fn unpack_func_sig_from_fields(fields: [Field; 5]) -> [u8; MAX_SIGNATURE_SIZE] {
    let mut func_sig: [u8; MAX_SIGNATURE_SIZE] = [0; MAX_SIGNATURE_SIZE];

    // First 4 fields, each with 31 bytes
    for f in 0..4 {
        let bytes: [u8; 31] = fields[f].to_be_bytes();
        for i in 0..31 {
            func_sig[f * 31 + i] = bytes[i];
        }
    }

    // Last 4 bytes from field 4
    let last: [u8; 4] = fields[4].to_be_bytes();
    for i in 0..4 {
        func_sig[124 + i] = last[i];
    }

    func_sig
}

/// Unpack salt from a single field (only first 31 bytes, last byte assumed 0)
fn unpack_salt_from_field(field: Field) -> [u8; 32] {
    let mut salt: [u8; 32] = [0; 32];
    let bytes: [u8; 31] = field.to_be_bytes();
    for i in 0..31 {
        salt[i] = bytes[i];
    }
    // salt[31] stays 0
    salt
}

// =============================================================================
// EIP-712 Hash Functions
// =============================================================================

/**
 * Hash a dynamic-length string for EIP-712 encoding
 * enc(string) = keccak256(string)
 */
pub fn hash_string<let N: u32>(data: [u8; N], len: u32) -> [u8; 32] {
    keccak256(data, len)
}

/**
 * Hash a uint256[] array for EIP-712 encoding
 * enc(uint256[]) = keccak256(enc(args[0]) || enc(args[1]) || ...)
 */
pub fn hash_uint256_array(args: [Field; MAX_SERIALIZED_ARGS], len: u32) -> [u8; 32] {
    // Maximum encoded size: 20 args * 32 bytes = 640 bytes
    let mut encoded: [u8; 640] = [0; 640];

    for i in 0..MAX_SERIALIZED_ARGS {
        if i < len {
            let arg_bytes: [u8; 32] = args[i].to_be_bytes();
            for j in 0..32 {
                encoded[i * 32 + j] = arg_bytes[j];
            }
        }
    }

    if len == 0 {
        // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ]
    } else {
        keccak256(encoded, len * 32)
    }
}

/**
 * Compute hashStruct(FunctionCall)
 *
 * Note: selector is NOT included in the EIP-712 hash - it's derived from
 * function_signature via Poseidon2 hashing.
 */
pub fn hash_function_call(
    target_address: [u8; 32],
    function_signature: [u8; MAX_SIGNATURE_SIZE],
    sig_len: u32,
    arguments: [Field; MAX_SERIALIZED_ARGS],
    args_len: u32,
    is_private: bool,
) -> [u8; 32] {
    let sig_hash = hash_string(function_signature, sig_len);
    let args_hash = hash_uint256_array(arguments, args_len);

    // Concatenate: typeHash (32) || contract (32) || sig_hash (32) || args_hash (32) || is_private (32) = 160 bytes
    let mut data: [u8; 160] = [0; 160];

    for i in 0..32 {
        data[i] = FUNCTION_CALL_TYPE_HASH[i];
    }

    for i in 0..32 {
        data[32 + i] = target_address[i];
    }

    for i in 0..32 {
        data[64 + i] = sig_hash[i];
    }

    for i in 0..32 {
        data[96 + i] = args_hash[i];
    }

    // EIP-712 bool encoding: 0 for false, 1 for true (right-padded to 32 bytes)
    // is_private goes in the last byte (index 159) since it's big-endian uint256
    if is_private {
        data[159] = 1;
    }

    keccak256(data, 160)
}

/**
 * Compute hashStruct(AppDomain)
 */
pub fn hash_app_domain(
    name: [u8; 32],
    version: [u8; 32],
    chain_id: [u8; 32],
    salt: [u8; 32],
) -> [u8; 32] {
    let mut data: [u8; 160] = [0; 160];

    for i in 0..32 {
        data[i] = APP_DOMAIN_TYPE_HASH[i];
    }

    for i in 0..32 {
        data[32 + i] = name[i];
    }

    for i in 0..32 {
        data[64 + i] = version[i];
    }

    for i in 0..32 {
        data[96 + i] = chain_id[i];
    }

    for i in 0..32 {
        data[128 + i] = salt[i];
    }

    keccak256(data, 160)
}

/**
 * Hash an array of FunctionCall hashes for EIP-712 encoding
 */
pub fn hash_function_calls_array(call_hashes: [[u8; 32]; ACCOUNT_MAX_CALLS]) -> [u8; 32] {
    let mut encoded: [u8; 160] = [0; 160];

    for i in 0..ACCOUNT_MAX_CALLS {
        for j in 0..32 {
            encoded[i * 32 + j] = call_hashes[i][j];
        }
    }

    keccak256(encoded, 160)
}

/**
 * Compute hashStruct(EntrypointAuthorization) for 5 function calls
 */
pub fn hash_entrypoint_authorization_5(
    app_domain_hash: [u8; 32],
    function_calls_array_hash: [u8; 32],
    tx_nonce: [u8; 32],
) -> [u8; 32] {
    let mut data: [u8; 128] = [0; 128];

    for i in 0..32 {
        data[i] = ENTRYPOINT_AUTHORIZATION_5_TYPE_HASH[i];
    }

    for i in 0..32 {
        data[32 + i] = app_domain_hash[i];
    }

    for i in 0..32 {
        data[64 + i] = function_calls_array_hash[i];
    }

    for i in 0..32 {
        data[96 + i] = tx_nonce[i];
    }

    keccak256(data, 128)
}

/**
 * Compute hashStruct(AuthwitAppDomain)
 */
pub fn hash_authwit_app_domain(chain_id: [u8; 32], verifying_contract: [u8; 32]) -> [u8; 32] {
    let mut data: [u8; 96] = [0; 96];

    for i in 0..32 {
        data[i] = AUTHWIT_APP_DOMAIN_TYPE_HASH[i];
    }

    for i in 0..32 {
        data[32 + i] = chain_id[i];
    }

    for i in 0..32 {
        data[64 + i] = verifying_contract[i];
    }

    keccak256(data, 96)
}

/**
 * Compute hashStruct(FunctionCallAuthorization)
 */
pub fn hash_function_call_authorization(
    authwit_domain_hash: [u8; 32],
    function_call_hash: [u8; 32],
) -> [u8; 32] {
    let mut data: [u8; 96] = [0; 96];

    for i in 0..32 {
        data[i] = FUNCTION_CALL_AUTHORIZATION_TYPE_HASH[i];
    }

    for i in 0..32 {
        data[32 + i] = authwit_domain_hash[i];
    }

    for i in 0..32 {
        data[64 + i] = function_call_hash[i];
    }

    keccak256(data, 96)
}

/**
 * Compute final EIP-712 payload
 */
pub fn compute_eip712_payload(domain_separator: [u8; 32], message_hash: [u8; 32]) -> [u8; 32] {
    let mut payload: [u8; 66] = [0; 66];

    payload[0] = 0x19;
    payload[1] = 0x01;

    for i in 0..32 {
        payload[2 + i] = domain_separator[i];
    }

    for i in 0..32 {
        payload[34 + i] = message_hash[i];
    }

    keccak256(payload, 66)
}

/**
 * Convert a Field to 32-byte big-endian representation
 */
pub fn field_to_bytes32(f: Field) -> [u8; 32] {
    f.to_be_bytes()
}

// =============================================================================
// Aztec Poseidon2 Hash Functions (for verification against AppPayload)
// =============================================================================

/**
 * Compute hash_args with variable length
 *
 * IMPORTANT: Public and private functions use different generator indices:
 * - Private functions: DOM_SEP__FUNCTION_ARGS (44)
 * - Public functions: DOM_SEP__PUBLIC_CALLDATA (43)
 *
 * This matches the SDK's HashedValues.fromArgs() vs fromCalldata() methods.
 */
pub fn compute_aztec_args_hash(
    args: [Field; MAX_SERIALIZED_ARGS],
    len: u32,
    is_public: bool,
    selector: Field,
) -> Field {
    // For public functions, selector is prepended to args in the AppPayload
    // For private functions, selector is not included (it's 0)
    if is_public {
        // Public: prepend selector to args
        // Note: For public calls, selector is always included even if len == 0
        // Args with selector prepended: [selector, arg0, arg1, ...]
        let mut input: [Field; 22] = [0; 22];
        let generator_index = DOM_SEP__PUBLIC_CALLDATA;
        input[0] = generator_index as Field;
        input[1] = selector; // Selector goes first
        for i in 0..MAX_SERIALIZED_ARGS {
            input[i + 2] = args[i];
        }
        // Total size: 1 (generator) + 1 (selector) + len (args) = len + 2
        // But the generator index slot is already accounted for in poseidon2_hash_subarray
        let message_size = len + 2; // +1 for generator, +1 for selector
        poseidon2_hash_subarray(input, message_size)
    } else {
        // Private: no selector
        if len == 0 {
            0
        } else {
            let mut input: [Field; 21] = [0; 21];
            let generator_index = DOM_SEP__FUNCTION_ARGS;
            input[0] = generator_index as Field;
            for i in 0..MAX_SERIALIZED_ARGS {
                input[i + 1] = args[i];
            }
            let message_size = len + 1;
            poseidon2_hash_subarray(input, message_size)
        }
    }
}

/**
 * Compute function selector from signature bytes with variable length
 */
pub fn compute_function_selector(signature: [u8; MAX_SIGNATURE_SIZE], len: u32) -> u32 {
    if len == 0 {
        0
    } else {
        let mut fields: [Field; 5] = [0; 5];
        let mut field_index: u32 = 0;
        let mut current_field: [u8; 31] = [0; 31];

        for i in 0..MAX_SIGNATURE_SIZE {
            if i < len {
                let index = i % 31;
                current_field[index] = signature[i];
                if index == 30 {
                    fields[field_index] = field_from_bytes_31_le(current_field);
                    current_field = [0; 31];
                    field_index += 1;
                }
            }
        }

        let remaining = len % 31;
        if remaining != 0 {
            fields[field_index] = field_from_bytes_31_le(current_field);
            field_index += 1;
        }

        let hash = poseidon2_hash_subarray(fields, field_index);
        hash as u32
    }
}

/**
 * Convert up to 31 bytes to a Field (little-endian)
 */
fn field_from_bytes_31_le(bytes: [u8; 31]) -> Field {
    let mut as_field: Field = 0;
    let mut offset: Field = 1;
    for i in 0..31 {
        as_field += (bytes[i] as Field) * offset;
        offset *= 256;
    }
    as_field
}

/**
 * Compute the Aztec inner_hash for authwit verification
 */
pub fn compute_inner_hash(caller: Field, selector: u32, args_hash: Field) -> Field {
    poseidon2_hash_with_separator(
        [caller, selector as Field, args_hash],
        DOM_SEP__AUTHWIT_INNER,
    )
}

// =============================================================================
// AppPayload Serialization Helpers
// =============================================================================

pub global APP_PAYLOAD_SERIALIZED_LEN: u32 = 31;
pub global FUNCTION_CALL_SERIALIZED_LEN: u32 = 6;

/**
 * Extract args_hash for a specific function call from serialized AppPayload
 */
pub fn extract_args_hash(
    serialized: [Field; APP_PAYLOAD_SERIALIZED_LEN],
    call_index: u32,
) -> Field {
    let offset = call_index * FUNCTION_CALL_SERIALIZED_LEN;
    serialized[offset]
}

/**
 * Extract function_selector for a specific function call from serialized AppPayload
 */
pub fn extract_function_selector(
    serialized: [Field; APP_PAYLOAD_SERIALIZED_LEN],
    call_index: u32,
) -> u32 {
    let offset = call_index * FUNCTION_CALL_SERIALIZED_LEN + 1;
    serialized[offset] as u32
}

/**
 * Extract target_address for a specific function call from serialized AppPayload
 */
pub fn extract_target_address(
    serialized: [Field; APP_PAYLOAD_SERIALIZED_LEN],
    call_index: u32,
) -> Field {
    let offset = call_index * FUNCTION_CALL_SERIALIZED_LEN + 2;
    serialized[offset]
}

/**
 * Extract is_public flag for a specific function call from serialized AppPayload
 * FunctionCall layout: [args_hash, function_selector, target_address, is_public, hide_msg_sender, is_static]
 */
pub fn extract_is_public(serialized: [Field; APP_PAYLOAD_SERIALIZED_LEN], call_index: u32) -> bool {
    let offset = call_index * FUNCTION_CALL_SERIALIZED_LEN + 3;
    serialized[offset] == 1
}
