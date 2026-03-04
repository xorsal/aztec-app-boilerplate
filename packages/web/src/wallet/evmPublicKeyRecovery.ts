import { hashMessage, recoverPublicKey, type Hex } from "viem";

/**
 * Recover the uncompressed public key from a signed message.
 *
 * Uses Ethereum's ecrecover to extract the public key from a signature.
 * The public key is used to deploy an Aztec EIP-712 account contract.
 */
export async function recoverPublicKeyFromSignature(
  message: string,
  signature: Hex,
): Promise<{ x: Buffer; y: Buffer }> {
  const messageHash = hashMessage(message);

  // recoverPublicKey returns uncompressed key (65 bytes: 0x04 + x[32] + y[32])
  const publicKey = await recoverPublicKey({
    hash: messageHash,
    signature,
  });

  // Remove the 0x04 prefix and split into x and y coordinates
  const pubKeyHex = publicKey.slice(4); // Remove '0x04'
  const x = Buffer.from(pubKeyHex.slice(0, 64), "hex");
  const y = Buffer.from(pubKeyHex.slice(64, 128), "hex");

  return { x, y };
}

/**
 * Standard message for public key recovery during account setup.
 * Deterministic so the same EVM address always produces the same Aztec account.
 */
export function getPublicKeyRecoveryMessage(evmAddress: Hex): string {
  return `Sign to allow creation and inspection state of your Aztec account linked to ${evmAddress}`;
}
