import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import { Fr } from "@aztec/aztec.js/fields";
import { CounterContract } from "../../contracts/artifacts/Counter.js";

/**
 * Deploy a Counter contract using the given wallet.
 *
 * @param wallet - EmbeddedWallet instance connected to an Aztec node
 * @param owner  - Address that will own the contract
 * @param salt   - Optional deployment salt for deterministic addresses
 * @returns The deployed CounterContract instance
 */
export async function deployCounter(
  wallet: EmbeddedWallet,
  owner: AztecAddress,
  salt?: Fr,
): Promise<CounterContract> {
  const deployerAddress = (await wallet.getAccounts())[0]!.item;

  const contract = await CounterContract.deployWithOpts(
    { wallet },
    owner,
  ).send({ from: deployerAddress });

  return contract;
}
