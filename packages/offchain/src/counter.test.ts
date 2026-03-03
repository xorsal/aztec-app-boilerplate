import { CounterContract } from "../../contracts/artifacts/Counter.js";
import { describe, it, expect, beforeAll } from "vitest";
import { EmbeddedWallet } from "@aztec/wallets/embedded";
import { createAztecNodeClient } from "@aztec/aztec.js/node";
import { AztecAddress } from "@aztec/stdlib/aztec-address";
import {
  INITIAL_TEST_SECRET_KEYS,
  INITIAL_TEST_ACCOUNT_SALTS,
} from "@aztec/accounts/testing";
import { deployCounter } from "./utils.js";

describe("Counter Contract", () => {
  let wallet: EmbeddedWallet;
  let owner: AztecAddress;
  let counter: CounterContract;

  beforeAll(async () => {
    const aztecNode = await createAztecNodeClient("http://localhost:8080", {});
    wallet = await EmbeddedWallet.create(aztecNode, {
      pxeConfig: {
        dataDirectory: "pxe-test-counter",
        proverEnabled: false,
      },
    });

    // Register first test account as owner
    const accountManager = await wallet.createSchnorrAccount(
      INITIAL_TEST_SECRET_KEYS[0],
      INITIAL_TEST_ACCOUNT_SALTS[0],
    );
    owner = accountManager.address;

    // Deploy Counter
    counter = await deployCounter(wallet, owner);
  }, 240_000);

  it("deploys with correct owner", async () => {
    const contractOwner = await counter.methods
      .get_owner()
      .simulate({ from: owner });
    expect(contractOwner).toStrictEqual(owner);
  });

  it("initializes counter at 0", async () => {
    const value = await counter.methods
      .get_counter()
      .simulate({ from: owner });
    expect(value).toBe(0n);
  });

  it("increments the counter", async () => {
    await counter.methods.increment().send({ from: owner });

    const value = await counter.methods
      .get_counter()
      .simulate({ from: owner });
    expect(value).toBe(1n);
  }, 120_000);

  it("increments multiple times", async () => {
    await counter.methods.increment().send({ from: owner });
    await counter.methods.increment().send({ from: owner });

    const value = await counter.methods
      .get_counter()
      .simulate({ from: owner });
    // 1 from previous test + 2 = 3
    expect(value).toBe(3n);
  }, 120_000);
});
