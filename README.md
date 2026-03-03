# Aztec App Boilerplate

A unified starter for Aztec v4 projects — contracts, offchain scripts, and web app in one monorepo.

## Prerequisites

- Node.js 22+
- Yarn 1.22+
- Aztec CLI (install via `aztec-up`)

```bash
curl -s https://install.aztec.network | VERSION=4.0.0-devnet.2-patch.1 bash
aztec-up
```

## Quick Start

```bash
# Install dependencies
yarn install

# Compile Noir contracts & generate TypeScript bindings
yarn build:contracts

# Start the Aztec sandbox (in a separate terminal)
yarn workspace @aztec-app/offchain sandbox:start

# Run integration tests
yarn test:js

# Deploy to local sandbox
yarn deploy

# Start the web app
yarn dev
```

## Project Structure

```
packages/
  contracts/   — Noir smart contracts (Counter example)
  offchain/    — Node.js scripts, tests, and bot skeleton
  web/         — React + Vite frontend with EmbeddedWallet
```

## Packages

### `@aztec-app/contracts`

Noir smart contracts compiled with `aztec compile` and codegen'd to TypeScript.

- `yarn build` — clean, compile, codegen
- `yarn test:nr` — run TXE (Noir) unit tests

### `@aztec-app/offchain`

Integration tests, deploy scripts, and a bot skeleton using `EmbeddedWallet`.

- `yarn test:js` — run vitest integration tests against sandbox
- `yarn deploy` — deploy Counter to local sandbox
- `yarn bot` — run the bot polling skeleton

### `@aztec-app/web`

React + Vite frontend with Zustand state management and `EmbeddedWallet`.

- `yarn dev` — start dev server on localhost:3000
- `yarn build` — production build
