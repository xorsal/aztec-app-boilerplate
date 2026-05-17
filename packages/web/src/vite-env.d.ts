/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_AZTEC_NODE_URL: string;
  readonly VITE_CONTRACT_ADDRESS: string;
  readonly VITE_APP_ID: string;
  readonly VITE_CHAIN_ID: string;
  readonly VITE_CHAIN_VERSION: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
