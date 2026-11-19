import { extendProvider, HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import '@nomicfoundation/hardhat-ledger';
import 'dotenv/config';
import { computeAddress } from 'ethers';
import { assertNoMainnetKeys, devKeyAccounts } from './scripts/lib/devKeyException';
import { RetryEmptyReadsProvider } from './scripts/lib/rpcRetry';

// ──────────────────────────────────────────────────────────────────────────────
// Cofferdam — Base contracts (ERC-4337 account abstraction)
// Target: Base mainnet (8453) + Base Sepolia (84532)
// Proof system: optimistic rollup (OP-stack) with Azul dual-proof (TEE+ZK)
// AA: ERC-4337 EntryPoint v0.7 (0x0000000071727De22E5E9d8BAf0edAc6f37da032)
// ──────────────────────────────────────────────────────────────────────────────

// Hardhat/Anvil account #0: a publicly known key, fine for local and testnet
// use only.
const PUBLIC_DEV_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || PUBLIC_DEV_KEY;

// Base mainnet signs only with a Ledger (decision 0080, 9; decision 0017): the
// `base` and `baseFork` networks take no private key, whatever .env holds, and
// list LEDGER_ADDRESS through the Hardhat Ledger plugin. The scripts' guards
// (scripts/lib/chain.ts) check the chain id the node reports, so a fork dry run
// runs them too.
//
// The one departure is the M2 dev-key exception (scripts/lib/devKeyException.ts;
// workspace docs/runbooks/mainnet-deploys.md): `baseDevTest` carries
// DEPLOYER_PRIVATE_KEY only when MAINNET_DEV_KEY_EXCEPTION=zkp-test-1 and
// GENERATION=zkp-test-1 are set and the key is the CofferdamDev wallet's
// (0x2c8A…6AB2). Temporary, MVP only, never production.
const DEV_KEY_ACCOUNTS = devKeyAccounts(process.env, computeAddress);
const LEDGER_ACCOUNTS = process.env.LEDGER_ADDRESS?.trim() ? [process.env.LEDGER_ADDRESS.trim()] : [];
const BASE_RPC_URL = process.env.BASE_RPC_URL || 'https://mainnet.base.org';

// `BASE_FORK=1` turns the in-process network into a fork of Base mainnet that
// keeps chain id 8453 (test/fork/, `yarn test:fork`); BASE_FORK_BLOCK pins
// the block. Off by default, so `yarn test` never touches the network.
const BASE_FORK = process.env.BASE_FORK === '1';
const BASE_FORK_BLOCK = process.env.BASE_FORK_BLOCK?.trim() ? Number(process.env.BASE_FORK_BLOCK) : undefined;

const config: HardhatUserConfig = {
  defaultNetwork: 'hardhat',

  solidity: {
    version: '0.8.28',
    settings: {
      evmVersion: 'cancun',
      viaIR: true,
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },

  networks: {
    // Local anvil node (forks Base Sepolia by default — see package.json node:start)
    localhost: {
      url: 'http://127.0.0.1:8545',
      accounts: [PRIVATE_KEY],
    },

    // Standard hardhat in-memory node; with BASE_FORK=1 a fork of Base mainnet
    // on chain id 8453.
    hardhat: BASE_FORK
      ? {
          chainId: 8453,
          forking: { url: BASE_RPC_URL, blockNumber: BASE_FORK_BLOCK },
          // EDR needs a hardfork history to fork a chain it does not know.
          chains: { 8453: { hardforkHistory: { prague: 0 } } },
        }
      : {
          chainId: 31337,
        },

    // A local fork of Base mainnet that keeps chain id 8453 (`yarn
    // node:start:base`), for deploy dry runs: anvil's unlocked accounts, or the
    // Ledger with LEDGER_ADDRESS for the Ledger dry run.
    baseFork: {
      url: 'http://127.0.0.1:8546',
      chainId: 8453,
      // A fork fetches the state it lacks from the forked RPC: the first proof
      // verification on a fresh fork outlasts Hardhat's 20 s HTTP default
      // (2026-11-17: two proofs read, then lost to a headers timeout).
      timeout: 600_000,
      accounts: 'remote',
      ledgerAccounts: LEDGER_ACCOUNTS,
    },

    // Base Sepolia testnet
    baseSepolia: {
      url: process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org',
      chainId: 84532,
      accounts: [PRIVATE_KEY],
    },

    // Base mainnet: the Ledger only, never a private key.
    base: {
      url: BASE_RPC_URL,
      chainId: 8453,
      accounts: [],
      ledgerAccounts: LEDGER_ACCOUNTS,
    },

    // Base mainnet under the M2 dev-key exception only: the CofferdamDev hot
    // wallet deploys the test generation zkp-test-1, nothing else. No key
    // unless the exception holds (above); the scripts check the signer and the
    // generation again (scripts/lib/chain.ts).
    baseDevTest: {
      url: BASE_RPC_URL,
      chainId: 8453,
      accounts: DEV_KEY_ACCOUNTS,
    },
  },

  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts',
  },

  // Basescan verification through Etherscan's v2 API: one Etherscan.io key for
  // every chain (hardhat-verify uses v2 only when apiKey is a single string; its
  // built-in Base and Base Sepolia entries carry the chain ids). The per-chain
  // keys and api.basescan.org endpoints of the v1 API are retired.
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY || process.env.BASESCAN_API_KEY || '',
  },
};

// No network that reaches chain 8453 may carry private keys, whatever is
// added later, except `baseDevTest` under the dev-key exception. The
// in-process fork is exempt: it is local by construction.
assertNoMainnetKeys(config.networks as Parameters<typeof assertNoMainnetKeys>[0]);

// A public RPC's empty answer to a read (HH110) is asked again rather than
// stopping a script after its transaction went out (scripts/lib/rpcRetry.ts).
// Sends are never repeated. The in-process network has no RPC to retry.
extendProvider(async (provider, _config, network) =>
  // The cast: Hardhat's ProviderWrapper types listeners() as Function[], its
  // EIP1193Provider as (...args) => void; the object is the same.
  network === 'hardhat' ? provider : (new RetryEmptyReadsProvider(provider) as unknown as typeof provider),
);

export default config;
