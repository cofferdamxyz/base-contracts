import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import '@nomicfoundation/hardhat-ledger';
import 'dotenv/config';

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
  },

  paths: {
    sources: './contracts',
    tests: './test',
    cache: './cache',
    artifacts: './artifacts',
  },

  // Etherscan / Basescan verification
  etherscan: {
    apiKey: {
      baseSepolia: process.env.BASESCAN_API_KEY || '',
      base: process.env.BASESCAN_API_KEY || '',
    },
    customChains: [
      {
        network: 'baseSepolia',
        chainId: 84532,
        urls: {
          apiURL: 'https://api-sepolia.basescan.org/api',
          browserURL: 'https://sepolia.basescan.org',
        },
      },
      {
        network: 'base',
        chainId: 8453,
        urls: {
          apiURL: 'https://api.basescan.org/api',
          browserURL: 'https://basescan.org',
        },
      },
    ],
  },
};

// No network that reaches chain 8453 may carry private keys, whatever is
// added later. The in-process fork is exempt: it is local by construction.
for (const [name, net] of Object.entries(config.networks ?? {})) {
  if (name === 'hardhat' || !net || net.chainId !== 8453) continue;
  if (Array.isArray(net.accounts) && net.accounts.length > 0) {
    throw new Error(`hardhat.config.ts: network ${name} is chain 8453 and lists private keys; Base mainnet signs with the Ledger only`);
  }
}

export default config;
