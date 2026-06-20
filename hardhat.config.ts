import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import 'dotenv/config';

// ──────────────────────────────────────────────────────────────────────────────
// Cofferdam — Base contracts (ERC-4337 account abstraction)
// Target: Base mainnet (8453) + Base Sepolia (84532)
// Proof system: optimistic rollup (OP-stack) with Azul dual-proof (TEE+ZK)
// AA: ERC-4337 EntryPoint v0.7 (0x0000000071727De22E5E9d8BAf0edAc6f37da032)
// ──────────────────────────────────────────────────────────────────────────────

const PRIVATE_KEY =
  process.env.DEPLOYER_PRIVATE_KEY ||
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

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

    // Standard hardhat in-memory node (no fork)
    hardhat: {
      chainId: 31337,
    },

    // Base Sepolia testnet
    baseSepolia: {
      url: process.env.BASE_SEPOLIA_RPC_URL || 'https://sepolia.base.org',
      chainId: 84532,
      accounts: [PRIVATE_KEY],
    },

    // Base mainnet
    base: {
      url: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
      chainId: 8453,
      accounts: [PRIVATE_KEY],
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

export default config;
