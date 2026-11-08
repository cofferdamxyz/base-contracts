import { ethers, network } from 'hardhat';

// Guards for deploy scripts (decision 0080, 9). They read the chain id from
// the node, never the network's name, so a dry run on a fork of Base mainnet
// (`yarn node:start:base` plus `--network baseFork`, or `BASE_FORK=1` on the
// in-process network) runs every mainnet guard.

export const BASE_MAINNET_CHAIN_ID = 8453n;
/** The least delay a mainnet generation pins (decisions 0022, 0023, 0080). */
export const MIN_MAINNET_DELAY_SECONDS = 259_200n;

/** The chain id the node reports. */
export async function chainId(): Promise<bigint> {
  return (await ethers.provider.getNetwork()).chainId;
}

export async function isBaseMainnetChain(): Promise<boolean> {
  return (await chainId()) === BASE_MAINNET_CHAIN_ID;
}

/**
 * The node is a development node (the in-process Hardhat network, anvil or a
 * Hardhat node), so nothing it signs reaches a public chain. Asked of the node
 * itself, never read from the URL: a real Base node or an RPC tunnel can
 * listen on 127.0.0.1 too.
 */
export async function isLocalFork(): Promise<boolean> {
  if (network.name === 'hardhat') return true;
  for (const method of ['anvil_nodeInfo', 'hardhat_metadata']) {
    try {
      await ethers.provider.send(method, []);
      return true;
    } catch {
      // not a development node, or not this kind
    }
  }
  return false;
}

/** Throw on Base mainnet (or a fork of it): for scripts whose contracts never go there. */
export async function refuseMainnet(what: string): Promise<void> {
  if (await isBaseMainnetChain()) {
    throw new Error(`${what} never deploys to Base mainnet (chain 8453), a fork of it included (decision 0080)`);
  }
}

/**
 * On Base mainnet the deployer is the Ledger (decision 0017; the founder's
 * Ledger for the test generation, T3). The `base` network has no private keys
 * (hardhat.config.ts), so a signer there can only come from `ledgerAccounts`;
 * this checks it once more against the network the script actually reached.
 * On a local fork it only says that this is a dry run.
 */
export async function assertMainnetSigner(signer: string): Promise<void> {
  if (!(await isBaseMainnetChain())) return;
  if (await isLocalFork()) {
    console.log(`DRY RUN: chain 8453 on a local fork (${network.name}); nothing reaches Base mainnet.`);
    return;
  }
  const cfg = network.config as { accounts?: unknown; ledgerAccounts?: string[] };
  if (Array.isArray(cfg.accounts) && cfg.accounts.length > 0) {
    throw new Error(`Network ${network.name} reaches Base mainnet with private keys configured: refused (decision 0080)`);
  }
  const ledger = (cfg.ledgerAccounts ?? []).map((a) => a.toLowerCase());
  if (!ledger.includes(signer.toLowerCase())) {
    throw new Error(`On Base mainnet the deployer must be a Ledger account (LEDGER_ADDRESS); got ${signer}`);
  }
}

/**
 * The deployer: the Ledger when LEDGER_ADDRESS is set (the plugin lists it
 * after the node's own accounts, so it must be picked by address), else the
 * first signer. On a local fork an unfunded Ledger gets test ETH, so the
 * Ledger dry run needs no faucet. On `base` the only signer is LEDGER_ADDRESS.
 */
export async function getDeployer() {
  const ledger = process.env.LEDGER_ADDRESS?.trim();
  const listed = ((network.config as { ledgerAccounts?: string[] }).ledgerAccounts ?? []).map((a) => a.toLowerCase());
  if (ledger && listed.includes(ledger.toLowerCase())) {
    const signer = await ethers.getSigner(ledger);
    if ((await isLocalFork()) && (await ethers.provider.getBalance(ledger)) < ethers.parseEther('1')) {
      await ethers.provider.send('hardhat_setBalance', [ledger, ethers.toBeHex(ethers.parseEther('10'))]);
    }
    return signer;
  }
  const [deployer] = await ethers.getSigners();
  if (!deployer) {
    throw new Error(`No signer on ${network.name}: Base mainnet signs with the Ledger only; set LEDGER_ADDRESS (decision 0080)`);
  }
  return deployer;
}

/** A delay from the environment, at least 72 hours on Base mainnet. */
export async function mainnetDelay(name: string, offMainnetDefault: bigint): Promise<bigint> {
  const raw = process.env[name]?.trim();
  const mainnet = await isBaseMainnetChain();
  const value = raw ? BigInt(raw) : mainnet ? MIN_MAINNET_DELAY_SECONDS : offMainnetDefault;
  if (mainnet && value < MIN_MAINNET_DELAY_SECONDS) throw new Error(`${name} must be at least 72 hours on Base mainnet`);
  return value;
}
